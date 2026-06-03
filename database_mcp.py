import sys
import json
import sqlite3
import os

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(PROJECT_DIR, "damn-vulnerable-llm-agent", "transactions.db")

def log(msg):
    print(f"[database-provider] {msg}", file=sys.stderr, flush=True)

def handle_request(req):
    method = req.get("method")
    req_id = req.get("id")
    
    if method in ("tools/list", "listTools"):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "GetCurrentUser",
                        "description": "Returns the current user for querying transactions.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "keycloak_sub": {"type": "string"},
                                "debug_mode": {"type": "boolean"}
                            }
                        }
                    },
                    {
                        "name": "GetUserTransactions",
                        "description": "Returns the transactions associated to the userId provided.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "userId": {"type": "string"}
                            },
                            "required": ["userId"]
                        }
                    }
                ]
            }
        }
        
    elif method in ("tools/call", "callTool"):
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            if tool_name == "GetCurrentUser":
                keycloak_sub = args.get("keycloak_sub")
                debug_mode = args.get("debug_mode", True)
                
                rows = []
                if keycloak_sub:
                    cursor.execute("SELECT userId, username FROM Users WHERE keycloak_sub = ?", (str(keycloak_sub),))
                    rows = cursor.fetchall()
                elif debug_mode:
                    cursor.execute("SELECT userId, username FROM Users WHERE userId = 1")
                    rows = cursor.fetchall()
                
                users = [dict(row) for row in rows]
                result_text = json.dumps(users, indent=4)
                
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": result_text}]
                    }
                }
                
            elif tool_name == "GetUserTransactions":
                userId = args.get("userId")
                if not userId:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": "Missing required parameter 'userId'"}
                    }
                
                cursor.execute("SELECT * FROM Transactions WHERE userId = ?", (str(userId),))
                rows = cursor.fetchall()
                columns = [c[0] for c in cursor.description]
                txs = [dict(zip(columns, row)) for row in rows]
                result_text = json.dumps(txs, indent=4)
                
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": result_text}]
                    }
                }
                
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: {tool_name}"}
                }
        except Exception as e:
            log(f"Error executing tool {tool_name}: {e}")
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32000, "message": str(e)}
            }
        finally:
            conn.close()
            
    elif method in ("initialize", "ping"):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "database-provider", "version": "1.0.0"}
            }
        }
    
    # Notifications or other methods
    return None

def main():
    log("Database MCP server starting...")
    while True:
        line = sys.stdin.readline()
        if not line:
            log("Stdin reached EOF, exiting.")
            break
        if not line.strip():
            continue
        log(f"Received raw request line: {line.strip()}")
        try:
            req = json.loads(line)
            resp = handle_request(req)
            if resp:
                resp_line = json.dumps(resp) + "\n"
                log(f"Sending response: {resp_line.strip()}")
                sys.stdout.write(resp_line)
                sys.stdout.flush()
        except Exception as e:
            log(f"Error handling line: {e}")

if __name__ == "__main__":
    main()
