import sys
import json
import os

def log(msg):
    import re
    msg_str = str(msg)
    # Match JWT tokens starting with eyJ and replace the middle part with a placeholder
    jwt_pattern = r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\b'
    def replace_token(match):
        token = match.group(0)
        if len(token) > 30:
            return f"{token[:15]}...[TRUNCATED_JWT]...{token[-15:]}"
        return token
    msg_str = re.sub(jwt_pattern, replace_token, msg_str)
    print(f"[system-monitor-provider] {msg_str}", file=sys.stderr, flush=True)

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
                        "name": "GetSystemMetrics",
                        "description": "Returns basic host system health metrics (CPU, memory, disk).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    },
                    {
                        "name": "GetActiveConnections",
                        "description": "Returns active TCP network connections (admin only diagnostic tool).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    }
                ]
            }
        }
        
    elif method in ("tools/call", "callTool"):
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})
        
        try:
            if tool_name == "GetSystemMetrics":
                metrics = {
                    "cpu_usage_pct": 14.5,
                    "memory_usage_pct": 68.2,
                    "disk_usage_pct": 42.1,
                    "system_uptime_seconds": 86400 * 3 + 1200,
                    "status": "Healthy"
                }
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(metrics, indent=4)}]
                    }
                }
                
            elif tool_name == "GetActiveConnections":
                connections = [
                    {"protocol": "TCP", "local_address": "127.0.0.1:5001", "remote_address": "127.0.0.1:64532", "state": "ESTABLISHED"},
                    {"protocol": "TCP", "local_address": "127.0.0.1:9090", "remote_address": "127.0.0.1:64533", "state": "ESTABLISHED"},
                    {"protocol": "TCP", "local_address": "127.0.0.1:8080", "remote_address": "0.0.0.0:0", "state": "LISTENING"}
                ]
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(connections, indent=4)}]
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
            
    elif method in ("initialize", "ping"):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "system-monitor-provider", "version": "1.0.0"}
            }
        }
    return None

def main():
    log("System Monitor MCP server starting...")
    while True:
        line = sys.stdin.readline()
        if not line:
            log("Stdin reached EOF, exiting.")
            break
        if not line.strip():
            continue
        try:
            req = json.loads(line)
            resp = handle_request(req)
            if resp:
                resp_line = json.dumps(resp) + "\n"
                sys.stdout.write(resp_line)
                sys.stdout.flush()
        except Exception as e:
            log(f"Error handling line: {e}")

if __name__ == "__main__":
    main()
