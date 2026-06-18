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
    print(f"[scanner-provider] {msg_str}", file=sys.stderr, flush=True)

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
                        "name": "ScanDependencies",
                        "description": "Scans requirements.txt and package.json for known vulnerabilities.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    },
                    {
                        "name": "ScanSecrets",
                        "description": "Scans workspace directory for leaked secrets or API keys.",
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
            if tool_name == "ScanDependencies":
                # Simulated dependency scan
                scan_results = {
                    "vulnerabilities_found": 1,
                    "vulnerabilities": [
                        {
                            "package": "urllib3",
                            "installed_version": "1.26.5",
                            "fixed_version": "1.26.18",
                            "severity": "medium",
                            "description": "CVE-2023-43804: Request header leakage on redirect"
                        }
                    ],
                    "status": "Vulnerable packages detected"
                }
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(scan_results, indent=4)}]
                    }
                }
                
            elif tool_name == "ScanSecrets":
                # Simulated secrets scan
                scan_results = {
                    "secrets_found": 0,
                    "files_scanned": 12,
                    "findings": [],
                    "status": "Clean"
                }
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(scan_results, indent=4)}]
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
                "serverInfo": {"name": "scanner-provider", "version": "1.0.0"}
            }
        }
    return None

def main():
    log("Scanner MCP server starting...")
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
