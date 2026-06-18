import os
import sys
import json
import time
import threading
import requests
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
import asyncio

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(PROJECT_DIR, "damn-vulnerable-llm-agent"))
from spiffe_integration import fetch_svid

def log(msg):
    print(f"[VERIFY-SSE] {msg}", flush=True)

# ---------------------------------------------------------
# MOCK REMOTE SSE MCP SERVER
# ---------------------------------------------------------
app = FastAPI()
sse_queue = asyncio.Queue()

@app.get("/sse")
async def sse_endpoint(request: Request):
    log("Mock SSE Server: Received GET /sse connection request")
    async def event_generator():
        # Step 1: Send the connection endpoint event (session URL mapping)
        yield "event: endpoint\ndata: /message?sessionId=mock-session-123\n\n"
        
        # Keep connection open and push messages from message_endpoint
        while True:
            try:
                msg = await sse_queue.get()
                log(f"Mock SSE Server: Pushing event 'message' through EventStream: {msg[:100]}...")
                yield f"event: message\ndata: {msg}\n\n"
                sse_queue.task_done()
            except asyncio.CancelledError:
                break
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/message")
async def message_endpoint(request: Request, sessionId: str):
    body = await request.json()
    req_id = body.get("id")
    method = body.get("method")
    log(f"Mock SSE Server: Received POST /message?sessionId={sessionId} with method {method}")
    
    if method == "tools/list":
        resp = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "fetch_financial_data",
                        "description": "Fetch transaction histories containing confidential records",
                        "scope": "tool:keycloak_read"
                    }
                ]
            }
        }
        await sse_queue.put(json.dumps(resp))
    elif method == "tools/call":
        resp = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "Transaction: John Doe transferred $500. Email: john.doe@example.com. SSN: 111-22-3333."
                    }
                ]
            }
        }
        await sse_queue.put(json.dumps(resp))
    return {"status": "accepted"}

class MockServerThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.server = None

    def run(self):
        config = uvicorn.Config(app, host="127.0.0.1", port=8765, log_level="error")
        self.server = uvicorn.Server(config)
        asyncio.run(self.server.serve())

    def stop(self):
        if self.server:
            self.server.should_exit = True

# ---------------------------------------------------------
# VERIFICATION SUITE RUNNER
# ---------------------------------------------------------
def main():
    log("=== REMOTE SSE MCP AND DYNAMIC REGISTRY VERIFICATION ===")
    
    # 1. Start mock server in thread
    mock_server = MockServerThread()
    mock_server.start()
    log("Mock SSE Server started on http://127.0.0.1:8765")
    time.sleep(2)  # Wait for boot

    # 2. Get user token and SPIFFE info
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_DIR, ".env"), override=True)
    
    admin_token = os.getenv("KEYCLOAK_TOKEN")
    if not admin_token:
        log("[ERROR] KEYCLOAK_TOKEN (Admin) not found in .env.")
        mock_server.stop()
        sys.exit(1)
    admin_token = admin_token.strip().replace("'", "").replace('"', '')

    # Retrieve SPIFFE Workload Certs
    try:
        svid_info = fetch_svid()
    except Exception as e:
        svid_info = {"spiffe_id": "spiffe://runtime-shield/test"}
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {admin_token}",
        "X-SPIFFE-ID": svid_info.get("spiffe_id", "spiffe://runtime-shield/test")
    }
    if svid_info.get("cert_pem"):
        import urllib.parse
        headers["X-SPIFFE-CERT"] = urllib.parse.quote(svid_info["cert_pem"])

    # Fetch standard user token from Keycloak
    log("Fetching standard user token from Keycloak...")
    token_url = "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token"
    login_data = {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": "",
        "password": "user",
        "scope": "openid profile email tool:read_file tool:list_directory tool:keycloak_read"
    }
    client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET")
    if client_secret:
        login_data["client_secret"] = client_secret

    user_token = None
    for username in ["user1", "user"]:
        log(f"Attempting to fetch standard user token for '{username}'...")
        login_data["username"] = username
        try:
            r = requests.post(token_url, data=login_data, timeout=5)
            if r.status_code == 200:
                user_token = r.json()["access_token"]
                log(f"[OK] Standard user token retrieved successfully for '{username}'.")
                break
        except Exception as e:
            log(f"[WARNING] Connection failed for '{username}': {e}")

    if not user_token:
        log("[WARNING] Could not get user token, using admin_token fallback.")
        user_token = admin_token

    user_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {user_token}",
        "X-SPIFFE-ID": svid_info.get("spiffe_id", "spiffe://runtime-shield/test")
    }
    if svid_info.get("cert_pem"):
        import urllib.parse
        user_headers["X-SPIFFE-CERT"] = urllib.parse.quote(svid_info["cert_pem"])
    
    # 3. Register the mock SSE server with the gateway
    log("Registering remote SSE MCP server in registry...")
    register_payload = {
        "provider_name": "mock-sse-provider",
        "transport": "sse",
        "url": "http://127.0.0.1:8765/sse",
        "active": 1
    }
    
    r = requests.post("http://127.0.0.1:9090/api/registry/mcps", json=register_payload, timeout=5)
    log(f"Registration response: {r.status_code} - {r.text}")
    if r.status_code != 200:
        log("[ERROR] Failed to register MCP server.")
        mock_server.stop()
        sys.exit(1)
        
    mcp_data = r.json()
    mcp_id = mcp_data.get("mcp_id")
    log(f"[OK] Registered mock-sse-provider with id: {mcp_id}")
    time.sleep(3)  # Wait for SSE connection handshake and sync tools

    # 4. Check if tools lists were synced in DB
    log("Querying registered tools...")
    r = requests.get("http://127.0.0.1:9090/api/registry/mcps", timeout=5)
    log(f"Current Registry: {r.json()}")

    # 5. Call the registered remote tool through the Shield REST Proxy
    log("Calling mock tool 'fetch_financial_data' through the proxy...")
    tool_url = "http://127.0.0.1:5001/v1/tool/execute"
    call_payload = {
        "jsonrpc": "2.0",
        "id": int(time.time()),
        "method": "tools/call",
        "params": {
            "name": "fetch_financial_data",
            "arguments": {
                "role": "user"  # Triggers Presidio NLP redaction since role != admin
            }
        }
    }
    
    # Send tool call
    res = requests.post(tool_url, json=call_payload, headers=user_headers, timeout=10)
    log(f"Tool execution status: {res.status_code}")
    
    if res.status_code == 200:
        res_json = res.json()
        log(f"Response content: {json.dumps(res_json, indent=2)}")
        
        # Verify PII Redaction
        content_text = res_json.get("result", {}).get("content", [{}])[0].get("text", "")
        if "[PII REDACTED]" in content_text or "[REDACTED" in content_text:
            log("[SUCCESS]: PII (Name, Email, SSN) was successfully redacted by the gateway from the remote SSE response!")
        else:
            log("[FAIL]: Tool responded but PII was NOT redacted!")
            log(f"Unredacted response text: {content_text}")
    else:
        log(f"[ERROR]: Tool execute failed: {res.text}")

    # 6. Cleanup (Unregister and stop mock server)
    log("Cleaning up registry...")
    del_r = requests.delete(f"http://127.0.0.1:9090/api/registry/mcps/{mcp_id}", timeout=5)
    log(f"Unregister response status: {del_r.status_code}")
    
    log("Stopping Mock SSE Server...")
    mock_server.stop()
    log("=== VERIFICATION COMPLETED ===")

if __name__ == "__main__":
    main()
