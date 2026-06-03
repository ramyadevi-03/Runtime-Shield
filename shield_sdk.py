import json
import logging
import time
import sys
import os
import requests
import urllib.parse

# Ensure terminal standard streams handle UTF-8/emojis correctly on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

class ShieldStub:
    """
    Client SDK for integrating chatbots with the Secure Runtime Shield.
    Wraps tool calls and delegates execution to the sandboxed Bridge REST endpoint.
    """
    def __init__(self, tenant_id: str, dashboard_url: str = "http://127.0.0.1:9090"):
        self.tenant_id = tenant_id
        self.dashboard_url = dashboard_url
        self.proxy_url = os.getenv("SHIELD_PROXY_URL", "http://127.0.0.1:5001/v1/tool/execute")
        print(f"🛡️ [Shield SDK] Initialized for Tenant: {self.tenant_id}")
        
    def call_tool(self, tool_name: str, args: dict, sso_token: str = None, spiffe_id: str = None, cert_pem: str = None) -> dict:
        """
        Wraps a tool execution request, injecting identity and sending it to the Shield Bridge.
        """
        print(f"🛡️ [Shield SDK] Routing '{tool_name}' through Secure Bridge REST Endpoint...")
        
        # 1. Prepare MCP-compliant JSON-RPC request
        request_id = int(time.time() * 1000)
        request_payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args,
                "metadata": {}
            }
        }
        
        # 2. Build headers (JWT + SPIFFE identity)
        headers = {
            "Content-Type": "application/json"
        }
        
        token = sso_token or os.getenv("KEYCLOAK_TOKEN")
        if token:
            # Clean quotes if any
            token = token.strip().replace("'", "").replace('"', '')
            headers["X-Shield-Token"] = token
            headers["Authorization"] = f"Bearer {token}"
            
        spiffe_id_val = spiffe_id or os.getenv("SPIFFE_LLM_ID", "spiffe://runtime-shield/llm-agent")
        headers["X-SPIFFE-ID"] = spiffe_id_val
        
        if cert_pem:
            headers["X-SPIFFE-CERT"] = urllib.parse.quote(cert_pem)
            
        # 3. Synchronously POST to the Bridge's execution API
        try:
            print(f"🛡️ [Shield SDK] Dispatching payload to {self.proxy_url} for verification...")
            resp = requests.post(self.proxy_url, json=request_payload, headers=headers, timeout=30)
            
            if resp.status_code == 403:
                # Firewall Block or RBAC Block
                err_data = resp.json()
                reason = err_data.get("error", "Access Denied by Firewall policy")
                raise PermissionError(f"Security Violation: {reason}")
            elif resp.status_code == 400:
                # Jailbreak or Safety Block
                err_data = resp.json()
                reason = err_data.get("error", "Blocked by safety guardrails")
                raise ValueError(f"Safety Block: {reason}")
            elif resp.status_code != 200:
                raise RuntimeError(f"Bridge tool execution failed (HTTP {resp.status_code}): {resp.text}")
                
            json_rpc_resp = resp.json()
            if "error" in json_rpc_resp:
                err_msg = json_rpc_resp["error"].get("message", "Unknown error")
                raise PermissionError(f"Security Exception: {err_msg}")
                
            # Expose standard output content block mapping back to ReAct agent
            result = json_rpc_resp.get("result", {})
            content_list = result.get("content", [])
            
            # Extract and return the raw text result from the MCP sandboxed stdout
            if content_list and isinstance(content_list, list):
                raw_text = content_list[0].get("text", "")
                return {
                    "status": "success",
                    "request_id": request_id,
                    "result": raw_text
                }
                
            return {
                "status": "success",
                "request_id": request_id,
                "result": ""
            }
            
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Failed to communicate with Shield Bridge: {e}")
