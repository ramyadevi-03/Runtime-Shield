import os
import sys
import json
import time
import requests
import urllib.parse

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(PROJECT_DIR, "damn-vulnerable-llm-agent"))

from spiffe_integration import fetch_svid

def log(msg):
    print(f"[VERIFY] {msg}", flush=True)

def test_tool(url, headers, tool_name, arguments):
    payload = {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }
    log(f"Calling tool '{tool_name}'...")
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        log(f"Status Code: {r.status_code}")
        try:
            res = r.json()
            if "error" in res:
                log(f"[ERROR]: {json.dumps(res['error'], indent=2)}")
            else:
                log(f"[OK]: Response:\n{json.dumps(res.get('result', {}), indent=2)}")
            return res
        except json.JSONDecodeError:
            log(f"[ERROR] Non-JSON Response: {r.text}")
            return None
    except Exception as e:
        log(f"[ERROR] Connection failed: {e}")
        return None

def main():
    log("=== MULTI-MCP SECURITY SHIELD VERIFICATION ===")
    
    # 1. Load dotenv to get KEYCLOAK_TOKEN
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_DIR, ".env"), override=True)
    
    admin_token = os.getenv("KEYCLOAK_TOKEN")
    if not admin_token:
        log("[ERROR] KEYCLOAK_TOKEN (Admin) not found in .env.")
        sys.exit(1)
        
    admin_token = admin_token.strip().replace("'", "").replace('"', '')
    
    # 2. Fetch standard user token from Keycloak
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
            else:
                log(f"[INFO] Failed to fetch user token for '{username}': {r.status_code}")
        except Exception as e:
            log(f"[WARNING] Connection failed for '{username}': {e}")
            
    if not user_token:
        log("[ERROR] Failed to obtain standard user token for user1 or user.")
        sys.exit(1)
    
    # 3. Fetch SPIFFE identity
    log("Retrieving SPIFFE Workload Certs...")
    svid_info = fetch_svid()
    log(f"SPIFFE ID: {svid_info.get('spiffe_id')}")
    
    # 4. Setup headers
    admin_headers = {
        "Content-Type": "application/json",
        "X-Shield-Token": admin_token,
        "Authorization": f"Bearer {admin_token}",
        "X-SPIFFE-ID": svid_info["spiffe_id"]
    }
    
    user_headers = {
        "Content-Type": "application/json",
        "X-Shield-Token": user_token,
        "Authorization": f"Bearer {user_token}",
        "X-SPIFFE-ID": svid_info["spiffe_id"]
    }
    
    if svid_info.get("cert_pem"):
        quoted_cert = urllib.parse.quote(svid_info["cert_pem"])
        admin_headers["X-SPIFFE-CERT"] = quoted_cert
        user_headers["X-SPIFFE-CERT"] = quoted_cert
        
    proxy_url = "http://127.0.0.1:5001/v1/tool/execute"
    
    # --- Case 1: ScanDependencies (general diagnostic, allowed for user role) ---
    log("\n--- TEST CASE 1: ScanDependencies (Allowed to all users) ---")
    test_tool(proxy_url, user_headers, "ScanDependencies", {})
    
    # --- Case 2: GetSystemMetrics (general diagnostic, allowed for user role) ---
    log("\n--- TEST CASE 2: GetSystemMetrics (Allowed to all users) ---")
    test_tool(proxy_url, user_headers, "GetSystemMetrics", {})
    
    # --- Case 3: GetActiveConnections with user token (Should be BLOCKED) ---
    log("\n--- TEST CASE 3: GetActiveConnections with standard user token (Should be BLOCKED) ---")
    res = test_tool(proxy_url, user_headers, "GetActiveConnections", {})
    if res and "error" in res:
        log("[VERIFIED]: User access to GetActiveConnections was blocked successfully by the gateway!")
        
    # --- Case 4: GetActiveConnections with admin token (Should be ALLOWED) ---
    log("\n--- TEST CASE 4: GetActiveConnections with admin token (Should be ALLOWED) ---")
    test_tool(proxy_url, admin_headers, "GetActiveConnections", {})

if __name__ == "__main__":
    main()
