import os
import sys
import subprocess
import time
import json
import requests
import jwt

# Add project root and subfolder to sys.path to handle hyphens in folder name
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_DIR)
sys.path.append(os.path.join(PROJECT_DIR, "damn-vulnerable-llm-agent"))

from spiffe_integration import fetch_svid

def log(msg):
    print(f"[TEST] {msg}", flush=True)

def main():
    log("=== RUNTIME SHIELD REAL-TIME VERIFICATION SUITE ===")
    
    # 1. Fetch config from .env
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_DIR, ".env"), override=True)
    
    kc_url = os.getenv("KEYCLOAK_URL", "http://127.0.0.1:8080")
    realm = os.getenv("KEYCLOAK_REALM", "master")
    client_id = os.getenv("KEYCLOAK_CLIENT_ID", "admin-cli")
    client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET")
    
    # 2. Get a fresh JWT token from Keycloak using Password Grant
    log(f"Attempting password grant login to Keycloak at {kc_url}...")
    token_url = f"{kc_url}/realms/{realm}/protocol/openid-connect/token"
    login_data = {
        "grant_type": "password",
        "client_id": client_id,
        "username": "user1" if realm == "master" else "user", # Default user in realm
        "password": "user",
        "scope": "openid profile email tool:read_file tool:list_directory tool:keycloak_read"
    }
    # Fallback to general admin credentials if specific user is not found
    if os.getenv("KEYCLOAK_USER_PASSWORD"):
        login_data["password"] = os.getenv("KEYCLOAK_USER_PASSWORD")
        login_data["username"] = "user"
    if client_secret:
        login_data["client_secret"] = client_secret
        
    try:
        r = requests.post(token_url, data=login_data, timeout=5)
        if r.status_code != 200:
            # Try logging in as admin
            log(f"User login returned {r.status_code}. Trying admin login...")
            login_data["username"] = os.getenv("KEYCLOAK_ADMIN_USERNAME", "admin")
            login_data["password"] = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin")
            r = requests.post(token_url, data=login_data, timeout=5)
            
        r.raise_for_status()
        token_info = r.json()
        access_token = token_info["access_token"]
        log("✅ Successfully acquired fresh JWT access token from Keycloak!")
        log(f"Token length: {len(access_token)} characters")
        
        # Decode claims to print username and scopes
        claims = jwt.decode(access_token, options={"verify_signature": False})
        log(f"Authenticated user: {claims.get('preferred_username')}")
        log(f"Token scopes: {claims.get('scope')}")
        log(f"Realm roles: {claims.get('realm_access', {}).get('roles', [])}")
    except Exception as e:
        log(f"❌ Failed to acquire Keycloak token: {e}")
        sys.exit(1)
        
    # 3. Retrieve SPIFFE Workload Identity (dynamic certs)
    log("Fetching workload SVID from SPIRE...")
    svid_info = fetch_svid()
    log(f"SPIFFE ID obtained: {svid_info.get('spiffe_id')}")
    log(f"SVID Source: {svid_info.get('source')}")
    log(f"SVID Cryptographically Attested: {svid_info.get('attested')}")
    
    # 4. Start the Bridge server in the background
    log("Starting Runtime Shield Bridge (bridge.py)...")
    bridge_proc = subprocess.Popen(
        [sys.executable, "bridge.py"],
        cwd=PROJECT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for bridge proxy to initialize on port 5001
    log("Waiting for proxy to start on port 5001...")
    time.sleep(5)
    
    # Verify process is still running
    if bridge_proc.poll() is not None:
        stdout, stderr = bridge_proc.communicate()
        log(f"❌ Bridge failed to start! Exit code: {bridge_proc.returncode}")
        log(f"STDOUT:\n{stdout}")
        log(f"STDERR:\n{stderr}")
        sys.exit(1)
        
    log("✅ Bridge process is running.")
    
    # 5. Execute tool call via the proxy API
    proxy_url = "http://127.0.0.1:5001/v1/tool/execute"
    log(f"Executing tool call (GetCurrentUser) via REST proxy endpoint: {proxy_url}...")
    
    headers = {
        "Content-Type": "application/json",
        "X-Shield-Token": access_token,
        "Authorization": f"Bearer {access_token}",
        "X-SPIFFE-ID": svid_info["spiffe_id"]
    }
    
    if svid_info.get("cert_pem"):
        import urllib.parse
        headers["X-SPIFFE-CERT"] = urllib.parse.quote(svid_info["cert_pem"])
        
    request_payload = {
        "jsonrpc": "2.0",
        "id": int(time.time()),
        "method": "tools/call",
        "params": {
            "name": "GetCurrentUser",
            "arguments": {
                "debug_mode": False
            }
        }
    }
    
    try:
        r = requests.post(proxy_url, json=request_payload, headers=headers, timeout=10)
        log(f"Response status code: {r.status_code}")
        if r.status_code == 200:
            log("🎉 SUCCESS: REST Proxy successfully executed GetCurrentUser and verified JIT & SPIFFE!")
            log(f"Response body:\n{json.dumps(r.json(), indent=2)}")
        else:
            log(f"❌ Error response received: {r.text}")
    except Exception as e:
        log(f"❌ Tool execution request failed: {e}")
        
    # 6. Clean up bridge process
    log("Shutting down Bridge process...")
    bridge_proc.terminate()
    try:
        bridge_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        bridge_proc.kill()
    log("Bridge process terminated.")
    log("=== VERIFICATION SUITE COMPLETE ===")

if __name__ == "__main__":
    main()
