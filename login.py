import os
import sys
import webbrowser
import requests
import time
import json
import socket
from urllib.parse import urlencode, urljoin, parse_qs, urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from dotenv import load_dotenv, set_key

# Fix console encoding for emojis on Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

# Load environment
DOTENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
# 🏠 Synchronize with the main project folder
MAIN_DOTENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

load_dotenv(DOTENV_PATH, override=True)


KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
REALM = os.getenv("KEYCLOAK_REALM")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")

if not all([KEYCLOAK_URL, REALM, CLIENT_ID]):
    print("\n❌ Error: Missing mandatory Keycloak environment configuration.")
    print("Please verify that your .env contains: KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID.")
    sys.exit(1)

REDIRECT_URI = "http://localhost:18080/callback"


# Global to store the auth code
auth_code = None

class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global auth_code
        query = urlparse(self.path).query
        params = parse_qs(query)
        
        if self.path.startswith("/callback"):
            print(f"DEBUG: Callback received at {self.path}")
            if "code" in params:
                auth_code = params["code"][0]
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body style='font-family:sans-serif;text-align:center;padding-top:50px;'>")
                self.wfile.write(b"<h1 style='color:#2ecc71;'>Success!</h1>")
                self.wfile.write(b"<p>Authentication code captured. You can close this tab and return to the terminal.</p></body></html>")
            else:
                print(f"ERROR: No code in redirect. Full parameters: {params}")
                self.send_response(400)
                self.end_headers()
                error_msg = f"Error: No code found in Keycloak redirect. Params: {params}".encode()
                self.wfile.write(error_msg)

        else:
            # Handle favicon or other requests silently
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return 

def save_and_resolve(access_token):
    if not access_token:
        return
    
    set_key(DOTENV_PATH, "KEYCLOAK_TOKEN", access_token)
    if os.path.exists(MAIN_DOTENV_PATH):
        set_key(MAIN_DOTENV_PATH, "KEYCLOAK_TOKEN", access_token)
    print(f"Token saved to BOTH .env files (Sync Active)")
    
    import jwt
    try:
        decoded = jwt.decode(access_token, options={"verify_signature": False})
        roles = decoded.get("realm_access", {}).get("roles", [])
        resource_roles = []
        for res in decoded.get("resource_access", {}).values():
            resource_roles.extend(res.get("roles", []))
            
        scopes = decoded.get("scope", "").split()
        all_claims = list(set(roles + resource_roles + scopes))
        print(f"DEBUG: All claims found in token: {all_claims}")
        
        # Determine role based on the token's preferred_username claim
        preferred = decoded.get('preferred_username', '').lower()
        role = 'admin' if preferred == 'admin' else 'user'
        
        # The runtime role is derived from the token; avoid overwriting it.
        # set_key(DOTENV_PATH, "RUNTIME_ROLE", role)
        # if os.path.exists(MAIN_DOTENV_PATH):
        #     set_key(MAIN_DOTENV_PATH, "RUNTIME_ROLE", role)
        print(f"Identity Resolved: {decoded.get('preferred_username', 'Unknown')} (Role: {role})")
        print("\nSUCCESS: You are now dynamically authenticated.")
        print("You can now RESTART Claude Desktop.")
    except Exception as e:
        print(f"Could not resolve identity: {e}")

def _require_dev_mode(flow_name: str) -> bool:
    """Gate insecure flows to LOCAL_DEV_MODE=true only. Returns True if allowed."""
    if os.getenv("LOCAL_DEV_MODE", "false").strip().lower() != "true":
        print(f"\n❌ [{flow_name}] DISABLED: This flow is only available when LOCAL_DEV_MODE=true.")
        print("   In production, use Browser Login (Authorization Code + PKCE) only.")
        return False
    print(f"\n⚠️  [DEV ONLY] {flow_name} enabled because LOCAL_DEV_MODE=true.")
    print("   WARNING: This flow must NOT be used in production environments.")
    return True

def manual_login():
    # DEV ONLY: Password grant is insecure for production.
    # Use Authorization Code flow (Browser Login) for production.
    if not _require_dev_mode("Manual Login (Password Grant)"):
        return

    print("\n--- Manual Login (DEV ONLY — Password Grant) ---")
    username = input("Username: ")
    password = input("Password: ")
    
    token_url = urljoin(KEYCLOAK_URL, f"realms/{REALM}/protocol/openid-connect/token")
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": username,
        "password": password,
        "scope": "openid profile email tool:read_file tool:write_file tool:list_directory tool:keycloak_read tool:keycloak_admin tool:keycloak_report tool:admin_internal"
    }
    
    client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET")
    if client_secret:
        data["client_secret"] = client_secret
        
    try:
        response = requests.post(token_url, data=data)
        if response.status_code == 200:
            save_and_resolve(response.json().get("access_token"))
        else:
            print(f"Login failed: {response.text}")
    except Exception as e:
        print(f"Error connecting to Keycloak: {e}")

def run_login():
    global auth_code
    
    is_dev = os.getenv("LOCAL_DEV_MODE", "false").strip().lower() == "true"
    print("\nSelect login method:")
    print("1. Browser Login (Authorization Code — Recommended)")
    print("2. Manual Login (Password Grant — DEV ONLY)" + ("" if is_dev else " [DISABLED — set LOCAL_DEV_MODE=true]"))
    print("3. Mock Login (Demo Mode — DEV ONLY)" + ("" if is_dev else " [DISABLED — set LOCAL_DEV_MODE=true]"))
    choice = input("[1/2/3]: ")
    
    if choice == "3":
        # DEV ONLY: Mock login creates an unsigned HS256 JWT with synthetic claims.
        # This MUST NOT be used in production.
        if not _require_dev_mode("Mock Login (Demo Mode)"):
            return
        print("\n--- SHIELD-FORCE-ONE Quick Identity Switch (DEV ONLY) ---")
        print("1. Administrator (👑 Full Control)")
        print("1. Keycloak Admin (Global Access)")
        print("2. Standard Researcher (Sandboxed)")
        print("3. Restricted Auditor (No Scopes - Test Layer 1)")
        print("4. Custom Test User (Modified Sandbox - Test Layer 3)")
        choice = input("> ")
        
        if choice == "1":
            user_info = {
                "sub": "admin-123",
                "name": "Security Admin",
                "preferred_username": "admin",
                "roles": ["admin"],
                "scope": "openid email profile files:list files:read keycloak:admin",
                "allowed_paths": ["./"]
            }
        elif choice == "3":
            user_info = {
                "sub": "intruder-456",
                "name": "Scopeless User",
                "preferred_username": "intruder",
                "roles": ["user"],
                "scope": "openid", # Missing files:list scope
                "allowed_paths": ["./secure-experiment-zone"]
            }
        elif choice == "4":
            new_path = input("Enter custom sandbox path (e.g. ./rules): ")
            user_info = {
                "sub": "tester-789",
                "name": "Dynamic Tester",
                "preferred_username": "tester",
                "roles": ["user"],
                "scope": "openid profile files:list",
                "allowed_paths": [new_path]
            }
        else:
            user_info = {
                "sub": "user-456",
                "name": "Standard User",
                "preferred_username": "user",
                "roles": ["user"],
                "scope": "openid profile files:list",
                "allowed_paths": ["./secure-experiment-zone"]
            }
            
        # Create a mock JWT for the bridge to decode
        import jwt
        mock_token = jwt.encode(user_info, "secret", algorithm="HS256")
        
        set_key(DOTENV_PATH, "KEYCLOAK_TOKEN", mock_token)
        if os.path.exists(MAIN_DOTENV_PATH):
            set_key(MAIN_DOTENV_PATH, "KEYCLOAK_TOKEN", mock_token)
            
        role = user_info["preferred_username"]
        set_key(DOTENV_PATH, "RUNTIME_ROLE", role)
        if os.path.exists(MAIN_DOTENV_PATH):
            set_key(MAIN_DOTENV_PATH, "RUNTIME_ROLE", role)
            
        print(f"\nSUCCESS: Identity set to: {role.upper()} (Synced with Claims)")
        print(f"DEBUG: Injected Scopes: {user_info['scope']}")
        print(f"DEBUG: Injected Paths: {user_info['allowed_paths']}")
        return

    if choice == "2":
        manual_login()
        return

    # Check if port 8082 is free
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(('localhost', 18080)) == 0:
            print("Error: Port 18080 is already in use.")
            return

    server = HTTPServer(("0.0.0.0", 18080), CallbackHandler)
    
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email tool:read_file tool:write_file tool:list_directory tool:keycloak_read tool:keycloak_admin tool:keycloak_report tool:admin_internal",
        "redirect_uri": REDIRECT_URI,
        "prompt": "login"
    }

    auth_url = urljoin(KEYCLOAK_URL, f"realms/{REALM}/protocol/openid-connect/auth")
    full_url = f"{auth_url}?{urlencode(params)}"
    
    print(f"\nOpening browser to: {full_url}")
    webbrowser.open(full_url)
    
    print("Waiting for callback on port 18080... (Press Ctrl+C to abort)")
    try:
        # Loop until we get the code, to handle multiple browser requests
        while auth_code is None:
            server.handle_request()
            
        if auth_code:
            print("Code received! Exchanging for token...")
            token_url = urljoin(KEYCLOAK_URL, f"realms/{REALM}/protocol/openid-connect/token")
            data = {
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": auth_code,
                "redirect_uri": REDIRECT_URI
            }
            client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET")
            if client_secret:
                data["client_secret"] = client_secret
                
            response = requests.post(token_url, data=data)
            if response.status_code == 200:
                save_and_resolve(response.json().get("access_token"))
            else:
                print(f"Token exchange failed: {response.text}")
    except KeyboardInterrupt:
        print("\nInterrupted.")

if __name__ == "__main__":
    run_login()
