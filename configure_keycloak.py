"""
configure_keycloak.py — DEV/SETUP UTILITY
==========================================
One-time setup script to configure Keycloak users and realm settings.
This is a SETUP UTILITY and must NOT be called automatically at runtime.

Requires the following environment variables (no hardcoded defaults):
  - KEYCLOAK_URL
  - KEYCLOAK_REALM
  - KEYCLOAK_ADMIN_USERNAME
  - KEYCLOAK_ADMIN_PASSWORD
  - KEYCLOAK_CLIENT_ID
  - KEYCLOAK_CLIENT_SECRET (optional, used if the client is confidential)
"""
import requests
import os
import sys
from dotenv import load_dotenv

load_dotenv()

def _require_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        print(f"\n❌ Fatal: Missing required environment variable '{name}'.")
        print("   Please set it in your .env file before running this setup utility.")
        sys.exit(1)
    return val

KEYCLOAK_URL   = _require_env("KEYCLOAK_URL")
REALM          = _require_env("KEYCLOAK_REALM")
ADMIN_USER     = _require_env("KEYCLOAK_ADMIN_USERNAME")
ADMIN_PASS     = _require_env("KEYCLOAK_ADMIN_PASSWORD")
CLIENT_ID      = _require_env("KEYCLOAK_CLIENT_ID")
CLIENT_SECRET  = os.getenv("KEYCLOAK_CLIENT_SECRET")  # optional for public clients


def get_admin_token() -> str | None:
    """Acquire an admin token via password grant using the configured admin credentials."""
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
    }
    if CLIENT_SECRET:
        data["client_secret"] = CLIENT_SECRET

    try:
        r = requests.post(url, data=data, timeout=10)
        if r.status_code == 200:
            return r.json()["access_token"]
        print(f"❌ Admin token request failed (HTTP {r.status_code}): {r.text}")
    except requests.RequestException as e:
        print(f"❌ Connection error while getting admin token: {e}")
    return None


def update_user(token: str, username: str, password: str):
    """Create or update a user's password in the configured realm."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?username={username}"
    r = requests.get(url, headers=headers, timeout=10)

    users = r.json()
    if users:
        user_id = users[0]["id"]
    else:
        create_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"
        user_data = {
            "username": username,
            "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": password, "temporary": False}]
        }
        r = requests.post(create_url, json=user_data, headers=headers, timeout=10)
        if r.status_code == 201:
            print(f"[OK] Created user '{username}'")
        else:
            print(f"[ERROR] Failed to create user '{username}': {r.status_code} {r.text}")
        return

    pass_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/reset-password"
    pass_data = {"type": "password", "value": password, "temporary": False}
    r = requests.put(pass_url, json=pass_data, headers=headers, timeout=10)
    if r.status_code == 204:
        print(f"[OK] Password updated for '{username}'")
    else:
        print(f"[ERROR] Failed to update password for '{username}': {r.status_code} {r.text}")


def configure_client_scopes(token: str):
    """Ensure required tool:* scopes exist and are associated as optional client scopes for the client."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    # 1. Get the client UUID for CLIENT_ID (e.g. admin-cli)
    clients_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={CLIENT_ID}"
    try:
        r = requests.get(clients_url, headers=headers, timeout=10)
        if r.status_code != 200:
            print(f"[ERROR] Failed to get client metadata: {r.status_code} {r.text}")
            return
        clients = r.json()
        if not clients:
            print(f"[ERROR] Client '{CLIENT_ID}' not found in realm '{REALM}'")
            return
        client_uuid = clients[0]["id"]
        print(f"[INFO] Found client '{CLIENT_ID}' with UUID '{client_uuid}'")
    except Exception as e:
        print(f"[ERROR] Exception while retrieving client UUID: {e}")
        return

    # 2. Get existing client scopes
    scopes_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/client-scopes"
    try:
        r = requests.get(scopes_url, headers=headers, timeout=10)
        if r.status_code != 200:
            print(f"[ERROR] Failed to list client scopes: {r.status_code} {r.text}")
            return
        existing_scopes = {s["name"]: s["id"] for s in r.json() if "name" in s}
    except Exception as e:
        print(f"[ERROR] Exception while listing client scopes: {e}")
        return

    # 3. Scopes we want to configure
    required_scopes = [
        "tool:read_file",
        "tool:write_file",
        "tool:list_directory",
        "tool:keycloak_read",
        "tool:keycloak_admin",
        "tool:keycloak_report",
        "tool:admin_internal"
    ]

    for scope_name in required_scopes:
        if scope_name in existing_scopes:
            scope_uuid = existing_scopes[scope_name]
            print(f"[INFO] Client scope '{scope_name}' already exists (UUID: {scope_uuid})")
        else:
            # Create the scope
            create_scope_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/client-scopes"
            scope_data = {
                "name": scope_name,
                "protocol": "openid-connect",
                "attributes": {
                    "display.on.consent.screen": "true",
                    "consent.screen.text": f"Scope for {scope_name}"
                }
            }
            try:
                r = requests.post(create_scope_url, json=scope_data, headers=headers, timeout=10)
                if r.status_code == 201:
                    print(f"[OK] Created client scope '{scope_name}'")
                    # Fetch scopes again to get the new UUID
                    r_list = requests.get(scopes_url, headers=headers, timeout=10)
                    existing_scopes = {s["name"]: s["id"] for s in r_list.json() if "name" in s}
                    scope_uuid = existing_scopes.get(scope_name)
                else:
                    print(f"[ERROR] Failed to create client scope '{scope_name}': {r.status_code} {r.text}")
                    continue
            except Exception as e:
                print(f"[ERROR] Exception while creating scope '{scope_name}': {e}")
                continue

        # 4. Associate client scope with the client as an optional client scope
        if scope_uuid:
            assoc_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{client_uuid}/optional-client-scopes/{scope_uuid}"
            try:
                r = requests.put(assoc_url, headers=headers, timeout=10)
                if r.status_code in [204, 201, 200]:
                    print(f"[OK] Associated scope '{scope_name}' as optional for client '{CLIENT_ID}'")
                else:
                    print(f"[ERROR] Failed to associate scope '{scope_name}': {r.status_code} {r.text}")
            except Exception as e:
                print(f"[ERROR] Exception while associating scope '{scope_name}': {e}")


def main():
    print("--- Keycloak Setup Utility ---")
    print(f"  URL:   {KEYCLOAK_URL}")
    print(f"  Realm: {REALM}")
    print(f"  Admin: {ADMIN_USER}")
    print()

    token = get_admin_token()
    if not token:
        print("[ERROR] Could not acquire admin token. Aborting setup.")
        sys.exit(1)

    # Configure the client scopes
    configure_client_scopes(token)

    # Set passwords for the configured realm users from environment
    # KEYCLOAK_USER_PASSWORD must be defined or this will abort.
    user_pass = os.getenv("KEYCLOAK_USER_PASSWORD")
    if not user_pass:
        print("[ERROR] KEYCLOAK_USER_PASSWORD is not set in .env — skipping user password updates.")
        sys.exit(1)

    update_user(token, "admin", ADMIN_PASS)
    update_user(token, "user", user_pass)

    print("\n[OK] Keycloak setup complete.")


if __name__ == "__main__":
    main()
