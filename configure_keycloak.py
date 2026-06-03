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
            print(f"✅ Created user '{username}'")
        else:
            print(f"❌ Failed to create user '{username}': {r.status_code} {r.text}")
        return

    pass_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/reset-password"
    pass_data = {"type": "password", "value": password, "temporary": False}
    r = requests.put(pass_url, json=pass_data, headers=headers, timeout=10)
    if r.status_code == 204:
        print(f"✅ Password updated for '{username}'")
    else:
        print(f"❌ Failed to update password for '{username}': {r.status_code} {r.text}")


def main():
    print("--- Keycloak Setup Utility ---")
    print(f"  URL:   {KEYCLOAK_URL}")
    print(f"  Realm: {REALM}")
    print(f"  Admin: {ADMIN_USER}")
    print()

    token = get_admin_token()
    if not token:
        print("❌ Could not acquire admin token. Aborting setup.")
        sys.exit(1)

    # Set passwords for the configured realm users from environment
    # KEYCLOAK_USER_PASSWORD must be defined or this will abort.
    user_pass = os.getenv("KEYCLOAK_USER_PASSWORD")
    if not user_pass:
        print("❌ KEYCLOAK_USER_PASSWORD is not set in .env — skipping user password updates.")
        sys.exit(1)

    update_user(token, "admin", ADMIN_PASS)
    update_user(token, "user", user_pass)

    print("\n✅ Keycloak setup complete.")


if __name__ == "__main__":
    main()
