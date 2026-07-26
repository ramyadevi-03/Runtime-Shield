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
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _require_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        print(f"\n[FATAL] Missing required environment variable '{name}'.")
        print("   Please set it in your .env file before running this setup utility.")
        sys.exit(1)
    return val

KEYCLOAK_URL   = _require_env("KEYCLOAK_URL")
REALM          = _require_env("KEYCLOAK_REALM")
ADMIN_USER     = _require_env("KEYCLOAK_ADMIN_USERNAME")
ADMIN_PASS     = _require_env("KEYCLOAK_ADMIN_PASSWORD")
CLIENT_ID      = _require_env("KEYCLOAK_CLIENT_ID")
CLIENT_SECRET  = os.getenv("KEYCLOAK_CLIENT_SECRET")  # optional for public clients


class KeycloakSession:
    """
    Manages Keycloak admin sessions, automatically acquiring and refreshing
    the admin token if a 401 Unauthorized error is encountered.
    """
    def __init__(self):
        self.token = None
        self.authenticate()

    def authenticate(self):
        """Acquire an admin token via password grant."""
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
            r = requests.post(url, data=data, timeout=10, verify=False)
            if r.status_code == 200:
                self.token = r.json()["access_token"]
                return
            print(f"[ERROR] Admin token request failed (HTTP {r.status_code}): {r.text}")
        except requests.RequestException as e:
            print(f"[ERROR] Connection error while getting admin token: {e}")
        self.token = None

    def get_headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    def request(self, method, url, **kwargs):
        """Perform a request, auto-refreshing token on 401."""
        if not self.token:
            self.authenticate()
            if not self.token:
                raise RuntimeError("Not authenticated")

        kwargs["headers"] = self.get_headers()
        kwargs["verify"] = False
        r = requests.request(method, url, **kwargs)

        if r.status_code == 401:
            print("[INFO] Token expired or unauthorized (401). Attempting token refresh...")
            self.authenticate()
            if not self.token:
                raise RuntimeError("Re-authentication failed")
            kwargs["headers"] = self.get_headers()
            kwargs["verify"] = False
            r = requests.request(method, url, **kwargs)

        return r


def assign_realm_role(session: KeycloakSession, user_id: str, role_name: str):
    """Ensure the realm role exists and is assigned to the user."""
    role_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/roles/{role_name}"
    try:
        r = session.request("GET", role_url, timeout=10)
        if r.status_code != 200:
            # Create the role first if it doesn't exist
            create_role_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/roles"
            session.request("POST", create_role_url, json={"name": role_name}, timeout=10)
            r = session.request("GET", role_url, timeout=10)
            if r.status_code != 200:
                print(f"[ERROR] Failed to create or retrieve role '{role_name}'")
                return
        role_data = r.json()
        
        mapping_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm"
        mapping_data = [{
            "id": role_data["id"],
            "name": role_name
        }]
        r = session.request("POST", mapping_url, json=mapping_data, timeout=10)
        if r.status_code in [200, 204]:
            print(f"[OK] Assigned role '{role_name}' to user ID '{user_id}'")
        else:
            print(f"[ERROR] Failed to map role '{role_name}': {r.status_code} {r.text}")
    except Exception as e:
        print(f"[ERROR] Exception mapping role '{role_name}': {e}")


def update_user(session: KeycloakSession, username: str, password: str, role_name: str = None):
    """Create or update a user's password in the configured realm and map roles."""
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?username={username}"
    try:
        r = session.request("GET", url, timeout=10)
        if r.status_code != 200:
            print(f"[ERROR] Failed to fetch user '{username}': {r.status_code} {r.text}")
            return

        users = r.json()
        if not isinstance(users, list):
            print(f"[ERROR] Invalid response format when fetching user '{username}': {users}")
            return

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
            r = session.request("POST", create_url, json=user_data, timeout=10)
            if r.status_code == 201:
                print(f"[OK] Created user '{username}'")
                # Retrieve the newly created user's ID
                r_get = session.request("GET", url, timeout=10)
                if r_get.status_code == 200 and r_get.json():
                    user_id = r_get.json()[0]["id"]
                else:
                    return
            else:
                print(f"[ERROR] Failed to create user '{username}': {r.status_code} {r.text}")
                return

        pass_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/reset-password"
        pass_data = {"type": "password", "value": password, "temporary": False}
        r = session.request("PUT", pass_url, json=pass_data, timeout=10)
        if r.status_code == 204:
            print(f"[OK] Password updated for '{username}'")
        else:
            print(f"[ERROR] Failed to update password for '{username}': {r.status_code} {r.text}")

        # Map role if specified
        if role_name:
            assign_realm_role(session, user_id, role_name)
    except Exception as e:
        print(f"[ERROR] Exception during user update for '{username}': {e}")


def configure_client_scopes(session: KeycloakSession):
    """Ensure required tool:* scopes exist and are associated as optional client scopes for the client."""
    # 1. Get the client UUID for CLIENT_ID (e.g. admin-cli)
    clients_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={CLIENT_ID}"
    try:
        r = session.request("GET", clients_url, timeout=10)
        if r.status_code != 200:
            print(f"[ERROR] Failed to get client metadata: {r.status_code} {r.text}")
            return
        clients = r.json()
        if not clients or not isinstance(clients, list):
            print(f"[ERROR] Client '{CLIENT_ID}' not found or invalid format in realm '{REALM}'")
            return
        client_uuid = clients[0]["id"]
        print(f"[INFO] Found client '{CLIENT_ID}' with UUID '{client_uuid}'")
    except Exception as e:
        print(f"[ERROR] Exception while retrieving client UUID: {e}")
        return

    # 2. Get existing client scopes
    scopes_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/client-scopes"
    try:
        r = session.request("GET", scopes_url, timeout=10)
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
        scope_uuid = None
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
                r = session.request("POST", create_scope_url, json=scope_data, timeout=10)
                if r.status_code == 201:
                    print(f"[OK] Created client scope '{scope_name}'")
                    # Fetch scopes again to find the newly created UUID
                    r_list = session.request("GET", scopes_url, timeout=10)
                    if r_list.status_code == 200:
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
                r = session.request("PUT", assoc_url, timeout=10)
                if r.status_code in [204, 201, 200]:
                    print(f"[OK] Associated scope '{scope_name}' as optional for client '{CLIENT_ID}'")
                else:
                    print(f"[ERROR] Failed to associate scope '{scope_name}': {r.status_code} {r.text}")
            except Exception as e:
                print(f"[ERROR] Exception while associating scope '{scope_name}': {e}")


def configure_groups_and_mappers(session: KeycloakSession):
    """Ensure groups exist, assign users, and add group membership mapper to the client client."""
    groups = ["Normal-Users", "Privileged-Users", "Administrators"]
    group_ids = {}
    
    # 1. Create groups if they don't exist
    groups_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/groups"
    try:
        r = session.request("GET", groups_url, timeout=10)
        if r.status_code == 200:
            existing_groups = {g["name"]: g["id"] for g in r.json() if "name" in g}
        else:
            existing_groups = {}
    except Exception as e:
        print(f"[ERROR] Failed to list groups: {e}")
        existing_groups = {}

    for gname in groups:
        if gname in existing_groups:
            group_ids[gname] = existing_groups[gname]
            print(f"[INFO] Group '{gname}' already exists (ID: {group_ids[gname]})")
        else:
            try:
                r = session.request("POST", groups_url, json={"name": gname}, timeout=10)
                if r.status_code == 201:
                    print(f"[OK] Created group '{gname}'")
                    r_list = session.request("GET", groups_url, timeout=10)
                    if r_list.status_code == 200:
                        existing_groups = {g["name"]: g["id"] for g in r_list.json() if "name" in g}
                        group_ids[gname] = existing_groups.get(gname)
                else:
                    print(f"[ERROR] Failed to create group '{gname}': {r.status_code} {r.text}")
            except Exception as e:
                print(f"[ERROR] Exception while creating group '{gname}': {e}")

    # 2. Get client UUID
    clients_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={CLIENT_ID}"
    try:
        r = session.request("GET", clients_url, timeout=10)
        if r.status_code != 200:
            print(f"[ERROR] Failed to get client metadata: {r.status_code} {r.text}")
            return
        clients = r.json()
        if not clients or not isinstance(clients, list):
            print(f"[ERROR] Client '{CLIENT_ID}' not found or invalid format")
            return
        client_uuid = clients[0]["id"]
    except Exception as e:
        print(f"[ERROR] Exception retrieving client UUID: {e}")
        return

    # 3. Add Group Membership Mapper to the client
    mappers_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models"
    try:
        r = session.request("GET", mappers_url, timeout=10)
        existing_mappers = []
        if r.status_code == 200:
            existing_mappers = [m["name"] for m in r.json() if "name" in m]
        
        if "group-membership" in existing_mappers:
            print("[INFO] Group membership mapper already exists for client")
        else:
            mapper_data = {
                "name": "group-membership",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-group-membership-mapper",
                "config": {
                    "full.path": "false",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "groups",
                    "userinfo.token.claim": "true"
                }
            }
            r = session.request("POST", mappers_url, json=mapper_data, timeout=10)
            if r.status_code == 201:
                print("[OK] Created group membership mapper for client")
            else:
                print(f"[ERROR] Failed to create group mapper: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[ERROR] Exception creating group mapper: {e}")

    # 4. User mapping function helper
    def assign_user_to_group(username, gname):
        user_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?username={username}"
        try:
            r = session.request("GET", user_url, timeout=10)
            if r.status_code == 200 and r.json():
                user_id = r.json()[0]["id"]
                group_id = group_ids.get(gname)
                if group_id:
                    join_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/groups/{group_id}"
                    r_join = session.request("PUT", join_url, timeout=10)
                    if r_join.status_code in [200, 204]:
                        print(f"[OK] Assigned user '{username}' to group '{gname}'")
                    else:
                        print(f"[ERROR] Failed to assign user '{username}' to group '{gname}': {r_join.status_code} {r_join.text}")
            else:
                print(f"[ERROR] User '{username}' not found for group assignment")
        except Exception as e:
            print(f"[ERROR] Exception assigning user '{username}' to group: {e}")

    # Assign users to their respective groups
    assign_user_to_group("admin", "Administrators")
    assign_user_to_group("admin", "Privileged-Users")
    assign_user_to_group("privileged", "Privileged-Users")
    assign_user_to_group("user", "Normal-Users")


def configure_trusted_idps(session: KeycloakSession):
    """Ensure trusted external Identity Providers are configured in Keycloak."""
    idp_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/identity-provider/instances"
    try:
        r = session.request("GET", idp_url, timeout=10)
        existing_idps = []
        if r.status_code == 200:
            existing_idps = [idp["alias"] for idp in r.json() if "alias" in idp]
        
        idp_alias = "external-idp"
        if idp_alias in existing_idps:
            print(f"[INFO] Identity Provider '{idp_alias}' already exists")
        else:
            idp_data = {
                "alias": idp_alias,
                "displayName": "External IDP (XAA)",
                "providerId": "keycloak-oidc",
                "enabled": True,
                "trustEmail": True,
                "storeToken": True,
                "addReadTokenRoleOnCreate": True,
                "authenticateByDefault": False,
                "linkOnly": False,
                "firstBrokerLoginFlowAlias": "first broker login",
                "config": {
                    "clientId": "external-client",
                    "clientSecret": "external-secret",
                    "tokenUrl": "https://external-idp.example.com/oauth/token",
                    "authorizationUrl": "https://external-idp.example.com/oauth/authorize",
                    "userInfoUrl": "https://external-idp.example.com/oauth/userinfo",
                    "jwksUrl": "https://external-idp.example.com/oauth/jwks",
                    "useJwksUrl": "true"
                }
            }
            r = session.request("POST", idp_url, json=idp_data, timeout=10)
            if r.status_code == 201:
                print(f"[OK] Registered External Identity Provider '{idp_alias}' for XAA support")
            else:
                # Keycloak might be offline or mocked during dev setup; output warning instead of hard crash
                print(f"[WARNING] Could not register Identity Provider '{idp_alias}' (HTTP {r.status_code}): {r.text}")
    except Exception as e:
        print(f"[WARNING] Exception registering Identity Provider: {e}")


def main():
    print("--- Keycloak Setup Utility ---")
    print(f"  URL:   {KEYCLOAK_URL}")
    print(f"  Realm: {REALM}")
    print(f"  Admin: {ADMIN_USER}")
    print()

    session = KeycloakSession()
    if not session.token:
        print("[ERROR] Could not acquire admin token. Aborting setup.")
        sys.exit(1)

    # Configure the client scopes
    configure_client_scopes(session)

    # Set passwords for the configured realm users from environment
    user_pass = os.getenv("KEYCLOAK_USER_PASSWORD")
    if not user_pass:
        print("[ERROR] KEYCLOAK_USER_PASSWORD is not set in .env — skipping user password updates.")
        sys.exit(1)

    update_user(session, "admin", ADMIN_PASS, "admin")
    update_user(session, "user", user_pass, "user")
    update_user(session, "privileged", user_pass, "user")

    # Configure Groups and Mappers
    configure_groups_and_mappers(session)

    # Configure Trusted Identity Providers for XAA
    configure_trusted_idps(session)

    print("\n[OK] Keycloak setup complete.")


if __name__ == "__main__":
    main()

