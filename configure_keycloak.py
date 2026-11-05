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

NOTE: On a fresh Keycloak instance, KEYCLOAK_CLIENT_ID may be set to
"runtime-shield-jit" (a confidential, service-account-only client with no
direct access grants). This script needs a client that supports direct
access grants to obtain its own admin token. If you hit:
  [ERROR] Admin token request failed (HTTP 400): unauthorized_client
run this script once with the client temporarily overridden:
  PowerShell: $env:KEYCLOAK_CLIENT_ID = "admin-cli"; python configure_keycloak.py
This only affects the current shell session, not your .env file.
"""
import requests
import os
import sys
import secrets
import urllib3
from dotenv import load_dotenv , set_key

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
DOTENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

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
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?exact=true&username={username}"
    try:
        r = session.request("GET", url, timeout=10)
        if r.status_code != 200:
            print(f"[ERROR] Failed to fetch user '{username}': {r.status_code} {r.text}")
            return

        users = [u for u in r.json() if u.get("username") == username] if isinstance(r.json(), list) else []
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
        "tool:admin_internal",
        "repository:read",
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
            for mapper in r.json():
                if mapper.get("name") == "group-membership":
                    del_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models/{mapper['id']}"
                    session.request("DELETE", del_url, timeout=10)
                    print("[INFO] Deleted old group membership mapper to refresh config")
        
        # Create fresh mapper with correct token/userinfo configs
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
    assign_user_to_group("user1", "Normal-Users")


def configure_jit_exchange_client(session: KeycloakSession):
    """
    Creates the runtime-shield-jit client used by the gateway for JIT token
    exchange (confidential, service-account, Standard Token Exchange enabled),
    grants it the minimum Keycloak roles needed to query users, associates the
    tool:* scopes with it, and adds audience mappers to the Runtime Shield
    requester clients so their tokens can be exchanged for runtime-shield-jit.
    """
    jit_client_id_name = "runtime-shield-jit"
    source_client_ids = list(dict.fromkeys([
        "runtime-shield-cli",
        os.getenv("OPENID_CLIENT_ID", "runtime-shield-librechat"),
        os.getenv("RUNTIME_SHIELD_MCP_CLIENT_ID", "runtime-shield-hitl"),
    ]))
    token_lifespans = {
        **{client_id: "1800" for client_id in source_client_ids},
        jit_client_id_name: "300",
    }

    # 1. Create runtime-shield-jit client if it doesn't exist
    clients_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={jit_client_id_name}"
    try:
        r = session.request("GET", clients_url, timeout=10)
        existing = r.json() if r.status_code == 200 else []
    except Exception as e:
        print(f"[ERROR] Exception checking for '{jit_client_id_name}': {e}")
        return

    if existing:
        jit_uuid = existing[0]["id"]
        print(f"[INFO] Client '{jit_client_id_name}' already exists (UUID: {jit_uuid})")
    else:
        create_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients"
        client_data = {
            "clientId": jit_client_id_name,
            "name": "Runtime Shield JIT Exchange",
            "enabled": True,
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "implicitFlowEnabled": False,
            "protocol": "openid-connect",
            "attributes": {
                "standard.token.exchange.enabled": "true"
            }
        }
        try:
            r = session.request("POST", create_url, json=client_data, timeout=10)
            if r.status_code == 201:
                print(f"[OK] Created client '{jit_client_id_name}'")
            else:
                print(f"[ERROR] Failed to create '{jit_client_id_name}': {r.status_code} {r.text}")
                return
            r = session.request("GET", clients_url, timeout=10)
            existing = r.json() if r.status_code == 200 else []
            if not existing:
                print(f"[ERROR] Could not retrieve '{jit_client_id_name}' after creation")
                return
            jit_uuid = existing[0]["id"]
        except Exception as e:
            print(f"[ERROR] Exception creating '{jit_client_id_name}': {e}")
            return

    # Bind exchanged access tokens to the Runtime Shield JIT audience and
    # gateway workload. Gateway and provider code independently verify both.
    jit_mappers_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{jit_uuid}/protocol-mappers/models"
    jit_mappers = [
        {
            "name": "runtime-shield-jit-audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.client.audience": jit_client_id_name,
                "id.token.claim": "false",
                "access.token.claim": "true",
            },
        },
        {
            "name": "runtime-shield-workload-id",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "config": {
                "claim.name": "workload_id",
                "claim.value": os.getenv("RUNTIME_SHIELD_JIT_WORKLOAD_ID", "spiffe://runtime-shield/bridge"),
                "jsonType.label": "String",
                "id.token.claim": "false",
                "access.token.claim": "true",
                "userinfo.token.claim": "false",
            },
        },
    ]
    try:
        response = session.request("GET", jit_mappers_url, timeout=10)
        existing_mappers = response.json() if response.status_code == 200 else []
        by_name = {item.get("name"): item for item in existing_mappers}
        for mapper in jit_mappers:
            current = by_name.get(mapper["name"])
            if current and current.get("config") == mapper["config"]:
                continue
            if current:
                response = session.request("PUT", f"{jit_mappers_url}/{current['id']}", json=mapper, timeout=10)
            else:
                response = session.request("POST", jit_mappers_url, json=mapper, timeout=10)
            if response.status_code not in (200, 201, 204):
                print(f"[ERROR] Failed to configure JIT token mapper '{mapper['name']}': HTTP {response.status_code}")
                return
        print("[OK] JIT exchanged tokens are audience- and gateway-workload-bound")
    except Exception as e:
        print(f"[ERROR] Exception configuring JIT token mappers: {e}")
        return

    # 2. Write its secret to .env so docker-compose.yml can reference it
    #    as ${RUNTIME_SHIELD_JIT_CLIENT_SECRET} — never hardcode this value,
    #    it's regenerated fresh whenever this client is (re)created.
    try:
        secret_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{jit_uuid}/client-secret"
        r = session.request("GET", secret_url, timeout=10)
        if r.status_code == 200:
            secret = r.json().get("value")
            set_key(DOTENV_PATH, "RUNTIME_SHIELD_JIT_CLIENT_SECRET", secret, quote_mode="never")
            print(f"[OK] Wrote RUNTIME_SHIELD_JIT_CLIENT_SECRET to {DOTENV_PATH}")
        else:
            print(f"[ERROR] Failed to fetch secret for '{jit_client_id_name}': {r.status_code} {r.text}")
    except Exception as e:
        print(f"[ERROR] Exception fetching/writing secret for '{jit_client_id_name}': {e}")

    # 2a. Grant only the user-query roles needed by the Keycloak provider.
    try:
        realm_management = session.request(
            "GET",
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients",
            params={"clientId": "realm-management"},
            timeout=10,
        )
        if realm_management.status_code != 200:
            print(f"[ERROR] Could not find the realm-management client: HTTP {realm_management.status_code}")
            return
        realm_management_clients = realm_management.json()
        if not realm_management_clients and REALM == "master":
            realm_management = session.request(
                "GET",
                f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients",
                params={"clientId": "master-realm"},
                timeout=10,
            )
            realm_management_clients = realm_management.json() if realm_management.status_code == 200 else []
        if not realm_management_clients:
            print(f"[ERROR] Could not find the administrative roles client in realm '{REALM}'")
            return
        realm_management_id = realm_management_clients[0]["id"]

        service_account = session.request(
            "GET",
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{jit_uuid}/service-account-user",
            timeout=10,
        )
        if service_account.status_code != 200:
            print(f"[ERROR] Could not find the '{jit_client_id_name}' service-account user: HTTP {service_account.status_code}")
            return
        service_account_id = service_account.json()["id"]

        assigned = session.request(
            "GET",
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{service_account_id}/role-mappings/clients/{realm_management_id}",
            timeout=10,
        )
        if assigned.status_code != 200:
            print(f"[ERROR] Could not read service-account role mappings: HTTP {assigned.status_code}")
            return
        assigned_names = {role.get("name") for role in assigned.json()}

        roles_to_add = []
        for role_name in ("query-users", "view-users"):
            role_response = session.request(
                "GET",
                f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{realm_management_id}/roles/{role_name}",
                timeout=10,
            )
            if role_response.status_code != 200:
                print(f"[ERROR] Could not find realm-management role '{role_name}': HTTP {role_response.status_code}")
                return
            if role_name not in assigned_names:
                roles_to_add.append(role_response.json())

        if roles_to_add:
            mapping = session.request(
                "POST",
                f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{service_account_id}/role-mappings/clients/{realm_management_id}",
                json=roles_to_add,
                timeout=10,
            )
            if mapping.status_code not in (200, 204):
                print(f"[ERROR] Failed to grant user-query roles: HTTP {mapping.status_code} {mapping.text}")
                return
        print("[OK] JIT service account has the minimum query-users and view-users roles")
    except Exception as e:
        print(f"[ERROR] Exception configuring JIT service-account roles: {e}")

    # 3. Associate tool:* scopes as optional on runtime-shield-jit
    scopes_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/client-scopes"
    try:
        r = session.request("GET", scopes_url, timeout=10)
        existing_scopes = {s["name"]: s["id"] for s in r.json() if "name" in s} if r.status_code == 200 else {}
    except Exception as e:
        print(f"[ERROR] Exception listing client scopes: {e}")
        existing_scopes = {}

    tool_scopes = [
        "tool:read_file", "tool:write_file", "tool:list_directory",
        "tool:keycloak_read", "tool:keycloak_admin", "tool:keycloak_report",
        "tool:admin_internal", "repository:read"
    ]
    for scope_name in tool_scopes:
        scope_uuid = existing_scopes.get(scope_name)
        if not scope_uuid:
            print(f"[WARNING] Scope '{scope_name}' not found — run configure_client_scopes() first")
            continue
        assoc_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{jit_uuid}/optional-client-scopes/{scope_uuid}"
        try:
            r = session.request("PUT", assoc_url, timeout=10)
            if r.status_code in [204, 201, 200]:
                print(f"[OK] Associated scope '{scope_name}' as optional for '{jit_client_id_name}'")
            else:
                print(f"[ERROR] Failed to associate scope '{scope_name}': {r.status_code} {r.text}")
        except Exception as e:
            print(f"[ERROR] Exception associating scope '{scope_name}': {e}")

    # 4. Add an audience mapper to each requester client. Standard Token
    #    Exchange requires the requester to appear in the subject token aud.
    for source_client_id_name in source_client_ids:
        src_clients_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={source_client_id_name}"
        try:
            r = session.request("GET", src_clients_url, timeout=10)
            src_clients = r.json() if r.status_code == 200 else []
            if not src_clients:
                print(f"[WARNING] Client '{source_client_id_name}' not found — skipping audience mapper")
                continue
            src_uuid = src_clients[0]["id"]
        except Exception as e:
            print(f"[ERROR] Exception retrieving '{source_client_id_name}': {e}")
            continue

        repository_scope_uuid = existing_scopes.get("repository:read")
        if repository_scope_uuid:
            scope_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{src_uuid}/optional-client-scopes/{repository_scope_uuid}"
            try:
                scope_response = session.request("PUT", scope_url, timeout=10)
                if scope_response.status_code not in (200, 201, 204):
                    print(f"[ERROR] Failed to add repository:read scope to '{source_client_id_name}'")
                    continue
            except Exception as e:
                print(f"[ERROR] Exception assigning repository:read to '{source_client_id_name}': {e}")
                continue

        mappers_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{src_uuid}/protocol-mappers/models"
        try:
            r = session.request("GET", mappers_url, timeout=10)
            existing_mappers = r.json() if r.status_code == 200 else []
            existing_mapper = next(
                (mapper for mapper in existing_mappers if mapper.get("name") == "jit-audience"),
                None,
            )
            if (
                existing_mapper
                and existing_mapper.get("config", {}).get("included.client.audience")
                == jit_client_id_name
            ):
                print(f"[INFO] 'jit-audience' mapper already exists on '{source_client_id_name}', skipping")
                continue

            mapper_data = {
                "name": "jit-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.client.audience": jit_client_id_name,
                    "id.token.claim": "false",
                    "access.token.claim": "true"
                }
            }
            if existing_mapper:
                mapper_url = f"{mappers_url}/{existing_mapper['id']}"
                r = session.request("PUT", mapper_url, json=mapper_data, timeout=10)
            else:
                r = session.request("POST", mappers_url, json=mapper_data, timeout=10)
            if r.status_code in (200, 201, 204):
                print(f"[OK] Added 'jit-audience' mapper to '{source_client_id_name}'")
            else:
                print(f"[ERROR] Failed to add audience mapper to '{source_client_id_name}': {r.status_code} {r.text}")
        except Exception as e:
            print(f"[ERROR] Exception adding audience mapper to '{source_client_id_name}': {e}")

    # Give the interactive requester token a practical demo lifetime while
    # keeping the downscoped JIT token short-lived for the approval window.
    for token_client_id, token_lifespan in token_lifespans.items():
        clients_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients"
        try:
            r = session.request(
                "GET",
                clients_url,
                params={"clientId": token_client_id},
                timeout=10,
            )
            clients = r.json() if r.status_code == 200 else []
            if not clients:
                print(f"[WARNING] Client '{token_client_id}' not found — skipping token lifespan")
                continue

            client = clients[0]
            attributes = client.setdefault("attributes", {})
            if attributes.get("access.token.lifespan") == token_lifespan:
                print(
                    f"[INFO] '{token_client_id}' access-token lifespan is already "
                    f"{token_lifespan} seconds"
                )
                continue

            attributes["access.token.lifespan"] = token_lifespan
            update = session.request(
                "PUT",
                f"{clients_url}/{client['id']}",
                json=client,
                timeout=10,
            )
            if update.status_code in (200, 204):
                print(
                    f"[OK] Set '{token_client_id}' access-token lifespan to "
                    f"{token_lifespan} seconds"
                )
            else:
                print(
                    f"[ERROR] Failed to set '{token_client_id}' access-token lifespan: "
                    f"{update.status_code} {update.text}"
                )
        except Exception as e:
            print(f"[ERROR] Exception configuring '{token_client_id}' token lifespan: {e}")


def configure_frontend_url(session: KeycloakSession):
    """
    Sets the realm's Frontend URL to the public Keycloak URL shared by
    LibreChat and Runtime Shield.
    This is required so tokens issued to external callers (e.g. login.py on
    the host) carry an issuer that internally-issued JIT-exchanged tokens
    also match — otherwise downstream token verification fails with an
    issuer mismatch, since Keycloak dev mode derives the issuer from the
    Host header of whichever hostname reached it (host vs internal Docker
    network) unless Frontend URL pins it to one fixed value.
    """
    frontend_url = os.getenv("KEYCLOAK_PUBLIC_URL", KEYCLOAK_URL).rstrip("/")
    realm_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}"
    try:
        r = session.request("GET", realm_url, timeout=10)
        if r.status_code != 200:
            raise RuntimeError(f"Could not fetch realm representation: HTTP {r.status_code}")
        realm_rep = r.json()
    except Exception as e:
        raise RuntimeError(f"Could not fetch realm representation: {e}") from e

    current = realm_rep.get("attributes", {}).get("frontendUrl", "")
    if current == frontend_url:
        print(f"[INFO] Frontend URL already set to '{frontend_url}'")
        return

    if "attributes" not in realm_rep or realm_rep["attributes"] is None:
        realm_rep["attributes"] = {}
    realm_rep["attributes"]["frontendUrl"] = frontend_url

    try:
        r = session.request("PUT", realm_url, json=realm_rep, timeout=10)
        if r.status_code in [200, 204]:
            print(f"[OK] Set realm Frontend URL to '{frontend_url}'")
        else:
            raise RuntimeError(f"Failed to set realm Frontend URL: HTTP {r.status_code}")
    except Exception as e:
        raise RuntimeError(f"Could not set realm Frontend URL: {e}") from e

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


def _get_client(session: KeycloakSession, client_id: str) -> dict | None:
    response = session.request(
        "GET",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients",
        params={"clientId": client_id},
        timeout=10,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Could not inspect Keycloak client '{client_id}': HTTP {response.status_code}")
    clients = response.json()
    return clients[0] if clients else None


def _ensure_group_mapper(session: KeycloakSession, client: dict) -> None:
    client_id = client["clientId"]
    mappers_url = (
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/"
        f"{client['id']}/protocol-mappers/models"
    )
    response = session.request("GET", mappers_url, timeout=10)
    if response.status_code != 200:
        raise RuntimeError(f"Could not inspect mappers for '{client_id}': HTTP {response.status_code}")

    expected = {
        "name": "runtime-shield-groups",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-group-membership-mapper",
        "config": {
            "full.path": "false",
            "claim.name": "groups",
            "access.token.claim": "true",
            "id.token.claim": "true",
            "userinfo.token.claim": "true",
        },
    }
    existing = next(
        (mapper for mapper in response.json() if mapper.get("name") == expected["name"]),
        None,
    )
    if existing:
        if (
            existing.get("protocolMapper") != expected["protocolMapper"]
            or any(
                existing.get("config", {}).get(key) != value
                for key, value in expected["config"].items()
            )
        ):
            raise RuntimeError(
                f"'{client_id}' already has an incompatible '{expected['name']}' mapper; "
                "no existing mapper was changed."
            )
        print(f"[INFO] Group claims already enabled for '{client_id}'")
        return

    response = session.request("POST", mappers_url, json=expected, timeout=10)
    if response.status_code != 201:
        raise RuntimeError(
            f"Could not add group claims mapper to '{client_id}': "
            f"HTTP {response.status_code} {response.text}"
        )
    print(f"[OK] Added group claims mapper to '{client_id}'")


def _ensure_realm_roles_scope(session: KeycloakSession, client: dict) -> None:
    client_id = client["clientId"]
    scopes_url = (
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/"
        f"{client['id']}/default-client-scopes"
    )
    response = session.request("GET", scopes_url, timeout=10)
    if response.status_code != 200:
        raise RuntimeError(f"Could not inspect default scopes for '{client_id}': HTTP {response.status_code}")
    if any(scope.get("name") == "roles" for scope in response.json()):
        return

    scopes_response = session.request(
        "GET",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/client-scopes",
        params={"search": "roles"},
        timeout=10,
    )
    if scopes_response.status_code != 200:
        raise RuntimeError(
            f"Could not find the Keycloak 'roles' client scope: HTTP {scopes_response.status_code}"
        )
    roles_scope = next(
        (scope for scope in scopes_response.json() if scope.get("name") == "roles"),
        None,
    )
    if not roles_scope:
        raise RuntimeError("The Keycloak 'roles' client scope does not exist.")

    response = session.request(
        "PUT",
        f"{scopes_url}/{roles_scope['id']}",
        timeout=10,
    )
    if response.status_code not in (200, 204):
        raise RuntimeError(f"Could not add realm-role claims to '{client_id}': HTTP {response.status_code}")
    print(f"[OK] Enabled realm-role claims for '{client_id}'")


def configure_librechat_oidc_client(session: KeycloakSession) -> None:
    """Create a dedicated OIDC browser-login client without changing Runtime Shield clients."""
    client_id = os.getenv("OPENID_CLIENT_ID", "runtime-shield-librechat")
    redirect_uri = "http://localhost:3080/oauth/openid/callback"
    client = _get_client(session, client_id)

    if client is None:
        create_response = session.request(
            "POST",
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients",
            json={
                "clientId": client_id,
                "name": "Runtime Shield LibreChat Login",
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "standardFlowEnabled": True,
                "implicitFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": False,
                "redirectUris": [redirect_uri],
                "webOrigins": ["http://localhost:3080"],
                "attributes": {
                    "post.logout.redirect.uris": "http://localhost:3080/login",
                },
            },
            timeout=10,
        )
        if create_response.status_code != 201:
            raise RuntimeError(
                f"Could not create the dedicated LibreChat OIDC client: "
                f"HTTP {create_response.status_code} {create_response.text}"
            )
        client = _get_client(session, client_id)
        if client is None:
            raise RuntimeError("The LibreChat OIDC client was created but could not be retrieved.")
        print(f"[OK] Created dedicated Keycloak OIDC client '{client_id}'")
    elif (
        client.get("protocol") != "openid-connect"
        or client.get("publicClient") is not False
        or client.get("standardFlowEnabled") is not True
        or redirect_uri not in client.get("redirectUris", [])
    ):
        raise RuntimeError(
            f"Keycloak client '{client_id}' exists but does not match the LibreChat OIDC setup. "
            "It was left unchanged."
        )
    else:
        print(f"[INFO] Existing dedicated LibreChat OIDC client '{client_id}' is configured")

    attributes = client.get("attributes") or {}
    logout_redirect_uri = "http://localhost:3080/login"
    if attributes.get("post.logout.redirect.uris") != logout_redirect_uri:
        attributes["post.logout.redirect.uris"] = logout_redirect_uri
        client["attributes"] = attributes
        update_response = session.request(
            "PUT",
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{client['id']}",
            json=client,
            timeout=10,
        )
        if update_response.status_code not in (200, 204):
            raise RuntimeError(
                f"Could not configure the LibreChat post-logout redirect URI: "
                f"HTTP {update_response.status_code}"
            )
        print(f"[OK] Configured LibreChat post-logout redirect URI '{logout_redirect_uri}'")

    _ensure_realm_roles_scope(session, client)
    _ensure_group_mapper(session, client)

    mcp_client_id = os.getenv("RUNTIME_SHIELD_MCP_CLIENT_ID", "runtime-shield-hitl")
    mcp_client = _get_client(session, mcp_client_id)
    if mcp_client is None:
        raise RuntimeError(
            f"Runtime Shield MCP OAuth client '{mcp_client_id}' was not found; "
            "no Runtime Shield/JIT client was created or overwritten."
        )
    _ensure_realm_roles_scope(session, mcp_client)
    _ensure_group_mapper(session, mcp_client)

    secret_response = session.request(
        "GET",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{client['id']}/client-secret",
        timeout=10,
    )
    if secret_response.status_code != 200 or not secret_response.json().get("value"):
        raise RuntimeError(
            f"Could not retrieve the LibreChat client secret: HTTP {secret_response.status_code}"
        )

    public_url = os.getenv(
        "KEYCLOAK_PUBLIC_URL",
        "https://host.docker.internal:8443",
    ).rstrip("/")
    env_values = {
        "KEYCLOAK_PUBLIC_URL": public_url,
        "KEYCLOAK_ISSUER_URL": public_url,
        "OPENID_ISSUER": f"{public_url}/realms/{REALM}",
        "OPENID_CLIENT_ID": client_id,
        "OPENID_CLIENT_SECRET": secret_response.json()["value"],
    }
    if not os.getenv("OPENID_SESSION_SECRET"):
        env_values["OPENID_SESSION_SECRET"] = secrets.token_urlsafe(48)
    for key, value in env_values.items():
        set_key(DOTENV_PATH, key, value, quote_mode="never")
    print(f"[OK] Updated OIDC environment values in {DOTENV_PATH}; secret values were not printed")


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

    # Configure the JIT exchange client (runtime-shield-jit) and audience mapper
    configure_jit_exchange_client(session)
    configure_frontend_url(session)

    # Set passwords for the configured realm users from environment
    user_pass = os.getenv("KEYCLOAK_USER_PASSWORD")
    if not user_pass:
        print("[ERROR] KEYCLOAK_USER_PASSWORD is not set in .env — skipping user password updates.")
        sys.exit(1)

    update_user(session, "admin", "admin", "admin")
    update_user(session, "user", user_pass, "user")
    update_user(session, "privileged", user_pass, "user")
    update_user(session, "user1", user_pass, "user")

    # Configure Groups and Mappers
    configure_groups_and_mappers(session)

    # Configure Trusted Identity Providers for XAA
    configure_trusted_idps(session)

    print("\n[OK] Keycloak setup complete.")


def configure_jit_exchange_only():
    """Configure only the JIT exchange client without changing user passwords."""
    global CLIENT_ID, CLIENT_SECRET

    if CLIENT_ID == "runtime-shield-jit":
        CLIENT_ID = os.getenv("KEYCLOAK_SETUP_CLIENT_ID", "admin-cli")
        CLIENT_SECRET = None

    session = KeycloakSession()
    if not session.token:
        print("[ERROR] Could not acquire a Keycloak admin token. No JIT changes were made.")
        sys.exit(1)

    configure_jit_exchange_client(session)
    print("\n[OK] Keycloak JIT exchange setup complete.")


def configure_librechat_oidc_only():
    """Configure only LibreChat login; do not rewrite demo-user passwords."""
    global CLIENT_ID, CLIENT_SECRET

    if CLIENT_ID == "runtime-shield-jit":
        CLIENT_ID = os.getenv("KEYCLOAK_SETUP_CLIENT_ID", "admin-cli")
        CLIENT_SECRET = None
    os.environ.setdefault(
        "KEYCLOAK_PUBLIC_URL",
        "https://host.docker.internal:8443",
    )

    session = KeycloakSession()
    if not session.token:
        print("[ERROR] Could not acquire a Keycloak admin token. No OIDC changes were made.")
        sys.exit(1)

    configure_librechat_oidc_client(session)
    configure_frontend_url(session)
    print("\n[OK] LibreChat OIDC setup complete.")


if __name__ == "__main__":
    if "--jit-only" in sys.argv[1:]:
        configure_jit_exchange_only()
    elif "--librechat-oidc-only" in sys.argv[1:]:
        configure_librechat_oidc_only()
    else:
        main()
