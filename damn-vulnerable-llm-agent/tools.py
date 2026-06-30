# #############################################################
#  🛡️ SECURED TOOL WRAPPERS DELEGATING TO RUNTIME SHIELD GATEWAY
# #############################################################
import os
import sys
import json
from langchain.agents import Tool

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shield_sdk import ShieldStub

# Initialize the central Shield client
shield = ShieldStub(tenant_id="customer-delta-99")

def get_current_user(keycloak_sub: str = "", debug_mode: bool = True, sso_token: str = None, spiffe_id: str = None, cert_pem: str = None):
    """
    Retrieves the current user identity by delegating execution to the sandboxed 
    'database-provider' MCP tool via the central Runtime Shield.
    """
    try:
        args = {"keycloak_sub": keycloak_sub, "debug_mode": debug_mode}
        resp = shield.call_tool(
            tool_name="GetCurrentUser",
            args=args,
            sso_token=sso_token,
            spiffe_id=spiffe_id,
            cert_pem=cert_pem
        )
        return resp.get("result", "[]")
    except Exception as e:
        return f"Security Violation: {e}"

def get_transactions(userId: str, keycloak_sub: str = "", role: str = "user", debug_mode: bool = True, sso_token: str = None, spiffe_id: str = None, cert_pem: str = None):
    """
    Retrieves banking transactions by delegating execution to the sandboxed
    'database-provider' MCP tool via the central Runtime Shield.
    """
    try:
        args = {"userId": str(userId), "keycloak_sub": keycloak_sub, "role": role, "debug_mode": debug_mode}
        resp = shield.call_tool(
            tool_name="GetUserTransactions",
            args=args,
            sso_token=sso_token,
            spiffe_id=spiffe_id,
            cert_pem=cert_pem
        )
        return resp.get("result", "[]")
    except Exception as e:
        # Propagate the block reasons clearly to be picked up by the LangChain UI block parsers
        return f"Security Violation: {e}"

def read_file_with_policy(file_path: str, role: str = "user", sso_token: str = None, spiffe_id: str = None, cert_pem: str = None) -> str:
    """
    Reads project files by delegating execution to the sandboxed 'read_file' tool
    running inside the isolated 'filesystem-provider' subprocess.
    """
    try:
        # Route file reading to standard sandboxed MCP tool 'read_file'
        args = {"path": file_path, "role": role}
        resp = shield.call_tool(
            tool_name="read_file",
            args=args,
            sso_token=sso_token,
            spiffe_id=spiffe_id,
            cert_pem=cert_pem
        )
        return resp.get("result", "")
    except Exception as e:
        return f"Security Violation: {e}"

def list_directory_with_policy(dir_path: str, role: str = "user", sso_token: str = None, spiffe_id: str = None, cert_pem: str = None) -> str:
    """
    Lists files inside directories by delegating execution to the sandboxed 'list_directory' tool
    running inside the isolated 'filesystem-provider' subprocess.
    """
    try:
        args = {"path": dir_path, "role": role}
        resp = shield.call_tool(
            tool_name="list_directory",
            args=args,
            sso_token=sso_token,
            spiffe_id=spiffe_id,
            cert_pem=cert_pem
        )
        return resp.get("result", "")
    except Exception as e:
        return f"Security Violation: {e}"

def keycloak_list_users_with_policy(sso_token: str = None, spiffe_id: str = None, cert_pem: str = None) -> str:
    """
    Lists Keycloak users by delegating execution to the sandboxed 'keycloak_list_users' tool
    running inside the isolated 'keycloak-provider' subprocess.
    """
    try:
        args = {}
        resp = shield.call_tool(
            tool_name="keycloak_list_users",
            args=args,
            sso_token=sso_token,
            spiffe_id=spiffe_id,
            cert_pem=cert_pem
        )
        return resp.get("result", "[]")
    except Exception as e:
        return f"Security Violation: {e}"

def keycloak_revoke_user_sessions_with_policy(username: str = "", userId: str = "", sso_token: str = None, spiffe_id: str = None, cert_pem: str = None) -> str:
    """
    Revokes user sessions in Keycloak by delegating execution to the sandboxed 'keycloak_revoke_user_sessions' tool
    running inside the isolated 'keycloak-provider' subprocess.
    """
    try:
        # Clean inputs in case the LLM agent passes extra quotes or spaces
        username = username.strip().strip("'").strip('"')
        userId = userId.strip().strip("'").strip('"')
        
        args = {}
        if username:
            args["username"] = username
        if userId:
            args["userId"] = userId
            
        resp = shield.call_tool(
            tool_name="keycloak_revoke_user_sessions",
            args=args,
            sso_token=sso_token,
            spiffe_id=spiffe_id,
            cert_pem=cert_pem
        )
        return resp.get("result", "")
    except Exception as e:
        return f"Security Violation: {e}"

def keycloak_run_drills_with_policy(role: str = "user", sso_token: str = None, spiffe_id: str = None, cert_pem: str = None) -> str:
    """
    Executes automated policy verification drills via the Shield Bridge proxy.
    """
    try:
        args = {"role": role}
        resp = shield.call_tool(
            tool_name="keycloak_run_drills",
            args=args,
            sso_token=sso_token,
            spiffe_id=spiffe_id,
            cert_pem=cert_pem
        )
        return resp.get("result", "")
    except Exception as e:
        return f"Security Violation: {e}"

# LangChain Tool placeholders imported by main.py at load-time (overridden dynamically during agent run)
get_current_user_tool = Tool(
    name='GetCurrentUser',
    func=lambda x="": "Placeholder",
    description="Placeholder"
)
get_recent_transactions_tool = Tool(
    name='GetUserTransactions',
    func=lambda x="": "Placeholder",
    description="Placeholder"
)
read_file_tool = Tool(
    name='ReadFile',
    func=lambda x="": "Placeholder",
    description="Placeholder"
)
list_directory_tool = Tool(
    name='ListDirectory',
    func=lambda x="": "Placeholder",
    description="Placeholder"
)
keycloak_list_users_tool = Tool(
    name='KeycloakListUsers',
    func=lambda x="": "Placeholder",
    description="Placeholder"
)
keycloak_revoke_user_sessions_tool = Tool(
    name='KeycloakRevokeUserSessions',
    func=lambda x="": "Placeholder",
    description="Placeholder"
)
keycloak_run_drills_tool = Tool(
    name='KeycloakRunDrills',
    func=lambda x="": "Placeholder",
    description="Placeholder"
)
