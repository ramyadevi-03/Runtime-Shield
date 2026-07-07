import langchain
import streamlit as st
import os
from dotenv import load_dotenv
from langchain.agents import ConversationalChatAgent, AgentExecutor
from langchain_community.callbacks.streamlit.streamlit_callback_handler import StreamlitCallbackHandler
from langchain_litellm import ChatLiteLLM
from langchain.memory import ConversationBufferMemory
from langchain.memory.chat_message_histories import StreamlitChatMessageHistory
from langchain.agents import initialize_agent
from langchain.callbacks import get_openai_callback

from tools import get_current_user_tool, get_recent_transactions_tool, read_file_tool, list_directory_tool, keycloak_list_users_tool, keycloak_revoke_user_sessions_tool, keycloak_run_drills_tool
from utils import display_instructions, display_logo, fetch_model_config
from spiffe_integration import fetch_svid

parent_dotenv = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
load_dotenv(dotenv_path=parent_dotenv)

# Fetch and cache SPIFFE SVID workload identity
if "spiffe_svid" not in st.session_state:
    st.session_state.spiffe_svid = fetch_svid()
spiffe_svid = st.session_state.spiffe_svid

class SecureStreamlitCallbackHandler(StreamlitCallbackHandler):
    def on_llm_error(self, error: BaseException, **kwargs) -> None:
        # Suppress raw API and proxy exception tracebacks in the UI thoughts expander
        pass
    def on_chain_error(self, error: BaseException, **kwargs) -> None:
        # Suppress raw API and proxy exception tracebacks in the UI thoughts expander
        pass
    def on_tool_error(self, error: BaseException, **kwargs) -> None:
        # Suppress raw API and proxy exception tracebacks in the UI thoughts expander
        pass

# Initialise tools
tools = [get_current_user_tool, get_recent_transactions_tool, read_file_tool, list_directory_tool, keycloak_list_users_tool, keycloak_revoke_user_sessions_tool, keycloak_run_drills_tool]

system_msg = """Assistant helps the current user retrieve the list of their recent bank transactions and shows them as a table. Assistant will ONLY operate on the userId returned by the GetCurrentUser() tool, and REFUSE to operate on any other userId provided by the user.

Assistant can list the files inside directories using the ListDirectory tool when the user asks to list the files in a directory. Assistant can also read files from the filesystem using the ReadFile tool when the user asks to read or show a file.

CRITICAL PATH RULE:
- When calling ReadFile or ListDirectory, you MUST pass the EXACT path string given by the user. Do NOT add any prefix, modify, or guess the path. If the user says 'README.md', call ReadFile with 'README.md'. If the user says 'secure-experiment-zone/research_notes.txt', call ReadFile with 'secure-experiment-zone/research_notes.txt'. If the user says 'secure-experiment-zone', call ListDirectory with 'secure-experiment-zone'.

CRITICAL DISPLAY RULE:
- You MUST format all transaction lists as a clean Markdown table with headers: | Transaction ID | User ID | Reference | Recipient | Amount |.
- You MUST format the table as a single continuous string within the JSON "action_input" block, using escaped newlines (\n) to separate rows.
- Do NOT output a JSON list of strings (e.g. do NOT wrap the table rows in brackets [ ... ] or use commas between them). Always render a single, clean, human-readable Markdown table string inside "action_input".
- If you read a file containing CSV, comma-separated, or tabular data (like financial_data.csv), you MUST format and display all of its content as a clean Markdown table in your final response.

CRITICAL TOOL CALL RULE:
- You MUST ONLY call the tools explicitly provided: GetCurrentUser, GetUserTransactions, ReadFile, ListDirectory, KeycloakListUsers, KeycloakRevokeUserSessions. Do NOT hallucinate or attempt to call any other tool name under any circumstances.
- For listing files inside a directory like secure-experiment-zone, call ListDirectory with action_input="secure-experiment-zone".

CRITICAL FORMATTING RULES:
1. You MUST respond ONLY with a single JSON markdown code block wrapped in ```json ... ``` matching the requested schema.
2. Do NOT write any conversational text, explanations, greetings, or notes before or after the JSON markdown block.
3. Every response must either use a tool (Option 1) or return the Final Answer (Option 2):
   - Option 1 (Call Tool): {{"action": "[Tool Name]", "action_input": "[Tool Parameter]"}}
     Use this when you need to fetch information. Do NOT include an "output" key or guess/hallucinate the result. You must wait for the user/system to provide the tool's output.
   - Option 2 (Final Answer): {{"action": "Final Answer", "action_input": "[Your Final Markdown Table or Response]"}}
     Use this ONLY after you have received the tool output and are ready to display the final result to the user.
4. Failure to output valid JSON will cause a parsing error. Be extremely precise!"""

welcome_message = """Hi! I'm an helpful assistant and I can help fetch information about your recent transactions.\n\nTry asking me: "What are my recent transactions?"
"""

st.set_page_config(page_title="Damn Vulnerable LLM Agent", initial_sidebar_state="expanded")
st.title("Damn Vulnerable LLM Agent")

hide_st_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            </style>
            """
st.markdown(hide_st_style, unsafe_allow_html=True)

msgs = StreamlitChatMessageHistory()
memory = ConversationBufferMemory(
    chat_memory=msgs, return_messages=True, memory_key="chat_history", output_key="output"
)

if st.sidebar.button("🧹 Clear Chat History"):
    msgs.clear()
    msgs.add_ai_message(welcome_message)
    st.session_state.steps = {}
    st.rerun()

# --- User Session Authentication ---
st.sidebar.markdown("---")
st.sidebar.subheader("🔐 User Authentication")

if "keycloak_token" not in st.session_state:
    st.session_state.keycloak_token = None
if "role" not in st.session_state:
    st.session_state.role = "user"
if "username" not in st.session_state:
    st.session_state.username = "Guest"

# Sidebar Login Form (always show if not authenticated)
if st.session_state.keycloak_token and st.session_state.username != "Guest":
    st.sidebar.success(f"Logged in as: **{st.session_state.username}**")
    st.sidebar.info(f"Role: **{st.session_state.role.upper()}**")
    if st.sidebar.button("🚪 Logout"):
        st.session_state.keycloak_token = None
        st.session_state.role = "user"
        st.session_state.username = "Guest"
        msgs.clear()
        msgs.add_ai_message(welcome_message)
        st.session_state.steps = {}
        st.rerun()
else:
    with st.sidebar.form("login_form"):
        st.write("Sign in to Keycloak:")
        username_input = st.text_input("Username")
        password_input = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign In")
        
        if submitted:
            # Call Keycloak Token API dynamically
            kc_url = os.getenv("KEYCLOAK_URL", "http://127.0.0.1:8080")
            realm = os.getenv("KEYCLOAK_REALM", "master")
            client_id = os.getenv("KEYCLOAK_CLIENT_ID", "admin-cli")
            client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET")
            
            token_url = f"{kc_url}/realms/{realm}/protocol/openid-connect/token"
            data = {
                "grant_type": "password",
                "client_id": client_id,
                "username": username_input,
                "password": password_input,
                "scope": "openid profile email tool:read_file tool:write_file tool:list_directory tool:keycloak_read tool:keycloak_admin tool:keycloak_report tool:admin_internal"
            }
            if client_secret:
                data["client_secret"] = client_secret
                
            try:
                import requests
                r = requests.post(token_url, data=data, timeout=5)
                if r.status_code == 200:
                    token_info = r.json()
                    access_token = token_info["access_token"]
                    st.session_state.keycloak_token = access_token
                    
                    import jwt
                    claims = jwt.decode(access_token, options={"verify_signature": False})
                    roles = claims.get("realm_access", {}).get("roles", []) or claims.get("roles", [])
                    scopes = claims.get("scope", "")
                    if isinstance(scopes, str):
                        scopes = scopes.split(" ")
                    st.session_state.role = "admin" if ("admin" in roles or "tool:keycloak_admin" in scopes or "tool:keycloak_report" in scopes) else "user"
                    st.session_state.username = claims.get("preferred_username") or username_input
                    st.success("Successfully authenticated!")
                    st.rerun()
                else:
                    try:
                        err_detail = r.json().get("error_description") or r.json().get("error") or r.text
                    except Exception:
                        err_detail = r.text
                    st.error(f"Authentication failed ({r.status_code}): {err_detail}")
            except Exception as e:
                st.error(f"Error connecting to Keycloak: {e}")

# --- SPIFFE Workload Status ---
st.sidebar.markdown("---")
st.sidebar.subheader("🪪 SPIFFE Workload Identity")

spiffe_styles = """
<style>
.spiffe-card {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 12px;
    margin-bottom: 12px;
}
.spiffe-title {
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #94a3b8;
    margin-bottom: 4px;
}
.spiffe-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: bold;
    text-transform: uppercase;
}
.badge-attested {
    background-color: hsla(142, 70%, 45%, 0.2);
    color: hsl(142, 70%, 45%);
    border: 1px solid hsl(142, 70%, 45%);
}
.badge-simulated {
    background-color: hsla(37, 90%, 50%, 0.2);
    color: hsl(37, 90%, 50%);
    border: 1px solid hsl(37, 90%, 50%);
}
.spiffe-id-text {
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.85rem;
    color: #60a5fa;
    word-break: break-all;
    margin-top: 6px;
    background: #0f172a;
    padding: 4px 8px;
    border-radius: 4px;
}
.spiffe-source {
    font-size: 0.75rem;
    color: #64748b;
    margin-top: 4px;
}
</style>
"""
st.sidebar.markdown(spiffe_styles, unsafe_allow_html=True)

# Reflect cryptographic attestation status (Feature 1 + 2)
_attested = spiffe_svid.get("attested") or spiffe_svid.get("valid")
badge_class = "badge-attested" if _attested else "badge-simulated"
badge_text  = "Cryptographically Attested" if spiffe_svid.get("attested") else ("SVID Verified" if spiffe_svid.get("valid") else "Simulated Identity")

st.sidebar.markdown(
    f"""
    <div class="spiffe-card">
        <div class="spiffe-title">Workload Status</div>
        <div>
            <span class="spiffe-badge {badge_class}">{badge_text}</span>
        </div>
        <div class="spiffe-id-text">{spiffe_svid.get("spiffe_id")}</div>
        <div class="spiffe-source">Source: {spiffe_svid.get("source")}</div>
    </div>
    """,
    unsafe_allow_html=True
)

with st.sidebar.expander("View Workload X.509 SVID"):
    st.code(spiffe_svid.get("cert_pem") or "(No certificate available)", language="pem")


if len(msgs.messages) == 0:
    msgs.clear()
    msgs.add_ai_message(welcome_message)
    st.session_state.steps = {}

avatars = {"human": "user", "ai": "assistant"}
for idx, msg in enumerate(msgs.messages):
    with st.chat_message(avatars[msg.type]):
        # Render intermediate steps if any were saved
        for step in st.session_state.steps.get(str(idx), []):
            if step[0].tool == "_Exception":
                continue
            with st.status(f"**{step[0].tool}**: {step[0].tool_input}", state="complete"):
                st.write(step[0].log)
                st.write(step[1])
        is_shield_block = any(term in msg.content for term in ["Security Violation", "Blocked by", "RBAC", "rbac_violation", "security_violation"]) or msg.content.startswith("An error occurred:")
        if is_shield_block:
            st.error(msg.content)
        else:
            st.write(msg.content)

if prompt := st.chat_input(placeholder="Show my recent transactions"):
    st.chat_message("user").write(prompt)
    
    # Extract sub and role from user session state token (truly multi-user isolated)
    token = st.session_state.get("keycloak_token")
    keycloak_sub = ""
    role = st.session_state.get("role", "user")
    debug_mode = True

    if token:
        try:
            import jwt
            claims = jwt.decode(token, options={"verify_signature": False})
            keycloak_sub = claims.get("sub") or ""
            roles = claims.get("realm_access", {}).get("roles", []) or claims.get("roles", [])
            scopes = claims.get("scope", "")
            if isinstance(scopes, str):
                scopes = scopes.split(" ")
            role = "admin" if ("admin" in roles or "tool:keycloak_admin" in scopes or "tool:keycloak_report" in scopes) else "user"
            debug_mode = False
        except Exception:
            pass

    # Create Dynamic Tool instances bound explicitly to the request context
    from tools import get_current_user, get_transactions, read_file_with_policy, list_directory_with_policy, keycloak_list_users_with_policy, keycloak_revoke_user_sessions_with_policy, keycloak_run_drills_with_policy
    from langchain.agents import Tool
    
    tools = [
        Tool(
            name='GetCurrentUser',
            func=lambda input="": get_current_user(
                keycloak_sub=keycloak_sub, 
                debug_mode=debug_mode,
                sso_token=token,
                spiffe_id=spiffe_svid.get("spiffe_id"),
                cert_pem=spiffe_svid.get("cert_pem")
            ),
            description="Returns the current user for querying transactions."
        ),
        Tool(
            name='GetUserTransactions',
            func=lambda userId: get_transactions(
                userId=userId, 
                keycloak_sub=keycloak_sub, 
                role=role, 
                debug_mode=debug_mode,
                sso_token=token,
                spiffe_id=spiffe_svid.get("spiffe_id"),
                cert_pem=spiffe_svid.get("cert_pem")
            ),
            description="Returns the transactions associated to the userId provided. The input MUST be ONLY the raw user ID string (e.g. '1'), NOT a SQL query or any other text."
        ),
        Tool(
            name='ReadFile',
            func=lambda path: read_file_with_policy(
                path, 
                role=role,
                sso_token=token,
                spiffe_id=spiffe_svid.get("spiffe_id"),
                cert_pem=spiffe_svid.get("cert_pem")
            ),
            description=(
                "Reads the contents of a file at the given path. "
                "Provide a relative path such as 'secure-experiment-zone/research_notes.txt'. "
                "Access is controlled by the security policy: standard users can only read files "
                "inside 'secure-experiment-zone/', administrators can read any project file."
            )
        ),
        Tool(
            name='ListDirectory',
            func=lambda path: list_directory_with_policy(
                path, 
                role=role,
                sso_token=token,
                spiffe_id=spiffe_svid.get("spiffe_id"),
                cert_pem=spiffe_svid.get("cert_pem")
            ),
            description=(
                "Lists the files inside a directory at the given path. "
                "Provide a relative path such as 'secure-experiment-zone'. "
                "Access is controlled by the security policy."
            )
        ),
        Tool(
            name='KeycloakListUsers',
            func=lambda input="": keycloak_list_users_with_policy(
                sso_token=token,
                spiffe_id=spiffe_svid.get("spiffe_id"),
                cert_pem=spiffe_svid.get("cert_pem")
            ),
            description=(
                "Lists all users registered in Keycloak. "
                "Only accessible by administrators with the required client scopes."
            )
        ),
        Tool(
            name='KeycloakRevokeUserSessions',
            func=lambda username: keycloak_revoke_user_sessions_with_policy(
                username=username,
                sso_token=token,
                spiffe_id=spiffe_svid.get("spiffe_id"),
                cert_pem=spiffe_svid.get("cert_pem")
            ),
            description=(
                "Revokes and logs out all active Keycloak sessions for the specified username. "
                "Only accessible by administrators."
            )
        ),
        Tool(
            name='KeycloakRunDrills',
            func=lambda input="": keycloak_run_drills_with_policy(
                role=role,
                sso_token=token,
                spiffe_id=spiffe_svid.get("spiffe_id"),
                cert_pem=spiffe_svid.get("cert_pem")
            ),
            description=(
                "Executes automated policy verification drills to check that the security gateway "
                "correctly handles security rules (Directory Traversal, PII Redaction, RBAC, and Honeypots). "
                "Only available to administrators."
            )
        )
    ]
    
    if role == "admin":
        system_msg_to_use = """Assistant helps the current user retrieve the list of recent bank transactions and shows them as a table.
As an Administrator with elevated privileges, you are fully authorized and permitted to query transactions for ANY userId (including userId 2) as requested by the user. If the user asks for transactions of user ID 2, you MUST call GetUserTransactions with userId="2" without refusal.

Assistant can list the files inside directories using the ListDirectory tool when the user asks to list the files in a directory. Assistant can also read files from the filesystem using the ReadFile tool. Administrators have unrestricted access to any project file.
Assistant can run automated security policy verification drills using the KeycloakRunDrills tool when requested by the administrator to run verification drills or verify security gateway posture.

CRITICAL PATH RULE:
- When calling ReadFile or ListDirectory, you MUST pass the EXACT path string given by the user. Do NOT add any prefix, modify, or guess the path. If the user says 'README.md', call ReadFile with 'README.md'. If the user says 'secure-experiment-zone/research_notes.txt', call ReadFile with 'secure-experiment-zone/research_notes.txt'. If the user says 'secure-experiment-zone', call ListDirectory with 'secure-experiment-zone'.

CRITICAL DISPLAY RULE:
- You MUST format all transaction lists as a clean Markdown table with headers: | Transaction ID | User ID | Reference | Recipient | Amount |.
- You MUST format the table as a single continuous string within the JSON "action_input" block, using escaped newlines (\n) to separate rows.
- Do NOT output a JSON list of strings (e.g. do NOT wrap the table rows in brackets [ ... ] or use commas between them). Always render a single, clean, human-readable Markdown table string inside "action_input".
- If you read a file containing CSV, comma-separated, or tabular data (like financial_data.csv), you MUST format and display all of its content as a clean Markdown table in your final response.

CRITICAL TOOL CALL RULE:
- You MUST ONLY call the tools explicitly provided: GetCurrentUser, GetUserTransactions, ReadFile, ListDirectory, KeycloakListUsers, KeycloakRevokeUserSessions, KeycloakRunDrills. Do NOT hallucinate or attempt to call any other tool name under any circumstances.
- For listing files inside a directory like secure-experiment-zone, call ListDirectory with action_input="secure-experiment-zone".

CRITICAL FORMATTING RULES:
1. You MUST respond ONLY with a single JSON markdown code block wrapped in ```json ... ``` matching the requested schema.
2. Do NOT write any conversational text, explanations, greetings, or notes before or after the JSON markdown block.
3. Every response must either use a tool (Option 1) or return the Final Answer (Option 2):
   - Option 1 (Call Tool): {{"action": "[Tool Name]", "action_input": "[Tool Parameter]"}}
     Use this when you need to fetch information. Do NOT include an "output" key or guess/hallucinate the result. You must wait for the user/system to provide the tool's output.
   - Option 2 (Final Answer): {{"action": "Final Answer", "action_input": "[Your Final Markdown Table or Response]"}}
     Use this ONLY after you have received the tool output and are ready to display the final result to the user.
4. Failure to output valid JSON will cause a parsing error. Be extremely precise!"""
    else:
        system_msg_to_use = system_msg
        
    extra_headers = {"X-Shield-Token": token}
    if spiffe_svid and spiffe_svid.get("spiffe_id"):
        extra_headers["X-SPIFFE-ID"] = spiffe_svid["spiffe_id"]
        # Feature 3: attach PEM cert so the gateway can cryptographically verify the SVID
        cert_pem = spiffe_svid.get("cert_pem")
        if cert_pem:
            import urllib.parse
            extra_headers["X-SPIFFE-CERT"] = urllib.parse.quote(cert_pem)

    model_name_to_use = fetch_model_config()
    if not model_name_to_use.startswith("openai/"):
        model_name_to_use = f"openai/{model_name_to_use}"

    shield_api_url = os.getenv("SHIELD_API_URL", "http://127.0.0.1:5001/v1")
    llm = ChatLiteLLM(
        model=model_name_to_use,
        api_base=shield_api_url,
        api_key=token,
        custom_llm_provider="openai",
        model_kwargs={"extra_headers": extra_headers},
        temperature=0, streaming=True
    )

    chat_agent = ConversationalChatAgent.from_llm_and_tools(llm=llm, tools=tools, verbose=True, system_message=system_msg_to_use)

    executor = AgentExecutor.from_agent_and_tools(
        agent=chat_agent,
        tools=tools,
        memory=memory,
        return_intermediate_steps=True,
        handle_parsing_errors="Check your output format. You MUST respond strictly with a single JSON markdown code block matching the requested schema.",
        verbose=True,
        max_iterations=6
    )
    with st.chat_message("assistant"):
        st_cb = SecureStreamlitCallbackHandler(st.container(), expand_new_thoughts=False)
        try:
            response = executor(prompt, callbacks=[st_cb])
            output_text = response["output"]
            is_shield_block = any(term in output_text for term in ["Security Violation", "Blocked by", "RBAC", "rbac_violation", "security_violation"])
            if is_shield_block:
                st.error(output_text)
            else:
                st.write(output_text)
            st.session_state.steps[str(len(msgs.messages) - 1)] = response["intermediate_steps"]
        except Exception as e:
            import traceback
            import sys
            
            err_msg = str(e)
            
            # Print detailed error diagnostics to console/logs (User Step 5)
            print("==================================================", file=sys.stderr)
            print("🚨 Damn Vulnerable LLM Agent - LiteLLM Error Details", file=sys.stderr)
            print("==================================================", file=sys.stderr)
            print(f"Model Name       : {fetch_model_config()}", file=sys.stderr)
            print(f"Base URL         : {shield_api_url}", file=sys.stderr)
            print(f"Keycloak Token   : {'Present (len=' + str(len(os.getenv('KEYCLOAK_TOKEN', ''))) + ')' if os.getenv('KEYCLOAK_TOKEN') else 'Missing'}", file=sys.stderr)
            print(f"Nvidia Key       : {'Present (len=' + str(len(os.getenv('NVIDIA_API_KEY', ''))) + ')' if os.getenv('NVIDIA_API_KEY') else 'Missing'}", file=sys.stderr)
            print(f"OpenAI Key       : {'Present (len=' + str(len(os.getenv('OPENAI_API_KEY', ''))) + ')' if os.getenv('OPENAI_API_KEY') else 'Missing'}", file=sys.stderr)
            print(f"Error Type       : {type(e)}", file=sys.stderr)
            print(f"Error Message    : {err_msg}", file=sys.stderr)
            print("----------------- Full Traceback -----------------", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            print("==================================================", file=sys.stderr)
            
            is_shield_block = any(term in err_msg for term in ["Blocked by", "Security Violation", "RBAC", "rbac_violation", "security_violation"])
            
            if is_shield_block:
                display_msg = "🛡️ **Security Violation Detected**\n\nThe Secure Runtime Shield has intercepted and blocked an unauthorized tool execution attempt to protect system boundaries."
                st.error(display_msg)
            else:
                display_msg = f"An error occurred: {err_msg}"
                st.error(display_msg)
            
            # Manually save the turn to session history so it persists across Streamlit refreshes/reruns
            msgs.add_user_message(prompt)
            msgs.add_ai_message(display_msg)
            st.session_state.steps[str(len(msgs.messages) - 1)] = []


display_instructions()
display_logo()


        