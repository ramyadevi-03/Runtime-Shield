# Just-in-Time (JIT) Token Exchange & JWKS Verification Guide

This guide details the architecture, integration, and execution workflow for the production-ready **Just-in-Time (JIT) Token Exchange (RFC 8693)** and dynamic **JWKS (JSON Web Key Set) Cryptographic Verification** implemented within the Secure Runtime Shield bridge.

---

## 🏗️ Architecture Overview

```
                      +-------------------+
                      |   Client Application   | (e.g., Streamlit Agent / Claude Desktop)
                      +---------+---------+
                                | User Access Token (Broad permissions)
                                v
                      +---------+---------+
                      |   MCP Shield Bridge    | (Acts as Keycloak Client)
                      +---------+---------+
                                |
                                | POST /openid-connect/token
                                | (RFC 8693 Token Exchange Request)
                                v
                      +---------+---------+
                      |      Keycloak     | (Validates broad token, issues downscoped JIT token)
                      +---------+---------+
                                |
                                | JIT Access Token (TTL: 60s, Single Scope)
                                v
                      +---------+---------+
                      | Isolated Sandboxes| (Downstream API services/tools)
                      +-------------------+
```

---

## 🚀 Fresh Machine Quickstart Guide

To easily boot and run this JIT-hardened architecture on a fresh machine (Windows or macOS/Linux):

### 1. Install System Prerequisites
Ensure you have **Python 3.9+** and **Docker Desktop** installed.

### 2. Install Project Dependencies
Clone the repository, initialize a virtual environment (optional), and install dependencies:
```bash
# On macOS / Linux
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# On Windows
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Start Keycloak with Token-Exchange Feature
Boot the Keycloak container in the background:
```bash
docker-compose up -d keycloak
```

### 4. Initialize Keycloak Users
Configure the Keycloak master realm, create the default clients, and set up user profiles:
```bash
# macOS / Linux
python3 configure_keycloak.py

# Windows
python configure_keycloak.py
```

### 5. Authenticate to Sync Token
Authenticate against Keycloak to acquire your broad access token. This automatically syncs `KEYCLOAK_TOKEN` into the `.env` configuration file:
```bash
# macOS / Linux
python3 login.py

# Windows
python login.py
```
*(Choose **Option 1 (Browser)** or **Option 2 (Manual)** to complete the OAuth handshake).*

### 6. Launch the Security Bridge
In your primary terminal, start the Multi-MCP Shield Bridge:
```bash
# macOS / Linux
python3 bridge.py

# Windows
python bridge.py
```

### 7. Run the Streamlit LLM Agent
In a second terminal, activate the environment, navigate to the agent directory, and boot the conversational interface:
```bash
cd damn-vulnerable-llm-agent

# macOS / Linux
source ../venv/bin/activate
streamlit run main.py

# Windows
..\venv\Scripts\activate
streamlit run main.py
```
Open `http://localhost:8501` to use the agent.

---

## 🛠️ Components & File Changes

### 1. Keycloak Server Feature Activation
* **File**: [docker-compose.yml](file:///c:/Users/Lenovo/Desktop/Runtime-shield-%20login/Runtime-shield-for-agentic-systems/docker-compose.yml)
* **Configuration**: Added the `--features=token-exchange` startup argument to Keycloak to enable the standard RFC 8693 profile engine:
  ```yaml
  command: ["start-dev", "--features=token-exchange"]
  ```

### 2. Core Security Bridge JIT Token Manager
* **File**: [bridge.py](file:///c:/Users/Lenovo/Desktop/Runtime-shield-%20login/Runtime-shield-for-agentic-systems/bridge.py)
* **Implementation**: Substituted the simulated placeholders with real, production-ready REST API requests to Keycloak's `/openid-connect/token` endpoint. 
* **Robust Fallback**: Upgraded the MCP tool interceptor to automatically fall back to the environment `KEYCLOAK_TOKEN` if a direct MCP client (like Claude Desktop) triggers a tool without passing user metadata.

### 3. Dynamic Cryptographic JWKS Verifier
* **File**: [verifier.py](file:///c:/Users/Lenovo/Desktop/Runtime-shield-%20login/Runtime-shield-for-agentic-systems/damn-vulnerable-llm-agent/verifier.py)
* **Implementation**: Implemented a reusable `JITVerifier` class using `PyJWT`'s built-in `PyJWKClient`. 
* **Capabilities**:
  1. Dynamically downloads Keycloak's public keys from the JWKS certificates endpoint.
  2. Verifies the RS256 signature dynamically.
  3. Validates the audience (`aud`) field and checks required scope parameters.
  4. Incorporates `LOCAL_DEV_MODE` toggles to support expired static tokens in developer environments while maintaining absolute production strictness.

### 4. Zero-Trust Tool-Level Verification
* **File**: [tools.py](file:///c:/Users/Lenovo/Desktop/Runtime-shield-%20login/Runtime-shield-for-agentic-systems/damn-vulnerable-llm-agent/tools.py)
* **Implementation**: Injected the `JITVerifier` and a robust `verify_token_or_raise` check directly inside the execution layer of sensitive downstream tools (`get_transactions` and `read_file_with_policy`), ensuring no database queries or file accesses occur without valid cryptographic proof of identity.

---

## 🧪 Verification & Proof of Concept

To verify that the verifier successfully fetches keys and validates claims dynamically, execute the validation script:

### On Windows (PowerShell)
```powershell
python c:\Users\Lenovo\.gemini\antigravity-ide\scratch\test_verifier.py
```

### On macOS / Linux (bash/zsh)
```bash
python3 scratch/test_verifier.py
```

### Expected Output
```
Initializing JITVerifier for JWKS URL: http://localhost:8080/realms/master/protocol/openid-connect/certs
SUCCESS: JITVerifier initialized
Verifying token...
VERIFIED SUCCESSFULLY!
DECODED Preferred Username: user1
DECODED Scope: openid email profile
```

---

## 🛡️ Security Impact & Platform Portability

1. **Least-Privilege Enforcement**: Tools and sandboxes never handle broad user access tokens. They only receive short-lived JIT tokens matching the minimal scope required for their specific execution window.
2. **Reduced Blast Radius**: If a third-party dependency is exploited or compromised, the attacker only acquires a downscoped token that automatically expires in 60 seconds.
3. **Cross-Platform Defense in Depth**: Combined with process sandboxing, the logical security (JIT Tokens) and physical security completely lock down execution boundaries:
   - **Windows**: Enforced via **Windows Restricted Process Groups** (Job Objects).
   - **macOS**: Enforced via standard **POSIX App Sandbox boundaries** (`BaseJailer` platform abstraction).
   - **Linux**: Enforced via **NSJail namespace isolation** and **Landlock** kernel rulesets.

---

## 🔧 Production Hardening & Bug Fixes

During empirical multi-user verification, the following critical security gates were added to solidify the runtime architecture:

### 1. Multi-Turn Query Isolation (User1 Transaction Bug)
* **Hardening**: In `bridge.py`, isolated `actual_user_query` to extract only from the active turn's latest user message rather than the full joined history. Evaluated **Rule B (Prompt ID Hijacking check)** against `actual_user_query.lower()` so that historic blocked queries do not pollute the verification of new, legitimate prompts.

### 2. Dynamic Subprocess Role Attestation (Admin Session Revocation Bug)
* **Hardening**: Transitioned Keycloak session revocation in `src/tools/tools.ts` from static startup-time `process.env.RUNTIME_ROLE` checks to dynamic token-based context checks. By accepting `extra` middleware arguments, the sandboxed MCP server resolves the verified role directly from the JIT token's `authContext`:
  ```typescript
  const ext = extra as any;
  const role = ext?._meta?.authContext?.requiredRole || process.env.RUNTIME_ROLE || "analyst";
  ```
  This guarantees dynamic credentials take immediate effect across sandboxed subprocesses.

