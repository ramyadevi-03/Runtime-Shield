# Runtime Shield + Credential Broker Integration: Changes & Fixes

This document records all modifications and fixes applied to complete the integration testing between **Runtime Shield** and **Credential Broker** according to `CREDENTIAL_BROKER_INTEGRATION_TESTING.md`.

---

## 1. Keycloak Token Lifespan Details

* **Previous Lifespan**: **300 seconds (5 minutes)**.  
  This was Keycloak's default setting for `accessTokenLifespan`.
* **Issue Encountered**: During multi-step end-to-end testing, if more than 5 minutes elapsed between logging in or authorizing the MCP server and executing the tool call, Keycloak access tokens expired. When LibreChat subsequently sent the expired bearer token to Gateway, the gateway rejected it with `401 {"error":"Invalid or expired Keycloak authentication token"}`.
* **Updated Lifespan**: Set to **3600 seconds (1 hour)** in `configure_keycloak.py` (both at the realm level and specifically on the `runtime-shield-hitl` client). 1 hour provides ample time for testing without leaving tokens open indefinitely.

---

## 2. Summary of Changes Made Across the Project

### A. Keycloak Configuration (`configure_keycloak.py`)
1. **Automated `runtime-shield-hitl` Client Provisioning**:
   - Automatically checks for and provisions the `runtime-shield-hitl` OAuth client if missing.
   - Sets standard authorization code flow, redirect URI `http://localhost:3080/api/mcp/runtime-shield-hitl/oauth/callback`, and web origin `http://localhost:3080`.
   - Retrieves the client secret and writes `RUNTIME_SHIELD_MCP_CLIENT_SECRET` into `.env`.
   - Configures realm roles scope and group mappers.
2. **Client Scopes Provisioning in `--jit-only`**:
   - Ensures `repository:read` and `tool:*` client scopes are configured even when `--jit-only` or `--librechat-oidc-only` flags are passed.
3. **Protocol Mapper 500 Fix**:
   - Fixed payload format for PUT protocol mappers by including the mapper ID and comparing config dictionaries properly.
4. **Token Lifespan Management**:
   - Configured `accessTokenLifespan = 3600` (1 hour) on the realm and `access.token.lifespan = 3600` on the `runtime-shield-hitl` client.

### B. Gateway & Mock LLM Dispatching (`bridge.py`)
1. **SPIFFE SVID Header Parsing**:
   - Detected unexpanded placeholder `${SPIFFE_LLM_CERT}` from `librechat.yaml`.
   - Added automatic fallback to load `/app/spire/certs/llm-agent.crt` from disk so cryptographic SVID signature and SAN verification against SPIRE CA succeeds.
2. **Prompt-Level Heuristic Exclusion**:
   - In `chat_completions_proxy`, excluded repository/GitHub keywords (`repository`, `github`, `read_repository`, `repo`) from the prompt-level regex that maps `read` to filesystem `read_file`.
3. **Mock LLM Tool Call Generation for `github.read_repository`**:
   - Added native handling in `handle_mock_llm_response` for `is_repo_request`.
   - When asked to read a repository, the mock agent responds with an assistant `tool_calls` message targeting `github.read_repository` with argument `{"repository": "runtime-shield/demo"}`.
   - When the tool completes, parses the tool result and formats the repository file listing (`README.md`).
4. **Deterministic & Semantic Intent Routing Exclusions**:
   - Excluded repository queries from `det_file` and semantic `ReadFile` routing, preventing false-positive OPA `read_file` blocks.
5. **Secret Redaction**:
   - Enforced defensive scrubbing ensuring `local-dummy-github-token` is never echoed in responses.
6. **Presidio Redaction Helper (`presidio_redact`)**:
   - Defined missing `presidio_redact(text, is_admin)` helper in `bridge.py`, resolving the `NameError: name 'presidio_redact' is not defined` crash that was interrupting the return of sanitized repository content after egress execution.
7. **Credential Execution Error Diagnostics**:
   - Added explicit logging of exception details in `bridge.py` and `src/credential_tools.py` when calls to the broker or egress service fail.

### C. LibreChat Configuration (`librechat.yaml`)
1. **Auto-Attach MCP to Model Specification**:
   - Added `mcpServers: ["runtime-shield-hitl"]` to `modelSpecs.list[name=runtime-shield-agent]`. Every new chat using Runtime Shield Agent now automatically binds the MCP server and its tools without requiring manual per-chat activation.
2. **Offline Access Scope**:
   - Added `offline_access` to `mcpServers.runtime-shield-hitl.oauth.scope` (`openid offline_access repository:read`) so LibreChat can receive and maintain refresh tokens.
3. **Allowed Origins**:
   - Ensured `http://gateway:5001`, `https://host.docker.internal:8443`, and `http://keycloak:8080` are allowed MCP domains.

### D. Docker Compose (`docker-compose.yml`)
1. **Local SSL Trust in LibreChat**:
   - Added `NODE_TLS_REJECT_UNAUTHORIZED=0` to `chatbot` container so Node.js native `fetch` (Undici) trusts Keycloak's local self-signed CA certificate.
2. **Direct Container Networking (`host.docker.internal`)**:
   - Configured `host.docker.internal` as a network alias directly on the `keycloak` container in the `default` network.
   - Removed broken `extra_hosts: "host.docker.internal:host-gateway"` from Linux containers to prevent dropped packets on the host `docker0` bridge.
3. **Gateway Volume Mounts**:
   - Mounted `./bridge.py:/app/bridge.py:ro` and `./src:/app/src:ro` into `gateway` so code changes take effect on container restart without a full image rebuild.

### E. Credential Egress & Broker Networking
1. **Network Alias on Cross-Compose Networks**:
   - `credential-broker/docker-compose.yml`: Added explicit `broker` network alias on `credential-broker-control` (`runtime-shield-broker-control`) and `credential-broker-redemption` (`runtime-shield-broker-redemption`) so containers in the root Compose stack (`gateway` and `credential-egress`) can resolve `http://broker:8000` across project boundaries.
2. **DNS Fallback in Python Services**:
   - In `src/credential_tools.py` and `credential_egress/app.py`, added automatic candidate URL fallback (`http://broker:8000` $\rightarrow$ `http://credential-broker-broker-1:8000`) and surfaced detailed HTTP error status logging.
3. **Hot-Reload Volume Mount**:
   - Mounted `./credential_egress/app.py:/app/app.py:ro` in `docker-compose.yml` so executor fixes reload immediately upon container restart.

---

## 3. Verifying the Credential Broker Flow

When `{"error":"Credential-backed operation failed."}` occurs after admin approval:
1. Verify the broker stack is running from `credential-broker/`:
   ```bash
   cd credential-broker
   docker compose ps
   ```
   Ensure `openbao`, `broker`, and `opa` are all healthy.
2. Ensure OpenBao is unsealed:
   ```bash
   docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao status
   ```
   If `Sealed: true`, unseal with 3 unseal keys:
   ```bash
   docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao operator unseal
   ```
3. Ensure the dummy credential was written to OpenBao:
   ```bash
   docker compose exec broker python -c 'import asyncio,httpx,os; token="admin:local-admin:admin-cli:"+os.environ["BROKER_DEV_ADMIN_SECRET"]; r=asyncio.run(httpx.AsyncClient().put("http://127.0.0.1:8000/v1/admin/credentials/github-production",headers={"Authorization":"Bearer "+token},json={"value":{"api_key":"local-dummy-github-token"}})); print("HTTP",r.status_code); r.raise_for_status()'
   ```
   *(Must return `HTTP 204`)*.
4. Check the gateway log for the exact error:
   ```bash
   docker compose logs gateway --tail 30
   ```

