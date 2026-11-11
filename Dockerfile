# --- Stage 1: Build TypeScript MCP Server ---
FROM node:20-slim AS node-builder
WORKDIR /app
COPY package*.json tsconfig.json ./
COPY src/ ./src/
RUN npm ci && npm run build

FROM ghcr.io/spiffe/spire-agent:1.8.0 AS spire-cli

# --- Stage 2: Unified Gateway Runner ---
FROM python:3.11-slim
WORKDIR /app

# Install Node.js runtime and utilities.
#
# bubblewrap is installed from the distro archive (apt) ONLY — never vendored
# into the repository — so the sandbox helper can attempt a nested
# bubblewrap+seccomp sandbox INSIDE this container (defense in depth).
#
# Deliberate isolation decision for this image (see jail_factory.JailFactory):
#   * At startup the bridge runs the behavioral sandbox self-test inside the
#     container. Docker's DEFAULT seccomp profile usually denies unprivileged
#     user namespaces, so the test typically fails here. Providers then run
#     with the CONTAINER boundary as the filesystem isolation, hardened by
#     ContainerSeccompJailer: the Codex inner stage still applies
#     PR_SET_NO_NEW_PRIVS, verifies the effective/permitted capability sets
#     are empty, and installs the per-provider network seccomp filter. This is
#     explicitly logged as the CONTAINER isolation tier, never reported as a
#     stronger sandbox.
#   * The shipped seccomp profile permits the syscalls bubblewrap needs, but
#     bwrap can still fail inside the container (for example "Failed to make /
#     slave: Permission denied" when Docker's mount namespace is owned by the
#     initial user namespace). In that case the self-test fails closed to the
#     CONTAINER + seccomp tier above. BWRAP_SECCOMP inside the image requires
#     a host that permits nested user and mount namespaces.
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    bubblewrap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install the pinned spaCy model used by Microsoft Presidio PII redaction.
RUN pip install --no-cache-dir \
    https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

# Copy Node.js built files and node_modules from builder stage
COPY --from=node-builder /app/dist ./dist
COPY --from=node-builder /app/node_modules ./node_modules
COPY --from=spire-cli /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
COPY package*.json tsconfig.json ./

# Copy other project code files
COPY bridge.py telemetry.py database_mcp.py scanner_mcp.py system_monitor_mcp.py audit_agent.py windows_sandbox.py chain_helpers.py run_security_drills.py sandbox_enforcer.py jail_factory.py workshop_sandbox.py gateway_auth.py ./
# SQLite schema/seed module used by the sandboxed database provider. It lives
# in the demo subdirectory; without this copy the provider exits at startup with
# ModuleNotFoundError inside the deployed image.
COPY damn-vulnerable-llm-agent/transaction_db.py ./damn-vulnerable-llm-agent/transaction_db.py
COPY rules/ ./rules/
COPY mcp-firewall.yaml ./mcp-firewall.yaml
COPY mcp_firewall/ ./mcp_firewall/
COPY governance_memory/ ./governance_memory/
COPY shield_sdk.py dashboard_client.py ./
COPY src/ ./src/
COPY spire/ ./spire/

# Set environment defaults
ENV PYTHONUNBUFFERED=1 \
    LOCAL_DEV_MODE=false \
    SPIFFE_ENABLED=true \
    SPIRE_AGENT_SOCKET=/run/spire/sockets/agent.sock

# --- Non-root runtime user ---------------------------------------------------
# The gateway no longer runs as root. Runtime write targets all live under /app
# (bridge.log, telemetry.db, telemetry.log, audit.log, governance_memory/ and
# the .env that login.py writes), so /app is owned by the runtime user.
# Compose additionally applies cap_drop: ALL, no-new-privileges and the shipped
# gateway-seccomp.json profile, which permits nested bubblewrap where the host
# allows it; otherwise the CONTAINER + seccomp fallback is used (see
# jail_factory.JailFactory and docker-compose.yml).
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin shield \
    && chown -R shield:shield /app
USER 10001:10001

# Expose ports for proxy (5001), dashboard (9090), and sse-bridge (5002)
EXPOSE 5001
EXPOSE 9090
EXPOSE 5002

ENTRYPOINT ["python", "-u", "bridge.py"]
