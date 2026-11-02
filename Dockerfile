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

# Install Node.js runtime and utilities
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
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
COPY bridge.py telemetry.py database_mcp.py scanner_mcp.py system_monitor_mcp.py audit_agent.py windows_sandbox.py chain_helpers.py run_security_drills.py sandbox_enforcer.py jail_factory.py workshop_sandbox.py ./
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

# Expose ports for proxy (5001), dashboard (9090), and sse-bridge (5002)
EXPOSE 5001
EXPOSE 9090
EXPOSE 5002

ENTRYPOINT ["python", "-u", "bridge.py"]
