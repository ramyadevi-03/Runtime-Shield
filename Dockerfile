# --- Stage 1: Build TypeScript MCP Server ---
FROM node:20-slim AS node-builder
WORKDIR /app
COPY package*.json tsconfig.json ./
COPY src/ ./src/
RUN npm ci && npm run build

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

# Download spaCy models for Microsoft Presidio PII Redaction
RUN python -m spacy download en_core_web_sm && \
    python -m spacy download en_core_web_lg

# Copy Node.js built files and node_modules from builder stage
COPY --from=node-builder /app/dist ./dist
COPY --from=node-builder /app/node_modules ./node_modules
COPY package*.json tsconfig.json ./

# Copy other project code files
COPY bridge.py telemetry.py database_mcp.py scanner_mcp.py system_monitor_mcp.py sse_bridge.cjs start.sh ./
COPY rules/ ./rules/
COPY mcp-firewall.yaml ./mcp-firewall.yaml
COPY mcp_firewall/ ./mcp_firewall/
COPY shield_sdk.py dashboard_client.py ./
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

ENTRYPOINT ["/bin/bash", "start.sh"]
