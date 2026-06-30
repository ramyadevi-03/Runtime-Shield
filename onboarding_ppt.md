---
marp: true
theme: default
paginate: true
size: 16:9
---

<style>
section {
  font-size: 16px;
  padding: 25px;
}

h1 {
  font-size: 28px;
  color: #1f4e79;
}

h2 {
  font-size: 22px;
}

table {
  font-size: 13px;
}

pre {
  font-size: 12px;
}
</style>

# Runtime Shield Onboarding

## Zero-Friction Deployment & Pilot Guide

Securely integrate, validate, and operationalize Runtime Shield.

---

# 1. Zero-Friction Integration Options

### Designed to Fit Your Existing Architecture

| Mode | Target Clients | Connection Type | Best Suited For |
|------|---------------|-----------------|-----------------|
| **Remote SSE Gateway** | Web UIs (LibreChat), Custom Frontends | HTTP EventStream | Cloud Deployments (Dokploy, Docker) |
| **Stdio Interception** | Claude Desktop, Cursor, Local CLIs | Standard Pipes | Local Developer Machines |
| **API Proxy / SDK** | LangChain, Custom ReAct Agents | REST API | Custom Codebase Integrations |

### How Remote SSE Works
- The tool server runs as an independent web service.
- Shield acts as a secure reverse proxy, multiplexing remote SSE streams.
- Unified access policies are checked *before* forwarding to the SSE server.

### Fully Offline Option
✓ Microsoft Presidio for local PII scrubbing (no external leaks)
✓ Zero cloud dependencies required by default
✓ NVIDIA NIM only if advanced jailbreak guardrails are enabled

---

# 2. The 4-Phase Pilot Roadmap

## Recommended Low-Risk Rollout

| Phase | Activity | Purpose |
|---------|---------|---------|
| 1️⃣ Learning Mode | Passive Monitoring | Observe tool behavior without blocking |
| 2️⃣ Generate Policy YAML | Auto-Discovery | Create firewall policies from real usage |
| 3️⃣ Security Drill | Red-Team Testing | Verify protection mechanisms |
| 4️⃣ Dashboard Audit | Operational Review | Validate alerts, logs, and risk trends |

## Success Criteria

✓ Policies generated automatically

✓ Threat detection validated

✓ Dashboard visibility confirmed

✓ Production readiness established

### Outcome

A fully validated Runtime Shield deployment with verified security controls and operational visibility.

---

# 3. Learning Mode & Auto-Policy Generation

### Step 1: Run in Learning Mode (Passive Discovery)

```bash
python bridge.py --learning
# Or set LEARNING_MODE=true in .env
```

**What happens under the hood:**
- The Shield intercepts and validates incoming tool calls but **never blocks them**.
- Legitimate tool parameters and invocation contexts are logged to `discovery.log`.
- For each unknown tool call, the bridge auto-formats a `"proposed_rule"` field.

### Step 2: Auto-Compile Policy & Test Cases

Trigger the administrative policy generation tool via the console or CLI:
- **Via Admin MCP Tool**: Invoke `keycloak_generate_policy`.
- **Via CLI compilation**:
```bash
python -c "import telemetry; print(telemetry.get_registered_tools())"
```

**Result:**
- Parses `discovery.log` and compiles all observed accesses.
- Generates ready-to-use YAML rules to copy into `mcp-firewall.yaml`.
- **Auto-generates companion test cases** in YAML format to test and verify the newly deployed policies.

### Outcome
Production-ready policy baseline and verification test suite compiled from actual usage records.

---

# 4. Testing the Shield – Red Team Drills

| Drill | Action | Expected Result |
|---------|---------|---------|
| Directory Traversal | ../../etc/passwd | Request blocked |
| Honeypot Trigger | fetch_internal_db | Agent quarantined |
| PII Exfiltration | Emails / SSNs | Data redacted |

### Directory Traversal

Attempts to access files outside the sandbox.

### Honeypot Interception

Targets fake internal databases or endpoints.

### PII Exfiltration

Privacy Router replaces sensitive values before they reach the LLM.

### Goal

Validate all protection layers before production.

---

# 5. Multiplexing Remote SSE Tools

### Hybrid Architecture (Local & Remote)

```text
               💬 AI Client (e.g., LibreChat)
                             │
                             ▼
                  🛡️ Runtime Shield Gateway
                             │
       ┌─────────────────────┴─────────────────────┐
       ▼                                           ▼
📁 Local Filesystem MCP                    💾 Remote SSE MCP Server
  (Local CLI / stdio)                      (Host: https://api.customer.com/sse)
```

### Option A: Register Permanently via Dashboard UI (Zero-CLI)
1. Go to **MCP Registry** in the Shield Console (`http://localhost:9090`).
2. Click **+ Register MCP Server**.
3. Choose **Remote Network (SSE)** and enter the SSE Endpoint URL.
4. Click **Sync Tools** to auto-import tools and register them in the governance database.

### Option B: Declare via mcp-firewall.yaml
```yaml
mcp_servers:
  customer-database-mcp:
    transport: "sse"
    url: "https://api.customer.com/sse"
    active: 1
```

---

# 6. Cloud Deployment & Verification

### Dokploy Production Setup
1. Mount a persistent Docker volume to store `telemetry.db`.
2. Boot all core services:
   ```bash
   docker-compose up -d
   ```
3. Securely connect your AI client to the Shield endpoint.

### Dashboard Verification (`http://localhost:9090`)
✓ **Telemetry Dashboard**: Real-time traffic, latency, and system alerts.
✓ **Audit Trails**: Inspect the exact input/output payloads of all remote tool requests.
✓ **Quarantine Panel**: Live threat containment of malicious agent sessions.

### Result
One secure gateway managing both local files and remote SSE tools with centralized policy enforcement.

---

# Thank You

## Runtime Shield Onboarding Complete

### Ready for Pilot Deployment