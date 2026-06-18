# Runtime Shield Onboarding Guide

Welcome to Runtime Shield! Our goal is to secure your agentic workflows with **zero friction**. We understand that the easier the integration, the better. You shouldn't have to rewrite your entire stack or deal with complex APIs to get enterprise-grade security.

## SDK vs. API: Minimizing Friction

When integrating a new security layer, the biggest question is usually: *Do I need an API or an SDK?*

**Our Approach: Drop-In SDK / Proxy Bridge**
We prioritize a drop-in SDK and Proxy model. Why? Because it minimizes friction. 
- **No heavy API wiring:** You don't need to manually construct API requests, manage rate limits, or handle complex authentication flows for every agent action.
- **Minimal Code Changes:** By using our SDK or routing through our Bridge, you secure your existing agents or MCP (Model Context Protocol) clients with just a few lines of configuration. The shield handles policy enforcement, telemetry, and auditing transparently.

The lesser the work required for integration, the better.

---

## The Pilot Phase: What Happens Next?

Often, organizations start by saying, *"Let's do a pilot."* Here is the clear, actionable process we follow to ensure the pilot is successful and non-disruptive:

1. **Scope Definition:** Identify a single, low-risk agentic workflow (e.g., an internal research assistant).
2. **Passive Monitoring (Shadow Mode):** We deploy Runtime Shield in "Audit-Only" mode. It logs telemetry, flags policy violations, and builds a behavioral baseline without blocking any actions.
3. **Review & Refine:** We review the dashboard with you to show what the Shield caught. We tweak the policies (e.g., `mcp-firewall.yaml`) to eliminate false positives.
4. **Active Enforcement:** Once you are confident, we flip the switch to enforcement mode. The Shield now actively blocks malicious or non-compliant agent actions.
5. **Scale Up:** Expand the Shield's coverage to other agents and MCP servers across your organization.

---

## Deploying with Dokploy (Zero-Friction Infrastructure)

Since you are using **Dokploy**, onboarding is even simpler. Dokploy natively supports Docker Compose, which perfectly aligns with our containerized proxy and dashboard components.

**How it changes onboarding (for the better):**
- **No manual server provisioning:** You don't need to manually set up VMs or run scripts. 
- **One-Click Deploy:** You can deploy the Runtime Shield Bridge and Dashboard directly from your Git repository as a Dokploy Compose project.
- **Environment Management:** You can easily inject your `mcp-firewall.yaml` rules and API keys using Dokploy's built-in environment variable management.

Simply add our `docker-compose.yml` to your Dokploy project alongside your agents, and the infrastructure is ready instantly.

---

## Quick Start: LibreChat + Multiple MCPs

Let's look at a simple use case. You are using **LibreChat** and have multiple MCPs (e.g., File System MCP, Database MCP, Web Search MCP). You want to ensure LibreChat's agents can't execute destructive commands or exfiltrate sensitive data.

### Step 1: Install the Runtime Shield SDK
Add the SDK to your existing project environment.
```bash
pip install runtime-shield-sdk
```

### Step 2: Define Your Firewall Policy
Create a simple `mcp-firewall.yaml` that defines what LibreChat is allowed to do. For example, allow reading from the database, but block writing or dropping tables.

```yaml
rules:
  - name: block_destructive_db_actions
    target_mcp: database_mcp
    action: deny
    pattern: "(DROP|DELETE|UPDATE|INSERT)"
```

### Step 3: Wrap Your MCP Clients
In your LibreChat configuration or the tier where the MCP connections are established, wrap the standard client with the Runtime Shield proxy. 

```python
from shield_sdk import ShieldProxy

# Your existing MCP client setup
# client = MCPClient(endpoint="...")

# New: Wrap the client in the Shield Proxy
client = ShieldProxy(
    target_endpoint="...",
    policy_path="mcp-firewall.yaml"
)
```

**That's it!** Runtime Shield now sits between LibreChat and your MCPs. Every tool call and response is inspected, logged, and evaluated against your policies in real-time, with near-zero latency.
