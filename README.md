# Centralized LLM-Agnostic Runtime Governance for Agentic Systems

The **Runtime Shield** is a high-performance, identity-aware gateway implementing **Centralized LLM-Agnostic Runtime Governance** designed to harden autonomous AI agents (such as Claude Desktop, custom chatbot agents, or corporate ReAct frameworks) against prompt injections, data exfiltration, and unauthorized tool use. 

It acts as a stateful, unified interception bridge between any AI client and its execution environment, enforcing **Zero-Trust** boundaries at runtime.

---

## 🛡️ 5-Layer Defense Framework

1.  **Identity & Auth (Layer 2):** Dual-factor verification using:
    *   **Keycloak (User Roles):** Dynamic JWKS-based RS256 signature and claims verification (`iss`, `exp`, `aud`).
    *   **SPIFFE/SPIRE (Workload Identity):** Strict cryptographic SVID client certificate verification (`X-SPIFFE-CERT`) attested against the local CA trust bundle (`ca.crt`).
2.  **Policy Firewall (Layer 3):** Real-time tool-call inspection against `mcp-firewall.yaml` to block directory traversal and unauthorized path access.
3.  **Fraud Engine (Layer 4):** Behavioral risk scoring that automatically quarantines agents displaying suspicious or repetitive attack patterns.
4.  **Privacy Router (Layer 5):** In-flight JSON-aware PII redaction (Microsoft Presidio NLP) that scrubs PII from tool outputs before the AI can see them.
5.  **Infrastructure Isolation (Layer 1):** Secure execution in isolated "Experiment Zones" and Docker-bound containers.

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.10+**
- **Node.js 18+**
- **Docker & Docker Compose**
- **SPIRE** (for Workload Identity)

### 1. Setup Environment
Clone the repository and create a `.env` file based on `.env.example`:
```bash
cp .env.example .env
# Update values for KEYCLOAK_URL, SPIFFE_BRIDGE_ID, and RUNTIME_ROLE
```

### 2. Launch Infrastructure
Start Keycloak, SPIRE Server, and SPIRE Agent:
```bash
docker-compose up -d
```

### 3. Build the MCP Server
Install dependencies and compile the TypeScript source:
```bash
npm install
npm run build
```

### 4. Run the Secure Bridge & Agent Demo
Start the entire integrated bridge, live dashboard, and Streamlit agent chatbot with one command:
```powershell
.\run_shield_demo.ps1
```

---

## 🧪 Security & Governance Verification

Verify the active security layers using the programmatic test suite:

```powershell
python run_security_drills.py
```
*Validates directory traversal guardrails, role-based access control (RBAC), tool normalization, and zero-trust default-deny blocks on unauthorized tools.*

---

## 📊 Security Dashboard
Once the bridge is active, you can monitor all tool calls, risk levels, and redactions in real-time:
- **URL:** `http://127.0.0.1:9090`

## ⚙️ Pluggable Policy Engine Architecture

The Runtime Shield features a pluggable policy engine architecture allowing for seamless migration and parity checking between internal and enterprise policy backends.

## OPA/Rego Policy Engine

Runtime Shield uses OPA/Rego as its sole policy engine.

- Policy logic: `rules/runtime_shield.rego`
- Policy data: `rules/runtime_shield_data.json`
- OPA decision endpoint: configured through `OPA_URL`
- Default behaviour: deny when no policy rule matches
- Fail-closed behaviour: deny requests if OPA is unavailable, returns an error, or returns an invalid decision

`mcp-firewall.yaml` is retained only for operational configuration such as MCP server definitions, NeMo guardrails, PII and secrets settings, tool scopes, and trusted identity providers. It is not used as a policy-rule source.

### Final Enforcement Flow
```text
mcp-firewall.yaml → opa_sync.py → OPA data → generic Rego policy → PolicyDecision → Bridge enforcement
```

### Troubleshooting OPA Integration
- **OPA Server Unreachable**: If `POLICY_BACKEND=opa`, the Bridge will intentionally **fail closed** (exit on startup, or block all requests) to prevent unsecured execution.
- **OPA Sync Failure**: If OPA is reachable but synchronization fails, verify the syntax in `mcp-firewall.yaml` and check the Bridge logs for `opa_sync.py` errors.
- **Shadow Mode Mismatch**: If `POLICY_SHADOW_BACKEND=opa` logs a mismatch, verify that the OPA server contains the latest synchronized rules. Note that if OPA is offline, it will log a distinct `shadow_error: true` rather than a policy mismatch.
- **Policy Parity Test Failure**: Run `python -m pytest tests/test_policy_engines.py`. If tests fail, ensure the OPA server is running locally on port 8181 and the `opa_sync` logic properly translates the failing YAML rule.

---

## 📚 Configuration & Architecture Guides
- **Centralized Governance Walkthrough:** [centralized_governance_walkthrough.md](file:///c:/Users/Lenovo/Desktop/Runtime-shield-%20login/Runtime-shield-for-agentic-systems/document/centralized_governance_walkthrough.md) — Comprehensive guide detailing unified tool normalization, cryptographic JWKS/SVID verification, Llama Guard bypass optimization, and RBAC rules.
- **Firewall Rules:** Modify `mcp-firewall.yaml` to define tool permissions and path guardrails.
- **Roles:** Set `RUNTIME_ROLE=user` or `admin` in your `.env` to test different RBAC personas dynamically.

---
**Note:** This project is part of a Secure Agentic Runtime research initiative. Use the `--learning` flag with `bridge.py` to discover required policies without enforcing blocks.

