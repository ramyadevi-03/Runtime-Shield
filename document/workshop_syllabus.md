# 🛡️ 2-Day AI Security Workshop Syllabus & Detailed Guide

**Project:** Runtime Shield for Agentic Systems
**Location:** `document/workshop_syllabus.md`

---

## 📚 Overview
This document provides a **comprehensive, in‑depth guide** for the 16‑hour **AI Security Workshop** based on the **Runtime Shield** project. It is intended for students and practitioners who want to understand the underlying concepts, explore hands‑on labs, and learn how to run the accompanying **Marp** slide deck (`document/workshop_slides.md`).

---

## 🎯 Learning Objectives
By the end of the workshop participants will be able to:
1. **Explain** the Model Context Protocol (MCP) and its role in agentic AI.
2. **Build** a minimal MCP server in TypeScript and integrate it with a Python console chatbot.
3. **Identify** and **exploit** common agentic vulnerabilities (prompt‑injection, directory‑traversal, data exfiltration).
4. **Design** and **deploy** a Zero‑Trust Runtime Shield that intercepts tool calls.
5. **Implement** identity attestation and policy‑based risk scoring.
6. **Apply** privacy safeguards (PII redaction, LLM safety guardrails) to protect downstream data.
7. **Operate** a monitoring dashboard to observe events in real‑time.

---

## 📅 Detailed 2‑Day Curriculum

### **Day 1 – MCP Foundations & Agentic Vulnerabilities (8 Hours)**
| Time | Session | Topics | Lab |
|------|---------|--------|-----|
| 09:00‑11:00 | **Introduction to Agentic AI & MCP** | • Evolution of LLMs – static generators → autonomous agents <br>• The ReAct loop (Reason → Act → Observe) <br>• MCP fundamentals – decoders, transports (Stdio, SSE) <br>• Client‑server model | — |
| 11:00‑13:00 | **Building an MCP Server from Scratch** | • Setting up a Node.js/TypeScript monorepo <br>• Defining schemas for custom tools (`read_file`, `list_directory`, …) <br>• Implementing JSON‑RPC request/response handlers <br>• Project layout (`src/tools/tools.ts`) | **Lab 1 – Scaffold the MCP server** – create `src/mcp/server.ts` and expose a `read_file` tool. |
| 13:00‑14:00 | **Lunch Break** | — | — |
| 14:00‑16:00 | **Connecting MCP to a Console Chatbot** | • Launching MCP server as a background subprocess from Python <br>• Parsing prompts, extracting tool arguments, relaying stdout <br>• Building a conversational memory loop | **Lab 2 – Wire a Python chatbot** – edit `scratch/mock_remote_mcp.py` to spawn the server and route tool calls. |
| 16:00‑18:00 | **Agentic Vulnerabilities & Exploitation** | • Threat landscape overview <br>• Indirect prompt injection <br>• Directory traversal & sandbox escape <br>• Data exfiltration techniques | **Lab 3 – Exploit a console agent** – craft a prompt that reads a file outside the workspace.
| 18:00‑18:30 | **Wrap‑up & Q&A** | — | — |

### **Day 2 – 5‑Layer Defense & Runtime Shield (8 Hours)**
| Time | Session | Topics | Lab |
|------|---------|--------|-----|
| 09:00‑11:00 | **Zero‑Trust Runtime Shield Fundamentals** | • Why traditional firewalls fail against semantic attacks <br>• Runtime Shield architecture (HTTP proxy vs. stdio interception) <br>• Gateway pipeline sequence diagram (see `mcp_firewall/outbound/pii.py`) | **Lab 4 – Deploy a mock shield** – configure a simple proxy that blocks `read_file` without attestation. |
| 11:00‑13:00 | **Infrastructure Isolation & Identity Attestation** | • SPIFFE/SPIRE workload attestation – cryptographic certs for tool executors <br>• Keycloak OAuth2 integration – JWKS verification <br>• JIT short‑lived token exchange (RFC 8693) | **Lab 5 – Add SPIFFE identity** – generate a workload certificate and validate it in the shield. |
| 13:00‑14:00 | **Lunch Break** | — | — |
| 14:00‑16:00 | **Policies & Behavioral Risk Scoring** | • Writing policies in `mcp-firewall.yaml` <br>• Honeypot traps – bait tools to detect hijacking <br>• Fraud engine – scoring rules (denial +15, redaction +10, quarantine) | **Lab 6 – Craft a policy** – deny `list_directory` for unauthenticated agents, enable a honey‑tool. |
| 16:00‑18:00 | **Privacy & LLM Safety Guardrails** | • PII redaction with Microsoft Presidio (email, credit‑card, SSN) <br>• Prompt safety via NVIDIA NIM Llama Guard 4 <br>• Capstone Lab – deploy the shield, trigger rules, monitor events | **Lab 7 – End‑to‑end shield demo** – run the chatbot through the shield, observe alerts on the dashboard. |
| 18:00‑18:30 | **Closing Remarks & Future Directions** | — | — |

---

## 🛠️ Prerequisites & Setup
| Component | Minimum / Recommended Version | Install / Source |
|-----------|------------------------------|-----------------|
| **Node.js** | 18.x or later (latest LTS) | `winget install OpenJS.NodeJS` |
| **TypeScript** | Latest stable (via npm) | `npm i -g typescript` |
| **Python** | 3.10 or later (latest) | `winget install Python.Python.3` |
| **Marp CLI** | Latest (via npx) | `npx @marp-team/marp-cli` |
| **Docker** | Latest stable release | `winget install Docker.DockerDesktop` |
| **Keycloak** | Optional – latest container image | `docker run -p 8080:8080 quay.io/keycloak/keycloak:latest` |
| **SPIFFE/SPIRE** | Latest release (v1.x) | Download from https://github.com/spiffe/spire/releases |
| **Microsoft Presidio** | Latest (pip) | `pip install presidio-analyzer presidio-anonymizer` |
| **NVIDIA Llama Guard** | Latest (pip) | `pip install llama-guard` |

Clone the repository and install dependencies:
```bash
# From the workspace root
git clone https://github.com/rise-research-labs/Agentic-AI-Security.git
cd Agentic-AI-Security
npm ci   # installs TypeScript tools and runtime‑shield packages
pip install -r requirements.txt   # Python deps for labs
```

---

## 📂 Project Structure
```
Runtime-shield-for-agentic-systems/
│   README.md                # Overview of the Runtime Shield
│   .env                     # Environment configuration (API keys, etc.)
│
├───src/
│   ├── tools/               # TypeScript definitions of MCP tools
│   │   └── tools.ts
│   └── mcp_server/          # Minimal MCP server implementation
│
├───mcp_firewall/
│   └── outbound/
│       └── pii.py           # Example PII redaction hook
│
├───document/
│   ├── workshop_slides.md   # Marp slide deck (already provided)
│   └── workshop_syllabus.md # **This file**
│
├───scratch/
│   └── mock_remote_mcp.py   # Python helper to spawn a mock MCP server
│
└───windows_sandbox.py      # Sandbox utilities for Windows environments
```

---

## ▶️ How to Render & Export the Marp Slides
**Option A – VS Code Extension (recommended)**
1. Install **Marp for VS Code** from the marketplace.
2. Open `document/workshop_slides.md`.
3. Click the Marp eye‑icon in the top‑right to preview.
4. Use `Ctrl+Shift+P` → *Marp: Export Slide Deck…* and choose **HTML** or **PDF**.

**Option B – Marp CLI** (useful for CI pipelines)
```powershell
# From the workspace root
npx @marp-team/marp-cli document/workshop_slides.md -o document/workshop_slides.html
npx @marp-team/marp-cli document/workshop_slides.md -o document/workshop_slides.pdf
```
The generated files live alongside the markdown source.

---

## 📊 Evaluation & Grading Rubric (Optional)
| Criterion | Points |
|-----------|--------|
| **Lab Completion** (7 labs) | 35 |
| **Written Report** – explain the threat model, mitigation strategy, and lessons learned | 20 |
| **Presentation** – clear slides, demo of the Runtime Shield | 15 |
| **Quiz** – 10 multiple‑choice questions covering MCP & Runtime Shield concepts | 10 |
| **Participation & Q&A** | 20 |
| **Total** | 100 |

---

## 🧭 Further Reading & Resources
- **MCP Specification** – https://github.com/rise-research-labs/mcp-spec
- **SPIFFE/SPIRE Docs** – https://spiffe.io/docs/latest/
- **Microsoft Presidio** – https://github.com/microsoft/presidio
- **NVIDIA Llama Guard** – https://github.com/NVIDIA/llama‑guard
- **Runtime Shield Blog Series** – https://medium.com/@runtime‑shield

---

*Prepared by the Runtime Shield team. Adjust timings or labs as needed for your audience.*
