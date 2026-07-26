# 🚨 Long-Term Memory: Incident History

> Every DENY/BLOCK decision is recorded here with full context.
> Used by the Audit Agent and Policy Advisor for pattern analysis.

---

### Incident: 2026-07-12 22:54:55 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `test-session-001` |
| **Agent** | `spiffe://runtime-shield/bridge` |
| **User** | `user1` |
| **Tool** | `read_file` |
| **Args** | `path=../../etc/passwd` |
| **Reason** | Directory traversal blocked |
| **Risk Score at Block** | `15` |

---

### Incident: 2026-07-12 22:58:37 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `session-demo-001` |
| **Agent** | `spiffe://bridge/user1` |
| **User** | `user1` |
| **Tool** | `read_file` |
| **Args** | `path=../../etc/passwd` |
| **Reason** | Directory traversal blocked |
| **Risk Score at Block** | `25` |

---

### Incident: 2026-07-12 22:58:37 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `session-demo-2` |
| **Agent** | `spiffe://bridge/user1` |
| **User** | `user1` |
| **Tool** | `read_file` |
| **Args** | `path=../etc/passwd` |
| **Reason** | Directory traversal blocked |
| **Risk Score at Block** | `40` |

---

### Incident: 2026-07-12 22:58:37 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `session-demo-3` |
| **Agent** | `spiffe://bridge/user1` |
| **User** | `user1` |
| **Tool** | `read_file` |
| **Args** | `path=../../etc/passwd` |
| **Reason** | Directory traversal blocked |
| **Risk Score at Block** | `50` |

---

### Incident: 2026-07-12 22:58:37 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `session-demo-4` |
| **Agent** | `spiffe://bridge/user1` |
| **User** | `user1` |
| **Tool** | `read_file` |
| **Args** | `path=../../../etc/passwd` |
| **Reason** | Directory traversal blocked |
| **Risk Score at Block** | `60` |

---

### Incident: 2026-07-12 23:02:13 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `session-A001` |
| **Agent** | `spiffe://bridge/agent-alpha` |
| **User** | `alice` |
| **Tool** | `read_file` |
| **Args** | `path=../../etc/passwd` |
| **Reason** | Directory traversal blocked |
| **Risk Score at Block** | `25` |

---

### Incident: 2026-07-12 23:02:13 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `session-A001` |
| **Agent** | `spiffe://bridge/agent-alpha` |
| **User** | `alice` |
| **Tool** | `get_system_config` |
| **Args** | `config=db_credentials` |
| **Reason** | Honeypot tool access blocked |
| **Risk Score at Block** | `100` |

---

### Incident: 2026-07-12 23:02:13 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `session-B002` |
| **Agent** | `spiffe://bridge/agent-beta` |
| **User** | `bob` |
| **Tool** | `read_file` |
| **Args** | `path=../../etc/passwd` |
| **Reason** | Directory traversal blocked |
| **Risk Score at Block** | `25` |

---

### Incident: 2026-07-12 23:02:13 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `session-B002` |
| **Agent** | `spiffe://bridge/agent-beta` |
| **User** | `bob` |
| **Tool** | `get_system_config` |
| **Args** | `config=db_credentials` |
| **Reason** | Honeypot tool access blocked |
| **Risk Score at Block** | `100` |

---

### Incident: 2026-07-12 23:02:13 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `session-C003` |
| **Agent** | `spiffe://bridge/agent-alpha` |
| **User** | `alice` |
| **Tool** | `read_file` |
| **Args** | `path=../../etc/passwd` |
| **Reason** | Directory traversal blocked |
| **Risk Score at Block** | `25` |

---

### Incident: 2026-07-12 23:02:13 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `session-C003` |
| **Agent** | `spiffe://bridge/agent-alpha` |
| **User** | `alice` |
| **Tool** | `get_system_config` |
| **Args** | `config=db_credentials` |
| **Reason** | Honeypot tool access blocked |
| **Risk Score at Block** | `100` |

---

### Incident: 2026-07-12 23:17:32 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `audit-1783878452` |
| **Agent** | `spiffe://bridge/agent-alpha` |
| **User** | `llama-guard-4` |
| **Tool** | `(audit-agent)` |
| **Args** | `categories=S2, S7, score=9` |
| **Reason** | Llama Guard Score 9/10 — Categories: S2, S7 — UNSAFE — Data exfiltration + PII leak |
| **Risk Score at Block** | `90` |

---

### Incident: 2026-07-13 14:52:13 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `dedup-gate-0` |
| **Agent** | `spiffe://test/dedup-test` |
| **User** | `tester` |
| **Tool** | `read_file` |
| **Args** | `path=../../etc/passwd` |
| **Reason** | Directory traversal blocked |
| **Risk Score at Block** | `25` |

---

### Incident: 2026-07-13 14:52:13 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `dedup-gate-1` |
| **Agent** | `spiffe://test/dedup-test` |
| **User** | `tester` |
| **Tool** | `read_file` |
| **Args** | `path=../../etc/passwd` |
| **Reason** | Directory traversal blocked |
| **Risk Score at Block** | `25` |

---

### Incident: 2026-07-13 14:52:13 | Severity: `critical`

| Field | Value |
|-------|-------|
| **Session** | `dedup-gate-2` |
| **Agent** | `spiffe://test/dedup-test` |
| **User** | `tester` |
| **Tool** | `read_file` |
| **Args** | `path=../../etc/passwd` |
| **Reason** | Directory traversal blocked |
| **Risk Score at Block** | `25` |

---
