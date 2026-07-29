# 🛡️ Long-Term Memory: Attack Patterns

> Known attack signatures detected across all sessions.
> Updated by the Consolidator when cross-session patterns are confirmed.

---

## Pattern: P-0001 — Path Traversal

| Field | Value |
|-------|-------|
| **Tool** | `read_file` |
| **Category** | `path_traversal` |
| **Pattern Key** | `read_file:path_traversal` |
| **First Promoted** | 2026-07-12 23:03:52 |
| **Last Seen** | 2026-07-28 18:54:43 |
| **Session Count** | `8` |
| **Agent Count** | `4` |
| **Total Attempts** | `11` |
| **Example Reason** | file` | `path`: `../../etc/passwd` | |
| **Known Agents** | `spiffe://bridge/user1`, `spiffe://runtime-shield/bridge`, `spiffe://bridge/agent-beta`, `spiffe://bridge/agent-alpha` |

---

## Pattern: P-0002 — Other Block

| Field | Value |
|-------|-------|
| **Tool** | `get_system_config` |
| **Category** | `other_block` |
| **Pattern Key** | `get_system_config:other_block` |
| **First Promoted** | 2026-07-12 23:03:52 |
| **Last Seen** | 2026-07-28 18:54:43 |
| **Session Count** | `3` |
| **Agent Count** | `2` |
| **Total Attempts** | `3` |
| **Example Reason** | system |
| **Known Agents** | `spiffe://bridge/agent-beta`, `spiffe://bridge/agent-alpha` |

---

## Pattern: P-0001 — Path Traversal

| Field | Value |
|-------|-------|
| **Tool** | `read_file` |
| **Category** | `path_traversal` |
| **Pattern Key** | `read_file:path_traversal` |
| **First Promoted** | 2026-07-13 14:52:13 |
| **Last Seen** | 2026-07-28 18:54:43 |
| **Session Count** | `11` |
| **Agent Count** | `5` |
| **Total Attempts** | `11` |
| **Example Reason** | file` | `path`: `../etc/passwd` | |
| **Known Agents** | `spiffe://bridge/agent-alpha`, `spiffe://test/dedup-test`, `spiffe://runtime-shield/bridge`, `spiffe://bridge/agent-beta`, `spiffe://bridge/user1` |

---

## Pattern: P-0002 — Other Block

| Field | Value |
|-------|-------|
| **Tool** | `get_system_config` |
| **Category** | `other_block` |
| **Pattern Key** | `get_system_config:other_block` |
| **First Promoted** | 2026-07-13 14:52:13 |
| **Last Seen** | 2026-07-28 18:54:43 |
| **Session Count** | `3` |
| **Agent Count** | `2` |
| **Total Attempts** | `3` |
| **Example Reason** | system |
| **Known Agents** | `spiffe://bridge/agent-alpha`, `spiffe://bridge/agent-beta` |

---
