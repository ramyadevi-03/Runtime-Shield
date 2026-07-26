"""
MemoryWriter — Phase 1 Core Component.

Writes governance decisions to short-term session .md files and updates
long-term agent profile .md files after every tool call decision.

Called from bridge.py immediately after FraudDetectionEngine.analyze().
"""

import os
import re
import time
import uuid
import threading
from datetime import datetime
from pathlib import Path


# ── Directory Layout ────────────────────────────────────────────────────────
#   governance_memory/
#   ├── short_term/
#   │   ├── sessions/          ← One .md per active session
#   │   ├── active_threats.md  ← Live threat summary (overwritten each run)
#   │   └── current_risk_state.md
#   └── long_term/
#       ├── agent_profiles.md
#       ├── attack_patterns.md
#       ├── incident_history.md
#       ├── policy_evolution.md
#       └── governance_decisions.md
# ────────────────────────────────────────────────────────────────────────────


def _ts() -> str:
    """Return a human-readable timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _action_emoji(action: str) -> str:
    """Return an emoji for a governance action."""
    return {
        "allow": "✅",
        "deny":  "🚫",
        "block": "🚫",
        "redact": "✂️",
    }.get(str(action).lower(), "ℹ️")


class MemoryWriter:
    """
    Writes every governance decision to structured .md memory files.

    Usage in bridge.py:
        from governance_memory.writer import MemoryWriter
        memory_writer = MemoryWriter(base_dir=PROJECT_DIR)

        # After fraud_engine.analyze():
        memory_writer.record_decision(
            session_id=session_id,
            agent_id=spiffe_id,
            user_id=user_id,
            user_role=user_role,
            tool_name=tool_name,
            tool_args=tool_args,
            action=final_action,
            reason=final_reason,
            severity=final_severity,
            risk_score=fraud_engine.agent_risk_scores.get(spiffe_id, 0),
        )
    """

    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.mem_dir = self.base_dir / "governance_memory"

        # Sub-directories
        self.short_term_dir = self.mem_dir / "short_term"
        self.sessions_dir   = self.short_term_dir / "sessions"
        self.long_term_dir  = self.mem_dir / "long_term"

        # Thread safety — multiple threads write from bridge.py
        self._lock = threading.Lock()

        # Create the full directory tree if it doesn't exist
        self._init_dirs()

        # Initialize long-term .md files with headers if they are new
        self._init_long_term_files()

    # ── Directory & File Initialization ────────────────────────────────────

    def _init_dirs(self):
        """Create the governance_memory directory tree."""
        for d in [
            self.short_term_dir,
            self.sessions_dir,
            self.long_term_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)

    def _init_long_term_files(self):
        """Seed long-term .md files with headers on first creation."""
        files = {
            self.long_term_dir / "agent_profiles.md": self._agent_profiles_header(),
            self.long_term_dir / "attack_patterns.md": self._attack_patterns_header(),
            self.long_term_dir / "incident_history.md": self._incident_history_header(),
            self.long_term_dir / "policy_evolution.md": self._policy_evolution_header(),
            self.long_term_dir / "governance_decisions.md": self._governance_decisions_header(),
            self.short_term_dir / "active_threats.md": self._active_threats_header(),
            self.short_term_dir / "current_risk_state.md": self._risk_state_header(),
        }
        for path, header in files.items():
            if not path.exists():
                path.write_text(header, encoding="utf-8")

    # ── Public API ──────────────────────────────────────────────────────────

    def record_decision(
        self,
        session_id: str,
        agent_id: str,
        user_id: str,
        user_role: str,
        tool_name: str,
        tool_args: dict,
        action: str,
        reason: str,
        severity: str,
        risk_score: int = 0,
        memory_context: dict = None,
    ):
        """
        Main entry point — called from bridge.py after every governance decision.

        Writes to:
          1. short_term/sessions/{session_id}.md  — session log
          2. long_term/agent_profiles.md          — agent profile update
          3. long_term/incident_history.md        — on DENY/BLOCK only
          4. short_term/active_threats.md         — on DENY/BLOCK only
        """
        with self._lock:
            try:
                # 1. Always write to the session log
                self._write_session_entry(
                    session_id, agent_id, user_id, user_role,
                    tool_name, tool_args, action, reason, severity,
                    risk_score, memory_context
                )

                # 2. Update agent profile (always)
                self._update_agent_profile(
                    agent_id, user_id, user_role, tool_name, action, risk_score
                )

                # 3. On deny/block — also write to incident history + active threats
                if str(action).lower() in ("deny", "block"):
                    self._write_incident(
                        session_id, agent_id, user_id, tool_name,
                        tool_args, reason, severity, risk_score
                    )
                    self._update_active_threats(
                        agent_id, tool_name, reason, severity, risk_score
                    )

            except Exception as e:
                # Memory write failures must NEVER crash the bridge
                print(f"[MemoryWriter] ⚠️ Non-fatal write error: {e}", flush=True)

    def ensure_session_header(
        self,
        session_id: str,
        agent_id: str,
        user_id: str,
        user_role: str,
    ):
        """
        Create the session .md file with a header if it doesn't exist yet.
        Call this when a new connection/session starts.
        """
        with self._lock:
            session_file = self.sessions_dir / f"{session_id}.md"
            if not session_file.exists():
                header = (
                    f"# Session Memory: {session_id}\n\n"
                    f"| Field | Value |\n"
                    f"|-------|-------|\n"
                    f"| **Agent** | `{agent_id}` |\n"
                    f"| **User** | `{user_id}` |\n"
                    f"| **Role** | `{user_role}` |\n"
                    f"| **Started** | {_ts()} |\n\n"
                    f"---\n\n"
                    f"## Action Log\n\n"
                )
                session_file.write_text(header, encoding="utf-8")

    # ── Private Writers ─────────────────────────────────────────────────────

    def _write_session_entry(
        self,
        session_id, agent_id, user_id, user_role,
        tool_name, tool_args, action, reason, severity,
        risk_score, memory_context
    ):
        """Append one action line to the session .md file."""
        session_file = self.sessions_dir / f"{session_id}.md"

        # Create header if this is the first entry for this session
        if not session_file.exists():
            header = (
                f"# Session Memory: {session_id}\n\n"
                f"| Field | Value |\n"
                f"|-------|-------|\n"
                f"| **Agent** | `{agent_id}` |\n"
                f"| **User** | `{user_id}` |\n"
                f"| **Role** | `{user_role}` |\n"
                f"| **Started** | {_ts()} |\n\n"
                f"---\n\n"
                f"## Action Log\n\n"
            )
            session_file.write_text(header, encoding="utf-8")

        emoji = _action_emoji(action)
        action_upper = str(action).upper()

        # Summarize key args (avoid dumping huge objects)
        args_summary = ", ".join(
            f"`{k}`: `{str(v)[:60]}`"
            for k, v in (tool_args or {}).items()
            if k != "role"  # role is already in session header
        ) or "_(no args)_"

        # Memory context note
        mem_note = ""
        if memory_context:
            known = memory_context.get("known_attack_match")
            trust = memory_context.get("agent_trust_level", "")
            if known:
                mem_note = f" | 🧠 Memory: `{known}`"
            elif trust and trust != "new":
                mem_note = f" | 🧠 Trust: `{trust}`"

        line = (
            f"- [{_ts()}] {emoji} **{action_upper}** | "
            f"`{tool_name}` | {args_summary} | "
            f"_{reason}_ | Risk: `{risk_score}`{mem_note}\n"
        )

        with open(session_file, "a", encoding="utf-8") as f:
            f.write(line)

    def _update_agent_profile(
        self,
        agent_id: str,
        user_id: str,
        user_role: str,
        tool_name: str,
        action: str,
        risk_score: int,
    ):
        """
        Update the agent's entry in long_term/agent_profiles.md.
        Uses a simple text-search-and-replace approach on the .md file.
        """
        profile_file = self.long_term_dir / "agent_profiles.md"
        content = profile_file.read_text(encoding="utf-8")

        # Build the section header we look for
        section_marker = f"## Agent: {agent_id}"

        if section_marker not in content:
            # First time we've seen this agent — create a new profile section
            is_blocked = str(action).lower() in ("deny", "block")
            new_section = (
                f"\n{section_marker}\n\n"
                f"| Field | Value |\n"
                f"|-------|-------|\n"
                f"| **User ID** | `{user_id}` |\n"
                f"| **Role** | `{user_role}` |\n"
                f"| **Trust Level** | `new` |\n"
                f"| **First Seen** | {_ts()} |\n"
                f"| **Last Seen** | {_ts()} |\n"
                f"| **Total Calls** | `1` |\n"
                f"| **Blocked Attempts** | `{'1' if is_blocked else '0'}` |\n"
                f"| **Current Risk Score** | `{risk_score}` |\n"
                f"| **Most Used Tool** | `{tool_name}` |\n\n"
                f"---\n"
            )
            with open(profile_file, "a", encoding="utf-8") as f:
                f.write(new_section)
        else:
            # Agent exists — update Last Seen, Total Calls, Blocked, Risk Score
            lines = content.split("\n")
            in_section = False
            new_lines = []

            for line in lines:
                if line.startswith(f"## Agent: {agent_id}"):
                    in_section = True

                if in_section:
                    # Update Last Seen
                    if "| **Last Seen**" in line:
                        line = f"| **Last Seen** | {_ts()} |"

                    # Increment Total Calls
                    elif "| **Total Calls**" in line:
                        m = re.search(r"`(\d+)`", line)
                        if m:
                            new_count = int(m.group(1)) + 1
                            line = f"| **Total Calls** | `{new_count}` |"

                    # Increment Blocked if this was a deny/block
                    elif "| **Blocked Attempts**" in line and str(action).lower() in ("deny", "block"):
                        m = re.search(r"`(\d+)`", line)
                        if m:
                            new_count = int(m.group(1)) + 1
                            line = f"| **Blocked Attempts** | `{new_count}` |"

                    # Update Risk Score
                    elif "| **Current Risk Score**" in line:
                        line = f"| **Current Risk Score** | `{risk_score}` |"

                    # Update Trust Level based on risk score
                    elif "| **Trust Level**" in line:
                        trust = "trusted" if risk_score < 30 else ("suspicious" if risk_score < 150 else "high-risk")
                        line = f"| **Trust Level** | `{trust}` |"

                    # Stop updating after the section ends (next ## heading)
                    elif line.startswith("## ") and f"## Agent: {agent_id}" not in line:
                        in_section = False

                new_lines.append(line)

            profile_file.write_text("\n".join(new_lines), encoding="utf-8")

    def _write_incident(
        self,
        session_id: str,
        agent_id: str,
        user_id: str,
        tool_name: str,
        tool_args: dict,
        reason: str,
        severity: str,
        risk_score: int,
    ):
        """Append a block/deny incident to long_term/incident_history.md."""
        incident_file = self.long_term_dir / "incident_history.md"

        args_str = ", ".join(
            f"{k}={str(v)[:40]}" for k, v in (tool_args or {}).items() if k != "role"
        ) or "none"

        entry = (
            f"\n### Incident: {_ts()} | Severity: `{severity}`\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| **Session** | `{session_id}` |\n"
            f"| **Agent** | `{agent_id}` |\n"
            f"| **User** | `{user_id}` |\n"
            f"| **Tool** | `{tool_name}` |\n"
            f"| **Args** | `{args_str}` |\n"
            f"| **Reason** | {reason} |\n"
            f"| **Risk Score at Block** | `{risk_score}` |\n\n"
            f"---\n"
        )

        with open(incident_file, "a", encoding="utf-8") as f:
            f.write(entry)

    def _update_active_threats(
        self,
        agent_id: str,
        tool_name: str,
        reason: str,
        severity: str,
        risk_score: int,
    ):
        """
        Rewrite short_term/active_threats.md with the latest threat summary.
        This file is always current — read by the Memory Scanner for fast lookups.
        """
        threat_file = self.short_term_dir / "active_threats.md"

        # Read existing threats
        existing = threat_file.read_text(encoding="utf-8") if threat_file.exists() else self._active_threats_header()

        # Build the new entry line
        new_line = (
            f"| {_ts()} | `{agent_id}` | `{tool_name}` | "
            f"`{severity}` | `{risk_score}` | {reason[:80]} |\n"
        )

        # Append after the table header
        if "| Timestamp |" in existing:
            # Find the header separator line and insert after it
            lines = existing.split("\n")
            insert_idx = None
            for i, l in enumerate(lines):
                if l.startswith("|---"):
                    insert_idx = i + 1
                    break
            if insert_idx is not None:
                lines.insert(insert_idx, new_line.rstrip())
                # Keep only the most recent 50 threats to prevent unbounded growth
                header_end = insert_idx
                data_lines = [l for l in lines[header_end:] if l.startswith("|")]
                data_lines = data_lines[:50]
                final = "\n".join(lines[:header_end]) + "\n" + "\n".join(data_lines) + "\n"
                threat_file.write_text(final, encoding="utf-8")
            else:
                with open(threat_file, "a", encoding="utf-8") as f:
                    f.write(new_line)
        else:
            with open(threat_file, "a", encoding="utf-8") as f:
                f.write(new_line)

    # ── File Headers ────────────────────────────────────────────────────────

    def _agent_profiles_header(self) -> str:
        return (
            "# 🧠 Long-Term Memory: Agent Profiles\n\n"
            "> Auto-maintained by the Runtime Shield Governance Memory Layer.\n"
            "> Each section tracks one agent's historical behavior, trust level, and risk trends.\n\n"
            "---\n"
        )

    def _attack_patterns_header(self) -> str:
        return (
            "# 🛡️ Long-Term Memory: Attack Patterns\n\n"
            "> Known attack signatures detected across all sessions.\n"
            "> Updated by the Consolidator when cross-session patterns are confirmed.\n\n"
            "---\n"
        )

    def _incident_history_header(self) -> str:
        return (
            "# 🚨 Long-Term Memory: Incident History\n\n"
            "> Every DENY/BLOCK decision is recorded here with full context.\n"
            "> Used by the Audit Agent and Policy Advisor for pattern analysis.\n\n"
            "---\n"
        )

    def _policy_evolution_header(self) -> str:
        return (
            "# 📋 Long-Term Memory: Policy Evolution Log\n\n"
            "> Tracks every change to mcp-firewall.yaml (or OPA rules).\n"
            "> Each entry records what changed, why, and what memory evidence triggered it.\n\n"
            "---\n"
        )

    def _governance_decisions_header(self) -> str:
        return (
            "# 🏛️ Long-Term Memory: Governance Decisions & Recommendations\n\n"
            "> Policy recommendations generated by the Policy Advisor.\n"
            "> Each recommendation has a unique ID, a dedup fingerprint, and an engine-tracking field.\n\n"
            "| Field | Description |\n"
            "|-------|-------------|\n"
            "| **ID** | Unique recommendation ID (R-YYYY-NNNN) |\n"
            "| **Status** | PENDING → APPLIED → MIGRATED / ALREADY_COVERED / REJECTED |\n"
            "| **Applied To** | yaml, opa, both, or none |\n"
            "| **Fingerprint** | Semantic dedup key (tool:pattern:action) |\n\n"
            "---\n"
        )

    def _active_threats_header(self) -> str:
        return (
            "# ⚡ Short-Term Memory: Active Threats\n\n"
            "> Rolling log of the most recent 50 blocked attempts.\n"
            "> Overwritten on each update. Read by the Memory Scanner for fast lookups.\n\n"
            "| Timestamp | Agent | Tool | Severity | Risk Score | Reason |\n"
            "|-----------|-------|------|----------|------------|--------|\n"
        )

    def _risk_state_header(self) -> str:
        return (
            "# 📊 Short-Term Memory: Current Risk State\n\n"
            "> Updated by the Consolidator with the latest session risk summary.\n\n"
            "---\n"
        )
