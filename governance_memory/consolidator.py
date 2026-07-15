"""
MemoryConsolidator — Phase 3 Core Component.

Runs as a background daemon thread (every 5 minutes by default).

Responsibilities:
  1. Scans all short_term/sessions/*.md files
  2. Detects cross-session attack patterns (same tool+pattern from 2+ sessions)
  3. Promotes confirmed patterns to long_term/attack_patterns.md
  4. Writes governance recommendations to long_term/governance_decisions.md
  5. Archives/cleans up expired session files (older than SESSION_TTL_HOURS)
  6. Updates short_term/current_risk_state.md with a live summary

Usage in bridge.py:
    from governance_memory.consolidator import MemoryConsolidator
    memory_consolidator = MemoryConsolidator(base_dir=PROJECT_DIR)
    memory_consolidator.start()   # starts daemon thread — runs every 5 minutes
"""

import re
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


# ── Configuration ─────────────────────────────────────────────────────────────
CONSOLIDATION_INTERVAL_SEC = 300      # Run every 5 minutes
SESSION_TTL_HOURS = 24                # Archive sessions older than 24 hours
PATTERN_CONFIRM_THRESHOLD = 2         # Seen in 2+ sessions → promote to long-term
# ─────────────────────────────────────────────────────────────────────────────


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _rec_id() -> str:
    """Generate a unique recommendation ID like R-2026-42819."""
    import random
    return f"R-{datetime.now().strftime('%Y')}-{random.randint(10000, 99999)}"


class MemoryConsolidator:
    """
    Background thread that consolidates short-term session memories
    into long-term knowledge patterns.
    """

    def __init__(self, base_dir: str, interval_sec: int = CONSOLIDATION_INTERVAL_SEC):
        self.base_dir = Path(base_dir)
        self.mem_dir = self.base_dir / "governance_memory"
        self.short_term_dir = self.mem_dir / "short_term"
        self.sessions_dir = self.short_term_dir / "sessions"
        self.long_term_dir = self.mem_dir / "long_term"

        self.interval_sec = interval_sec
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="MemoryConsolidator",
            daemon=True,   # Dies automatically when bridge.py exits
        )
        self._lock = threading.Lock()

        # Track which patterns we've already promoted to avoid duplicates
        self._promoted_patterns: set = set()

        # ── DedupGuard: prevents duplicate rules across policy engines ──
        try:
            from governance_memory.dedup_guard import DedupGuard
            self._dedup = DedupGuard(base_dir=str(self.base_dir))
        except Exception as _dg_err:
            self._dedup = None
            print(f"[MemoryConsolidator] ⚠️ DedupGuard unavailable: {_dg_err}", flush=True)

        # Load already-promoted patterns from long_term file on startup
        self._load_existing_patterns()

    # ── Public API ─────────────────────────────────────────────────────────

    def start(self):
        """Start the consolidator background thread."""
        print("[MemoryConsolidator] 🧠 Starting background consolidation thread "
              f"(interval: {self.interval_sec}s)", flush=True)
        self._thread.start()

    def stop(self):
        """Signal the consolidator to stop gracefully."""
        self._stop_event.set()

    def run_once(self):
        """
        Run one consolidation cycle manually.
        Useful for testing or triggering from the dashboard.
        """
        self._consolidate()

    # ── Core Loop ──────────────────────────────────────────────────────────

    def _run_loop(self):
        """Main daemon loop — runs consolidation every interval_sec."""
        # Wait a bit on startup before the first run so bridge.py fully initializes
        time.sleep(30)

        while not self._stop_event.is_set():
            try:
                self._consolidate()
            except Exception as e:
                print(f"[MemoryConsolidator] ⚠️ Non-fatal consolidation error: {e}",
                      flush=True)

            # Wait for next cycle (checks stop_event every second)
            for _ in range(self.interval_sec):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

        print("[MemoryConsolidator] 🛑 Consolidator stopped.", flush=True)

    # ── Consolidation Logic ────────────────────────────────────────────────

    def _consolidate(self):
        """One full consolidation cycle."""
        print(f"[MemoryConsolidator] 🔄 Running consolidation cycle at {_ts()}",
              flush=True)

        with self._lock:
            # Step 1: Read and parse all active session files
            sessions = self._read_all_sessions()

            if not sessions:
                print("[MemoryConsolidator] ℹ️ No session files found — nothing to consolidate.",
                      flush=True)
                return

            # Step 2: Detect cross-session attack patterns
            patterns = self._detect_patterns(sessions)

            # Step 3: Promote confirmed patterns to long-term memory
            new_promotions = self._promote_patterns(patterns)

            # Step 4: Write governance recommendations for new patterns
            if new_promotions:
                self._write_recommendations(new_promotions)

            # Step 5: Update live risk state summary
            self._update_risk_state(sessions)

            # Step 6: Archive expired session files
            archived = self._archive_expired_sessions()

            print(
                f"[MemoryConsolidator] ✅ Cycle complete — "
                f"{len(sessions)} sessions scanned, "
                f"{len(new_promotions)} new patterns promoted, "
                f"{archived} sessions archived.",
                flush=True
            )

    # ── Step 1: Read Sessions ──────────────────────────────────────────────

    def _read_all_sessions(self) -> list[dict]:
        """
        Parse all .md files in short_term/sessions/ and return structured data.

        Returns a list of session dicts:
        {
            "session_id": str,
            "agent_id":   str,
            "user_id":    str,
            "started_at": datetime | None,
            "file_path":  Path,
            "actions":    [{"tool": str, "action": str, "reason": str, "risk": int}]
            "deny_count": int,
            "tools_used": [str],
        }
        """
        sessions = []

        if not self.sessions_dir.exists():
            return sessions

        for session_file in self.sessions_dir.glob("*.md"):
            try:
                content = session_file.read_text(encoding="utf-8")
                session = self._parse_session_file(session_file, content)
                if session:
                    sessions.append(session)
            except Exception as e:
                print(f"[MemoryConsolidator] ⚠️ Could not parse {session_file.name}: {e}",
                      flush=True)

        return sessions

    def _parse_session_file(self, file_path: Path, content: str) -> dict | None:
        """Parse a single session .md file into a structured dict."""
        session = {
            "session_id": file_path.stem,
            "agent_id":   "unknown",
            "user_id":    "unknown",
            "started_at": None,
            "file_path":  file_path,
            "actions":    [],
            "deny_count": 0,
            "tools_used": [],
        }

        # Extract header table fields
        for line in content.split("\n"):
            # | **Agent** | `value` |
            m = re.match(r"\|\s*\*\*Agent\*\*\s*\|\s*`?(.+?)`?\s*\|", line)
            if m:
                session["agent_id"] = m.group(1).strip()

            m = re.match(r"\|\s*\*\*User\*\*\s*\|\s*`?(.+?)`?\s*\|", line)
            if m:
                session["user_id"] = m.group(1).strip()

            m = re.match(r"\|\s*\*\*Started\*\*\s*\|\s*(.+?)\s*\|", line)
            if m:
                try:
                    session["started_at"] = datetime.strptime(
                        m.group(1).strip(), "%Y-%m-%d %H:%M:%S"
                    )
                except ValueError:
                    pass

            # Action log lines (actual format from writer.py):
            # - [2026-07-12 22:54:55] 🚫 **DENY** | `read_file` | `path`: `../../etc/passwd` | _reason_ | Risk: `25`
            if line.startswith("- [") and "**" in line and "Risk:" in line:
                # Extract action word (DENY / ALLOW / REDACT)
                action_m  = re.search(r"\*\*(\w+)\*\*", line)
                # Extract first backtick-quoted word after **ACTION** | → tool name
                tool_m    = re.search(r"\*\*\w+\*\*\s*\|\s*`([^`]+)`", line)
                # Extract reason in _italics_
                reason_m  = re.search(r"_([^_]+)_", line)
                # Extract risk score
                risk_m    = re.search(r"Risk:\s*`(\d+)`", line)
                # Extract timestamp
                ts_m      = re.search(r"\[([^\]]+)\]", line)

                if action_m and tool_m and risk_m:
                    action_entry = {
                        "timestamp": ts_m.group(1).strip() if ts_m else "",
                        "action":    action_m.group(1).strip().lower(),
                        "tool":      tool_m.group(1).strip(),
                        "reason":    reason_m.group(1).strip() if reason_m else "",
                        "risk":      int(risk_m.group(1)),
                    }
                    session["actions"].append(action_entry)
                    session["tools_used"].append(action_entry["tool"])
                    if action_entry["action"] in ("deny", "block"):
                        session["deny_count"] += 1

        return session if session["agent_id"] != "unknown" else None

    # ── Step 2: Detect Cross-Session Patterns ─────────────────────────────

    def _detect_patterns(self, sessions: list[dict]) -> list[dict]:
        """
        Identify attack patterns that appear in 2+ sessions.

        Groups deny events by (tool, reason_category) across sessions and
        flags combinations that appear in >= PATTERN_CONFIRM_THRESHOLD sessions.
        """
        # Map: pattern_key → {sessions: set, agents: set, count: int, example_reason: str}
        pattern_map: dict = defaultdict(lambda: {
            "sessions": set(), "agents": set(), "count": 0, "example_reason": ""
        })

        for session in sessions:
            for action in session["actions"]:
                if action["action"] not in ("deny", "block"):
                    continue

                # Build a canonical pattern key
                reason_cat = self._categorize_reason(action["reason"])
                key = f"{action['tool']}:{reason_cat}"

                pattern_map[key]["sessions"].add(session["session_id"])
                pattern_map[key]["agents"].add(session["agent_id"])
                pattern_map[key]["count"] += 1
                if not pattern_map[key]["example_reason"]:
                    pattern_map[key]["example_reason"] = action["reason"]

        # Filter to patterns seen in 2+ sessions
        confirmed = []
        for key, data in pattern_map.items():
            if len(data["sessions"]) >= PATTERN_CONFIRM_THRESHOLD:
                tool, category = key.split(":", 1)
                confirmed.append({
                    "key":            key,
                    "tool":           tool,
                    "category":       category,
                    "session_count":  len(data["sessions"]),
                    "agent_count":    len(data["agents"]),
                    "total_attempts": data["count"],
                    "example_reason": data["example_reason"],
                    "agents":         list(data["agents"]),
                })

        return confirmed

    def _categorize_reason(self, reason: str) -> str:
        """Map a raw block reason string to a short canonical category."""
        reason_lower = reason.lower()
        if "traversal" in reason_lower or "../" in reason_lower:
            return "path_traversal"
        if "injection" in reason_lower or "eval" in reason_lower or "constructor" in reason_lower:
            return "code_injection"
        if "honeypot" in reason_lower:
            return "honeypot_access"
        if "role" in reason_lower or "rbac" in reason_lower or "admin" in reason_lower:
            return "rbac_violation"
        if "pii" in reason_lower or "redact" in reason_lower:
            return "pii_leak"
        if "rate" in reason_lower or "limit" in reason_lower:
            return "rate_limit"
        if "jailbreak" in reason_lower or "topical" in reason_lower:
            return "jailbreak_attempt"
        return "other_block"

    # ── Step 3: Promote to Long-Term ──────────────────────────────────────

    def _promote_patterns(self, patterns: list[dict]) -> list[dict]:
        """
        Write newly confirmed patterns to long_term/attack_patterns.md.
        Skips patterns already promoted (tracked in self._promoted_patterns).
        Returns the list of newly promoted patterns.
        """
        new_promotions = []

        for pattern in patterns:
            key = pattern["key"]
            if key in self._promoted_patterns:
                # Already in long-term — update occurrence count only
                self._increment_pattern_count(key, pattern["total_attempts"])
                continue

            # New pattern — write a full entry
            self._write_attack_pattern(pattern)
            self._promoted_patterns.add(key)
            new_promotions.append(pattern)

        return new_promotions

    def _write_attack_pattern(self, pattern: dict):
        """Append a new confirmed attack pattern to long_term/attack_patterns.md."""
        pattern_file = self.long_term_dir / "attack_patterns.md"

        # Generate a human-readable pattern ID
        count = len(self._promoted_patterns) + 1
        pattern_id = f"P-{count:04d}"

        entry = (
            f"\n## Pattern: {pattern_id} — {pattern['category'].replace('_', ' ').title()}\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| **Tool** | `{pattern['tool']}` |\n"
            f"| **Category** | `{pattern['category']}` |\n"
            f"| **Pattern Key** | `{pattern['key']}` |\n"
            f"| **First Promoted** | {_ts()} |\n"
            f"| **Last Seen** | {_ts()} |\n"
            f"| **Session Count** | `{pattern['session_count']}` |\n"
            f"| **Agent Count** | `{pattern['agent_count']}` |\n"
            f"| **Total Attempts** | `{pattern['total_attempts']}` |\n"
            f"| **Example Reason** | {pattern['example_reason']} |\n"
            f"| **Known Agents** | {', '.join(f'`{a}`' for a in pattern['agents'][:5])} |\n\n"
            f"---\n"
        )

        with open(pattern_file, "a", encoding="utf-8") as f:
            f.write(entry)

    def _increment_pattern_count(self, key: str, new_total: int):
        """Update the Total Attempts count for an existing pattern entry."""
        pattern_file = self.long_term_dir / "attack_patterns.md"
        if not pattern_file.exists():
            return

        content = pattern_file.read_text(encoding="utf-8")
        # Find the line with this pattern key and update total attempts
        lines = content.split("\n")
        new_lines = []
        in_pattern = False

        for line in lines:
            if f"| **Pattern Key** | `{key}`" in line:
                in_pattern = True
            if in_pattern and "| **Total Attempts**" in line:
                line = f"| **Total Attempts** | `{new_total}` |"
                in_pattern = False
            if in_pattern and "| **Last Seen**" in line:
                line = f"| **Last Seen** | {_ts()} |"
            new_lines.append(line)

        pattern_file.write_text("\n".join(new_lines), encoding="utf-8")

    def _load_existing_patterns(self):
        """Load already-promoted pattern keys from attack_patterns.md on startup."""
        pattern_file = self.long_term_dir / "attack_patterns.md"
        if not pattern_file.exists():
            return

        content = pattern_file.read_text(encoding="utf-8")
        for m in re.finditer(r"\*\*Pattern Key\*\*\s*\|\s*`([^`]+)`", content):
            self._promoted_patterns.add(m.group(1))

        if self._promoted_patterns:
            print(f"[MemoryConsolidator] 📖 Loaded {len(self._promoted_patterns)} "
                  f"existing patterns from long-term memory.", flush=True)

    # ── Step 4: Governance Recommendations ────────────────────────────────

    def _write_recommendations(self, new_promotions: list[dict]):
        """
        Write a new governance recommendation for each newly promoted pattern.
        Calls DedupGuard.is_duplicate() before writing — skips rules already
        covered by active YAML/OPA rules or existing recommendations.
        """
        decisions_file = self.long_term_dir / "governance_decisions.md"

        for pattern in new_promotions:
            rec_id      = _rec_id()
            fingerprint = f"{pattern['tool']}:{pattern['category']}:deny"

            # ── DEDUP CHECK ──
            if self._dedup and self._dedup.is_duplicate(fingerprint, engine="yaml"):
                print(
                    f"[MemoryConsolidator] ⚠️  DEDUP SKIP: '{fingerprint}' already covered "
                    f"by an active YAML rule or existing recommendation — not writing duplicate.",
                    flush=True
                )
                continue
            # ──────────────────

            # Build a suggested rule description (human-readable, engine-agnostic)
            suggestion = self._build_rule_suggestion(pattern)

            entry = (
                f"\n## Recommendation: {rec_id}\n\n"
                f"| Field | Value |\n"
                f"|-------|-------|\n"
                f"| **Pattern** | {pattern['category'].replace('_', ' ').title()} on `{pattern['tool']}` |\n"
                f"| **Source** | Observed in `{pattern['session_count']}` sessions, "
                f"`{pattern['agent_count']}` unique agents |\n"
                f"| **Fingerprint** | `{fingerprint}` |\n"
                f"| **Suggested Rule** | {suggestion} |\n"
                f"| **Status** | `PENDING` |\n"
                f"| **Applied To** | `none` |\n"
                f"| **Created At** | {_ts()} |\n"
                f"| **Engine Switch Note** | Verify equivalent rule exists when switching YAML ↔ OPA |\n\n"
                f"---\n"
            )

            with open(decisions_file, "a", encoding="utf-8") as f:
                f.write(entry)

            print(f"[MemoryConsolidator] 📋 Recommendation {rec_id} written: {fingerprint}",
                  flush=True)

    def _build_rule_suggestion(self, pattern: dict) -> str:
        """Generate a human-readable rule suggestion based on pattern category."""
        suggestions = {
            "path_traversal":   f"Deny `{pattern['tool']}` calls with `../` or `..\\` in any argument (seen {pattern['total_attempts']}x)",
            "code_injection":   f"Deny `{pattern['tool']}` calls containing `eval`, `constructor`, or `Function(` patterns",
            "honeypot_access":  f"Rate-limit or block `{pattern['tool']}` entirely — accessed {pattern['total_attempts']}x by {pattern['agent_count']} agents",
            "rbac_violation":   f"Review role requirements for `{pattern['tool']}` — {pattern['total_attempts']} unauthorized attempts",
            "pii_leak":         f"Enforce PII redaction for all outputs from `{pattern['tool']}`",
            "rate_limit":       f"Add stricter rate limiting to `{pattern['tool']}` (current limit being triggered repeatedly)",
            "jailbreak_attempt":f"Escalate jailbreak detection sensitivity for `{pattern['tool']}` context",
            "other_block":      f"Review blocking policy for `{pattern['tool']}` — {pattern['total_attempts']} denials detected",
        }
        return suggestions.get(pattern["category"], f"Review `{pattern['tool']}` access policy")

    # ── Step 5: Update Risk State ──────────────────────────────────────────

    def _update_risk_state(self, sessions: list[dict]):
        """Rewrite short_term/current_risk_state.md with a live summary."""
        risk_file = self.short_term_dir / "current_risk_state.md"

        total_sessions = len(sessions)
        total_denies = sum(s["deny_count"] for s in sessions)
        active_agents = len({s["agent_id"] for s in sessions})
        high_risk_sessions = [s for s in sessions if s["deny_count"] >= 3]

        content = (
            f"# 📊 Short-Term Memory: Current Risk State\n\n"
            f"> Last updated by Consolidator: {_ts()}\n\n"
            f"---\n\n"
            f"## Live Summary\n\n"
            f"| Metric | Value |\n"
            f"|--------|-------|\n"
            f"| **Active Sessions Scanned** | `{total_sessions}` |\n"
            f"| **Unique Agents** | `{active_agents}` |\n"
            f"| **Total Denies This Window** | `{total_denies}` |\n"
            f"| **High-Risk Sessions** (≥3 blocks) | `{len(high_risk_sessions)}` |\n"
            f"| **Known Patterns in Long-Term** | `{len(self._promoted_patterns)}` |\n\n"
        )

        if high_risk_sessions:
            content += "## ⚠️ High-Risk Agents This Window\n\n"
            content += "| Agent | Session | Blocks |\n"
            content += "|-------|---------|--------|\n"
            for s in high_risk_sessions[:10]:
                content += (
                    f"| `{s['agent_id']}` | `{s['session_id']}` | `{s['deny_count']}` |\n"
                )
            content += "\n"

        risk_file.write_text(content, encoding="utf-8")

    # ── Step 6: Archive Expired Sessions ──────────────────────────────────

    def _archive_expired_sessions(self) -> int:
        """
        Move session files older than SESSION_TTL_HOURS to an archive subfolder.
        Returns the count of archived files.
        """
        archive_dir = self.sessions_dir / "archive"
        archive_dir.mkdir(exist_ok=True)

        cutoff = datetime.now() - timedelta(hours=SESSION_TTL_HOURS)
        archived_count = 0

        for session_file in self.sessions_dir.glob("*.md"):
            # Check file modification time
            mtime = datetime.fromtimestamp(session_file.stat().st_mtime)
            if mtime < cutoff:
                dest = archive_dir / session_file.name
                session_file.rename(dest)
                archived_count += 1
                print(f"[MemoryConsolidator] 📦 Archived expired session: {session_file.name}",
                      flush=True)

        return archived_count
