"""
PolicyAdvisor — Phase 4 Core Component.

Reads long-term memory files and provides structured governance insights:
  - PENDING recommendations from governance_decisions.md
  - Attack pattern summaries from attack_patterns.md
  - Agent profile summaries from agent_profiles.md
  - Current risk state from current_risk_state.md

Used by the dashboard REST API endpoints to power the
Governance Intelligence panel at http://localhost:9090.
"""

import re
import os
from pathlib import Path
from datetime import datetime


class PolicyAdvisor:
    """
    Read-only view into the governance memory long-term files.
    Returns structured dicts suitable for JSON API responses.
    """

    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.mem_dir  = self.base_dir / "governance_memory"
        self.lt_dir   = self.mem_dir / "long_term"
        self.st_dir   = self.mem_dir / "short_term"

    # ── Public API ──────────────────────────────────────────────────────────

    def get_recommendations(self, status_filter: str = None) -> list[dict]:
        """
        Parse governance_decisions.md and return all recommendations.
        Optionally filter by status: PENDING | APPLIED | REJECTED | etc.
        """
        file = self.lt_dir / "governance_decisions.md"
        if not file.exists():
            return []

        content = file.read_text(encoding="utf-8")
        recs = self._parse_recommendations(content)

        if status_filter:
            recs = [r for r in recs if r.get("status", "").upper() == status_filter.upper()]

        return recs

    def get_attack_patterns(self) -> list[dict]:
        """Parse attack_patterns.md and return all known patterns."""
        file = self.lt_dir / "attack_patterns.md"
        if not file.exists():
            return []

        content = file.read_text(encoding="utf-8")
        return self._parse_attack_patterns(content)

    def get_agent_profiles(self) -> list[dict]:
        """Parse agent_profiles.md and return all agent profiles."""
        file = self.lt_dir / "agent_profiles.md"
        if not file.exists():
            return []

        content = file.read_text(encoding="utf-8")
        return self._parse_agent_profiles(content)

    def get_risk_state(self) -> dict:
        """Read current_risk_state.md and return the live summary."""
        file = self.st_dir / "current_risk_state.md"
        if not file.exists():
            return {"error": "Risk state not yet generated — run consolidator first"}

        content = file.read_text(encoding="utf-8")
        return self._parse_risk_state(content)

    def get_memory_stats(self) -> dict:
        """Return file counts, sizes, and last-modified timestamps for all memory files."""
        stats = {
            "short_term": {"sessions": 0, "session_size_kb": 0},
            "long_term":  {},
            "last_consolidation": None,
        }

        sessions_dir = self.st_dir / "sessions"
        if sessions_dir.exists():
            session_files = list(sessions_dir.glob("*.md"))
            stats["short_term"]["sessions"] = len(session_files)
            stats["short_term"]["session_size_kb"] = round(
                sum(f.stat().st_size for f in session_files) / 1024, 1
            )

        for name in ["attack_patterns", "agent_profiles", "incident_history",
                     "governance_decisions", "policy_evolution"]:
            f = self.lt_dir / f"{name}.md"
            if f.exists():
                stats["long_term"][name] = {
                    "size_kb": round(f.stat().st_size / 1024, 1),
                    "modified": datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                }

        risk_file = self.st_dir / "current_risk_state.md"
        if risk_file.exists():
            stats["last_consolidation"] = datetime.fromtimestamp(
                risk_file.stat().st_mtime
            ).strftime("%Y-%m-%d %H:%M:%S")

        return stats

    def update_recommendation_status(self, rec_id: str, new_status: str, applied_to: str = None) -> bool:
        """
        Update a recommendation's status in governance_decisions.md.
        Returns True if the recommendation was found and updated.
        """
        file = self.lt_dir / "governance_decisions.md"
        if not file.exists():
            return False

        content = file.read_text(encoding="utf-8")
        lines   = content.split("\n")
        new_lines = []
        in_rec = False
        updated = False

        for line in lines:
            if f"## Recommendation: {rec_id}" in line:
                in_rec = True

            if in_rec:
                if "| **Status**" in line:
                    line = f"| **Status** | `{new_status}` |"
                    updated = True
                if applied_to and "| **Applied To**" in line:
                    line = f"| **Applied To** | `{applied_to}` |"
                # Stop updating once we hit the next section
                if line.startswith("## ") and rec_id not in line:
                    in_rec = False

            new_lines.append(line)

        if updated:
            file.write_text("\n".join(new_lines), encoding="utf-8")

        return updated

    # ── Parsers ─────────────────────────────────────────────────────────────

    def _parse_recommendations(self, content: str) -> list[dict]:
        recs = []
        sections = re.split(r"\n## Recommendation: ", content)

        for section in sections[1:]:
            lines = section.strip().split("\n")
            rec = {"id": lines[0].strip()}

            for line in lines[1:]:
                m = re.match(r"\|\s*\*\*(.+?)\*\*\s*\|\s*(.+?)\s*\|", line)
                if m:
                    key = m.group(1).strip().lower().replace(" ", "_")
                    val = m.group(2).strip().strip("`")
                    rec[key] = val

            if "id" in rec and "fingerprint" in rec:
                recs.append(rec)

        return recs

    def _parse_attack_patterns(self, content: str) -> list[dict]:
        patterns = []
        sections = re.split(r"\n## Pattern: ", content)

        for section in sections[1:]:
            lines = section.strip().split("\n")
            pat = {"name": lines[0].strip()}

            for line in lines[1:]:
                m = re.match(r"\|\s*\*\*(.+?)\*\*\s*\|\s*`?(.+?)`?\s*\|", line)
                if m:
                    key = m.group(1).strip().lower().replace(" ", "_")
                    val = m.group(2).strip().strip("`")
                    pat[key] = val

            for num_field in ("session_count", "agent_count", "total_attempts"):
                if num_field in pat:
                    try:
                        pat[num_field] = int(pat[num_field])
                    except ValueError:
                        pass

            if "pattern_key" in pat:
                patterns.append(pat)

        return patterns

    def _parse_agent_profiles(self, content: str) -> list[dict]:
        profiles = []
        sections = re.split(r"\n## Agent: ", content)

        for section in sections[1:]:
            lines = section.strip().split("\n")
            prof = {"agent_id": lines[0].strip()}

            for line in lines[1:]:
                m = re.match(r"\|\s*\*\*(.+?)\*\*\s*\|\s*`?(.+?)`?\s*\|", line)
                if m:
                    key = m.group(1).strip().lower().replace(" ", "_")
                    val = m.group(2).strip().strip("`")
                    prof[key] = val

            for num_field in ("total_calls", "blocked_attempts", "current_risk_score"):
                if num_field in prof:
                    try:
                        prof[num_field] = int(prof[num_field])
                    except ValueError:
                        pass

            if "agent_id" in prof and len(prof) > 1:
                profiles.append(prof)

        return profiles

    def _parse_risk_state(self, content: str) -> dict:
        state = {}

        for line in content.split("\n"):
            m = re.match(r"\|\s*\*\*(.+?)\*\*(?:\s*\([^)]*\))?\s*\|\s*`?(\d+)`?\s*\|", line)
            if m:
                key = m.group(1).strip().lower().replace(" ", "_").replace("(", "").replace(")", "")
                try:
                    state[key] = int(m.group(2))
                except ValueError:
                    state[key] = m.group(2)

        # Extract last updated timestamp
        ts_m = re.search(r"Last updated by Consolidator:\s*(.+)", content)
        if ts_m:
            state["last_updated"] = ts_m.group(1).strip()

        return state
