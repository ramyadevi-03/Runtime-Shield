"""
DedupGuard — Phase 6 Core Component.

Prevents rule duplication when:
  1. Memory Consolidator recommends a new rule that already exists in the active engine
  2. Switching policy engines (YAML → OPA or OPA → YAML), where rules may overlap

How it works — 3 safeguards:

  Safeguard 1 — Pre-write duplicate check:
      Before writing a recommendation to governance_decisions.md, call
      guard.is_duplicate(fingerprint, engine) → True if already covered

  Safeguard 2 — Rule fingerprinting:
      Every recommendation gets a canonical key: tool:category:action
      e.g.  "read_file:path_traversal:deny"
      The guard reads active YAML/OPA rules and computes the same fingerprint,
      then compares before allowing a new recommendation.

  Safeguard 3 — Engine migration check:
      When switching YAML → OPA (or vice versa), call
      guard.check_migration(from_engine, to_engine) → list of migration items
      Each item says: ALREADY_COVERED | NEEDS_MIGRATION | UNKNOWN

Usage:
    from governance_memory.dedup_guard import DedupGuard

    guard = DedupGuard(base_dir=PROJECT_DIR)

    # Before writing a recommendation:
    if guard.is_duplicate("read_file:path_traversal:deny", engine="yaml"):
        log("Skipping — rule already covered")
    else:
        write_recommendation(...)

    # On engine switch:
    report = guard.check_migration(from_engine="yaml", to_engine="opa")
    for item in report:
        print(item["id"], item["status"])  # ALREADY_COVERED | NEEDS_MIGRATION
"""

import os
import re
from pathlib import Path
from datetime import datetime



def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── YAML → Fingerprint Mapping ────────────────────────────────────────────────
# Maps YAML rule names to their canonical fingerprint.
# Used to check if a recommended rule already exists in mcp-firewall.yaml.
YAML_RULE_FINGERPRINTS = {
    "block-traversal":                 "read_file:path_traversal:deny",
    "block-vuln-fs-traversal":         "read_file:path_traversal:deny",
    "block-vuln-fs-absolute":          "read_file:path_traversal:deny",
    "block-vuln-fs-all-default":       "read_file:path_traversal:deny",
    "block-env-access":                "read_file:credential_access:deny",
    "block-honeypots":                 "get_system_config:honeypot_access:deny",
    "block-eval-injection-process":    "vuln_get_qotd:code_injection:deny",
    "block-eval-injection-require":    "vuln_get_qotd:code_injection:deny",
    "block-eval-injection-constructor":"vuln_get_qotd:code_injection:deny",
    "block-cmd-injection-semicolon":   "vuln_run_diagnostic:command_injection:deny",
    "block-cmd-injection-pipe":        "vuln_run_diagnostic:command_injection:deny",
    "block-cmd-injection-backtick":    "vuln_run_diagnostic:command_injection:deny",
    "block-ip-leakage":                "vuln_get_current_ip:infrastructure_disclosure:deny",
    "block-unauthorized-fs":           "read_file:rbac_violation:deny",
    "block-admin-access":              "read_file:rbac_violation:deny",
    "deny-user-active-connections":    "get_active_connections:rbac_violation:deny",
    "deny-user-scan-dependencies":     "scan_dependencies:rbac_violation:deny",
}
# ─────────────────────────────────────────────────────────────────────────────


class DedupGuard:
    """
    Prevents rule duplication across governance memory and policy engines.
    Stateless between calls — reads live files every time for accuracy.
    """

    def __init__(self, base_dir: str):
        self.base_dir     = Path(base_dir)
        self.mem_dir      = self.base_dir / "governance_memory"
        self.lt_dir       = self.mem_dir / "long_term"
        self.yaml_path    = self.base_dir / "mcp-firewall.yaml"
        self.rules_dir    = self.base_dir / "rules"
        self.decisions_file = self.lt_dir / "governance_decisions.md"

        # In-memory fingerprint cache for the current process lifetime
        # (refreshed when YAML changes)
        self._yaml_fingerprints: set[str] = set()
        self._yaml_mtime: float = 0.0
        self._applied_fingerprints: set[str] = set()

    # ── Public API ──────────────────────────────────────────────────────────

    def is_duplicate(self, fingerprint: str, engine: str = "yaml") -> bool:
        """
        Check if a rule with this fingerprint already exists in:
          - The active policy engine (yaml rules or opa policies)
          - The governance_decisions.md (already recommended/applied)

        Returns True if a duplicate is found — caller should skip writing the rec.
        """
        fingerprint = fingerprint.lower().strip()

        # Check 1: Already in active YAML rules?
        if engine in ("yaml", "both"):
            yaml_fps = self._get_yaml_fingerprints()
            if fingerprint in yaml_fps:
                return True

        # Check 2: Already in OPA rules? (placeholder — OPA not yet deployed)
        if engine in ("opa", "both"):
            opa_fps = self._get_opa_fingerprints()
            if fingerprint in opa_fps:
                return True

        # Check 3: Already in governance_decisions.md (APPLIED or PENDING)?
        existing = self._get_applied_fingerprints()
        if fingerprint in existing:
            return True

        return False

    def check_migration(self, from_engine: str, to_engine: str) -> list[dict]:
        """
        When switching between policy engines (e.g. yaml → opa), analyse
        every APPLIED recommendation and report its migration status.

        Returns a list of dicts:
        {
            "id":          str,       # Recommendation ID e.g. R-2026-12345
            "fingerprint": str,
            "status":      str,       # ALREADY_COVERED | NEEDS_MIGRATION | UNKNOWN
            "reason":      str,
        }
        """
        report = []
        recs   = self._parse_decisions()

        # Get fingerprints already in the destination engine
        if to_engine == "opa":
            dest_fps = self._get_opa_fingerprints()
        else:
            dest_fps = self._get_yaml_fingerprints()

        for rec in recs:
            fp     = rec.get("fingerprint", "").lower()
            status = rec.get("status", "PENDING").upper()

            # Only analyse APPLIED recommendations
            if status not in ("APPLIED", "PENDING"):
                continue

            if not fp:
                report.append({
                    "id": rec.get("id", "?"),
                    "fingerprint": fp,
                    "status": "UNKNOWN",
                    "reason": "No fingerprint recorded for this recommendation",
                })
                continue

            if fp in dest_fps:
                migration_status = "ALREADY_COVERED"
                reason = f"Equivalent rule exists in {to_engine} — no migration needed"
            else:
                migration_status = "NEEDS_MIGRATION"
                reason = (
                    f"Rule '{fp}' is in {from_engine} but not found in {to_engine} — "
                    f"manual porting required before switching engines"
                )

            report.append({
                "id":          rec.get("id", "?"),
                "fingerprint": fp,
                "status":      migration_status,
                "reason":      reason,
            })

        return report

    def register_applied(self, fingerprint: str, rec_id: str, engine: str):
        """
        Mark a recommendation as APPLIED in governance_decisions.md.
        Also updates the in-memory cache so subsequent is_duplicate() calls
        catch it immediately.
        """
        fingerprint = fingerprint.lower().strip()
        self._applied_fingerprints.add(fingerprint)
        self._update_decision_status(rec_id, "APPLIED", applied_to=engine)

    def get_yaml_coverage(self) -> list[dict]:
        """
        Return all rules currently active in mcp-firewall.yaml as
        structured dicts with their fingerprints.
        Used by the dashboard to show what's already covered.
        """
        rules     = self._load_yaml_rules()
        coverage  = []
        for rule in rules:
            name = rule.get("name", "unnamed")
            fp   = YAML_RULE_FINGERPRINTS.get(name)
            coverage.append({
                "rule_name":   name,
                "fingerprint": fp or self._infer_fingerprint(rule),
                "action":      rule.get("action", "unknown"),
                "tool":        rule.get("tool", "*"),
                "source":      "yaml",
            })
        return coverage

    def get_dedup_report(self) -> dict:
        """
        Full deduplication status report — used by the dashboard API.
        Shows:
          - All YAML rule fingerprints active
          - All recommendation fingerprints (PENDING / APPLIED)
          - Which recommendations are duplicates of existing YAML rules
        """
        yaml_fps  = self._get_yaml_fingerprints()
        recs      = self._parse_decisions()

        duplicates = []
        new_rules  = []
        pending    = []

        for rec in recs:
            fp     = rec.get("fingerprint", "").lower()
            status = rec.get("status", "PENDING").upper()

            if status == "PENDING":
                pending.append(rec)
                if fp in yaml_fps:
                    duplicates.append({
                        "rec_id":      rec.get("id"),
                        "fingerprint": fp,
                        "note":        "Already covered by an active YAML rule — safe to REJECT",
                    })
                else:
                    new_rules.append({
                        "rec_id":      rec.get("id"),
                        "fingerprint": fp,
                        "note":        "New rule — not yet in any policy engine",
                    })

        return {
            "yaml_rules_active":    len(yaml_fps),
            "yaml_fingerprints":    sorted(yaml_fps),
            "recommendations_total": len(recs),
            "pending_count":        len(pending),
            "duplicates_found":     len(duplicates),
            "duplicates":           duplicates,
            "new_rules_needed":     new_rules,
            "generated_at":         _ts(),
        }

    # ── Private: YAML Parser ────────────────────────────────────────────────

    def _load_yaml_rules(self) -> list[dict]:
        """Load and return all rules from mcp-firewall.yaml."""
        if not self.yaml_path.exists():
            return []
        try:
            import yaml  # lazy import — only needed when YAML engine is active
            with open(self.yaml_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            return config.get("rules", []) if config else []
        except Exception:
            return []

    def _get_yaml_fingerprints(self) -> set[str]:
        """
        Return the set of semantic fingerprints for all active YAML rules.
        Uses a file-mtime cache so we only re-parse when the file changes.
        """
        if not self.yaml_path.exists():
            return set()

        try:
            mtime = self.yaml_path.stat().st_mtime
            if mtime != self._yaml_mtime:
                rules = self._load_yaml_rules()
                fps   = set()
                for rule in rules:
                    name = rule.get("name", "")
                    # Try the static map first
                    if name in YAML_RULE_FINGERPRINTS:
                        fps.add(YAML_RULE_FINGERPRINTS[name])
                    else:
                        # Fall back to inference
                        inferred = self._infer_fingerprint(rule)
                        if inferred:
                            fps.add(inferred)
                self._yaml_fingerprints = fps
                self._yaml_mtime = mtime
            return self._yaml_fingerprints
        except Exception:
            return set()

    def _infer_fingerprint(self, rule: dict) -> str | None:
        """
        Infer a semantic fingerprint from a YAML rule dict.
        Format: tool:category:action
        """
        tool   = rule.get("tool", "*")
        action = rule.get("action", "deny")
        name   = rule.get("name", "")

        # Infer category from rule name keywords
        category = "other"
        name_lower = name.lower()
        if "traversal" in name_lower or "fs" in name_lower:
            category = "path_traversal"
        elif "inject" in name_lower or "eval" in name_lower:
            category = "code_injection"
        elif "cmd" in name_lower or "command" in name_lower:
            category = "command_injection"
        elif "honeypot" in name_lower:
            category = "honeypot_access"
        elif "env" in name_lower or "secret" in name_lower:
            category = "credential_access"
        elif "rbac" in name_lower or "admin" in name_lower or "user" in name_lower:
            category = "rbac_violation"
        elif "ip" in name_lower or "leak" in name_lower:
            category = "infrastructure_disclosure"
        elif "pii" in name_lower or "redact" in name_lower:
            category = "pii_leak"

        return f"{tool}:{category}:{action}".lower()

    # ── Private: OPA Parser ─────────────────────────────────────────────────

    def _get_opa_fingerprints(self) -> set[str]:
        """
        Scan .rego files in the rules/ directory and extract fingerprints.
        Looks for comments like: # fingerprint: read_file:path_traversal:deny
        Returns empty set if no OPA files exist (not yet deployed).
        """
        fps = set()
        if not self.rules_dir.exists():
            return fps

        for rego_file in self.rules_dir.glob("**/*.rego"):
            try:
                content = rego_file.read_text(encoding="utf-8")
                for m in re.finditer(
                    r"#\s*fingerprint:\s*([a-z0-9_*]+:[a-z0-9_]+:[a-z]+)",
                    content, re.IGNORECASE
                ):
                    fps.add(m.group(1).lower())
            except Exception:
                pass

        return fps

    # ── Private: Decisions Parser ───────────────────────────────────────────

    def _parse_decisions(self) -> list[dict]:
        """Parse governance_decisions.md and return all recommendation dicts."""
        if not self.decisions_file.exists():
            return []

        content = self.decisions_file.read_text(encoding="utf-8")
        recs    = []
        sections = re.split(r"\n## Recommendation: ", content)

        for section in sections[1:]:
            lines = section.strip().split("\n")
            rec   = {"id": lines[0].strip()}
            for line in lines[1:]:
                m = re.match(r"\|\s*\*\*(.+?)\*\*\s*\|\s*`?(.+?)`?\s*\|", line)
                if m:
                    key = m.group(1).strip().lower().replace(" ", "_")
                    val = m.group(2).strip().strip("`")
                    rec[key] = val
            if "fingerprint" in rec or "id" in rec:
                recs.append(rec)

        return recs

    def _get_applied_fingerprints(self) -> set[str]:
        """Return fingerprints of all PENDING or APPLIED recommendations."""
        recs = self._parse_decisions()
        fps  = set()
        for rec in recs:
            status = rec.get("status", "PENDING").upper()
            if status in ("PENDING", "APPLIED"):
                fp = rec.get("fingerprint", "").lower()
                if fp:
                    fps.add(fp)
        return fps

    def _update_decision_status(
        self, rec_id: str, new_status: str, applied_to: str = None
    ):
        """Update status + applied_to in governance_decisions.md."""
        if not self.decisions_file.exists():
            return

        content   = self.decisions_file.read_text(encoding="utf-8")
        lines     = content.split("\n")
        new_lines = []
        in_rec    = False

        for line in lines:
            if f"## Recommendation: {rec_id}" in line:
                in_rec = True
            if in_rec:
                if "| **Status**" in line:
                    line = f"| **Status** | `{new_status}` |"
                if applied_to and "| **Applied To**" in line:
                    line = f"| **Applied To** | `{applied_to}` |"
                if line.startswith("## ") and rec_id not in line:
                    in_rec = False
            new_lines.append(line)

        self.decisions_file.write_text("\n".join(new_lines), encoding="utf-8")
