"""
MemoryScanner — Phase 2 Core Component.

Reads .md memory files BEFORE each governance decision to provide
historical context that enriches the policy firewall and fraud engine.

Called from bridge.py right before the firewall check (Layer 3).

Returns a MemoryContext object containing:
    - agent_trust_level  : "new" | "trusted" | "suspicious" | "high-risk"
    - known_attack_match : str | None  (matched pattern name if any)
    - historical_blocks  : int         (past block count for this agent)
    - recommended_action : "block" | "allow" | "escalate" | None
    - reasoning          : str         (human-readable explanation)
    - base_risk_boost    : int         (extra risk to add to FraudEngine start score)
"""

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class MemoryContext:
    """
    Result of a memory scan — returned to bridge.py before Layer 3.
    All fields are safe defaults so the pipeline never breaks if memory
    files are missing or corrupted.
    """
    agent_trust_level: str = "new"          # new | trusted | suspicious | high-risk
    known_attack_match: Optional[str] = None # e.g. "P-0012: Sequential Traversal"
    historical_blocks: int = 0               # lifetime blocked attempts for this agent
    recommended_action: Optional[str] = None # block | allow | escalate | None
    reasoning: str = ""                      # human-readable explanation
    base_risk_boost: int = 0                 # extra points to add to fraud engine score
    agent_found_in_memory: bool = False      # True if agent has an existing profile


# ── Known Attack Pattern Signatures ─────────────────────────────────────────
# These match against tool_name + tool_args to detect known attack classes
# before the static YAML firewall rules even run.
ATTACK_SIGNATURES = [
    {
        "name": "P-0001: Directory Traversal",
        "tool_pattern": r"(read_file|list_directory|write_file|vuln_read_file)",
        "arg_pattern": r"\.\./|\.\.\\|%2e%2e|%252e",
        "severity": "critical",
        "risk_boost": 25,
    },
    {
        "name": "P-0002: Eval / Code Injection",
        "tool_pattern": r"(vuln_get_qotd|eval_tool)",
        "arg_pattern": r"process\.|require\(|constructor|Function\(|eval\(",
        "severity": "critical",
        "risk_boost": 30,
    },
    {
        "name": "P-0003: Command Injection",
        "tool_pattern": r"(vuln_run_diagnostic|run_command|exec)",
        "arg_pattern": r";|\|`|\$\(",
        "severity": "critical",
        "risk_boost": 30,
    },
    {
        "name": "P-0004: Honeypot Access",
        "tool_pattern": r"(get_system_config|fetch_internal_db)",
        "arg_pattern": r".*",  # Any args — honeypot tools are always suspicious
        "severity": "critical",
        "risk_boost": 100,
    },
    {
        "name": "P-0005: Credential / Env File Access",
        "tool_pattern": r"(read_file|write_file)",
        "arg_pattern": r"\.env|id_rsa|\.pem|\.key|credentials|secrets",
        "severity": "high",
        "risk_boost": 20,
    },
    {
        "name": "P-0006: Infrastructure Disclosure",
        "tool_pattern": r"(vuln_get_current_ip|get_server_info)",
        "arg_pattern": r".*",
        "severity": "high",
        "risk_boost": 15,
    },
]
# ─────────────────────────────────────────────────────────────────────────────


class MemoryScanner:
    """
    Reads .md memory files to provide historical context for governance decisions.

    Usage in bridge.py:
        from governance_memory.scanner import MemoryScanner, MemoryContext
        memory_scanner = MemoryScanner(base_dir=PROJECT_DIR)

        # Before Layer 3 (Policy Firewall):
        mem_ctx = memory_scanner.scan(
            agent_id=spiffe_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        # Use mem_ctx.base_risk_boost to elevate fraud engine starting score
        # Use mem_ctx.known_attack_match to enrich log messages
    """

    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.mem_dir = self.base_dir / "governance_memory"
        self.long_term_dir = self.mem_dir / "long_term"
        self.short_term_dir = self.mem_dir / "short_term"

        # Simple in-memory cache so we don't re-read the same .md file
        # on every single tool call (TTL = 30 seconds)
        self._profile_cache: dict = {}
        self._cache_ts: float = 0.0
        self._CACHE_TTL = 30.0  # seconds

    # ── Public API ──────────────────────────────────────────────────────────

    def scan(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: dict,
    ) -> MemoryContext:
        """
        Main entry point. Called from bridge.py before the policy firewall.

        Steps:
          1. Check active_threats.md for rapid threat lookup
          2. Load agent profile from agent_profiles.md
          3. Run signature matching against known attack patterns
          4. Return enriched MemoryContext
        """
        ctx = MemoryContext()

        try:
            # Step 1: Signature match (fast, no file I/O if already cached)
            self._match_attack_signatures(tool_name, tool_args, ctx)

            # Step 2: Agent profile lookup
            self._load_agent_profile(agent_id, ctx)

            # Step 3: Quick active threats check
            self._check_active_threats(agent_id, ctx)

            # Step 4: Build final recommendation
            self._build_recommendation(ctx)

        except Exception as e:
            # Scanner failures must NEVER block the pipeline
            ctx.reasoning = f"[MemoryScanner] Non-fatal scan error: {e}"

        return ctx

    # ── Private Methods ─────────────────────────────────────────────────────

    def _match_attack_signatures(
        self,
        tool_name: str,
        tool_args: dict,
        ctx: MemoryContext,
    ):
        """
        Check the current tool call against known attack signatures.
        This works purely from in-memory signatures (no file I/O).
        """
        # Build a single string from all argument values for pattern matching
        args_str = " ".join(str(v) for v in (tool_args or {}).values())

        for sig in ATTACK_SIGNATURES:
            tool_match = re.search(sig["tool_pattern"], tool_name, re.IGNORECASE)
            arg_match = re.search(sig["arg_pattern"], args_str, re.IGNORECASE)

            if tool_match and arg_match:
                ctx.known_attack_match = sig["name"]
                ctx.base_risk_boost = max(ctx.base_risk_boost, sig["risk_boost"])
                break  # First match wins

    def _load_agent_profile(self, agent_id: str, ctx: MemoryContext):
        """
        Read agent_profiles.md and extract this agent's trust level and block count.
        Uses a 30-second TTL cache to avoid reading the file on every tool call.
        """
        profile_file = self.long_term_dir / "agent_profiles.md"
        if not profile_file.exists():
            return

        # Refresh cache if expired
        now = time.time()
        if now - self._cache_ts > self._CACHE_TTL or agent_id not in self._profile_cache:
            self._refresh_profile_cache(profile_file)

        profile = self._profile_cache.get(agent_id)
        if not profile:
            return

        ctx.agent_found_in_memory = True
        ctx.agent_trust_level = profile.get("trust_level", "new")
        ctx.historical_blocks = profile.get("blocked_attempts", 0)

        # Boost risk based on trust level
        trust_boost = {
            "new": 0,
            "trusted": 0,
            "suspicious": 20,
            "high-risk": 50,
        }
        ctx.base_risk_boost = max(
            ctx.base_risk_boost,
            trust_boost.get(ctx.agent_trust_level, 0)
        )

    def _refresh_profile_cache(self, profile_file: Path):
        """Parse agent_profiles.md and load all agent entries into cache."""
        content = profile_file.read_text(encoding="utf-8")
        self._profile_cache = {}
        self._cache_ts = time.time()

        # Split on agent section headers: "## Agent: <id>"
        sections = re.split(r"\n## Agent: ", content)

        for section in sections[1:]:  # Skip the file header
            lines = section.strip().split("\n")
            if not lines:
                continue

            agent_id = lines[0].strip()
            profile = {}

            for line in lines[1:]:
                # Parse markdown table rows: | **Field** | `value` |
                m = re.match(r"\|\s*\*\*(.+?)\*\*\s*\|\s*`?(.+?)`?\s*\|", line)
                if m:
                    key = m.group(1).strip().lower().replace(" ", "_")
                    value = m.group(2).strip().strip("`")
                    profile[key] = value

            # Convert numeric fields
            for numeric_field in ("total_calls", "blocked_attempts", "current_risk_score"):
                if numeric_field in profile:
                    try:
                        profile[numeric_field] = int(profile[numeric_field])
                    except ValueError:
                        profile[numeric_field] = 0

            self._profile_cache[agent_id] = profile

    def _check_active_threats(self, agent_id: str, ctx: MemoryContext):
        """
        Quick scan of active_threats.md — looks for recent blocks by this agent
        to detect attack campaigns happening right now in this session window.
        """
        threat_file = self.short_term_dir / "active_threats.md"
        if not threat_file.exists():
            return

        content = threat_file.read_text(encoding="utf-8")
        # Count recent lines that contain this agent_id
        recent_hits = sum(
            1 for line in content.split("\n")
            if agent_id in line and line.startswith("|")
        )

        # 3+ recent blocks in the rolling window = active campaign
        if recent_hits >= 3 and ctx.agent_trust_level not in ("suspicious", "high-risk"):
            ctx.agent_trust_level = "suspicious"
            ctx.base_risk_boost = max(ctx.base_risk_boost, 15)
            ctx.reasoning = (
                f"Active threat detected: {recent_hits} recent blocks "
                f"from this agent in the current session window."
            )

    def _build_recommendation(self, ctx: MemoryContext):
        """
        Build the final recommended_action and reasoning string from all signals.
        """
        signals = []

        if ctx.known_attack_match:
            signals.append(f"Known attack signature: {ctx.known_attack_match}")

        if ctx.agent_trust_level == "high-risk":
            ctx.recommended_action = "block"
            signals.append(f"Agent trust level is HIGH-RISK ({ctx.historical_blocks} lifetime blocks)")

        elif ctx.agent_trust_level == "suspicious":
            ctx.recommended_action = "escalate"
            signals.append(f"Agent trust level is SUSPICIOUS ({ctx.historical_blocks} lifetime blocks)")

        elif ctx.known_attack_match:
            ctx.recommended_action = "escalate"

        if ctx.base_risk_boost > 0:
            signals.append(f"Risk boost applied: +{ctx.base_risk_boost}")

        ctx.reasoning = " | ".join(signals) if signals else "No historical risk signals detected."
