"""YAML policy engine — evaluate rules against tool calls."""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from ..base import InboundStage
from ...models import (
    Action,
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallRequest,
    RuleConfig,
)


class PolicyEngine(InboundStage):
    """Evaluate YAML policy rules (first-match-wins)."""

    stage = PipelineStage.POLICY

    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        # 1. Check tenant-specific roles first
        tenant_roles = config.tenants.get(request.tenant_id)
        if tenant_roles:
            role_cfg = tenant_roles.get(request.agent_id)
            if role_cfg:
                decision = self._check_agent_policy(request, role_cfg)
                if decision:
                    return decision

        # 2. Check global agent-specific rules
        agent_cfg = config.agents.get(request.agent_id)
        if agent_cfg:
            decision = self._check_agent_policy(request, agent_cfg)
            if decision:
                return decision

        # Check rules (first match wins)
        for rule in config.rules:
            if self._rule_matches(request, rule):
                # Handle both object and dict access for robustness
                r_action = rule.action if hasattr(rule, "action") else rule.get("action", Action.DENY)
                r_name = rule.name if hasattr(rule, "name") else rule.get("name", "unnamed")
                r_msg = rule.message if hasattr(rule, "message") else rule.get("message")

                if r_action == Action.ALLOW:
                    return self._allow(f"Rule '{r_name}' allows this call")
                elif r_action == Action.DENY:
                    msg = r_msg or f"Blocked by rule '{r_name}'"
                    return self._deny(msg, severity=Severity.HIGH)
                elif r_action == Action.PROMPT:
                    return self._prompt(f"Rule '{r_name}' requires approval")

        # Default action
        if config.default_action == Action.DENY:
            return self._deny("No matching rule, default action is deny")
        elif config.default_action == Action.PROMPT:
            return self._prompt("No matching rule, default action is prompt")

        return None  # default allow

    def _check_agent_policy(
        self, request: ToolCallRequest, agent_cfg: Any
    ) -> PipelineDecision | None:
        """Check agent-specific allow/deny lists."""
        tool = request.tool_name

        # Explicit deny takes priority
        if agent_cfg.deny:
            for pattern in agent_cfg.deny:
                if _tool_matches(tool, pattern):
                    return self._deny(
                        f"Tool '{tool}' denied for agent '{request.agent_id}'",
                        severity=Severity.HIGH,
                    )

        # Require approval
        if agent_cfg.require_approval:
            for pattern in agent_cfg.require_approval:
                if _tool_matches(tool, pattern):
                    return self._prompt(
                        f"Tool '{tool}' requires approval for agent '{request.agent_id}'"
                    )

        # Explicit allow
        if agent_cfg.allow:
            for pattern in agent_cfg.allow:
                if _tool_matches(tool, pattern):
                    return self._allow(f"Tool '{tool}' allowed for agent '{request.agent_id}'")
            # If allow list exists but tool not in it, deny
            return self._deny(
                f"Tool '{tool}' not in allow list for agent '{request.agent_id}'",
                severity=Severity.MEDIUM,
            )

        return None

    def _rule_matches(self, request: ToolCallRequest, rule: Any) -> bool:
        """Check if a rule matches the request."""
        # Handle both object and dict access
        r_tool = rule.tool if hasattr(rule, "tool") else rule.get("tool", "*")
        r_match = rule.match if hasattr(rule, "match") else rule.get("match", {})

        # Check tool name
        if r_tool != "*":
            patterns = r_tool.split("|")
            if not any(_tool_matches(request.tool_name, p) for p in patterns):
                return False
        
        # Check argument matchers
        if r_match and "arguments" in r_match:
            arg_matchers = r_match["arguments"]
            if not _arguments_match(request.arguments, arg_matchers):
                return False

        return True


def _tool_matches(tool_name: str, pattern: str) -> bool:
    """Check if tool name matches a pattern (glob or exact)."""
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(tool_name, pattern)
    return tool_name == pattern


def _arguments_match(arguments: dict[str, Any], matchers: dict[str, Any]) -> bool:
    """Check if arguments match the specified patterns."""
    for key, pattern in matchers.items():
        value = arguments.get(key)
        if value is None:
            return False

        if isinstance(pattern, str) and isinstance(value, str):
            # Support glob patterns with **
            glob_pattern = pattern.replace("**", "GLOBSTAR").replace("*", "[^/]*")
            glob_pattern = glob_pattern.replace("GLOBSTAR", ".*")
            if not re.match(glob_pattern, value):
                return False
        elif pattern != value:
            return False

    return True
