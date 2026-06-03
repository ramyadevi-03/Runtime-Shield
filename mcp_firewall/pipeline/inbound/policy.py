"""YAML policy engine — evaluate rules against tool calls."""

from __future__ import annotations

import fnmatch
import os
import re
from typing import Any, List

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
        # Path traversal and absolute path hardening before any policy checks
        for key in ["path", "directory"]:
            if key in request.arguments and isinstance(request.arguments[key], str):
                path_val = request.arguments[key]
                # Replace backslashes with forward slashes for unified check
                normalized = path_val.replace("\\", "/")
                
                # Split segments to check traversal elements exactly
                segments = [s.strip() for s in normalized.split("/") if s.strip()]
                
                has_traversal = ".." in segments or any(s == ".." or s.startswith("..") or s.endswith("..") for s in segments)
                has_trailing_dot = normalized.endswith("/.") or normalized.endswith("/..") or normalized == "." or normalized == ".."
                is_absolute = normalized.startswith("/") or ":" in normalized or normalized.startswith("//")
                
                if has_traversal or has_trailing_dot or is_absolute:
                    return self._deny(
                        "Security violation: Potential directory traversal or absolute path escape detected.",
                        severity=Severity.HIGH
                    )
                
                # Apply normalization
                norm_path = os.path.normpath(path_val)
                # Keep forward slashes for matching compatibility
                request.arguments[key] = norm_path.replace("\\", "/")

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
                    msg = agent_cfg.message or f"Policy: Tool '{tool}' explicitly denied for role '{request.agent_id}'"
                    return self._deny(
                        msg,
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
                    msg = agent_cfg.message or f"Policy: Tool '{tool}' allowed for role '{request.agent_id}'"
                    return self._allow(msg)
            # If allow list exists but tool not in it, deny
            msg = agent_cfg.message or f"Policy: Tool '{tool}' not in allow list for role '{request.agent_id}'"
            return self._deny(
                msg,
                severity=Severity.MEDIUM,
            )

        # 4. Check Path Restrictions (if any defined for this tool)
        tool_policy = agent_cfg.tool_policies.get(tool, {})
        allowed_paths = tool_policy.get("allowed_paths", [])
        if allowed_paths:
            path_decision = self._check_path_restrictions(request, allowed_paths)
            if path_decision:
                return path_decision

        return None

    def _check_path_restrictions(
        self, request: ToolCallRequest, allowed_paths: List[str]
    ) -> PipelineDecision | None:
        """Verify path is within allowed directories (no traversal)."""
        path_arg = request.arguments.get("path") or request.arguments.get("directory")
        if not path_arg:
            return None

        cwd = os.getcwd()
        try:
            # Handle leading slashes for Windows
            clean_path = str(path_arg).lstrip('/')
            abs_path = os.path.normpath(os.path.abspath(os.path.join(cwd, clean_path)))
            
            for d in allowed_paths:
                abs_dir = os.path.normpath(os.path.abspath(os.path.join(cwd, d.lstrip('./'))))
                if abs_path == abs_dir or abs_path.startswith(abs_dir + os.sep):
                    return None # Allowed
            
            return self._deny(
                f"Path Restricted: '{path_arg}' outside your authorized identity sandbox.",
                severity=Severity.HIGH,
            )
        except Exception:
            return self._deny(
                "Path Restricted: Invalid path or traversal attempt detected.",
                severity=Severity.HIGH,
            )

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
