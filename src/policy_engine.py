import os
import json
import logging
import requests
from typing import TypedDict, Optional, Dict, Any

from mcp_firewall.sdk import Gateway, CheckResult

logger = logging.getLogger(__name__)

class PolicyInput(TypedDict):
    user: Dict[str, Any]
    workload: Dict[str, Any]
    agent: Dict[str, Any]
    mcp: Dict[str, Any]
    resource: Dict[str, Any]
    request: Dict[str, Any]

class PolicyDecision(TypedDict):
    allow: bool
    reason: str
    risk_delta: int
    redact_output: bool
    quarantine: bool
    rule_id: str
    policy_backend: str

class PolicyEngine:
    def evaluate_policy(self, policy_input: PolicyInput) -> PolicyDecision:
        raise NotImplementedError

class YamlPolicyEngine(PolicyEngine):
    def __init__(self, config_path: str):
        self.backend = "yaml"
        self.gw = Gateway(config_path=config_path)
    
    def evaluate_policy(self, policy_input: PolicyInput) -> PolicyDecision:
        # Map PolicyInput back to mcp_firewall.sdk format
        tool_name = policy_input["mcp"].get("tool", "")
        agent_id = policy_input["agent"].get("id", "default")
        
        # Build arguments map. mcp_firewall historically expected "path" or "command" or "role" inside arguments
        arguments = {}
        if "path" in policy_input["resource"]:
            arguments["path"] = policy_input["resource"]["path"]
        if "role" in policy_input["user"]:
            arguments["role"] = policy_input["user"]["role"]
        
        # Pass the full original arguments if they exist to support custom regex checks
        # But ensure we don't overwrite role or path we just explicitly set from the standardized fields
        original_args = policy_input["request"].get("original_args", {})
        if isinstance(original_args, dict):
            for k, v in original_args.items():
                if k not in arguments:
                    arguments[k] = v
        
        # Run through legacy Gateway
        check_res: CheckResult = self.gw.check(
            tool_name=tool_name,
            arguments=arguments,
            agent=agent_id
        )
        
        # Determine risk_delta: YAML-defined value from CheckResult takes priority.
        # Fall back to action-based defaults only when the rule did not specify one.
        if check_res.risk_delta is not None:
            risk_delta = check_res.risk_delta
        elif check_res.action == "deny":
            risk_delta = 15
        elif check_res.action == "redact":
            risk_delta = 10
        else:
            risk_delta = 0

        # quarantine is true when the matched rule has priority=critical and action=deny
        quarantine = (check_res.priority == "critical" and check_res.action == "deny")

        # Translate to standard schema
        decision: PolicyDecision = {
            "allow": not check_res.blocked,
            "reason": check_res.reason,
            "risk_delta": risk_delta,
            "redact_output": check_res.action == "redact",
            "quarantine": quarantine,
            "rule_id": check_res.rule_name or "legacy_yaml_rule",
            "policy_backend": "yaml"
        }
            
        return decision

class OpaPolicyEngine(PolicyEngine):
    def __init__(self, endpoint_url: str = None):
        self.backend = "opa"
        self.endpoint_url = endpoint_url or os.getenv("OPA_URL", "http://localhost:8181/v1/data/runtime_shield/authz/decision")
        
    def evaluate_policy(self, policy_input: PolicyInput) -> PolicyDecision:
        try:
            resp = requests.post(
                self.endpoint_url,
                json={"input": policy_input},
                timeout=3.0
            )
            if resp.status_code == 200:
                result = resp.json().get("result", {})
                return {
                    "allow": result.get("allow", False),
                    "reason": result.get("reason", "OPA denied the request (no reason provided)"),
                    "risk_delta": result.get("risk_delta", 0),
                    "redact_output": result.get("redact_output", False),
                    "quarantine": result.get("quarantine", False),
                    "rule_id": result.get("rule_id", "opa_rule"),
                    "policy_backend": "opa"
                }
            else:
                logger.error(f"OPA returned non-200 status: {resp.status_code} - {resp.text}")
                return self._fail_closed(f"OPA endpoint returned error: {resp.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"OPA connection error: {e}")
            return self._fail_closed("OPA connection failed")
            
    def _fail_closed(self, reason: str) -> PolicyDecision:
        return {
            "allow": False,
            "reason": reason,
            "risk_delta": 0,
            "redact_output": False,
            "quarantine": False,
            "rule_id": "opa_fail_closed",
            "policy_backend": "opa"
        }
