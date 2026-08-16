import os
import sys
# Ensure repository root is prioritized in sys.path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import logging
import requests
from typing import TypedDict, Dict, Any

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


class OpaPolicyEngine(PolicyEngine):
    """
    OPA-only policy engine. This is the sole policy backend.
    Fails closed on any connection or response error.
    """

    def __init__(self, endpoint_url: str = None):
        self.backend = "opa"
        self.endpoint_url = endpoint_url or os.getenv(
            "OPA_URL", "http://localhost:8182/v1/data/runtime_shield/authz/decision"
        )

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
        except requests.exceptions.ConnectionError as e:
            logger.error(f"OPA connection error: {e}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"OPA request error: {e}")
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
