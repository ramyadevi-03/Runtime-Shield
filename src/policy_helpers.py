import time
import logging

log = logging.getLogger(__name__)


def evaluate_tool_policy_with_engines(active_policy_engine, fraud_engine_instance, user_id: str, user_role: str, tool_name: str, request_context: dict | None = None) -> dict:
    """Central helper to evaluate the active policy engine for a given tool call.

    This variant accepts the engines as parameters so it can be imported and
    unit-tested without importing the full `bridge` module (which has side-effects).
    Returns a decision dict with at least: `allow` (bool), `reason` (str), and policy metadata
    such as `policy_backend`, `rule_id`, `risk_delta`, and `priority` when available.
    """
    request_context = request_context or {}
    spiffe_id_val = "spiffe://runtime-shield/workload/mock-llm"
    inp = {
        "user": {"id": user_id or "anonymous_user", "role": user_role, "scopes": []},
        "workload": {"spiffe_id": spiffe_id_val},
        "agent": {"id": spiffe_id_val, "risk_score": fraud_engine_instance.agent_risk_scores.get(spiffe_id_val, 0) if fraud_engine_instance else 0},
        "mcp": {"server": "keycloak-provider", "tool": tool_name, "action": "call"},
        "resource": {"path": ""},
        "request": request_context,
    }

    decision = {"allow": True, "reason": "no policy engine", "policy_backend": "none"}
    try:
        if active_policy_engine:
            decision = active_policy_engine.evaluate_policy(inp) or decision
            if isinstance(decision, dict) and "policy_backend" not in decision:
                decision["policy_backend"] = getattr(active_policy_engine, "backend", "opa")
    except Exception as e:
        log.warning(f"Policy evaluation error for {tool_name}: {e}")
        decision = {"allow": False, "reason": f"Policy evaluation error: {e}", "policy_backend": "error", "rule_id": "policy_eval_error"}

    return decision


# Backwards-compat wrapper used by bridge (so bridge can call evaluate_tool_policy(user_id=..., ...))
def evaluate_tool_policy(user_id: str, user_role: str, tool_name: str, request_context: dict | None = None):
    import bridge
    return evaluate_tool_policy_with_engines(bridge.active_policy_engine, bridge.fraud_engine_instance, user_id, user_role, tool_name, request_context)
