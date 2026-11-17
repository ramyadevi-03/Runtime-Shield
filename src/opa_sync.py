import os
import json
import logging
import time
import requests

logger = logging.getLogger(__name__)

# State variables for policy status card visibility
_last_sync_status: str = "N/A"
_last_data_hash: str = "N/A"
_last_sync_time: float = 0.0
_opa_reachable: bool = False


def check_opa_health() -> bool:
    """Check if OPA server health endpoint is reachable."""
    global _opa_reachable
    opa_url = os.getenv("OPA_URL", "http://localhost:8182/v1/data/runtime_shield/authz/decision")
    base_url = opa_url.split("/v1/")[0]
    try:
        resp = requests.get(f"{base_url}/health", timeout=1.0)
        _opa_reachable = (resp.status_code == 200)
        return _opa_reachable
    except Exception:
        _opa_reachable = False
        return False


def get_opa_status() -> dict:
    """Return status dictionary for display in the dashboard."""
    check_opa_health()
    return {
        "opa_reachable": _opa_reachable,
        "last_sync_status": _last_sync_status,
        "last_data_hash": _last_data_hash,
        "last_sync_time": _last_sync_time,
    }


def sync_policies(max_retries: int = 15, retry_interval: float = 2.0) -> bool:
    """
    Confirm the read-only mounted policy is loaded by OPA. Runtime Shield never
    writes policy/data through OPA's unauthenticated management API.
    """
    global _last_sync_status, _last_data_hash, _last_sync_time, _opa_reachable
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(project_dir, "rules", "runtime_shield_data.json")
    rego_path = os.path.join(project_dir, "rules", "runtime_shield.rego")

    opa_url = os.getenv("OPA_URL", "http://localhost:8182/v1/data/runtime_shield/authz/decision")
    base_url = opa_url.split("/v1/")[0]

    for attempt in range(1, max_retries + 1):
        try:
            # Check if OPA is reachable before proceeding
            resp = requests.get(f"{base_url}/health", timeout=2.0)
            if resp.status_code == 200:
                _opa_reachable = True
                break
        except requests.exceptions.RequestException:
            logger.info(f"⏳ Waiting for OPA server at {base_url} (attempt {attempt}/{max_retries})...")
            time.sleep(retry_interval)
    else:
        _opa_reachable = False
        _last_sync_status = "failed"
        logger.error(f"❌ Failed to reach OPA server at {base_url} after {max_retries} attempts.")
        return False

    try:
        with open(data_path, "r", encoding="utf-8") as f:
            data_payload = json.load(f)
        with open(rego_path, "r", encoding="utf-8") as f:
            rego_content = f.read()
        if not isinstance(data_payload.get("rules"), list) or "package runtime_shield.authz" not in rego_content:
            raise ValueError("Runtime Shield policy files are invalid")
        check = requests.post(
            f"{base_url}/v1/data/runtime_shield/authz/decision",
            json={"input": {
                "user": {"sub": "policy-health-probe", "scopes": ["health:probe"]},
                "workload": {"id": "policy-health-probe"},
                "agent": {"id": "policy-health-probe"},
                "mcp": {"tool": "__policy_health_probe__"},
                "resource": {},
                "request": {"original_args": {}},
            }},
            timeout=3.0,
        )
        check.raise_for_status()
        loaded_decision = check.json().get("result", {})
        if loaded_decision.get("rule_id") != "default_deny" or loaded_decision.get("allow") is not False:
            raise ValueError("OPA did not return the expected default-deny policy result")
        _last_data_hash = "read-only"
        _last_sync_status = "success"
        _last_sync_time = time.time()
        logger.info("✅ OPA policy is loaded from read-only mounted files; management API was not used.")
        return True

    except requests.exceptions.RequestException as e:
        _opa_reachable = False
        _last_sync_status = "failed"
        logger.error(f"❌ Failed to connect to OPA server for sync: {e}")
        return False
    except Exception as e:
        _last_sync_status = "failed"
        logger.error(f"❌ Error during OPA sync process: {e}")
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sync_policies()
