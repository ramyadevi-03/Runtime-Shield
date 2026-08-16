import os
import json
import hashlib
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


def sync_policies() -> bool:
    """
    Loads pre-normalized rules from rules/runtime_shield_data.json and the Rego
    policy from rules/runtime_shield.rego, then pushes both to the OPA server.

    Policy rules are no longer read from mcp-firewall.yaml.
    mcp-firewall.yaml is retained for operational config only (MCP servers,
    NeMo, PII/secrets settings, etc.).
    """
    global _last_sync_status, _last_data_hash, _last_sync_time, _opa_reachable
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(project_dir, "rules", "runtime_shield_data.json")
    rego_path = os.path.join(project_dir, "rules", "runtime_shield.rego")

    opa_url = os.getenv("OPA_URL", "http://localhost:8182/v1/data/runtime_shield/authz/decision")
    base_url = opa_url.split("/v1/")[0]

    try:
        # Check if OPA is reachable before proceeding
        requests.get(f"{base_url}/health", timeout=2.0)
        _opa_reachable = True

        # Load pre-normalized rules from the OPA-native JSON data file
        with open(data_path, "r", encoding="utf-8") as f:
            data_payload = json.load(f)

        rules = data_payload.get("rules", [])

        # 1. Upload Rego Policy
        with open(rego_path, "r", encoding="utf-8") as f:
            rego_content = f.read()

        logger.info(f"Syncing Rego policy to OPA at {base_url}...")
        resp_pol = requests.put(
            f"{base_url}/v1/policies/runtime_shield",
            data=rego_content,
            headers={"Content-Type": "text/plain"},
            timeout=5.0
        )
        resp_pol.raise_for_status()

        # 2. Upload JSON Data
        logger.info(f"Syncing {len(rules)} rules to OPA from runtime_shield_data.json...")
        resp_data = requests.put(
            f"{base_url}/v1/data/runtime_shield",
            json=data_payload,
            timeout=5.0
        )
        resp_data.raise_for_status()

        config_hash = hashlib.md5(json.dumps(rules, sort_keys=True).encode()).hexdigest()
        _last_data_hash = config_hash[:8]
        _last_sync_status = "success"
        _last_sync_time = time.time()
        logger.info(f"✅ Successfully synchronized OPA rules. (Data Hash: {_last_data_hash})")
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
