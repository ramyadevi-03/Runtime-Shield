import os
import yaml
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
    opa_url = os.getenv("OPA_URL", "http://localhost:8181/v1/data/runtime_shield/authz/decision")
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
    Parses mcp-firewall.yaml, normalizes the rules into an OPA-compatible 
    JSON array, and pushes both the generic Rego policy and the data to the OPA server.
    """
    global _last_sync_status, _last_data_hash, _last_sync_time, _opa_reachable
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(project_dir, "mcp-firewall.yaml")
    rego_path = os.path.join(project_dir, "rules", "runtime_shield.rego")
    
    opa_url = os.getenv("OPA_URL", "http://localhost:8181/v1/data/runtime_shield/authz/decision")
    base_url = opa_url.split("/v1/")[0]
    
    try:
        # Check if OPA is reachable before proceeding
        requests.get(f"{base_url}/health", timeout=2.0)
        _opa_reachable = True
        
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            
        rules = config.get("rules", [])
        
        normalized_rules = []
        for rule in rules:
            action = rule.get("action", "deny")

            # Risk delta: YAML-defined value takes priority.
            # Fall back to action-based defaults only when not explicitly set.
            yaml_risk_delta = rule.get("risk_delta")
            if yaml_risk_delta is not None:
                risk_delta = int(yaml_risk_delta)
            elif action == "deny":
                risk_delta = 15
            elif action == "redact":
                risk_delta = 10
            else:
                risk_delta = 0

            # Normalize tool pattern for OPA Rego regex evaluation (regex.match)
            import re
            raw_tool = rule.get("tool", "*")
            if raw_tool == "*":
                tool_pattern = ".*"
            else:
                # Replace glob '*' with '.*' unless already preceded by '.'
                tool_pattern = re.sub(r'(?<!\.)\*', '.*', raw_tool)

            # Map YAML fields to standard OPA rule schema
            normalized_rule = {
                "name": rule.get("name", "unnamed"),
                "tool": tool_pattern,
                "action": action,
                "message": rule.get("message", "No reason provided"),
                "priority": rule.get("priority", ""),
                "risk_delta": risk_delta,
            }
            
            # Handle match clause extraction
            match_clause = rule.get("match", {}).get("arguments", {})
            if match_clause:
                normalized_rule["match"] = {}
                if "role" in match_clause:
                    normalized_rule["match"]["role"] = match_clause["role"]
                if "path" in match_clause:
                    normalized_rule["match"]["path"] = match_clause["path"]
            
            normalized_rules.append(normalized_rule)
            
        # 1. Upload Rego Policy
        with open(rego_path, "r", encoding="utf-8") as f:
            rego_content = f.read()
            
        logger.info(f"Syncing generic Rego policy to OPA at {base_url}...")
        resp_pol = requests.put(
            f"{base_url}/v1/policies/runtime_shield", 
            data=rego_content, 
            headers={"Content-Type": "text/plain"}, 
            timeout=5.0
        )
        resp_pol.raise_for_status()
        
        # 2. Upload JSON Data
        logger.info(f"Syncing {len(normalized_rules)} normalized rules to OPA...")
        data_payload = {"rules": normalized_rules}
        resp_data = requests.put(
            f"{base_url}/v1/data/runtime_shield", 
            json=data_payload, 
            timeout=5.0
        )
        resp_data.raise_for_status()
        
        import hashlib
        config_hash = hashlib.md5(json.dumps(normalized_rules, sort_keys=True).encode()).hexdigest()
        _last_data_hash = config_hash[:8]
        _last_sync_status = "success"
        _last_sync_time = time.time()
        logger.info(f"✅ Successfully synchronized YAML policies to OPA backend. (Data Hash: {_last_data_hash})")
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
