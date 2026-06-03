import yaml
import os
import json
import logging
import fnmatch
from typing import Dict, Any, List, Optional
from enum import Enum

logger = logging.getLogger("policy_engine")

import jsonschema
from jsonschema import validate

class Action(Enum):
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"

class PolicyEngine:
    def __init__(self, rules_path: str = "rules/tenant_rules.yaml"):
        self.rules_path = rules_path
        self.policies = {}
        self.version = "unknown"
        self._last_rules_mtime = 0
        self.load_policies()

    def _check_reload(self):
        """Hot-reload policies if file changed on disk."""
        try:
            mtime = os.path.getmtime(self.rules_path)
            if mtime > self._last_rules_mtime:
                self.load_policies()
                self._last_rules_mtime = mtime
        except: pass

    def load_policies(self):
        """Load policies from YAML with Fail-Closed logic."""
        try:
            if not os.path.exists(self.rules_path):
                logger.error(f"Policy file not found: {self.rules_path}. FAIL-CLOSED ENABLED.")
                self.policies = {}
                return

            with open(self.rules_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                # Upgrade: Load roles and scopes
                self.roles = data.get("roles", {})
                self.scopes = data.get("scopes", {})
                self.version = data.get("version", "3.0.0")
                logger.info(f"Loaded Global Policy Version: {self.version}")
        except Exception as e:
            logger.error(f"Critical error loading policies: {e}. FAIL-CLOSED ENABLED.")
            self.policies = {}

    def _check_path_restrictions(self, path: str, allowed_dirs: List[str]) -> bool:
        """Verify path is within allowed directories (no traversal)."""
        if not path or not allowed_dirs: return True
        
        # Ensure we are checking against the current project directory
        cwd = os.getcwd()
        try:
            # Handle leading slashes for Windows
            clean_path = path.lstrip('/')
            abs_path = os.path.normpath(os.path.abspath(os.path.join(cwd, clean_path)))
            
            # 🆔 Combined Allowed Dirs (YAML + Keycloak Attributes)
            all_allowed = list(allowed_dirs)
            
            for d in all_allowed:
                abs_dir = os.path.normpath(os.path.abspath(os.path.join(cwd, d.lstrip('./'))))
                if abs_path == abs_dir or abs_path.startswith(abs_dir + os.sep):
                    return True
            return False
        except Exception:
            return False

    def evaluate(self, role: str, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        True Triple-Layer Co-Enforcement:
        Layer 1: Identity (OIDC Scopes) - AUTHORITATIVE
        Layer 2: Policy (RBAC Roles) - DETERMINISTIC
        Layer 3: Attributes (JWT Claims) - DYNAMIC
        """
        self._check_reload()
        
        token_scopes = arguments.get("token_scopes", [])
        attribute_paths = arguments.get("attribute_paths", [])

        # --- LAYER 1: IDENTITY ENFORCEMENT (Mandatory Scopes) ---
        # Find all scopes that grant access to this tool
        required_scopes = [s for s, rule in self.scopes.items() if any(fnmatch.fnmatch(tool_name, p) for p in rule.get("allow", []))]
        
        # If the tool is "Scope-Protected" but the user lacks the scope, DENY.
        if required_scopes and not any(s in token_scopes for s in required_scopes):
            return {
                "action": Action.DENY, 
                "reason": f"Identity Layer Violation: Missing mandatory OIDC scope(s): {required_scopes}",
                "source": "identity_layer"
            }

        # --- LAYER 2: POLICY ENFORCEMENT (Role-Based RBAC) ---
        role_rules = self.roles.get(role, {})
        if not role_rules:
            return {"action": Action.DENY, "reason": f"Policy Layer Violation: Role '{role}' not defined."}

        # Check Deny List first
        deny_list = role_rules.get("deny", [])
        if any(fnmatch.fnmatch(tool_name, p) for p in deny_list):
            return {"action": Action.DENY, "reason": f"Policy Layer Violation: Tool '{tool_name}' explicitly denied for role '{role}'."}

        # Check Allow List
        granted_tools = role_rules.get("allow", [])
        is_role_allowed = any(p == "*" or fnmatch.fnmatch(tool_name, p) for p in granted_tools)
        
        if not is_role_allowed:
            return {"action": Action.DENY, "reason": f"Policy Layer Violation: Tool '{tool_name}' not permitted for role '{role}'."}

        # --- LAYER 3: ATTRIBUTE ENFORCEMENT (Identity-Aware Sandbox) ---
        # Merge path policies from Scopes and Roles
        path_arg = arguments.get("path") or arguments.get("directory")
        if path_arg:
            combined_allowed = []
            
            # A. Get allowed paths from matching scopes
            for s in token_scopes:
                if s in self.scopes:
                    combined_allowed.extend(self.scopes[s].get("tool_policies", {}).get(tool_name, {}).get("allowed_paths", []))

            # B. Get allowed paths from Role
            combined_allowed.extend(role_rules.get("tool_policies", {}).get(tool_name, {}).get("allowed_paths", []))

            # C. Inject DYNAMIC Attributes from Keycloak JWT (Highest Authority)
            if attribute_paths:
                combined_allowed.extend(attribute_paths)
            
            # Enforce confinement
            if combined_allowed and not self._check_path_restrictions(path_arg, combined_allowed):
                return {
                    "action": Action.DENY, 
                    "reason": f"Attribute Layer Violation: Path '{path_arg}' outside your authorized identity sandbox.",
                    "source": "attribute_layer"
                }

        return {"action": Action.ALLOW, "reason": "Triple-Layer Verification Successful", "source": "shield_hybrid"}

    def get_version(self):
        return self.version
