"""
chain_helpers.py – Side-effect-free bridge utility helpers.

These utilities are extracted from bridge.py so that:
  1. Tests can import them without triggering bridge.py's module-level side effects
     (stdout redirection, subprocess spawning, etc.).
  2. bridge.py can re-import them from here for DRY reuse.

No I/O, no network calls, no global state mutation at import time.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# ToolExecutionResult
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ToolExecutionResult:
    """Lightweight wrapper around a tool execution outcome."""
    success: bool
    result: Any = None
    error: Any = None
    status_code: int = 200


# ─────────────────────────────────────────────────────────────────────────────
# Hashing
# ─────────────────────────────────────────────────────────────────────────────

def secure_hash(val: Optional[str]) -> str:
    """Return a stable 16-char hex SHA-256 digest of *val*, or '' if empty."""
    if not val:
        return ""
    return hashlib.sha256(val.encode("utf-8")).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# Tool name canonicalization
# ─────────────────────────────────────────────────────────────────────────────

_KNOWN_MAPPINGS: dict[str, str] = {
    "fetchurl": "fetch_url",
    "readfile": "read_file",
    "listdirectory": "list_directory",
    "writefile": "write_file",
    "getcurrentuser": "GetCurrentUser",
    "getusertransactions": "GetUserTransactions",
    "getsystemconfig": "get_system_config",
    "fetchinternaldb": "fetch_internal_db",
    "keycloaklistusers": "keycloak_list_users",
    "keycloaklistusersessions": "keycloak_list_user_sessions",
    "keycloakrevokeusersessions": "keycloak_revoke_user_sessions",
    "keycloakgetuserevents": "keycloak_get_user_events",
    "keycloaksecurityreport": "keycloak_security_report",
    "keycloakgeneratepolicy": "keycloak_generate_policy",
    "keycloakquarantineuser": "keycloak_quarantine_user",
    "keycloakrundrills": "keycloak_run_drills",
    "scandependencies": "ScanDependencies",
    "scansecrets": "ScanSecrets",
    "getsystemmetrics": "GetSystemMetrics",
    "getactiveconnections": "GetActiveConnections",
}


def canonicalize_tool_name(raw_name: Optional[str]) -> str:
    """
    Map any variant of a tool name (PascalCase, camelCase, kebab-case,
    snake_case) to the canonical form used throughout the pipeline.

    Unknown tool names are returned as lower-cased originals.
    Returns '' for None / empty input.
    """
    if not raw_name or not isinstance(raw_name, str):
        return ""
    normalized = raw_name.strip().lower().replace("-", "").replace("_", "").replace(" ", "")
    return _KNOWN_MAPPINGS.get(normalized, raw_name.strip().lower())


# ─────────────────────────────────────────────────────────────────────────────
# Context ID builder
# ─────────────────────────────────────────────────────────────────────────────

_SENTINEL = {"", "unknown", None}


def build_chain_context_id(
    session_id: Optional[str] = None,
    mcp_connection_id: Optional[str] = None,
    user_id: Optional[str] = None,
    spiffe_id: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> str:
    """
    Build a stable, hashed context identifier from the best available token.

    Priority order:
      1. session_id
      2. mcp_connection_id
      3. user_id + spiffe_id + agent_id  (combined)
      4. user_id alone
      5. spiffe_id alone

    Returns '' if no usable identifier is present (fail-closed).
    """
    def _valid(v: Optional[str]) -> bool:
        return bool(v and v.strip() and v.strip() not in _SENTINEL)

    if _valid(session_id):
        source = f"session:{session_id.strip()}"
    elif _valid(mcp_connection_id):
        source = f"mcp:{mcp_connection_id.strip()}"
    elif _valid(user_id) and _valid(spiffe_id) and _valid(agent_id):
        source = f"identity:{user_id.strip()}|{spiffe_id.strip()}|{agent_id.strip()}"
    else:
        return ""

    return secure_hash(source)


# ─────────────────────────────────────────────────────────────────────────────
# Execution success helpers
# ─────────────────────────────────────────────────────────────────────────────

def rest_execution_success(result: Any) -> bool:
    """Return True iff the REST/sandboxed tool execution succeeded."""
    if result is None:
        return False
    if isinstance(result, ToolExecutionResult):
        return result.success
    if hasattr(result, "status_code"):
        if result.status_code >= 400:
            return False
        if hasattr(result, "body"):
            try:
                data = json.loads(result.body)
                if isinstance(data, dict) and "error" in data:
                    return False
            except Exception:
                pass
        return True
    if isinstance(result, dict):
        return "error" not in result
    return True


def mcp_execution_success(response: Any) -> bool:
    """Return True iff the JSON-RPC MCP response carries a 'result' (not 'error')."""
    if not response:
        return False
    if isinstance(response, str):
        try:
            response = json.loads(response)
        except Exception:
            return False
    if isinstance(response, dict):
        if "error" in response:
            return False
        return "result" in response
    return False
