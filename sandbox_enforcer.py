"""
sandbox_enforcer.py — Fail-closed sandbox verification for Runtime Shield.

This module provides SandboxEnforcer, a single source of truth for:
  1. Detecting what sandbox technology is actually available and operational.
  2. Enforcing that high-risk HITL-approved actions are blocked when the
     required sandbox cannot be verified.

Design principles:
  - Fail-closed: any uncertainty → BLOCK.
  - No silent fallbacks: if gVisor is required but absent, raise.
  - Minimal surface: one public function per concern.
  - No side-effects: this module never executes destructive commands.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Public constants / enums
# ──────────────────────────────────────────────────────────────────────────────

class SandboxType(str, Enum):
    """Ordered from most to least isolated."""
    GVISOR = "gvisor"          # Docker + runsc (gVisor kernel-level isolation)
    DOCKER = "docker"          # Standard Docker container (namespace isolation)
    CONTAINER = "container"    # Already running inside container (Docker/Kubernetes)
    WINDOWS_JOB = "windows_job"  # Windows Job Object + restricted token
    NSJAIL = "nsjail"          # Linux nsjail namespace isolation
    LANDLOCK = "landlock"      # Linux Landlock kernel ruleset
    NONE = "none"              # BaseJailer — NO real isolation


class SandboxUnavailableError(RuntimeError):
    """Raised when the required sandbox cannot be confirmed operational.

    Never catch this broadly — let it propagate to the HITL handler which
    must return 503 to the caller.
    """


# ──────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SandboxStatus:
    """Full snapshot of sandbox availability at the moment of the check."""
    timestamp: float = field(default_factory=time.time)

    # Binary flags
    docker_binary_found: bool = False
    docker_daemon_reachable: bool = False
    gvisor_binary_found: bool = False
    gvisor_configured_in_docker: bool = False
    windows_sandbox_script_found: bool = False
    nsjail_found: bool = False
    landlock_available: bool = False
    inside_container: bool = False

    # Error messages captured during probing
    docker_daemon_error: Optional[str] = None
    gvisor_check_error: Optional[str] = None

    # Resolved sandbox type that would be selected by JailFactory
    effective_sandbox: SandboxType = SandboxType.NONE

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "docker_binary_found": self.docker_binary_found,
            "docker_daemon_reachable": self.docker_daemon_reachable,
            "gvisor_binary_found": self.gvisor_binary_found,
            "gvisor_configured_in_docker": self.gvisor_configured_in_docker,
            "windows_sandbox_script_found": self.windows_sandbox_script_found,
            "nsjail_found": self.nsjail_found,
            "landlock_available": self.landlock_available,
            "inside_container": self.inside_container,
            "docker_daemon_error": self.docker_daemon_error,
            "gvisor_check_error": self.gvisor_check_error,
            "effective_sandbox": self.effective_sandbox.value,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Cache & Test Override Support
# ──────────────────────────────────────────────────────────────────────────────

_CACHE_TTL_SECONDS = 10
_cache: Optional[SandboxStatus] = None
_override_status: Optional[SandboxStatus] = None
_cache_lock = threading.Lock()


def _cached_status() -> SandboxStatus:
    global _cache, _override_status
    with _cache_lock:
        if _override_status is not None:
            return _override_status
        if _cache is not None and (time.time() - _cache.timestamp) < _CACHE_TTL_SECONDS:
            return _cache
        status = _probe_sandbox()
        _cache = status
        return status


def invalidate_cache() -> None:
    """Force the next call to re-probe. Useful after configuration changes."""
    global _cache
    with _cache_lock:
        _cache = None


def set_override_status(status: Optional[SandboxStatus]) -> None:
    """Set an override status for unit/integration testing."""
    global _override_status
    with _cache_lock:
        _override_status = status


def reset_override() -> None:
    """Clear any test override."""
    global _override_status
    with _cache_lock:
        _override_status = None


# ──────────────────────────────────────────────────────────────────────────────
# Probing logic
# ──────────────────────────────────────────────────────────────────────────────

def _probe_sandbox() -> SandboxStatus:
    """Perform all sandbox probes and return a SandboxStatus snapshot.

    Every probe is safe: read-only, no side-effects, short timeouts.
    """
    st = SandboxStatus()

    # ── Are we already inside a container? ───────────────────────────────────
    st.inside_container = (
        os.path.exists("/.dockerenv") or
        os.getenv("DOCKER_CONTAINER", "false").lower() == "true"
    )

    project_dir = os.path.dirname(os.path.abspath(__file__))

    # ── Windows sandbox script ───────────────────────────────────────────────
    sandbox_script = os.path.join(project_dir, "windows_sandbox.py")
    st.windows_sandbox_script_found = os.path.isfile(sandbox_script)

    # ── Docker binary ────────────────────────────────────────────────────────
    docker_bin = shutil.which("docker")
    st.docker_binary_found = docker_bin is not None

    if docker_bin:
        # ── Docker daemon reachability ────────────────────────────────────────
        try:
            result = subprocess.run(
                [docker_bin, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=4
            )
            if result.returncode == 0 and result.stdout.strip():
                st.docker_daemon_reachable = True
            else:
                st.docker_daemon_error = (result.stderr or "").strip()[:200]
        except subprocess.TimeoutExpired:
            st.docker_daemon_error = "docker info timed out after 4 s"
        except Exception as exc:
            st.docker_daemon_error = str(exc)[:200]

        # ── gVisor (runsc) — binary and Docker runtime ──────────────────────
        st.gvisor_binary_found = shutil.which("runsc") is not None

        if st.docker_daemon_reachable:
            try:
                res2 = subprocess.run(
                    [docker_bin, "info"],
                    capture_output=True, text=True, timeout=4
                )
                combined = (res2.stdout + res2.stderr).lower()
                if "runsc" in combined or "gvisor" in combined:
                    st.gvisor_configured_in_docker = True
            except Exception as exc:
                st.gvisor_check_error = str(exc)[:200]

    # ── NSJail ───────────────────────────────────────────────────────────────
    st.nsjail_found = shutil.which("nsjail") is not None

    # ── Landlock ─────────────────────────────────────────────────────────────
    try:
        import landlock as _ll  # type: ignore[import]
        st.landlock_available = True
    except ImportError:
        st.landlock_available = False

    # ── Resolve effective sandbox (mirror JailFactory logic) ─────────────────
    if st.inside_container:
        st.effective_sandbox = SandboxType.CONTAINER
    elif sys.platform == "win32":
        # JailFactory selects WindowsJailer on a Windows host, regardless of
        # Docker availability. Do not report an unused Docker runtime as active.
        if st.windows_sandbox_script_found:
            st.effective_sandbox = SandboxType.WINDOWS_JOB
        else:
            st.effective_sandbox = SandboxType.NONE
    elif docker_bin and st.docker_daemon_reachable:
        use_gvisor = os.getenv("OPENSANDBOX_USE_GVISOR", "true").lower() == "true"
        if use_gvisor and st.gvisor_configured_in_docker:
            st.effective_sandbox = SandboxType.GVISOR
        else:
            st.effective_sandbox = SandboxType.DOCKER
    elif sys.platform.startswith("linux"):
        if st.nsjail_found:
            st.effective_sandbox = SandboxType.NSJAIL
        elif st.landlock_available:
            st.effective_sandbox = SandboxType.LANDLOCK
        else:
            st.effective_sandbox = SandboxType.NONE
    else:
        st.effective_sandbox = SandboxType.NONE

    return st


# ──────────────────────────────────────────────────────────────────────────────
# Policy: minimum sandbox required for high-risk tools
# ──────────────────────────────────────────────────────────────────────────────

_TOOLS_REQUIRING_ISOLATION: frozenset[str] = frozenset({
    "write_file",
    "keycloak_revoke_user_sessions",
    "keycloak_quarantine_user",
    "ScanSecrets",
})

_SANDBOX_ORDER = [
    SandboxType.NONE,
    SandboxType.LANDLOCK,
    SandboxType.NSJAIL,
    SandboxType.WINDOWS_JOB,
    SandboxType.CONTAINER,
    SandboxType.DOCKER,
    SandboxType.GVISOR,
]

_MINIMUM_ISOLATION_RANK: int = _SANDBOX_ORDER.index(SandboxType.CONTAINER)


def _isolation_rank(sandbox: SandboxType) -> int:
    try:
        return _SANDBOX_ORDER.index(sandbox)
    except ValueError:
        return 0


def requires_sandbox_isolation(tool_name: str, risk_delta: int = 0) -> bool:
    """Return True if this tool invocation must execute inside a real sandbox."""
    return tool_name in _TOOLS_REQUIRING_ISOLATION or risk_delta >= 10


# ──────────────────────────────────────────────────────────────────────────────
# Public enforcement API
# ──────────────────────────────────────────────────────────────────────────────

class SandboxEnforcer:
    """Fail-closed sandbox gate for use in the HITL post-approval code path."""

    @staticmethod
    def get_status() -> SandboxStatus:
        """Return the current (cached) sandbox status. Always safe to call."""
        return _cached_status()

    @staticmethod
    def set_override_status(status: Optional[SandboxStatus]) -> None:
        set_override_status(status)

    @staticmethod
    def reset_override() -> None:
        reset_override()

    @staticmethod
    def verify_for_high_risk(
        tool_name: str,
        risk_delta: int = 0,
        req_id: str = "",
    ) -> SandboxStatus:
        """Verify that a safe sandbox is available for a high-risk tool.

        Called immediately after HITL approval, before routing the tool call.

        Returns:
            SandboxStatus — callers may log this for audit purposes.

        Raises:
            SandboxUnavailableError — if the effective sandbox does not meet
                the minimum isolation requirement.  The caller MUST NOT execute
                the tool and MUST return an error response to the client.
        """
        if not requires_sandbox_isolation(tool_name, risk_delta):
            return _cached_status()

        status = _cached_status()
        effective = status.effective_sandbox

        require_gvisor = os.getenv("OPENSANDBOX_REQUIRE_GVISOR", "false").lower() == "true"
        require_docker = os.getenv("OPENSANDBOX_REQUIRE_DOCKER", "false").lower() == "true"

        # ── Fail-closed check 1: gVisor required but not available ───────────
        if require_gvisor and effective != SandboxType.GVISOR:
            reason = (
                f"gVisor (runsc) is required by configuration (OPENSANDBOX_REQUIRE_GVISOR=true), "
                f"but is not operational. Docker reachable: {status.docker_daemon_reachable}, "
                f"runsc configured: {status.gvisor_configured_in_docker}."
            )
            _log_block(tool_name, req_id, effective, reason)
            raise SandboxUnavailableError(
                f"[SANDBOX BLOCKED] Tool '{tool_name}' requires gVisor isolation, but gVisor is unavailable. "
                f"{reason} Action blocked. No command executed on host."
            )

        # ── Fail-closed check 2: Docker required but not accessible ──────────
        if require_docker and effective not in (SandboxType.DOCKER, SandboxType.GVISOR, SandboxType.CONTAINER):
            reason = (
                f"Docker container isolation is required (OPENSANDBOX_REQUIRE_DOCKER=true), "
                f"but Docker daemon is not accessible: {status.docker_daemon_error or 'not running / access denied'}."
            )
            _log_block(tool_name, req_id, effective, reason)
            raise SandboxUnavailableError(
                f"[SANDBOX BLOCKED] Tool '{tool_name}' requires Docker sandbox isolation, but Docker is unavailable. "
                f"{reason} Action blocked. No command executed on host."
            )

        # ── Fail-closed check 3: No operational sandbox at all (rank < minimum)
        if _isolation_rank(effective) < _MINIMUM_ISOLATION_RANK:
            reason = _build_unavailability_reason(status, tool_name)
            _log_block(tool_name, req_id, effective, reason)
            raise SandboxUnavailableError(
                f"[SANDBOX BLOCKED] Tool '{tool_name}' requires sandbox isolation, "
                f"but no operational sandbox is available. {reason} "
                f"Action blocked. No command was executed on the host."
            )

        # ── Fail-closed check 4: Non-Windows host Docker daemon unreachable ──
        if sys.platform != "win32" and not status.inside_container:
            if status.docker_binary_found and not status.docker_daemon_reachable:
                reason = (
                    f"Docker binary found but daemon is not reachable "
                    f"({status.docker_daemon_error or 'permission denied / not running'}). "
                    f"Effective sandbox: {effective.value}."
                )
                _log_block(tool_name, req_id, effective, reason)
                raise SandboxUnavailableError(
                    f"[SANDBOX BLOCKED] Tool '{tool_name}' requires an operational Docker sandbox, "
                    f"but the Docker daemon is not accessible. {reason} "
                    f"Action blocked. No command was executed on the host."
                )

        # ── Passed — log confirmation ─────────────────────────────────────────
        log.info(
            "[SANDBOX ENFORCER] ✅ Sandbox verified for high-risk tool '%s' "
            "(req_id=%s, sandbox=%s, gvisor=%s, docker_reachable=%s)",
            tool_name, req_id, effective.value,
            status.gvisor_configured_in_docker,
            status.docker_daemon_reachable,
        )
        return status


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _build_unavailability_reason(status: SandboxStatus, tool_name: str) -> str:
    parts = []
    if not status.docker_binary_found:
        parts.append("Docker is not installed.")
    elif not status.docker_daemon_reachable:
        parts.append(
            f"Docker daemon is not reachable "
            f"({status.docker_daemon_error or 'unknown error'})."
        )
    if not status.gvisor_configured_in_docker and os.getenv("OPENSANDBOX_REQUIRE_GVISOR", "false").lower() == "true":
        parts.append("gVisor (runsc) runtime is not configured in Docker.")
    if sys.platform == "win32" and not status.windows_sandbox_script_found:
        parts.append("Windows sandbox script (windows_sandbox.py) not found.")
    if not parts:
        parts.append(
            f"Effective sandbox '{status.effective_sandbox.value}' "
            f"does not meet the minimum isolation requirement."
        )
    return " ".join(parts)


def _log_block(tool_name: str, req_id: str, effective: SandboxType, reason: str) -> None:
    log.warning(
        "[SANDBOX ENFORCER] 🚫 BLOCKED high-risk tool '%s' (req_id=%s). "
        "Effective sandbox: %s. Reason: %s",
        tool_name, req_id, effective.value, reason,
    )
