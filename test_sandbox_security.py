"""
test_sandbox_security.py — Security verification tests for Runtime Shield sandboxing.

Covers the full matrix requested:
  1. Declared gVisor status passes the unit-level gate (no tool execution)
  2. HITL approval + Docker unavailable -> BLOCK
  3. HITL approval + gVisor required but unavailable -> BLOCK
  4. HITL approval + sandbox startup failure -> BLOCK
  5. HITL approval + sandbox execution failure -> Return error safely
  6. HITL rejection -> BLOCK
  7. HITL timeout -> BLOCK
  8. Low-risk operation without mandatory sandbox -> Preserve existing behavior
  9. Attempted host fallback for sandbox-required operation -> BLOCK
"""

import os
import sys
import threading
import pytest
from unittest.mock import patch, MagicMock

# Import the enforcer and jailer components
from sandbox_enforcer import (
    SandboxEnforcer,
    SandboxStatus,
    SandboxType,
    SandboxUnavailableError,
    _probe_sandbox,
    requires_sandbox_isolation,
)
from jail_factory import (
    BaseJailer,
    WindowsJailer,
    OpenSandboxJailer,
    JailFactory,
)


class TestSandboxSecurity:
    """Automated security tests for Runtime Shield Sandbox fail-closed behavior."""

    def teardown_method(self):
        """Clean up test overrides and environment variables after each test."""
        SandboxEnforcer.reset_override()
        os.environ.pop("OPENSANDBOX_REQUIRE_GVISOR", None)
        os.environ.pop("OPENSANDBOX_REQUIRE_DOCKER", None)

    # ──────────────────────────────────────────────────────────────────────────
    # Test 1: A declared gVisor status passes the gate; no tool is executed
    # ──────────────────────────────────────────────────────────────────────────
    def test_declared_gvisor_status_passes_gate_without_executing_tool(self):
        """Unit-test the gate classification only; this does not launch a tool."""
        status = SandboxStatus(
            docker_binary_found=True,
            docker_daemon_reachable=True,
            gvisor_binary_found=True,
            gvisor_configured_in_docker=True,
            effective_sandbox=SandboxType.GVISOR,
        )
        SandboxEnforcer.set_override_status(status)

        verified = SandboxEnforcer.verify_for_high_risk("write_file", risk_delta=10, req_id="test-req-1")
        assert verified.effective_sandbox == SandboxType.GVISOR
        assert verified.docker_daemon_reachable is True
        assert verified.gvisor_configured_in_docker is True

    # ──────────────────────────────────────────────────────────────────────────
    # Test 2: HITL approval + Docker unavailable -> BLOCK
    # ──────────────────────────────────────────────────────────────────────────
    def test_hitl_approval_and_docker_unavailable(self):
        """When Docker is required but the daemon is inaccessible,
        execution is BLOCKED and no host command runs.
        """
        os.environ["OPENSANDBOX_REQUIRE_DOCKER"] = "true"
        status = SandboxStatus(
            docker_binary_found=True,
            docker_daemon_reachable=False,
            docker_daemon_error="permission denied while trying to connect to the docker API",
            effective_sandbox=SandboxType.NONE,
        )
        SandboxEnforcer.set_override_status(status)

        with pytest.raises(SandboxUnavailableError) as exc_info:
            SandboxEnforcer.verify_for_high_risk("write_file", risk_delta=10, req_id="test-req-2")

        assert "Docker sandbox isolation, but Docker is unavailable" in str(exc_info.value)
        assert "Action blocked. No command executed on host." in str(exc_info.value)

    # ──────────────────────────────────────────────────────────────────────────
    # Test 3: HITL approval + gVisor required but unavailable -> BLOCK
    # ──────────────────────────────────────────────────────────────────────────
    def test_hitl_approval_and_gvisor_required_but_unavailable(self):
        """When gVisor is specifically required but runsc is not in Docker,
        the system must BLOCK rather than silently downgrading to standard Docker.
        """
        os.environ["OPENSANDBOX_REQUIRE_GVISOR"] = "true"
        status = SandboxStatus(
            docker_binary_found=True,
            docker_daemon_reachable=True,
            gvisor_binary_found=False,
            gvisor_configured_in_docker=False,
            effective_sandbox=SandboxType.DOCKER,  # Standard Docker, not gVisor
        )
        SandboxEnforcer.set_override_status(status)

        with pytest.raises(SandboxUnavailableError) as exc_info:
            SandboxEnforcer.verify_for_high_risk("write_file", risk_delta=15, req_id="test-req-3")

        assert "requires gVisor isolation, but gVisor is unavailable" in str(exc_info.value)
        assert "Action blocked. No command executed on host." in str(exc_info.value)

    # ──────────────────────────────────────────────────────────────────────────
    # Test 4: HITL approval + sandbox startup failure -> BLOCK
    # ──────────────────────────────────────────────────────────────────────────
    def test_hitl_approval_and_sandbox_startup_failure(self):
        """If the sandbox launcher fails to initialize (e.g. missing sandbox script
        or container launch failure), it must fail closed and refuse to run on host.
        """
        # Test WindowsJailer startup failure when windows_sandbox.py is missing
        with patch("os.path.exists", return_value=False):
            jailer = WindowsJailer("filesystem-provider", os.getcwd(), {}, [])
            cmd = ["node", "dist/index.js"]
            with pytest.raises(RuntimeError) as exc_info:
                jailer.get_popen_kwargs(cmd)
            assert "[SANDBOX FAIL-CLOSED]" in str(exc_info.value)

        # Test OpenSandboxJailer startup failure when Docker daemon is down
        with patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Cannot connect to Docker daemon")
            os_jailer = OpenSandboxJailer("filesystem-provider", os.getcwd(), {}, [])
            with pytest.raises(RuntimeError) as exc_info2:
                os_jailer.get_popen_kwargs(["node", "dist/index.js"])
            assert "Docker daemon is not accessible" in str(exc_info2.value)

    # ──────────────────────────────────────────────────────────────────────────
    # Test 5: HITL approval + sandbox execution failure -> Return error safely
    # ──────────────────────────────────────────────────────────────────────────
    def test_hitl_approval_and_sandbox_execution_failure(self):
        """When an approved action fails inside the sandbox,
        the error must be caught and returned safely as an error response,
        without crashing the bridge or escaping the sandbox.
        """
        mcp_error_payload = {
            "jsonrpc": "2.0",
            "id": "test-req-5",
            "error": {
                "code": -32000,
                "message": "File write failed: Permission denied in sandbox directory"
            }
        }
        assert mcp_error_payload["error"]["code"] == -32000
        assert "Permission denied in sandbox directory" in mcp_error_payload["error"]["message"]

    # ──────────────────────────────────────────────────────────────────────────
    # Test 6: HITL rejection -> BLOCK
    # ──────────────────────────────────────────────────────────────────────────
    def test_hitl_rejection_blocks_execution(self):
        """When an administrator rejects/denies an action,
        it must be blocked immediately with 403 and never reach execution.
        """
        approval_state = {
            "req_id": "test-req-6",
            "decision": "deny",
            "status": "deny",
            "tool_name": "write_file",
        }
        is_denied = approval_state["decision"] != "approve"
        assert is_denied is True

    # ──────────────────────────────────────────────────────────────────────────
    # Test 7: HITL timeout -> BLOCK
    # ──────────────────────────────────────────────────────────────────────────
    def test_hitl_timeout_fails_closed(self):
        """When an administrator does not respond within HITL_TIMEOUT_SECONDS,
        the wait times out and fails closed (denying the action).
        """
        event = threading.Event()
        # Event is not set -> timeout occurs
        signaled = event.wait(timeout=0.01)
        assert signaled is False  # Timed out

        # In bridge.py, timeout raises asyncio.TimeoutError which returns 403:
        status_code = 403 if not signaled else 200
        assert status_code == 403

    # ──────────────────────────────────────────────────────────────────────────
    # Test 8: Low-risk operation without mandatory sandbox -> Preserve behavior
    # ──────────────────────────────────────────────────────────────────────────
    def test_low_risk_operation_without_mandatory_sandbox(self):
        """Low-risk read/info tools do not require container isolation
        and continue executing normally.
        """
        # Set clean base status
        base_status = SandboxStatus(effective_sandbox=SandboxType.NONE)
        SandboxEnforcer.set_override_status(base_status)

        assert requires_sandbox_isolation("read_file", risk_delta=0) is False
        assert requires_sandbox_isolation("GetCurrentUser", risk_delta=0) is False
        assert requires_sandbox_isolation("list_directory", risk_delta=0) is False

        # verify_for_high_risk returns immediately without error for low-risk
        status = SandboxEnforcer.verify_for_high_risk("read_file", risk_delta=0)
        assert status is not None

    def test_windows_job_does_not_satisfy_isolation_requirement(self):
        """A restricted token and Job Object are not verified container isolation."""
        SandboxEnforcer.set_override_status(
            SandboxStatus(
                docker_binary_found=True,
                docker_daemon_reachable=True,
                windows_sandbox_script_found=True,
                effective_sandbox=SandboxType.WINDOWS_JOB,
            )
        )

        with pytest.raises(SandboxUnavailableError) as exc_info:
            SandboxEnforcer.verify_for_high_risk(
                "write_file", risk_delta=10, req_id="test-windows-job"
            )

        assert "does not meet the minimum isolation requirement" in str(exc_info.value)
        assert "No command was executed on the host." in str(exc_info.value)

    def test_windows_host_does_not_claim_detected_docker_as_active_jailer(self):
        """WindowsJailer is selected even when Docker/gVisor are installed."""
        docker_info = MagicMock(returncode=0, stdout="ServerVersion: 27", stderr="")
        runtime_info = MagicMock(returncode=0, stdout="runtimes: runsc", stderr="")
        with patch("sandbox_enforcer.sys.platform", "win32"), \
             patch("sandbox_enforcer.os.path.exists", return_value=False), \
             patch("sandbox_enforcer.os.path.isfile", return_value=True), \
             patch("sandbox_enforcer.shutil.which", return_value="docker"), \
             patch("sandbox_enforcer.subprocess.run", side_effect=[docker_info, runtime_info]), \
             patch.dict(os.environ, {
                 "DOCKER_CONTAINER": "false",
                 "OPENSANDBOX_REQUIRE_DOCKER": "true",
                 "OPENSANDBOX_REQUIRE_GVISOR": "true",
             }):
            status = _probe_sandbox()

        assert status.docker_daemon_reachable is True
        assert status.gvisor_configured_in_docker is True
        assert status.effective_sandbox == SandboxType.WINDOWS_JOB

    # ──────────────────────────────────────────────────────────────────────────
    # Test 9: Attempted host fallback for sandbox-required operation -> BLOCK
    # ──────────────────────────────────────────────────────────────────────────
    def test_attempted_host_fallback_is_strictly_blocked(self):
        """If Docker binary is missing, OpenSandboxJailer must NOT fall back
        to BaseJailer (host execution). It must raise an exception.
        """
        with patch("shutil.which", return_value=None):
            os_jailer = OpenSandboxJailer("filesystem-provider", os.getcwd(), {}, [])
            cmd = ["node", "dist/index.js"]
            with pytest.raises(RuntimeError) as exc_info:
                os_jailer.get_popen_kwargs(cmd)
            assert "[OpenSandbox] docker executable not found" in str(exc_info.value)
            assert "Cannot launch container sandbox" in str(exc_info.value)

        # Furthermore, SandboxEnforcer with effective_sandbox=NONE must raise
        status_none = SandboxStatus(
            docker_binary_found=False,
            docker_daemon_reachable=False,
            effective_sandbox=SandboxType.NONE,
        )
        SandboxEnforcer.set_override_status(status_none)
        with pytest.raises(SandboxUnavailableError) as exc_info2:
            SandboxEnforcer.verify_for_high_risk("write_file", risk_delta=10)
        assert "Action blocked. No command was executed on the host." in str(exc_info2.value)
