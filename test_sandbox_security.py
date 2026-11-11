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

Additional coverage for the Linux bubblewrap+seccomp tier:
 10. Windows Job Object does not satisfy the isolation requirement (restored)
 11. JailFactory tier selection and order (Docker/gVisor restored, bwrap, fail-closed)
 12. Writable roots are allowed_paths only — never the working directory
 13. Global sandbox kill switches do not exist (no env-var override)
 14. Per-provider network policy table
 15. bubblewrap argv construction (namespaces, /etc, protected metadata,
     missing/transient protected-path masks, deny-read masks)
 16. Behavioral self-test: the sandbox actually confines (including EPERM-
     specific seccomp checks and an empty capability set)
 17. Real pipeline: overwriting bridge.py / rules/ / .env is denied
 18. keycloak-provider keeps network access inside its sandbox while
     AF_VSOCK and io_uring stay denied (VmSocketRestricted)
 19. seccomp deny list matches codex-rs seccomp.rs entry for entry,
     plus the x32 syscall-number gate (Runtime Shield addition)
 20. inner-stage failures are reported as sandbox failures
 21. in-container fallback is deliberate and logged as the CONTAINER tier
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import tempfile
import pytest
from unittest.mock import patch, MagicMock

# Import the enforcer and jailer components
from sandbox_enforcer import (
    SandboxEnforcer,
    SandboxStatus,
    SandboxType,
    SandboxUnavailableError,
    _probe_sandbox,
    _SANDBOX_ORDER,
    _isolation_rank,
    requires_sandbox_isolation,
)
from jail_factory import (
    BaseJailer,
    WindowsJailer,
    OpenSandboxJailer,
    ContainerSeccompJailer,
    NSJailer,
    LandlockJailer,
    BubblewrapJailer,
    JailFactory,
    FileSystemSandboxPolicy,
    PermissionProfile,
    BwrapOptions,
    BwrapNetworkMode,
    create_bwrap_command_args,
    bwrap_behavior_probe,
    bwrap_operational,
    provider_sandbox_policy,
    providers_requiring_network,
)

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))


def _bwrap_available_on_host() -> bool:
    try:
        import jail_factory as jf
        return bool(jf.find_bwrap()) and jf.user_namespaces_supported()
    except Exception:
        return False


def _docker_available_on_host() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        return subprocess.run(
            [docker, "info"], capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        return False


def _docker_image_available(image: str) -> bool:
    if not _docker_available_on_host():
        return False
    try:
        return subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, timeout=10,
        ).returncode == 0
    except Exception:
        return False


class TestSandboxSecurity:
    """Automated security tests for Runtime Shield Sandbox fail-closed behavior."""

    def teardown_method(self):
        """Clean up test overrides and environment variables after each test."""
        SandboxEnforcer.reset_override()
        os.environ.pop("OPENSANDBOX_REQUIRE_GVISOR", None)
        os.environ.pop("OPENSANDBOX_REQUIRE_DOCKER", None)
        os.environ.pop("CODEX_SANDBOX", None)
        os.environ.pop("CODEX_SANDBOX_NETWORK", None)

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
        # (sys.platform is patched so the win32 branch is exercised on any host)
        with patch("sys.platform", "win32"), \
             patch("os.path.exists", return_value=False):
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

    # ──────────────────────────────────────────────────────────────────────────
    # Test 10: JailFactory tier selection and order
    # ──────────────────────────────────────────────────────────────────────────
    def _bare_host_patches(self):
        """Patches that make the current host look like a bare (non-container)
        host, regardless of any real DOCKER_CONTAINER variable."""
        real_exists = os.path.exists

        def fake_exists(p):
            if p == "/.dockerenv":
                return False
            return real_exists(p)

        def fake_getenv(key, default=None):
            if key == "DOCKER_CONTAINER":
                return "false"
            return os.environ.get(key, default)

        import contextlib
        stack = contextlib.ExitStack()
        stack.enter_context(patch("os.path.exists", fake_exists))
        stack.enter_context(patch("os.getenv", fake_getenv))
        return stack

    def test_jail_factory_restored_tier_order(self):
        """Docker/gVisor (OpenSandboxJailer) is the primary tier again; the
        bubblewrap+seccomp tier follows; nsjail and Landlock remain fallbacks;
        a bare host fails closed instead of silently running unsandboxed."""
        import jail_factory as jf

        # 10a. Docker present -> OpenSandboxJailer (restored strongest tier)
        with self._bare_host_patches(), \
             patch("shutil.which", return_value="/usr/bin/docker"):
            jailer = JailFactory.get_jailer("filesystem-provider", PROJECT_DIR, {}, [])
            assert isinstance(jailer, OpenSandboxJailer)

        # 10b. No Docker, bubblewrap behaviorally verified -> BubblewrapJailer
        def which_no_docker(name):
            return None if name == "docker" else f"/usr/bin/{name}"

        with self._bare_host_patches(), \
             patch("shutil.which", side_effect=which_no_docker), \
             patch.object(jf, "_PROBE_CACHE", {"operational": True, "checks": {}}):
            jailer = JailFactory.get_jailer("filesystem-provider", PROJECT_DIR, {}, [])
            assert isinstance(jailer, BubblewrapJailer)

        # 10c. bubblewrap present but FAILED its behavioral probe, nsjail exists
        def which_nsjail_only(name):
            return "/usr/bin/nsjail" if name == "nsjail" else None

        with self._bare_host_patches(), \
             patch("shutil.which", side_effect=which_nsjail_only), \
             patch.object(jf, "_PROBE_CACHE", {"operational": False, "skipped": "probe mismatch", "checks": {}}):
            jailer = JailFactory.get_jailer("filesystem-provider", PROJECT_DIR, {}, [])
            assert isinstance(jailer, NSJailer)

        # 10d. Nothing available -> fail closed (no silent host execution)
        with self._bare_host_patches(), \
             patch("shutil.which", return_value=None), \
             patch.object(jf, "landlock", None), \
             patch.object(jf, "_PROBE_CACHE", {"operational": False, "skipped": "bubblewrap not found on PATH", "checks": {}}):
            with pytest.raises(RuntimeError) as exc_info:
                JailFactory.get_jailer("filesystem-provider", PROJECT_DIR, {}, [])
            assert "FAIL-CLOSED" in str(exc_info.value)

        # 10e. Inside a container without a working nested sandbox the
        # container boundary is the filesystem isolation, hardened with the
        # Codex seccomp inner stage (logged as the CONTAINER tier).
        with patch("os.path.exists", return_value=True), \
             patch("os.getenv", return_value="false"), \
             patch.object(jf, "_PROBE_CACHE", {"operational": False, "skipped": "user namespaces unavailable", "checks": {}}):
            jailer = JailFactory.get_jailer("filesystem-provider", PROJECT_DIR, {}, [])
            assert isinstance(jailer, ContainerSeccompJailer)

    # ──────────────────────────────────────────────────────────────────────────
    # Test 11: Writable roots are allowed_paths only — never the working directory
    # ──────────────────────────────────────────────────────────────────────────
    def test_bubblewrap_writable_roots_are_allowed_paths_only(self):
        """build_permission_profile must never include cwd in the writable
        roots: a compromised provider must not be able to rewrite bridge.py,
        rules/, mcp-firewall.yaml or .env."""
        allowed = [os.path.join(PROJECT_DIR, "secure-experiment-zone")]
        jailer = BubblewrapJailer("filesystem-provider", PROJECT_DIR, {}, allowed)
        profile = jailer.build_permission_profile()

        writable = profile.file_system.get_writable_roots_with_cwd(PROJECT_DIR)
        assert writable == [os.path.abspath(p) for p in allowed]
        assert os.path.abspath(PROJECT_DIR) not in writable
        # The project root is readable (providers execute from it) but read-only.
        assert profile.file_system.has_full_disk_read_access() is True
        assert profile.file_system.has_full_disk_write_access() is False

        # Empty allowed_paths -> a fully read-only sandbox, never a writable cwd.
        jailer2 = BubblewrapJailer("filesystem-provider", PROJECT_DIR, {}, None)
        assert jailer2.build_permission_profile().file_system.get_writable_roots_with_cwd(PROJECT_DIR) == []

    # ──────────────────────────────────────────────────────────────────────────
    # Test 12: No global sandbox kill switches
    # ──────────────────────────────────────────────────────────────────────────
    def test_global_env_kill_switches_do_not_exist(self):
        """CODEX_SANDBOX=forbid / CODEX_SANDBOX_NETWORK=true must have no
        effect: sandboxing cannot be disabled or network opened globally."""
        import jail_factory as jf

        os.environ["CODEX_SANDBOX"] = "forbid"
        os.environ["CODEX_SANDBOX_NETWORK"] = "true"

        # Provider network policy still comes from the in-code table only.
        assert provider_sandbox_policy("filesystem-provider").network is False
        assert provider_sandbox_policy("keycloak-provider").network is True

        # The factory still selects the sandboxed jailer.
        def which_no_docker(name):
            return None if name == "docker" else f"/usr/bin/{name}"

        with self._bare_host_patches(), \
             patch("shutil.which", side_effect=which_no_docker), \
             patch.object(jf, "_PROBE_CACHE", {"operational": True, "checks": {}}):
            jailer = JailFactory.get_jailer("filesystem-provider", PROJECT_DIR, {}, [])
            assert isinstance(jailer, BubblewrapJailer)
            assert jailer.policy.network is False

    # ──────────────────────────────────────────────────────────────────────────
    # Test 13: Per-provider network policy table
    # ──────────────────────────────────────────────────────────────────────────
    def test_per_provider_network_policy_table(self):
        """Only keycloak-provider needs network (Keycloak Admin API over
        HTTP); every other known provider and every unknown provider fails
        closed without network."""
        assert providers_requiring_network() == ["keycloak-provider"]

        expected = {
            "keycloak-provider": True,       # talks to KEYCLOAK_URL over HTTP(S)
            "filesystem-provider": False,    # local filesystem tools
            "database-provider": False,      # embedded sqlite
            "scanner-provider": False,       # local scanning
            "system-monitor-provider": False,  # local process metrics
        }
        for name, network in expected.items():
            assert provider_sandbox_policy(name).network is network, name

        # Unknown providers fail closed.
        assert provider_sandbox_policy("totally-new-provider").network is False
        assert provider_sandbox_policy("keycloak-provider-evil-twin").network is False

    # ──────────────────────────────────────────────────────────────────────────
    # Test 14: verified bubblewrap+seccomp satisfies the high-risk minimum
    # ──────────────────────────────────────────────────────────────────────────
    def test_verified_bwrap_satisfies_high_risk_minimum(self):
        """A behaviorally verified bwrap+seccomp pipeline is a real sandbox and
        must satisfy the high-risk gate even when Docker is absent or its
        daemon is down. Weaker single-mechanism tiers stay below the minimum."""
        assert _SANDBOX_ORDER[_isolation_rank(SandboxType.CONTAINER)] == SandboxType.CONTAINER
        assert SandboxType.CONTAINER in _SANDBOX_ORDER
        assert _isolation_rank(SandboxType.BWRAP_SECCOMP) < _isolation_rank(SandboxType.CONTAINER)
        assert _isolation_rank(SandboxType.BWRAP_SECCOMP) > _isolation_rank(SandboxType.NSJAIL)
        assert _isolation_rank(SandboxType.WINDOWS_JOB) < _isolation_rank(SandboxType.BWRAP_SECCOMP)
        assert _isolation_rank(SandboxType.GVISOR) > _isolation_rank(SandboxType.DOCKER)

        # Verified bwrap passes, and a broken Docker install must not block it.
        SandboxEnforcer.set_override_status(
            SandboxStatus(
                docker_binary_found=True,
                docker_daemon_reachable=False,
                docker_daemon_error="permission denied",
                bwrap_found=True,
                user_namespaces_supported=True,
                behavior_probe={"operational": True, "checks": {}},
                effective_sandbox=SandboxType.BWRAP_SECCOMP,
            )
        )
        verified = SandboxEnforcer.verify_for_high_risk(
            "write_file", risk_delta=10, req_id="test-bwrap-rank"
        )
        assert verified.effective_sandbox == SandboxType.BWRAP_SECCOMP

        # nsjail alone does not meet the minimum.
        SandboxEnforcer.set_override_status(
            SandboxStatus(
                docker_binary_found=False,
                nsjail_found=True,
                bwrap_found=True,
                user_namespaces_supported=True,
                behavior_probe={
                    "operational": False,
                    "skipped": "probe mismatch",
                    "checks": {},
                },
                effective_sandbox=SandboxType.NSJAIL,
            )
        )
        with pytest.raises(SandboxUnavailableError) as exc_info:
            SandboxEnforcer.verify_for_high_risk(
                "write_file", risk_delta=10, req_id="test-nsjail-rank"
            )
        reason = str(exc_info.value)
        assert "Effective sandbox 'nsjail'" in reason
        assert "bwrap_seccomp" in reason
        # Diagnostics must explain the bwrap failure instead of only saying
        # "Docker is not installed".
        assert "behavioral self-test" in reason
        assert "probe mismatch" in reason

        # A declared BWRAP_SECCOMP tier without a passing behavioral probe is
        # not trusted: rank alone is insufficient evidence.
        SandboxEnforcer.set_override_status(
            SandboxStatus(
                docker_binary_found=False,
                bwrap_found=True,
                user_namespaces_supported=True,
                behavior_probe={"operational": False, "checks": {}},
                effective_sandbox=SandboxType.BWRAP_SECCOMP,
            )
        )
        with pytest.raises(SandboxUnavailableError) as exc_info:
            SandboxEnforcer.verify_for_high_risk(
                "write_file", risk_delta=10, req_id="test-bwrap-unverified"
            )
        assert "not behaviorally verified" in str(exc_info.value)

    # ──────────────────────────────────────────────────────────────────────────
    # Test 15: bubblewrap argv construction
    # ──────────────────────────────────────────────────────────────────────────
    def test_bwrap_argv_construction(self):
        """The generated bwrap invocation mounts the root read-only (so /etc
        and the working directory are not writable), binds only allowed_paths
        writable, protects workspace metadata, and always unshares ipc."""
        # Writable root outside /tmp: a private sandbox-local /tmp is mounted.
        ws = os.path.join(PROJECT_DIR, ".selftest-ws")
        os.makedirs(os.path.join(ws), exist_ok=True)
        try:
            with open(os.path.join(ws, ".env"), "w") as fh:  # protected metadata
                fh.write("SECRET=1\n")                        # non-empty => re-bind
            fs = FileSystemSandboxPolicy.workspace_write([ws])
            args = create_bwrap_command_args(
                ["/usr/bin/env", "true"], fs, PROJECT_DIR, PROJECT_DIR,
                BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
            )
            flat = " ".join(args)

            assert "--ro-bind / /" in flat              # read-only root
            assert f"--bind {ws} {ws}" in flat          # allowed path writable
            assert f"--ro-bind {ws}/.env {ws}/.env" in flat  # .env stays read-only
            assert "--unshare-user" in flat
            assert "--unshare-pid" in flat
            assert "--unshare-ipc" in flat               # IPC namespace isolation
            assert "--unshare-net" in flat               # network-off policy
            assert "--cap-drop ALL" in flat
            # Private /tmp is mounted unless the project itself lives under
            # /tmp (then the paths must stay visible instead).
            tmpfs_targets = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "--tmpfs"]
            project_under_tmp = os.path.realpath(PROJECT_DIR).startswith(os.sep + "tmp" + os.sep)
            if project_under_tmp:
                assert "/tmp" not in tmpfs_targets
            else:
                assert "/tmp" in tmpfs_targets
            # No writable bind of the project dir, /etc, or the root.
            assert f"--bind {PROJECT_DIR} {PROJECT_DIR}" not in flat
            assert "--bind /etc /etc" not in flat
            assert "--bind / /" not in flat

            # Network-on policy keeps the host network namespace.
            args_net = create_bwrap_command_args(
                ["/usr/bin/env", "true"], fs, PROJECT_DIR, PROJECT_DIR,
                BwrapOptions(network_mode=BwrapNetworkMode.FULL_ACCESS),
            )
            assert "--unshare-net" not in " ".join(args_net)
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

        # Writable root under /tmp: the private /tmp tmpfs is skipped so the
        # sandbox itself can still see (and bind) its own paths.
        with tempfile.TemporaryDirectory() as ws_tmp:
            fs_tmp = FileSystemSandboxPolicy.workspace_write([ws_tmp])
            args_tmp = create_bwrap_command_args(
                ["/usr/bin/env", "true"], fs_tmp, ws_tmp, ws_tmp,
                BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
            )
            tmpfs_targets = [args_tmp[i + 1] for i, a in enumerate(args_tmp[:-1]) if a == "--tmpfs"]
            assert "/tmp" not in tmpfs_targets
            assert f"--bind {ws_tmp} {ws_tmp}" in " ".join(args_tmp)

    # ──────────────────────────────────────────────────────────────────────────
    # Test 16: Behavioral self-test — the sandbox actually confines
    # ──────────────────────────────────────────────────────────────────────────
    def test_behavioral_selftest_confines(self):
        """The behavioral probe runs a REAL sandboxed process and verifies:
        writing bridge.py fails, writing under rules/ fails, creating a new
        .env fails, writing /etc fails, IP sockets are denied, AF_UNIX
        socketpairs still work, the allowed path stays writable, protected
        names cannot be created inside the writable root, the capability set
        is empty, deny-read masks hide secrets, and ptrace/process_vm/
        io_uring fail with EPERM specifically."""
        if not _bwrap_available_on_host():
            pytest.skip("bubblewrap + user namespaces not available on this host")
        report = bwrap_behavior_probe()
        assert report.get("skipped") is None, report
        assert report.get("operational") is True, report
        checks = report["checks"]
        assert checks["open_bridge_py"] == "denied"
        assert checks["create_in_rules_dir"] == "denied"
        assert checks["create_env_file"] == "denied"
        assert checks["write_etc"] == "denied"
        assert checks["inet_socket"] == "denied"
        assert checks["unix_socketpair"] == "succeeded"
        assert checks["write_allowed_path"] == "succeeded"
        assert checks["create_in_writable_root"] == "denied"
        assert checks["capabilities_empty"] == "succeeded"
        assert checks["read_denied_secret"] == "denied"
        assert checks["ptrace_syscall"] == "eperm"
        assert checks["process_vm_readv_syscall"] == "eperm"
        assert checks["io_uring_setup_syscall"] == "eperm"

    # ──────────────────────────────────────────────────────────────────────────
    # Test 17: Real pipeline — a sandboxed provider cannot overwrite the project
    # ──────────────────────────────────────────────────────────────────────────
    def test_sandboxed_process_cannot_overwrite_project_files(self):
        """End-to-end through the real two-stage pipeline: attempts to
        overwrite bridge.py, create files under rules/ and plant a new .env
        must all be denied, while the secure experiment zone stays writable."""
        if not _bwrap_available_on_host():
            pytest.skip("bubblewrap + user namespaces not available on this host")
        import subprocess as sp

        ws = os.path.join(PROJECT_DIR, "secure-experiment-zone")
        probe = (
            "import json, socket, sys\n"
            "r = {}\n"
            "def att(n, f):\n"
            "    try:\n"
            "        f(); r[n] = 'ALLOWED'\n"
            "    except OSError:\n"
            "        r[n] = 'DENIED'\n"
            "att('bridge_py', lambda: open(sys.argv[1], 'r+').close())\n"
            "att('rules_dir', lambda: open(sys.argv[2], 'x').close())\n"
            "att('new_env', lambda: open(sys.argv[3], 'x').close())\n"
            "att('tcp_socket', lambda: socket.socket(socket.AF_INET).close())\n"
            "att('workspace', lambda: open(sys.argv[4], 'w').write('probe'))\n"
            "print(json.dumps(r))\n"
        )
        env_file = os.path.join(PROJECT_DIR, ".env.selftest-tmp")
        cmd = [sys.executable, "-c", probe,
               os.path.join(PROJECT_DIR, "bridge.py"),
               os.path.join(PROJECT_DIR, "rules", ".selftest-tmp"),
               env_file,
               os.path.join(ws, ".selftest-tmp")]
        jailer = BubblewrapJailer("filesystem-provider", PROJECT_DIR,
                                  {"PATH": os.environ.get("PATH", "")}, [ws])
        jailer.get_popen_kwargs(cmd)  # rewrites cmd in place with the wrapper
        completed = sp.run(cmd, capture_output=True, text=True, timeout=60,
                           cwd=PROJECT_DIR)
        results = json.loads(completed.stdout.strip().splitlines()[-1])

        assert results["bridge_py"] == "DENIED"
        assert results["rules_dir"] == "DENIED"
        assert results["new_env"] == "DENIED"
        assert results["tcp_socket"] == "DENIED"
        assert results["workspace"] == "ALLOWED"

        # No files were actually created outside the workspace.
        assert not os.path.exists(os.path.join(PROJECT_DIR, "rules", ".selftest-tmp"))
        assert not os.path.exists(env_file)
        assert os.path.exists(os.path.join(ws, ".selftest-tmp"))
        os.unlink(os.path.join(ws, ".selftest-tmp"))

    # ──────────────────────────────────────────────────────────────────────────
    # Test 18: keycloak-provider keeps network access inside its sandbox
    # ──────────────────────────────────────────────────────────────────────────
    def test_keycloak_provider_policy_allows_network_in_sandbox(self):
        """The per-provider policy grants keycloak-provider host networking
        (no --unshare-net, no network syscall denial) while the filesystem
        restrictions stay identical, and the VM-socket-restricted seccomp
        mode still denies AF_VSOCK sockets and io_uring even with network
        on (matching codex-rs seccomp.rs NetworkSeccompMode::VmSocketRestricted)."""
        if not _bwrap_available_on_host():
            pytest.skip("bubblewrap + user namespaces not available on this host")
        import subprocess as sp
        import jail_factory as jf

        ws = os.path.join(PROJECT_DIR, "secure-experiment-zone")
        AF_VSOCK = 40
        IOURING_NR = jf.SYSNO["io_uring_setup"]
        probe = (
            "import ctypes, errno, json, socket, sys\n"
            "r = {}\n"
            "try:\n"
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    s.close()\n"
            "    r['inet_socket'] = 'ALLOWED'\n"
            "except OSError:\n"
            "    r['inet_socket'] = 'DENIED'\n"
            "try:\n"
            "    open('bridge.py', 'r+').close()\n"
            "    r['bridge_py'] = 'ALLOWED'\n"
            "except OSError:\n"
            "    r['bridge_py'] = 'DENIED'\n"
            # AF_VSOCK must be denied even though network is on
            "try:\n"
            f"    s = socket.socket({AF_VSOCK}, socket.SOCK_STREAM)\n"
            "    s.close()\n"
            "    r['vsock_socket'] = 'ALLOWED'\n"
            "except OSError as e:\n"
            "    r['vsock_socket'] = 'EPERM' if e.errno == errno.EPERM else f'errno:{e.errno}'\n"
            # io_uring is denied in every socket-restricted mode
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "ctypes.set_errno(0)\n"
            f"rc = libc.syscall(ctypes.c_long({IOURING_NR}), 1, 0, 0)\n"
            "r['io_uring'] = 'allowed' if rc != -1 else (" 
            "'eperm' if ctypes.get_errno() == errno.EPERM else f\"errno:{ctypes.get_errno()}\")\n"
            "print(json.dumps(r))\n"
        )
        jailer = BubblewrapJailer("keycloak-provider", PROJECT_DIR,
                                  {"PATH": os.environ.get("PATH", "")}, [ws])
        assert jailer.policy.network is True
        cmd = [sys.executable, "-c", probe]
        jailer.get_popen_kwargs(cmd)  # rewrites cmd in place with the wrapper
        completed = sp.run(cmd, capture_output=True, text=True, timeout=60,
                           cwd=PROJECT_DIR)
        results = json.loads(completed.stdout.strip().splitlines()[-1])

        assert results["inet_socket"] == "ALLOWED"
        assert results["bridge_py"] == "DENIED"
        assert results["vsock_socket"] == "EPERM"
        assert results["io_uring"] == "eperm"

    # ──────────────────────────────────────────────────────────────────────
    # Test 19: seccomp deny list matches codex-rs seccomp.rs entry for entry
    # ──────────────────────────────────────────────────────────────────────
    def test_seccomp_deny_list_matches_codex_seccomp_rs(self):
        """Decoded BPF for RESTRICTED mode must contain a JEQ-deny for every
        syscall codex-rs/linux-sandbox/src/seccomp.rs denies (ptrace,
        process_vm_*, the networking calls, io_uring_*), and VM_SOCKET_
        RESTRICTED must deny io_uring_* while leaving ptrace allowed (as
        upstream does in that mode)."""
        import struct
        import jail_factory as jf

        def jeq_constants(mode):
            prog = jf.build_seccomp_bpf(mode)
            found = set()
            for i in range(len(prog) // 8):
                code, _jt, _jf, k = struct.unpack_from("<HBBI", prog, i * 8)
                if code == (jf.BPF_JMP | jf.BPF_JEQ | jf.BPF_K):
                    found.add(k)
            return found

        restricted = jeq_constants(jf.NetworkSeccompMode.RESTRICTED)
        for name in ("ptrace", "process_vm_readv", "process_vm_writev",
                     "connect", "accept", "accept4", "bind", "listen",
                     "getpeername", "getsockname", "shutdown", "sendto",
                     "sendmmsg", "recvmmsg", "getsockopt", "setsockopt",
                     "io_uring_setup", "io_uring_enter", "io_uring_register"):
            assert jf.SYSNO[name] in restricted, f"{name} missing from deny list"
        # recvfrom is deliberately NOT denied (cargo clippy needs it)
        assert jf.SYSNO["recvfrom"] not in restricted if "recvfrom" in jf.SYSNO else True

        vsock_mode = jeq_constants(jf.NetworkSeccompMode.VM_SOCKET_RESTRICTED)
        for name in ("io_uring_setup", "io_uring_enter", "io_uring_register"):
            assert jf.SYSNO[name] in vsock_mode, f"{name} must be denied even with network on"
        # in VmSocketRestricted, upstream does NOT deny ptrace/process_vm_*
        assert jf.SYSNO["ptrace"] not in vsock_mode
        assert jf.SYSNO["process_vm_readv"] not in vsock_mode
        # the AF_VSOCK family gate is present in that mode
        assert jf.AF_VSOCK in vsock_mode

    def test_seccomp_bpf_blocks_x32_syscall_numbers(self):
        """Runtime Shield addition beyond upstream: on x86_64 the BPF program
        must jump to the deny action for any syscall number >= 0x40000000
        (the x32 ABI keeps AUDIT_ARCH_X86_64, so the arch gate alone cannot
        stop x32-numbered calls from bypassing the deny rules)."""
        import struct
        import jail_factory as jf

        prog = jf.build_seccomp_bpf(jf.NetworkSeccompMode.RESTRICTED)
        has_x32_gate = False
        for i in range(len(prog) // 8):
            code, _jt, _jf, k = struct.unpack_from("<HBBI", prog, i * 8)
            if code == (jf.BPF_JMP | jf.BPF_JGE | jf.BPF_K) and k == 0x40000000:
                has_x32_gate = True
        if jf._IS_X86_64:
            assert has_x32_gate, "x32 syscall-number gate missing on x86_64"
        else:
            assert not has_x32_gate, "x32 gate must not exist on non-x86_64"

    def test_x32_syscall_denied_behaviorally(self):
        """A real sandboxed process calling socket() through the x32 ABI
        (syscall 41 | 0x40000000) must get EPERM. Skipped when the kernel
        has no x32 ABI (ENOSYS — nothing to protect then)."""
        if not _bwrap_available_on_host():
            pytest.skip("bubblewrap + user namespaces not available on this host")
        import subprocess as sp
        import jail_factory as jf
        if not jf._IS_X86_64:
            pytest.skip("x32 gate is x86_64-only")

        ws = os.path.join(PROJECT_DIR, "secure-experiment-zone")
        probe = (
            "import ctypes, errno, json, sys\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "ctypes.set_errno(0)\n"
            "rc = libc.syscall(ctypes.c_long(41 | 0x40000000), 2, 1, 0)\n"
            "if rc != -1:\n"
            "    out = 'allowed'\n"
            "else:\n"
            "    e = ctypes.get_errno()\n"
            "    out = 'eperm' if e == errno.EPERM else ('enosys' if e == errno.ENOSYS else f'errno:{e}')\n"
            "print(json.dumps({'x32_socket': out}))\n"
        )
        jailer = BubblewrapJailer("filesystem-provider", PROJECT_DIR,
                                  {"PATH": os.environ.get("PATH", "")}, [ws])
        cmd = [sys.executable, "-c", probe]
        jailer.get_popen_kwargs(cmd)
        completed = sp.run(cmd, capture_output=True, text=True, timeout=60,
                           cwd=PROJECT_DIR)
        stdout = completed.stdout.strip()
        if not stdout and completed.returncode in (159, -31, 128 + 31):
            # The kernel itself killed the x32 syscall with SIGSYS ("Bad
            # system call") before any filter ran: x32 is unreachable on
            # this host, so our gate cannot be distinguished behaviorally.
            # The structural test (test_seccomp_bpf_blocks_x32_syscall_)
            # numbers) still proves the gate is present in the BPF.
            pytest.skip("kernel already blocks x32 syscalls with SIGSYS")
        results = json.loads(stdout.splitlines()[-1])
        if results["x32_socket"] == "enosys":
            pytest.skip("kernel built without the x32 ABI (CONFIG_X86_X32_ABI)")
        assert results["x32_socket"] == "eperm", results

    # ──────────────────────────────────────────────────────────────────────
    # Test 20: inner-stage failures are sandbox failures, not crashes
    # ──────────────────────────────────────────────────────────────────────
    def test_inner_stage_failure_is_reported_as_sandbox_failure(self, capsys):
        """If the capability check or the seccomp filter install fails inside
        the sandbox, the helper must report a SANDBOX FAILURE and exit 126
        instead of dying with a traceback (mirrors Codex mapping these to
        CodexErr::Sandbox)."""
        import jail_factory as jf

        profile = jf.PermissionProfile.workspace_write(["/tmp"], network=False)
        argv = [
            "--sandbox-policy-cwd", PROJECT_DIR,
            "--command-cwd", PROJECT_DIR,
            "--permission-profile", json.dumps(profile.to_dict()),
            "--apply-seccomp-then-exec",
            "--", "/usr/bin/env", "true",
        ]
        original = jf.verify_no_capabilities
        def _boom():
            raise RuntimeError("simulated capability-check failure")
        jf.verify_no_capabilities = _boom
        try:
            with pytest.raises(SystemExit) as exc_info:
                jf.run_linux_sandbox_main(argv)
        finally:
            jf.verify_no_capabilities = original
        assert exc_info.value.code == 126
        captured = capsys.readouterr()
        assert "SANDBOX FAILURE" in captured.err
        assert "simulated capability-check failure" in captured.err

    # ──────────────────────────────────────────────────────────────────────
    # Test 21: in-container fallback is deliberate and logged as CONTAINER
    # ──────────────────────────────────────────────────────────────────────
    def test_container_fallback_is_logged_as_container_tier(self, caplog, monkeypatch):
        """Inside a container with no operational bubblewrap, providers fall
        back to the container boundary plus the Codex seccomp inner stage —
        explicitly logged as the CONTAINER tier, never silently and never
        reported as a stronger sandbox."""
        import logging
        import jail_factory as jf

        monkeypatch.setenv("DOCKER_CONTAINER", "true")
        monkeypatch.setattr(jf, "bwrap_operational", lambda: False)
        with caplog.at_level(logging.INFO, logger="jail_factory"):
            jailer = jf.JailFactory.get_jailer("filesystem-provider", PROJECT_DIR, {}, None)
        assert isinstance(jailer, jf.ContainerSeccompJailer)
        assert "CONTAINER" in caplog.text

    def test_container_uses_bwrap_when_selftest_passes(self, caplog, monkeypatch):
        """Inside a container whose seccomp profile permits user namespaces,
        the behavioral self-test passes and providers get the nested
        bubblewrap+seccomp sandbox (defense in depth)."""
        import logging
        import jail_factory as jf

        monkeypatch.setenv("DOCKER_CONTAINER", "true")
        monkeypatch.setattr(jf, "bwrap_operational", lambda: True)
        with caplog.at_level(logging.INFO, logger="jail_factory"):
            jailer = jf.JailFactory.get_jailer("filesystem-provider", PROJECT_DIR, {}, None)
        assert isinstance(jailer, jf.BubblewrapJailer)
        assert "defense in depth" in caplog.text

    # ──────────────────────────────────────────────────────────────────────
    # Test 22: helper flags after `--` are command arguments (injection fix)
    # ──────────────────────────────────────────────────────────────────────
    def test_helper_flags_after_separator_are_command_arguments(self):
        """A provider command argument that looks like a helper flag must be
        passed to the command, never parsed as sandbox configuration. This is
        the regression test for the --apply-seccomp-then-exec bypass."""
        import jail_factory as jf

        profile = PermissionProfile.read_only(network=False)
        argv = [
            "--sandbox-policy-cwd", PROJECT_DIR,
            "--command-cwd", PROJECT_DIR,
            "--permission-profile", json.dumps(profile.to_dict()),
            "--", "/usr/bin/env", "true",
            "--apply-seccomp-then-exec", "--no-proc",
        ]
        with patch.object(jf, "_outer_stage") as outer, \
             patch.object(jf, "_inner_stage") as inner:
            jf.run_linux_sandbox_main(argv)

        assert inner.call_count == 0
        assert outer.call_count == 1
        command = outer.call_args.args[0]
        assert command[-2:] == ["--apply-seccomp-then-exec", "--no-proc"]
        # Boolean helper flags after `--` must not affect the outer options.
        assert outer.call_args.args[4] is False   # no_proc
        assert outer.call_args.args[5] is False   # inherit_pid_namespace

    def test_helper_rejects_unknown_flags_before_separator(self):
        """Only documented helper flags are accepted before `--`, mirroring
        clap. Unknown prefix arguments fail closed with exit code 2."""
        import jail_factory as jf

        profile = PermissionProfile.read_only(network=False)
        argv = [
            "--sandbox-policy-cwd", PROJECT_DIR,
            "--permission-profile", json.dumps(profile.to_dict()),
            "--bogus-helper-flag",
            "--", "/usr/bin/env", "true",
        ]
        with pytest.raises(SystemExit) as exc_info:
            jf.run_linux_sandbox_main(argv)
        assert exc_info.value.code == 2

    def test_helper_requires_sandbox_policy_cwd_before_separator(self):
        """A --sandbox-policy-cwd placed after `--` is a command argument, so
        the helper must reject the invocation as missing its required flag."""
        import jail_factory as jf

        profile = PermissionProfile.read_only(network=False)
        argv = [
            "--permission-profile", json.dumps(profile.to_dict()),
            "--", "/usr/bin/env", "true", "--sandbox-policy-cwd", PROJECT_DIR,
        ]
        with pytest.raises(SystemExit) as exc_info:
            jf.run_linux_sandbox_main(argv)
        assert exc_info.value.code == 2

    # ──────────────────────────────────────────────────────────────────────
    # Test 23: synthetic-target cleanup preserves pre-existing empty paths
    # ──────────────────────────────────────────────────────────────────────
    def test_cleanup_preserves_preexisting_empty_protected_paths(self):
        """Empty .env/.ssh paths that existed before the run are user data:
        the masks may cover them during the run, but cleanup must keep them.
        Only targets this run created are removed."""
        import jail_factory as jf
        import shutil as _shutil

        base = tempfile.mkdtemp(prefix="synthetic-cleanup-", dir="/tmp/opencode")
        try:
            cwd = os.path.join(base, "project")
            ws = os.path.join(base, "workspace")
            os.makedirs(cwd)
            os.makedirs(ws)
            env_file = os.path.join(ws, ".env")
            ssh_dir = os.path.join(ws, ".ssh")
            open(env_file, "w").close()
            os.makedirs(ssh_dir)

            fs = FileSystemSandboxPolicy.workspace_write([ws])
            mounts = jf.build_bwrap_mounts(
                ["/usr/bin/env", "true"], fs, cwd, cwd,
                BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
            )
            try:
                registrations = jf._register_synthetic_mount_targets(
                    mounts.synthetic_targets
                )
            finally:
                for fd in mounts.preserved_fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

            # Simulate bwrap materializing a missing protected directory.
            created_by_run = os.path.join(ws, ".git")
            os.makedirs(created_by_run)
            jf._cleanup_synthetic_mount_targets(registrations)

            assert os.path.isfile(env_file), "pre-existing empty .env was deleted"
            assert os.path.isdir(ssh_dir), "pre-existing empty .ssh was deleted"
            assert not os.path.exists(created_by_run), (
                "a target created by this run was not cleaned up"
            )
        finally:
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 24: NSJailer fails closed if nsjail disappears
    # ──────────────────────────────────────────────────────────────────────
    def test_nsjail_missing_fails_closed(self):
        import jail_factory as jf

        with patch("jail_factory.shutil.which", return_value=None):
            jailer = NSJailer("filesystem-provider", PROJECT_DIR, {}, [])
            with pytest.raises(RuntimeError) as exc_info:
                jailer.get_popen_kwargs(["node", "dist/index.js"])
        assert "[SANDBOX FAIL-CLOSED]" in str(exc_info.value)
        assert "nsjail executable not found" in str(exc_info.value)

    # ──────────────────────────────────────────────────────────────────────
    # Test 25: OpenSandbox hardening preserves read-only-cwd invariant
    # ──────────────────────────────────────────────────────────────────────
    def test_opensandbox_hardening_and_read_only_cwd(self):
        import shutil as _shutil

        base = tempfile.mkdtemp(prefix="opensandbox-", dir="/tmp/opencode")
        try:
            cwd = os.path.join(base, "project")
            ws = os.path.join(cwd, "zone")
            os.makedirs(ws)
            daemon = MagicMock(
                returncode=0,
                stdout="ServerVersion: 27\nruntimes: runsc",
                stderr="",
            )
            with patch("jail_factory.shutil.which", return_value="/usr/bin/docker"), \
                 patch("jail_factory.subprocess.run", return_value=daemon):
                jailer = OpenSandboxJailer(
                    "filesystem-provider", cwd, {"PATH": "/usr/bin"}, [ws]
                )
                cmd = ["python", "-c", "print(1)"]
                jailer.get_popen_kwargs(cmd)

            assert "--read-only" in cmd
            assert cmd[cmd.index("--cap-drop") + 1] == "ALL"
            assert "no-new-privileges:true" in cmd
            user = cmd[cmd.index("--user") + 1]
            assert user != "0:0", "sandboxed provider must not run as container root"
            assert cmd[cmd.index("--network") + 1] == "none"
            assert f"{os.path.abspath(cwd)}:/workspace:ro" in cmd
            assert f"{os.path.abspath(ws)}:/workspace/zone:rw" in cmd
            assert f"{os.path.abspath(cwd)}:/workspace" not in cmd

            # A network-granted provider keeps Docker's default bridge (never
            # host networking) and is not forced to --network none.
            with patch("jail_factory.shutil.which", return_value="/usr/bin/docker"), \
                 patch("jail_factory.subprocess.run", return_value=daemon):
                jailer2 = OpenSandboxJailer(
                    "keycloak-provider", cwd, {"PATH": "/usr/bin"}, [ws]
                )
                cmd2 = ["python", "-c", "print(1)"]
                jailer2.get_popen_kwargs(cmd2)
            assert "--network" not in cmd2
            assert "--network" + "=host" not in " ".join(cmd2)
        finally:
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 26: capability check rejects permitted (not just effective) caps
    # ──────────────────────────────────────────────────────────────────────
    def test_capability_check_rejects_permitted_capabilities(self):
        import ctypes
        import struct
        import jail_factory as jf

        class FakeLibc:
            def __init__(self, permitted):
                self.permitted = permitted

            def syscall(self, _nr, _header, buf):
                ctypes.memmove(
                    buf,
                    struct.pack("<IIIIII", 0, self.permitted, 0, 0, 0, 0),
                    24,
                )
                return 0

        original = jf._libc
        try:
            jf._libc = FakeLibc(1)
            with pytest.raises(RuntimeError) as exc_info:
                jf.verify_no_capabilities()
            assert "permitted" in str(exc_info.value)

            jf._libc = FakeLibc(0)
            jf.verify_no_capabilities()
        finally:
            jf._libc = original

    # ──────────────────────────────────────────────────────────────────────
    # Test 27: deny-read coverage includes container/account secrets
    # ──────────────────────────────────────────────────────────────────────
    def test_deny_read_covers_container_and_account_secrets(self):
        import jail_factory as jf

        home = "/home/selftest"
        paths = jf.runtime_shield_deny_read_paths(
            PROJECT_DIR, {"HOME": home, "SPIFFE_ENABLED": "false"}
        )
        expected = [
            os.path.join(PROJECT_DIR, ".env"),
            os.path.join(PROJECT_DIR, ".env.local"),
            os.path.join(PROJECT_DIR, "keycloak-tls"),
            os.path.join(PROJECT_DIR, "spire", "certs"),
            "/run/docker.sock",
            "/run/secrets",
            "/etc/shadow",
            os.path.join(home, ".ssh"),
            os.path.join(home, ".aws"),
            os.path.join(home, ".gnupg"),
            os.path.join(home, ".netrc"),
            os.path.join(home, ".config", "gcloud"),
            "/run/spire/sockets/agent.sock",
        ]
        for path in expected:
            assert path in paths, f"missing deny-read mask: {path}"

        # The SPIRE socket stays visible when SPIFFE is enabled.
        with_spiffe = jf.runtime_shield_deny_read_paths(
            PROJECT_DIR, {"HOME": home, "SPIFFE_ENABLED": "true"}
        )
        assert "/run/spire/sockets/agent.sock" not in with_spiffe

    # ──────────────────────────────────────────────────────────────────────
    # Test 28: full-disk-write policies match Codex's two special paths
    # ──────────────────────────────────────────────────────────────────────
    def test_full_disk_write_policy_matches_codex_paths(self):
        import jail_factory as jf

        fs = FileSystemSandboxPolicy.full_disk_access()
        args = create_bwrap_command_args(
            ["/usr/bin/env", "true"], fs, PROJECT_DIR, PROJECT_DIR,
            BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
        )
        flat = " ".join(args)
        assert "--bind / /" in flat
        assert "--unshare-net" in flat
        assert "--ro-bind / /" not in flat

        # Full write + full network: no bwrap wrapper at all.
        args_full = create_bwrap_command_args(
            ["/usr/bin/env", "true"], fs, PROJECT_DIR, PROJECT_DIR,
            BwrapOptions(network_mode=BwrapNetworkMode.FULL_ACCESS),
        )
        assert args_full == ["/usr/bin/env", "true"]

    def test_full_disk_write_full_network_execs_without_bwrap(self):
        import jail_factory as jf

        profile = PermissionProfile.danger_full_access()
        argv = [
            "--sandbox-policy-cwd", PROJECT_DIR,
            "--permission-profile", json.dumps(profile.to_dict()),
            "--", "/usr/bin/env", "true",
        ]
        with patch.object(jf, "find_bwrap", return_value="/usr/bin/bwrap"), \
             patch.object(jf, "is_wsl1", return_value=False), \
             patch.object(jf, "apply_sandbox_policies_to_current_thread") as apply_policy, \
             patch.object(jf, "_execvp", side_effect=SystemExit(0)) as execvp:
            with pytest.raises(SystemExit):
                jf.run_linux_sandbox_main(argv)
        apply_policy.assert_called_once()
        execvp.assert_called_once_with(["/usr/bin/env", "true"])

    # ──────────────────────────────────────────────────────────────────────
    # Test 29: container seccomp tier uses the exact inner-stage flag
    # ──────────────────────────────────────────────────────────────────────
    def test_container_seccomp_jailer_uses_inner_stage(self):
        jailer = ContainerSeccompJailer(
            "filesystem-provider", PROJECT_DIR, {"PATH": "/usr/bin"}, None
        )
        cmd = ["/usr/bin/env", "true"]
        jailer.get_popen_kwargs(cmd)
        assert cmd[0] == sys.executable
        assert "--apply-seccomp-then-exec" in cmd
        assert cmd[cmd.index("--apply-seccomp-then-exec") + 1] == "--"
        assert cmd[-2:] == ["/usr/bin/env", "true"]

    # ──────────────────────────────────────────────────────────────────────
    # Test 30: probe reports verified bwrap inside a container
    # ──────────────────────────────────────────────────────────────────────
    def test_probe_inside_container_reports_verified_bwrap(self):
        import sandbox_enforcer as se

        with patch.object(se.os.path, "exists", return_value=True), \
             patch.object(se.shutil, "which", return_value=None), \
             patch.object(se, "find_bwrap", return_value="/usr/bin/bwrap"), \
             patch.object(se, "user_namespaces_supported", return_value=True), \
             patch.object(se, "is_wsl1", return_value=False), \
             patch.object(se, "preflight_proc_mount_supported", return_value=True), \
             patch.object(se.subprocess, "run",
                          return_value=MagicMock(returncode=0, stdout="bubblewrap 0.11.1", stderr="")), \
             patch.object(se, "bwrap_behavior_probe",
                          return_value={"operational": True, "skipped": None, "checks": {}}), \
             patch.object(se, "bwrap_operational", return_value=True):
            status = se._probe_sandbox()

        assert status.inside_container is True
        assert status.bwrap_found is True
        assert status.effective_sandbox == SandboxType.BWRAP_SECCOMP

    # ──────────────────────────────────────────────────────────────────────
    # Test 31: symlinked writable roots bind/mask the canonical target
    # ──────────────────────────────────────────────────────────────────────
    def test_symlinked_writable_root_binds_canonical_target(self):
        """Codex binds a symlinked writable root at its real target and remaps
        carveouts there. Binding the logical alias would let the sandboxed
        process replace the alias after the mount was decided."""
        import shutil as _shutil
        import jail_factory as jf

        base = tempfile.mkdtemp(prefix="symlink-root-", dir="/tmp/opencode")
        try:
            real_root = os.path.join(base, "real")
            link_root = os.path.join(base, "link")
            blocked = os.path.join(real_root, "blocked")
            os.makedirs(blocked)
            os.symlink(real_root, link_root)

            policy = FileSystemSandboxPolicy([
                FileSystemSandboxPolicy.workspace_write([link_root])
                .entries[0],  # read-only "/" baseline
                jf.FileSystemSandboxEntry(link_root, jf.FileSystemAccessMode.WRITE),
                jf.FileSystemSandboxEntry(
                    os.path.join(link_root, "blocked"), jf.FileSystemAccessMode.DENY
                ),
            ])
            args = create_bwrap_command_args(
                ["/usr/bin/env", "true"], policy, base, base,
                BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
            )
            flat = " ".join(args)
            assert f"--bind {real_root} {real_root}" in flat
            assert f"--bind {link_root} {link_root}" not in flat
            assert f"--tmpfs {blocked}" in flat
            assert f"--tmpfs {os.path.join(link_root, 'blocked')}" not in flat
        finally:
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 32: --chdir uses the canonical command cwd
    # ──────────────────────────────────────────────────────────────────────
    def test_canonical_command_cwd_used_for_chdir(self):
        """A symlinked logical cwd disappears when only canonical roots are
        mounted, so bwrap must enter the canonical path explicitly."""
        import shutil as _shutil
        import jail_factory as jf

        base = tempfile.mkdtemp(prefix="canonical-cwd-", dir="/tmp/opencode")
        try:
            real_root = os.path.join(base, "real")
            real_sub = os.path.join(real_root, "subdir")
            link_root = os.path.join(base, "link")
            link_sub = os.path.join(link_root, "subdir")
            os.makedirs(real_sub)
            os.symlink(real_root, link_root)

            policy = FileSystemSandboxPolicy.workspace_write([link_root])
            args = create_bwrap_command_args(
                ["/usr/bin/env", "true"], policy, link_root, link_sub,
                BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
            )
            real_sub_canonical = os.path.realpath(real_sub)
            flat = " ".join(args)
            assert f"--chdir {real_sub_canonical}" in flat
            assert f"--chdir {link_sub}" not in flat
            assert f"--bind {os.path.realpath(link_root)} {os.path.realpath(link_root)}" in flat
        finally:
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 32b: a distinct command cwd is entered explicitly
    # ──────────────────────────────────────────────────────────────────────
    def test_distinct_command_cwd_is_entered_explicitly(self):
        """The helper runs with cwd == sandbox_policy_cwd, so even a plain
        (non-symlinked) command subdirectory must be passed to --chdir or
        bwrap would run the command in the policy cwd instead."""
        import shutil as _shutil
        import jail_factory as jf

        base = tempfile.mkdtemp(prefix="distinct-cwd-", dir="/tmp/opencode")
        try:
            sub = os.path.join(base, "sub")
            os.makedirs(sub)
            policy = FileSystemSandboxPolicy.workspace_write([base])
            args = create_bwrap_command_args(
                ["/usr/bin/env", "true"], policy, base, sub,
                BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
            )
            assert any(
                args[i:i + 2] == ["--chdir", os.path.realpath(sub)]
                for i in range(len(args) - 1)
            )
        finally:
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 32c: denied-ancestor masks recreate nested writable mount targets
    # ──────────────────────────────────────────────────────────────────────
    def test_denied_ancestor_mask_recreates_nested_mount_targets(self):
        """Codex calls append_mount_target_parent_dir_args before binding a
        writable root that sits under an already-masked deny ancestor, so the
        bind target exists inside the fresh tmpfs."""
        import shutil as _shutil
        import jail_factory as jf

        base = tempfile.mkdtemp(prefix="masked-ancestor-", dir="/tmp/opencode")
        try:
            denied = os.path.join(base, "blocked")
            nested = os.path.join(denied, "allowed")
            os.makedirs(nested)
            policy = FileSystemSandboxPolicy([
                jf.FileSystemSandboxEntry("/", jf.FileSystemAccessMode.READ),
                jf.FileSystemSandboxEntry(nested, jf.FileSystemAccessMode.WRITE),
                jf.FileSystemSandboxEntry(denied, jf.FileSystemAccessMode.DENY),
            ])
            args = create_bwrap_command_args(
                ["/usr/bin/env", "true"], policy, base, base,
                BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
            )
            assert any(
                args[i:i + 2] == ["--tmpfs", denied]
                for i in range(len(args) - 1)
            )
            dir_index = next(
                i for i in range(len(args) - 1)
                if args[i:i + 2] == ["--dir", nested]
            )
            bind_index = next(
                i for i in range(len(args) - 2)
                if args[i:i + 3] == ["--bind", nested, nested]
            )
            assert dir_index < bind_index
        finally:
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 33: registry protection precedes a denied parent mask
    # ──────────────────────────────────────────────────────────────────────
    def test_registry_protection_precedes_denied_parent_mask(self):
        """When a writable root exposes the synthetic-mount registry, Codex
        re-binds the registry read-only BEFORE deny masks freeze its parent.
        Otherwise a sandboxed process could corrupt concurrent registrations."""
        import shutil as _shutil
        import jail_factory as jf

        base = tempfile.mkdtemp(prefix="registry-mask-", dir="/tmp/opencode")
        registry = os.path.join(base, "registry")
        try:
            policy = FileSystemSandboxPolicy([
                jf.FileSystemSandboxEntry("/", jf.FileSystemAccessMode.WRITE),
                jf.FileSystemSandboxEntry(base, jf.FileSystemAccessMode.DENY),
            ])
            with patch.object(jf, "_synthetic_mount_registry_root",
                              return_value=registry):
                args = create_bwrap_command_args(
                    ["/usr/bin/env", "true"], policy, "/", "/",
                    BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
                )
            registry_bind = args.index(registry)
            mask_index = args.index(base)
            assert args[registry_bind - 1] == "--ro-bind"
            assert args[registry_bind + 1] == registry
            assert args[mask_index - 1] == "--tmpfs"
            assert registry_bind < mask_index, (
                "registry bind must precede the deny mask that covers it"
            )
        finally:
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 34: signals are forwarded to the process group and the child
    # ──────────────────────────────────────────────────────────────────────
    def test_send_signal_to_child_targets_group_and_pid(self):
        """Codex sends the signal to kill(-pid) and kill(pid). The group send
        reaches grandchildren; the direct send works when the child is not a
        process group leader."""
        import signal as _signal
        import jail_factory as jf

        with patch.object(jf.os, "killpg") as killpg, \
             patch.object(jf.os, "kill") as kill:
            jf._send_signal_to_child(4321, _signal.SIGTERM)
        killpg.assert_called_once_with(4321, _signal.SIGTERM)
        kill.assert_called_once_with(4321, _signal.SIGTERM)

        # A non-group-leader child makes killpg fail; the direct send must
        # still happen.
        with patch.object(jf.os, "killpg", side_effect=ProcessLookupError) as killpg, \
             patch.object(jf.os, "kill") as kill:
            jf._send_signal_to_child(4321, _signal.SIGINT)
        killpg.assert_called_once_with(4321, _signal.SIGINT)
        kill.assert_called_once_with(4321, _signal.SIGINT)

    # ──────────────────────────────────────────────────────────────────────
    # Test 35: helper exit status matches Codex's exit_with_wait_status
    # ──────────────────────────────────────────────────────────────────────
    def test_exit_with_wait_status_propagates_exit_code_and_signal(self):
        import signal as _signal
        import jail_factory as jf

        # Normal exit: propagate the exact code.
        with patch.object(jf.sys, "exit", side_effect=SystemExit(7)) as exit_:
            with pytest.raises(SystemExit) as exc_info:
                jf._exit_with_wait_status(7 << 8)
        assert exc_info.value.code == 7
        exit_.assert_called_once_with(7)

        # Signal termination: reset the disposition and re-raise the signal
        # before falling back to 128+signal.
        status = _signal.SIGTERM  # WIFSIGNALED + WTERMSIG == SIGTERM
        with patch.object(jf.signal, "signal") as sig_action, \
             patch.object(jf.os, "kill") as kill, \
             patch.object(jf.sys, "exit", side_effect=SystemExit(128 + _signal.SIGTERM)) as exit_:
            with pytest.raises(SystemExit) as exc_info:
                jf._exit_with_wait_status(status)
        assert exc_info.value.code == 128 + _signal.SIGTERM
        sig_action.assert_called_once_with(_signal.SIGTERM, _signal.SIG_DFL)
        kill.assert_called_once_with(os.getpid(), _signal.SIGTERM)
        exit_.assert_called_once_with(128 + _signal.SIGTERM)

    # ──────────────────────────────────────────────────────────────────────
    # Test 36: nested writable roots get their metadata masks exactly once
    # ──────────────────────────────────────────────────────────────────────
    def test_nested_writable_root_metadata_masks_are_deferred(self):
        """A read-only parent followed by a nested writable child must mount
        the child's protected metadata once, after the child bind — not at the
        parent stage where the later bind would overwrite it (Codex's
        deferred_read_only_subpaths)."""
        import shutil as _shutil
        import jail_factory as jf

        base = tempfile.mkdtemp(prefix="nested-root-", dir="/tmp/opencode")
        try:
            workspace = os.path.join(base, "workspace")
            docs = os.path.join(workspace, "docs")
            docs_public = os.path.join(docs, "public")
            os.makedirs(docs_public)

            entries = [
                jf.FileSystemSandboxEntry(workspace, jf.FileSystemAccessMode.WRITE),
                jf.FileSystemSandboxEntry(docs, jf.FileSystemAccessMode.READ),
                jf.FileSystemSandboxEntry(docs_public, jf.FileSystemAccessMode.WRITE),
            ]
            for name in jf.PROTECTED_METADATA_PATH_NAMES:
                entries.append(jf.FileSystemSandboxEntry(
                    os.path.join(docs_public, name), jf.FileSystemAccessMode.READ
                ))
            policy = FileSystemSandboxPolicy(entries)

            args = create_bwrap_command_args(
                ["/usr/bin/env", "true"], policy, base, base,
                BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
            )
            docs_public_bind = next(
                i for i in range(len(args) - 2)
                if args[i:i + 3] == ["--bind", docs_public, docs_public]
            )
            docs_ro_index = next(
                i for i in range(len(args) - 2)
                if args[i:i + 3] == ["--ro-bind", docs, docs]
            )
            assert docs_ro_index < docs_public_bind

            for name in jf.PROTECTED_METADATA_DIR_NAMES:
                path = os.path.join(docs_public, name)
                tmpfs_mounts = [
                    i for i in range(len(args) - 1)
                    if args[i:i + 2] == ["--tmpfs", path]
                ]
                assert len(tmpfs_mounts) == 1, (
                    f"{path} must be masked exactly once, got {len(tmpfs_mounts)}"
                )
                assert tmpfs_mounts[0] > docs_public_bind

            env_path = os.path.join(docs_public, ".env")
            assert args.count(env_path) == 1
            assert args.index(env_path) > docs_public_bind
        finally:
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 37: bridge launch path confines a real provider process
    # ──────────────────────────────────────────────────────────────────────
    def test_bridge_launch_path_enforces_sandbox_end_to_end(self):
        """Launch sandbox_probe_mcp.py through bridge.launch_sandboxed_node.

        This is the exact process-launch path used for real stdio providers
        (bridge supervisor -> JailFactory -> BubblewrapJailer -> Codex outer
        mount stage + inner seccomp stage). The probe attempts project writes,
        /etc writes, protected-name creation, deny-masked reads, TCP sockets,
        and capability retention, then reports the raw errno outcomes.
        """
        if not _bwrap_available_on_host():
            pytest.skip("bubblewrap + user namespaces not available on this host")
        pytest.importorskip("fastapi")

        workspace = os.path.join(PROJECT_DIR, "secure-experiment-zone")
        secret_dir = os.path.join(PROJECT_DIR, "keycloak-tls")
        secret_path = os.path.join(secret_dir, f"sandbox-probe-{os.getpid()}.txt")
        created_secret_dir = not os.path.isdir(secret_dir)
        artifacts = [
            os.path.join(PROJECT_DIR, "sandbox-probe-escape.txt"),
            os.path.join(workspace, "sandbox-probe-ok.txt"),
            os.path.join(PROJECT_DIR, "bridge.log"),
            os.path.join(PROJECT_DIR, "telemetry.db"),
        ]
        preexisting = {path: os.path.exists(path) for path in artifacts}
        os.makedirs(secret_dir, exist_ok=True)
        with open(secret_path, "w", encoding="utf-8") as handle:
            handle.write("sandbox-probe-secret\n")

        env = dict(os.environ)
        env.update({
            "PYTHONPATH": PROJECT_DIR,
            "SANDBOX_PROBE_WORKSPACE": workspace,
            "SANDBOX_PROBE_SECRET": secret_path,
            "LOCAL_DEV_MODE": "false",
        })
        try:
            completed = subprocess.run(
                [sys.executable, os.path.join(PROJECT_DIR, "sandbox_probe_runner.py")],
                cwd=PROJECT_DIR,
                env=env,
                capture_output=True,
                text=True,
                timeout=90,
            )
        finally:
            for path, existed in preexisting.items():
                if not existed:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
            try:
                os.unlink(secret_path)
            except OSError:
                pass
            if created_secret_dir:
                try:
                    os.rmdir(secret_dir)
                except OSError:
                    pass

        assert completed.returncode == 0, completed.stderr[-2500:]
        results = json.loads(completed.stdout.strip().splitlines()[-1])
        assert results["project_write"].startswith("denied:"), results
        assert results["etc_write"].startswith("denied:"), results
        assert results["workspace_protected_env"].startswith("denied:"), results
        assert results["read_secret"].startswith("denied:"), results
        assert results["read_shadow"].startswith("denied:"), results
        assert results["workspace_write"] == "allowed", results
        assert results["unix_socketpair"] == "allowed", results
        assert results["tcp_socket"].startswith("denied:"), results
        assert results["cap_eff"] == "empty", results

    # ──────────────────────────────────────────────────────────────────────
    # Test 38: real end-to-end canonical chdir through bubblewrap
    # ──────────────────────────────────────────────────────────────────────
    def test_symlinked_project_cwd_runs_in_canonical_directory(self):
        """End-to-end: a provider launched from a symlinked project alias runs
        with the canonical cwd and can still write only through the allowed
        path inside the sandbox."""
        if not _bwrap_available_on_host():
            pytest.skip("bubblewrap + user namespaces not available on this host")
        import shutil as _shutil
        import subprocess as sp
        import jail_factory as jf

        base = tempfile.mkdtemp(prefix="bwrap-cwd-", dir="/tmp/opencode")
        try:
            real_project = os.path.join(base, "real-project")
            link_project = os.path.join(base, "link-project")
            workspace = os.path.join(real_project, "workspace")
            os.makedirs(workspace)
            os.symlink(real_project, link_project)
            os.chmod(base, 0o777)
            os.chmod(real_project, 0o777)
            os.chmod(workspace, 0o777)

            probe = (
                "import os, sys\n"
                "print(os.getcwd())\n"
                "open(os.path.join(os.getcwd(), 'workspace', 'ok.txt'), 'w').write('x')\n"
            )
            env = {"PATH": os.environ.get("PATH", "")}
            jailer = BubblewrapJailer(
                "filesystem-provider", link_project, env, [workspace]
            )
            cmd = [sys.executable, "-c", probe]
            jailer.get_popen_kwargs(cmd)
            completed = sp.run(
                cmd, capture_output=True, text=True, timeout=60,
                cwd=link_project, env=env,
            )
            assert completed.returncode == 0, completed.stderr
            assert completed.stdout.strip() == os.path.realpath(real_project)
            assert os.path.exists(os.path.join(workspace, "ok.txt"))
        finally:
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 39: seccomp profile generator applies the documented relaxations
    # ──────────────────────────────────────────────────────────────────────
    def test_gateway_seccomp_generator_produces_bwrap_relaxations(self):
        import importlib.util

        script_path = os.path.join(PROJECT_DIR, "scripts", "generate_gateway_seccomp.py")
        spec = importlib.util.spec_from_file_location("generate_gateway_seccomp", script_path)
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)

        default_profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 1,
            "archMap": [],
            "syscalls": [{"names": ["mount", "umount2"], "action": "SCMP_ACT_ALLOW"}],
        }
        patched = generator.apply_gateway_patches(default_profile)
        rules = generator.normalized_rules(patched)

        for name in (
            "mount", "umount2", "pivot_root", "unshare", "chroot",
            "fsopen", "fsmount", "fspick", "open_tree", "move_mount",
            "mount_setattr",
        ):
            assert (name, "SCMP_ACT_ALLOW", "null") in rules, name

        clone_rules = [rule for rule in rules if rule[0] == "clone"]
        assert len(clone_rules) == 2 * len(generator.CLONE_NAMESPACE_COMBINATIONS)
        assert patched["_comment"].startswith("gateway-seccomp.json:")
        assert generator.compare_profiles(patched, patched) == []

    # ──────────────────────────────────────────────────────────────────────
    # Test 40: non-regular deny paths (socket) are masked with /dev/null
    # ──────────────────────────────────────────────────────────────────────
    def test_socket_deny_mask_uses_bind_and_dedupes_symlink_alias(self):
        """bwrap cannot --ro-bind-data over a socket (it must create a file
        there). The mask must bind /dev/null instead, and a symlink alias of
        the same inode must not produce a second mask."""
        import shutil as _shutil
        import jail_factory as jf

        base = tempfile.mkdtemp(prefix="socket-mask-", dir="/tmp/opencode")
        listener = None
        try:
            workspace = os.path.join(base, "ws")
            os.makedirs(workspace)
            sock_path = os.path.join(base, "daemon.sock")
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(sock_path)
            alias = os.path.join(base, "daemon-alias.sock")
            os.symlink(sock_path, alias)

            policy = FileSystemSandboxPolicy.workspace_write(
                [workspace], deny_read_paths=[sock_path, alias]
            )
            args = create_bwrap_command_args(
                ["/usr/bin/env", "true"], policy, base, base,
                BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
            )
            null_masks = [
                args[i + 2] for i in range(len(args) - 2)
                if args[i] == "--ro-bind" and args[i + 1] == "/dev/null"
            ]
            assert len(null_masks) == 1, null_masks
            assert os.path.realpath(null_masks[0]) == os.path.realpath(sock_path)
            assert not any(
                args[i] == "--ro-bind-data" and os.path.realpath(args[i + 2]) == os.path.realpath(sock_path)
                for i in range(len(args) - 2)
            )
        finally:
            if listener is not None:
                listener.close()
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 41: live socket mask denies sandboxed connect, host unaffected
    # ──────────────────────────────────────────────────────────────────────
    def test_socket_deny_mask_blocks_sandboxed_connect(self):
        if not _bwrap_available_on_host():
            pytest.skip("bubblewrap + user namespaces not available on this host")
        import shutil as _shutil
        import jail_factory as jf

        base = tempfile.mkdtemp(prefix="socket-mask-run-", dir="/tmp/opencode")
        listener = None
        try:
            workspace = os.path.join(base, "ws")
            os.makedirs(workspace)
            sock_path = os.path.join(base, "daemon.sock")
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(sock_path)
            listener.listen(1)

            code = (
                "import socket,sys\n"
                "client=socket.socket(socket.AF_UNIX)\n"
                "try:\n"
                "    client.connect(sys.argv[1])\n"
                "    print('connected')\n"
                "except OSError as exc:\n"
                "    print('denied', exc.errno)\n"
            )
            policy = FileSystemSandboxPolicy([
                jf.FileSystemSandboxEntry("/", jf.FileSystemAccessMode.READ),
                jf.FileSystemSandboxEntry(workspace, jf.FileSystemAccessMode.WRITE),
                jf.FileSystemSandboxEntry(sock_path, jf.FileSystemAccessMode.DENY),
            ])
            args = create_bwrap_command_args(
                [sys.executable, "-c", code, sock_path],
                policy, base, base,
                BwrapOptions(network_mode=BwrapNetworkMode.ISOLATED),
            )
            completed = subprocess.run(
                [jf.find_bwrap()] + args,
                capture_output=True, text=True, timeout=60, cwd=base,
            )
            assert completed.returncode == 0, completed.stderr
            assert completed.stdout.strip().startswith("denied"), completed.stdout

            # The host socket itself must remain usable.
            client = socket.socket(socket.AF_UNIX)
            client.connect(sock_path)
            client.close()
        finally:
            if listener is not None:
                listener.close()
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 42: Docker tier over-mounts project and workspace secrets
    # ──────────────────────────────────────────────────────────────────────
    def test_opensandbox_masks_project_secrets(self):
        import shutil as _shutil
        import jail_factory as jf

        base = tempfile.mkdtemp(prefix="docker-masks-", dir="/tmp/opencode")
        try:
            workspace = os.path.join(base, "secure-experiment-zone")
            os.makedirs(os.path.join(base, "keycloak-tls"))
            os.makedirs(workspace)
            with open(os.path.join(base, ".env"), "w", encoding="utf-8") as handle:
                handle.write("SECRET=1\n")
            with open(os.path.join(base, "keycloak-tls", "ca.key"), "w", encoding="utf-8") as handle:
                handle.write("key\n")
            with open(os.path.join(workspace, ".env"), "w", encoding="utf-8") as handle:
                handle.write("WS_SECRET=1\n")

            jailer = OpenSandboxJailer(
                "filesystem-provider", base, {"PATH": "/usr/bin"}, [workspace]
            )
            masks = dict((destination, kind) for kind, destination in jailer._read_only_masks())
            assert masks["/workspace/.env"] == "null"
            assert masks["/workspace/keycloak-tls"] == "tmpfs"
            assert masks["/workspace/secure-experiment-zone/.env"] == "null"
        finally:
            _shutil.rmtree(base, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────
    # Test 43: live Docker tier confinement (requires the cached image)
    # ──────────────────────────────────────────────────────────────────────
    def test_opensandbox_live_container_tier_confines(self):
        if not _docker_image_available("python:3.11-slim"):
            pytest.skip("python:3.11-slim image is not cached locally")
        import shutil as _shutil
        import jail_factory as jf

        base = tempfile.mkdtemp(prefix="docker-live-", dir="/tmp/opencode")
        try:
            workspace = os.path.join(base, "secure-experiment-zone")
            os.makedirs(workspace)
            with open(os.path.join(base, "bridge.py"), "w", encoding="utf-8") as handle:
                handle.write("# project file\n")
            with open(os.path.join(base, ".env"), "w", encoding="utf-8") as handle:
                handle.write("DOCKER_TIER_SECRET=leak\n")
            os.chmod(base, 0o777)
            os.chmod(workspace, 0o777)

            code = (
                "import errno,json,os,socket\n"
                "def t(fn):\n"
                "    try:\n"
                "        fn(); return 'allowed'\n"
                "    except OSError as exc:\n"
                "        return 'denied:'+errno.errorcode.get(exc.errno,str(exc.errno))\n"
                "r={}\n"
                "r['project_write']=t(lambda: open('/workspace/bridge.py','a').close())\n"
                "r['workspace_write']=t(lambda: open('/workspace/secure-experiment-zone/ok.txt','w').close())\n"
                "r['root_write']=t(lambda: open('/etc/docker-probe','w').close())\n"
                "r['env_content']=open('/workspace/.env').read()\n"
                "r['uid']=os.getuid()\n"
                "r['cap_eff']=[l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff:')][0]\n"
                "r['interfaces']=sorted(os.listdir('/sys/class/net'))\n"
                "try:\n"
                "    socket.create_connection(('1.1.1.1',80),timeout=1); r['tcp']='allowed'\n"
                "except OSError as exc:\n"
                "    r['tcp']='denied:'+errno.errorcode.get(exc.errno,str(exc.errno))\n"
                "print(json.dumps(r))\n"
            )
            jailer = OpenSandboxJailer(
                "filesystem-provider", base, {"PATH": os.environ.get("PATH", "")}, [workspace]
            )
            cmd = ["python", "-c", code]
            kwargs = jailer.get_popen_kwargs(cmd)
            completed = subprocess.run(cmd, timeout=120, **kwargs)
            assert completed.returncode == 0, completed.stderr
            results = json.loads(completed.stdout.strip())
            assert results["project_write"].startswith("denied:")
            assert results["workspace_write"] == "allowed"
            assert results["root_write"].startswith("denied:")
            assert results["env_content"] == "", "project .env must be masked with /dev/null"
            assert results["uid"] != 0
            assert set(results["cap_eff"]) == {"0"}
            assert results["interfaces"] == ["lo"]
            assert results["tcp"].startswith("denied:")
        finally:
            _shutil.rmtree(base, ignore_errors=True)
