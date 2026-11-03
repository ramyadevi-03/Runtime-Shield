"""
jail_factory.py — Pluggable process jailers and sandbox runtime factory for Runtime Shield.

Provides:
  - BaseJailer: baseline process execution (NO isolation).
  - LandlockJailer: Linux Landlock kernel filesystem ruleset.
  - NSJailer: Linux nsjail namespace isolation.
  - WindowsJailer: Windows Job Object + restricted security token (win32job).
  - OpenSandboxJailer: Docker container + runsc (gVisor) virtualization.
  - JailFactory: dynamic factory selecting the appropriate jailer per platform and policy.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import logging

log = logging.getLogger(__name__)

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    import landlock
except ImportError:
    landlock = None


class BaseJailer:
    """Baseline process launcher with no isolation (used for internal/safe workloads)."""

    def __init__(self, provider_name: str, cwd: str, env: dict, allowed_paths: list | None):
        self.provider_name = provider_name
        self.cwd = cwd
        self.env = env
        self.allowed_paths = allowed_paths

    def get_popen_kwargs(self, cmd: list) -> dict:
        return {
            "cwd": self.cwd,
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "encoding": "utf-8",
            "bufsize": 1,
            "env": self.env,
        }


class LandlockJailer(BaseJailer):
    """Linux Landlock kernel ruleset jailer."""

    def get_popen_kwargs(self, cmd: list) -> dict:
        kwargs = super().get_popen_kwargs(cmd)
        if sys.platform.startswith("linux") and landlock:
            def landlock_preexec():
                try:
                    rs = landlock.Ruleset()
                    rs.allow(PROJECT_DIR)
                    if self.allowed_paths:
                        for p in self.allowed_paths:
                            if os.path.exists(p):
                                rs.allow(p)
                    rs.apply()
                except Exception as e:
                    sys.stderr.write(f"[SANDBOX ERROR] Failed to apply Landlock: {e}\n")
                    sys.exit(1)
            kwargs["preexec_fn"] = landlock_preexec
            log.info("🔒 Sandboxing [%s]: Landlock kernel ruleset initialized", self.provider_name)
        return kwargs


class NSJailer(BaseJailer):
    """Linux NSJail namespace and chroot jailer."""

    def get_popen_kwargs(self, cmd: list) -> dict:
        nsjail_bin = shutil.which("nsjail")
        if not nsjail_bin:
            return super().get_popen_kwargs(cmd)

        new_cmd = [
            nsjail_bin, "-Mo",
            "--chroot", "/",
            "-R", "/usr", "-R", "/lib", "-R", "/lib64", "-R", "/bin",
            "-B", self.cwd,
            "--",
        ] + cmd
        cmd[:] = new_cmd
        log.info("🏛️ Sandboxing [%s]: NSJail namespace isolation active", self.provider_name)
        return super().get_popen_kwargs(cmd)


class WindowsJailer(BaseJailer):
    """Windows Job Object + Restricted Security Token jailer."""

    def get_popen_kwargs(self, cmd: list) -> dict:
        kwargs = super().get_popen_kwargs(cmd)
        if sys.platform == "win32":
            sandbox_script = os.path.join(PROJECT_DIR, "windows_sandbox.py")
            if os.path.exists(sandbox_script):
                new_cmd = [sys.executable, sandbox_script, "--provider", self.provider_name, "--"] + cmd
                cmd[:] = new_cmd
                log.info("🪟 Sandboxing [%s]: Windows Restricted Process Group initialized (win32job + restricted token)", self.provider_name)
            else:
                # FAIL-CLOSED: Refuse to run without sandboxing
                msg = f"[SANDBOX FAIL-CLOSED] Windows sandbox script not found at {sandbox_script}. Refusing to run '{self.provider_name}' unsandboxed on host."
                log.error("🚫 %s", msg)
                raise RuntimeError(msg)
        return kwargs


class OpenSandboxJailer(BaseJailer):
    """OpenSandbox: A cross-platform gVisor-based container jailer.

    Runs commands in an isolated Docker container with the runsc (gVisor) runtime,
    hiding host OS files and isolating the filesystem.
    """

    def get_popen_kwargs(self, cmd: list) -> dict:
        docker_bin = shutil.which("docker")
        if not docker_bin:
            # FAIL-CLOSED: Do not silently execute on host
            msg = f"[OpenSandbox] docker executable not found. Cannot launch container sandbox for '{self.provider_name}'."
            log.error("🚫 %s", msg)
            raise RuntimeError(msg)

        use_gvisor = os.getenv("OPENSANDBOX_USE_GVISOR", "true").lower() == "true"
        require_gvisor = os.getenv("OPENSANDBOX_REQUIRE_GVISOR", "false").lower() == "true"
        container_workspace = "/workspace"

        # Verify Docker daemon is reachable before attempting container execution
        try:
            daemon_check = subprocess.run([docker_bin, "info"], capture_output=True, text=True, timeout=4)
            if daemon_check.returncode != 0:
                err_detail = (daemon_check.stderr or "").strip()[:200]
                msg = f"[OpenSandbox] Docker daemon is not accessible: {err_detail}. Container launch aborted."
                log.error("🚫 %s", msg)
                raise RuntimeError(msg)
        except subprocess.TimeoutExpired:
            msg = "[OpenSandbox] Docker daemon check timed out after 4s. Container launch aborted."
            log.error("🚫 %s", msg)
            raise RuntimeError(msg)

        volumes = [f"{self.cwd}:{container_workspace}"]
        if self.allowed_paths:
            for idx, path in enumerate(self.allowed_paths):
                abs_path = os.path.abspath(path)
                if os.path.exists(abs_path):
                    if not abs_path.startswith(self.cwd):
                        # Mount external paths read-only
                        volumes.append(f"{abs_path}:/allowed_path_{idx}:ro")

        docker_cmd = [
            docker_bin, "run", "--rm",
            "-i",  # Keep stdin open
        ]

        # Check if gVisor (runsc) is available in docker info
        if use_gvisor or require_gvisor:
            has_runsc = False
            combined = (daemon_check.stdout + (daemon_check.stderr or "")).lower()
            if "runsc" in combined or "gvisor" in combined:
                has_runsc = True

            if has_runsc:
                docker_cmd.extend(["--runtime", "runsc"])
                log.info("🛡️ [OpenSandbox] Using gVisor (runsc) runtime for kernel-level virtualization.")
            elif require_gvisor:
                # FAIL-CLOSED: gVisor was explicitly required but is not available
                msg = "[OpenSandbox] gVisor (runsc) runtime is required by OPENSANDBOX_REQUIRE_GVISOR but not configured in Docker. Aborting."
                log.error("🚫 %s", msg)
                raise RuntimeError(msg)
            else:
                log.warning("⚠️ [OpenSandbox] gVisor (runsc) runtime not configured in Docker. Falling back to standard container sandbox.")

        for vol in volumes:
            docker_cmd.extend(["-v", vol])

        docker_cmd.extend(["-w", container_workspace])

        # Pass environment variables
        for k, v in self.env.items():
            if v is not None:
                docker_cmd.extend(["-e", f"{k}={v}"])

        # Choose node or python image
        if cmd and "node" in cmd[0]:
            image = os.getenv("OPENSANDBOX_NODE_IMAGE", "node:20-slim")
        else:
            image = os.getenv("OPENSANDBOX_PYTHON_IMAGE", "python:3.11-slim")

        docker_cmd.append(image)

        # Map command paths
        new_cmd_parts = []
        for part in cmd:
            if part.startswith(self.cwd):
                rel = os.path.relpath(part, self.cwd)
                rel_forward = rel.replace("\\", "/")
                new_cmd_parts.append(f"./{rel_forward}")
            else:
                new_cmd_parts.append(part)

        docker_cmd.extend(new_cmd_parts)
        cmd[:] = docker_cmd

        log.info("🐳 [OpenSandbox] Containerized isolation active: running via Docker image '%s'", image)
        return super().get_popen_kwargs(cmd)


class JailFactory:
    """Dynamic factory for sandbox jailers."""

    @staticmethod
    def get_jailer(provider_name: str, cwd: str, env: dict, allowed_paths: list | None) -> BaseJailer:
        # When running inside a container, internal MCP servers run directly
        if os.path.exists("/.dockerenv") or os.getenv("DOCKER_CONTAINER", "false").lower() == "true":
            return BaseJailer(provider_name, cwd, env, allowed_paths)
        # Docker Desktop's Linux containers cannot bind-mount Windows paths reliably
        # for stdio MCP providers; use the restricted Windows process jail instead.
        if sys.platform == "win32":
            return WindowsJailer(provider_name, cwd, env, allowed_paths)

        # 1. OpenSandbox is the primary cross-platform isolated runtime on host machines
        if shutil.which("docker"):
            return OpenSandboxJailer(provider_name, cwd, env, allowed_paths)

        # 2. Linux native fallbacks
        is_linux = sys.platform.startswith("linux")
        if is_linux:
            if shutil.which("nsjail"):
                return NSJailer(provider_name, cwd, env, allowed_paths)
            if landlock:
                return LandlockJailer(provider_name, cwd, env, allowed_paths)

        return BaseJailer(provider_name, cwd, env, allowed_paths)
