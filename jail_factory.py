"""
jail_factory.py — Pluggable process jailers and sandbox runtime factory for Runtime Shield.

Jailer tiers (selection order in JailFactory.get_jailer, strongest first):

  OpenSandboxJailer  Docker container, optionally on the runsc (gVisor) runtime.
  BubblewrapJailer   Linux bubblewrap namespaces + seccomp syscall filter,
                     launched through a two-stage pipeline modelled on the
                     OpenAI Codex Linux sandbox (codex-rs/linux-sandbox):
                     the outer stage builds the mount/namespace view with
                     bwrap, the inner stage applies PR_SET_NO_NEW_PRIVS plus
                     the seccomp filter and execs the provider command.
  NSJailer           Linux nsjail namespace isolation.
  LandlockJailer     Linux Landlock kernel filesystem ruleset.
  WindowsJailer      Windows Job Object + restricted security token (win32job).
  BaseJailer         No isolation: only for the container boundary (the bridge
                     itself runs in a container) or explicitly trusted workloads.

Security invariants enforced by every filesystem-isolating tier:

  * Writable roots are the caller's allowed_paths ONLY. The process working
    directory (cwd) is mounted READ-ONLY, so a compromised provider cannot
    rewrite the gateway's own code (bridge.py), its policy (rules/,
    mcp-firewall.yaml) or its configuration (.env).
  * Protected workspace metadata names (.git/.ssh/.agents/.aws/.env) directly
    under a writable root stay read-only, mirroring Codex's protected metadata
    behaviour. Paths that do not exist yet are masked (a read-only empty
    mount is placed over them) so a sandboxed process cannot create .env or
    .git/hooks, and mounts that would cross a writable symlink fail closed.
  * Secret material is hidden from reads: the project .env, generated TLS
    material (keycloak-tls/, spire/certs/), the user's .ssh/.aws, the Docker
    daemon socket and (when SPIFFE is disabled) the SPIRE agent socket are
    mounted unreadable. The SPIRE agent socket stays visible when SPIFFE is
    enabled because providers use it for workload attestation.
  * Network access follows the in-code per-provider policy table
    (PROVIDER_SANDBOX_POLICIES). There are deliberately NO environment
    variables that disable sandboxing or grant network access globally.
  * Fail-closed: a host with no operational jailer raises RuntimeError
    instead of silently executing on the host.

Two-stage Linux pipeline (helper mode):

  python jail_factory.py --helper
      --sandbox-policy-cwd <path>     where policy paths resolve
      --command-cwd <path>            working directory for the command
      --permission-profile <json>     FileSystem/Network sandbox policy
      [--bwrap <path>]                controller-resolved bubblewrap binary
      [--apply-seccomp-then-exec]     inner stage: seccomp + exec
      [--no-proc]                     skip the /proc mount
      [--inherit-pid-namespace]       keep the caller's PID namespace
      -- <command...>

  python jail_factory.py --self-test   behavioral sandbox verification
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading

log = logging.getLogger(__name__)

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
IS_LINUX = sys.platform.startswith("linux")

try:
    import landlock
except ImportError:
    landlock = None


# ─────────────────────────────────────────────────────────────────────────────
# Per-provider sandbox policy (in code — no environment kill switches)
# ─────────────────────────────────────────────────────────────────────────────

# Providers that legitimately need outbound network access inside the sandbox.
#
#   keycloak-provider      talks to the Keycloak Admin API over HTTP(S)
#                          (KEYCLOAK_URL / KEYCLOAK_TOKEN_URL).
#   filesystem-provider    local filesystem tools only.
#   database-provider      embedded sqlite (transaction_db), no sockets.
#   scanner-provider       local dependency/secret scanning, no sockets.
#   system-monitor-provider local process/metrics inspection, no sockets.
#
# Every other (unknown) provider defaults to network=False. Granting network
# requires editing this table in code and passing code review — an operator
# cannot widen it with an environment variable.
class ProviderSandboxPolicy:
    """Sandbox policy applied to a named MCP provider."""

    __slots__ = ("network",)

    def __init__(self, network: bool = False):
        self.network = bool(network)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ProviderSandboxPolicy(network={self.network})"


PROVIDER_SANDBOX_POLICIES: dict = {
    "keycloak-provider": ProviderSandboxPolicy(network=True),
    "filesystem-provider": ProviderSandboxPolicy(network=False),
    "database-provider": ProviderSandboxPolicy(network=False),
    "scanner-provider": ProviderSandboxPolicy(network=False),
    "system-monitor-provider": ProviderSandboxPolicy(network=False),
}

_DEFAULT_PROVIDER_POLICY = ProviderSandboxPolicy(network=False)


def provider_sandbox_policy(provider_name: str) -> ProviderSandboxPolicy:
    """Policy for a provider; unknown providers fail closed (no network)."""
    return PROVIDER_SANDBOX_POLICIES.get(provider_name, _DEFAULT_PROVIDER_POLICY)


def providers_requiring_network() -> list:
    """Report which providers are granted network access and why (audit aid)."""
    return sorted(name for name, p in PROVIDER_SANDBOX_POLICIES.items() if p.network)


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


# Read-only access set for the Landlock tier (pylandlock granular rules).
try:
    _LANDLOCK_READ_ONLY = (
        landlock.FSAccess.READ_FILE
        | landlock.FSAccess.READ_DIR
        | landlock.FSAccess.EXECUTE
    )
except AttributeError:  # pragma: no cover - very old pylandlock
    _LANDLOCK_READ_ONLY = None


def apply_landlock_rules(cwd: str, allowed_paths: list | None) -> None:
    """Apply a Landlock ruleset to the current thread.

    Read-only everywhere (including the working directory), full access to
    /dev/null, and WRITE access only to the allowed paths — never to the
    working directory itself.
    """
    if _LANDLOCK_READ_ONLY is None:
        raise RuntimeError(
            "installed `landlock` package does not expose granular access rules; "
            "refusing to apply a weaker ruleset"
        )
    rs = landlock.Ruleset()
    rs.allow("/", rules=_LANDLOCK_READ_ONLY)
    rs.allow("/dev/null")
    for path in allowed_paths or []:
        if os.path.exists(path):
            rs.allow(path)
    rs.apply()


class LandlockJailer(BaseJailer):
    """Linux Landlock kernel ruleset jailer."""

    def get_popen_kwargs(self, cmd: list) -> dict:
        kwargs = super().get_popen_kwargs(cmd)
        if IS_LINUX and landlock:
            def landlock_preexec():
                try:
                    apply_landlock_rules(self.cwd, self.allowed_paths)
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
            # FAIL-CLOSED: nsjail may disappear between factory selection and
            # launch (package removal, PATH change). Never silently fall back
            # to an unsandboxed BaseJailer process.
            msg = (
                f"[SANDBOX FAIL-CLOSED] nsjail executable not found on PATH. "
                f"Refusing to run '{self.provider_name}' unsandboxed on host."
            )
            log.error("🚫 %s", msg)
            raise RuntimeError(msg)

        new_cmd = [
            nsjail_bin, "-Mo",
            "--chroot", "/",
            "-R", "/usr", "-R", "/lib", "-R", "/lib64", "-R", "/bin",
            "-R", "/sbin", "-R", "/etc",
            "-R", self.cwd,
        ]
        # Writable roots: allowed_paths only — the working directory stays
        # mounted read-only (-R) so a provider cannot rewrite the gateway.
        if self.allowed_paths:
            for path in self.allowed_paths:
                if os.path.exists(path):
                    new_cmd += ["-B", path]
        new_cmd += ["--"]
        new_cmd.extend(cmd)
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
    """OpenSandbox: a hardened Docker container jailer (optional gVisor).

    The container preserves the same core invariant as every other
    filesystem-isolating tier: the project working directory is mounted
    READ-ONLY at /workspace, and only the caller's allowed_paths are writable.
    The container root is read-only, all capabilities are dropped, privilege
    escalation is disabled, and the process runs as a non-root uid.
    """

    CONTAINER_WORKSPACE = "/workspace"
    MEMORY_LIMIT = "1g"
    CPU_LIMIT = "1.0"
    PIDS_LIMIT = "128"
    TMPFS_SIZE = "64m"

    def __init__(self, provider_name: str, cwd: str, env: dict, allowed_paths: list | None):
        super().__init__(provider_name, cwd, env, allowed_paths)
        self.policy = provider_sandbox_policy(provider_name)

    def _container_user(self) -> str:
        uid, gid = os.geteuid(), os.getegid()
        if uid == 0:
            # Never run the sandboxed provider as container root, even when
            # the gateway itself was started as root on a host.
            uid = gid = 65534
        return f"{uid}:{gid}"

    def _volumes(self) -> list:
        cwd_abs = os.path.abspath(self.cwd)
        # Project: READ-ONLY, so a compromised provider cannot rewrite
        # bridge.py, rules/, mcp-firewall.yaml or .env.
        volumes = [f"{cwd_abs}:{self.CONTAINER_WORKSPACE}:ro"]
        seen = set()
        for idx, path in enumerate(self.allowed_paths or []):
            abs_path = os.path.abspath(path)
            if abs_path in seen or not os.path.exists(abs_path):
                continue
            seen.add(abs_path)
            if abs_path == cwd_abs:
                log.warning(
                    "⚠️ [OpenSandbox] ignoring allowed_path == cwd (%s): the "
                    "project directory must stay read-only",
                    abs_path,
                )
                continue
            if _is_within(cwd_abs, abs_path):
                # Mounting an ancestor writable would make the project
                # writable again through the parent bind.
                raise RuntimeError(
                    f"[OpenSandbox] allowed_path {abs_path} contains the "
                    f"project directory {cwd_abs}; refusing to make the "
                    f"project writable"
                )
            if _is_within(abs_path, cwd_abs):
                # Re-open exactly this subtree as writable over the read-only
                # /workspace bind (the bind target must stay inside it).
                rel = os.path.relpath(abs_path, cwd_abs).replace("\\", "/")
                volumes.append(f"{abs_path}:{self.CONTAINER_WORKSPACE}/{rel}:rw")
            else:
                # Keep the host path so absolute command arguments still work.
                volumes.append(f"{abs_path}:{abs_path}:rw")
        return volumes

    def _read_only_masks(self) -> list:
        """Mask host secrets that the project bind would otherwise expose.

        The project is bind-mounted read-only, so a provider can still READ
        .env, keycloak TLS material and SPIRE keys. Bubblewrap masks these in
        every other tier; mirror that here with an over-mounted /dev/null file
        or an empty read-only tmpfs directory. Only existing paths are masked:
        Docker creates the destination of a missing bind mount on the host,
        which must not pollute the project or workspace.
        """
        cwd_abs = os.path.abspath(self.cwd)
        masks: dict[str, str] = {}

        def add(host_path: str, destination: str) -> None:
            if destination in masks:
                return
            if not (os.path.exists(host_path) or os.path.islink(host_path)):
                return
            if os.path.isdir(host_path) and not os.path.islink(host_path):
                masks[destination] = "tmpfs"
            else:
                masks[destination] = "null"

        for path in runtime_shield_deny_read_paths(cwd_abs, self.env):
            if _is_within(path, cwd_abs):
                rel = os.path.relpath(path, cwd_abs).replace("\\", "/")
                add(path, f"{self.CONTAINER_WORKSPACE}/{rel}")

        for allowed in self.allowed_paths or []:
            abs_allowed = os.path.abspath(allowed)
            if abs_allowed == cwd_abs or not os.path.isdir(abs_allowed):
                continue
            for name in PROTECTED_METADATA_PATH_NAMES:
                path = os.path.join(abs_allowed, name)
                if _is_within(abs_allowed, cwd_abs):
                    rel = os.path.relpath(path, cwd_abs).replace("\\", "/")
                    destination = f"{self.CONTAINER_WORKSPACE}/{rel}"
                else:
                    destination = path
                add(path, destination)

        return [(kind, destination) for destination, kind in masks.items()]

    def get_popen_kwargs(self, cmd: list) -> dict:
        docker_bin = shutil.which("docker")
        if not docker_bin:
            # FAIL-CLOSED: Do not silently execute on host
            msg = f"[OpenSandbox] docker executable not found. Cannot launch container sandbox for '{self.provider_name}'."
            log.error("🚫 %s", msg)
            raise RuntimeError(msg)

        use_gvisor = os.getenv("OPENSANDBOX_USE_GVISOR", "true").lower() == "true"
        require_gvisor = os.getenv("OPENSANDBOX_REQUIRE_GVISOR", "false").lower() == "true"
        container_workspace = self.CONTAINER_WORKSPACE

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

        volumes = self._volumes()

        docker_cmd = [
            docker_bin, "run", "--rm",
            "-i",  # Keep stdin open
            "--init",
            # Root filesystem is immutable; only explicit binds are writable.
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--user", self._container_user(),
            "--pids-limit", self.PIDS_LIMIT,
            "--memory", self.MEMORY_LIMIT,
            "--cpus", self.CPU_LIMIT,
            "--tmpfs", f"/tmp:rw,nosuid,nodev,size={self.TMPFS_SIZE}",
            "--tmpfs", "/run:rw,nosuid,nodev,size=1m",
        ]

        # Per-provider network policy: providers without an explicit grant get
        # no network namespace access at all. Network-granted providers keep
        # Docker's default bridge (never --network host).
        if not self.policy.network:
            docker_cmd.extend(["--network", "none"])

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
        for kind, destination in self._read_only_masks():
            if kind == "null":
                docker_cmd.extend(["-v", f"/dev/null:{destination}:ro"])
            else:
                # Empty, read-only tmpfs: the host directory contents are hidden.
                docker_cmd.extend(["--tmpfs", f"{destination}:ro,size=1m"])

        docker_cmd.extend(["-w", container_workspace])

        # Sandbox-local writable scratch space for the runtime user.
        docker_cmd.extend([
            "-e", "HOME=/tmp",
            "-e", "TMPDIR=/tmp",
            "-e", "XDG_CACHE_HOME=/tmp/.cache",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
        ])
        # Pass environment variables (provider env may intentionally override
        # the defaults above).
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

        log.info("🐳 [OpenSandbox] Hardened container isolation active: image '%s', read-only root/cwd, writable=%s, network=%s",
                 image, self.allowed_paths or [], "on" if self.policy.network else "off")
        return super().get_popen_kwargs(cmd)


# ═════════════════════════════════════════════════════════════════════════════
# Linux bubblewrap + seccomp backend (two-stage pipeline)
#
# Ported from OpenAI Codex (codex-rs/linux-sandbox + codex-rs/sandboxing),
# adapted to Runtime Shield's security posture: the working directory is
# READ-ONLY and only allowed_paths are writable.
# ═════════════════════════════════════════════════════════════════════════════

# Top-level metadata paths that stay read-only even under writable roots.
# Codex protects .git/.agents/.codex/.aws (codex-rs/protocol/src/permissions.rs,
# PROTECTED_METADATA_PATH_NAMES); Runtime Shield swaps .codex for .env (its
# secrets file) and adds .ssh. File-typed names are masked with a read-only
# empty file, directory-typed names with a read-only empty directory.
PROTECTED_METADATA_FILE_NAMES = (".env",)
PROTECTED_METADATA_DIR_NAMES = (".git", ".ssh", ".agents", ".aws")
PROTECTED_METADATA_PATH_NAMES = PROTECTED_METADATA_FILE_NAMES + PROTECTED_METADATA_DIR_NAMES


def runtime_shield_deny_read_paths(cwd: str, env: dict | None = None) -> list:
    """Paths hidden from sandboxed reads for every provider (Runtime Shield
    addition — in Codex, unreadable entries come from the user's policy JSON).

    The sandbox root is mounted read-only, so without these masks a
    compromised provider could READ the gateway's secrets. Masks are no-ops
    for paths that do not exist outside writable roots (they could not be
    created there anyway — the root is read-only).

    The SPIRE agent socket is masked only when SPIFFE is disabled: with
    SPIFFE enabled, providers use it for workload attestation.

    Scope/limits: masks are concrete paths only (no glob patterns). A secret
    stored anywhere else on the read-only root is therefore still readable
    (though not writable). Keep credentials in one of the masked locations
    below, or add the path here in code and pass code review. This list is
    intentionally built in code and cannot be widened/narrowed by an
    environment variable.
    """
    env = env if env is not None else os.environ
    paths = [
        os.path.join(cwd, ".env"),
        os.path.join(cwd, ".env.local"),
        os.path.join(cwd, ".env.production"),
        os.path.join(cwd, ".env.development"),
        os.path.join(cwd, ".env.test"),
        os.path.join(cwd, "keycloak-tls"),    # generated Keycloak TLS material
        os.path.join(cwd, "spire", "certs"),  # CA/workload keys (generate_certs.py)
        "/var/run/docker.sock",
        "/run/docker.sock",
        # Container/daemon secret mounts and host account databases.
        "/run/secrets",
        "/var/run/secrets",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
    ]
    home = env.get("HOME") or os.environ.get("HOME") or os.path.expanduser("~")
    if home and os.path.isabs(home) and home != os.sep:
        paths += [
            os.path.join(home, name) for name in (
                ".ssh",
                ".aws",
                ".gnupg",
                ".netrc",
                ".git-credentials",
                ".docker",
                ".kube",
                ".npmrc",
                ".pypirc",
                os.path.join(".config", "gcloud"),
                os.path.join(".config", "gh"),
            )
        ]
    spiffe_enabled = str(
        env.get("SPIFFE_ENABLED", os.environ.get("SPIFFE_ENABLED", "false"))
    ).lower() == "true"
    if not spiffe_enabled:
        paths.append(
            env.get("SPIRE_AGENT_SOCKET")
            or os.environ.get("SPIRE_AGENT_SOCKET")
            or "/run/spire/sockets/agent.sock"
        )
    # de-duplicate, keep order
    seen, unique = set(), []
    for p in paths:
        if p and p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


# ─────────────────────────────────────────────────────────────────────────────
# Sandbox policy model (helper protocol + bwrap mount construction)
# ─────────────────────────────────────────────────────────────────────────────

class FileSystemAccessMode:
    READ = "read"
    WRITE = "write"
    DENY = "none"


class FileSystemSandboxEntry:
    """One (path, access) rule. '/' is the root; access is read/write/deny."""

    __slots__ = ("path", "access")

    def __init__(self, path: str, access: str = FileSystemAccessMode.READ):
        self.path = path
        self.access = access

    def to_dict(self) -> dict:
        return {"path": self.path, "access": self.access}


class FileSystemSandboxPolicy:
    """Filesystem ruleset: read-only baseline plus explicit writable roots."""

    def __init__(self, entries=()):
        self.entries = [FileSystemSandboxEntry(e["path"], e["access"]) if isinstance(e, dict) else e for e in entries]

    @classmethod
    def full_disk_access(cls) -> "FileSystemSandboxPolicy":
        return cls([FileSystemSandboxEntry("/", FileSystemAccessMode.WRITE)])

    @classmethod
    def read_only(cls) -> "FileSystemSandboxPolicy":
        return cls([FileSystemSandboxEntry("/", FileSystemAccessMode.READ)])

    @classmethod
    def workspace_write(cls, writable_roots, deny_read_paths=()) -> "FileSystemSandboxPolicy":
        """Read-only baseline plus writable roots; workspace metadata names
        (.git/.ssh/.agents/.aws/.env) directly under a writable root are
        protected whether or not they exist yet (missing ones are masked at
        mount time so they cannot be created), mirroring Codex's protected
        metadata behaviour. `deny_read_paths` become unreadable masks."""
        entries = [FileSystemSandboxEntry("/", FileSystemAccessMode.READ)]
        for root in writable_roots:
            entries.append(FileSystemSandboxEntry(root, FileSystemAccessMode.WRITE))
            for name in PROTECTED_METADATA_PATH_NAMES:
                entries.append(
                    FileSystemSandboxEntry(os.path.join(root, name), FileSystemAccessMode.READ)
                )
        for path in deny_read_paths:
            if path:
                entries.append(FileSystemSandboxEntry(path, FileSystemAccessMode.DENY))
        return cls(entries)

    # ── queries ─────────────────────────────────────────────────────────────
    def has_full_disk_write_access(self) -> bool:
        return any(e.path == "/" and e.access == FileSystemAccessMode.WRITE for e in self.entries)

    def has_full_disk_read_access(self) -> bool:
        return any(
            e.path == "/" and e.access in (FileSystemAccessMode.READ, FileSystemAccessMode.WRITE)
            for e in self.entries
        )

    def get_writable_roots_with_cwd(self, cwd: str) -> list:
        return [self._resolve(e.path, cwd) for e in self.entries if e.access == FileSystemAccessMode.WRITE]

    def get_readable_roots_with_cwd(self, cwd: str) -> list:
        return [self._resolve(e.path, cwd) for e in self.entries if e.access == FileSystemAccessMode.READ]

    def get_unreadable_roots_with_cwd(self, cwd: str) -> list:
        return [self._resolve(e.path, cwd) for e in self.entries if e.access == FileSystemAccessMode.DENY]

    def get_read_only_subpaths_for_root(self, root: str, cwd: str) -> list:
        """Read-only subpaths layered under a writable root (re-bound with
        --ro-bind after the writable --bind)."""
        root_abs = os.path.abspath(self._resolve(root, cwd))
        subpaths = []
        for e in self.entries:
            if e.access != FileSystemAccessMode.READ:
                continue
            p = os.path.abspath(self._resolve(e.path, cwd))
            if p != root_abs and p.startswith(root_abs + os.sep):
                subpaths.append(p)
        return subpaths

    @staticmethod
    def _resolve(path: str, cwd: str) -> str:
        if path == "/" or path.startswith("/"):
            return path
        return os.path.normpath(os.path.join(cwd, path))

    def to_dict(self) -> dict:
        return {"entries": [e.to_dict() for e in self.entries]}

    @classmethod
    def from_dict(cls, data: dict) -> "FileSystemSandboxPolicy":
        return cls([{"path": e["path"], "access": e.get("access", "read")} for e in data.get("entries", [])])


class NetworkSandboxPolicy:
    """Network ruleset: enabled providers keep host networking; disabled
    providers get an empty network namespace plus a seccomp filter."""

    __slots__ = ("enabled",)

    def __init__(self, enabled: bool = False):
        self.enabled = bool(enabled)

    def is_enabled(self) -> bool:
        return self.enabled

    def to_dict(self) -> dict:
        return {"enabled": self.enabled}

    @classmethod
    def from_dict(cls, data: dict) -> "NetworkSandboxPolicy":
        return cls(bool(data.get("enabled", False)))


class PermissionProfile:
    """Runtime permission profile carried through the helper protocol."""

    __slots__ = ("file_system", "network")

    def __init__(self, file_system: FileSystemSandboxPolicy, network: NetworkSandboxPolicy):
        self.file_system = file_system
        self.network = network

    def to_runtime_permissions(self):
        return self.file_system, self.network

    def to_dict(self) -> dict:
        return {
            "file_system": self.file_system.to_dict(),
            "network": self.network.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PermissionProfile":
        return cls(
            FileSystemSandboxPolicy.from_dict(data.get("file_system", {})),
            NetworkSandboxPolicy.from_dict(data.get("network", {})),
        )

    @classmethod
    def danger_full_access(cls) -> "PermissionProfile":
        return cls(FileSystemSandboxPolicy.full_disk_access(), NetworkSandboxPolicy(enabled=True))

    @classmethod
    def workspace_write(cls, writable_roots, network: bool = False,
                        deny_read_paths=()) -> "PermissionProfile":
        return cls(
            FileSystemSandboxPolicy.workspace_write(writable_roots, deny_read_paths),
            NetworkSandboxPolicy(enabled=network),
        )

    @classmethod
    def read_only(cls, network: bool = False) -> "PermissionProfile":
        return cls(FileSystemSandboxPolicy.read_only(), NetworkSandboxPolicy(enabled=network))


# ─────────────────────────────────────────────────────────────────────────────
# bubblewrap discovery — PATH only, never from inside the working directory
# (a repository-checked-in bwrap must not be able to hijack the sandbox)
# ─────────────────────────────────────────────────────────────────────────────

def _is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:
        return False


def find_system_bwrap_in_path(cwd: str | None = None) -> str | None:
    """First `bwrap` on PATH that lives OUTSIDE the given directory."""
    cwd = cwd or os.getcwd()
    seen = set()
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or entry in seen:
            continue
        seen.add(entry)
        candidate = os.path.join(entry, "bwrap")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            if _is_within(os.path.realpath(candidate), cwd):
                continue  # never use a bwrap from inside the workspace
            return candidate
    return None


def find_bwrap() -> str | None:
    return find_system_bwrap_in_path()


def is_wsl1() -> bool:
    if not IS_LINUX:
        return False
    try:
        with open("/proc/sys/kernel/osrelease", encoding="ascii") as f:
            release = f.read().lower()
        return "microsoft" in release and "wsl2" not in release
    except OSError:
        return False


WSL1_BWRAP_WARNING = (
    "WSL1 is unsupported for bubblewrap sandboxing: it cannot create the "
    "required user namespaces, so sandboxed commands are rejected."
)


def user_namespaces_supported() -> bool:
    """Capability probe: enter a throw-away user namespace."""
    if not IS_LINUX:
        return False
    try:
        result = subprocess.run(
            ["unshare", "--user", "--map-root-user", "/usr/bin/env", "true"],
            capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            return True
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone", encoding="ascii") as f:
            return f.read().strip() != "0"
    except OSError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# seccomp BPF (inner stage) — ported from codex-rs/linux-sandbox/src/seccomp.rs
# ─────────────────────────────────────────────────────────────────────────────

if IS_LINUX:
    import ctypes
    import platform as _platform
    import struct as _struct

    PR_SET_NO_NEW_PRIVS = 38
    SECCOMP_SET_MODE_FILTER = 1
    SYS_SECCOMP = 317  # x86_64
    SYS_CAPGET = 125   # x86_64

    BPF_LD, BPF_W, BPF_ABS = 0x00, 0x00, 0x20
    BPF_JMP, BPF_JA, BPF_JEQ, BPF_JGE, BPF_K = 0x05, 0x00, 0x10, 0x30, 0x00
    BPF_RET = 0x06
    SECCOMP_RET_ALLOW = 0x7FFF0000
    SECCOMP_RET_ERRNO = 0x00050000
    EPERM = 1
    AF_UNIX = 1
    AF_INET = 2
    AF_INET6 = 10
    AF_VSOCK = 40
    AUDIT_ARCH_X86_64 = 0xC000003E
    AUDIT_ARCH_AARCH64 = 0xC00000B7
    # x32 ABI (64-bit x86 with 32-bit pointers) keeps AUDIT_ARCH_X86_64 as its
    # audit architecture but sets bit 30 of every syscall number, so those
    # numbers never match deny rules written for native numbers.
    X32_SYSCALL_BIT = 0x40000000
    _IS_X86_64 = _platform.machine() in ("x86_64", "amd64")

    _SYSNO_X86_64 = {
        "ptrace": 101, "socket": 41, "socketpair": 53,
        "process_vm_readv": 310, "process_vm_writev": 311,
        "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
        "connect": 42, "accept": 43, "accept4": 288, "bind": 49, "listen": 50,
        "getpeername": 52, "getsockname": 51, "shutdown": 48, "sendto": 44,
        "sendmmsg": 307, "recvmmsg": 299, "getsockopt": 54, "setsockopt": 55,
    }
    _SYSNO_AARCH64 = {
        "ptrace": 26, "socket": 198, "socketpair": 199,
        "process_vm_readv": 270, "process_vm_writev": 271,
        "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
        "connect": 203, "accept": 202, "accept4": 242, "bind": 200, "listen": 201,
        "getpeername": 205, "getsockname": 204, "shutdown": 210, "sendto": 206,
        "sendmmsg": 269, "recvmmsg": 243, "getsockopt": 209, "setsockopt": 208,
    }
    SYSNO = _SYSNO_AARCH64 if _platform.machine() == "aarch64" else _SYSNO_X86_64
    NATIVE_ARCH = AUDIT_ARCH_AARCH64 if _platform.machine() == "aarch64" else AUDIT_ARCH_X86_64
    if _platform.machine() == "aarch64":
        SYS_SECCOMP = 277
        SYS_CAPGET = 90

    # seccomp_data offsets
    SD_ARCH = 4
    SD_NR = 0
    SD_ARG0 = 16

    # Load the C library through the already-running interpreter's global
    # symbol table. The previous hard-coded "libc.so.6" fails on musl/Alpine
    # (where the soname is libc.musl-<arch>.so.1); CDLL(None) resolves libc
    # symbols on glibc and musl alike.
    _libc = ctypes.CDLL(None, use_errno=True)

    class _SockFilter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                    ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]

    class _SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


class NetworkSeccompMode:
    RESTRICTED = "restricted"                 # network off: AF_UNIX only
    VM_SOCKET_RESTRICTED = "vm_socket_restricted"  # network on: deny AF_VSOCK only


def _bpf_stmt(code: int, k: int):
    return ("s", code, None, None, k)


def _bpf_jeq(k: int, jt=None, jf=None):
    return ("j", BPF_JMP | BPF_JEQ | BPF_K, jt, jf, k)


def _bpf_jge(k: int, jt=None, jf=None):
    return ("j", BPF_JMP | BPF_JGE | BPF_K, jt, jf, k)


class _BpfAsm:
    """Two-pass BPF assembler with labels."""

    def __init__(self):
        self.insns: list = []
        self.labels: dict = {}

    def emit(self, *insns):
        self.insns.extend(insns)

    def label(self, name):
        self.labels[name] = len(self.insns)

    def assemble(self) -> bytes:
        out = []
        for insn in self.insns:
            _, code, jt, jf, k = insn
            if isinstance(jt, str):
                jt = self.labels[jt] - (len(out) + 1)
            if isinstance(jf, str):
                jf = self.labels[jf] - (len(out) + 1)
            out.append(_struct.pack("HBBI", code, jt or 0, jf or 0, k))
        return b"".join(out)


def build_seccomp_bpf(mode: str) -> bytes:
    """Build the seccomp BPF program (default ALLOW, matched rules EPERM).

    Mirrors install_network_seccomp_filter_on_current_thread:
      - io_uring denied in every socket-restricted mode (it can create
        AF_VSOCK sockets without a socket() syscall)
      - RESTRICTED: ptrace/process_vm_* plus every networking syscall
        denied outright; socket()/socketpair() allowed only for AF_UNIX
      - VM_SOCKET_RESTRICTED: socket()/socketpair() denied only for AF_VSOCK
        (ptrace/process_vm_* stay allowed in this mode, as upstream)
      - non-native architecture (e.g. 32-bit compat syscalls): EPERM
      - x86_64 only, Runtime Shield addition beyond upstream: syscall
        numbers with the x32 bit (>= 0x40000000) are denied. Upstream's
        seccompiler 0.5 gate only compares the audit architecture, which
        x32 shares with native x86_64, so an x32-ABI binary could
        otherwise reach every socket/ptrace/io_uring syscall outside the
        number-matched deny rules.
    """
    a = _BpfAsm()
    # Architecture gate: reject 32-bit compat syscalls (different numbering).
    a.emit(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SD_ARCH))
    a.emit(_bpf_jeq(NATIVE_ARCH, jf="bad_arch"))
    a.label("native")
    a.emit(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SD_NR))  # load syscall number
    if _IS_X86_64:
        # x32 ABI: same audit arch, numbers with bit 30 set (see docstring).
        a.emit(_bpf_jge(X32_SYSCALL_BIT, jt="deny"))

    if mode == NetworkSeccompMode.RESTRICTED:
        for name in ("ptrace", "process_vm_readv", "process_vm_writev",
                     "connect", "accept", "accept4", "bind", "listen",
                     "getpeername", "getsockname", "shutdown", "sendto",
                     "sendmmsg", "recvmmsg", "getsockopt", "setsockopt"):
            a.emit(_bpf_jeq(SYSNO[name], jt="deny"))
    for name in ("io_uring_setup", "io_uring_enter", "io_uring_register"):
        a.emit(_bpf_jeq(SYSNO[name], jt="deny"))

    # socket(): family gate on args[0]
    a.emit(_bpf_jeq(SYSNO["socket"], jf="check_socketpair"))
    a.emit(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SD_ARG0))
    if mode == NetworkSeccompMode.RESTRICTED:
        a.emit(_bpf_jeq(AF_UNIX, jt="allow_socket", jf="deny"))
    else:  # VM_SOCKET_RESTRICTED
        a.emit(_bpf_jeq(AF_VSOCK, jt="deny", jf="allow_socket"))
    a.label("deny")
    a.emit(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM))
    a.label("allow_socket")
    a.emit(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

    # socketpair(): family gate on args[0]
    a.label("check_socketpair")
    a.emit(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SD_NR))  # reload nr
    a.emit(_bpf_jeq(SYSNO["socketpair"], jf="default"))
    a.emit(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SD_ARG0))
    if mode == NetworkSeccompMode.RESTRICTED:
        a.emit(_bpf_jeq(AF_UNIX, jt="allow_sp", jf="deny_sp"))
    else:
        a.emit(_bpf_jeq(AF_VSOCK, jt="deny_sp", jf="allow_sp"))
    a.label("deny_sp")
    a.emit(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM))
    a.label("allow_sp")
    a.emit(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
    a.label("default")
    a.emit(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
    # Non-native architecture: deny everything that is not the native ABI.
    a.label("bad_arch")
    a.emit(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM))
    return a.assemble()


def set_no_new_privs() -> None:
    rc = _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if rc != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")


def install_seccomp_filter(prog: bytes) -> None:
    """Apply the BPF program to the current thread."""
    n = len(prog) // 8
    if n == 0 or len(prog) % 8:
        raise ValueError("invalid BPF program length")
    words = _struct.unpack("<" + "HBBI" * n, prog)
    arr = (_SockFilter * n)()
    for i in range(n):
        arr[i] = _SockFilter(*words[i * 4: i * 4 + 4])
    fprog = _SockFprog(n, arr)
    set_no_new_privs()
    rc = _libc.syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, 0, ctypes.byref(fprog))
    if rc != 0:
        raise OSError(ctypes.get_errno(), "seccomp(SECCOMP_SET_MODE_FILTER) failed")


def verify_no_capabilities() -> None:
    """Inner-stage guard: effective AND permitted capabilities must be empty
    (capget check, mirroring the --apply-seccomp-then-exec stage of the Codex
    helper, which rejects a non-zero effective or permitted set)."""
    header = _struct.pack("II", 0x20080522, 0)
    data = bytearray(24)
    buf = (ctypes.c_char * 24).from_buffer(data)
    rc = _libc.syscall(SYS_CAPGET, header, buf)
    if rc != 0:
        raise OSError(ctypes.get_errno(), "capget failed")
    eff, perm = _struct.unpack_from("<II", data, 0)
    eff2, perm2 = _struct.unpack_from("<II", data, 12)
    if eff or perm or eff2 or perm2:
        raise RuntimeError(
            "Linux sandbox retained effective or permitted capabilities"
        )


def apply_sandbox_policies_to_current_thread(
    file_system_policy: FileSystemSandboxPolicy,
    network_policy: NetworkSandboxPolicy,
) -> None:
    """In-process restrictions for the inner stage: PR_SET_NO_NEW_PRIVS plus
    the network seccomp filter. Filesystem restrictions are established by
    bubblewrap in the outer stage."""
    if not IS_LINUX:
        raise RuntimeError("in-process Linux restrictions require Linux")

    if not network_policy.is_enabled():
        mode = NetworkSeccompMode.RESTRICTED
    elif not file_system_policy.has_full_disk_write_access():
        # VM sockets reach host services outside the filesystem sandbox.
        mode = NetworkSeccompMode.VM_SOCKET_RESTRICTED
    else:
        return  # full access with network: no in-process restrictions

    set_no_new_privs()
    install_seccomp_filter(build_seccomp_bpf(mode))


# ─────────────────────────────────────────────────────────────────────────────
# bubblewrap argv construction — ported from codex-rs/linux-sandbox/src/bwrap.rs
# ─────────────────────────────────────────────────────────────────────────────

class BwrapNetworkMode:
    FULL_ACCESS = "full_access"   # keep host network namespace
    ISOLATED = "isolated"         # --unshare-net


class BwrapOptions:
    __slots__ = ("mount_proc", "inherit_pid_namespace", "network_mode")

    def __init__(self, mount_proc: bool = True, inherit_pid_namespace: bool = False,
                 network_mode: str = BwrapNetworkMode.FULL_ACCESS):
        self.mount_proc = mount_proc
        self.inherit_pid_namespace = inherit_pid_namespace
        self.network_mode = network_mode


def _bwrap_network_mode(network_policy: NetworkSandboxPolicy) -> str:
    if network_policy.is_enabled():
        return BwrapNetworkMode.FULL_ACCESS
    return BwrapNetworkMode.ISOLATED


# ─────────────────────────────────────────────────────────────────────────────
# Mount construction helpers — ported from codex-rs/linux-sandbox/src/bwrap.rs
# ─────────────────────────────────────────────────────────────────────────────

def _path_depth(path: str) -> int:
    return path.count(os.sep)


def _is_within_any(path: str, roots) -> bool:
    return any(_is_within(path, root) for root in roots)


def _dedupe_unreadable_roots(paths) -> list:
    """Drop duplicate deny paths that resolve to the same host node.

    The built-in deny list contains both /run/docker.sock and
    /var/run/docker.sock (a symlink to /run). Masking the same socket twice is
    wasteful and the second mount target may already be the /dev/null bind.
    """
    seen = set()
    result = []
    for path in sorted(set(paths)):
        try:
            key = os.path.realpath(path) if os.path.exists(path) or os.path.islink(path) else path
        except OSError:
            key = path
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def find_first_non_existent_component(target_path: str):
    """First missing path component while walking `target_path` (port of
    Codex's find_first_non_existent_component).

    Mounting a read-only empty file over the first missing component prevents
    the sandboxed process from creating the protected path hierarchy.
    """
    if not os.path.isabs(target_path):
        return None
    current = ""
    for part in target_path.split(os.sep):
        if not part or part == ".":
            continue
        if part == "..":
            current = os.path.dirname(current) or os.sep
            continue
        current = os.path.join(current or os.sep, part)
        if not os.path.exists(current):
            return current
    return None


def first_writable_symlink_component(target_path: str, writable_roots):
    """First symlink component of `target_path` that lives under a writable
    root (port of Codex's first_writable_symlink_component_in_path).

    These symlinks are mutable from inside the sandbox, so any mount or mask
    based on their resolved target would race a path the sandboxed process
    can change. Callers fail closed when one is found.
    """
    if not os.path.isabs(target_path):
        return None
    current = ""
    for part in target_path.split(os.sep):
        if not part or part == ".":
            continue
        if part == "..":
            current = os.path.dirname(current) or os.sep
            continue
        current = os.path.join(current or os.sep, part)
        if os.path.islink(current) and _is_within_any(current, writable_roots):
            return current
    return None


def _canonical_target_if_symlinked_path(path: str):
    """Return the fully resolved target only when some component of `path` is
    a symlink (port of Codex's canonical_target_if_symlinked_path).

    Ordinary paths stay in their logical form. Missing paths return None so
    the caller keeps the logical path (bwrap will reject a genuinely missing
    bind target, which callers already filter). A resolved symlink alias is
    bound at its real location so the sandbox view cannot be raced by
    replacing the alias inside a writable root.
    """
    if not os.path.isabs(path):
        return None
    current = os.sep
    for part in path.split(os.sep):
        if not part or part == ".":
            continue
        if part == "..":
            current = os.path.dirname(current.rstrip(os.sep)) or os.sep
            continue
        current = os.path.join(current, part)
        try:
            st = os.lstat(current)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            try:
                target = os.path.realpath(path)
            except OSError:
                return None
            if os.path.normpath(target) == os.path.normpath(path):
                return None
            return target
    return None


def _remap_paths_for_symlink_target(paths, root: str, target: str) -> list:
    """Map paths under a symlinked writable root onto the real target (port of
    Codex's remap_paths_for_symlink_target), so carveouts and deny masks apply
    to the location bwrap actually mounts."""
    remapped = []
    root_prefix = root.rstrip(os.sep) + os.sep
    for path in paths:
        if path == root:
            remapped.append(target)
        elif path.startswith(root_prefix):
            remapped.append(os.path.join(target, os.path.relpath(path, root)))
        else:
            remapped.append(path)
    return remapped


def _normalize_command_cwd_for_bwrap(command_cwd: str) -> str:
    """Canonicalize the command cwd when it exists (port of Codex's
    normalize_command_cwd_for_bwrap). Bubblewrap otherwise inherits the
    helper's logical cwd, which can be a symlink alias that disappears once
    only canonical roots are mounted."""
    try:
        if os.path.exists(command_cwd):
            return os.path.realpath(command_cwd)
    except OSError:
        pass
    return command_cwd


def transient_empty_metadata_path(path: str):
    """'file' | 'dir' when `path` is an existing-but-empty protected metadata
    path (port of Codex's transient_empty_metadata_path).

    Another concurrent bwrap setup — or a previous run whose cleanup could
    not complete — can leave an empty mount target at a missing metadata
    path. Treat it like the missing case instead of binding that transient
    host path as the stable source.
    """
    if os.path.basename(path) not in PROTECTED_METADATA_PATH_NAMES:
        return None
    try:
        st = os.lstat(path)
    except OSError:
        return None
    import stat as _stat
    if _stat.S_ISREG(st.st_mode) and st.st_size == 0:
        return "file"
    if _stat.S_ISDIR(st.st_mode) and not os.listdir(path):
        return "dir"
    return None


def _is_active_mount_target(path: str) -> bool:
    """True when `path` is the mount point of an active mount (checked via
    /proc/self/mountinfo). Used by synthetic-target cleanup so a concurrent
    sandbox launch using the same mask is never disturbed."""
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as fh:
            for line in fh:
                fields = line.split()
                if len(fields) > 4 and os.path.normpath(fields[4]) == os.path.normpath(path):
                    return True
    except OSError:
        return True  # cannot verify — be conservative
    return False


class SyntheticMountTarget:
    """One host path that bwrap may materialize while building the sandbox.

    Port of Codex's SyntheticMountTarget: `pre_existing` records the
    (st_dev, st_ino) identity of an empty protected path that existed before
    the run. Cleanup compares identities and therefore never deletes a real
    pre-existing empty `.env`/`.git`/`.ssh` file or directory.
    """

    __slots__ = ("path", "kind", "pre_existing")

    def __init__(self, path: str, kind: str, pre_existing=None):
        self.path = path
        self.kind = kind  # 'file' | 'dir'
        self.pre_existing = pre_existing  # (st_dev, st_ino) or None

    @classmethod
    def missing(cls, path: str) -> "SyntheticMountTarget":
        return cls(path, "file")

    @classmethod
    def missing_empty_directory(cls, path: str) -> "SyntheticMountTarget":
        return cls(path, "dir")

    @classmethod
    def existing_empty_file(cls, path: str, st) -> "SyntheticMountTarget":
        return cls(path, "file", _file_identity(st))

    @classmethod
    def existing_empty_directory(cls, path: str, st) -> "SyntheticMountTarget":
        return cls(path, "dir", _file_identity(st))

    def preserves_pre_existing_path(self) -> bool:
        return self.pre_existing is not None


def _file_identity(st) -> tuple:
    return (st.st_dev, st.st_ino)


def _append_mount_target_parent_dir_args(args: list, mount_target: str, anchor: str) -> None:
    """Recreate missing parent directories of a nested mount target inside a
    tmpfs that is about to be remounted read-only (port of Codex's
    append_mount_target_parent_dir_args)."""
    if os.path.isdir(mount_target):
        target_dir = mount_target
    else:
        target_dir = os.path.dirname(mount_target)
    if not target_dir:
        return
    dirs = []
    current = os.path.abspath(target_dir)
    anchor_abs = os.path.abspath(anchor)
    while current != anchor_abs and current != os.path.dirname(current):
        dirs.append(current)
        current = os.path.dirname(current)
    for directory in reversed(dirs):
        args += ["--dir", directory]


class BwrapMounts:
    """bubblewrap argv fragment plus the resources it needs.

    args              : the mount/namespace arguments (without the bwrap path)
    synthetic_targets : SyntheticMountTarget entries bwrap materializes inside
                        writable roots for missing/transient protected paths;
                        they must be removed after the sandboxed process exits
    preserved_fds     : open descriptors passed to --ro-bind-data mounts; bwrap
                        consumes them, so they must stay open across exec
    """

    __slots__ = ("args", "synthetic_targets", "preserved_fds")

    def __init__(self):
        self.args: list = []
        self.synthetic_targets: list = []
        self.preserved_fds: list = []

    def open_null_fd(self) -> int:
        """One inheritable /dev/null descriptor per --ro-bind-data mount
        (bwrap consumes the descriptor of every bind-data mount)."""
        fd = os.open("/dev/null", os.O_RDONLY)
        os.set_inheritable(fd, True)
        self.preserved_fds.append(fd)
        return fd

    # ── read-only protection of workspace metadata ───────────────────────────

    def append_read_only_empty_directory(self, path: str, pre_existing_st=None) -> None:
        self.args += ["--perms", "555", "--tmpfs", path, "--remount-ro", path]
        if pre_existing_st is None:
            self.synthetic_targets.append(SyntheticMountTarget.missing_empty_directory(path))
        else:
            self.synthetic_targets.append(
                SyntheticMountTarget.existing_empty_directory(path, pre_existing_st)
            )

    def append_empty_file_bind_data(self, path: str, pre_existing_st=None) -> None:
        fd = self.open_null_fd()
        self.args += ["--ro-bind-data", str(fd), path]
        if pre_existing_st is None:
            self.synthetic_targets.append(SyntheticMountTarget.missing(path))
        else:
            self.synthetic_targets.append(
                SyntheticMountTarget.existing_empty_file(path, pre_existing_st)
            )

    def append_missing_read_only_subpath(self, path: str) -> None:
        """Port of Codex's append_missing_read_only_subpath_args: protected
        directory names get a read-only empty directory, everything else a
        read-only empty file."""
        if os.path.basename(path) in PROTECTED_METADATA_DIR_NAMES:
            self.append_read_only_empty_directory(path)
        else:
            self.append_empty_file_bind_data(path)

    def append_read_only_subpath(self, subpath: str, allowed_write_paths) -> None:
        """Port of Codex's append_read_only_subpath_args: existing subpaths
        are re-bound read-only; missing/transient ones are masked."""
        transient = transient_empty_metadata_path(subpath)
        if transient is not None and _is_within_any(subpath, allowed_write_paths):
            # Record the identity of the pre-existing empty path so cleanup
            # preserves it (Codex's existing_empty_file/directory targets).
            try:
                pre_existing_st = os.lstat(subpath)
            except OSError:
                pre_existing_st = None
            if transient == "file":
                self.append_empty_file_bind_data(subpath, pre_existing_st)
            else:
                self.append_read_only_empty_directory(subpath, pre_existing_st)
            return
        if not os.path.exists(subpath):
            first_missing = find_first_non_existent_component(subpath)
            if first_missing is not None and _is_within_any(first_missing, allowed_write_paths):
                self.append_missing_read_only_subpath(first_missing)
            return
        if _is_within_any(subpath, allowed_write_paths):
            # A symlink at (or crossing into) the protected path under a
            # writable root cannot be protected reliably: fail closed.
            self.args += ["--ro-bind", subpath, subpath]

    # ── unreadable (deny-read) masks ──────────────────────────────────────

    def append_unreadable_root(self, path: str, allowed_write_paths) -> None:
        """Port of Codex's append_unreadable_root_args: existing files are
        replaced with a mode-000 empty read-only file, existing directories
        with a mode-000/111 read-only tmpfs, and missing paths inside
        writable roots have their first missing component masked."""
        if os.path.isdir(path) and not os.path.islink(path):
            writable_descendants = [
                root for root in allowed_write_paths
                if root != path and root.startswith(path + os.sep)
            ]
            # Execute-only perms let the process traverse into explicitly
            # re-opened writable descendants while still hiding the denied
            # directory contents (plain denied dirs stay at 000).
            self.args += [
                "--perms", "111" if writable_descendants else "000",
                "--tmpfs", path,
            ]
            # Recreate nested writable mount targets inside the fresh tmpfs
            # before it is frozen read-only (Codex does the same).
            for descendant in sorted(writable_descendants, key=_path_depth):
                _append_mount_target_parent_dir_args(self.args, descendant, path)
            self.args += ["--remount-ro", path]
            return
        if os.path.exists(path) or os.path.islink(path):
            if os.path.isfile(path) and not os.path.islink(path):
                fd = self.open_null_fd()
                self.args += ["--perms", "000", "--ro-bind-data", str(fd), path]
            else:
                # Sockets, FIFOs, devices and symlinks cannot be masked with
                # --ro-bind-data: bwrap must create a regular file at the
                # destination and fails with "Can't create file" for a socket
                # (e.g. /run/docker.sock on a Docker host). Bind the harmless
                # /dev/null over the path instead; the original node/socket is
                # no longer reachable inside the sandbox.
                self.args += ["--ro-bind", "/dev/null", path]
            return
        first_missing = find_first_non_existent_component(path)
        if first_missing is not None and _is_within_any(first_missing, allowed_write_paths):
            self.append_empty_file_bind_data(first_missing)


def _subpath_is_deferred_to_nested_root(
    subpath: str, root: str, writable_roots, file_system_policy, cwd: str
) -> bool:
    """True when `subpath` belongs to a deeper writable root's read-only
    subpaths. Codex mounts it once, after the deeper bind (port of
    deferred_read_only_subpaths)."""
    for nested in writable_roots:
        if nested == root or not _is_within(nested, root):
            continue
        if not _is_within(subpath, nested):
            continue
        if subpath in file_system_policy.get_read_only_subpaths_for_root(nested, cwd):
            return True
    return False


def build_bwrap_mounts(
    command: list,
    file_system_policy: FileSystemSandboxPolicy,
    sandbox_policy_cwd: str,
    command_cwd: str,
    options: BwrapOptions,
) -> BwrapMounts:
    """Wrap a command with bubblewrap so the filesystem is read-only by
    default, with explicit writable roots layered afterward.

    Mount order (documented in bwrap.rs, create_filesystem_args):
      1. `--ro-bind / /` (full read baseline) or a tmpfs root with scoped
         read binds for restricted-read policies
      2. `--dev /dev` minimal device tree
      3. Unreadable ancestors of writable roots are masked before their
         child mounts are rebound
      4. `--bind <writable_root>` re-enables writes, shallowest first
      5. `--ro-bind <subpath>` re-applies read-only protection under those
         writable roots (protected metadata: .git, .env, ...); missing or
         transient-empty protected paths are masked instead
      6. Unreadable carveouts under a writable root are masked after that
         root is bound; unrelated unreadable roots are masked afterward

    Namespaces: --unshare-user, --unshare-pid (unless inherited),
    --unshare-ipc always, --unshare-net when the network policy is off.
    Capabilities: --cap-drop ALL. A private --tmpfs /tmp keeps provider
    temp files working without granting access to host /tmp.

    Raises RuntimeError when a read-only or deny mount would cross a symlink
    inside a writable root (fail closed — the mount could be raced).
    """
    mounts = BwrapMounts()
    full_disk_unreadable = sorted(
        set(file_system_policy.get_unreadable_roots_with_cwd(sandbox_policy_cwd))
    )
    if file_system_policy.has_full_disk_write_access() and not full_disk_unreadable:
        if options.network_mode == BwrapNetworkMode.FULL_ACCESS:
            mounts.args.extend(list(command))  # nothing to enforce
            return mounts
        # Port of Codex's create_bwrap_flags_full_filesystem: full writable
        # filesystem, but still isolate the namespaces the network policy
        # requires. No protected-metadata/deny masks are applied here because
        # the policy explicitly granted full disk write access.
        args = [
            "--new-session", "--die-with-parent",
            "--bind", "/", "/",
            "--dev", "/dev",
            "--bind-try", "/dev/shm", "/dev/shm",
            "--unshare-user",
        ]
        if not options.inherit_pid_namespace:
            args.append("--unshare-pid")
        args.append("--unshare-ipc")
        if options.network_mode != BwrapNetworkMode.FULL_ACCESS:
            args.append("--unshare-net")
        if options.mount_proc:
            args += ["--proc", "/proc"]
        args += ["--cap-drop", "ALL", "--"]
        args.extend(command)
        mounts.args = args
        return mounts

    cwd = sandbox_policy_cwd
    command_cwd = command_cwd or sandbox_policy_cwd
    writable_roots = [r for r in file_system_policy.get_writable_roots_with_cwd(cwd) if os.path.exists(r)]
    # Codex records both the logical root and its canonical target as allowed
    # write paths: the bind and carveout validation must accept either form.
    allowed_write_paths = []
    for root in writable_roots:
        allowed_write_paths.append(root)
        symlink_target = _canonical_target_if_symlinked_path(root)
        if symlink_target is not None and symlink_target not in allowed_write_paths:
            allowed_write_paths.append(symlink_target)
    unreadable_roots = _dedupe_unreadable_roots(
        file_system_policy.get_unreadable_roots_with_cwd(cwd)
    )
    unreadable_paths = set(unreadable_roots)

    args = ["--new-session", "--die-with-parent"]

    # 1. base filesystem view
    if file_system_policy.has_full_disk_read_access():
        args += ["--ro-bind", "/", "/", "--dev", "/dev"]
    else:
        args += ["--tmpfs", "/", "--dev", "/dev"]
        readable = set(file_system_policy.get_readable_roots_with_cwd(cwd))
        readable.discard("/")
        for root in sorted(readable):
            if not os.path.exists(root):
                continue
            # Writable roots are rebound by real target below; mirror that for
            # their restricted-read bootstrap mount. Plain read-only roots
            # stay logical because callers may execute those paths inside
            # bwrap (port of create_filesystem_args).
            mount_root = root
            if any(
                root == writable_root
                or _is_within(root, writable_root)
                for writable_root in writable_roots
            ):
                mount_root = _canonical_target_if_symlinked_path(root) or root
            args += ["--ro-bind", mount_root, mount_root]

    # Private, sandbox-local /tmp: providers can still use temp files but
    # never touch (or see) host /tmp. Skipped when the sandbox itself needs
    # paths under /tmp (e.g. a project checked out there) — those must stay
    # visible through the read-only root bind.
    def _under_tmp(path: str) -> bool:
        try:
            return os.path.commonpath([os.path.abspath(path), "/tmp"]) == "/tmp"
        except ValueError:
            return False

    _tmp_consumers = [sandbox_policy_cwd, command_cwd or sandbox_policy_cwd,
                      os.path.abspath(__file__)]
    try:
        _tmp_consumers.append(os.path.realpath(sys.executable))
    except OSError:
        pass
    _tmp_consumers.extend(writable_roots)
    if command and command[0].startswith("/"):
        _tmp_consumers.append(command[0])
    if not any(_under_tmp(p) for p in _tmp_consumers):
        args += ["--tmpfs", "/tmp"]

    # 3. unreadable ancestors of writable roots (masked before the binds so
    #    nested writable carveouts can be reopened safely)
    ancestors = [
        p for p in unreadable_roots
        if not _is_within_any(p, allowed_write_paths)
        and any(_is_within(root, p) for root in allowed_write_paths)
    ]
    for path in sorted(ancestors, key=_path_depth):
        _fail_on_writable_symlink(path, allowed_write_paths)
        mounts.append_unreadable_root(path, allowed_write_paths)

    # 4/5. writable roots (shallow first), protected subpaths under each.
    #     Binds AND masks are recorded on `mounts.args` so their relative
    #     order (bind before its re-bind masks) is preserved verbatim.
    binds_file_system_root = any(
        os.path.normpath(root) == os.sep for root in writable_roots
    )
    for root in sorted(writable_roots, key=lambda p: (_path_depth(p), p)):
        symlink_target = _canonical_target_if_symlinked_path(root)
        mount_root = symlink_target or root
        # Rebinding a root alias would also undo masks already applied to `/`.
        # The physical root is already writable; only the alias's carveouts
        # remain (port of redundant_root_alias).
        redundant_root_alias = (
            binds_file_system_root
            and os.path.normpath(root) != os.sep
            and os.path.normpath(mount_root) == os.sep
        )
        # If a denied ancestor was already masked, recreate any missing mount
        # target parents before binding the narrower writable descendant
        # (port of Codex's append_mount_target_parent_dir_args call).
        masking_root = None
        for unreadable_root in unreadable_roots:
            if _is_within(root, unreadable_root):
                if masking_root is None or _path_depth(unreadable_root) > _path_depth(masking_root):
                    masking_root = unreadable_root
        if masking_root is not None:
            _append_mount_target_parent_dir_args(mounts.args, root, masking_root)

        if not redundant_root_alias:
            mounts.args += ["--bind", mount_root, mount_root]
            if os.path.normpath(mount_root) == os.sep:
                # The root bind shadows the earlier device tree and applies
                # nodev. Recreate only standard devices before deny masks.
                mounts.args += [
                    "--dev", "/dev",
                    "--bind-try", "/dev/shm", "/dev/shm",
                ]

        subpaths = [
            sub for sub in file_system_policy.get_read_only_subpaths_for_root(root, cwd)
            if sub not in unreadable_paths
            # A deeper writable root re-applies its own read-only subpaths
            # after its bind. Defer the mount so it is not installed twice
            # (port of Codex's deferred_read_only_subpaths).
            and not _subpath_is_deferred_to_nested_root(
                sub, root, writable_roots, file_system_policy, cwd
            )
        ]
        if symlink_target is not None:
            subpaths = _remap_paths_for_symlink_target(
                subpaths, root, symlink_target
            )
        for sub in sorted(subpaths, key=_path_depth):
            _fail_on_writable_symlink(sub, allowed_write_paths)
            mounts.append_read_only_subpath(sub, allowed_write_paths)

        # Protect the synthetic-mount registry only where a writable bind
        # exposes it. Apply this before deny masks so a denied parent stays
        # hidden rather than trying to recreate the registry beneath an
        # already read-only tmpfs (port of registry_protection).
        registry_root = _synthetic_mount_registry_root()
        if _is_within(registry_root, mount_root):
            registry_mount = registry_root
        elif _is_within(mount_root, registry_root):
            registry_mount = mount_root
        else:
            registry_mount = None
        if registry_mount is not None:
            os.makedirs(registry_root, exist_ok=True)
            mounts.args += ["--ro-bind", registry_mount, registry_mount]

        # 6a. nested unreadable carveouts under this writable root are
        #     masked after the root is bound
        nested = [p for p in unreadable_roots if _is_within(p, root)]
        if symlink_target is not None:
            nested = _remap_paths_for_symlink_target(
                nested, root, symlink_target
            )
        for path in sorted(nested, key=_path_depth):
            _fail_on_writable_symlink(path, allowed_write_paths)
            mounts.append_unreadable_root(path, allowed_write_paths)

    # 6b. unreadable roots unrelated to every writable root
    unrelated = [
        p for p in unreadable_roots
        if not _is_within_any(p, allowed_write_paths)
        and not any(_is_within(root, p) for root in allowed_write_paths)
    ]
    for path in sorted(unrelated, key=_path_depth):
        _fail_on_writable_symlink(path, allowed_write_paths)
        mounts.append_unreadable_root(path, allowed_write_paths)

    # namespaces
    args.append("--unshare-user")
    if not options.inherit_pid_namespace:
        args.append("--unshare-pid")
    args.append("--unshare-ipc")
    if options.network_mode != BwrapNetworkMode.FULL_ACCESS:
        args.append("--unshare-net")
    if options.mount_proc:
        args += ["--proc", "/proc"]
    # The helper runs with cwd == sandbox_policy_cwd, so bwrap inherits that
    # path. Enter the command cwd explicitly whenever its canonical form
    # differs from the (canonical) helper cwd (port of Codex's
    # normalize_command_cwd_for_bwrap / --chdir comparison).
    normalized_command_cwd = _normalize_command_cwd_for_bwrap(command_cwd)
    normalized_sandbox_cwd = _normalize_command_cwd_for_bwrap(sandbox_policy_cwd)
    if normalized_command_cwd != normalized_sandbox_cwd:
        args += ["--chdir", normalized_command_cwd]
    args += ["--cap-drop", "ALL", "--"]
    args.extend(command)

    # args = [base view ... namespaces ... -- command]; the fragments on
    # mounts.args were recorded in exact mount order and belong between the
    # base view and the namespace tail. Splice them in at the tail boundary.
    mounts.args = _splice_mount_args(args, mounts.args)
    return mounts


def _splice_mount_args(base_args: list, mount_fragments: list) -> list:
    """Insert the mount fragments between the base-view args and the
    namespace tail (everything before bwrap's `--` separator)."""
    if not mount_fragments:
        return list(base_args)
    # --unshare-user always starts the namespace tail.
    tail_start = base_args.index("--unshare-user")
    return base_args[:tail_start] + list(mount_fragments) + base_args[tail_start:]


def _fail_on_writable_symlink(path: str, allowed_write_paths) -> None:
    """Fail closed when a protected path crosses a symlink under a writable
    root (port of Codex's fatal error paths in append_read_only_subpath_args /
    append_unreadable_root_args)."""
    symlink = first_writable_symlink_component(path, allowed_write_paths)
    if symlink is not None:
        raise RuntimeError(
            f"cannot enforce sandbox path {path}: it crosses writable "
            f"symlink {symlink}, which the sandboxed process could replace"
        )


def create_bwrap_command_args(
    command: list,
    file_system_policy: FileSystemSandboxPolicy,
    sandbox_policy_cwd: str,
    command_cwd: str,
    options: BwrapOptions,
) -> list:
    """Backwards-compatible shim over build_bwrap_mounts for tests and
    inspection: returns just the argv (and closes the preserved fds, since
    no bwrap exec will consume them here)."""
    mounts = build_bwrap_mounts(
        command, file_system_policy, sandbox_policy_cwd, command_cwd, options,
    )
    for fd in mounts.preserved_fds:
        try:
            os.close(fd)
        except OSError:
            pass
    return mounts.args


def preflight_proc_mount_supported(bwrap_path: str) -> bool:
    """Probe whether `--proc /proc` works here (mirrors the proc-mount
    fallback): run a preflight bwrap and inspect stderr on failure."""
    try:
        result = subprocess.run(
            [
                bwrap_path,
                "--unshare-user", "--unshare-pid",
                "--ro-bind", "/", "/",
                "--dev", "/dev",
                "--proc", "/proc",
                "--", "/usr/bin/env", "true",
            ],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return True
        stderr = (result.stderr or "").lower()
        return "can't mount proc" not in stderr and "mount proc" not in stderr
    except (OSError, subprocess.SubprocessError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Helper CLI (outer stage builds bwrap argv; inner stage applies seccomp)
# ─────────────────────────────────────────────────────────────────────────────

FORWARDED_SIGNALS = [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]


def _sandbox_interpreter() -> str:
    """Canonical interpreter path for the inner re-exec (avoids symlink chains
    that would be unresolvable under a restricted-read sandbox view)."""
    try:
        return os.path.realpath(sys.executable)
    except OSError:
        return sys.executable


def _execvp(command: list) -> None:
    os.execvp(command[0], command)
    os._exit(127)  # exec failed


def _block_forwarded_signals():
    """Block the signals this helper forwards and return the previous mask
    (port of Codex's ForwardedSignalMask::block). Returns None when the
    platform does not expose pthread_sigmask."""
    try:
        return signal.pthread_sigmask(signal.SIG_BLOCK, FORWARDED_SIGNALS)
    except (AttributeError, OSError, ValueError):
        return None


def _restore_signal_mask(previous) -> None:
    """Restore a previous signal mask, unblocking the forwarded signals
    (port of Codex's ForwardedSignalMask::restore)."""
    if previous is None:
        return
    try:
        restored = set(previous) - set(FORWARDED_SIGNALS)
        signal.pthread_sigmask(signal.SIG_SETMASK, restored)
    except (AttributeError, OSError, ValueError):
        pass


def _terminate_with_parent(parent_pid: int) -> None:
    """Die if the helper parent disappears (port of terminate_with_parent):
    PR_SET_PDEATHSIG plus an explicit getppid check for the race where the
    parent exits before prctl takes effect."""
    try:
        _libc.prctl(1, signal.SIGTERM, 0, 0, 0)  # PR_SET_PDEATHSIG
    except Exception:
        pass
    try:
        if os.getppid() != parent_pid:
            os.kill(os.getpid(), signal.SIGTERM)
    except OSError:
        pass


def _send_signal_to_child(pid: int, signum: int) -> None:
    """Forward to the child's process group and the child itself, matching
    Codex's send_signal_to_bwrap_child. The group send reaches grandchildren;
    the direct send still works when the child is not a group leader."""
    for send in (
        lambda: os.killpg(pid, signum),
        lambda: os.kill(pid, signum),
    ):
        try:
            send()
        except ProcessLookupError:
            pass
        except PermissionError:
            pass


def _exit_with_wait_status(status: int) -> None:
    """Exit with the child's status (port of Codex's exit_with_wait_status).

    A signal-terminated child is reported by re-raising the same signal on
    this process, so the caller (bridge, shell, supervisor) observes the same
    termination semantics as an unsandboxed process. sys.exit is the fallback
    when re-raising is impossible.
    """
    if os.WIFEXITED(status):
        sys.exit(os.WEXITSTATUS(status))
    if os.WIFSIGNALED(status):
        signum = os.WTERMSIG(status)
        try:
            signal.signal(signum, signal.SIG_DFL)
        except (OSError, ValueError):
            pass
        try:
            os.kill(os.getpid(), signum)
        except OSError:
            pass
        sys.exit(128 + signum)
    sys.exit(1)


def _inner_stage(command: list, sandbox_policy_cwd: str,
                 permission_profile: PermissionProfile) -> None:
    """Inner stage (runs INSIDE the bubblewrap namespace): verify capabilities
    were dropped, apply seccomp + PR_SET_NO_NEW_PRIVS to this thread, then
    fork+exec the provider command with signal forwarding."""
    verify_no_capabilities()
    file_system_policy, network_policy = permission_profile.to_runtime_permissions()
    apply_sandbox_policies_to_current_thread(file_system_policy, network_policy)

    pid = os.fork()
    if pid == 0:
        # exec resets handled dispositions, but reset explicitly so the
        # command never inherits a forwarder installed by this helper.
        for s in FORWARDED_SIGNALS:
            try:
                signal.signal(s, signal.SIG_DFL)
            except (OSError, ValueError):
                pass
        _execvp(command)

    def _forward(signum, _frame):
        _send_signal_to_child(pid, signum)

    for s in FORWARDED_SIGNALS:
        signal.signal(s, _forward)
    while True:
        try:
            wpid, status = os.waitpid(pid, 0)
            if wpid == pid:
                break
        except InterruptedError:
            continue
    _exit_with_wait_status(status)


# ── synthetic mount registry (port of Codex's linux_run_main registry) ──────
#
# Concurrent sandbox launches can race on the same missing protected path: one
# run creates the empty mount target, another observes it and would otherwise
# treat it as a stable host path. Codex serializes registrations through a
# marker directory keyed by a hash of the target path, with one marker file per
# live helper PID. Cleanup removes a target only when no other live owner
# remains and the path is still empty. Pre-existing empty paths additionally
# carry a (dev, inode) identity so they are never deleted.

_SYNTHETIC_MARKER_SYNTHETIC = b"synthetic\n"
_SYNTHETIC_MARKER_EXISTING = b"existing\n"


def _synthetic_mount_registry_root() -> str:
    # Codex canonicalizes the temp directory before deriving the registry so
    # a symlinked TMPDIR cannot hide the registry from the writable-root
    # overlap check.
    try:
        temp_dir = os.path.realpath(tempfile.gettempdir())
    except OSError:
        temp_dir = tempfile.gettempdir()
    root = os.path.join(
        temp_dir,
        f"runtime-shield-bwrap-synthetic-mount-targets-{os.geteuid()}",
    )
    # A registry symlink could redirect bookkeeping into a writable root that
    # does not overlap TMPDIR, bypassing its read-only mount.
    if os.path.islink(root):
        raise RuntimeError(
            f"synthetic mount registry must not be a symlink: {root}"
        )
    return root


def _hash_path(path: str) -> str:
    """FNV-1a over the filesystem-encoded path (same scheme as Codex)."""
    value = 0xCBF29CE484222325
    for byte in os.fsencode(path):
        value ^= byte
        value = (value * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}"


def _synthetic_mount_marker_dir(path: str) -> str:
    return os.path.join(_synthetic_mount_registry_root(), _hash_path(path))


def _process_is_active(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True


def _marker_has_active_process_matching(marker_dir: str, matches) -> bool:
    try:
        names = os.listdir(marker_dir)
    except FileNotFoundError:
        return False
    for name in names:
        try:
            pid = int(name)
        except ValueError:
            continue
        marker_file = os.path.join(marker_dir, name)
        if not _process_is_active(pid):
            try:
                os.unlink(marker_file)
            except FileNotFoundError:
                pass
            except OSError as exc:
                log.warning("failed to remove stale synthetic mount marker %s: %s",
                            marker_file, exc)
            continue
        try:
            with open(marker_file, "rb") as fh:
                contents = fh.read()
        except FileNotFoundError:
            continue
        except OSError as exc:
            log.warning("failed to read synthetic mount marker %s: %s",
                        marker_file, exc)
            continue
        if matches(contents):
            return True
    return False


def _marker_has_active_process(marker_dir: str) -> bool:
    return _marker_has_active_process_matching(marker_dir, lambda _contents: True)


def _with_synthetic_mount_registry_lock(func):
    """Run `func` under an exclusive flock on the registry root."""
    import fcntl

    root = _synthetic_mount_registry_root()
    os.makedirs(root, exist_ok=True)
    lock_path = os.path.join(root, "lock")
    with open(lock_path, "a+b") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            return func()
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _register_synthetic_mount_targets(synthetic_targets):
    """Register this helper as an owner of every synthetic target.

    Returns registrations to pass to cleanup. If a pre-existing empty path is
    already owned by another live synthetic mount, downgrade it to a missing
    target so cleanup applies the marker/concurrency checks instead of treating
    the current host path as stable.
    """
    if not synthetic_targets:
        return []

    def register():
        registrations = []
        pid = os.getpid()
        for target in synthetic_targets:
            marker_dir = _synthetic_mount_marker_dir(target.path)
            os.makedirs(marker_dir, exist_ok=True)
            effective_target = target
            if target.preserves_pre_existing_path() and \
                    _marker_has_active_process_matching(
                        marker_dir,
                        lambda contents: contents == _SYNTHETIC_MARKER_SYNTHETIC,
                    ):
                if target.kind == "file":
                    effective_target = SyntheticMountTarget.missing(target.path)
                else:
                    effective_target = SyntheticMountTarget.missing_empty_directory(target.path)
            marker_file = os.path.join(marker_dir, str(pid))
            contents = (
                _SYNTHETIC_MARKER_EXISTING
                if effective_target.preserves_pre_existing_path()
                else _SYNTHETIC_MARKER_SYNTHETIC
            )
            with open(marker_file, "wb") as fh:
                fh.write(contents)
            registrations.append((effective_target, marker_file, marker_dir))
        return registrations

    return _with_synthetic_mount_registry_lock(register)


def _remove_synthetic_mount_target(target: SyntheticMountTarget) -> None:
    try:
        st = os.lstat(target.path)
    except FileNotFoundError:
        return
    if target.kind == "file":
        if not stat.S_ISREG(st.st_mode) or st.st_size != 0:
            return
    else:
        if not stat.S_ISDIR(st.st_mode):
            return
        try:
            if os.listdir(target.path):
                return
        except OSError:
            return
    if target.pre_existing is not None and _file_identity(st) == target.pre_existing:
        # This path existed before the run (empty .env/.git/.ssh, ...): the
        # sandbox masked it temporarily, but it is user data and stays.
        return
    if _is_active_mount_target(target.path):
        return
    try:
        if target.kind == "file":
            os.unlink(target.path)
        else:
            os.rmdir(target.path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        # DirectoryNotEmpty is expected if the sandboxed process raced us.
        log.debug("could not remove synthetic mount target %s: %s", target.path, exc)


def _cleanup_synthetic_mount_targets(registrations) -> None:
    """Unregister this helper and remove only targets created by this run.

    Pre-existing empty paths are preserved by identity; targets still owned by
    another live helper PID are preserved by the marker registry.
    """
    if not registrations:
        return

    def cleanup():
        for _target, marker_file, _marker_dir in reversed(registrations):
            try:
                os.unlink(marker_file)
            except FileNotFoundError:
                pass
            except OSError as exc:
                log.warning("failed to unregister synthetic mount target %s: %s",
                            marker_file, exc)
        for target, _marker_file, marker_dir in reversed(registrations):
            if _marker_has_active_process(marker_dir):
                continue
            _remove_synthetic_mount_target(target)
            try:
                os.rmdir(marker_dir)
            except FileNotFoundError:
                pass
            except OSError as exc:
                # DirectoryNotEmpty: another owner registered in the meantime.
                log.debug("could not remove synthetic mount marker dir %s: %s",
                          marker_dir, exc)

    _with_synthetic_mount_registry_lock(cleanup)


def _outer_stage(
    command: list,
    sandbox_policy_cwd: str,
    command_cwd: str | None,
    permission_profile: PermissionProfile,
    no_proc: bool,
    inherit_pid_namespace: bool,
    bwrap_path: str | None = None,
) -> None:
    """Outer stage: build the bubblewrap argv and exec bwrap. The inner command
    re-enters this file with --apply-seccomp-then-exec.

    When the argv contains synthetic mount targets (masks over missing or
    transient-empty protected paths), bwrap materializes empty files/dirs
    inside the writable roots on the host; those must not outlive the
    sandboxed process, so bwrap is forked and the targets are removed after
    it exits (port of Codex's run_bwrap_in_child_with_synthetic_mount_cleanup).
    """
    bwrap_path = bwrap_path or find_bwrap()
    if bwrap_path is None:
        sys.stderr.write(
            "[linux-sandbox] no bubblewrap executable found on PATH "
            "(outside the working directory)\n"
        )
        sys.exit(126)

    file_system_policy, network_policy = permission_profile.to_runtime_permissions()

    if is_wsl1():
        sys.stderr.write(f"[linux-sandbox] {WSL1_BWRAP_WARNING}\n")
        sys.exit(126)

    # Port of Codex's run_main fast path: full disk write with full network
    # access needs no bubblewrap at all. Apply the in-process policy (which is
    # a no-op for this combination) and exec the command directly instead of
    # constructing an invalid "bwrap <command>" argv.
    if file_system_policy.has_full_disk_write_access() and network_policy.is_enabled():
        apply_sandbox_policies_to_current_thread(file_system_policy, network_policy)
        _execvp(command)

    # Inner command: re-enter this helper inside the sandbox. Use the
    # canonical interpreter path so symlink chains resolve inside the view.
    inner = [
        _sandbox_interpreter(), os.path.abspath(__file__), "--helper",
        "--sandbox-policy-cwd", sandbox_policy_cwd,
        "--command-cwd", command_cwd or sandbox_policy_cwd,
        "--permission-profile", json.dumps(permission_profile.to_dict()),
        "--apply-seccomp-then-exec",
        "--",
    ] + command

    options = BwrapOptions(
        mount_proc=True,
        inherit_pid_namespace=inherit_pid_namespace,
        network_mode=_bwrap_network_mode(network_policy),
    )
    # Restrictive containers can deny mounting /proc: preflight and fall back.
    if options.mount_proc and (no_proc or not preflight_proc_mount_supported(bwrap_path)):
        options.mount_proc = False

    mounts = build_bwrap_mounts(
        inner, file_system_policy, sandbox_policy_cwd,
        command_cwd or sandbox_policy_cwd, options,
    )
    argv = [bwrap_path] + mounts.args

    if not mounts.synthetic_targets:
        os.execv(bwrap_path, argv)  # fast path: bwrap consumes the fds

    # Block forwarded signals across registration+registration and fork so a
    # signal cannot arrive before the child PID is known (Codex's
    # ForwardedSignalMask::block).
    setup_mask = _block_forwarded_signals()

    # Register this helper as an owner of every synthetic target before
    # forking, exactly like Codex's register_synthetic_mount_targets.
    try:
        registrations = _register_synthetic_mount_targets(mounts.synthetic_targets)
    except BaseException:
        _restore_signal_mask(setup_mask)
        raise

    # Fork model with synthetic-target cleanup.
    parent_pid = os.getpid()
    try:
        pid = os.fork()
    except OSError:
        _restore_signal_mask(setup_mask)
        _cleanup_synthetic_mount_targets(registrations)
        raise
    if pid == 0:
        for s in FORWARDED_SIGNALS:
            try:
                signal.signal(s, signal.SIG_DFL)
            except (OSError, ValueError):
                pass
        _restore_signal_mask(setup_mask)
        try:
            # Own process group so group signals reach the forwarder below
            # exactly once (mirrors Codex's setpgid on the bwrap child).
            os.setpgid(0, 0)
        except OSError:
            pass
        _terminate_with_parent(parent_pid)
        os.execv(bwrap_path, argv)
        os._exit(127)

    # Parent: the child owns the preserved fds now (bwrap consumes them).
    for fd in mounts.preserved_fds:
        try:
            os.close(fd)
        except OSError:
            pass

    def _forward(signum, _frame):
        _send_signal_to_child(pid, signum)

    for s in FORWARDED_SIGNALS:
        signal.signal(s, _forward)
    _restore_signal_mask(setup_mask)

    while True:
        try:
            wpid, status = os.waitpid(pid, 0)
            if wpid == pid:
                break
        except InterruptedError:
            continue

    # Block signals again for cleanup; a late forward would race a reused PID.
    cleanup_mask = _block_forwarded_signals()
    _cleanup_synthetic_mount_targets(registrations)
    _restore_signal_mask(cleanup_mask)
    _exit_with_wait_status(status)


def run_linux_sandbox_main(argv: list | None = None) -> None:
    """CLI surface for the Linux sandbox helper.

    Helper flags are parsed ONLY before the first `--`, mirroring clap's
    trailing_var_arg parsing in Codex. Everything after `--` is the command,
    even if it looks like a helper flag. The previous parser searched the
    whole argv and therefore let a provider command argument such as
    `--apply-seccomp-then-exec` disable bubblewrap and run with only seccomp.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--helper":
        argv = argv[1:]

    # Split at the first `--`; only the prefix may contain helper flags.
    try:
        separator = argv.index("--")
    except ValueError:
        flag_args, command = argv, []
    else:
        flag_args, command = argv[:separator], argv[separator + 1:]

    value_flags = {
        "--sandbox-policy-cwd": "sandbox_policy_cwd",
        "--command-cwd": "command_cwd",
        "--permission-profile": "profile_json",
        "--bwrap": "bwrap_path",
    }
    bool_flags = {
        "--apply-seccomp-then-exec": "apply_seccomp_then_exec",
        "--no-proc": "no_proc",
        "--inherit-pid-namespace": "inherit_pid_namespace",
    }
    parsed = {name: False for name in bool_flags.values()}
    parsed.update({name: None for name in value_flags.values()})

    index = 0
    while index < len(flag_args):
        arg = flag_args[index]
        if arg in bool_flags:
            parsed[bool_flags[arg]] = True
            index += 1
            continue
        if arg in value_flags:
            if index + 1 >= len(flag_args):
                sys.stderr.write(
                    f"[linux-sandbox] missing value for {arg}\n"
                )
                sys.exit(2)
            parsed[value_flags[arg]] = flag_args[index + 1]
            index += 2
            continue
        sys.stderr.write(f"[linux-sandbox] unexpected argument '{arg}' before '--'\n")
        sys.exit(2)

    apply_seccomp_then_exec = parsed["apply_seccomp_then_exec"]
    no_proc = parsed["no_proc"]
    inherit_pid_namespace = parsed["inherit_pid_namespace"]
    sandbox_policy_cwd = parsed["sandbox_policy_cwd"]
    command_cwd = parsed["command_cwd"]
    profile_json = parsed["profile_json"]
    bwrap_path = parsed["bwrap_path"]

    if not command:
        sys.stderr.write("[linux-sandbox] no command specified to execute.\n")
        sys.exit(2)
    if sandbox_policy_cwd is None:
        sys.stderr.write("[linux-sandbox] missing --sandbox-policy-cwd configuration\n")
        sys.exit(2)
    if profile_json is None:
        sys.stderr.write("[linux-sandbox] missing permission profile configuration\n")
        sys.exit(2)
    try:
        permission_profile = PermissionProfile.from_dict(json.loads(profile_json))
    except (ValueError, KeyError) as exc:
        sys.stderr.write(f"[linux-sandbox] invalid permission profile JSON: {exc}\n")
        sys.exit(2)

    if apply_seccomp_then_exec:
        try:
            _inner_stage(command, sandbox_policy_cwd, permission_profile)
        except SystemExit:
            raise
        except BaseException as exc:  # noqa: BLE001 - reported, not silenced
            # An inner-stage failure (capability check, no_new_privs, filter
            # install) means the sandbox could NOT be applied: report it as a
            # sandbox failure instead of a generic crash (mirrors Codex
            # mapping these to CodexErr::Sandbox).
            sys.stderr.write(
                "[linux-sandbox] SANDBOX FAILURE: the sandbox could not be "
                f"applied, the command was NOT executed: "
                f"{type(exc).__name__}: {exc}\n"
            )
            sys.exit(126)
        return  # unreachable
    try:
        _outer_stage(
            command, sandbox_policy_cwd, command_cwd, permission_profile,
            no_proc, inherit_pid_namespace, bwrap_path,
        )
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - reported, not silenced
        sys.stderr.write(
            "[linux-sandbox] SANDBOX FAILURE: the sandbox could not be "
            f"launched, the command was NOT executed: "
            f"{type(exc).__name__}: {exc}\n"
        )
        sys.exit(126)


class BubblewrapJailer(BaseJailer):
    """Linux bubblewrap + seccomp jailer (two-stage pipeline).

    Permission profile: read-only root filesystem, writable roots = the
    caller's allowed_paths ONLY (the working directory is never writable),
    and per-provider network policy from PROVIDER_SANDBOX_POLICIES.
    """

    def __init__(self, provider_name: str, cwd: str, env: dict, allowed_paths: list | None):
        super().__init__(provider_name, cwd, env, allowed_paths)
        self.policy = provider_sandbox_policy(provider_name)

    def build_permission_profile(self) -> PermissionProfile:
        writable_roots = []
        for path in self.allowed_paths or []:
            abs_path = os.path.abspath(path)
            if os.path.exists(abs_path) and abs_path not in writable_roots:
                writable_roots.append(abs_path)
        # NOTE: self.cwd (the project directory) is deliberately NOT a
        # writable root — a compromised provider must not be able to rewrite
        # bridge.py, rules/, mcp-firewall.yaml or .env.
        return PermissionProfile.workspace_write(
            writable_roots,
            network=self.policy.network,
            deny_read_paths=runtime_shield_deny_read_paths(self.cwd, self.env),
        )

    def get_popen_kwargs(self, cmd: list) -> dict:
        if not IS_LINUX:
            raise RuntimeError("BubblewrapJailer is only available on Linux")
        if is_wsl1():
            raise RuntimeError(f"[SANDBOX FAIL-CLOSED] {WSL1_BWRAP_WARNING}")
        bwrap = find_bwrap()
        if bwrap is None:
            # FAIL-CLOSED: never silently execute unsandboxed on the host.
            msg = (
                f"[SANDBOX FAIL-CLOSED] bubblewrap executable not found on PATH "
                f"(outside the working directory). Refusing to run "
                f"'{self.provider_name}' unsandboxed on host."
            )
            log.error("🚫 %s", msg)
            raise RuntimeError(msg)

        permissions = self.build_permission_profile()
        helper_args = [
            "--sandbox-policy-cwd", self.cwd,
            "--command-cwd", self.cwd,
            "--permission-profile", json.dumps(permissions.to_dict()),
            "--bwrap", bwrap,
            "--",
        ] + list(cmd)
        cmd[:] = [sys.executable, os.path.abspath(__file__), "--helper"] + helper_args

        log.info(
            "🔒 Sandboxing [%s]: Linux bubblewrap namespaces + seccomp active "
            "(read-only root, writable=%s, network=%s)",
            self.provider_name,
            self.allowed_paths or [],
            "on" if self.policy.network else "off",
        )
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


class ContainerSeccompJailer(BaseJailer):
    """CONTAINER-tier jailer: container filesystem boundary + Codex seccomp.

    Used only when the bridge already runs inside a container and bubblewrap
    cannot be nested there (e.g. Docker's default seccomp profile denies
    unprivileged user namespaces). Filesystem isolation is the container
    boundary; this tier additionally applies the exact Codex inner stage
    (`PR_SET_NO_NEW_PRIVS`, empty-capability verification, and the per-provider
    network/VM-socket seccomp filter) so providers cannot open IP sockets when
    their policy says network=False, cannot use AF_VSOCK, and cannot use
    io_uring. It never claims to be a stronger tier than CONTAINER.
    """

    def __init__(self, provider_name: str, cwd: str, env: dict, allowed_paths: list | None):
        super().__init__(provider_name, cwd, env, allowed_paths)
        self.policy = provider_sandbox_policy(provider_name)

    def build_permission_profile(self) -> PermissionProfile:
        # No filesystem claim here (the container provides it), but a
        # read-only policy keeps VmSocketRestricted active for network-on
        # providers and Restricted for network-off providers.
        return PermissionProfile.read_only(network=self.policy.network)

    def get_popen_kwargs(self, cmd: list) -> dict:
        if not IS_LINUX:
            raise RuntimeError("ContainerSeccompJailer is only available on Linux")
        permissions = self.build_permission_profile()
        helper_args = [
            "--sandbox-policy-cwd", self.cwd,
            "--command-cwd", self.cwd,
            "--permission-profile", json.dumps(permissions.to_dict()),
            "--apply-seccomp-then-exec",
            "--",
        ] + list(cmd)
        cmd[:] = [sys.executable, os.path.abspath(__file__), "--helper"] + helper_args
        log.info(
            "🐳 Sandboxing [%s]: CONTAINER filesystem boundary + seccomp "
            "(no_new_privs, empty capabilities, network=%s)",
            self.provider_name,
            "on" if self.policy.network else "off",
        )
        return super().get_popen_kwargs(cmd)


# ─────────────────────────────────────────────────────────────────────────────
# Behavioral sandbox verification (run the real pipeline and check that it
# actually confines) — availability checks alone are not proof.
# ─────────────────────────────────────────────────────────────────────────────

# Outcome each probe must produce for the sandbox to count as operational.
# "denied"     -> the sandboxed process must NOT be able to do it
# "succeeded"  -> the sandboxed process must still be able to do it
# "eperm"      -> the syscall must fail with EPERM specifically (proves the
#                  seccomp filter fired, not merely that the syscall is
#                  unsupported on this kernel)
_PROBE_EXPECTATIONS = {
    "open_bridge_py": "denied",          # overwrite gateway code
    "create_in_rules_dir": "denied",     # overwrite OPA policy
    "create_env_file": "denied",         # plant a new .env
    "write_etc": "denied",               # write under /etc
    "inet_socket": "denied",             # TCP/UDP socket creation
    "unix_socketpair": "succeeded",      # stdio/IPC must keep working
    "write_allowed_path": "succeeded",   # providers must still function
    "create_in_writable_root": "denied",  # protected names stay uncreatable
    "capabilities_empty": "succeeded",   # --cap-drop ALL took effect
    "read_denied_secret": "denied",      # deny-read masks hide secrets
    "ptrace_syscall": "eperm",            # seccomp.rs deny list
    "process_vm_readv_syscall": "eperm",  # seccomp.rs deny list
    "io_uring_setup_syscall": "eperm",    # denied in every mode
}

_PROBE_CODE = r"""
import ctypes, errno, json, os, socket, sys

results = {}

PTRACE_NR, PVMR_NR, IOURING_NR = (int(x) for x in sys.argv[5].split(","))

def attempt(name, fn):
    try:
        fn()
        results[name] = "succeeded"
    except OSError:
        results[name] = "denied"
    except Exception:
        results[name] = "denied"

def syscall_outcome(nr, *args):
    # 'eperm' when the syscall fails with EPERM (filter fired),
    # 'allowed' when it succeeded, else 'errno:<n>'.
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    rc = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args])
    if rc != -1:
        return "allowed"
    err = ctypes.get_errno()
    return "eperm" if err == errno.EPERM else f"errno:{err}"

def open_rw(path, mode):
    def _w():
        handle = open(path, mode)
        try:
            handle.write("sandbox-selftest")
        finally:
            handle.close()
    return _w

bridge_py, rules_probe, env_path, allowed_probe = sys.argv[1:5]
writable_root, secret_probe = sys.argv[6], sys.argv[7]

# 1. existing gateway code must not be openable for write (r+ never truncates,
#    so a broken sandbox cannot damage the file during this probe either).
def _open_bridge():
    handle = open(bridge_py, "r+")
    handle.close()
attempt("open_bridge_py", _open_bridge)

# 2. no new files inside the OPA policy directory.
attempt("create_in_rules_dir", open_rw(rules_probe, "x"))

# 3. no planting a fresh .env in the project root (x = fail if it exists).
attempt("create_env_file", open_rw(env_path, "x"))

# 4. /etc stays read-only.
attempt("write_etc", open_rw("/etc/runtime-shield-selftest", "x"))

# 5. network-off policy: AF_INET sockets must be denied by seccomp.
def _inet():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.close()
attempt("inet_socket", _inet)

# 6. AF_UNIX socketpairs must still work (pipes/IPC keep functioning).
def _unix_pair():
    a, b = socket.socketpair(socket.AF_UNIX)
    a.close()
    b.close()
attempt("unix_socketpair", _unix_pair)

# 7. writes inside the allowed path must still succeed.
attempt("write_allowed_path", open_rw(allowed_probe, "w"))

# 8. protected metadata names cannot be created inside the writable root
#    even though the root itself is writable (missing-path masks).
attempt("create_in_writable_root", open_rw(os.path.join(writable_root, ".env"), "x"))

# 9. the capability set must be empty (outer stage used --cap-drop ALL).
def _caps():
    with open("/proc/self/status") as fh:
        for line in fh:
            if line.startswith("CapEff:"):
                if set(line.split()[1].strip()) == {"0"}:
                    return
                raise RuntimeError("non-empty CapEff: " + line.strip())
    raise RuntimeError("CapEff not reported")
attempt("capabilities_empty", _caps)

# 10. deny-read masks must hide secrets (mode-000 mount => EACCES).
attempt("read_denied_secret", lambda: open(secret_probe).read())

# 11. seccomp deny list: each entry must fail with EPERM specifically.
results["ptrace_syscall"] = syscall_outcome(PTRACE_NR, 0, 0, 1, 0)
results["process_vm_readv_syscall"] = syscall_outcome(PVMR_NR, -1, 0, 0, 0, 0, 0)
results["io_uring_setup_syscall"] = syscall_outcome(IOURING_NR, 1, 0, 0)

print(json.dumps(results))
"""

_PROBE_CACHE: dict | None = None
_PROBE_LOCK = threading.Lock()


def bwrap_behavior_probe() -> dict:
    """Run the real two-stage pipeline with a network-off, read-only-root
    policy and verify every confinement expectation. Cached per process.

    Returns a dict:
      operational : bool  — every expectation held
      skipped     : str   — reason the probe could not run
      checks      : dict  — raw outcomes per probe name
    """
    global _PROBE_CACHE
    with _PROBE_LOCK:
        if _PROBE_CACHE is not None:
            return _PROBE_CACHE
        result = _run_bwrap_behavior_probe()
        _PROBE_CACHE = result
        return result


def _run_bwrap_behavior_probe() -> dict:
    if not IS_LINUX:
        return {"operational": False, "skipped": "not Linux", "checks": {}}
    if is_wsl1():
        return {"operational": False, "skipped": WSL1_BWRAP_WARNING, "checks": {}}
    bwrap = find_bwrap()
    if bwrap is None:
        return {"operational": False, "skipped": "bubblewrap not found on PATH", "checks": {}}
    if not user_namespaces_supported():
        return {"operational": False, "skipped": "user namespaces unavailable", "checks": {}}

    bridge_py = os.path.join(PROJECT_DIR, "bridge.py")
    rules_dir = os.path.join(PROJECT_DIR, "rules")
    if not os.path.isfile(bridge_py) or not os.path.isdir(rules_dir):
        return {"operational": False, "skipped": "probe run outside the project directory", "checks": {}}

    env_path = os.path.join(PROJECT_DIR, ".env")
    if os.path.exists(env_path):
        env_path = os.path.join(PROJECT_DIR, ".env.selftest-probe")
    rules_probe = os.path.join(rules_dir, ".selftest-probe")

    # Syscall numbers for the deny-list checks are architecture dependent.
    sysno_csv = ",".join(str(SYSNO[n]) for n in ("ptrace", "process_vm_readv", "io_uring_setup"))

    tmpdir = tempfile.mkdtemp(prefix="runtime-shield-selftest-")
    allowed_probe = os.path.join(tmpdir, "writable.txt")
    secret_probe = os.path.join(tmpdir, "secret.conf")
    try:
        with open(secret_probe, "w", encoding="utf-8") as fh:
            fh.write("TOPSECRET=selftest\n")
        # Network-off profile with a single writable root (the temp dir),
        # exactly like a default provider launch, plus one deny-read entry
        # so the secret-hiding masks are behaviorally verified too.
        profile = PermissionProfile.workspace_write(
            [tmpdir], network=False, deny_read_paths=[secret_probe],
        )
        probe_cmd = [
            sys.executable, "-c", _PROBE_CODE,
            bridge_py, rules_probe, env_path, allowed_probe,
            sysno_csv, tmpdir, secret_probe,
        ]
        helper_args = [
            "--sandbox-policy-cwd", PROJECT_DIR,
            "--command-cwd", PROJECT_DIR,
            "--permission-profile", json.dumps(profile.to_dict()),
            "--bwrap", bwrap,
            "--",
        ] + probe_cmd
        completed = subprocess.run(
            [sys.executable, os.path.abspath(__file__), "--helper"] + helper_args,
            capture_output=True, text=True, timeout=30,
        )
        checks = {}
        try:
            checks = json.loads(completed.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {
                "operational": False,
                "skipped": f"probe did not report results (exit={completed.returncode})",
                "checks": {},
                "stderr": (completed.stderr or "")[-400:],
            }

        operational = all(
            checks.get(name) == expected
            for name, expected in _PROBE_EXPECTATIONS.items()
        )
        if not operational:
            # Clean up anything a broken sandbox may have created.
            for path in (rules_probe, env_path, "/etc/runtime-shield-selftest"):
                try:
                    os.unlink(path)
                except OSError:
                    pass
        return {
            "operational": operational,
            "skipped": None,
            "checks": checks,
        }
    except subprocess.TimeoutExpired:
        return {"operational": False, "skipped": "behavior probe timed out", "checks": {}}
    except OSError as exc:
        return {"operational": False, "skipped": f"probe failed to start: {exc}", "checks": {}}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def bwrap_operational() -> bool:
    """True when the bubblewrap+seccomp backend is available AND a real
    sandboxed process verified every confinement expectation."""
    return bwrap_behavior_probe().get("operational") is True


# ─────────────────────────────────────────────────────────────────────────────
# JailFactory
# ─────────────────────────────────────────────────────────────────────────────

class JailFactory:
    """Dynamic factory for sandbox jailers.

    Selection order (strongest first):
      1. Inside a container        -> bubblewrap+seccomp if the behavioral
                                     probe passes inside the container
                                     (defense in depth: providers are
                                     sandboxed within the container too);
                                     otherwise ContainerSeccompJailer: the
                                     container boundary plus the exact Codex
                                     inner stage (no_new_privs, capability
                                     verification, per-provider seccomp),
                                     explicitly logged as CONTAINER — never
                                     a silent fallback, and never reported
                                     as a stronger sandbox than it is
      2. Windows host              -> WindowsJailer (Docker Desktop cannot
                                     bind-mount Windows paths for stdio MCP
                                     providers)
      3. Docker available          -> OpenSandboxJailer (container, optional
                                     gVisor runtime via OPENSANDBOX_*)
      4. Linux + bubblewrap usable -> BubblewrapJailer (namespaces + seccomp,
                                     behaviorally verified)
      5. Linux + nsjail            -> NSJailer
      6. Linux + landlock          -> LandlockJailer
      7. Anything else             -> RuntimeError (FAIL-CLOSED: refuse to
                                     run unsandboxed on a bare host)
    """

    @staticmethod
    def get_jailer(provider_name: str, cwd: str, env: dict, allowed_paths: list | None) -> BaseJailer:
        # When running inside a container, internal MCP servers run in the
        # same container as the bridge. Deliberate decision (documented in
        # the Dockerfile): first try to nest the bubblewrap+seccomp sandbox
        # INSIDE the container — Docker's default seccomp profile usually
        # denies unprivileged user namespaces, so the behavioral probe
        # decides. If it cannot run there, fall back to the container
        # boundary itself and say so explicitly: this is the CONTAINER tier
        # of isolation, not a stronger sandbox, and it is never silent.
        if os.path.exists("/.dockerenv") or os.getenv("DOCKER_CONTAINER", "false").lower() == "true":
            if IS_LINUX and bwrap_operational():
                log.info(
                    "🔒 [JailFactory] Inside a container AND bubblewrap+seccomp "
                    "passed its behavioral self-test there: providers are "
                    "sandboxed with namespaces + seccomp INSIDE the container "
                    "(defense in depth) for '%s'.",
                    provider_name,
                )
                return BubblewrapJailer(provider_name, cwd, env, allowed_paths)
            log.info(
                "🐳 [JailFactory] Inside a container: the container boundary is "
                "the filesystem isolation (CONTAINER tier), hardened with the "
                "Codex inner stage (no_new_privs + empty-capability check + "
                "per-provider network seccomp). This is the documented "
                "fallback, logged as CONTAINER, not as a stronger sandbox. "
                "To nest the bubblewrap sandbox inside the image, run Docker "
                "with a seccomp profile that permits unprivileged user "
                "namespaces. Provider: '%s'.",
                provider_name,
            )
            return ContainerSeccompJailer(provider_name, cwd, env, allowed_paths)

        # Docker Desktop's Linux containers cannot bind-mount Windows paths reliably
        # for stdio MCP providers; use the restricted Windows process jail instead.
        if sys.platform == "win32":
            return WindowsJailer(provider_name, cwd, env, allowed_paths)

        # 1. OpenSandbox is the primary cross-platform isolated runtime on host machines
        if shutil.which("docker"):
            return OpenSandboxJailer(provider_name, cwd, env, allowed_paths)

        # 2. Linux native tiers
        if IS_LINUX:
            # Bubblewrap + seccomp: behaviorally verified before use.
            if bwrap_operational():
                return BubblewrapJailer(provider_name, cwd, env, allowed_paths)
            if shutil.which("nsjail"):
                return NSJailer(provider_name, cwd, env, allowed_paths)
            if landlock:
                return LandlockJailer(provider_name, cwd, env, allowed_paths)

        # FAIL-CLOSED: no operational sandbox on a bare host.
        msg = (
            f"[JailFactory FAIL-CLOSED] No operational sandbox backend for "
            f"'{provider_name}' (checked: Docker, bubblewrap+seccomp, nsjail, "
            f"Landlock). Refusing host execution. Install Docker or bubblewrap."
        )
        log.error("🚫 %s", msg)
        raise RuntimeError(msg)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    argv = sys.argv[1:]
    if argv and argv[0] == "--helper":
        if not IS_LINUX:
            sys.stderr.write("linux sandbox helper is only supported on Linux\n")
            sys.exit(2)
        run_linux_sandbox_main(argv)
    elif argv and argv[0] == "--self-test":
        report = bwrap_behavior_probe()
        print(json.dumps(report, indent=2))
        if report.get("skipped"):
            sys.exit(2)
        sys.exit(0 if report.get("operational") else 1)
    else:
        sys.stderr.write(
            "usage: jail_factory.py --helper <sandbox flags> -- <command...>\n"
            "       jail_factory.py --self-test\n"
        )
        sys.exit(2)
