"""Test-only MCP stdio provider used to verify confinement end-to-end.

It is launched through the same bridge launch path as a real provider
(``bridge.launch_sandboxed_node`` -> ``JailFactory`` -> ``BubblewrapJailer``)
and attempts the escapes the sandbox must prevent. The pytest integration test
asserts the returned outcomes; this file is never listed in
``mcp-firewall.yaml`` and is not part of the deployed provider set.
"""

import errno
import json
import os
import socket
import sys

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE_DIR = os.environ.get(
    "SANDBOX_PROBE_WORKSPACE", os.path.join(PROJECT_DIR, "secure-experiment-zone")
)
SECRET_PATH = os.environ.get(
    "SANDBOX_PROBE_SECRET", os.path.join(PROJECT_DIR, "keycloak-tls", "sandbox-probe-secret.txt")
)


def _outcome(action):
    try:
        action()
        return "allowed"
    except OSError as exc:
        return "denied:" + errno.errorcode.get(exc.errno, str(exc.errno))
    except Exception:
        return "denied"


def _create(path, mode):
    handle = open(path, mode)
    handle.close()


def _socketpair():
    left, right = socket.socketpair(socket.AF_UNIX)
    left.close()
    right.close()


def _cap_effective():
    try:
        with open("/proc/self/status", encoding="ascii") as status:
            for line in status:
                if line.startswith("CapEff:"):
                    value = line.split()[1].strip()
                    return "empty" if set(value) == {"0"} else "nonempty:" + value
    except OSError:
        return "unknown"
    return "unknown"


def run_probe():
    project_probe = os.path.join(PROJECT_DIR, "sandbox-probe-escape.txt")
    workspace_probe = os.path.join(WORKSPACE_DIR, "sandbox-probe-ok.txt")
    results = {
        "project_write": _outcome(lambda: _create(project_probe, "x")),
        "workspace_write": _outcome(lambda: _create(workspace_probe, "w")),
        "workspace_protected_env": _outcome(
            lambda: _create(os.path.join(WORKSPACE_DIR, ".env"), "x")
        ),
        "etc_write": _outcome(lambda: _create("/etc/runtime-shield-sandbox-probe", "x")),
        "read_secret": _outcome(lambda: open(SECRET_PATH).read()),
        "read_shadow": _outcome(lambda: open("/etc/shadow").read()),
        "tcp_socket": _outcome(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()),
        "unix_socketpair": _outcome(_socketpair),
        "cap_eff": _cap_effective(),
    }
    for path in (project_probe, workspace_probe):
        try:
            os.unlink(path)
        except OSError:
            pass
    return results


def _reply(request_id, result=None, error=None):
    response = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        response["error"] = error
    else:
        response["result"] = result
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
        except ValueError:
            continue
        method = request.get("method")
        request_id = request.get("id")
        if method in ("initialize", "ping"):
            _reply(request_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sandbox-probe-provider", "version": "1.0.0"},
            })
        elif method in ("tools/list", "listTools"):
            _reply(request_id, {
                "tools": [{
                    "name": "SandboxProbe",
                    "description": "Test-only confinement probe.",
                    "inputSchema": {"type": "object", "properties": {}},
                }]
            })
        elif method in ("tools/call", "callTool"):
            tool = (request.get("params") or {}).get("name")
            if tool != "SandboxProbe":
                _reply(request_id, error={"code": -32601, "message": f"Unknown tool: {tool}"})
                continue
            _reply(request_id, {
                "content": [{"type": "text", "text": json.dumps(run_probe())}]
            })
        else:
            _reply(request_id, error={"code": -32601, "message": f"Unknown method: {method}"})


if __name__ == "__main__":
    main()
