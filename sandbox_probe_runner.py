"""Test helper: launch sandbox_probe_mcp.py through bridge.launch_sandboxed_node.

The bridge's real JIT/policy path is exercised by test_sandbox_security.py; this
runner isolates the process-launch path because importing bridge.py redirects
the process stdout to stderr. It forces the bubblewrap jailer so the test is
deterministic on hosts that also have Docker installed.
"""

import json
import os
import sys

import bridge
from jail_factory import BubblewrapJailer

workspace = os.environ["SANDBOX_PROBE_WORKSPACE"]
secret = os.environ["SANDBOX_PROBE_SECRET"]

probe_env = {
    key: os.environ[key]
    for key in ("PATH", "SANDBOX_PROBE_WORKSPACE", "SANDBOX_PROBE_SECRET")
    if key in os.environ
}
probe_env.update({
    "LOCAL_DEV_MODE": "false",
    "SPIFFE_ENABLED": "false",
    "PROVIDER_NAME": "filesystem-provider",
})

cmd = [sys.executable, os.path.join(bridge.PROJECT_DIR, "sandbox_probe_mcp.py")]
jailer = BubblewrapJailer(
    "filesystem-provider", bridge.PROJECT_DIR, probe_env, [workspace]
)
original_get_jailer = bridge.JailFactory.get_jailer
bridge.JailFactory.get_jailer = staticmethod(lambda *args, **kwargs: jailer)
try:
    proc = bridge.launch_sandboxed_node(
        cmd,
        cwd=bridge.PROJECT_DIR,
        env=probe_env,
        allowed_paths=[workspace],
        provider_name="filesystem-provider",
    )
    try:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "SandboxProbe", "arguments": {}},
        }
        proc.stdin.write(json.dumps(request) + "\n")
        proc.stdin.flush()
        response_line = proc.stdout.readline()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except Exception:
            proc.kill()
finally:
    bridge.JailFactory.get_jailer = original_get_jailer

if not response_line.strip():
    raise SystemExit("sandbox probe returned no response")
response = json.loads(response_line)
# bridge.py redirects sys.stdout to stderr on import; write the probe result to
# the real fd 1 so the test can parse it.
os.write(1, (response["result"]["content"][0]["text"] + "\n").encode("utf-8"))
