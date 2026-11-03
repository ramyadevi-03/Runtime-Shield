# Runtime Shield HITL + Docker workshop demo

This runbook uses a separate staging gateway and a dedicated Docker `runc`
filesystem provider. It does not change the existing gateway or delete Docker
volumes. Only the exact `write_file` request below is routed to this provider;
other high-risk operations retain their existing sandbox policy.

## Validation status and scope

The provider container has been inspected and independently exercised. It runs
as UID 10001 with `runc`, a read-only root filesystem, no privileges or
capabilities, `no-new-privileges`, seccomp, an internal network without a
default route, and one writable mount: `secure-experiment-zone/`. It has no
Docker socket. The provider reported the same restrictions from inside its
container. The target file was absent at the last check.

The new staging route has **not** yet completed an end-to-end rehearsal. An
earlier LibreChat call reached the old gateway and returned 503 because that
gateway required unavailable gVisor. The admin-cli test token also lacks a
requester subject and correctly receives HTTP 401 before a pending request is
created. Do not treat either result as successful execution or weaken
authentication.

## One-time staging setup

Run commands from the repository root in PowerShell. The staging containers
are separate from `gateway_mcp` and `runtime-shield-workshop-2`:

| Component | Address |
|---|---|
| LibreChat | `http://localhost:3080` |
| Staging HITL dashboard | `http://localhost:9091/` |
| Staging gateway MCP endpoint | `http://localhost:5003/mcp/runtime-shield` |
| Filesystem provider | Private Docker network only |

The workshop LibreChat config now targets the staging network alias
`gateway-workshop-next`; the original `librechat.yaml` remains untouched. The
chatbot container is already using `docker-compose.librechat-demo.yml`. The
launcher saves the shared filesystem-provider token in the Git-ignored `.env`
and, when it detects the staging gateway/provider, updates the local LibreChat
config and restarts only the chatbot. This preserves gateway containers and
MongoDB/upload volumes:

```powershell
.\start_librechat_demo.ps1
```

If you are starting this stack from a clean environment instead, the launcher
builds the Compose stack and opens LibreChat at port 3080 and the dashboard at
port 9090. On this already-running workshop setup, it reuses the staging
gateway/provider and opens the staging dashboard at port 9091.

To manually start only the staging services if they are stopped:

```powershell
docker start runtime-shield-workshop-gateway-next runtime-shield-filesystem-provider
```

Confirm the containers and target state before each rehearsal:

```powershell
docker inspect runtime-shield-workshop-gateway-next --format 'status={{.State.Status}}'
docker inspect runtime-shield-filesystem-provider --format 'status={{.State.Status}} health={{.State.Health.Status}} runtime={{.HostConfig.Runtime}} uid={{.Config.User}} privileged={{.HostConfig.Privileged}} readonly={{.HostConfig.ReadonlyRootfs}}'
docker inspect runtime-shield-filesystem-provider --format '{{range .Mounts}}{{println .Destination "rw=" .RW}}{{end}}'
docker exec runtime-shield-filesystem-provider python -c "import filesystem_provider as p; print(p.provider_identity())"
if (Test-Path .\secure-experiment-zone\hitl-demo-approved.txt) {
    throw "The demo target already exists; verify it and reset it before continuing."
}
```

The provider mount listing must show only
`/workspace/secure-experiment-zone rw=True`. Its identity must report Docker
`runc`, UID 10001, read-only root filesystem, empty capabilities,
`no_new_privs`, seccomp mode 2, and no default route. Do not continue if a
check fails.

Open the dashboard and sign in under **Admin approval access** as the
Keycloak administrator. In another tab, sign in to LibreChat using **Continue
with OpenID** as a normal requester. If LibreChat has a stale OpenID session,
sign out and repeat that normal login. Do not use the admin-cli password grant
for the requester.

## Demo 1 - approval followed by verified Docker execution

**Exact LibreChat prompt**

> Use the Runtime Shield `write_file` tool to create
> `secure-experiment-zone/hitl-demo-approved.txt` with exactly this content:
> `Runtime Shield HITL and Docker sandbox execution successful`

The provider route is deliberately an exact-match exception. If the tool call
changes the path or content, the normal high-risk sandbox policy applies and
the operation remains blocked.
The gateway preserves this exact known demo phrase during PII filtering to
avoid false-positive substitutions; all other content remains subject to the
normal redaction rules.

**Before submitting**

In the active LibreChat conversation, open **+ / Attach and tools** →
**MCP Servers** and select **Runtime Shield HITL**. Complete the OpenID
connection if LibreChat prompts, and confirm the server is connected and its
`write_file` tool is enabled for this chat. A configured MCP server is not
automatically attached to every conversation. If using a LibreChat agent,
enable the same server and tool in that agent's tool settings. This workshop
setup has no saved agent by default, so a regular chat with the MCP tool
attached is the shortest path.

If the server list fails to load or LibreChat reports HTTP 401, sign out and
sign back in through **Continue with OpenID**, then reconnect the MCP server.
Do not disable authentication or substitute the admin-cli token.

**Steps**

1. Submit the prompt in LibreChat. Confirm the HITL request appears as
   **PENDING** in the dashboard. Do not approve a different path or content.
   If LibreChat responds HTTP 400 saying to enable/select the tool, no MCP tool
   was attached to that chat; fix the selection and resubmit. That response
   occurs before HITL and is not a sandbox failure.
   The `pending` row in **Live Audit** is an audit event, not the approval
   control. The separate **HITL Pending Approval Queue** appears in
   **Admin approval access** after a valid admin sign-in. If it is missing,
   check the sign-in status and reauthenticate if the admin session expired.
2. Click **Approve** for this request promptly. The current default HITL
   timeout is 180 seconds; an expired request is denied and must be resubmitted.
3. Wait for the tool response. The gateway checks the provider's signed
   identity response before sending the write. The provider creates the file
   exclusively, reads it back, and signs the verified result.
4. Verify the exact file bytes from the repository root:

```powershell
$target = ".\secure-experiment-zone\hitl-demo-approved.txt"
$expected = "Runtime Shield HITL and Docker sandbox execution successful"
if (-not (Test-Path $target)) { throw "Expected file was not created." }
$actual = [System.IO.File]::ReadAllText((Resolve-Path $target))
if ($actual -cne $expected) { throw "File content does not match exactly." }
Get-FileHash $target -Algorithm SHA256
```

**Expected tool result**

The tool returns a success message that identifies
`secure-experiment-zone/hitl-demo-approved.txt` and the verified Docker `runc`
provider. The file contains exactly the requested text, without an added
newline.

**Dashboard evidence**

In the Live Audit feed, find events for the same `write_file` request:

- `pending`, stage `hitl-approval`
- `approve`, stage `hitl-approval`
- `sandbox_verified`, with `required_sandbox: docker`,
  `docker_runtime: runc`, `actual_execution_environment: docker`, and the
  provider container ID/restriction fields
- `allow`, stage `sandbox-execution`, with `execution_success: true`,
  `execution_outcome: success`, and the requested resource path

The success event is emitted only after the provider's signed write and
read-back confirmation, not merely because approval or Docker availability was
observed.

**Participant explanation**

> “The administrator approved the request, but approval did not bypass the
> sandbox. Runtime Shield verified the dedicated restricted Docker provider,
> then recorded success only after that provider created and verified the
> exact file.”

## Demo 2 - approval followed by fail-closed sandbox failure

Run this after Demo 1, so the exact target can first be verified and then
removed. This test deliberately stops only the dedicated provider container.

```powershell
$target = ".\secure-experiment-zone\hitl-demo-approved.txt"
if (-not (Test-Path $target)) { throw "Verify Demo 1 before resetting its file." }
Remove-Item -LiteralPath $target
if (Test-Path $target) { throw "Could not reset the demo target." }
docker stop runtime-shield-filesystem-provider
```

Submit the **same exact prompt from Demo 1** in LibreChat and approve its
PENDING request in the dashboard.

**Expected result**

- The gateway returns **HTTP 503 Service Unavailable** with
  `Sandbox unavailable: high-risk action blocked after HITL approval.`
- The dashboard records `sandbox_block`, stage `sandbox-enforcement`,
  `hitl_decision: approve`, `required_sandbox: docker`,
  `execution_decision: blocked_sandbox_unavailable`, and
  `actual_execution_environment: none`.
- `Test-Path .\secure-experiment-zone\hitl-demo-approved.txt` remains `False`.
  No `sandbox_verified` or successful execution event should appear for this
  blocked request.
- If the LibreChat tool view hides the numeric status, inspect the staging
  gateway response/log for the request; do not infer HTTP 503 from the missing
  file alone.

Restore the provider after the blocked request:

```powershell
docker start runtime-shield-filesystem-provider
```

**Participant explanation**

> “Human approval authorizes intent, not execution without isolation. When the
> required provider is unavailable, Runtime Shield returns 503, records
> `sandbox_block`, and does not create the file.”

## Reset and rollback

After confirming the successful file's content and audit events, remove only
the named workshop file if you want to reset the demo:

```powershell
Remove-Item -LiteralPath .\secure-experiment-zone\hitl-demo-approved.txt
docker start runtime-shield-filesystem-provider
```

The original LibreChat config at `librechat.yaml` was not edited. To restore
the previous workshop endpoint setting, change the three
`gateway-workshop-next:5001` references in `librechat.runtime.yaml` back to
`gateway:5001`, then restart the chatbot:

```powershell
$path = ".\librechat.runtime.yaml"
$config = [System.IO.File]::ReadAllText((Resolve-Path $path))
$config = $config.Replace("gateway-workshop-next:5001", "gateway:5001")
[System.IO.File]::WriteAllText(
    (Resolve-Path $path),
    $config,
    [System.Text.UTF8Encoding]::new($false)
)
docker restart chatbot_mcp
```

The workshop gateway, original gateway containers, provider, MongoDB and
upload volumes, and dashboard telemetry are not removed by these steps.
