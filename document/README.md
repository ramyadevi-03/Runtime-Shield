# Runtime Shield: intern clone and workshop guide

This is the single starting guide for a new intern cloning this repository. It
covers local setup, first launch, Keycloak login, a safe HITL write, validation,
and cleanup. Use a disposable local clone; do not treat this workshop setup as
a production deployment.

## What this checkout runs

The Windows workshop launcher starts a local Docker Compose stack containing
Keycloak, the Runtime Shield gateway, the filesystem provider, LibreChat, and
supporting services. The HITL file-write demonstration requires an administrator
to approve the request before the dedicated filesystem provider writes a file
under `secure-experiment-zone/`.

The demo filesystem provider uses Docker `runc` with restrictive container
settings. This is not gVisor. Other high-risk operations retain their existing
sandbox requirements and fail closed if the required sandbox is unavailable.
Do not present the workshop write as proof that gVisor is active.

## Prerequisites

- Git.
- Docker Desktop with the **Linux** container engine and Docker Compose.
- Python 3.10 or later.
- Windows PowerShell for the one-command launcher below.
- A model-provider API key only if the selected model requires one.

Allow several minutes for the first Docker image build.

## 1. Clone the repository

The destination repository is private. Before cloning, ask a maintainer to grant
your GitHub account access to `rise-research-labs/Agentic-AI-Security`, then
sign in with GitHub CLI (`gh auth login`) or the Git Credential Manager prompt
used by Git for Windows. Do not put a GitHub password or personal access token
in the clone URL, README, or chat.

Clone the workshop branch directly:

```powershell
git clone --branch feature/agentic-security-controls --single-branch https://github.com/rise-research-labs/Agentic-AI-Security.git
Set-Location Agentic-AI-Security
```

Run all following commands from the cloned repository root. This branch is the
sanitized copy intended for onboarding; do not clone a developer's personal
workspace or copy their `.env`.

## 2. Create local configuration

Copy the safe template. The populated `.env` is local-only and must never be
committed or pasted into chat, tickets, or logs.

```powershell
Copy-Item .env.example .env
```

Edit `.env` and set unique values for:

- `KEYCLOAK_ADMIN_USERNAME` — defaults to `admin` in `.env.example`.
- `KEYCLOAK_ADMIN_PASSWORD` — a strong, unique password for this fresh local
  Keycloak database.
- `KEYCLOAK_HTTPS_KEY_STORE_PASSWORD` — at least 16 characters.
- `JWT_SECRET`, `JWT_REFRESH_SECRET`, and `OPENID_SESSION_SECRET`.
- `CREDS_KEY` — 64 hexadecimal characters; `CREDS_IV` — 32 hexadecimal
  characters.
- `RUNTIME_SHIELD_JIT_CLIENT_SECRET`.
- `RUNTIME_SHIELD_MCP_CLIENT_SECRET` and `OPENID_CLIENT_SECRET` after creating
  their corresponding Keycloak clients (see [Keycloak setup](#5-set-up-keycloak-login)).

Use a password manager or a secure local generator for secrets. Do not copy
admin credentials from another developer's machine. The workshop's current
local admin password is intentionally not recorded in this tracked guide.
If a value contains `$`, quote the value in `.env` so Compose treats it
literally. Compose requires non-empty client-secret values before the first
launch; use unique temporary local values for `RUNTIME_SHIELD_JIT_CLIENT_SECRET`,
`RUNTIME_SHIELD_MCP_CLIENT_SECRET`, and `OPENID_CLIENT_SECRET` if you have not
created the clients yet. Replace them with the matching Keycloak client
credentials before testing OAuth or JIT.

The launcher generates `RUNTIME_SHIELD_GATEWAY_API_KEY` and
`RUNTIME_SHIELD_FS_PROVIDER_TOKEN` if they are blank, then saves them in the
ignored `.env`. Do not replace these generated values on a running stack without
reconfiguring both the gateway and provider.

## 3. Generate local development certificates

Install the Python dependencies and generate the local Keycloak TLS files:

```powershell
python -m pip install -r requirements.txt
python .\generate_keycloak_tls.py
```

Generate fresh workload certificates for this disposable clone:

```powershell
python .\generate_certs.py
```

`generate_keycloak_tls.py` creates ignored local files in `keycloak-tls/` and
refuses to overwrite existing output. `generate_certs.py` writes development
certificates and private keys under `spire/certs/`; those generated files are
ignored by Git. Never force-add or commit the generated private keys. They are
local development certificates, not proof that SPIRE issued an SVID.

## 4. Start the stack

Run the launcher from PowerShell:

```powershell
.\start_librechat_demo.ps1
```

On a clean clone this builds and starts the Compose stack and opens:

| Service | Local URL |
|---|---|
| LibreChat | `http://localhost:3080` |
| Runtime Shield dashboard | `http://localhost:9090` |
| Keycloak admin console | `https://localhost:8443` |
| Gateway | `http://localhost:5001` |

The local Keycloak certificate is self-signed. Trust the generated
`keycloak-tls/root-ca.pem` on your development machine if the browser or
LibreChat rejects the login certificate; do not disable TLS verification as a
workaround.

The Compose file publishes several service ports on all host interfaces,
including Keycloak HTTPS. Run this stack only on a trusted development machine
with appropriate firewall protection; do not expose it to the internet.

Keycloak reads its bootstrap administrator credentials only when initializing
an empty data volume. Editing `.env` later does not reset an existing Keycloak
account; change an existing password in Keycloak itself.

## 5. Set up Keycloak login

Use the fresh local Keycloak administrator credentials from your `.env` to
sign in to the `master` realm. Create a separate requester account for
LibreChat and keep administrator access separate.

Create the `runtime-shield-hitl` OpenID Connect client for LibreChat MCP OAuth:

1. Enable **Client authentication** and **Standard flow**.
2. Set the redirect URI to
   `http://localhost:3080/api/mcp/runtime-shield-hitl/oauth/callback`.
3. Set the Web Origin to `http://localhost:3080`.
4. Save the client secret to `RUNTIME_SHIELD_MCP_CLIENT_SECRET` in `.env`.

Configure the dedicated LibreChat browser-login client and save its secret into
`.env` using the targeted setup mode:

```powershell
$env:KEYCLOAK_URL = "http://127.0.0.1:8083"
$env:KEYCLOAK_REALM = "master"
$env:KEYCLOAK_CLIENT_ID = "admin-cli"
python .\configure_keycloak.py --librechat-oidc-only
Remove-Item Env:KEYCLOAK_URL, Env:KEYCLOAK_REALM, Env:KEYCLOAK_CLIENT_ID
```

The targeted mode configures LibreChat OIDC without resetting user passwords.
Do **not** run `python .\configure_keycloak.py` without a targeted option on a
shared or valuable Keycloak database: the full setup path changes demo account
passwords. After changing `.env`, rerun the launcher so the services receive
the updated values.

Configure the JIT exchange client separately, using the same local admin
environment:

```powershell
python .\configure_keycloak.py --jit-only
```

This targeted mode configures JIT exchange and does not reset demo-user
passwords. Keep the matching client secret in `.env`; do not paste it into the
guide or source control.

## 6. Run the HITL file-write demonstration

1. Open LibreChat and sign in with the requester account using **Continue with
   OpenID**.
2. In a chat, attach the **Runtime Shield HITL** MCP server and enable its
   `write_file` tool. A configured server is not automatically enabled for
   every chat.
3. Open the dashboard at `http://localhost:9090`. In **Admin approval access**,
   sign in with the Keycloak administrator credentials from this clone's `.env`.
4. Submit this harmless prompt in LibreChat:

   > Use the Runtime Shield `write_file` tool to create
   > `secure-experiment-zone/intern-hitl-demo.txt` with exactly this content:
   > `HITL approval test`

5. Confirm the request is **PENDING** in the dashboard's approval queue, then
   approve that request.
6. Confirm the tool reports success and verify the resulting local file:

   ```powershell
   $target = ".\secure-experiment-zone\intern-hitl-demo.txt"
   if (-not (Test-Path $target)) { throw "Expected file was not created." }
   [System.IO.File]::ReadAllText((Resolve-Path $target))
   Get-FileHash $target -Algorithm SHA256
   ```

The dedicated provider only accepts a direct `.txt` child of
`secure-experiment-zone/`, refuses to overwrite an existing file, and limits
content to 4096 UTF-8 bytes. Choose a new filename for each run. A request that
does not pass the HITL and provider checks must not be described as executed.

For a blocked request, confirm the tool returned HTTP 503, the dashboard shows
`sandbox_block`, and the target file is absent. A pending approval or an
approval alone is not evidence that an operation executed.

## 7. Check services, tests, and stop the stack

Check Compose service status:

```powershell
docker compose -f docker-compose.yml -f docker-compose.librechat-demo.yml ps
```

Run the focused gateway and workshop tests (if `pytest` is installed in your
Python environment):

```powershell
python -m pytest -q -p no:cacheprovider test_workshop_sandbox.py test_sandbox_security.py test_gateway_auth.py
```

Stop this clone's Compose stack when finished:

```powershell
docker compose -f docker-compose.yml -f docker-compose.librechat-demo.yml down
```

This stops and removes the Compose containers and network but preserves named
volumes. Do not add `-v` unless you intentionally want to delete this clone's
Keycloak, MongoDB, and LibreChat data.

## Troubleshooting

- **Docker is unavailable:** Start Docker Desktop, select the Linux engine, and
  rerun the launcher.
- **Compose reports a missing variable:** Check required entries in `.env`;
  never paste the file into a support request.
- **Keycloak login fails:** Confirm the selected Keycloak instance and use the
  current account password. Changing the bootstrap password in `.env` does not
  change an account in an initialized data volume.
- **No approval appears:** Confirm the MCP server and `write_file` tool are
  attached to the current chat, and that LibreChat is signed in as a requester.
- **Approved write returns HTTP 503:** Check the dashboard for `sandbox_block`.
  The gateway is fail-closed when its required sandbox is unavailable; do not
  disable the enforcement check to make the demo pass.
- **The target already exists:** Verify its contents, then choose a new filename
  or remove only that specific test file after the demo.

## Repository safety

- Keep `.env`, generated TLS files, generated SPIFFE private keys, runtime
  configs, logs, telemetry databases, and demo outputs out of commits.
- Before sharing or deploying a clone, resolve the tracked private-key issue
  described above.
- Do not use the demo admin password for any shared or internet-accessible
  service. Use a unique strong credential and restrict network exposure.
- This guide documents a local workshop workflow, not production readiness.
