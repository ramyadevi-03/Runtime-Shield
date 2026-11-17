# Runtime Shield + Credential Broker: Local Integration Test

This guide takes the copied Credential Broker and Runtime Shield from stopped containers to a brokered demo tool request and back. It uses only the local dummy upstream. Never provision a real GitHub credential for this test.

The broker and OpenBao have no host-published ports. The agent and gateway receive lease metadata, while only the egress service redeems the lease and uses the stored dummy value.

## Current verification status

- The broker Docker test target completed with **23 passed** in the current local setup.
- OpenBao KV v2 at `runtime-shield/` was enabled, and the broker, broker OPA, and OpenBao containers reported healthy.
- Runtime Shield's gateway started after the host directory `secure-experiment-zone/claude-desktop` was created.
- The complete Keycloak-authenticated LibreChat → gateway → broker → egress → dummy-upstream flow has **not yet been confirmed**.
- Gateway logs also showed the unrelated legacy database provider failing to create its database directory and the Keycloak administrative MCP child exiting without `KEYCLOAK_CLIENT_SECRET`. Do not pass the gateway's confidential JIT client secret into that child to suppress the error. These do not by themselves establish failure of the dedicated `github.read_repository` broker flow.

## Requirements and local files

Use Docker Engine with Docker Compose, Python 3.10 or newer, and this repository checked out on the intended development branch. From the repository root, create local environment files only if they do not already exist:

```sh
[ -f .env ] || cp .env.example .env
[ -f credential-broker/.env ] || cp credential-broker/.env.example credential-broker/.env
chmod 600 .env credential-broker/.env
```

Populate the blank values with development-only values. The following identity secrets must be at least 32 characters and distinct by role:

- `BROKER_DEV_AGENT_SECRET`: same value in both `.env` files.
- `BROKER_DEV_EGRESS_SECRET`: same value in both `.env` files.
- `BROKER_DEV_ADMIN_SECRET`: only in `credential-broker/.env`.
- `RUNTIME_SHIELD_EGRESS_EXECUTOR_TOKEN`: only in Runtime Shield `.env`.

`CREDS_KEY` must be 64 hexadecimal characters; `CREDS_IV` must be 32. Set `KEYCLOAK_HTTPS_KEY_STORE_PASSWORD` to at least 16 characters. The Keycloak helper scripts will write the actual `RUNTIME_SHIELD_JIT_CLIENT_SECRET` and `OPENID_CLIENT_SECRET`; do not treat synthetic placeholders as valid client credentials. `RUNTIME_SHIELD_MCP_CLIENT_SECRET` must match the Keycloak `runtime-shield-hitl` client. Leave `OPENBAO_ROLE_ID` and `OPENBAO_SECRET_ID` blank until you provision the AppRole below.

Keep `.env` files, Keycloak credentials, OpenBao root token/recovery shares, AppRole secret ID, and generated private keys out of Git. Never paste them into logs or support messages.

## Prepare certificates and Docker networks

If the generated files do not already exist, install the Runtime Shield Python requirements and generate the SPIFFE and local Keycloak certificates:

```sh
python -m pip install -r requirements.txt
python generate_certs.py
python generate_keycloak_tls.py
```

The root Compose project declares `dokploy-network` as external. Create it only if it is missing:

```sh
docker network inspect dokploy-network >/dev/null 2>&1 || docker network create dokploy-network
```

On Linux, if `getent hosts host.docker.internal` returns nothing, add a host-side name so the browser can reach Keycloak at the same canonical URL used in issued tokens:

```sh
echo '127.0.0.1 host.docker.internal' | sudo tee -a /etc/hosts
```

Runtime Shield Compose maps `host.docker.internal` to Docker's host gateway for the gateway and LibreChat containers. Keep the Keycloak URL, issuer, JWKS URL, and token URL aligned with `https://host.docker.internal:8443`. The local certificate authority is `keycloak-tls/root-ca.pem`; your browser may require trusting it or accepting the local development certificate warning.

## Start and configure the Credential Broker

From the broker directory:

```sh
cd credential-broker
docker compose up --build -d openbao
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao status
```

The Compose health check only proves OpenBao responds; it can still be sealed. For a new volume, initialize it **once** only when status says `Initialized: false`:

```sh
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao operator init -key-shares=5 -key-threshold=3
```

Save the recovery shares and root token in a secure offline location. Do not paste them into `.env`. If status says `Sealed: true`, unseal with three different shares, one command at a time:

```sh
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao operator unseal
```

Authenticate as operator interactively:

```sh
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao login
```

Enter the root token at the prompt. Inspect the mounts:

```sh
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao secrets list -format=json
```

If `runtime-shield/` already exists as KV v2, leave it as is. Only if absent, enable it:

```sh
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao secrets enable -path=runtime-shield -version=2 kv
```

Install the broker policy and check whether AppRole is enabled:

```sh
docker compose exec -T -e BAO_ADDR=http://127.0.0.1:8200 openbao bao policy write credential-broker - < docker/credential-broker-policy.hcl
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao auth list -format=json
```

If the auth list does not contain `approle/`, enable it:

```sh
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao auth enable approle
```

Create or update the restricted broker role and generate its credentials:

```sh
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao write auth/approle/role/credential-broker token_policies=credential-broker token_ttl=1h token_max_ttl=4h secret_id_ttl=0 secret_id_num_uses=0
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao read auth/approle/role/credential-broker/role-id
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao write -f auth/approle/role/credential-broker/secret-id
```

Put the generated role ID and secret ID in `OPENBAO_ROLE_ID` and `OPENBAO_SECRET_ID` in `credential-broker/.env`. Keep the secret ID private. Then start the broker and OPA:

```sh
docker compose up --build -d
docker compose ps
```

Wait for broker, OPA, and OpenBao to show healthy. After an OpenBao restart, check `bao status` and unseal again if needed.

## Provision and test the dummy credential

This command writes only the explicit local dummy value under `github-production`. It prints the HTTP status, not the credential:

```sh
docker compose exec broker python -c 'import asyncio,httpx,os; token="admin:local-admin:admin-cli:"+os.environ["BROKER_DEV_ADMIN_SECRET"]; r=asyncio.run(httpx.AsyncClient().put("http://127.0.0.1:8000/v1/admin/credentials/github-production",headers={"Authorization":"Bearer "+token},json={"value":{"api_key":"local-dummy-github-token"}})); print("HTTP",r.status_code); r.raise_for_status()'
```

Expected result: `HTTP 204`. A command that prints nothing does not confirm success; check the HTTP status. Run the broker lifecycle/concurrency/failure tests:

```sh
docker compose --profile test run --build --rm test
```

The currently reported result is `23 passed`. The tests use fake vault/policy adapters for lifecycle and concurrency behavior; they are not the live Runtime Shield end-to-end test.

## Configure Keycloak

From the repository root, start Keycloak:

```sh
cd ..
docker compose up -d keycloak
docker compose ps keycloak
```

Open `https://host.docker.internal:8443` and sign in with `KEYCLOAK_ADMIN_USERNAME` and `KEYCLOAK_ADMIN_PASSWORD` from the local Runtime Shield `.env`.

In the `master` realm:

1. Create or verify an OpenID Connect client named `runtime-shield-hitl`.
2. Enable client authentication and Standard flow. Set its valid redirect URI to `http://localhost:3080/api/mcp/runtime-shield-hitl/oauth/callback` and web origin to `http://localhost:3080`.
3. In the client’s Credentials page, copy its secret into `RUNTIME_SHIELD_MCP_CLIENT_SECRET` in the root `.env`. Do not share it.
4. Create the `repository:read` OpenID Connect client scope if it does not already exist.
5. Create a normal test user in Keycloak and set a non-temporary password.

Run the two setup helpers from the repository root. The first creates/configures the LibreChat login client; the second configures the JIT exchange client, scope associations, and requester audience mappers:

```sh
env KEYCLOAK_URL=https://host.docker.internal:8443 KEYCLOAK_REALM=master KEYCLOAK_CLIENT_ID=admin-cli python configure_keycloak.py --librechat-oidc-only
env KEYCLOAK_URL=https://host.docker.internal:8443 KEYCLOAK_REALM=master KEYCLOAK_CLIENT_ID=admin-cli python configure_keycloak.py --jit-only
```

These helpers update `OPENID_CLIENT_SECRET`, `RUNTIME_SHIELD_JIT_CLIENT_SECRET`, and related issuer settings in the root `.env`. Do **not** run `python configure_keycloak.py` without a mode: the current main setup path sets the `admin` user's password to the literal `admin`.

## Start Runtime Shield and run the end-to-end request

Ensure `secure-experiment-zone/claude-desktop` exists on the host before starting the gateway because that host directory is mounted read-only:

```sh
mkdir -p secure-experiment-zone/claude-desktop
```

Start or recreate the Runtime Shield stack so it loads the configured Keycloak values:

```sh
docker compose up --build -d
docker compose ps
```

Check that the gateway stays `Up`, LibreChat is `Up`, and the broker remains healthy (check it from `credential-broker/` with `docker compose ps`).

1. Open the dashboard at `http://localhost:9090` and authenticate as an administrator.
2. Open LibreChat at `http://localhost:3080`, sign in with the Keycloak test user, and enable the **Runtime Shield HITL** MCP server.
3. Ask the assistant to call `github.read_repository` for `runtime-shield/demo`.
4. Approve the pending request in the Runtime Shield dashboard.
5. Confirm the result contains the dummy repository listing. It must not contain `local-dummy-github-token`; that value must not appear in agent output, gateway output, or MCP responses.

Try a repository other than `runtime-shield/demo` as a negative check; it must be rejected. No real GitHub API call is made. The trusted tool mapping sends this request only to `dummy-upstream`.

To pause or resume both Compose projects, use the stop/start commands below. Do not use `docker compose down -v`; volumes contain the OpenBao file store and SQLite lease metadata.

## Stop and resume without deleting data

Stop Runtime Shield, then stop the broker stack:

```sh
# From Runtime-Shield/
docker compose stop
cd credential-broker
docker compose stop
```

To resume, start the broker stack first. OpenBao may need manual unsealing after it starts:

```sh
# From Runtime-Shield/credential-broker/
docker compose up -d
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 openbao bao status
```

If sealed, unseal it with three different saved shares. Then start Runtime Shield:

```sh
# Return to Runtime-Shield/
cd ..
docker compose up -d
```

`docker compose stop` preserves containers and named volumes. Never remove the named volumes during routine testing.

## Push changes on the current branch

The working branch for this copy is `vault-implementation`. From `Runtime-Shield/`, check the branch and review the staged file list before committing:

```sh
git branch --show-current
git status --short
git add -A
git diff --cached --check
git diff --cached --stat
```

Confirm the branch is `vault-implementation`, `.env` files and generated secrets are not staged, and the staged changes are intended. Then commit and push only that branch:

```sh
git commit -m "Integrate credential broker with Runtime Shield"
git push -u origin vault-implementation
```

These commands do not switch to or push `main`. Do not use `git push origin main`.
