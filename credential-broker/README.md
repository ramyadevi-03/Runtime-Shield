# Runtime Shield Credential Broker

Standalone FastAPI broker using OpenBao KV v2 for stored credentials, SQLite for lease metadata, and OPA for authorization. Agent requests receive opaque lease metadata. Secret-bearing redemption is limited to the separately authenticated egress workload.

## Local development stack

This Compose file is development-only. OpenBao runs a standard server with file-backed storage on the `openbao-data` named volume. It uses HTTP only on the private Compose network; the broker has no host-published port. The broker keeps its SQLite database in the separate `broker-data` volume. No root token, unseal key, or AppRole secret ID is stored in Compose or the image. The broker joins isolated control and redemption networks shared with Runtime Shield; only the broker and dedicated egress service are attached to the redemption network.

Production startup rejects development authentication, local policy mode, static `OPENBAO_TOKEN` authentication, and local/non-HTTPS OPA endpoints. Production requires an HTTPS OPA service, signed JWT identities, TLS, private networking, protected audit storage, and a separately managed OpenBao deployment. Configure production auto-unseal with a KMS or equivalent secure key-management system; do not use hardcoded unseal environment variables.

Production JWT validation uses `JWT_ISSUER`, `JWT_PUBLIC_KEY`, and `JWT_ALGORITHM`. Tokens must have the exact configured issuer, one of the role-specific audiences (`credential-broker-agent`, `credential-broker-admin`, or `credential-broker-egress`), and non-empty `sub`, `exp`, `iat`, `workload_id`, and `roles` claims. The role list must match the endpoint role. Issue egress audience/role only to the separately attested egress workload; never reuse an agent token for redemption. This starter accepts a configured public key rather than discovering JWKS, so production key rotation must be coordinated with the verifier or replaced with an approved JWKS integration.

Copy the environment template and start OpenBao first. `OPENBAO_ROLE_ID` and `OPENBAO_SECRET_ID` are filled after the operator configures AppRole below; keep the secret ID in the ignored `.env` file or another protected local secret store. Python packages come from the explicit `PYTHON_PACKAGE_INDEX` setting (PyPI by default); set it to an approved mirror before building if needed. Avoid embedding credentials in this URL or build arguments.

```sh
cp .env.example .env
docker compose up --build -d openbao
```

The OpenBao data volume is prepared for the image's non-root UID 100. The server is not initialized or unsealed automatically. Its health check accepts a responding sealed or unsealed server; the broker will not be able to access secrets until OpenBao is unsealed and configured. `data-init` assigns the existing SQLite volume to UID/GID 10001. Start the remaining services after setup:

```sh
docker compose up --build -d
```

OpenBao and OPA ports are not published on the host.

### First-time OpenBao setup

Run initialization once for a new data volume. OpenBao prints the initial root token and unseal shares to this terminal. Save them in an approved password manager or other encrypted offline store outside this repository. Do not paste them into `.env`, shell scripts, tickets, or routine logs. The root token is for operator administration; the broker uses only AppRole.

```sh
docker compose exec openbao bao operator init -key-shares=5 -key-threshold=3
```

Do not run `operator init` again for an initialized volume. Check its state with `docker compose exec openbao bao status`. To unseal after each restart, run the following command three times, entering a different retained share at the prompt each time (the key is not placed in shell history):

```sh
docker compose exec openbao bao operator unseal
```

After unsealing, authenticate as an operator interactively. This keeps the root token out of the command line and shell history:

```sh
docker compose exec openbao bao login
```

Enter the retained root token at the prompt. Do not put it in Compose configuration. Root credentials should be used only for this setup and controlled administration.

### KV v2 mount and broker AppRole

Inspect mounts before changing anything:

```sh
docker compose exec openbao bao secrets list -format=json
```

If `runtime-shield/` is absent, enable KV v2 at that path:

```sh
docker compose exec openbao bao secrets enable -path=runtime-shield -version=2 kv
```

If it already exists, verify its type is `kv` and `options.version` is `2`; leave an existing compatible mount and its contents intact. Stop if the path exists with another type or version. Never disable/recreate the mount as a repair step. Credential paths remain `runtime-shield/data/credentials/{alias}`.

Install the narrowly scoped policy. It grants only credential data create/read/update/delete operations; the broker does not need mount, policy, auth, or metadata administration:

```sh
docker compose exec -T openbao bao policy write credential-broker - < docker/credential-broker-policy.hcl
```

Enable AppRole only if it is not already enabled (`bao auth list` shows enabled methods), then create or update the broker role to use only this policy:

```sh
docker compose exec openbao bao auth enable approle
docker compose exec openbao bao write auth/approle/role/credential-broker token_policies=credential-broker token_ttl=1h token_max_ttl=4h secret_id_ttl=0 secret_id_num_uses=0
docker compose exec openbao bao read auth/approle/role/credential-broker/role-id
docker compose exec openbao bao write -f auth/approle/role/credential-broker/secret-id
```

The last two commands display a role ID and a secret ID to the operator terminal. Put them in the corresponding `OPENBAO_ROLE_ID` and `OPENBAO_SECRET_ID` entries in the ignored `.env` file, protect that file, then restart the broker so it reads the new values:

```sh
docker compose up -d --force-recreate broker
```

The role's token is limited to the credential data path. The secret ID is long-lived for this local development example so the broker can renew authentication after restarts; rotate it when needed and keep it outside source control. Production should use the organization's AppRole issuance and rotation practices.

When OpenBao is already configured and unsealed, `docker compose up --build -d` starts the broker and OPA. Startup does not initialize OpenBao, enable mounts, or create privileged credentials.

Health checks use `bao status` in the OpenBao image (accepting sealed and unsealed responses), and Python's standard-library HTTP client in the custom OPA and broker images. OPA health uses its `/health?bundles` endpoint. Broker `/health` is a liveness check.

Check services and mount:

```sh
docker compose ps
docker compose exec openbao bao secrets list -format=json
```

Expected: OpenBao, OPA, and broker show `healthy`; `runtime-shield/` appears as KV v2. `bao status` should report initialized and unsealed before testing broker operations.

### Local identities and sample authorization

Development authentication uses separate secrets configured with `BROKER_DEV_AGENT_SECRET`, `BROKER_DEV_ADMIN_SECRET`, and `BROKER_DEV_EGRESS_SECRET`. Compose constructs role-specific bearer credentials from those secrets and fixed local subject/workload identities. The broker uses constant-time secret comparison and rejects missing or mismatched roles. Keep these values in the ignored `.env`; they are development-only and are not production JWTs.

The agent and egress workload IDs match so the egress identity can redeem only a lease scoped to that workload. OPA development data allows the demo agent only `github-production`, `github.read_repository`, `repository:read`, resource `runtime-shield`, workload `agent-runtime`, and the registered digest below. OPA continues to deny by default.

The sample manifest is [policies/dev-manifest.json](policies/dev-manifest.json). Its canonical JSON digest is `sha256:ef6a79401b0d41c9773560c22bfb8d47efb591562b6a2162162c227b748999a7`; it is registered in `.env.example`, Compose broker configuration, and [policies/data.json](policies/data.json). The broker compares the request against its registered digest. OPA independently checks the same digest in policy data.

Provision a clearly dummy local credential through the broker's loopback API from inside the broker container. This keeps secret redemption off the host interface:

```sh
docker compose exec broker python -c 'import asyncio,httpx,os; token="admin:local-admin:admin-cli:"+os.environ["BROKER_DEV_ADMIN_SECRET"]; asyncio.run(httpx.AsyncClient().put("http://127.0.0.1:8000/v1/admin/credentials/github-production",headers={"Authorization":"Bearer "+token},json={"value":{"api_key":"local-dummy-github-token"}}))'
```

Lease issuance is exercised by the Runtime Shield `github.read_repository` flow documented in the Runtime Shield README. The gateway derives alias, operation, resource, digest, duration, and use count from its server-side registry. The broker returns lease metadata only. Only the broker and egress container are attached to the redemption network, and egress never returns the credential. There is no host-published broker or redemption port.

## Tests

The dedicated Docker test target includes the app, tests, pytest config, and pinned pytest while the runtime target excludes pytest and test files. The test container uses UID/GID 10001 and a writable cache under `/tmp`.

Run the full test suite with:

```sh
docker compose --profile test run --build --rm test
```

The tests use fake vault and policy adapters with real SQLite. They cover single-use and concurrent redemption, max-use exhaustion, vault failure recovery, revocation/expiry races, and lease response secrecy. A local OpenBao persistence check can verify mount/version metadata before and after a broker restart; do not expose the broker port or call redemption manually.

## Stop and cleanup

Stop containers while preserving the SQLite volume:

```sh
docker compose down
```

`docker compose down` preserves both named volumes. Do not remove volumes during routine development: the OpenBao file-backed store and SQLite lease metadata are persistent. Remove `.env` separately when no longer needed.

## API and security limits

- `GET /health`: liveness only; returns no dependency details.
- `PUT /v1/admin/credentials/{alias}` and `DELETE /v1/admin/credentials/{alias}`: admin identity required; secret values are not returned.
- `POST /v1/leases`: authenticated agent identity, OPA approval, registered manifest, and valid delegation where supplied.
- `DELETE /v1/leases/{lease_id}`: owner revocation.
- `POST /internal/v1/leases/{lease_id}/redeem`: egress identity only, workload-bound, expiry-checked, one-time by default, and secret-bearing.

An internal lease expiration/revocation does not revoke a static upstream API key. OpenBao KV v2 `DELETE` soft-deletes the current version; earlier versions can remain recoverable until version destruction or metadata deletion is performed by an operator. KV v2 static credentials do not have dynamic-secret lease semantics. Delegated leases are denied until a trusted signed parent chain is implemented. Manifest hashing verifies equality with the server-registered digest but does not attest tool code. This starter has not had a production security assessment; configure TLS, private redemption networking, restricted vault access, managed OPA bundles/data, durable audit collection, monitoring, database backup, and deployment-level quotas before production use.
