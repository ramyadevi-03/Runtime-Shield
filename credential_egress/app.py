"""Narrow local egress executor for the credential-backed repository demo."""
import os
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

BROKER_URL = os.getenv("CREDENTIAL_BROKER_URL", "http://broker:8000")
BROKER_EGRESS_TOKEN = os.getenv("BROKER_EGRESS_TOKEN", "")
EXECUTOR_TOKEN = os.getenv("RUNTIME_SHIELD_EGRESS_EXECUTOR_TOKEN", "")
UPSTREAM_URL = os.getenv("DUMMY_UPSTREAM_URL", "http://dummy-upstream:8088/repository")
ALLOWED_REPOSITORY = "runtime-shield/demo"


class ExecuteRequest(BaseModel):
    lease_id: str = Field(min_length=1, max_length=64)
    tool: str
    arguments: dict


app = FastAPI(title="Runtime Shield Isolated Egress", docs_url=None, redoc_url=None)


def _validate_configuration():
    parsed = urlsplit(UPSTREAM_URL)
    if parsed.scheme != "http" or parsed.hostname != "dummy-upstream" or parsed.port != 8088:
        raise RuntimeError("Egress upstream must be the configured dummy-upstream service")
    if not BROKER_EGRESS_TOKEN or not EXECUTOR_TOKEN:
        raise RuntimeError("Egress workload credentials are required")


@app.get("/health")
async def health():
    _validate_configuration()
    return {"ok": True}


@app.post("/execute")
async def execute(body: ExecuteRequest, authorization: str | None = Header(default=None)):
    _validate_configuration()
    if authorization != f"Bearer {EXECUTOR_TOKEN}":
        raise HTTPException(401, "Executor authentication failed")
    # The executor repeats the gateway's tool and resource checks. It never
    # accepts a caller-selected alias, operation, host, or header format.
    if body.tool != "github.read_repository" or body.arguments.get("repository") != ALLOWED_REPOSITORY:
        raise HTTPException(403, "Tool or resource is not allowed")

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            redemption = await client.post(
                f"{BROKER_URL}/internal/v1/leases/{body.lease_id}/redeem",
                headers={"Authorization": f"Bearer {BROKER_EGRESS_TOKEN}"},
            )
            if redemption.status_code != 200:
                raise HTTPException(409, "Credential lease cannot be redeemed")
            credential = redemption.json().get("credential")
            if not isinstance(credential, dict) or not isinstance(credential.get("api_key"), str):
                raise HTTPException(502, "Credential unavailable")
            # Secret exists only in this service and is attached only to the
            # allowlisted dummy upstream request. Never include it in output.
            upstream = await client.get(
                UPSTREAM_URL,
                params={"repository": ALLOWED_REPOSITORY},
                headers={"Authorization": f"Bearer {credential['api_key']}"},
            )
            upstream.raise_for_status()
            result = upstream.json()
            if not isinstance(result, dict) or result.get("repository") != ALLOWED_REPOSITORY:
                raise HTTPException(502, "Upstream response rejected")
            items = result.get("content", [])
            if not isinstance(items, list):
                raise HTTPException(502, "Upstream response rejected")
            # Validate the response schema and allow only harmless repository
            # listing fields; secrets or unexpected upstream fields are dropped.
            safe_items = []
            for item in items[:50]:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                    continue
                kind = item.get("type")
                name = item["name"][:255]
                for secret_value in credential.values():
                    if isinstance(secret_value, str) and secret_value:
                        name = name.replace(secret_value, "[REDACTED]")
                safe_items.append({"name": name, "type": kind[:32] if isinstance(kind, str) else "file"})
            return {"repository": result["repository"], "content": safe_items}
    except HTTPException:
        raise
    except Exception:
        # Do not echo transport errors, headers, or response bodies.
        raise HTTPException(502, "Credential-backed upstream request failed") from None
