"""Trusted registry and server-side broker/egress handoff for demo tools."""
import os

import httpx


MANIFEST_HASH = "sha256:ef6a79401b0d41c9773560c22bfb8d47efb591562b6a2162162c227b748999a7"
TOOL_REGISTRY = {
    "github.read_repository": {
        "credential_alias": "github-production",
        "operation": "repository:read",
        "resource": "runtime-shield",
        "target_host": "dummy-upstream",
        "secret_header": "Authorization: Bearer",
        "max_lease_seconds": 60,
        "max_redemptions": 1,
        "requires_hitl": True,
        "egress_route": "dummy-github-read",
        "manifest_hash": MANIFEST_HASH,
        "repository": "runtime-shield/demo",
    }
}


def registered_tool(tool: str):
    return TOOL_REGISTRY.get(tool)


async def execute_registered_tool(tool: str, arguments: dict, request_id: str):
    config = registered_tool(tool)
    if not config or arguments.get("repository") != config["repository"]:
        raise ValueError("Unauthorized tool or resource")
    broker_url = os.getenv("CREDENTIAL_BROKER_URL", "http://broker:8000").rstrip("/")
    agent_token = os.getenv("CREDENTIAL_BROKER_AGENT_TOKEN", "")
    egress_url = os.getenv("RUNTIME_SHIELD_EGRESS_URL", "http://credential-egress:8090").rstrip("/")
    executor_token = os.getenv("RUNTIME_SHIELD_EGRESS_EXECUTOR_TOKEN", "")
    if not agent_token or not executor_token:
        raise RuntimeError("Credential integration identity is unavailable")
    lease_payload = {
        "credential_alias": config["credential_alias"],
        "tool": tool,
        "operation": config["operation"],
        "resource": config["resource"],
        "manifest_hash": config["manifest_hash"],
        "lease_seconds": config["max_lease_seconds"],
        "max_uses": config["max_redemptions"],
    }
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
        try:
            lease_response = await client.post(
                f"{broker_url}/v1/leases",
                json=lease_payload,
                headers={"Authorization": f"Bearer {agent_token}", "X-Request-ID": request_id},
            )
            lease_response.raise_for_status()
            lease = lease_response.json()
            lease_id = lease.get("lease_id")
            if not isinstance(lease_id, str) or not lease_id:
                raise RuntimeError("Broker returned invalid lease metadata")
            result_response = await client.post(
                f"{egress_url}/execute",
                json={"lease_id": lease_id, "tool": tool, "arguments": {"repository": config["repository"]}},
                headers={"Authorization": f"Bearer {executor_token}", "X-Request-ID": request_id},
            )
            result_response.raise_for_status()
            result = result_response.json()
            if not isinstance(result, dict) or result.get("repository") != config["repository"]:
                raise RuntimeError("Egress returned an invalid result")
            return {"repository": result["repository"], "content": result.get("content", [])}
        except Exception:
            # No exception detail, response body, token, or secret is propagated.
            raise RuntimeError("Credential-backed operation failed") from None
