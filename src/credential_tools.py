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
            candidate_broker_urls = [broker_url]
            if "http://broker:8000" in broker_url:
                candidate_broker_urls.append(broker_url.replace("http://broker:8000", "http://credential-broker-broker-1:8000"))

            lease_response = None
            last_broker_err = None
            for b_url in candidate_broker_urls:
                try:
                    lease_response = await client.post(
                        f"{b_url}/v1/leases",
                        json=lease_payload,
                        headers={"Authorization": f"Bearer {agent_token}", "X-Request-ID": request_id},
                    )
                    break
                except (httpx.ConnectError, httpx.ConnectTimeout) as conn_err:
                    last_broker_err = conn_err
                    continue

            if lease_response is None:
                raise last_broker_err or RuntimeError("Cannot connect to credential broker")

            if lease_response.status_code != 200:
                import sys
                print(f"[ERROR execute_registered_tool] Broker lease request failed: HTTP {lease_response.status_code} - {lease_response.text}", file=sys.stderr, flush=True)
            lease_response.raise_for_status()
            lease = lease_response.json()
            lease_id = lease.get("lease_id")
            if not isinstance(lease_id, str) or not lease_id:
                raise RuntimeError("Broker returned invalid lease metadata")

            candidate_egress_urls = [egress_url]
            if "http://credential-egress:8090" in egress_url:
                candidate_egress_urls.append(egress_url.replace("http://credential-egress:8090", "http://runtime-shield-credential-egress-1:8090"))

            result_response = None
            last_egress_err = None
            for e_url in candidate_egress_urls:
                try:
                    result_response = await client.post(
                        f"{e_url}/execute",
                        json={"lease_id": lease_id, "tool": tool, "arguments": {"repository": config["repository"]}},
                        headers={"Authorization": f"Bearer {executor_token}", "X-Request-ID": request_id},
                    )
                    break
                except (httpx.ConnectError, httpx.ConnectTimeout) as conn_err:
                    last_egress_err = conn_err
                    continue

            if result_response is None:
                raise last_egress_err or RuntimeError("Cannot connect to credential egress")

            if result_response.status_code != 200:
                import sys
                print(f"[ERROR execute_registered_tool] Egress execute request failed: HTTP {result_response.status_code} - {result_response.text}", file=sys.stderr, flush=True)
            result_response.raise_for_status()
            result = result_response.json()
            if not isinstance(result, dict) or result.get("repository") != config["repository"]:
                raise RuntimeError("Egress returned an invalid result")
            return {"repository": result["repository"], "content": result.get("content", [])}
        except Exception as exc:
            import sys
            print(f"[ERROR execute_registered_tool] Failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            # No exception detail, response body, token, or secret is propagated to caller.
            raise RuntimeError("Credential-backed operation failed") from None
