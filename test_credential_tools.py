import asyncio

from src import credential_tools


class Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_gateway_registry_issues_server_derived_lease_and_only_returns_result(monkeypatch):
    calls = []

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/v1/leases"):
                return Response({"lease_id": "opaque-lease", "credential_alias": "github-production"})
            return Response({"repository": "runtime-shield/demo", "content": [{"name": "README.md"}]})

    monkeypatch.setattr(credential_tools.httpx, "AsyncClient", lambda **kwargs: Client())
    monkeypatch.setenv("CREDENTIAL_BROKER_AGENT_TOKEN", "agent-token")
    monkeypatch.setenv("RUNTIME_SHIELD_EGRESS_EXECUTOR_TOKEN", "executor-token")
    result = asyncio.run(credential_tools.execute_registered_tool(
        "github.read_repository", {"repository": "runtime-shield/demo", "credential_alias": "attacker"}, "request-1"
    ))

    issued = calls[0][1]["json"]
    assert issued["credential_alias"] == "github-production"
    assert issued["operation"] == "repository:read"
    assert issued["max_uses"] == 1
    assert calls[1][1]["json"]["lease_id"] == "opaque-lease"
    assert result == {"repository": "runtime-shield/demo", "content": [{"name": "README.md"}]}
    assert "credential" not in str(result)


def test_unregistered_resource_is_rejected_before_broker_call():
    try:
        asyncio.run(credential_tools.execute_registered_tool(
            "github.read_repository", {"repository": "attacker/repo"}, "request-2"
        ))
    except ValueError as exc:
        assert str(exc) == "Unauthorized tool or resource"
    else:
        raise AssertionError("unregistered repository was accepted")
