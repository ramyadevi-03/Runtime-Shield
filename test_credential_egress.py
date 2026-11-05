from fastapi.testclient import TestClient

from credential_egress import app as egress


def test_egress_redeems_and_injects_secret_but_returns_only_upstream_result(monkeypatch):
    calls = []

    class Response:
        status_code = 200

        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self.payload

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, **kwargs):
            calls.append(("post", url, kwargs))
            return Response({"credential": {"api_key": "local-dummy-github-token"}})

        async def get(self, url, **kwargs):
            calls.append(("get", url, kwargs))
            return Response({"repository": "runtime-shield/demo", "content": [{"name": "README.md"}]})

    monkeypatch.setattr(egress.httpx, "AsyncClient", lambda **kwargs: Client())
    monkeypatch.setattr(egress, "BROKER_EGRESS_TOKEN", "egress-token")
    monkeypatch.setattr(egress, "EXECUTOR_TOKEN", "executor-token")
    response = TestClient(egress.app).post(
        "/execute",
        headers={"Authorization": "Bearer executor-token"},
        json={"lease_id": "lease-1", "tool": "github.read_repository", "arguments": {"repository": "runtime-shield/demo"}},
    )
    assert response.status_code == 200
    assert "local-dummy-github-token" not in response.text
    assert calls[1][2]["headers"]["Authorization"] == "Bearer local-dummy-github-token"
    assert response.json()["repository"] == "runtime-shield/demo"


def test_egress_rejects_disallowed_target_and_resource(monkeypatch):
    monkeypatch.setattr(egress, "BROKER_EGRESS_TOKEN", "egress-token")
    monkeypatch.setattr(egress, "EXECUTOR_TOKEN", "executor-token")
    client = TestClient(egress.app)
    response = client.post(
        "/execute",
        headers={"Authorization": "Bearer executor-token"},
        json={"lease_id": "lease-1", "tool": "github.read_repository", "arguments": {"repository": "attacker/repo"}},
    )
    assert response.status_code == 403
    monkeypatch.setattr(egress, "UPSTREAM_URL", "http://example.com/steal")
    response = client.post(
        "/execute",
        headers={"Authorization": "Bearer executor-token"},
        json={"lease_id": "lease-2", "tool": "github.read_repository", "arguments": {"repository": "runtime-shield/demo"}},
    )
    assert response.status_code == 502
    assert "example.com" not in response.text
