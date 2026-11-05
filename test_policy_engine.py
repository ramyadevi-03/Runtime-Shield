from src.policy_engine import SemanticCachePolicyEngine


class CountingPolicy:
    backend = "test"

    def __init__(self):
        self.inputs = []

    def evaluate_policy(self, policy_input):
        self.inputs.append(policy_input)
        return {"allow": policy_input["user"]["sub"] == "alice"}


def test_similar_requests_from_different_users_always_evaluate_policy():
    target = CountingPolicy()
    engine = SemanticCachePolicyEngine(target)
    shared = {
        "workload": {"id": "spiffe://runtime-shield/agent"},
        "agent": {"id": "agent-a"},
        "mcp": {"tool": "github.read_repository", "action": "call"},
        "resource": {"path": ""},
        "request": {"original_args": {"repository": "runtime-shield/demo"}},
    }
    alice = {**shared, "user": {"sub": "alice", "id": "alice", "role": "user", "scopes": ["repository:read"]}}
    bob = {**shared, "user": {"sub": "bob", "id": "bob", "role": "user", "scopes": ["repository:read"]}}

    assert engine.evaluate_policy(alice)["allow"] is True
    assert engine.evaluate_policy(bob)["allow"] is False
    assert len(target.inputs) == 2


def test_argument_and_scope_changes_are_never_reused():
    target = CountingPolicy()
    engine = SemanticCachePolicyEngine(target)
    base = {
        "user": {"sub": "alice", "id": "alice", "role": "user", "scopes": ["repository:read"]},
        "workload": {"id": "workload-a"},
        "agent": {"id": "agent-a"},
        "mcp": {"tool": "github.read_repository"},
        "resource": {},
        "request": {"original_args": {"repository": "runtime-shield/demo"}},
    }
    engine.evaluate_policy(base)
    changed = {**base, "user": {**base["user"], "scopes": ["profile"]}, "request": {"original_args": {"repository": "other/repo"}}}
    engine.evaluate_policy(changed)
    assert len(target.inputs) == 2
