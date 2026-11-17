from src.jit_validation import validate_jit_claims


EXPECTED = {
    "iss": "https://id.example/realms/shield",
    "aud": ["runtime-shield-jit"],
    "scope": "tool:keycloak_read",
    "workload_id": "spiffe://runtime-shield/bridge",
    "iat": 100,
    "exp": 160,
}


def _valid(claims):
    return validate_jit_claims(
        claims,
        expected_issuer="https://id.example/realms/shield",
        expected_audience="runtime-shield-jit",
        required_scope="tool:keycloak_read",
        expected_workload="spiffe://runtime-shield/bridge",
        now=120,
    )


def test_jit_claims_require_issuer_audience_scope_expiry_and_workload():
    assert _valid(EXPECTED)
    for field, value in (
        ("iss", "https://attacker.example/"),
        ("aud", ["other-client"]),
        ("scope", "tool:read_file"),
        ("workload_id", "spiffe://runtime-shield/agent"),
        ("exp", 119),
        ("iat", 121),
    ):
        assert not _valid({**EXPECTED, field: value})


def test_jit_claims_reject_missing_or_malformed_claims():
    assert not _valid({key: value for key, value in EXPECTED.items() if key != "workload_id"})
    assert not _valid({**EXPECTED, "aud": {"not": "a-list"}})
