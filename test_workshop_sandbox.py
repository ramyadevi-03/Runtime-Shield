import hashlib

from workshop_sandbox import (
    WORKSHOP_DEMO_CONTENT,
    WORKSHOP_DEMO_PATH,
    create_request_auth,
    create_response_auth,
    expected_content_sha256,
    is_workshop_provider_write,
    provider_identity_failures,
    validate_provider_file_path,
    verify_response_auth,
)


def _valid_identity():
    return {
        "provider": "runtime-shield-filesystem-provider",
        "container_id": "0123456789ab",
        "docker_runtime": "runc",
        "uid": 10001,
        "rootfs_read_only": True,
        "secure_zone_mount_read_write": True,
        "capabilities_empty": True,
        "no_new_privs": True,
        "seccomp_mode": 2,
        "no_default_route": True,
    }


def test_workshop_provider_routes_safe_filesystem_writes():
    assert is_workshop_provider_write("write_file", {
        "path": WORKSHOP_DEMO_PATH,
        "content": WORKSHOP_DEMO_CONTENT,
    })
    assert is_workshop_provider_write("write_file", {
        "path": "secure-experiment-zone/workshop-rehearsal.txt",
        "content": "Harmless workshop content with different wording.",
    })
    assert not is_workshop_provider_write("write_file", {
        "path": "secure-experiment-zone/other.json",
        "content": WORKSHOP_DEMO_CONTENT,
    })
    assert not is_workshop_provider_write("write_file", {
        "path": "secure-experiment-zone/workshop-rehearsal.txt",
        "content": "x" * 4097,
    })
    assert not is_workshop_provider_write("keycloak_revoke_user_sessions", {
        "path": WORKSHOP_DEMO_PATH,
        "content": WORKSHOP_DEMO_CONTENT,
    })


def test_provider_identity_requires_all_container_restrictions():
    assert provider_identity_failures(_valid_identity()) == []

    for field, invalid_value in (
        ("uid", 0),
        ("rootfs_read_only", False),
        ("secure_zone_mount_read_write", False),
        ("capabilities_empty", False),
        ("no_new_privs", False),
        ("seccomp_mode", 0),
        ("no_default_route", False),
        ("docker_runtime", "gvisor"),
        ("container_id", "not-a-container"),
    ):
        identity = _valid_identity()
        identity[field] = invalid_value
        assert provider_identity_failures(identity), field


def test_provider_path_policy_is_limited_to_direct_txt_files():
    assert validate_provider_file_path(WORKSHOP_DEMO_PATH) == "hitl-demo-approved-20261103.txt"
    for path in (
        "../secure-experiment-zone/file.txt",
        "secure-experiment-zone/../file.txt",
        "secure-experiment-zone/subdir/file.txt",
        "secure-experiment-zone/.env",
        "secure-experiment-zone/file.json",
        "/workspace/secure-experiment-zone/file.txt",
        r"secure-experiment-zone\file.txt",
    ):
        assert validate_provider_file_path(path) is None, path


def test_gateway_provider_request_and_response_signatures_bind_payload():
    secret = "a" * 64
    body = b'{"tool":"write_file","path":"secure-experiment-zone/hitl-demo-approved.txt"}'
    request_id, timestamp, signature = create_request_auth(
        secret, "POST", "/v1/write_file", body, request_id="request-1", timestamp=100
    )
    assert request_id == "request-1"
    assert timestamp == "100"
    assert len(signature) == 64

    response_body = b'{"success":true}'
    response_headers = create_response_auth(
        secret, "/v1/write_file", request_id, 200, response_body, timestamp=100
    )
    assert verify_response_auth(
        secret, "/v1/write_file", request_id, 200, response_headers, response_body, now=100
    )
    assert not verify_response_auth(
        secret, "/v1/write_file", request_id, 200, response_headers, b'{"success":false}', now=100
    )
    assert not verify_response_auth(
        "b" * 64, "/v1/write_file", request_id, 200, response_headers, response_body, now=100
    )


def test_expected_hash_matches_exact_workshop_content():
    assert expected_content_sha256(WORKSHOP_DEMO_CONTENT) == hashlib.sha256(
        WORKSHOP_DEMO_CONTENT.encode("utf-8")
    ).hexdigest()
