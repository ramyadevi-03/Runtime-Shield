"""Narrow helpers for the approved workshop filesystem operation."""

import hashlib
import hmac
import re
import time
import uuid


WORKSHOP_DEMO_PATH = "secure-experiment-zone/hitl-demo-approved.txt"
WORKSHOP_DEMO_CONTENT = "Runtime Shield HITL and Docker sandbox execution successful"
WORKSHOP_PROVIDER_ID = "runtime-shield-filesystem-provider"
_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{12,64}$")
_WORKSHOP_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}\.txt$")


def is_workshop_demo_write(tool_name, tool_args):
    return (
        tool_name == "write_file"
        and isinstance(tool_args, dict)
        and tool_args.get("path") == WORKSHOP_DEMO_PATH
        and tool_args.get("content") == WORKSHOP_DEMO_CONTENT
    )


def validate_provider_file_path(path):
    if not isinstance(path, str) or "\\" in path or ":" in path:
        return None
    parts = path.split("/")
    if len(parts) != 2 or parts[0] != "secure-experiment-zone":
        return None
    filename = parts[1]
    if filename in (".", "..") or not _WORKSHOP_FILE_RE.fullmatch(filename):
        return None
    return filename


def provider_identity_failures(identity):
    if not isinstance(identity, dict):
        return ["provider identity response is not an object"]
    failures = []
    container_id = identity.get("container_id")
    if not isinstance(container_id, str) or not _CONTAINER_ID_RE.fullmatch(container_id):
        failures.append("provider container identity is missing or invalid")
    if identity.get("provider") != WORKSHOP_PROVIDER_ID:
        failures.append("unexpected filesystem provider identity")
    if identity.get("docker_runtime") != "runc":
        failures.append("provider is not configured for Docker runc")
    if not isinstance(identity.get("uid"), int) or identity["uid"] <= 0:
        failures.append("provider is running as root or has an invalid UID")
    for field, description in (
        ("rootfs_read_only", "provider root filesystem is writable"),
        ("secure_zone_mount_read_write", "secure experiment zone is not writable"),
        ("capabilities_empty", "provider retains Linux capabilities"),
        ("no_new_privs", "no-new-privileges is not active"),
        ("no_default_route", "provider has a default network route"),
    ):
        if identity.get(field) is not True:
            failures.append(description)
    if identity.get("seccomp_mode") != 2:
        failures.append("seccomp is not enforcing a filter")
    return failures


def expected_content_sha256(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def create_request_auth(secret, method, path, body, request_id=None, timestamp=None):
    request_id = request_id or uuid.uuid4().hex
    timestamp = str(timestamp if timestamp is not None else int(time.time()))
    message = (
        method.upper().encode("ascii")
        + b"\n"
        + path.encode("ascii")
        + b"\n"
        + timestamp.encode("ascii")
        + b"\n"
        + request_id.encode("ascii")
        + b"\n"
        + body
    )
    signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return request_id, timestamp, signature


def verify_response_auth(secret, path, request_id, status, headers, body, now=None):
    timestamp = headers.get("x-runtime-response-timestamp") or headers.get(
        "X-Runtime-Response-Timestamp", ""
    )
    signature = headers.get("x-runtime-response-signature") or headers.get(
        "X-Runtime-Response-Signature", ""
    )
    try:
        parsed_timestamp = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs((time.time() if now is None else now) - parsed_timestamp) > 30:
        return False
    message = (
        str(status).encode("ascii")
        + b"\n"
        + path.encode("ascii")
        + b"\n"
        + timestamp.encode("ascii")
        + b"\n"
        + request_id.encode("ascii")
        + b"\n"
        + body
    )
    expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def create_response_auth(secret, path, request_id, status, body, timestamp=None):
    timestamp = str(timestamp if timestamp is not None else int(time.time()))
    message = (
        str(status).encode("ascii")
        + b"\n"
        + path.encode("ascii")
        + b"\n"
        + timestamp.encode("ascii")
        + b"\n"
        + request_id.encode("ascii")
        + b"\n"
        + body
    )
    signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return {
        "X-Runtime-Response-Timestamp": timestamp,
        "X-Runtime-Response-Id": request_id,
        "X-Runtime-Response-Signature": signature,
    }
