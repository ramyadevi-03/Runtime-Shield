"""Private, single-purpose HTTP provider for workshop write_file calls."""

import hashlib
import hmac
import json
import os
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from workshop_sandbox import (
    WORKSHOP_PROVIDER_ID,
    create_response_auth,
    validate_provider_file_path,
)


PROVIDER_SECRET = os.environ.get("RUNTIME_SHIELD_FS_PROVIDER_TOKEN", "")
PROVIDER_ROOT = Path(os.environ.get("FS_PROVIDER_ROOT", "/workspace/secure-experiment-zone"))
PROVIDER_PORT = int(os.environ.get("FS_PROVIDER_PORT", "8765"))
PROVIDER_RUNTIME = os.environ.get("RUNTIME_SHIELD_FS_PROVIDER_RUNTIME", "")
MAX_REQUEST_BYTES = 16 * 1024
_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{12,64}$")
_used_request_ids = {}
_used_request_ids_lock = threading.Lock()


def _mount_is_read_only(mountpoint):
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as mountinfo:
            for line in mountinfo:
                before, separator, _after = line.partition(" - ")
                if not separator:
                    continue
                fields = before.split()
                if len(fields) > 5 and fields[4].replace("\\040", " ") == mountpoint:
                    return "ro" in fields[5].split(",")
    except OSError:
        return False
    return False


def _mount_is_read_write(mountpoint):
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as mountinfo:
            for line in mountinfo:
                before, separator, _after = line.partition(" - ")
                if not separator:
                    continue
                fields = before.split()
                if len(fields) > 5 and fields[4].replace("\\040", " ") == mountpoint:
                    return "rw" in fields[5].split(",")
    except OSError:
        return False
    return False


def _status_values():
    values = {}
    try:
        with open("/proc/self/status", encoding="utf-8") as status_file:
            for line in status_file:
                key, separator, value = line.partition(":")
                if separator:
                    values[key] = value.strip()
    except OSError:
        return {}
    return values


def _has_default_route():
    try:
        with open("/proc/net/route", encoding="ascii") as route_file:
            next(route_file, None)
            return any(line.split()[1] == "00000000" for line in route_file if len(line.split()) > 1)
    except (OSError, UnicodeError):
        return True


def provider_identity():
    status = _status_values()
    cap_effective = status.get("CapEff", "")
    hostname = socket.gethostname().lower()
    try:
        uid = os.geteuid()
    except AttributeError:
        uid = 0
    return {
        "provider": WORKSHOP_PROVIDER_ID,
        "container_id": hostname if _CONTAINER_ID_RE.fullmatch(hostname) else "",
        "docker_runtime": PROVIDER_RUNTIME,
        "uid": uid,
        "rootfs_read_only": _mount_is_read_only("/"),
        "secure_zone_mount_read_write": _mount_is_read_write(str(PROVIDER_ROOT)),
        "capabilities_empty": bool(cap_effective) and int(cap_effective, 16) == 0,
        "no_new_privs": status.get("NoNewPrivs") == "1",
        "seccomp_mode": int(status.get("Seccomp", "0")) if status.get("Seccomp", "").isdigit() else 0,
        "no_default_route": not _has_default_route(),
    }


def _write_new_file(path, content):
    filename = validate_provider_file_path(path)
    if filename is None:
        raise ValueError("write_file path must be a .txt file directly under secure-experiment-zone/")
    if not isinstance(content, str) or len(content.encode("utf-8")) > 4096:
        raise ValueError("write_file content must be text no larger than 4096 bytes")

    root = PROVIDER_ROOT.resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("secure-experiment-zone mount is unavailable")
    root_fd = os.open(str(root), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        fd = os.open(filename, flags, 0o600, dir_fd=root_fd)
        created = True
        with os.fdopen(fd, "wb") as file_handle:
            file_handle.write(content.encode("utf-8"))
            file_handle.flush()
            os.fsync(file_handle.fileno())
        read_fd = os.open(
            filename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd
        )
        with os.fdopen(read_fd, "rb") as file_handle:
            actual = file_handle.read()
        expected = content.encode("utf-8")
        if actual != expected:
            raise OSError("read-after-write verification did not match the requested content")
        os.fsync(root_fd)
        return {
            "tool": "write_file",
            "path": path,
            "success": True,
            "size_bytes": len(actual),
            "sha256": hashlib.sha256(actual).hexdigest(),
            "provider_container_id": socket.gethostname().lower(),
        }
    except Exception:
        if created:
            try:
                os.unlink(filename, dir_fd=root_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(root_fd)


class ProviderHandler(BaseHTTPRequestHandler):
    server_version = "RuntimeShieldFilesystemProvider"
    sys_version = ""

    def log_message(self, format_string, *args):
        print("filesystem-provider: " + format_string % args, flush=True)

    def _send_json(self, status, payload, request_id=None):
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if request_id:
            response_auth = create_response_auth(
                PROVIDER_SECRET, self.path, request_id, status, body
            )
            self.send_header("X-Runtime-Response-Timestamp", response_auth["X-Runtime-Response-Timestamp"])
            self.send_header("X-Runtime-Response-Id", response_auth["X-Runtime-Response-Id"])
            self.send_header("X-Runtime-Response-Signature", response_auth["X-Runtime-Response-Signature"])
        self.end_headers()
        self.wfile.write(body)

    def _authenticate(self, body):
        request_id = self.headers.get("X-Runtime-Request-Id", "")
        timestamp = self.headers.get("X-Runtime-Request-Timestamp", "")
        signature = self.headers.get("X-Runtime-Request-Signature", "")
        if (
            not request_id
            or len(request_id) > 128
            or not request_id.isascii()
            or "\n" in request_id
            or not timestamp.isdigit()
            or abs(time.time() - int(timestamp)) > 30
        ):
            return None
        message = (
            self.command.encode("ascii")
            + b"\n"
            + self.path.encode("ascii")
            + b"\n"
            + timestamp.encode("ascii")
            + b"\n"
            + request_id.encode("ascii")
            + b"\n"
            + body
        )
        expected = hmac.new(PROVIDER_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        now = time.time()
        with _used_request_ids_lock:
            for old_id, used_at in list(_used_request_ids.items()):
                if now - used_at > 60:
                    del _used_request_ids[old_id]
            if request_id in _used_request_ids:
                return None
            if len(_used_request_ids) >= 4096:
                return None
            _used_request_ids[request_id] = now
        return request_id

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        if self.path != "/v1/identity":
            self._send_json(404, {"error": "not found"})
            return
        request_id = self._authenticate(b"")
        if request_id is None:
            self._send_json(401, {"error": "provider authentication failed"})
            return
        self._send_json(200, provider_identity(), request_id)

    def do_POST(self):
        if self.path != "/v1/write_file":
            self._send_json(404, {"error": "not found"})
            return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send_json(400, {"error": "invalid content length"})
            return
        if content_length < 0 or content_length > MAX_REQUEST_BYTES:
            self._send_json(413, {"error": "request too large"})
            return
        body = self.rfile.read(content_length)
        if len(body) != content_length:
            self._send_json(400, {"error": "incomplete request body"})
            return
        request_id = self._authenticate(body)
        if request_id is None:
            self._send_json(401, {"error": "provider authentication failed"})
            return
        try:
            payload = json.loads(body)
            if not isinstance(payload, dict) or payload.get("tool") != "write_file":
                raise ValueError("only write_file is supported")
            result = _write_new_file(payload.get("path"), payload.get("content"))
        except FileExistsError:
            self._send_json(409, {"error": "target already exists; refusing to overwrite"}, request_id)
            return
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)}, request_id)
            return
        except OSError as exc:
            self._send_json(500, {"error": f"write_file failed: {exc}"}, request_id)
            return
        except Exception as exc:
            self._send_json(500, {"error": f"write_file failed: {type(exc).__name__}"}, request_id)
            return
        self._send_json(200, result, request_id)


def main():
    if len(PROVIDER_SECRET) < 32:
        raise RuntimeError("RUNTIME_SHIELD_FS_PROVIDER_TOKEN must contain at least 32 characters")
    if PROVIDER_RUNTIME != "runc":
        raise RuntimeError("RUNTIME_SHIELD_FS_PROVIDER_RUNTIME must be runc")
    server = ThreadingHTTPServer(("0.0.0.0", PROVIDER_PORT), ProviderHandler)
    server.daemon_threads = True
    print(f"{WORKSHOP_PROVIDER_ID} listening on private port {PROVIDER_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
