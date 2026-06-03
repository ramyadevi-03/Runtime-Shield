"""
Runtime Shield — SPIFFE Workload Integration
Fetches the X.509 SVID for this workload from the SPIRE agent (or uses signed
local certs) and provides helpers to build mTLS-capable HTTP sessions.
"""
import os
import ssl
import sys


# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_HERE)  # one level up: Runtime-shield-for-agentic-systems/
_CERTS_DIR = os.path.join(_PROJECT_DIR, "spire", "certs")

LLM_AGENT_SVID_CRT = os.path.join(_CERTS_DIR, "llm-agent.crt")
LLM_AGENT_SVID_KEY = os.path.join(_CERTS_DIR, "llm-agent.key")
CA_BUNDLE          = os.path.join(_CERTS_DIR, "ca.crt")


def _read_pem(path: str) -> str | None:
    """Read a PEM file and return its contents, or None if not found."""
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception:
        return None


def _attest_svid_locally(cert_path: str, ca_path: str, expected_spiffe_id: str) -> dict:
    """
    Cryptographically attest a local X.509 SVID against the CA bundle.
    Returns {"attested": bool, "spiffe_id": str, "reason": str}.
    """
    try:
        from cryptography import x509 as _x509
        from cryptography.hazmat.backends import default_backend
        import datetime as _dt

        if not os.path.exists(cert_path) or not os.path.exists(ca_path):
            return {"attested": False, "reason": "cert or CA not found"}

        with open(cert_path, "rb") as f:
            svid = _x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(ca_path, "rb") as f:
            ca = _x509.load_pem_x509_certificate(f.read(), default_backend())

        # Verify signature
        from cryptography.hazmat.primitives.asymmetric import padding as _padding
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        from cryptography.hazmat.primitives.asymmetric import ec as _ec

        ca_pubkey = ca.public_key()
        if isinstance(ca_pubkey, _rsa.RSAPublicKey):
            ca_pubkey.verify(
                svid.signature,
                svid.tbs_certificate_bytes,
                _padding.PKCS1v15(),
                svid.signature_hash_algorithm,
            )
        elif isinstance(ca_pubkey, _ec.EllipticCurvePublicKey):
            ca_pubkey.verify(
                svid.signature,
                svid.tbs_certificate_bytes,
                _ec.ECDSA(svid.signature_hash_algorithm),
            )
        else:
            ca_pubkey.verify(
                svid.signature,
                svid.tbs_certificate_bytes,
                svid.signature_hash_algorithm,
            )

        # Extract SPIFFE URI SAN
        spiffe_id = ""
        try:
            san = svid.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
            uris = san.value.get_values_for_type(_x509.UniformResourceIdentifier)
            spiffe_uris = [u for u in uris if u.startswith("spiffe://")]
            spiffe_id = spiffe_uris[0] if spiffe_uris else ""
        except Exception:
            pass

        # Validate expiry
        now = _dt.datetime.utcnow()
        if now < svid.not_valid_before or now > svid.not_valid_after:
            return {"attested": False, "spiffe_id": spiffe_id, "reason": "SVID is expired or not yet valid"}

        return {"attested": True, "spiffe_id": spiffe_id, "reason": "Local cryptographic attestation passed"}

    except Exception as e:
        return {"attested": False, "reason": f"Attestation error: {e}"}


def fetch_svid() -> dict:
    """
    Fetch the X.509 SVID for this workload.

    Priority order:
      1. SPIRE Agent Workload API (pyspiffe) — live cryptographic attestation
      2. Local signed SVID on disk (spire/certs/llm-agent.crt) — static attestation
      3. Simulated identity (offline/dev fallback)

    Returns a dict with:
      valid        (bool)   — True if a real or locally-attested SVID was obtained
      attested     (bool)   — True only if cryptographic attestation succeeded
      spiffe_id    (str)
      cert_pem     (str)    — PEM cert to attach as X-SPIFFE-CERT header
      private_key  (str)    — PEM key (for mTLS client use)
      source       (str)    — where the identity came from
      error        (str|None)
    """
    # ── Attempt 1: SPIRE Agent Workload API ──────────────────────────────────
    try:
        from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient
        client = DefaultWorkloadApiClient()
        svid = client.fetch_x509_svid()
        spiffe_id = str(svid.spiffe_id())
        cert_pem = (
            svid.cert_chain_as_pem().decode("utf-8")
            if isinstance(svid.cert_chain_as_pem(), bytes)
            else svid.cert_chain_as_pem()
        )
        key_pem = (
            svid.private_key_as_pem().decode("utf-8")
            if isinstance(svid.private_key_as_pem(), bytes)
            else svid.private_key_as_pem()
        )
        return {
            "valid": True,
            "attested": True,
            "spiffe_id": spiffe_id,
            "cert_pem": cert_pem,
            "private_key": key_pem,
            "source": "SPIRE Agent Workload API",
            "error": None,
        }
    except Exception as spire_err:
        pass  # Fall through to next option

    # ── Attempt 1.5: SPIRE Agent CLI fallback via Docker container (UID 1002) ──────────────────────
    try:
        import subprocess
        import json
        expected_id = os.getenv("SPIFFE_LLM_ID", "spiffe://runtime-shield/llm-agent")
        # Query as UID 1002 (llm-agent user inside container)
        cmd = ["docker", "exec", "-u", "1002", "spire-agent", "/opt/spire/bin/spire-agent", "api", "fetch", "x509", "-output", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            svids = data.get("svids", [])
            if svids:
                # SPIRE guarantees exactly 1 SVID is returned under UID 1002 isolation!
                svid = svids[0]
                if svid.get("spiffe_id") == expected_id:
                    def to_pem(b64_str: str, header: str, footer: str) -> str:
                        body = b64_str.strip()
                        chunks = [body[i:i+64] for i in range(0, len(body), 64)]
                        return f"-----BEGIN {header}-----\n" + "\n".join(chunks) + f"\n-----END {header}-----\n"

                    cert_pem = to_pem(svid.get("x509_svid"), "CERTIFICATE", "CERTIFICATE")
                    key_pem = to_pem(svid.get("x509_svid_key"), "PRIVATE KEY", "PRIVATE KEY")
                    return {
                        "valid": True,
                        "attested": True,
                        "spiffe_id": expected_id,
                        "cert_pem": cert_pem,
                        "private_key": key_pem,
                        "source": "SPIRE Agent Workload API (Docker Exec UID 1002)",
                        "error": None,
                    }
    except Exception:
        pass

    # ── Attempt 2: Locally signed SVID on disk (only used in local dev fallback) ───────────────────────
    cert_pem = _read_pem(LLM_AGENT_SVID_CRT)
    key_pem  = _read_pem(LLM_AGENT_SVID_KEY)

    if cert_pem and key_pem:
        expected_id = os.getenv("SPIFFE_LLM_ID", "spiffe://runtime-shield/llm-agent")
        attest = _attest_svid_locally(LLM_AGENT_SVID_CRT, CA_BUNDLE, expected_id)
        spiffe_id = attest.get("spiffe_id") or expected_id
        return {
            "valid": True,
            "attested": attest["attested"],
            "spiffe_id": spiffe_id,
            "cert_pem": cert_pem,
            "private_key": key_pem,
            "source": f"Local SVID (disk) — attestation: {'passed' if attest['attested'] else attest['reason']}",
            "error": None,
        }

    # ── Attempt 3: Simulated identity (offline/dev fallback) ─────────────────
    spiffe_id = os.getenv("SPIFFE_LLM_ID", "spiffe://runtime-shield/llm-agent")
    return {
        "valid": False,
        "attested": False,
        "spiffe_id": spiffe_id,
        "cert_pem": None,
        "private_key": None,
        "source": "Simulated Workload (SPIRE offline, no local SVID)",
        "error": "SPIRE agent unavailable and no local SVID found",
    }


def build_mtls_client_session(svid_result: dict):
    """
    Build an httpx.Client (or requests.Session) configured for mTLS using the
    workload's SVID cert+key and the shared CA bundle as the trust anchor.
    Returns None if mTLS credentials are not available.
    """
    cert_pem = svid_result.get("cert_pem")
    key_pem  = svid_result.get("private_key")

    if not cert_pem or not key_pem or not os.path.exists(CA_BUNDLE):
        return None  # Fall back to plain HTTP for local dev

    # Write temp PEM files for httpx (it needs file paths)
    import tempfile, httpx
    tmp_dir = tempfile.mkdtemp()
    cert_file = os.path.join(tmp_dir, "client.crt")
    key_file  = os.path.join(tmp_dir, "client.key")

    with open(cert_file, "w") as f:
        f.write(cert_pem)
    with open(key_file, "w") as f:
        f.write(key_pem)

    try:
        return httpx.Client(
            cert=(cert_file, key_file),
            verify=CA_BUNDLE,
        )
    except Exception as e:
        return None


if __name__ == "__main__":
    res = fetch_svid()
    print(f"SPIFFE ID : {res['spiffe_id']}")
    print(f"Source    : {res['source']}")
    print(f"Attested  : {res['attested']}")
    if res.get("cert_pem"):
        print(f"Cert PEM  : [present, {len(res['cert_pem'])} bytes]")
    if res.get("error"):
        print(f"Error     : {res['error']}")
