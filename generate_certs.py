"""
Runtime Shield — SPIFFE Certificate Generator
Generates X.509 SVIDs with proper SPIFFE URI SANs embedded for cryptographic attestation.
Each workload identity gets its own signed SVID traceable to the CA trust bundle.
"""
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import datetime
import os


SPIFFE_TRUST_DOMAIN = "runtime-shield"

WORKLOAD_IDENTITIES = {
    "agent":      f"spiffe://{SPIFFE_TRUST_DOMAIN}/agent",
    "bridge":     f"spiffe://{SPIFFE_TRUST_DOMAIN}/bridge",
    "llm-agent":  f"spiffe://{SPIFFE_TRUST_DOMAIN}/llm-agent",
    "dashboard":  f"spiffe://{SPIFFE_TRUST_DOMAIN}/dashboard",
}


def generate_certs(output_dir):
    os.makedirs(output_dir, exist_ok=True)

    # ── 1. CA Key & Self-Signed Certificate ──────────────────────────────────
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Runtime Shield SPIRE CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Runtime Shield"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ), critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    _write_key(ca_key, output_dir, "ca.key")
    _write_cert(ca_cert, output_dir, "ca.crt")
    print(f"CA certificate written to {output_dir}/ca.crt")

    # ── 2. Per-Workload SVIDs with SPIFFE URI SAN ────────────────────────────
    for workload_name, spiffe_id in WORKLOAD_IDENTITIES.items():
        wl_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        wl_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, workload_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Runtime Shield"),
            ]))
            .issuer_name(ca_name)
            .public_key(wl_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            # SPIFFE URI SAN — this is what cryptographic attestation verifies
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(spiffe_id)
                ]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ), critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                ]), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        _write_key(wl_key, output_dir, f"{workload_name}.key")
        _write_cert(wl_cert, output_dir, f"{workload_name}.crt")
        print(f"SVID written: {workload_name}.crt  [SPIFFE URI: {spiffe_id}]")

    # Backward-compat aliases for existing .env references
    _alias(output_dir, "agent.crt", "bridge.crt")
    _alias(output_dir, "agent.key", "bridge.key")
    print(f"\nAll SVIDs written to: {output_dir}")


def _write_key(key, directory, filename):
    path = os.path.join(directory, filename)
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def _write_cert(cert, directory, filename):
    path = os.path.join(directory, filename)
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _alias(directory, alias_name, source_name):
    """Copy source to alias_name for backward compat."""
    import shutil
    src = os.path.join(directory, source_name)
    dst = os.path.join(directory, alias_name)
    if os.path.exists(src):
        shutil.copy2(src, dst)


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    generate_certs(os.path.join(current_dir, "spire", "certs"))
