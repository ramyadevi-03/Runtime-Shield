#!/usr/bin/env python3
"""Generate local Keycloak TLS files from KEYCLOAK_HTTPS_KEY_STORE_PASSWORD."""

import argparse
import datetime
import ipaddress
import os
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from dotenv import load_dotenv


def generate_keycloak_tls(output_dir: Path, password: str) -> None:
    if len(password) < 16:
        raise ValueError("KEYCLOAK_HTTPS_KEY_STORE_PASSWORD must be at least 16 characters.")

    output_dir.mkdir(parents=True, exist_ok=True)
    ca_path = output_dir / "root-ca.pem"
    keystore_path = output_dir / "keycloak.p12"
    if ca_path.exists() or keystore_path.exists():
        raise FileExistsError(
            "Keycloak TLS output already exists; preserve it or remove it deliberately before regenerating."
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now.replace(tzinfo=None)
    not_after = (now + datetime.timedelta(days=365)).replace(tzinfo=None)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Runtime Shield Development"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Runtime Shield Local Development CA"),
        ]
    )
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Runtime Shield Development"),
            x509.NameAttribute(NameOID.COMMON_NAME, "host.docker.internal"),
        ]
    )
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("host.docker.internal"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    keystore = pkcs12.serialize_key_and_certificates(
        name=b"keycloak",
        key=server_key,
        cert=server_certificate,
        cas=[ca_certificate],
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )

    with tempfile.TemporaryDirectory(prefix=".keycloak-tls-", dir=output_dir) as temporary_dir:
        temporary_path = Path(temporary_dir)
        temporary_ca = temporary_path / ca_path.name
        temporary_keystore = temporary_path / keystore_path.name
        temporary_ca.write_bytes(
            ca_certificate.public_bytes(serialization.Encoding.PEM)
        )
        temporary_keystore.write_bytes(keystore)
        os.replace(temporary_ca, ca_path)
        os.replace(temporary_keystore, keystore_path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "keycloak-tls",
        help="Directory for ignored local TLS output (default: ./keycloak-tls)",
    )
    args = parser.parse_args()

    load_dotenv()
    password = os.getenv("KEYCLOAK_HTTPS_KEY_STORE_PASSWORD", "")
    try:
        generate_keycloak_tls(args.output_dir, password)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Generated local Keycloak TLS files in {args.output_dir.resolve()}.")


if __name__ == "__main__":
    main()
