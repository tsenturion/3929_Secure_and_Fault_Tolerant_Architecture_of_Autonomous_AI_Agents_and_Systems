import argparse
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from dispatcher.identity.iam import AGENT_CLIENT, RUNBOOK_CLIENT

IDENTITY_DIR = Path("certs/agent-identity")
AGENT_URI = f"urn:dispatcher:service:{AGENT_CLIENT}"
RUNBOOK_URI = f"urn:dispatcher:service:{RUNBOOK_CLIENT}"


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=path.parent, delete=False) as file:
        temp = Path(file.name)
        file.write(content)
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def read_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def issue(
    name: str,
    days: int,
    ca: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
    *,
    server: bool = False,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca[0].subject if ca else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=ca is None, path_length=0 if ca is None else None),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=ca is not None,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca is None,
                crl_sign=ca is None,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if ca:
        san = (
            x509.DNSName(name)
            if server
            else x509.UniformResourceIdentifier(f"urn:dispatcher:service:{name}")
        )
        purpose = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
        builder = (
            builder.add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca[1].public_key()),
                critical=False,
            )
        )
    return builder.sign(ca[1] if ca else key, hashes.SHA256()), key


def pem(cert: x509.Certificate, key: ec.EllipticCurvePrivateKey) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def provision(root: Path, *, rotate: bool = False, interagent: bool = False) -> x509.Certificate:
    """Готовит сертификаты стенда и по запросу заменяет пару агента диагностики."""
    authority = root / "authority" / "ca.pem"
    if not authority.exists():
        atomic_write(authority, pem(*issue("Dispatcher Training CA", 365)))
    ca = read_certificate(authority)
    ca_key = serialization.load_pem_private_key(authority.read_bytes(), password=None)
    if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Учебный центр сертификации использует ключ ECDSA.")
    renewal = datetime.now(UTC) + timedelta(days=1)
    if ca.not_valid_after_utc <= datetime.now(UTC) + timedelta(days=7):
        raise ValueError("Срок учебного центра сертификации истекает. Создайте новый комплект.")

    leaves = [
        ("executor", "tls.pem", "executor", True),
        ("agent", "tls.pem", AGENT_CLIENT, False),
    ]
    if interagent:
        leaves.extend(
            [
                ("runbook", "tls.pem", RUNBOOK_CLIENT, False),
                ("runbook", "server.pem", RUNBOOK_CLIENT, True),
                ("keycloak", "tls.pem", "keycloak", True),
            ]
        )
    for directory in {entry[0] for entry in leaves}:
        atomic_write(root / directory / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    for directory, filename, name, server in leaves:
        leaf = root / directory / filename
        expired = not leaf.exists() or read_certificate(leaf).not_valid_after_utc <= renewal
        if expired or (directory == "agent" and rotate):
            # Записываем сертификат и соответствующий закрытый ключ в один PEM-файл.
            atomic_write(leaf, pem(*issue(name, 7, (ca, ca_key), server=server)))
    if interagent:
        keycloak = root / "keycloak"
        combined = (keycloak / "tls.pem").read_bytes()
        certificate = x509.load_pem_x509_certificate(combined)
        key = serialization.load_pem_private_key(combined, password=None)
        atomic_write(keycloak / "server.pem", certificate.public_bytes(serialization.Encoding.PEM))
        atomic_write(
            keycloak / "server-key.pem",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
    return read_certificate(root / "agent" / "tls.pem")


def main() -> None:
    parser = argparse.ArgumentParser(description="Выпуск сертификатов учебного стенда.")
    parser.add_argument("--rotate", action="store_true", help="Выпустить новый сертификат агента.")
    parser.add_argument(
        "--interagent", action="store_true", help="Подготовить сертификаты OAuth-стенда."
    )
    args = parser.parse_args()
    certificate = provision(IDENTITY_DIR, rotate=args.rotate, interagent=args.interagent)
    print(f"Сертификат {AGENT_CLIENT} № {certificate.serial_number:X}")


if __name__ == "__main__":
    main()
