import logging
import ssl
from base64 import b64decode, urlsafe_b64encode
from binascii import Error as Base64Error
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from secrets import token_hex
from threading import Lock
from time import monotonic
from typing import Annotated
from urllib.parse import unquote_to_bytes

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel, StringConstraints

from dispatcher.identity.access import Caller, denied
from dispatcher.identity.iam import AGENT_CLIENT, RUNBOOK_CLIENT, ClientBinding
from dispatcher.identity.workload_identity.identity_pki import AGENT_URI, RUNBOOK_URI
from dispatcher.workflow.execution import ExecutorUnavailable

logger = logging.getLogger(__name__)
CERT_HEADER = "X-Verified-Client-Cert"
CHALLENGE_SECONDS = 30
Nonce = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Signature = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9+/]{342}==$")]


@dataclass(frozen=True)
class WorkloadCertificate:
    service: str
    san: str
    serial: str
    expires_at: datetime


def client_tls(directory: Path, *, present_certificate: bool = True) -> ssl.SSLContext:
    try:
        context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
        if present_certificate:
            context.load_cert_chain(str(directory / "tls.pem"))
    except OSError as error:
        raise ExecutorUnavailable("Не удалось загрузить сертификат агента.") from error
    return context


def identify_certificate(
    peer: str, encoded: str, *, interagent: bool = False
) -> tuple[WorkloadCertificate, ClientBinding]:
    # Цепочку проверяет TLS-прокси. Заголовок с сертификатом принимается только от него.
    if peer != "127.0.0.1" or not encoded:
        raise denied(401, "certificate_required", "Требуется сертификат агента.")
    try:
        certificate = x509.load_pem_x509_certificate(unquote_to_bytes(encoded))
        sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except ValueError, x509.ExtensionNotFound:
        raise denied(
            401, "certificate_invalid", "Сертификат агента не удалось прочитать."
        ) from None
    roles = {AGENT_URI: AGENT_CLIENT}
    if interagent:
        roles[RUNBOOK_URI] = RUNBOOK_CLIENT
    uris = sans.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1 or uris[0] not in roles:
        raise denied(403, "certificate_role_forbidden", "У сертификата другая сервисная роль.")
    uri = uris[0]
    service = roles[uri]
    serial = f"{certificate.serial_number:X}"
    thumbprint = (
        urlsafe_b64encode(certificate.fingerprint(hashes.SHA256())).rstrip(b"=").decode("ascii")
    )
    logger.info("Проверен сертификат сервис=%s номер=%s", service, serial)
    return (
        WorkloadCertificate(service, uri, serial, certificate.not_valid_after_utc),
        ClientBinding(service, thumbprint),
    )


class Challenge(BaseModel):
    nonce: Nonce


class TpmSignature(BaseModel):
    signature: Signature


class TpmProof(Challenge, TpmSignature):
    pass


@dataclass(frozen=True)
class TpmResult:
    service: str
    certificate_serial: str
    verified: bool


def challenge_message(nonce: str) -> bytes:
    return f"dispatcher:tpm-proof:v1:{AGENT_CLIENT}:{nonce}".encode("ascii")


class TpmVerifier:
    def __init__(self, public_key: Path):
        self.public_key = public_key
        self._lock = Lock()
        self._pending: dict[str, tuple[Caller, str, float]] = {}

    def issue(self, caller: Caller, certificate: WorkloadCertificate) -> Challenge:
        if not self.public_key.is_file():
            raise denied(503, "tpm_unavailable", "Открытый ключ TPM не зарегистрирован.")
        nonce = token_hex(32)
        now = monotonic()
        with self._lock:
            self._pending = {key: value for key, value in self._pending.items() if value[2] > now}
            if len(self._pending) >= 128:
                raise denied(503, "tpm_busy", "Заняты все слоты проверки TPM.")
            self._pending[nonce] = (caller, certificate.serial, now + CHALLENGE_SECONDS)
        return Challenge(nonce=nonce)

    def verify(
        self, caller: Caller, certificate: WorkloadCertificate, proof: TpmProof
    ) -> TpmResult:
        with self._lock:
            entry = self._pending.get(proof.nonce)
            if (
                entry is None
                or entry[:2] != (caller, certificate.serial)
                or entry[2] <= monotonic()
            ):
                raise denied(
                    409, "challenge_inactive", "Запрос TPM отсутствует или уже недействителен."
                )
            # Начатая проверка погашает запрос даже при неверной подписи.
            del self._pending[proof.nonce]
        try:
            key = serialization.load_pem_public_key(self.public_key.read_bytes())
            if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
                raise ValueError("Ожидался открытый ключ RSA-2048.")
        except OSError, ValueError, UnsupportedAlgorithm:
            raise denied(
                503, "tpm_unavailable", "Зарегистрированный ключ TPM недоступен."
            ) from None
        try:
            key.verify(
                b64decode(proof.signature, validate=True),
                challenge_message(proof.nonce),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except Base64Error, InvalidSignature:
            raise denied(403, "tpm_signature_invalid", "Подпись TPM не прошла проверку.") from None
        logger.info(
            "Подтверждён ключ TPM сервис=%s сертификат=%s", caller.service, certificate.serial
        )
        return TpmResult(caller.service, certificate.serial, True)
