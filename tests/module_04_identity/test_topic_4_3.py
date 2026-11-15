from base64 import b64encode
from urllib.parse import quote_from_bytes

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from dispatcher import executor
from dispatcher.identity.workload_identity import workload
from dispatcher.identity.workload_identity.identity_pki import (
    AGENT_URI,
    provision,
    read_certificate,
)


@pytest.fixture
def pki(tmp_path):
    root = tmp_path / "pki"
    provision(root)
    return root


def encoded_certificate(path):
    raw = read_certificate(path).public_bytes(serialization.Encoding.PEM)
    return quote_from_bytes(raw, safe="")


def test_rotates_agent_key_with_same_role(pki):
    before = read_certificate(pki / "agent/tls.pem")
    server = read_certificate(pki / "executor/tls.pem")
    ca = read_certificate(pki / "authority/ca.pem")
    assert provision(pki).serial_number == before.serial_number
    after = provision(pki, rotate=True)
    assert before.serial_number != after.serial_number
    assert before.public_key().public_numbers() != after.public_key().public_numbers()
    for certificate in before, after, server:
        certificate.verify_directly_issued_by(ca)
    assert read_certificate(pki / "executor/tls.pem").serial_number == server.serial_number
    assert b"PRIVATE KEY" not in (pki / "executor/ca.pem").read_bytes()
    assert b"PRIVATE KEY" not in (pki / "agent/ca.pem").read_bytes()


@pytest.fixture
def key(tmp_path, monkeypatch, access_keys):
    private = rsa.generate_private_key(65537, 2048)
    path = tmp_path / "agent.pem"
    path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    config = access_keys.model_copy(
        update={"service_auth_mode": "certificate", "tpm_public_key": path}
    )
    monkeypatch.setattr(executor, "settings", lambda: config)
    return private


def test_certificate_header_requires_trusted_tls_entry(pki, key, service_headers):
    certificate = encoded_certificate(pki / "agent/tls.pem")
    headers = {**service_headers, workload.CERT_HEADER: certificate}
    with TestClient(executor.app, client=("192.0.2.1", 1234)) as untrusted:
        response = untrusted.get("/identity", headers=headers)
        assert response.status_code == 401
        assert response.headers["X-Policy-Code"] == "certificate_required"
    with TestClient(executor.app, client=("127.0.0.1", 1234)) as trusted:
        assert trusted.get("/identity", headers=service_headers).status_code == 401
        identity = trusted.get("/workload-identity", headers=headers).json()
        assert identity["san"] == AGENT_URI
        wrong_role = encoded_certificate(pki / "executor/tls.pem")
        response = trusted.get("/identity", headers={**headers, workload.CERT_HEADER: wrong_role})
        assert response.status_code == 403
        assert response.headers["X-Policy-Code"] == "certificate_role_forbidden"


def test_tpm_challenge_is_bound_to_certificate_and_consumed(pki, key, service_headers, monkeypatch):
    clock = [100]
    monkeypatch.setattr(workload, "monotonic", lambda: clock[0])
    headers = {**service_headers, workload.CERT_HEADER: encoded_certificate(pki / "agent/tls.pem")}
    challenge_route = "/workload-identity/challenge"
    proof_route = "/workload-identity/proof"

    def sign_nonce(nonce):
        return b64encode(
            key.sign(workload.challenge_message(nonce), padding.PKCS1v15(), hashes.SHA256())
        ).decode()

    with TestClient(executor.app, client=("127.0.0.1", 1234), headers=headers) as trusted:
        nonce = trusted.post(challenge_route).json()["nonce"]
        proof = {"nonce": nonce, "signature": sign_nonce(nonce)}
        provision(pki, rotate=True)
        replacement = {workload.CERT_HEADER: encoded_certificate(pki / "agent/tls.pem")}
        assert trusted.post(proof_route, headers=replacement, json=proof).status_code == 409
        verified = trusted.post(proof_route, json=proof)
        assert verified.status_code == 200
        assert verified.json()["verified"]
        assert trusted.post(proof_route, json=proof).status_code == 409

        nonce = trusted.post(challenge_route).json()["nonce"]
        unrelated_signature = sign_nonce("f" * 64)
        wrong = trusted.post(proof_route, json={"nonce": nonce, "signature": unrelated_signature})
        assert wrong.status_code == 403
        consumed = trusted.post(proof_route, json={"nonce": nonce, "signature": sign_nonce(nonce)})
        assert consumed.status_code == 409
        nonce = trusted.post(challenge_route).json()["nonce"]
        clock[0] += workload.CHALLENGE_SECONDS
        expired = trusted.post(proof_route, json={"nonce": nonce, "signature": sign_nonce(nonce)})
        assert expired.status_code == 409
        assert expired.headers["X-Policy-Code"] == "challenge_inactive"
