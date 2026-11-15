from base64 import urlsafe_b64encode
from time import time
from urllib.parse import quote_from_bytes

import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from dispatcher import executor
from dispatcher.identity import iam
from dispatcher.identity.access import SERVICE_HEADER
from dispatcher.identity.workload_identity import workload
from dispatcher.identity.workload_identity.identity_pki import provision, read_certificate

ISSUER = "https://keycloak:8443/realms/dispatcher-workloads"


@pytest.fixture
def federation(tmp_path, access_keys, monkeypatch):
    provision(tmp_path, interagent=True)
    diagnostic = read_certificate(tmp_path / "agent/tls.pem")
    runbook = read_certificate(tmp_path / "runbook/tls.pem")
    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = RSAAlgorithm.to_jwk(signer.public_key(), as_dict=True)
    jwk.update(kid="test", alg="RS256", use="sig")
    verifier = iam.TokenVerifier(ISSUER)
    monkeypatch.setattr(verifier.keys, "fetch_data", lambda: {"keys": [jwk]})
    monkeypatch.setattr(executor, "bound_token_verifier", lambda issuer, ca: verifier)
    config = access_keys.model_copy(
        update={"service_auth_mode": "mtls_oauth", "iam_issuer": ISSUER}
    )
    monkeypatch.setattr(executor, "settings", lambda: config)

    def headers(*, client=iam.RUNBOOK_CLIENT, peer=runbook, bound=runbook, **claims):
        now = int(time())
        thumbprint = urlsafe_b64encode(bound.fingerprint(hashes.SHA256())).rstrip(b"=").decode()
        token = jwt.encode(
            {
                "sub": "service-account",
                "iss": ISSUER,
                "aud": iam.EXECUTOR_AUDIENCE,
                "azp": client,
                "scope": iam.RUNBOOK_SCOPE,
                "typ": "Bearer",
                "iat": now,
                "exp": now + 20,
                "cnf": {"x5t#S256": thumbprint},
                **claims,
            },
            signer,
            algorithm="RS256",
            headers={"kid": "test"},
        )
        return {
            "Authorization": f"Bearer {token}",
            workload.CERT_HEADER: quote_from_bytes(
                peer.public_bytes(serialization.Encoding.PEM), safe=""
            ),
        }

    return headers, diagnostic


def test_runbook_role_can_read_but_cannot_resolve(federation, monkeypatch):
    headers, _ = federation

    def forbidden_storage():
        pytest.fail("Проверка области доступа должна предшествовать обращению к базе.")

    monkeypatch.setattr(executor, "storage", forbidden_storage)
    with TestClient(executor.app, client=("127.0.0.1", 1234), headers=headers()) as client:
        read = client.get("/runbooks/RB-NOTIFY-07")
        rejected = client.post(f"/runs/{'0' * 32}/resolution", json={"decision": "approve"})

    assert read.status_code == 200
    assert read.json()["source"].startswith("RB-NOTIFY-07")
    assert rejected.status_code == 403
    assert rejected.headers["X-Policy-Code"] == "service_scope_forbidden"


@pytest.mark.parametrize(
    ("claims", "code"),
    [
        ({"cnf": {}}, "service_binding_invalid"),
        ({"cnf": {"x5t#S256": "unexpected"}}, "service_binding_invalid"),
        ({"azp": iam.AGENT_CLIENT}, "service_role_mismatch"),
        ({"aud": "another-service"}, "service_audience_invalid"),
        ({"scope": "runbooks.read.other"}, "service_scope_forbidden"),
    ],
)
def test_bound_token_rejects_wrong_identity_or_scope(federation, claims, code):
    headers, _ = federation
    with TestClient(executor.app, client=("127.0.0.1", 1234)) as client:
        response = client.get("/runbooks/RB-NOTIFY-07", headers=headers(**claims))
    assert response.status_code in {401, 403}
    assert response.headers["X-Policy-Code"] == code


def test_combined_mode_requires_both_credentials_and_retains_user_check(
    federation, service_headers, tmp_path
):
    headers, diagnostic = federation
    service = headers(
        client=iam.AGENT_CLIENT, peer=diagnostic, bound=diagnostic, scope=iam.EXECUTOR_SCOPE
    )
    operator = service_headers["Authorization"]
    renewed_certificate = provision(tmp_path, rotate=True)
    previous_binding = headers(
        client=iam.AGENT_CLIENT,
        peer=renewed_certificate,
        bound=diagnostic,
        scope=iam.EXECUTOR_SCOPE,
    )
    with TestClient(executor.app, client=("127.0.0.1", 1234)) as client:
        response = client.get("/identity", headers={**service, iam.OPERATOR_HEADER: operator})
        assert response.status_code == 200
        assert response.json()["service"] == iam.AGENT_CLIENT
        rejected = client.get(
            "/identity", headers={**previous_binding, iam.OPERATOR_HEADER: operator}
        )
        assert rejected.status_code == 401
        assert rejected.headers["X-Policy-Code"] == "service_binding_invalid"
        assert client.get("/identity", headers=service).status_code == 401
        missing = client.get(
            "/identity",
            headers={**service_headers, workload.CERT_HEADER: service[workload.CERT_HEADER]},
        )
        assert missing.status_code == 401
        assert (
            client.get("/runbooks/RB-NOTIFY-07", headers=headers(peer=diagnostic)).status_code
            == 403
        )
        response = client.get(
            "/runbooks/RB-NOTIFY-07", headers={"Authorization": service["Authorization"]}
        )
        assert response.status_code == 401
        assert response.headers["X-Policy-Code"] == "certificate_required"

        no_oauth = {workload.CERT_HEADER: service[workload.CERT_HEADER], SERVICE_HEADER: "legacy"}
        assert (
            client.get("/identity", headers=no_oauth).headers["X-Policy-Code"]
            == "service_unverified"
        )
