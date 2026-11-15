import asyncio
from base64 import b64decode
from json import loads
from pathlib import Path

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import PyJWKClientConnectionError
from pydantic import SecretStr

from dispatcher import executor, main
from dispatcher.identity import iam
from dispatcher.identity.access import SERVICE_HEADER, Caller
from dispatcher.settings import Settings
from dispatcher.workflow import client

ISSUER = "http://keycloak:8080/realms/dispatcher"


@pytest.fixture
def oauth(monkeypatch, access_keys):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    public_jwk.update(kid="fixture", use="sig", alg="RS256")
    verifier = iam.TokenVerifier(ISSUER)
    monkeypatch.setattr(verifier.keys, "fetch_data", lambda: {"keys": [public_jwk]})
    monkeypatch.setattr(executor, "token_verifier", lambda issuer: verifier)
    config = access_keys.model_copy(update={"service_auth_mode": "oauth", "iam_issuer": ISSUER})
    monkeypatch.setattr(executor, "settings", lambda: config)

    def sign(**claims):
        now = int(iam.time())
        values = {
            "iss": ISSUER,
            "aud": iam.EXECUTOR_AUDIENCE,
            "azp": iam.AGENT_CLIENT,
            "scope": iam.EXECUTOR_SCOPE,
            "typ": "Bearer",
            "sub": "service-account",
            "iat": now,
            "exp": now + 20,
            **claims,
        }
        return jwt.encode(values, private_key, algorithm="RS256", headers={"kid": "fixture"})

    return sign, verifier


@pytest.mark.parametrize(
    ("claims", "status", "code"),
    [
        ({"aud": "monitoring-api"}, 401, "service_audience_invalid"),
        ({"iss": "https://another-issuer.invalid"}, 401, "service_unverified"),
        ({"azp": "queue-monitor"}, 403, "service_scope_forbidden"),
        ({"scope": "executor.access.extra"}, 403, "service_scope_forbidden"),
        ({"typ": "ID"}, 401, "service_unverified"),
        ({"iat": 1, "exp": 2}, 401, "service_token_expired"),
        ({"iat": 1, "exp": 2, "aud": "monitoring-api"}, 401, "service_audience_invalid"),
    ],
)
def test_executor_checks_signed_claims(oauth, service_client, claims, status, code):
    sign, _ = oauth
    response = service_client.get("/identity", headers={SERVICE_HEADER: sign(**claims)})
    assert response.status_code == status
    assert response.headers["X-Policy-Code"] == code


def test_executor_rejects_static_and_modified_tokens(oauth, service_client, service_headers):
    sign, _ = oauth
    assert service_client.get("/identity", headers=service_headers).status_code == 401
    header, payload, signature = sign().split(".")
    first = "A" if signature[0] != "A" else "B"
    changed = ".".join((header, payload, first + signature[1:]))
    response = service_client.get("/identity", headers={SERVICE_HEADER: changed})
    assert response.status_code == 401
    assert response.headers["X-Policy-Code"] == "service_unverified"


def test_executor_fails_closed_without_signing_keys(oauth, service_client, monkeypatch):
    sign, verifier = oauth

    def unavailable():
        raise PyJWKClientConnectionError("Keycloak отключён")

    monkeypatch.setattr(verifier.keys, "fetch_data", unavailable)
    response = service_client.get("/identity", headers={SERVICE_HEADER: sign()})
    assert response.status_code == 503
    assert response.headers["X-Policy-Code"] == "identity_unavailable"


@pytest.mark.parametrize(
    ("code", "attempts"),
    [("service_token_expired", 2), ("service_audience_invalid", 1)],
)
@pytest.mark.parametrize("bound", [False, True])
def test_retries_only_after_expiry_and_only_once(code, attempts, bound, monkeypatch):
    tokens = iam.ServiceTokens(ISSUER, iam.AGENT_CLIENT, SecretStr("s" * 32))
    issued = []
    seen = []

    async def issue():
        value = f"demo-{len(issued)}"
        token = iam.AccessToken(value, iam.monotonic() + 20, 20)
        issued.append(value)
        return token

    def reject(request):
        assert request.headers["Idempotency-Key"] == "f" * 32
        if bound:
            seen.append(request.headers["Authorization"].removeprefix("Bearer "))
        else:
            seen.append(request.headers[SERVICE_HEADER])
        return httpx2.Response(401, json={"detail": "Отказ"}, headers={"X-Policy-Code": code})

    async def call():
        async with httpx2.AsyncClient(
            base_url="http://executor", transport=httpx2.MockTransport(reject)
        ) as http:
            await client.ExecutorClient(http, tokens, bound=bound).request(
                "GET", "/identity", Caller, headers={"Idempotency-Key": "f" * 32}
            )

    monkeypatch.setattr(tokens, "_issue", issue)
    with pytest.raises(client.ExecutorRejected) as error:
        asyncio.run(call())
    assert error.value.code == code
    assert seen == issued
    assert len(issued) == attempts


def test_expiry_demo_and_regular_requests(oauth, monkeypatch, service_headers, caplog):
    sign, _ = oauth
    realm_path = Path("deploy/ephemeral_tokens/config/dispatcher-realm.json")
    realm = loads(realm_path.read_text(encoding="utf-8"))
    ttl = realm["accessTokenLifespan"]
    scopes = {scope["name"]: scope for scope in realm["clientScopes"]}
    clients = {entry["clientId"]: entry for entry in realm["clients"]}
    clock = [int(iam.time()) - 60]
    issued = []
    exchanges = []
    monkeypatch.setattr(iam, "time", lambda: clock[0])
    monkeypatch.setattr(iam, "monotonic", lambda: clock[0])

    async def advance(seconds):
        clock[0] += seconds

    monkeypatch.setattr(client, "sleep", advance)
    config = Settings(
        _env_file=None,
        service_auth_mode="oauth",
        iam_issuer=ISSUER,
        iam_executor_client_secret="d" * 32,
        iam_monitoring_client_secret="m" * 32,
        executor_url="http://executor",
    )
    monkeypatch.setattr(main, "settings", lambda: config)
    agent_tokens = iam.ServiceTokens(ISSUER, iam.AGENT_CLIENT, config.iam_executor_client_secret)
    monkeypatch.setattr(main, "executor_tokens", lambda: agent_tokens)
    monkeypatch.delitem(main.app.dependency_overrides, main.executor_client)
    caplog.set_level("INFO", logger="dispatcher.workflow.client")

    def grant(request):
        assert request.url == f"{ISSUER}/protocol/openid-connect/token"
        assert request.content == b"grant_type=client_credentials"
        scheme, encoded = request.headers["Authorization"].split()
        assert scheme == "Basic"
        client_id, secret = b64decode(encoded).decode().split(":", maxsplit=1)
        assert (
            secret
            == {
                iam.AGENT_CLIENT: config.iam_executor_client_secret.get_secret_value(),
                iam.MONITOR_CLIENT: config.iam_monitoring_client_secret.get_secret_value(),
            }[client_id]
        )
        registration = clients[client_id]
        scope = registration["defaultClientScopes"][0]
        mapper = scopes[scope]["protocolMappers"][0]["config"]
        token = sign(
            azp=client_id,
            aud=mapper["included.custom.audience"],
            scope=scope,
            exp=clock[0] + ttl,
            jti=str(len(issued)),
        )
        issued.append((client_id, token))
        return httpx2.Response(
            200, json={"access_token": token, "expires_in": ttl, "token_type": "Bearer"}
        )

    class LoggedTransport(httpx2.ASGITransport):
        async def handle_async_request(self, request):
            response = await super().handle_async_request(request)
            exchanges.append(
                (request.url.path, response.status_code, request.headers[iam.REQUEST_ID_HEADER])
            )
            return response

    async_client = httpx2.AsyncClient

    def connect(**kwargs):
        transport = (
            LoggedTransport(app=executor.app)
            if kwargs.get("base_url") == config.executor_url
            else httpx2.MockTransport(grant)
        )
        return async_client(transport=transport, **kwargs)

    monkeypatch.setattr(httpx2, "AsyncClient", connect)
    with TestClient(main.app, headers={"Authorization": service_headers["Authorization"]}) as ui:
        assert ui.get("/api/identity").status_code == 200
        assert ui.get("/api/identity").status_code == 200
        assert [name for name, _ in issued] == [iam.AGENT_CLIENT]
        response = ui.post("/api/service-token-demo")

    assert response.status_code == 200, response.text
    demo = response.json()
    assert demo["fresh"]["status"] == 200
    assert demo["monitoring"] == {"status": 401, "code": "service_audience_invalid"}
    assert demo["expired"] == {"status": 401, "code": "service_token_expired"}
    assert demo["renewed"]["status"] == 200
    assert demo["tool_result"]["code"] == "ok"
    assert [name for name, _ in issued[1:]] == [
        iam.AGENT_CLIENT,
        iam.MONITOR_CLIENT,
        iam.AGENT_CLIENT,
    ]
    expired, renewed = exchanges[-2:]
    assert expired[:2] == ("/tools", 401)
    assert renewed[:2] == ("/tools", 200)
    assert expired[2] == renewed[2]
    assert expired[2] in caplog.text
    assert all(token not in response.text and token not in caplog.text for _, token in issued)
