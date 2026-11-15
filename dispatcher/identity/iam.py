import asyncio
import logging
from dataclasses import dataclass, field
from ssl import SSLContext
from time import monotonic, time
from typing import Literal

import httpx2
import jwt
from jwt.exceptions import PyJWKClientConnectionError, PyJWTError
from pydantic import BaseModel, Field, SecretStr

from dispatcher.identity.access import denied, matches

logger = logging.getLogger(__name__)

AGENT_CLIENT = "diagnostic-agent"
MONITOR_CLIENT = "queue-monitor"
RUNBOOK_CLIENT = "runbook-agent"
EXECUTOR_AUDIENCE = "incident-executor"
EXECUTOR_SCOPE = "executor.access"
RUNBOOK_SCOPE = "runbooks.read"
INCIDENT_SCOPE = "incidents.write"
TOKEN_EXPIRED = "service_token_expired"
REQUEST_ID_HEADER = "X-Request-ID"
OPERATOR_HEADER = "X-Operator-Authorization"

AuthMode = Literal["static", "oauth", "certificate", "mtls_oauth"]


class TokenServiceUnavailable(RuntimeError):
    pass


class TokenGrant(BaseModel):
    access_token: str = Field(min_length=1, repr=False)
    expires_in: int = Field(strict=True, gt=0)
    token_type: str


@dataclass(frozen=True)
class AccessToken:
    value: str = field(repr=False)
    expires_at: float
    lifetime: int

    def usable(self) -> bool:
        return monotonic() < self.expires_at - min(5, self.lifetime / 10)


class ServiceTokens:
    def __init__(
        self, issuer: str, client_id: str, secret: SecretStr, *, tls: SSLContext | None = None
    ):
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.secret = secret
        self.tls = tls
        self._lock = asyncio.Lock()
        self._token: AccessToken | None = None

    async def _issue(self) -> AccessToken:
        secret = self.secret.get_secret_value()
        if (
            not self.issuer
            or len(secret) < 32
            or (self.tls and not self.issuer.startswith("https://"))
        ):
            logger.warning("Выдача сервисного токена недоступна клиент=%s", self.client_id)
            raise TokenServiceUnavailable("Параметры выдачи сервисного токена не настроены.")
        started = monotonic()
        try:
            async with httpx2.AsyncClient(
                timeout=5, trust_env=False, verify=self.tls if self.tls is not None else True
            ) as http:
                response = await http.post(
                    f"{self.issuer}/protocol/openid-connect/token",
                    auth=(self.client_id, secret),
                    data={"grant_type": "client_credentials"},
                )
            response.raise_for_status()
            grant = TokenGrant.model_validate_json(response.content)
            if grant.token_type.lower() != "bearer":
                raise ValueError("Ожидался токен Bearer.")
        except httpx2.HTTPError, httpx2.InvalidURL, ValueError:
            logger.warning("Ошибка выдачи сервисного токена клиент=%s", self.client_id)
            raise TokenServiceUnavailable(
                "Не удалось получить сервисный токен у Keycloak."
            ) from None
        logger.info("Сервисный токен получен клиент=%s срок=%s", self.client_id, grant.expires_in)
        return AccessToken(grant.access_token, started + grant.expires_in, grant.expires_in)

    async def get(self, rejected: AccessToken | None = None) -> AccessToken:
        # Параллельные запросы используют уже перевыданный токен, если отклонена старая копия.
        async with self._lock:
            previous = self._token
            if previous is None or rejected is previous or not previous.usable():
                self._token = None
                self._token = await self._issue()
            return self._token


@dataclass(frozen=True)
class ClientBinding:
    service: str
    thumbprint: str


@dataclass(frozen=True)
class ServiceGrant:
    service: str
    scopes: frozenset[str]
    request_id: str

    def require(self, scope: str) -> None:
        if scope not in self.scopes:
            logger.info("Проверка области доступа сервис=%s область=%s", self.service, scope)
            raise denied(
                403,
                "service_scope_forbidden",
                "У сервисного токена нет права на эту операцию.",
                request_id=self.request_id,
            )


class TokenVerifier:
    def __init__(self, issuer: str, *, tls: SSLContext | None = None):
        self.issuer = issuer.rstrip("/")
        self.keys = jwt.PyJWKClient(
            f"{self.issuer}/protocol/openid-connect/certs", timeout=3, ssl_context=tls
        )

    def verify(
        self, token: str, *, request_id: str, binding: ClientBinding | None = None
    ) -> ServiceGrant:
        def refuse(status: int, code: str, message: str):
            return denied(status, code, message, request_id=request_id)

        if not self.issuer:
            raise refuse(503, "identity_unavailable", "Издатель токенов не настроен.")
        if not token or len(token) > 8192:
            raise refuse(401, "service_unverified", "Требуется сервисный токен.")

        try:
            if jwt.get_unverified_header(token).get("alg") != "RS256":
                raise jwt.InvalidAlgorithmError()
            key = self.keys.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=EXECUTOR_AUDIENCE,
                options={
                    "require": ["iss", "aud", "sub", "azp", "typ", "scope", "iat", "exp"],
                    "verify_exp": False,
                },
            )
            # Обновление разрешаем лишь после проверки остальных подписанных полей.
            if (
                type(claims["exp"]) is not int
                or type(claims["iat"]) is not int
                or claims["exp"] <= claims["iat"]
                or claims["typ"] != "Bearer"
                or not isinstance(claims["scope"], str)
                or not claims["sub"]
                or not isinstance(claims["azp"], str)
            ):
                raise jwt.InvalidTokenError()
        except jwt.InvalidAudienceError:
            raise refuse(
                401, "service_audience_invalid", "Токен выдан для другого сервиса."
            ) from None
        except PyJWKClientConnectionError:
            raise refuse(
                503, "identity_unavailable", "Ключи подписи временно недоступны."
            ) from None
        except PyJWTError, ValueError, TypeError, OverflowError:
            raise refuse(401, "service_unverified", "Сервисный токен не прошёл проверку.") from None

        grant = ServiceGrant(claims["azp"], frozenset(claims["scope"].split()), request_id)
        if binding is None:
            if "cnf" in claims:
                raise refuse(401, "service_binding_invalid", "Для токена требуется mTLS.")
            if grant.service != AGENT_CLIENT:
                raise refuse(
                    403, "service_scope_forbidden", "Сервису не разрешён вызов исполнителя."
                )
            grant.require(EXECUTOR_SCOPE)
        else:
            if grant.service != binding.service:
                raise refuse(403, "service_role_mismatch", "Роли сертификата и токена различаются.")
            confirmation = claims.get("cnf")
            thumbprint = confirmation.get("x5t#S256") if isinstance(confirmation, dict) else None
            if not isinstance(thumbprint, str) or not matches(thumbprint, binding.thumbprint):
                raise refuse(
                    401, "service_binding_invalid", "Токен привязан к другому сертификату."
                )
        if time() >= claims["exp"]:
            raise refuse(401, TOKEN_EXPIRED, "Срок действия сервисного токена истёк.")
        logger.info("Сервисный токен принят клиент=%s запрос=%s", grant.service, request_id)
        return grant
