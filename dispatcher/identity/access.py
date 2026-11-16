import logging
from dataclasses import dataclass
from enum import StrEnum
from secrets import compare_digest

from fastapi import HTTPException
from pydantic import BaseModel, SecretStr

from dispatcher.workflow.approval_policy import DEMO_OPERATOR
from dispatcher.workflow.case_ids import is_work_case

logger = logging.getLogger(__name__)

SERVICE_HEADER = "X-Service-Token"
NOTIFICATIONS = "order-notifications"
PAYMENTS = "payments"
NOTIFICATION_REQUESTS = frozenset({"REQ-1842", "REQ-1843"})


class Operator(StrEnum):
    DUTY = DEMO_OPERATOR
    OBSERVER = "observer"


class AccessKeys(BaseModel):
    """Локальные ключи сервиса и двух ролей кабинета."""

    service_token: SecretStr = SecretStr("")
    duty_operator_token: SecretStr = SecretStr("")
    observer_token: SecretStr = SecretStr("")

    def authenticate(self, service_token: str, authorization: str) -> Caller:
        """Подтверждает личность сервиса и определяет оператора по отдельному ключу."""
        tokens = (
            self.service_token.get_secret_value(),
            self.duty_operator_token.get_secret_value(),
            self.observer_token.get_secret_value(),
        )
        if any(len(token) < 32 for token in tokens) or len(set(tokens)) != 3:
            raise denied(503, "identity_unavailable", "Ключи доступа исполнителя не настроены.")
        if not matches(service_token, tokens[0]):
            raise denied(401, "service_unverified", "Личность вызывающего сервиса не подтверждена.")
        return self.identify_operator(authorization)

    def identify_operator(self, authorization: str) -> Caller:
        """Определяет роль пользователя по ключу из заголовка авторизации."""
        duty = self.duty_operator_token.get_secret_value()
        observer = self.observer_token.get_secret_value()
        if min(len(duty), len(observer)) < 32 or duty == observer:
            raise denied(503, "identity_unavailable", "Ключи пользователей не настроены.")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer":
            if matches(token, duty):
                return Caller(operator=Operator.DUTY)
            if matches(token, observer):
                return Caller(operator=Operator.OBSERVER)
        raise denied(401, "operator_unverified", "Ключ пользователя отсутствует или неверен.")


@dataclass(frozen=True, kw_only=True)
class Caller:
    operator: Operator
    service: str = "diagnostic-agent"

    def require_duty(self) -> None:
        if self.operator != Operator.DUTY:
            raise denied(403, "operation_forbidden", "Изменение доступно дежурному.")

    def require_case(self, scenario_id: str, operation: str) -> None:
        """Проверяет право оператора на конкретную операцию с обращением."""
        if is_work_case(scenario_id):
            if operation != "read":
                self.require_duty()
            return
        if scenario_id not in NOTIFICATION_REQUESTS:
            raise denied(403, "resource_forbidden", "Обращение вне области доступа.")
        if operation == "read_support":
            if self.operator != Operator.DUTY:
                raise denied(403, "operation_forbidden", "Карточка поддержки доступна дежурному.")
            return
        if operation not in {"read", "save"} and (
            operation != "resolve" or self.operator != Operator.DUTY
        ):
            raise denied(403, "operation_forbidden", "Согласование доступно дежурному.")


def matches(candidate: str, expected: str) -> bool:
    return compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def denied(status: int, code: str, message: str, *, request_id: str | None = None) -> HTTPException:
    if request_id is None:
        logger.warning("Доступ отклонён код=%s", code)
    else:
        logger.warning("Доступ отклонён код=%s запрос=%s", code, request_id)
    return HTTPException(status, message, headers={"X-Policy-Code": code})
