import asyncio
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from dispatcher.multiagent.information_flow import MessageId


class Action(StrEnum):
    STATUS = "get_service_status"
    DEPLOYMENT = "get_recent_deployment"
    INDIVIDUAL = "find_individual_runbook"
    INCIDENT = "find_incident_runbook"
    FINISH = "finish"


class Fault(StrEnum):
    MONITORING_TIMEOUT = "monitoring_timeout"
    STALE_MONITORING = "stale_monitoring"
    INVALID_MODEL_OUTPUT = "invalid_model_output"
    REPEATED_MONITORING = "repeated_monitoring"
    OVERSIZED_OBSERVATION = "oversized_observation"
    MODEL_UNAVAILABLE = "model_unavailable"


class SourceKind(StrEnum):
    MONITORING = "monitoring"
    DEPLOYMENT_LOG = "deployment_log"
    PUBLISHED_RUNBOOK = "published_runbook"
    UNPUBLISHED_COPY = "unpublished_copy"
    HISTORICAL_NOTE = "historical_note"


ACTION_LABELS = {
    Action.STATUS: "Снять показатели сервиса",
    Action.DEPLOYMENT: "Проверить последнее развёртывание",
    Action.INDIVIDUAL: "Найти регламент индивидуальной доставки",
    Action.INCIDENT: "Найти регламент массовой задержки",
    Action.FINISH: "Сформировать результат",
}


class ScenarioView(BaseModel):
    id: str
    title: str
    received_at: str
    report: str
    source: str = "Служба поддержки"
    goal: str = "Оценить влияние задержки и предложить следующий шаг дежурному."


class Observation(BaseModel):
    source: str
    observed_at: str
    summary: str
    kind: SourceKind | None = None


class Monitoring(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    queue_size: int = Field(ge=0)
    oldest_minutes: int = Field(ge=0)
    checkout_healthy: bool
    channel: Literal["email"] = "email"
    message_ids: tuple[MessageId, ...] = Field(default=(), max_length=8)
    observed_at: str = Field(default="14:12", pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")

    @property
    def scope(self) -> Literal["incident", "individual", "uncertain"]:
        if not self.checkout_healthy:
            return "uncertain"
        if self.oldest_minutes > 15:
            return "incident"
        if self.oldest_minutes <= 5:
            return "individual"
        return "uncertain"

    def observation(self, *, sample: bool = True) -> Observation:
        checkout = "штатно" if self.checkout_healthy else "наблюдаются ошибки"
        return Observation(
            source="Мониторинг · order-notifications",
            kind=SourceKind.MONITORING,
            observed_at=self.observed_at,
            summary=(
                f"В почтовой очереди {self.queue_size:,d} сообщений. Возраст старейшего "
                f"сообщения — {self.oldest_minutes} мин при цели до 5 мин. "
                + ("Канал push работает штатно. " if sample else "")
                + f"Заказы и оплата: {checkout}."
            ).replace(",", " "),
        )


@dataclass(frozen=True)
class Scenario:
    view: ScenarioView
    monitoring: Monitoring
    report_count: int
    observed_since: str
    customer_email: str | None = None
    case_revision: int | None = None
    snapshot_at: datetime | None = None
    deployment: Observation | None = None

    def read(self, action: Action) -> Observation:
        if action == Action.STATUS:
            observation = self.monitoring.observation(sample=self.case_revision is None)
            if self.snapshot_at is not None:
                observation.observed_at = self.observed_since
            return observation
        if action == Action.DEPLOYMENT and self.deployment is not None:
            return self.deployment.model_copy()
        return SOURCES[action].model_copy()


async def read_observation(scenario: Scenario, action: Action, fault: Fault | None) -> Observation:
    if action == Action.STATUS and fault == Fault.MONITORING_TIMEOUT:
        async with asyncio.timeout(2):
            await asyncio.Future()
    if action == Action.STATUS and fault == Fault.STALE_MONITORING:
        return STALE_MONITORING.observation().model_copy(update={"observed_at": "13:50"})
    if action == Action.STATUS and fault == Fault.OVERSIZED_OBSERVATION:
        observation = scenario.read(action)
        return observation.model_copy(update={"summary": (observation.summary + " ") * 25})
    return scenario.read(action)


STALE_MONITORING = Monitoring(queue_size=126, oldest_minutes=2, checkout_healthy=True)


SCENARIOS = {
    "REQ-1842": Scenario(
        ScenarioView(
            id="REQ-1842",
            title="Массовая задержка после обновления",
            received_at="14:12",
            report=(
                "Во время акции за 10 минут поступило 18 жалоб. Покупатели видят "
                "оплаченные заказы в личном кабинете, но письма о подтверждении "
                "приходят с задержкой или отсутствуют."
            ),
        ),
        Monitoring(
            queue_size=4800,
            oldest_minutes=17,
            checkout_healthy=True,
            message_ids=("MSG-NOTIFY-1842-001", "MSG-NOTIFY-1842-002"),
        ),
        report_count=18,
        observed_since="14:02",
    ),
    "REQ-1843": Scenario(
        ScenarioView(
            id="REQ-1843",
            title="Один покупатель не получил письмо",
            received_at="14:12",
            report=(
                "За 10 минут поступила одна жалоба. Покупатель видит оплаченный "
                "заказ в личном кабинете, но письмо о подтверждении отсутствует."
            ),
        ),
        Monitoring(queue_size=126, oldest_minutes=2, checkout_healthy=True),
        report_count=1,
        observed_since="14:02",
    ),
}

SOURCES = {
    Action.DEPLOYMENT: Observation(
        source="Журнал развёртываний · order-notifications",
        kind=SourceKind.DEPLOYMENT_LOG,
        observed_at="13:52",
        summary=(
            "Обновился обработчик почтовой очереди. Журнал фиксирует время обновления. "
            "Причину задержки нужно подтвердить диагностикой."
        ),
    ),
    Action.INDIVIDUAL: Observation(
        source="RB-NOTIFY-03 · Индивидуальная доставка",
        kind=SourceKind.PUBLISHED_RUNBOOK,
        observed_at="действующая версия",
        summary=(
            "При здоровой очереди проверить доставку для конкретного заказа "
            "и возможную фильтрацию письма у получателя."
        ),
    ),
    Action.INCIDENT: Observation(
        source="RB-NOTIFY-07 · Массовая задержка",
        kind=SourceKind.PUBLISHED_RUNBOOK,
        observed_at="действующая версия",
        summary=(
            "При возрасте очереди свыше 15 минут и штатном оформлении заказов "
            "предложить P2 в очереди «Уведомления» после подтверждения дежурным."
        ),
    ),
}
