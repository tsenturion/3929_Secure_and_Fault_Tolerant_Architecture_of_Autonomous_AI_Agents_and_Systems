from enum import StrEnum

from pydantic import BaseModel

from dispatcher.workflow.scenarios import Action, Observation, SourceKind


class Threat(StrEnum):
    INJECTION = "prompt_injection"
    POISONING = "memory_poisoning"
    MISUSE = "tool_misuse"
    EXFILTRATION = "data_exfiltration"


class BoundaryDecision(BaseModel):
    """Объяснение решения защиты, которое показывается в карточке прогона."""

    threat: Threat
    title: str
    detail: str


SOURCE_FOR_ACTION = {
    Action.STATUS: SourceKind.MONITORING,
    Action.DEPLOYMENT: SourceKind.DEPLOYMENT_LOG,
    Action.INDIVIDUAL: SourceKind.PUBLISHED_RUNBOOK,
    Action.INCIDENT: SourceKind.PUBLISHED_RUNBOOK,
}


def source_denial(action: Action, candidate: Observation) -> BoundaryDecision | None:
    """Сверяет тип полученного источника с назначением инструмента чтения."""
    if candidate.kind == SOURCE_FOR_ACTION[action]:
        return None
    if candidate.kind == SourceKind.HISTORICAL_NOTE:
        return BoundaryDecision(
            threat=Threat.POISONING,
            title="Заметка из истории не принята как регламент",
            detail=(
                "Закрытая заявка не имеет статуса опубликованного регламента. "
                "Приоритет рассчитывается по текущим наблюдениям и действующему регламенту."
            ),
        )
    return BoundaryDecision(
        threat=Threat.INJECTION,
        title="Неопубликованная копия исключена из контекста",
        detail=(
            "Каталог вернул копию без статуса публикации. "
            "Агент продолжил разбор по опубликованной версии."
        ),
    )
