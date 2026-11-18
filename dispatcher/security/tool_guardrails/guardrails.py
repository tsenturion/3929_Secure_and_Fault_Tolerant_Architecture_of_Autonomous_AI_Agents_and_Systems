from typing import Literal

from pydantic import BaseModel

from dispatcher.identity.access import NOTIFICATION_REQUESTS, NOTIFICATIONS
from dispatcher.security.agent_threats.boundaries import SOURCE_FOR_ACTION
from dispatcher.workflow.case_ids import is_work_case
from dispatcher.workflow.scenarios import Action


class ToolScope(BaseModel):
    """Ресурс, разрешённые инструменты и лимиты диагностического прогона."""

    resource: str
    actions: tuple[Action, ...]
    max_calls: int
    max_calls_per_action: int
    max_response_bytes: int


NOTIFICATION_SCOPE = ToolScope(
    resource=NOTIFICATIONS,
    actions=tuple(SOURCE_FOR_ACTION),
    max_calls=4,
    max_calls_per_action=1,
    max_response_bytes=2048,
)


def scope_for(scenario_id: str) -> ToolScope | None:
    return (
        NOTIFICATION_SCOPE
        if scenario_id in NOTIFICATION_REQUESTS or is_work_case(scenario_id)
        else None
    )


LimitCode = Literal["call_limit_reached", "action_limit_reached"]
LIMIT_MESSAGES: dict[LimitCode, str] = {
    "call_limit_reached": "Лимит чтений прогона исчерпан.",
    "action_limit_reached": "Источник уже запрошен в этом прогоне. Используйте сохранённое наблюдение.",
}


def call_limit(scope: ToolScope, actions: list[str], action: str) -> LimitCode | None:
    """Проверяет общий лимит чтений, затем лимит выбранного инструмента."""
    if len(actions) >= scope.max_calls:
        return "call_limit_reached"
    if actions.count(action) >= scope.max_calls_per_action:
        return "action_limit_reached"
    return None
