from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from dispatcher.security.agent_threats.boundaries import SOURCE_FOR_ACTION
from dispatcher.security.data_exfiltration.publication import PUBLIC_FIELDS, IncidentField
from dispatcher.workflow.approval_policy import ApprovalCode, ApprovalDecision, check_assignment
from dispatcher.workflow.lifecycle import Phase
from dispatcher.workflow.scenarios import SCENARIOS, Action, Fault

if TYPE_CHECKING:
    from dispatcher.workflow.triage import Run


class RegistrationArguments(BaseModel):
    """Структура параметров инцидента для проверки сохранённого черновика."""

    model_config = ConfigDict(extra="forbid")

    priority: Literal["P2"]
    queue: str = Field(min_length=1, max_length=80)
    incident_fields: list[IncidentField] = Field(max_length=len(IncidentField))


INCIDENT_QUEUE = "Уведомления"
REQUIRED_EVIDENCE = (Action.STATUS, Action.DEPLOYMENT, Action.INCIDENT)


class ManualDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    priority: Literal["P2"]


def can_draft_manually(run: Run) -> bool:
    scenario = SCENARIOS.get(run.scenario_id)
    return (
        run.degradation is not None
        and run.provider is not None
        and run.mode == "agent"
        and run.threat is None
        and not run.review_required
        and run.fault in {None, Fault.MODEL_UNAVAILABLE}
        and (scenario.monitoring.scope if scenario is not None else run.case_scope) == "incident"
    )


def check_registration(
    run: Run,
    *,
    confirmed: bool,
    operator: str,
    policy_path: Path,
) -> ApprovalDecision:
    """Проверяет состав публикации и условия согласования сохранённого черновика."""
    draft = run.recommendation
    # Запрет на поле публикации действует независимо от назначения и подтверждения дежурного.
    if any(field not in PUBLIC_FIELDS for field in draft.incident_fields):
        return ApprovalDecision(
            code=ApprovalCode.DATA_POLICY_DENIED,
            message="Политика данных запрещает публикацию контактов покупателей.",
        )
    try:
        arguments = RegistrationArguments(
            priority=draft.priority,
            queue=draft.queue,
            incident_fields=draft.incident_fields,
        )
    except ValidationError:
        return invalid_draft()
    scenario = SCENARIOS.get(run.scenario_id)
    manual = can_draft_manually(run)
    if (
        arguments.queue != INCIDENT_QUEUE
        or (scenario.monitoring.scope if scenario is not None else run.case_scope) != "incident"
        or run.mode != "agent"
        or run.threat is not None
        or run.review_required
        or (not manual and (run.degradation is not None or run.fault is not None))
        or draft.category != "incident"
        or run.status != Phase.AWAITING_APPROVAL
    ):
        return invalid_draft()
    evidence = {
        # Засчитываем шаг только при наличии наблюдения ожидаемого типа.
        step.action
        for step in (run.manual_evidence if manual else run.steps)
        if step.action in REQUIRED_EVIDENCE
        and step.observation is not None
        and step.observation.kind == SOURCE_FOR_ACTION[step.action]
    }
    if not set(REQUIRED_EVIDENCE).issubset(evidence):
        return ApprovalDecision(
            code=ApprovalCode.EVIDENCE_REQUIRED,
            message="Для регистрации нужны снимок очереди, журнал развёртываний и регламент.",
        )
    if not confirmed:
        return ApprovalDecision(
            code=ApprovalCode.CONFIRMATION_REQUIRED,
            message="Черновик ожидает подтверждения дежурным.",
        )
    return check_assignment(policy_path, arguments.queue, operator)


def invalid_draft() -> ApprovalDecision:
    return ApprovalDecision(
        code=ApprovalCode.INVALID_DRAFT,
        message="Черновик не соответствует условиям регистрации P2 в очереди «Уведомления».",
    )
