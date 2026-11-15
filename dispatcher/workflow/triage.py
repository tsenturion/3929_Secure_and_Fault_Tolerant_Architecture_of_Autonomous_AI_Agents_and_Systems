import asyncio
import logging
from enum import StrEnum
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, computed_field

from dispatcher.models.adapters import (
    Decision,
    InferenceResult,
    Model,
    ModelError,
    ModelFailure,
    ModelUnavailable,
    OutputRejected,
    RiskJudge,
    choice_context,
    validate_decision,
)
from dispatcher.multiagent.coordination.coordination_protocol import CoordinationTrace
from dispatcher.multiagent.hierarchy.delegation import DelegationTrace
from dispatcher.multiagent.information_flow import FlowCheck, FlowData, Party
from dispatcher.observability.tracing.telemetry import (
    TraceContext,
    current,
    error_code,
    event,
    span,
)
from dispatcher.resilience.retry_and_circuit_breaker.monitoring import MonitoringTrace
from dispatcher.security.agent_threats.boundaries import BoundaryDecision, Threat
from dispatcher.security.data_exfiltration.publication import (
    PUBLIC_FIELDS,
    IncidentField,
    Publication,
)
from dispatcher.security.filters import FilterCheck, SupportExport, display_text
from dispatcher.security.shield import RiskInput, RiskVerdict, ShieldCheck
from dispatcher.security.source_access.runbook_catalog import RUNBOOK_IDS
from dispatcher.security.tool_guardrails.guardrails import scope_for
from dispatcher.settings import Provider
from dispatcher.workflow.approval_policy import ApprovalBlock, ApprovalCode, ApprovalDecision
from dispatcher.workflow.execution import (
    ExecutorUnavailable,
    RunId,
    Scope,
    ToolExecutor,
    ToolProposal,
    ToolResult,
)
from dispatcher.workflow.lifecycle import Lifecycle, Phase
from dispatcher.workflow.registration import can_draft_manually
from dispatcher.workflow.scenarios import (
    ACTION_LABELS,
    Action,
    Fault,
    Observation,
    Scenario,
)

logger = logging.getLogger(__name__)


class Mode(StrEnum):
    FIXED = "fixed"
    AGENT = "agent"


class Step(BaseModel):
    action: Action
    label: str
    selected_by: Literal["route", "model", "rule", "operator"]
    reason: str
    observation: Observation | None
    executor_code: str | None = None
    decision_provider: Provider | None = None


class Recommendation(BaseModel):
    category: Literal["incident", "individual", "manual"]
    title: str
    detail: str
    priority: Literal["P1", "P2"] | None = None
    queue: str | None = None
    incident_fields: list[IncidentField] = Field(default_factory=lambda: list(PUBLIC_FIELDS))


class Run(BaseModel):
    id: RunId
    trace_id: RunId | None = None
    trace_span_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{16}$")] | None = None
    step_limit: int | None = Field(default=None, ge=1)
    scenario_id: str
    mode: Mode
    provider: Provider | None
    steps: list[Step]
    recommendation: Recommendation
    lifecycle: Lifecycle
    incident_id: str | None = None
    publication: Publication | None = None
    approval_block: ApprovalBlock | None = None
    approval_deadline: AwareDatetime | None = None
    error: str | None = None
    threat: Threat | None = None
    boundary_decisions: list[BoundaryDecision] = Field(default_factory=list)
    shield_checks: list[ShieldCheck] = Field(default_factory=list)
    review_required: bool = False
    fault: Fault | None = None
    degradation: ModelFailure | None = None
    manual_evidence: list[Step] = Field(default_factory=list)
    monitoring: MonitoringTrace | None = None
    model_result: InferenceResult | None = None
    coordination: CoordinationTrace | None = None
    delegation: DelegationTrace | None = None
    information: FlowData = Field(default_factory=FlowData)
    flow_checks: list[FlowCheck] = Field(default_factory=list)
    filter_checks: list[FilterCheck] = Field(default_factory=list)
    support_card_available: bool = False
    case_revision: int | None = None
    case_scope: Scope | None = None

    @computed_field
    @property
    def status(self) -> Phase:
        return self.lifecycle.phase

    @computed_field
    @property
    def manual_registration_available(self) -> bool:
        return can_draft_manually(self)

    def trace_context(self) -> TraceContext | None:
        if self.trace_id is None or self.trace_span_id is None:
            return None
        return TraceContext(self.trace_id, self.id, self.scenario_id, self.trace_span_id)


class RunWithSupport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run: Run
    support_export: SupportExport


class ComparisonCase(StrEnum):
    NORMAL = "normal"
    POLICY = "policy_denied"
    MODEL = "model_unavailable"
    LOST_REPLY = "reply_lost_after_commit"


class Checkpoint(BaseModel):
    title: str
    operator: str
    status: Phase
    incident_count: int
    incident_id: str | None
    policy_code: ApprovalCode | None = None


class ComparedRun(BaseModel):
    case: ComparisonCase
    title: str
    checkpoints: list[Checkpoint]
    trace: Run


class FailClosedComparison(BaseModel):
    blocked: Checkpoint
    restored: Checkpoint


class HierarchyComparison(BaseModel):
    blocked: Checkpoint
    approved: Checkpoint
    publication: Publication


class RegistrationCheckExample(BaseModel):
    label: str
    queue: str
    decision: ApprovalDecision


class RegistrationComparison(BaseModel):
    examples: list[RegistrationCheckExample]
    rejected_code: ApprovalCode
    incident_count: int


class ApprovalTimeoutComparison(BaseModel):
    timely: Checkpoint
    late: Checkpoint


FIXED_ROUTE = (Action.STATUS, Action.DEPLOYMENT, Action.INDIVIDUAL, Action.INCIDENT, Action.FINISH)


def recommend(scope: Scope | None, seen: set[Action]) -> Recommendation:
    if scope is not None:
        match scope:
            case "incident" if {Action.DEPLOYMENT, Action.INCIDENT} <= seen:
                return Recommendation(
                    category="incident",
                    title="Предложено открыть инцидент P2",
                    detail=(
                        "Возраст очереди превышает 15 минут, оформление заказов работает. "
                        "Регламент RB-NOTIFY-07 требует согласования дежурным. Причина уточняется."
                    ),
                    priority="P2",
                    queue="Уведомления",
                )
            case "individual" if Action.INDIVIDUAL in seen:
                return Recommendation(
                    category="individual",
                    title="Проверить доставку для одного заказа",
                    detail=(
                        "Состояние очереди в пределах цели. RB-NOTIFY-03 предлагает проверить "
                        "факт доставки и фильтрацию письма для конкретного заказа."
                    ),
                )
    return Recommendation(
        category="manual",
        title="Передано на разбор дежурному",
        detail="Для автоматической рекомендации недостаточно подтверждённых наблюдений.",
    )


async def run_triage(
    scenario: Scenario,
    mode: Mode,
    model: Model | None = None,
    provider: Provider | None = None,
    *,
    executor: ToolExecutor,
    max_steps: int = 5,
    timeout: float = 45,
    fault: Fault | None = None,
    threat: Threat | None = None,
    judge: RiskJudge | None = None,
    input_checks: tuple[FilterCheck, ...] = (),
    model_problem: ModelUnavailable | None = None,
    rules_only: bool = False,
) -> Run:
    trace = current.get()
    run_id = trace.run_id if trace is not None else uuid4().hex
    logger.info(
        "Начат прогон %s обращение=%s режим=%s провайдер=%s",
        run_id,
        scenario.view.id,
        mode,
        provider,
    )
    steps: list[Step] = []
    boundary_decisions: list[BoundaryDecision] = []
    shield_checks: list[ShieldCheck] = []
    filter_checks = list(input_checks)
    review_required = False
    observations: list[dict[str, str]] = []
    seen: set[Action] = set()
    tool_scope = scope_for(scenario.view.id)
    if tool_scope is None:
        raise ValueError("Для обращения не задана область действий.")
    lifecycle = Lifecycle()
    lifecycle.move(
        Phase.OBSERVE,
        f"Получено обращение {scenario.view.id}",
        f"{scenario.view.source}. {display_text(scenario.view.report)}",
    )
    result_error = None
    information = FlowData()
    flow_checks: list[FlowCheck] = []
    degradation = None
    monitoring = None
    model_result = None
    scope = None
    recommendation = recommend(scope, seen)
    deadline = asyncio.get_running_loop().time() + timeout

    try:
        for preset_action in FIXED_ROUTE[:max_steps]:
            selected_by: Literal["route", "model", "rule"]
            if asyncio.get_running_loop().time() >= deadline:
                raise ModelError("Истёк общий срок разбора обращения.")
            if mode == Mode.FIXED:
                selected_by = "route"
                decision = Decision(action=preset_action, reason="Шаг задан маршрутом.")
            elif not seen:
                selected_by = "rule"
                decision = Decision(
                    action=Action.STATUS, reason="Начальный снимок нужен для диагностики."
                )
            elif recommendation.category != "manual":
                selected_by = "rule"
                decision = Decision(
                    action=Action.FINISH,
                    reason="Собраны доказательства, достаточные для рекомендации.",
                )
            elif rules_only:
                selected_by = "rule"
                actions = {
                    "incident": (Action.DEPLOYMENT, Action.INCIDENT),
                    "individual": (Action.INDIVIDUAL,),
                }.get(scope, ())
                decision = Decision(
                    action=next(
                        (action for action in actions if action not in seen), Action.FINISH
                    ),
                    reason="Шаг выбран по состоянию очереди и регламенту.",
                )
            else:
                selected_by = "model"
                allowed = {
                    action: ACTION_LABELS[action]
                    for action in (*tool_scope.actions, Action.FINISH)
                    if action not in seen
                }
                context = choice_context(
                    scenario, observations, allowed, information=information, checks=flow_checks
                )
                if scenario.customer_email and not boundary_decisions:
                    boundary_decisions.append(
                        BoundaryDecision(
                            threat=Threat.EXFILTRATION,
                            title="Контакт покупателя исключён из запроса",
                            detail=(
                                "Разрешённые поля запроса: описание обращения, "
                                "наблюдения и перечень доступных действий."
                            ),
                        )
                    )
                try:
                    with span("model_decide", provider=provider):
                        if model_problem is not None:
                            raise model_problem
                        assert model is not None
                        async with asyncio.timeout_at(deadline):
                            decision = validate_decision(
                                await asyncio.to_thread(model.decide, context, allowed)
                            )
                except TimeoutError as error:
                    model_result = InferenceResult.UNAVAILABLE
                    raise ModelUnavailable(
                        "Истёк общий срок ожидания решения модели.", ModelFailure.TIMEOUT
                    ) from error
                except ModelError as error:
                    model_result = (
                        InferenceResult.INVALID_OUTPUT
                        if isinstance(error, OutputRejected)
                        else InferenceResult.UNAVAILABLE
                    )
                    raise
                else:
                    model_result = InferenceResult.OK
                if input_checks and not any(check.boundary == "output" for check in filter_checks):
                    filter_checks.append(
                        FilterCheck(
                            boundary="output",
                            code="decision_validated",
                            detail="Ответ содержит допустимые поля: код действия и объяснение.",
                        )
                    )

            action = Action(decision.action) if decision.action in ACTION_LABELS else None
            label = ACTION_LABELS[action] if action is not None else "Предложен инструмент"
            detail = decision.reason[:350] if action is not None else "Код передан исполнителю."
            lifecycle.move(Phase.REASON, label, detail)
            execution: ToolResult | None = None
            observation = None
            if action == Action.FINISH:
                lifecycle.move(Phase.ACT, "Сформирована рекомендация", recommendation.detail)
            else:
                # Решение модели здесь только предложение: исполнитель отдельно проверяет
                # область действия, лимит вызовов и актуальность рабочего обращения.
                try:
                    async with asyncio.timeout_at(deadline):
                        execution = await executor.execute(
                            ToolProposal(
                                action=decision.action,
                                resource=tool_scope.resource,
                                document_id=RUNBOOK_IDS.get(decision.action),
                                scenario_id=scenario.view.id,
                                run_id=run_id,
                                case_revision=scenario.case_revision,
                                fault=fault,
                                threat=threat,
                            )
                        )
                except TimeoutError as error:
                    message = f"Источник не ответил вовремя. Действие: «{label}»."
                    lifecycle.move(Phase.ACT, "Чтение завершилось таймаутом", message)
                    raise ModelError(message) from error
                except ExecutorUnavailable as error:
                    lifecycle.move(Phase.ACT, "Исполнитель недоступен", str(error))
                    raise ModelError(str(error)) from error
                if execution.monitoring is not None:
                    monitoring = execution.monitoring
                boundary_decisions.extend(execution.boundary_decisions)
                shield_checks.append(
                    ShieldCheck(
                        level="policy",
                        code=execution.code,
                        detail=(
                            f"{label}. Запрос прошёл проверку исполнителя."
                            if execution.code == "ok"
                            else execution.message
                        ),
                    )
                )
                if execution.code in {"not_allowed", "action_limit_reached", "call_limit_reached"}:
                    boundary_decisions.append(
                        BoundaryDecision(
                            threat=Threat.MISUSE,
                            title="Действие отклонено до вызова",
                            detail=execution.message,
                        )
                    )
                if execution.code != "ok":
                    if execution.code in {
                        "action_limit_reached",
                        "call_limit_reached",
                        "response_too_large",
                        "run_scope_mismatch",
                        "run_closed",
                    }:
                        review_required = True
                    title = {
                        "timeout": "Чтение завершилось таймаутом",
                        "circuit_open": "Чтение приостановлено",
                        "source_unavailable": "Источник недоступен",
                    }.get(execution.code, "Исполнитель отклонил действие")
                    lifecycle.move(Phase.ACT, title, f"{execution.message} Код: {execution.code}.")
                    raise ModelError(execution.message)
                observation = execution.observation
                assert observation is not None
                if action == Action.STATUS:
                    information = execution.information.forward(
                        Party.MONITORING, Party.TRIAGE, flow_checks
                    )
                observation = observation.model_copy(
                    update={
                        "summary": display_text(observation.summary),
                        "source": display_text(observation.source),
                        "observed_at": display_text(observation.observed_at),
                    }
                )
                scope = execution.scope or scope
                lifecycle.move(Phase.ACT, "Источник прочитан", observation.source)
            assert action is not None
            steps.append(
                Step(
                    action=action,
                    label=ACTION_LABELS[action],
                    selected_by=selected_by,
                    reason=decision.reason[:350],
                    observation=observation,
                    executor_code=execution.code if execution else None,
                    decision_provider=provider if selected_by == "model" else None,
                )
            )
            if observation is None:
                break
            seen.add(action)
            observations.append(
                {
                    "действие": action,
                    "источник": observation.source,
                    "время": observation.observed_at,
                    "содержание": observation.summary,
                }
            )
            lifecycle.move(Phase.OBSERVE, observation.source, observation.summary)
            if execution is not None and execution.risk is not None:
                risk = execution.risk
                shield_checks.append(
                    ShieldCheck(
                        level="heuristics",
                        code=(
                            "conflicting_signals"
                            if risk.conflicting_signals
                            else "stale_snapshot"
                            if risk.stale
                            else "clear"
                        ),
                        detail=(
                            f"Жалоб за 10 минут: {risk.recent_reports}. "
                            f"Возраст снимка: {risk.snapshot_age_minutes} мин."
                        ),
                    )
                )
                if risk.stale:
                    if risk.conflicting_signals:
                        shield_checks.append(await assess_risk(risk, judge, deadline))
                    review_required = True
                    raise ModelError(
                        "Снимок очереди устарел. Дежурному нужно проверить свежие данные."
                    )
            recommendation = recommend(scope, seen)
        else:
            raise ModelError(f"Достигнут лимит шагов ({max_steps}).")
    except ModelError as error:
        recommendation = recommend(None, set())
        result_error = str(error)
        if isinstance(error, OutputRejected):
            filter_checks.append(
                FilterCheck(
                    boundary="output",
                    code="invalid_model_output",
                    detail=result_error,
                )
            )
            review_required = True
        if isinstance(error, ModelUnavailable) and provider is not None:
            degradation = error.code
            shield_checks.append(
                ShieldCheck(
                    level="hitl",
                    code="manual_review_required",
                    detail="Решение модели недоступно. Дежурному переданы собранные наблюдения.",
                )
            )
        lifecycle.move(Phase.NEEDS_REVIEW, "Требуется ручной разбор", result_error)
        logger.warning(
            "Остановлен прогон %s шагов=%d код=%s",
            run_id,
            len(steps),
            error_code(error),
        )
    else:
        if recommendation.category == "incident" and mode == Mode.AGENT and threat is None:
            # Разбор формирует черновик; запись инцидента возможна после решения дежурного.
            shield_checks.append(
                ShieldCheck(
                    level="hitl",
                    code="approval_required",
                    detail="Регистрация инцидента ожидает подтверждения дежурного.",
                )
            )
            lifecycle.move(
                Phase.AWAITING_APPROVAL,
                "Передано на согласование",
                "Оператор проверяет приоритет P2 и очередь «Уведомления».",
            )
        elif recommendation.category == "manual":
            lifecycle.move(Phase.NEEDS_REVIEW, "Требуется ручной разбор", recommendation.detail)
        else:
            lifecycle.move(Phase.COMPLETED, "Разбор завершён", recommendation.title)

    if review_required:
        shield_checks.append(
            ShieldCheck(
                level="hitl",
                code="manual_review_required",
                detail="Дежурный может принять обращение в ручной разбор.",
            )
        )
    logger.info(
        "Прогон %s состояние=%s результат=%s", run_id, lifecycle.phase, recommendation.category
    )
    for check in boundary_decisions:
        logger.info("Проверка границы прогон=%s категория=%s", run_id, check.threat)
    for check in shield_checks:
        logger.info("Shield прогон=%s уровень=%s код=%s", run_id, check.level, check.code)
        event("policy", check.code, check_level=check.level)
    for check in filter_checks:
        logger.info("Фильтрация прогон=%s граница=%s код=%s", run_id, check.boundary, check.code)
        event("filter", check.code, check_level=check.boundary)
    return Run(
        id=run_id,
        trace_id=trace.trace_id if trace else None,
        trace_span_id=trace.span_id if trace else None,
        step_limit=max_steps,
        scenario_id=scenario.view.id,
        case_revision=scenario.case_revision,
        case_scope=scope if scenario.case_revision is not None else None,
        mode=mode,
        provider=provider,
        steps=steps,
        recommendation=recommendation,
        lifecycle=lifecycle,
        error=result_error,
        threat=threat,
        boundary_decisions=boundary_decisions,
        shield_checks=shield_checks,
        review_required=review_required,
        fault=fault,
        degradation=degradation,
        monitoring=monitoring,
        model_result=model_result,
        information=information,
        flow_checks=flow_checks,
        filter_checks=filter_checks,
    )


async def assess_risk(risk: RiskInput, judge: RiskJudge | None, deadline: float) -> ShieldCheck:
    try:
        if judge is None:
            raise ModelError("Судья не настроен.")
        with span("model_judge"):
            async with asyncio.timeout_at(deadline):
                verdict = RiskVerdict.model_validate(await asyncio.to_thread(judge.judge, risk))
    except TimeoutError, ModelError, ValueError:
        return ShieldCheck(
            level="judge",
            code="judge_unavailable",
            detail="Оценка судьи недоступна. Случай требует проверки дежурным.",
        )
    return ShieldCheck(level="judge", code=verdict.verdict, detail=verdict.reason)
