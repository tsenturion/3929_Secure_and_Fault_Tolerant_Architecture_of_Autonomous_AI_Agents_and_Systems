import asyncio
import logging
from datetime import UTC, datetime, time
from typing import TYPE_CHECKING

from dispatcher.identity.access import Caller, denied
from dispatcher.multiagent.information_flow import DataField, FlowData, Key, Level, queue_data
from dispatcher.observability.tracing.telemetry import event, span
from dispatcher.resilience.retry_and_circuit_breaker.monitoring import MonitoringClient
from dispatcher.security.agent_threats.boundaries import SOURCE_FOR_ACTION, source_denial
from dispatcher.security.agent_threats.demonstrations import source_candidate
from dispatcher.security.filters import display_text
from dispatcher.security.shield import RiskInput
from dispatcher.security.source_access.runbook_catalog import (
    RUNBOOK_IDS,
    CatalogError,
    RunbookCatalog,
)
from dispatcher.security.tool_guardrails.guardrails import scope_for
from dispatcher.workflow.case_ids import is_work_case
from dispatcher.workflow.execution import ToolProposal, ToolResult
from dispatcher.workflow.registration import REQUIRED_EVIDENCE
from dispatcher.workflow.scenarios import (
    ACTION_LABELS,
    SCENARIOS,
    STALE_MONITORING,
    Action,
    Fault,
    Observation,
    Scenario,
    read_observation,
)
from dispatcher.workflow.triage import Run, Step

if TYPE_CHECKING:
    from dispatcher.persistence.storage import RunStore

logger = logging.getLogger(__name__)


async def authorized_tool(
    caller: Caller, proposal: ToolProposal, store: RunStore, *, tools: LocalTools | None = None
) -> ToolResult:
    """Проверяет допустимость запроса перед вызовом инструмента чтения."""
    caller.require_case(proposal.scenario_id, "read")
    work = is_work_case(proposal.scenario_id)
    if work:
        caller.require_duty()
        if proposal.fault is not None or proposal.threat is not None:
            raise denied(
                403, "work_case_policy", "Учебный режим недоступен для рабочего обращения."
            )
    scope = scope_for(proposal.scenario_id)
    # Подтверждённый отправитель всё равно должен запрашивать ресурс из области обращения.
    if scope is None or proposal.resource != scope.resource:
        await asyncio.to_thread(
            store.audit_tool, caller, proposal, "resource_forbidden", admitted=False
        )
        event("source_policy", "resource_forbidden")
        raise denied(403, "resource_forbidden", "Ресурс недоступен для диагностического агента.")
    admitted = False
    if proposal.action not in scope.actions:
        # Отклонённое действие не резервирует вызов и не передаётся инструменту.
        result = ToolResult(code="not_allowed", message="Инструмент недоступен в этом обращении.")
    elif not allowed_document(proposal):
        await asyncio.to_thread(
            store.audit_tool, caller, proposal, "document_forbidden", admitted=False
        )
        event("source_policy", "document_forbidden")
        raise denied(403, "document_forbidden", "Инструмент принимает ID разрешённого регламента.")
    else:
        result = await asyncio.to_thread(store.reserve_tool_call, caller, proposal, scope)
        if result is None:
            admitted = True
            event("source_policy", "allowed")
            with span("source_read", tool=proposal.action) as operation:
                runner = tools or LocalTools()
                if work:
                    # Перед чтением повторно сверяем версию. Факты могли измениться после резерва.
                    scenario = await asyncio.to_thread(work_scenario, store, proposal)
                    result = await runner.execute(proposal, scenario=scenario)
                else:
                    result = await runner.execute(proposal)
                operation.code = result.code
    await asyncio.to_thread(
        store.audit_tool,
        caller,
        proposal,
        result.code,
        admitted=admitted,
        observation=result.observation,
    )
    logger.info(
        "Проверен инструмент сервис=%s оператор=%s ресурс=%s прогон=%s результат=%s",
        caller.service,
        caller.operator,
        scope.resource,
        proposal.run_id,
        result.code,
    )
    return result


def allowed_document(proposal: ToolProposal) -> bool:
    """Проверяет связь явно указанного документа с выбранным инструментом."""
    return proposal.document_id is None or proposal.document_id == RUNBOOK_IDS.get(proposal.action)


def work_scenario(store: RunStore, proposal: ToolProposal) -> Scenario:
    with store.connection() as db:
        return store.cases.for_run(db, proposal.scenario_id, proposal.case_revision).scenario()


async def read_manual_evidence(
    run: Run, caller: Caller, store: RunStore, tools: LocalTools
) -> list[Step]:
    scope = scope_for(run.scenario_id)
    if scope is None or not set(REQUIRED_EVIDENCE).issubset(scope.actions):
        return []
    steps = []
    for action in REQUIRED_EVIDENCE:
        proposal = ToolProposal(
            action=action,
            scenario_id=run.scenario_id,
            run_id=run.id,
            resource=scope.resource,
            case_revision=run.case_revision,
        )
        if run.case_revision is not None:
            scenario = await asyncio.to_thread(work_scenario, store, proposal)
            result = await tools.execute(proposal, scenario=scenario)
        else:
            result = await tools.execute(proposal)
        await asyncio.to_thread(
            store.audit_tool,
            caller,
            proposal,
            result.code,
            admitted=True,
            observation=result.observation,
        )
        observation = result.observation
        if (
            result.code != "ok"
            or observation is None
            or (action == Action.STATUS and result.scope != "incident")
        ):
            return []
        steps.append(
            Step(
                action=action,
                label=ACTION_LABELS[action],
                selected_by="operator",
                reason="Дежурный запросил проверку источников.",
                observation=Observation(
                    source=display_text(observation.source),
                    observed_at=display_text(observation.observed_at),
                    summary=display_text(observation.summary),
                    kind=observation.kind,
                ),
                executor_code=result.code,
            )
        )
    return steps


class LocalTools:
    def __init__(
        self, monitoring: MonitoringClient | None = None, catalog: RunbookCatalog | None = None
    ):
        self.monitoring = monitoring
        self.catalog = catalog

    async def execute(
        self, proposal: ToolProposal, *, scenario: Scenario | None = None
    ) -> ToolResult:
        if scenario is None:
            result = await execute_tool(proposal, self.monitoring, self.catalog)
        else:
            result = await execute_tool(proposal, catalog=self.catalog, scenario=scenario)
        scope = scope_for(proposal.scenario_id)
        # Проверяем размер всего JSON-результата до передачи наблюдения в разбор.
        if scope and len(result.model_dump_json().encode("utf-8")) > scope.max_response_bytes:
            result = ToolResult(
                code="response_too_large",
                message=f"Ответ источника превышает лимит {scope.max_response_bytes} байт.",
            )
        result.message = display_text(result.message)
        if result.observation is not None:
            result.observation = result.observation.model_copy(
                update={
                    "source": display_text(result.observation.source),
                    "observed_at": display_text(result.observation.observed_at),
                    "summary": display_text(result.observation.summary),
                }
            )
        result.boundary_decisions = [
            decision.model_copy(
                update={
                    "title": display_text(decision.title),
                    "detail": display_text(decision.detail),
                }
            )
            for decision in result.boundary_decisions
        ]
        logger.info("Исполнитель прогон=%s результат=%s", proposal.run_id, result.code)
        return result


async def execute_tool(
    proposal: ToolProposal,
    monitoring: MonitoringClient | None = None,
    catalog: RunbookCatalog | None = None,
    *,
    scenario: Scenario | None = None,
) -> ToolResult:
    if proposal.action not in SOURCE_FOR_ACTION:
        return ToolResult(code="not_allowed", message="Инструмент недоступен для диагностики.")
    if not allowed_document(proposal):
        return ToolResult(
            code="not_allowed", message="Инструмент принимает ID разрешённого регламента."
        )
    scenario = scenario or SCENARIOS.get(proposal.scenario_id)
    if scenario is None:
        return ToolResult(code="not_found", message="Обращение не найдено.")
    action = Action(proposal.action)
    trace = None
    snapshot = STALE_MONITORING if proposal.fault == Fault.STALE_MONITORING else scenario.monitoring
    if (
        action == Action.STATUS
        and monitoring is not None
        and proposal.fault
        not in {
            Fault.MONITORING_TIMEOUT,
            Fault.STALE_MONITORING,
            Fault.OVERSIZED_OBSERVATION,
        }
    ):
        reading = await monitoring.read(proposal.scenario_id)
        trace = reading.trace
        if reading.snapshot is None:
            detail = {
                "circuit_open": "Circuit breaker временно приостановил запросы к мониторингу.",
                "timeout": "Мониторинг не ответил вовремя.",
                "source_unavailable": "Мониторинг не вернул пригодный снимок.",
            }[reading.code]
            return ToolResult(
                code=reading.code, message=f"Нет свежих метрик. {detail}", monitoring=trace
            )
        snapshot = reading.snapshot
        observation = snapshot.observation()
    elif action in RUNBOOK_IDS and catalog is not None:
        try:
            observation = await catalog.find(action)
        except CatalogError as error:
            detail = {
                "runbook_not_found": "Опубликованный регламент отсутствует в индексе поиска.",
                "runbook_unavailable": "Поиск по каталогу регламентов недоступен.",
                "invalid_runbook": "Каталог вернул регламент, который не прошёл проверку.",
            }[error.code]
            return ToolResult(code=error.code, message=detail)
    else:
        try:
            observation = await read_observation(scenario, action, proposal.fault)
        except TimeoutError:
            return ToolResult(code="timeout", message="Источник не ответил вовремя.")
    checks = []
    for candidate in (source_candidate(proposal.threat, action), observation):
        if candidate is None:
            continue
        denial = source_denial(action, candidate)
        if denial is None:
            risk = None
            scope = None
            information = FlowData()
            if action == Action.STATUS:
                if scenario.snapshot_at is not None:
                    age = max(
                        0, int((datetime.now(UTC) - scenario.snapshot_at).total_seconds() // 60)
                    )
                else:
                    received = time.fromisoformat(scenario.view.received_at)
                    measured = time.fromisoformat(candidate.observed_at)
                    age = (
                        received.hour * 60 + received.minute - measured.hour * 60 - measured.minute
                    ) % 1440
                risk = RiskInput(
                    recent_reports=scenario.report_count,
                    snapshot_age_minutes=age,
                    oldest_message_minutes=snapshot.oldest_minutes,
                )
                scope = "uncertain" if risk.stale else snapshot.scope
                information = queue_data(
                    snapshot.queue_size,
                    snapshot.oldest_minutes,
                    snapshot.channel,
                    snapshot.message_ids,
                )
            elif action in RUNBOOK_IDS:
                information = FlowData(
                    fields=(
                        DataField(
                            key=Key.RUNBOOK_ID, level=Level.SHARED, value=RUNBOOK_IDS[action]
                        ),
                    )
                )
            return ToolResult(
                code="ok",
                message="Источник прочитан",
                observation=candidate,
                scope=scope,
                risk=risk,
                boundary_decisions=checks,
                monitoring=trace,
                information=information,
            )
        # Сохраняем объяснение отказа отдельно от содержимого неподходящего источника.
        checks.append(denial)
    return ToolResult(
        code="source_rejected",
        message="Не удалось получить данные из разрешённого источника.",
        boundary_decisions=checks,
    )
