import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from time import perf_counter
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel

from dispatcher.multiagent.coordination.coordination_protocol import (
    DiagnosticEvidence,
    Evidence,
    Participant,
    RunbookEvidence,
)
from dispatcher.multiagent.coordination.coordinator import Draft, assemble, build_run
from dispatcher.multiagent.hierarchy.delegation import (
    CASE,
    RUNBOOK_ID,
    DelegationEvent,
    DelegationTrace,
    DiagnosticOrder,
    RunbookOrder,
    SourceReference,
    TaskOrder,
    TaskStage,
)
from dispatcher.multiagent.information_flow import FlowCheck, Party
from dispatcher.observability.tracing.telemetry import current, event
from dispatcher.security.agent_threats.boundaries import source_denial
from dispatcher.security.filters import display_text
from dispatcher.workflow.execution import ExecutorUnavailable, ToolResult
from dispatcher.workflow.lifecycle import Lifecycle, Phase
from dispatcher.workflow.scenarios import SCENARIOS, Action
from dispatcher.workflow.triage import Run, recommend

DIAGNOSTIC_TIMEOUT = 3.0
RUNBOOK_TIMEOUT = 1.5
UNVERIFIED = "Приоритет ещё не проверен по регламенту."
Dispatch = Callable[[TaskOrder], Awaitable[Evidence]]


class ProgressFrame(BaseModel):
    kind: Literal["progress"] = "progress"
    event: DelegationEvent


class RunFrame(BaseModel):
    kind: Literal["result"] = "result"
    run: Run


class ErrorFrame(BaseModel):
    kind: Literal["error"] = "error"
    detail: str


class TaskFailure(ValueError):
    def __init__(self, stage: TaskStage, detail: str):
        super().__init__(detail)
        self.stage = stage


def task_reads(evidence: Evidence) -> dict[Action, ToolResult]:
    if isinstance(evidence, DiagnosticEvidence):
        return {Action.STATUS: evidence.snapshot, Action.DEPLOYMENT: evidence.deployment}
    return {Action.INCIDENT: evidence.runbook}


async def collect(
    dispatch: Dispatch, order: TaskOrder, timeout: float, *, delay_delivery: bool = False
) -> Evidence:
    """Проверяет срок, привязку ответа к заданию и происхождение наблюдений."""
    try:
        async with asyncio.timeout(timeout):
            result = await dispatch(order)
            if delay_delivery:
                await asyncio.sleep(timeout + 0.25)
    except TimeoutError as error:
        raise TaskFailure(TaskStage.TIMEOUT, "Срок ожидания ответа агента истёк.") from error
    except ExecutorUnavailable as error:
        raise TaskFailure(TaskStage.FAILED, "Связь с исполнителем прервана.") from error

    if (result.sender, result.message_id, result.run_id, result.scenario_id) != (
        order.role,
        order.task_id,
        order.run_id,
        order.scenario_id,
    ):
        raise TaskFailure(TaskStage.FAILED, "Ответ не соответствует выданному заданию.")
    if any(
        reply.observation is not None and source_denial(action, reply.observation) is not None
        for action, reply in task_reads(result).items()
    ):
        raise TaskFailure(TaskStage.FAILED, "Ответ содержит данные неподтверждённого источника.")
    return result


def references(reads: dict[Action, ToolResult]) -> list[SourceReference]:
    return [
        SourceReference(
            action=action,
            kind=observation.kind,
            label=display_text(observation.source),
            version=display_text(observation.observed_at),
            summary=display_text(observation.summary),
        )
        for action, result in reads.items()
        if result.code == "ok"
        and (observation := result.observation) is not None
        and observation.kind is not None
    ]


async def hierarchy(
    dispatch: Dispatch, *, slow_catalog: bool
) -> AsyncIterator[ProgressFrame | RunFrame]:
    trace = current.get()
    run_id = trace.run_id if trace is not None else uuid4().hex
    lifecycle = Lifecycle()
    lifecycle.move(
        Phase.OBSERVE, f"Получено обращение {CASE}", display_text(SCENARIOS[CASE].view.report)
    )
    started = perf_counter()
    journal: list[DelegationEvent] = []
    flow_checks: list[FlowCheck] = []

    def record(
        stage: TaskStage,
        actor: Participant,
        detail: str,
        *,
        task: TaskOrder | None = None,
        sources: list[SourceReference] | None = None,
        oldest_minutes: int | None = None,
    ) -> ProgressFrame:
        entry = DelegationEvent(
            elapsed_ms=round((perf_counter() - started) * 1000, 1),
            stage=stage,
            actor=actor,
            detail=detail,
            task_id=task.task_id if task else None,
            sources=sources or [],
            oldest_minutes=oldest_minutes,
        )
        journal.append(entry)
        fields = {"actor": str(actor)}
        if task is not None:
            fields["task_id"] = task.task_id
            fields["peer"] = str(
                task.role if actor == Participant.COORDINATOR else Participant.COORDINATOR
            )
        event("hierarchy", stage, **fields)
        return ProgressFrame(event=entry)

    def finish(draft: Draft) -> RunFrame:
        ready = draft.recommendation.category == "incident"
        record(
            TaskStage.READY if ready else TaskStage.MANUAL,
            Participant.COORDINATOR,
            "Черновик P2 передан дежурному." if ready else draft.error or UNVERIFIED,
        )
        run = build_run(draft, run_id, lifecycle)
        run.delegation = DelegationTrace(events=journal)
        run.flow_checks = flow_checks
        return RunFrame(run=run)

    diagnostic_order = DiagnosticOrder(task_id=uuid4().hex, run_id=run_id)
    yield record(
        TaskStage.DELEGATED,
        Participant.COORDINATOR,
        "Получить снимок очереди и журнал развёртываний.",
        task=diagnostic_order,
    )
    try:
        diagnostic = await collect(dispatch, diagnostic_order, DIAGNOSTIC_TIMEOUT)
    except TaskFailure as error:
        yield record(error.stage, Participant.DIAGNOSTIC, str(error), task=diagnostic_order)
        yield finish(Draft(recommend(None, set()), {}, str(error)))
        return

    assert isinstance(diagnostic, DiagnosticEvidence)
    reads = task_reads(diagnostic)
    risk = diagnostic.snapshot.risk
    yield record(
        TaskStage.REPORTED,
        Participant.DIAGNOSTIC,
        "Диагностические данные переданы Master Agent.",
        sources=references(reads),
        oldest_minutes=risk.oldest_message_minutes if risk else None,
        task=diagnostic_order,
    )
    failures = [display_text(result.message) for result in reads.values() if result.code != "ok"]
    if risk is not None and risk.stale:
        failures.append("Снимок очереди устарел.")
    if risk is None and diagnostic.snapshot.code == "ok":
        failures.append("Источник вернул снимок без данных о свежести.")
    if failures or diagnostic.snapshot.scope != "incident":
        # Регламент запрашивается только после свежего подтверждения масштаба инцидента.
        reason = " ".join(failures) or "Мониторинг не подтвердил массовую задержку."
        yield finish(Draft(recommend(None, set()), reads, reason))
        return

    runbook_order = RunbookOrder(
        task_id=uuid4().hex,
        run_id=run_id,
        runbook_id=RUNBOOK_ID,
        queue_context=diagnostic.snapshot.information.forward(
            Party.MASTER, Party.RUNBOOK, flow_checks
        ),
    )
    yield record(
        TaskStage.DELEGATED,
        Participant.COORDINATOR,
        f"Проверить опубликованный {RUNBOOK_ID}. {UNVERIFIED}",
        task=runbook_order,
    )
    try:
        catalog = await collect(
            dispatch, runbook_order, RUNBOOK_TIMEOUT, delay_delivery=slow_catalog
        )
    except TaskFailure as error:
        yield record(error.stage, Participant.RUNBOOK, str(error), task=runbook_order)
        yield finish(Draft(recommend(None, set()), reads, f"{error} {UNVERIFIED}"))
        return

    assert isinstance(catalog, RunbookEvidence)
    yield record(
        TaskStage.REPORTED if catalog.runbook.code == "ok" else TaskStage.FAILED,
        Participant.RUNBOOK,
        display_text(catalog.runbook.message),
        sources=references(task_reads(catalog)),
        task=runbook_order,
    )
    draft = assemble(diagnostic, catalog)
    if draft.error:
        draft = Draft(draft.recommendation, draft.reads, f"{draft.error} {UNVERIFIED}")
    yield finish(draft)
