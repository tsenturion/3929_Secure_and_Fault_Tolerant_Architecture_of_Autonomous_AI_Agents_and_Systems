import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from time import perf_counter
from uuid import uuid4

from dispatcher.multiagent.coordination.coordination_protocol import (
    CoordinationEvent,
    CoordinationMode,
    CoordinationTrace,
    DiagnosticEvidence,
    EventCode,
    Evidence,
    Inbox,
    Participant,
    ProtocolError,
    RunbookEvidence,
    evidence_parser,
)
from dispatcher.multiagent.information_flow import FlowCheck, Party, merge
from dispatcher.observability.tracing.telemetry import current, event
from dispatcher.security.agent_threats.boundaries import source_denial
from dispatcher.security.filters import display_text
from dispatcher.security.shield import ShieldCheck
from dispatcher.security.tool_guardrails.guardrails import scope_for
from dispatcher.workflow.execution import (
    ExecutorUnavailable,
    ToolExecutor,
    ToolProposal,
    ToolResult,
)
from dispatcher.workflow.lifecycle import Lifecycle, Phase
from dispatcher.workflow.scenarios import ACTION_LABELS, SCENARIOS, Action
from dispatcher.workflow.triage import Mode, Recommendation, Run, Step, recommend

logger = logging.getLogger(__name__)
CASE = "REQ-1842"
CATALOG_DELAY = 0.35
DEADLINE_SECONDS = 5
Publish = Callable[[Evidence], None]
Produce = Callable[[Publish], Awaitable[None]]
PARTIES = {
    Participant.DIAGNOSTIC: Party.DIAGNOSTIC,
    Participant.RUNBOOK: Party.RUNBOOK,
    Participant.COORDINATOR: Party.MASTER,
}


class Journal:
    def __init__(self, mode: CoordinationMode):
        self.started = perf_counter()
        self.flow_checks: list[FlowCheck] = []
        self.trace = CoordinationTrace(
            mode=mode, catalog_delay_ms=int(CATALOG_DELAY * 1000), events=[]
        )

    def record(
        self,
        code: EventCode,
        actor: Participant,
        *,
        peer: Participant | None = None,
        message_id: str | None = None,
        evidence_count: int | None = None,
    ) -> None:
        entry = CoordinationEvent(
            at_ms=round((perf_counter() - self.started) * 1000, 1),
            code=code,
            actor=actor,
            peer=peer,
            message_id=message_id,
            evidence_count=evidence_count,
        )
        self.trace.events.append(entry)
        logger.info(
            "Координация режим=%s участник=%s этап=%s корреспондент=%s сообщение=%s",
            self.trace.mode,
            actor,
            code,
            entry.peer,
            entry.message_id,
        )
        attributes = {"actor": str(actor)}
        if entry.peer is not None:
            attributes["peer"] = str(entry.peer)
        if entry.message_id is not None:
            attributes["message_id"] = entry.message_id
        event("coordination", code, **attributes)


@dataclass(frozen=True)
class Draft:
    recommendation: Recommendation
    reads: dict[Action, ToolResult]
    error: str | None


def assemble(diagnostic: DiagnosticEvidence, catalog: RunbookEvidence) -> Draft:
    reads = {
        Action.STATUS: diagnostic.snapshot,
        Action.DEPLOYMENT: diagnostic.deployment,
        Action.INCIDENT: catalog.runbook,
    }
    evidence = {action for action, result in reads.items() if result.code == "ok"}
    stale = diagnostic.snapshot.risk is not None and diagnostic.snapshot.risk.stale
    failures = [display_text(result.message) for result in reads.values() if result.code != "ok"]
    if stale:
        failures.append("Снимок очереди устарел.")
    scope = diagnostic.snapshot.scope if not failures and Action.STATUS in evidence else None
    error = " ".join(failures) if failures else None
    return Draft(recommend(scope, evidence), reads, error)


class Receiver:
    def __init__(self, role: Participant, run_id: str, journal: Journal):
        self.role = role
        self.inbox = Inbox(run_id, CASE)
        self.journal = journal
        self.draft: Draft | None = None

    def receive(self, data: str) -> None:
        message = evidence_parser.validate_json(data)
        stored = self.inbox.accept(message)
        self.journal.record(
            "stored" if stored else "duplicate",
            self.role,
            peer=message.sender,
            message_id=message.message_id,
            evidence_count=len(self.inbox.messages),
        )
        if stored and len(self.inbox.messages) == 2:
            diagnostic = self.inbox.messages[Participant.DIAGNOSTIC]
            catalog = self.inbox.messages[Participant.RUNBOOK]
            assert isinstance(diagnostic, DiagnosticEvidence) and isinstance(
                catalog, RunbookEvidence
            )
            self.draft = assemble(diagnostic, catalog)
            self.journal.record("assembled", self.role, evidence_count=2)


def send(message: Evidence, receiver: Receiver, journal: Journal) -> None:
    journal.record("sent", message.sender, peer=receiver.role, message_id=message.message_id)
    # Даже после проверки отправителя получатель видит лишь поля своего маршрута IFC.
    source, destination = PARTIES[message.sender], PARTIES[receiver.role]
    if isinstance(message, DiagnosticEvidence):
        result = message.snapshot.forward_information(source, destination, journal.flow_checks)
        outgoing = message.model_copy(update={"snapshot": result})
    else:
        result = message.runbook.forward_information(source, destination, journal.flow_checks)
        outgoing = message.model_copy(update={"runbook": result})
    receiver.receive(outgoing.model_dump_json())


async def coordinate(mode: CoordinationMode, executor: ToolExecutor) -> Run:
    scenario = SCENARIOS[CASE]
    trace = current.get()
    run_id = trace.run_id if trace is not None else uuid4().hex
    scope = scope_for(CASE)
    assert scope is not None
    lifecycle = Lifecycle()
    lifecycle.move(Phase.OBSERVE, f"Получено обращение {CASE}", display_text(scenario.view.report))
    journal = Journal(mode)
    # Общий срок охватывает параллельные чтения и задержку доставки, а не каждое чтение отдельно.
    deadline = asyncio.get_running_loop().time() + DEADLINE_SECONDS

    async def read(action: Action, *, delivery_delay: float = 0) -> ToolResult:
        try:
            async with asyncio.timeout_at(deadline):
                result = await executor.execute(
                    ToolProposal(
                        action=action, scenario_id=CASE, run_id=run_id, resource=scope.resource
                    )
                )
                if delivery_delay:
                    await asyncio.sleep(delivery_delay)
        except TimeoutError:
            return ToolResult(
                code="timeout", message=f"Таймаут источника «{ACTION_LABELS[action]}»."
            )
        except ExecutorUnavailable:
            return ToolResult(code="source_unavailable", message="Исполнитель чтения недоступен.")
        if result.observation is not None and source_denial(action, result.observation) is not None:
            return ToolResult(code="source_rejected", message="Источник не прошёл проверку.")
        return result

    async def diagnose(publish: Publish) -> None:
        snapshot = (await read(Action.STATUS)).forward_information(
            Party.MONITORING, Party.DIAGNOSTIC, journal.flow_checks
        )
        deployment = await read(Action.DEPLOYMENT)
        message = DiagnosticEvidence(
            run_id=run_id,
            scenario_id=CASE,
            message_id=uuid4().hex,
            snapshot=snapshot,
            deployment=deployment,
        )
        publish(message)
        publish(message)

    async def search(publish: Publish) -> None:
        journal.record("catalog_wait", Participant.RUNBOOK)
        result = (await read(Action.INCIDENT, delivery_delay=CATALOG_DELAY)).forward_information(
            Party.CATALOG, Party.RUNBOOK, journal.flow_checks
        )
        publish(
            RunbookEvidence(
                run_id=run_id,
                scenario_id=CASE,
                message_id=uuid4().hex,
                runbook=result,
            )
        )

    try:
        draft = await exchange(mode, run_id, journal, diagnose, search)
    except ProtocolError as error:
        logger.warning("Координация прервана прогон=%s причина=%s", run_id, error)
        draft = Draft(recommend(None, set()), {}, str(error))

    run = build_run(draft, run_id, lifecycle)
    run.coordination = journal.trace
    run.flow_checks = journal.flow_checks
    return run


def build_run(draft: Draft, run_id: str, lifecycle: Lifecycle) -> Run:
    trace = current.get()
    steps = []
    checks = []
    for action, result in draft.reads.items():
        observation = result.observation
        if observation is not None:
            observation = observation.model_copy(
                update={
                    "source": display_text(observation.source),
                    "observed_at": display_text(observation.observed_at),
                    "summary": display_text(observation.summary),
                }
            )
        lifecycle.move(
            Phase.REASON, ACTION_LABELS[action], "Действие назначено агенту по его роли."
        )
        lifecycle.move(Phase.ACT, "Ответ источника", display_text(result.message))
        lifecycle.move(Phase.OBSERVE, "Получен результат агента", display_text(result.message))
        steps.append(
            Step(
                action=action,
                label=ACTION_LABELS[action],
                selected_by="rule",
                reason="Действие входит в область роли агента.",
                observation=observation,
                executor_code=result.code,
            )
        )
        checks.append(
            ShieldCheck(level="policy", code=result.code, detail=display_text(result.message))
        )

    if draft.recommendation.category == "incident":
        lifecycle.move(Phase.REASON, "Сопоставлены доказательства", draft.recommendation.detail)
        lifecycle.move(Phase.ACT, "Подготовлен черновик P2", draft.recommendation.title)
        lifecycle.move(
            Phase.AWAITING_APPROVAL, "Передано дежурному", "Регистрация требует согласования."
        )
        checks.append(
            ShieldCheck(
                level="hitl", code="approval_required", detail="Дежурный подтверждает запись."
            )
        )
    else:
        lifecycle.move(
            Phase.NEEDS_REVIEW,
            "Требуется ручной разбор",
            draft.error or draft.recommendation.detail,
        )

    return Run(
        id=run_id,
        trace_id=trace.trace_id if trace else None,
        trace_span_id=trace.span_id if trace else None,
        scenario_id=CASE,
        mode=Mode.AGENT,
        provider=None,
        steps=steps,
        recommendation=draft.recommendation,
        lifecycle=lifecycle,
        shield_checks=checks,
        error=draft.error,
        review_required=draft.error is not None,
        information=merge(*(result.information for result in draft.reads.values())),
    )


async def exchange(
    mode: CoordinationMode,
    run_id: str,
    journal: Journal,
    diagnose: Produce,
    search: Produce,
) -> Draft:
    if mode == CoordinationMode.CENTRALIZED:
        coordinator = Receiver(Participant.COORDINATOR, run_id, journal)

        def publish(message: Evidence) -> None:
            send(message, coordinator, journal)

        await produce(diagnose(publish), search(publish))
        assert coordinator.draft is not None
        return coordinator.draft

    diagnostic = Receiver(Participant.DIAGNOSTIC, run_id, journal)
    runbook = Receiver(Participant.RUNBOOK, run_id, journal)

    def publish_diagnostic(message: Evidence) -> None:
        if Participant.DIAGNOSTIC not in diagnostic.inbox.messages:
            diagnostic.receive(message.model_dump_json())
        send(message, runbook, journal)

    def publish_runbook(message: Evidence) -> None:
        runbook.receive(message.model_dump_json())
        send(message, diagnostic, journal)

    await produce(diagnose(publish_diagnostic), search(publish_runbook))
    if diagnostic.draft is None or peer_view(diagnostic.draft) != runbook.draft:
        journal.record("inconsistent", Participant.DIAGNOSTIC, peer=Participant.RUNBOOK)
        raise ProtocolError("Агенты получили разные результаты объединения.")
    return diagnostic.draft


def peer_view(draft: Draft) -> Draft:
    """Сравнивает решения с учётом того, что соседний агент не видит закрытые поля."""
    reads = dict(draft.reads)
    snapshot = reads[Action.STATUS]
    reads[Action.STATUS] = snapshot.model_copy(
        update={"information": snapshot.information.permitted(Party.DIAGNOSTIC, Party.RUNBOOK)}
    )
    return replace(draft, reads=reads)


async def produce(*tasks: Awaitable[None]) -> None:
    for result in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(result, BaseException):
            raise result
