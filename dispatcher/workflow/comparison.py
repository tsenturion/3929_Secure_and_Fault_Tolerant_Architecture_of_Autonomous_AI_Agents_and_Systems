import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from dispatcher.identity.access import Caller, Operator
from dispatcher.identity.transactions import (
    ApprovalIntent,
    ApprovalToken,
    TransactionComparison,
    TransactionRejected,
)
from dispatcher.models.adapters import Decision, ModelError
from dispatcher.observability.tamper_evident_audit.audit import AuditComparison
from dispatcher.observability.tamper_evident_audit.audit_witness import capture
from dispatcher.persistence.storage import RunStore
from dispatcher.security.agent_threats.boundaries import Threat
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.security.data_exfiltration.publication import IncidentField
from dispatcher.security.tool_guardrails.tools import LocalTools
from dispatcher.workflow.approval_policy import DEMO_OPERATOR, ApprovalCode, ApprovalRejected
from dispatcher.workflow.lifecycle import Phase
from dispatcher.workflow.scenarios import SCENARIOS, Action
from dispatcher.workflow.triage import (
    ApprovalTimeoutComparison,
    Checkpoint,
    ComparedRun,
    ComparisonCase,
    FailClosedComparison,
    HierarchyComparison,
    Mode,
    RegistrationCheckExample,
    RegistrationComparison,
    Run,
    run_triage,
)

logger = logging.getLogger(__name__)
DEMO_CALLER = Caller(operator=Operator.DUTY)


class UnavailableModel:
    def decide(self, context: str, available: dict[Action, str]) -> Decision:
        raise ModelError("Провайдер модели недоступен. Новые решения не получены.")


def restore_demo_assignment(path: Path) -> None:
    path.write_text(
        json.dumps({"assignments": {"Уведомления": DEMO_OPERATOR}}, ensure_ascii=False),
        encoding="utf-8",
    )


def checkpoint(
    store: RunStore,
    run_id: str,
    title: str,
    operator: str,
    policy_code: ApprovalCode | None = None,
) -> Checkpoint:
    stored = store.get(run_id)
    return Checkpoint(
        title=title,
        operator=operator,
        status=stored.status,
        incident_count=store.count_incidents(stored.scenario_id),
        incident_id=stored.incident_id,
        policy_code=policy_code,
    )


def authorize(store: RunStore, run_id: str) -> ApprovalToken:
    run = store.get(run_id)
    return store.issue_approval(
        run_id,
        ApprovalIntent(scenario_id=run.scenario_id, recommendation=run.recommendation),
        DEMO_CALLER,
    )


def confirm(
    store: RunStore, run_id: str, grant: ApprovalToken | None = None, *, lose_reply: bool = False
) -> Run:
    approval = grant if grant is not None else authorize(store, run_id)
    run = store.resolve(
        run_id,
        "approve",
        DEMO_CALLER,
        transaction_token=approval.token,
        idempotency_key=approval.idempotency_key,
    )
    if lose_reply:
        raise TimeoutError("Ответ о регистрации потерян после фиксации транзакции.")
    return run


def compare_run(store: RunStore, case: ComparisonCase, run: Run) -> ComparedRun:
    store.save(run)
    checks = []
    match case:
        case ComparisonCase.NORMAL:
            title = "Штатный маршрут"
        case ComparisonCase.POLICY:
            title = "Отказ политики"
            checks.append(
                checkpoint(
                    store,
                    run.id,
                    "После отказа политики",
                    "Предложение отклонено. Дежурный может продолжить диагностику вручную.",
                )
            )
        case ComparisonCase.MODEL:
            title = "Модель недоступна"
            checks.append(
                checkpoint(
                    store,
                    run.id,
                    "После ошибки модели",
                    "Сохранены обращение и снимок очереди. Продолжить разбор можно вручную.",
                )
            )
        case ComparisonCase.LOST_REPLY:
            title = "Ответ трекера потерян"
    if run.status == Phase.AWAITING_APPROVAL:
        checks.append(
            checkpoint(
                store,
                run.id,
                "До подтверждения",
                "Дежурный проверяет черновик P2.",
            )
        )
        lose_reply = case == ComparisonCase.LOST_REPLY
        grant = authorize(store, run.id)
        try:
            run = confirm(store, run.id, grant, lose_reply=lose_reply)
        except TimeoutError as error:
            logger.warning("Прогон сравнения %s: %s", run.id, error)
            checks.append(
                checkpoint(
                    store,
                    run.id,
                    "После потери ответа",
                    "Дежурный видит таймаут. Номер инцидента пока неизвестен.",
                )
            )
            run = confirm(store, run.id, grant)
        checks.append(
            checkpoint(
                store,
                run.id,
                "После повтора подтверждения" if lose_reply else "После подтверждения",
                f"Дежурный получил номер {run.incident_id}.",
            )
        )
    logger.info(
        "Прогон сравнения %s сценарий=%s состояние=%s карточек=%d",
        run.id,
        case,
        run.status,
        checks[-1].incident_count,
    )
    return ComparedRun(case=case, title=title, checkpoints=checks, trace=run)


async def compare_outcomes() -> list[ComparedRun]:
    rows = []
    with TemporaryDirectory(prefix="dispatcher-comparison-") as directory:
        policy_path = Path(directory) / "on-call.json"
        restore_demo_assignment(policy_path)
        for case in ComparisonCase:
            threat = Threat.MISUSE if case == ComparisonCase.POLICY else None
            model = (
                UnavailableModel() if case == ComparisonCase.MODEL else DemonstrationModel(threat)
            )
            run = await run_triage(
                SCENARIOS["REQ-1842"], Mode.AGENT, model, threat=threat, executor=LocalTools()
            )
            store = RunStore(Path(directory) / f"{case}.sqlite3", policy_path)
            rows.append(await asyncio.to_thread(compare_run, store, case, run))
    return rows


def compare_approval(run: Run, directory: Path) -> FailClosedComparison:
    policy_path = directory / "on-call.json"
    policy_path.write_text('{"assignments": {}}', encoding="utf-8")
    store = RunStore(directory / "runs.sqlite3", policy_path)
    store.save(run)
    try:
        confirm(store, run.id)
    except ApprovalRejected as error:
        blocked = checkpoint(
            store,
            run.id,
            "Назначение дежурного отсутствует",
            str(error),
            error.block.code,
        )
    else:
        raise RuntimeError("Отсутствие назначения должно блокировать регистрацию.")

    restore_demo_assignment(policy_path)
    confirm(store, run.id)
    restored = checkpoint(
        store,
        run.id,
        "Назначение восстановлено",
        "Повторное подтверждение разрешило запись.",
        ApprovalCode.ALLOWED,
    )
    return FailClosedComparison(blocked=blocked, restored=restored)


async def demonstrate_fail_closed() -> FailClosedComparison:
    run = await run_triage(
        SCENARIOS["REQ-1842"], Mode.AGENT, DemonstrationModel(), executor=LocalTools()
    )
    with TemporaryDirectory(prefix="dispatcher-fail-closed-") as directory:
        return await asyncio.to_thread(compare_approval, run, Path(directory))


def compare_publication(run: Run, directory: Path) -> HierarchyComparison:
    policy_path = directory / "on-call.json"
    restore_demo_assignment(policy_path)
    store = RunStore(directory / "runs.sqlite3", policy_path)

    proposed = run.model_copy(deep=True)
    proposed.recommendation.incident_fields.append(IncidentField.CUSTOMER_CONTACTS)
    store.save(proposed)
    try:
        confirm(store, proposed.id)
    except ApprovalRejected as error:
        blocked = checkpoint(
            store,
            proposed.id,
            "Черновик с контактами",
            str(error),
            error.block.code,
        )
    else:
        raise RuntimeError("Политика данных должна блокировать публикацию контактов.")

    safe = run.model_copy(update={"id": uuid4().hex})
    store.save(safe)
    resolved = confirm(store, safe.id)
    assert resolved.publication is not None
    approved = checkpoint(
        store,
        safe.id,
        "Черновик со сводкой",
        "Дежурный подтвердил версию со сводными данными.",
        ApprovalCode.ALLOWED,
    )
    return HierarchyComparison(blocked=blocked, approved=approved, publication=resolved.publication)


async def demonstrate_hierarchy() -> HierarchyComparison:
    run = await run_triage(
        SCENARIOS["REQ-1842"], Mode.AGENT, DemonstrationModel(), executor=LocalTools()
    )
    with TemporaryDirectory(prefix="dispatcher-priorities-") as directory:
        return await asyncio.to_thread(compare_publication, run, Path(directory))


def compare_registration(run: Run, directory: Path) -> RegistrationComparison:
    policy_path = directory / "on-call.json"
    restore_demo_assignment(policy_path)
    store = RunStore(directory / "runs.sqlite3", policy_path)
    store.save(run)
    original = store.get(run.id)
    changed = original.model_copy(deep=True)
    changed.id = uuid4().hex
    changed.recommendation.queue = "Платежи"
    store.save(changed)
    changed = store.get(changed.id)

    examples = [
        RegistrationCheckExample(
            label=label,
            queue=draft.recommendation.queue,
            decision=store.check_approval(draft, DEMO_CALLER, confirmed=confirmed),
        )
        for label, draft, confirmed in (
            ("До подтверждения", original, False),
            ("Первая проверка", original, True),
            ("Повтор с теми же данными", original, True),
            ("Проверка после изменения очереди", changed, True),
        )
    ]
    try:
        confirm(store, changed.id)
    except ApprovalRejected as error:
        return RegistrationComparison(
            examples=examples,
            rejected_code=error.block.code,
            incident_count=store.count_incidents(run.scenario_id),
        )
    raise RuntimeError("Изменение очереди должно блокировать регистрацию.")


async def demonstrate_registration_checks() -> RegistrationComparison:
    run = await run_triage(
        SCENARIOS["REQ-1842"], Mode.AGENT, DemonstrationModel(), executor=LocalTools()
    )
    with TemporaryDirectory(prefix="dispatcher-registration-") as directory:
        return await asyncio.to_thread(compare_registration, run, Path(directory))


def compare_deadlines(run: Run, directory: Path) -> ApprovalTimeoutComparison:
    policy_path = directory / "on-call.json"
    restore_demo_assignment(policy_path)
    start = datetime(2026, 11, 15, 9, 12, tzinfo=UTC)
    now = start

    def clock() -> datetime:
        return now

    timely = RunStore(directory / "timely.sqlite3", policy_path, clock=clock)
    late = RunStore(directory / "late.sqlite3", policy_path, clock=clock)
    timely.save(run.model_copy(deep=True))
    late.save(run.model_copy(deep=True))
    now = start + timedelta(minutes=7)
    confirm(timely, run.id)
    accepted = checkpoint(
        timely,
        run.id,
        "Подтверждение в 14:19",
        "Согласование действует до 14:22. Инцидент зарегистрирован.",
        ApprovalCode.ALLOWED,
    )
    now = start + timedelta(minutes=11)
    try:
        confirm(late, run.id)
    except ApprovalRejected as error:
        rejected = checkpoint(
            late,
            run.id,
            "Подтверждение в 14:23",
            str(error),
            error.block.code,
        )
    else:
        raise RuntimeError("Истёкшее согласование должно блокировать регистрацию.")
    return ApprovalTimeoutComparison(timely=accepted, late=rejected)


async def demonstrate_approval_timeout() -> ApprovalTimeoutComparison:
    run = await run_triage(
        SCENARIOS["REQ-1842"], Mode.AGENT, DemonstrationModel(), executor=LocalTools()
    )
    with TemporaryDirectory(prefix="dispatcher-approval-timeout-") as directory:
        return await asyncio.to_thread(compare_deadlines, run, Path(directory))


def compare_transactions(run: Run, directory: Path) -> TransactionComparison:
    policy_path = directory / "on-call.json"
    restore_demo_assignment(policy_path)
    store = RunStore(directory / "runs.sqlite3", policy_path)
    store.save(run)
    grant = authorize(store, run.id)
    changed = run.model_copy(deep=True)
    changed.recommendation.priority = "P1"
    with store.connection() as db:
        store.update(db, changed)
    try:
        confirm(store, run.id, grant)
    except TransactionRejected as error:
        changed_code = error.code
        incidents_after_change = store.count_incidents(run.scenario_id)
    else:
        raise RuntimeError("Изменённый черновик должен требовать нового подтверждения.")
    with store.connection() as db:
        store.update(db, run)
    replacement = authorize(store, run.id)
    accepted = confirm(store, run.id, replacement)
    repeated = confirm(store, run.id, replacement)
    return TransactionComparison(
        changed_code=changed_code,
        incidents_after_change=incidents_after_change,
        incident_id=accepted.incident_id,
        repeated_incident_id=repeated.incident_id,
        incident_count=store.count_incidents(run.scenario_id),
    )


async def demonstrate_transactions() -> TransactionComparison:
    run = await run_triage(
        SCENARIOS["REQ-1842"], Mode.AGENT, DemonstrationModel(), executor=LocalTools()
    )
    with TemporaryDirectory(prefix="dispatcher-transaction-token-") as directory:
        return await asyncio.to_thread(compare_transactions, run, Path(directory))


def compare_audit(run: Run, directory: Path) -> AuditComparison:
    now = datetime.now(UTC)
    policy = directory / "on-call.json"
    restore_demo_assignment(policy)
    source = RunStore(directory / "source.sqlite3", policy, clock=lambda: now)
    source.save(run, DEMO_CALLER)
    confirm(source, run.id)
    trusted = directory / "checkpoints.sqlite3"
    capture(source.path, trusted, now)
    history = source.audit_history(run.scenario_id, trusted)
    approval = next(record for record in history.events if record.event.action == "approve_draft")

    modified = RunStore(directory / "modified.sqlite3", policy, clock=lambda: now)
    truncated = RunStore(directory / "truncated.sqlite3", policy, clock=lambda: now)
    with source.connection() as db:
        for copy in (modified, truncated):
            with copy.connection() as target:
                db.backup(target)
    replaced = approval.event.model_copy(update={"at": approval.event.at + timedelta(minutes=5)})
    key = (run.scenario_id, approval.day.isoformat(), approval.sequence)
    with modified.connection() as db:
        db.execute(
            """UPDATE audit_events SET payload = ?
               WHERE scenario_id = ? AND day = ? AND sequence = ?""",
            (replaced.model_dump_json(exclude_none=True), *key),
        )
    with truncated.connection() as db:
        db.execute(
            "DELETE FROM audit_events WHERE scenario_id = ? AND day = ? AND sequence >= ?", key
        )
    return AuditComparison(
        original=history.checks[0],
        approval=approval.event,
        modified=modified.audit_history(run.scenario_id, trusted).checks[0],
        truncated=truncated.audit_history(run.scenario_id, trusted).checks[0],
    )


async def demonstrate_audit() -> AuditComparison:
    run = await run_triage(
        SCENARIOS["REQ-1842"], Mode.AGENT, DemonstrationModel(), executor=LocalTools()
    )
    with TemporaryDirectory(prefix="dispatcher-audit-") as directory:
        return await asyncio.to_thread(compare_audit, run, Path(directory))
