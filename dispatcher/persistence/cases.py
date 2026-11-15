import json
import logging
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import datetime, timedelta
from uuid import uuid4

from dispatcher.identity.access import Caller
from dispatcher.observability.tamper_evident_audit import audit
from dispatcher.persistence.database import StoreConnection, begin_write
from dispatcher.security.filters import SupportExport
from dispatcher.workflow.cases import (
    CaseCreate,
    CaseEvidence,
    CaseEvidenceUpdate,
    CaseIncident,
    WorkCase,
)
from dispatcher.workflow.lifecycle import Phase

logger = logging.getLogger(__name__)
CASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS work_cases (
    id TEXT PRIMARY KEY,
    symptom TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revision INTEGER NOT NULL,
    closed_at TEXT,
    evidence TEXT,
    support TEXT NOT NULL
);
"""
CASE_SELECT = """
SELECT c.id, c.symptom, c.created_at, c.revision, c.closed_at, c.evidence,
       i.id, i.run_id, i.created_at, i.priority, r.status, r.payload
FROM work_cases AS c LEFT JOIN incidents AS i ON c.id = i.scenario_id
LEFT JOIN runs AS r ON r.id = (
    SELECT id FROM runs WHERE scenario_id = c.id AND mode = 'agent'
    ORDER BY started_at DESC, id DESC LIMIT 1
)
"""


class CaseError(ValueError):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status = status
        self.code = code


def as_case(row: tuple, now: datetime) -> WorkCase:
    (
        id_,
        symptom,
        created,
        revision,
        closed,
        evidence,
        incident,
        run,
        registered,
        priority,
        status,
        payload,
    ) = row
    if payload is not None:
        latest = json.loads(payload)
        # Статус старого прогона не описывает обращение после изменения его фактов.
        if latest.get("case_revision") != revision:
            status = None
        elif (
            status == Phase.AWAITING_APPROVAL
            and latest["approval_deadline"]
            and datetime.fromisoformat(latest["approval_deadline"]) <= now
        ):
            status = Phase.APPROVAL_EXPIRED
    return WorkCase(
        id=id_,
        symptom=symptom,
        created_at=created,
        revision=revision,
        closed_at=closed,
        evidence=CaseEvidence.model_validate_json(evidence) if evidence else None,
        analysis_status=status,
        incident=CaseIncident(
            id=f"INC-{3070 + incident}", run_id=run, registered_at=registered, priority=priority
        )
        if incident
        else None,
    )


class CaseStore:
    def __init__(
        self,
        connection: Callable[[], AbstractContextManager[StoreConnection]],
        clock: Callable[[], datetime],
    ):
        self.connection = connection
        self.clock = clock

    def read(self, db: StoreConnection, case_id: str) -> WorkCase:
        row = db.execute(CASE_SELECT + " WHERE c.id = ?", (case_id,)).fetchone()
        if row is None:
            raise CaseError(404, "case_not_found", "Рабочее обращение не найдено.")
        return as_case(row, self.clock())

    def get(self, case_id: str) -> WorkCase:
        with self.connection() as db:
            return self.read(db, case_id)

    def list(self) -> list[WorkCase]:
        with self.connection() as db:
            now = self.clock()
            return [
                as_case(row, now)
                for row in db.execute(
                    CASE_SELECT + " ORDER BY (c.closed_at IS NOT NULL), c.created_at DESC, c.id"
                )
            ]

    def create(self, request: CaseCreate, caller: Caller) -> WorkCase:
        caller.require_duty()
        case = WorkCase(
            id=f"CASE-{uuid4().hex}", symptom=request.symptom, created_at=self.clock(), revision=1
        )
        with self.connection() as db:
            begin_write(db)
            db.execute(
                "INSERT INTO work_cases (id, symptom, created_at, revision, support) VALUES (?, ?, ?, ?, ?)",
                (
                    case.id,
                    case.symptom,
                    case.created_at.isoformat(),
                    case.revision,
                    request.support.model_dump_json(),
                ),
            )
            self.record(db, case, caller, "case_created")
        return case

    def update(self, case_id: str, update: CaseEvidenceUpdate, caller: Caller) -> WorkCase:
        caller.require_case(case_id, "edit")
        with self.connection() as db:
            begin_write(db)
            case = self.read(db, case_id)
            # Проверяем ревизию под той же блокировкой, под которой запишем новые факты.
            self.require_current(case, update.revision)
            if update.evidence.snapshot_at > self.clock() + timedelta(minutes=1):
                raise CaseError(409, "future_snapshot", "Снимок мониторинга датирован будущим.")
            case.evidence = update.evidence
            case.revision += 1
            case.analysis_status = None
            db.execute(
                "UPDATE work_cases SET revision = ?, evidence = ? WHERE id = ?",
                (case.revision, case.evidence.model_dump_json(), case.id),
            )
            self.record(db, case, caller, "case_evidence_updated")
        return case

    def close(self, case_id: str, caller: Caller) -> WorkCase:
        caller.require_case(case_id, "resolve")
        with self.connection() as db:
            begin_write(db)
            case = self.read(db, case_id)
            if case.closed_at is None:
                case.closed_at = self.clock()
                case.revision += 1
                case.analysis_status = None
                db.execute(
                    "UPDATE work_cases SET revision = ?, closed_at = ? WHERE id = ?",
                    (case.revision, case.closed_at.isoformat(), case.id),
                )
                self.record(db, case, caller, "case_closed")
        return case

    def support(self, case_id: str, caller: Caller) -> SupportExport:
        caller.require_case(case_id, "read_support")
        with self.connection() as db:
            begin_write(db)
            case = self.read(db, case_id)
            row = db.execute("SELECT support FROM work_cases WHERE id = ?", (case_id,)).fetchone()
            original = SupportExport.model_validate_json(row[0])
            self.record(db, case, caller, "case_support_opened")
            return original

    @staticmethod
    def require_current(case: WorkCase, revision: int | None) -> None:
        if case.closed_at is not None:
            raise CaseError(409, "case_closed", "Рабочее обращение закрыто.")
        if case.revision != revision:
            raise CaseError(
                409, "case_changed", "Данные обращения изменились. Запустите новый разбор."
            )

    def for_run(self, db: StoreConnection, case_id: str, revision: int | None) -> WorkCase:
        case = self.read(db, case_id)
        # Прогон привязан к конкретной версии фактов; смена версии требует нового разбора.
        self.require_current(case, revision)
        if case.evidence is None:
            raise CaseError(
                409, "case_evidence_missing", "Добавьте данные мониторинга и развёртывания."
            )
        return case

    def record(self, db: StoreConnection, case: WorkCase, caller: Caller, action: str) -> None:
        audit.append(
            db,
            case.id,
            audit.AuditEvent(
                at=self.clock(),
                service=caller.service,
                operator=caller.operator,
                run_id=case.id,
                action=action,
                decision="record",
                result="ok",
                incident_id=case.incident.id if case.incident else None,
            ),
        )
        logger.info("Рабочее обращение=%s операция=%s версия=%d", case.id, action, case.revision)
