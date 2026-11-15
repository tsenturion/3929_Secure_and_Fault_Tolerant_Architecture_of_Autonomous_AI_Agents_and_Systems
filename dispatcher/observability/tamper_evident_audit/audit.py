import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, date, datetime, timedelta
from hashlib import blake2b
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ValidationError

from dispatcher.persistence.database import StoreConnection

GENESIS = "0" * 64
RETENTION_DAYS = 30
HISTORY_LIMIT = 40
AuditCode = Literal[
    "verified",
    "unanchored",
    "pending_checkpoint",
    "event_modified",
    "sequence_gap",
    "checkpoint_mismatch",
    "truncated",
]
Partition = tuple[str, str]
Decision = Literal["allow", "deny", "record", "replay"]


AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    scenario_id TEXT NOT NULL,
    day TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    payload TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    PRIMARY KEY (scenario_id, day, sequence)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS audit_retention ON audit_events(day);
"""

CHECKPOINT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_checkpoints (
    scenario_id TEXT NOT NULL,
    day TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    event_hash TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    PRIMARY KEY (scenario_id, day)
) WITHOUT ROWID;
"""


class AuditEvent(BaseModel):
    at: AwareDatetime
    service: str
    operator: str | None = None
    run_id: str
    action: str
    decision: Decision
    result: str
    tool: str | None = None
    trace_id: str | None = None
    admitted: bool | None = None
    snapshot_at: str | None = None
    snapshot_version: str | None = None
    steps_used: int | None = None
    step_limit: int | None = None
    approval_id: str | None = None
    priority: str | None = None
    queue: str | None = None
    incident_id: str | None = None


class AuditRecord(BaseModel):
    day: date
    sequence: int
    previous_hash: str
    event_hash: str
    event: AuditEvent


class AuditCheck(BaseModel):
    day: date
    code: AuditCode
    records: int
    anchored_through: int
    first_difference: int | None = None
    checkpoint_at: datetime | None = None


class AuditHistory(BaseModel):
    checks: list[AuditCheck]
    events: list[AuditRecord]


class AuditComparison(BaseModel):
    original: AuditCheck
    modified: AuditCheck
    truncated: AuditCheck
    approval: AuditEvent


class AuditCheckpoint(BaseModel):
    sequence: int
    event_hash: str
    captured_at: datetime


def cutoff(now: datetime) -> str:
    return (now.astimezone(UTC).date() - timedelta(days=RETENTION_DAYS - 1)).isoformat()


def digest(scenario_id: str, day: str, sequence: int, previous_hash: str, payload: str) -> str:
    """Связывает запись с обращением, днём, позицией и предыдущей записью цепочки."""
    message = json.dumps(
        [scenario_id, day, sequence, previous_hash, payload],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return blake2b(message.encode("utf-8"), digest_size=32, person=b"dispatch-audit").hexdigest()


def append(
    db: StoreConnection,
    scenario_id: str,
    event: AuditEvent,
) -> None:
    assert db.in_transaction
    day = event.at.astimezone(UTC).date().isoformat()
    row = db.execute(
        """SELECT sequence, event_hash FROM audit_events
           WHERE scenario_id = ? AND day = ? ORDER BY sequence DESC LIMIT 1""",
        (scenario_id, day),
    ).fetchone()
    last, previous = row if row is not None else (0, GENESIS)
    sequence = last + 1
    payload = event.model_dump_json(exclude_none=True)
    db.execute(
        "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?)",
        (
            scenario_id,
            day,
            sequence,
            payload,
            previous,
            digest(scenario_id, day, sequence, previous, payload),
        ),
    )


def checkpoints(db: sqlite3.Connection, since: str) -> dict[Partition, AuditCheckpoint]:
    return {
        (scenario_id, day): AuditCheckpoint(
            sequence=sequence,
            event_hash=event_hash,
            captured_at=datetime.fromisoformat(captured_at),
        )
        for scenario_id, day, sequence, event_hash, captured_at in db.execute(
            """SELECT scenario_id, day, sequence, event_hash, captured_at
               FROM audit_checkpoints WHERE day >= ?""",
            (since,),
        )
    }


def readonly(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def partitions(db: StoreConnection, since: str, scenario_id: str | None = None) -> set[Partition]:
    sql = "SELECT DISTINCT scenario_id, day FROM audit_events WHERE day >= ?"
    return set(
        db.execute(sql, (since,))
        if scenario_id is None
        else db.execute(sql + " AND scenario_id = ?", (since, scenario_id))
    )


def inspect(
    db: StoreConnection, partition: Partition, checkpoint: AuditCheckpoint | None
) -> tuple[AuditCheck, list[AuditRecord], str]:
    """Проверяет всю дневную цепочку; для показа оставляет только последние записи."""
    scenario_id, day = partition
    rows = db.execute(
        """SELECT sequence, payload, previous_hash, event_hash FROM audit_events
           WHERE scenario_id = ? AND day = ? ORDER BY sequence""",
        partition,
    ).fetchall()
    anchor = checkpoint.sequence if checkpoint else 0
    checked = AuditCheck(
        day=date.fromisoformat(day),
        code="unanchored",
        records=len(rows),
        anchored_through=anchor,
        checkpoint_at=checkpoint.captured_at if checkpoint else None,
    )
    previous = GENESIS
    records = []
    for expected, (sequence, payload, link, event_hash) in enumerate(rows, start=1):
        if sequence != expected:
            checked.code = "sequence_gap"
            checked.first_difference = expected
            return checked, [], previous
        if (
            not isinstance(payload, str)
            or link != previous
            or event_hash != digest(scenario_id, day, sequence, previous, payload)
        ):
            checked.code = "event_modified"
            checked.first_difference = expected
            return checked, [], previous
        if checkpoint is not None and sequence == anchor and event_hash != checkpoint.event_hash:
            checked.code = "checkpoint_mismatch"
            checked.first_difference = expected
            return checked, [], previous
        try:
            event = AuditEvent.model_validate_json(payload)
        except ValidationError:
            checked.code = "event_modified"
            checked.first_difference = expected
            return checked, [], previous
        if sequence > len(rows) - HISTORY_LIMIT:
            records.append(
                AuditRecord(
                    day=checked.day,
                    sequence=sequence,
                    previous_hash=link,
                    event_hash=event_hash,
                    event=event,
                )
            )
        previous = event_hash
    if checkpoint is not None:
        # Отдельная контрольная точка позволяет отличить дописанные события от усечения хвоста.
        if len(rows) < anchor:
            checked.code = "truncated"
            checked.first_difference = len(rows) + 1
            return checked, [], previous
        checked.code = "verified" if len(rows) == anchor else "pending_checkpoint"
    return checked, records, previous


def history(
    source: StoreConnection, checkpoint_path: Path | None, scenario_id: str, now: datetime
) -> AuditHistory:
    since = cutoff(now)
    trusted = {}
    if checkpoint_path is not None and checkpoint_path.exists():
        with closing(readonly(checkpoint_path)) as checkpoint_db:
            trusted = {
                key: value
                for key, value in checkpoints(checkpoint_db, since).items()
                if key[0] == scenario_id
            }
    days = partitions(source, since, scenario_id) | trusted.keys()
    checks, events = [], []
    for partition in sorted(days, reverse=True):
        result, records, _ = inspect(source, partition, trusted.get(partition))
        checks.append(result)
        events.extend(reversed(records))
    return AuditHistory(checks=checks, events=events[:HISTORY_LIMIT])


def recent_events(
    db: StoreConnection,
    scenario_ids: tuple[str, ...],
    start: datetime,
    end: datetime,
) -> Iterator[tuple[date, int, AuditEvent]]:
    placeholders = ", ".join("?" for _ in scenario_ids)
    rows = db.execute(
        f"""SELECT day, sequence, payload FROM audit_events
            WHERE scenario_id IN ({placeholders}) AND day BETWEEN ? AND ?
            ORDER BY day, sequence""",
        (
            *scenario_ids,
            start.astimezone(UTC).date().isoformat(),
            end.astimezone(UTC).date().isoformat(),
        ),
    )
    for day, sequence, payload in rows:
        try:
            event = AuditEvent.model_validate_json(payload)
        except ValidationError:
            continue
        if start < event.at <= end:
            yield date.fromisoformat(day), sequence, event
