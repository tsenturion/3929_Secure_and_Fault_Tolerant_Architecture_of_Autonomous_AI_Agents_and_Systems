import logging
import os
import sqlite3
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from time import sleep

from psycopg import Error as PostgresError
from pydantic import SecretStr

from dispatcher.observability.tamper_evident_audit import audit
from dispatcher.observability.tracing.diagnostics import configure_logging
from dispatcher.persistence.database import PostgresDatabase, begin_read

logger = logging.getLogger("dispatcher.observability.tamper_evident_audit.audit_witness")
INTERVAL_SECONDS = 5


@contextmanager
def open_source(source: Path | PostgresDatabase):
    if isinstance(source, PostgresDatabase):
        with source.connect() as db:
            yield db
    else:
        with closing(audit.readonly(source)) as db, db:
            yield db


def capture(
    source: Path | PostgresDatabase, destination: Path, now: datetime
) -> dict[audit.Partition, audit.AuditCheck]:
    """Сохраняет проверенную вершину цепочки отдельно от основного журнала."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    since = audit.cutoff(now)
    saved = []
    with closing(sqlite3.connect(destination)) as witness, witness:
        witness.executescript(audit.CHECKPOINT_SCHEMA)
        witness.execute("BEGIN IMMEDIATE")
        witness.execute("DELETE FROM audit_checkpoints WHERE day < ?", (since,))
        trusted = audit.checkpoints(witness, since)
        if isinstance(source, Path) and not source.exists() and not trusted:
            return {}
        with open_source(source) as live:
            begin_read(live)
            checks = {}
            for partition in sorted(audit.partitions(live, since) | trusted.keys()):
                check, _, head = audit.inspect(live, partition, trusted.get(partition))
                checks[partition] = check
                if check.code not in {"unanchored", "pending_checkpoint"}:
                    continue
                # Контрольная точка движется только вперёд после успешной проверки цепочки.
                witness.execute(
                    """INSERT INTO audit_checkpoints VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT (scenario_id, day) DO UPDATE SET
                           sequence = excluded.sequence, event_hash = excluded.event_hash,
                           captured_at = excluded.captured_at
                       WHERE excluded.sequence > audit_checkpoints.sequence""",
                    (*partition, check.records, head, now.isoformat()),
                )
                saved.append((*partition, check.records))
    for scenario_id, day, sequence in saved:
        logger.info(
            "Сохранена контрольная точка аудит обращение=%s день=%s номер=%s",
            scenario_id,
            day,
            sequence,
        )
    return checks


def main() -> None:
    configure_logging("audit-witness")
    source_dsn = os.getenv("AUDIT_SOURCE_DSN", "")
    source = (
        PostgresDatabase(SecretStr(source_dsn), SecretStr(os.getenv("AUDIT_SOURCE_PASSWORD", "")))
        if source_dsn
        else Path(os.getenv("AUDIT_SOURCE_DB", "state/dispatcher.sqlite3"))
    )
    destination = Path(os.getenv("AUDIT_CHECKPOINT_DB", "state/audit-checkpoints.sqlite3"))
    if isinstance(source, Path) and source.resolve() == destination.resolve():
        raise SystemExit("Журнал и контрольные точки должны находиться в разных файлах.")
    previous_failures = {}
    source_unavailable = False
    while True:
        try:
            checks = capture(source, destination, datetime.now(UTC))
            failures = {
                key: (check.code, check.first_difference)
                for key, check in checks.items()
                if check.first_difference is not None
            }
            for key, result in failures.items():
                if previous_failures.get(key) != result:
                    logger.warning(
                        "Нарушена целостность аудита обращение=%s день=%s код=%s номер=%s",
                        *key,
                        *result,
                    )
            previous_failures = failures
            if source_unavailable:
                logger.info("Снова доступна проверка контрольных точек аудита")
            source_unavailable = False
        except OSError, sqlite3.Error, PostgresError, ValueError:
            if not source_unavailable:
                logger.warning("Контрольные точки аудита временно недоступны")
            source_unavailable = True
        sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
