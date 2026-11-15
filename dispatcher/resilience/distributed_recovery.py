import asyncio
import json
import logging
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from enum import StrEnum
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from psycopg import sql
from pydantic import BaseModel, SecretStr

from dispatcher.identity.transactions import ApprovalToken
from dispatcher.persistence.database import PostgresDatabase
from dispatcher.persistence.storage import RunStore
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.security.tool_guardrails.tools import LocalTools
from dispatcher.workflow.comparison import authorize, confirm, restore_demo_assignment
from dispatcher.workflow.lifecycle import Phase
from dispatcher.workflow.scenarios import SCENARIOS
from dispatcher.workflow.triage import Mode, Run, run_triage

logger = logging.getLogger(__name__)
CASE = "REQ-1842"
BEFORE_COMMIT_EXIT = 81
AFTER_COMMIT_EXIT = 82


class Stage(StrEnum):
    BEFORE_COMMIT = "before_commit"
    AFTER_COMMIT = "after_commit"
    RETRY = "retry"


class DurableState(BaseModel):
    status: Phase
    incident_count: int
    incident_id: str | None
    receipt_saved: bool


class Recovery(BaseModel):
    stage: Stage
    after_failure: DurableState
    after_retry: DurableState


class ResilienceReport(BaseModel):
    scenario_id: str
    before_commit: Recovery
    after_commit: Recovery


class RecoveryFailed(RuntimeError):
    pass


class WorkerJob(BaseModel):
    stage: Stage
    dsn: SecretStr
    password: SecretStr
    schema_name: str
    policy_path: Path
    run_id: str
    grant: ApprovalToken


@contextmanager
def isolated_schema(database: PostgresDatabase) -> Iterator[PostgresDatabase]:
    name = f"resilience_{uuid4().hex}"
    identifier = sql.Identifier(name)
    with database.connect() as db:
        db.execute(sql.SQL("CREATE SCHEMA {}").format(identifier))
    try:
        yield replace(database, schema=name, audit_role="")
    finally:
        with database.connect() as db:
            db.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(identifier))


def demo_store(
    database: PostgresDatabase, policy: Path, store_type: type[RunStore] = RunStore
) -> RunStore:
    return store_type(policy.with_suffix(".sqlite3"), policy, postgres=database)


def start_worker(job: WorkerJob) -> Run | None:
    expected = {
        Stage.BEFORE_COMMIT: BEFORE_COMMIT_EXIT,
        Stage.AFTER_COMMIT: AFTER_COMMIT_EXIT,
        Stage.RETRY: 0,
    }[job.stage]
    # Пароли и токен передаются только через stdin дочернего процесса.
    data = job.model_dump(mode="json", exclude={"dsn", "password"})
    data["dsn"] = job.dsn.get_secret_value()
    data["password"] = job.password.get_secret_value()
    try:
        response = subprocess.run(
            [sys.executable, "-m", "dispatcher.resilience.distributed_recovery"],
            input=json.dumps(data),
            capture_output=True,
            encoding="utf-8",
            timeout=6,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        logger.warning("Дочерний исполнитель этап=%s класс=%s", job.stage, type(error).__name__)
        raise RecoveryFailed("Дочерний исполнитель не завершился вовремя.") from error
    if response.returncode != expected:
        logger.warning("Дочерний исполнитель этап=%s код=%s", job.stage, response.returncode)
        raise RecoveryFailed("Дочерний исполнитель завершился на неожиданном этапе.")
    return Run.model_validate_json(response.stdout) if job.stage == Stage.RETRY else None


def observed_state(store: RunStore, run_id: str, approval_id: str) -> DurableState:
    run = store.get(run_id)
    with store.connection() as db:
        receipt = db.execute(
            "SELECT result IS NOT NULL FROM transaction_approvals WHERE id = ?", (approval_id,)
        ).fetchone()
    if receipt is None:
        raise RecoveryFailed("После сбоя отсутствует сохранённое согласование.")
    return DurableState(
        status=run.status,
        incident_count=store.count_incidents(run.scenario_id),
        incident_id=run.incident_id,
        receipt_saved=bool(receipt[0]),
    )


def recover(database: PostgresDatabase, run: Run, stage: Stage) -> Recovery:
    with (
        TemporaryDirectory(prefix="dispatcher-resilience-") as directory,
        isolated_schema(database) as schema,
    ):
        policy = Path(directory) / "on-call.json"
        restore_demo_assignment(policy)
        store = demo_store(schema, policy)
        store.save(run)
        grant = authorize(store, run.id)
        job = WorkerJob(
            stage=stage,
            dsn=schema.dsn,
            password=schema.password,
            schema_name=schema.schema,
            policy_path=policy,
            run_id=run.id,
            grant=grant,
        )
        start_worker(job)
        after_failure = observed_state(store, run.id, grant.approval_id)
        committed = stage == Stage.AFTER_COMMIT
        expected_phase = Phase.COMPLETED if committed else Phase.AWAITING_APPROVAL
        if (
            after_failure.status != expected_phase
            or after_failure.incident_count != int(committed)
            or after_failure.receipt_saved != committed
        ):
            raise RecoveryFailed("После сбоя сохранено неожиданное состояние транзакции.")
        replay = start_worker(job.model_copy(update={"stage": Stage.RETRY}))
        after_retry = observed_state(store, run.id, grant.approval_id)
        if (
            replay is None
            or after_retry.status != Phase.COMPLETED
            or after_retry.incident_count != 1
            or not after_retry.receipt_saved
            or after_retry.incident_id is None
            or replay.incident_id != after_retry.incident_id
            or (committed and after_retry.incident_id != after_failure.incident_id)
        ):
            raise RecoveryFailed("После повтора не подтверждена единственная запись инцидента.")
        logger.info(
            "Восстановление этап=%s до=%s после=%s инцидент=%s",
            stage,
            after_failure.incident_count,
            after_retry.incident_count,
            after_retry.incident_id,
        )
        return Recovery(stage=stage, after_failure=after_failure, after_retry=after_retry)


async def demonstrate_resilience(database: PostgresDatabase) -> ResilienceReport:
    results = []
    for stage in (Stage.BEFORE_COMMIT, Stage.AFTER_COMMIT):
        run = await run_triage(
            SCENARIOS[CASE], Mode.AGENT, DemonstrationModel(), executor=LocalTools()
        )
        results.append(await asyncio.to_thread(recover, database, run, stage))
    return ResilienceReport(scenario_id=CASE, before_commit=results[0], after_commit=results[1])


class InterruptedStore(RunStore):
    def audit_run(self, db, run, caller, action, decision, result, **details) -> None:
        super().audit_run(db, run, caller, action, decision, result, **details)
        if action == "register_incident" and result == "created":
            # Завершаем процесс после всех записей, пока контекст транзакции открыт.
            os._exit(BEFORE_COMMIT_EXIT)


def worker() -> None:
    job = WorkerJob.model_validate_json(sys.stdin.buffer.read())
    database = PostgresDatabase(job.dsn, job.password, schema=job.schema_name)
    store_type = InterruptedStore if job.stage == Stage.BEFORE_COMMIT else RunStore
    run = confirm(demo_store(database, job.policy_path, store_type), job.run_id, job.grant)
    if job.stage == Stage.AFTER_COMMIT:
        os._exit(AFTER_COMMIT_EXIT)
    print(run.model_dump_json())


if __name__ == "__main__":
    worker()
