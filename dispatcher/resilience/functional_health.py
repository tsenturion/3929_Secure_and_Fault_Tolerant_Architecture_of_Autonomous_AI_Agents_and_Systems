import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel

from dispatcher.models.adapters import InferenceResult
from dispatcher.persistence.storage import RunStore
from dispatcher.security.tool_guardrails.guardrails import scope_for
from dispatcher.security.tool_guardrails.tools import LocalTools
from dispatcher.settings import Provider
from dispatcher.workflow.approval_policy import DEMO_OPERATOR, ApprovalCode, check_assignment
from dispatcher.workflow.execution import ToolProposal, ToolResult
from dispatcher.workflow.registration import INCIDENT_QUEUE
from dispatcher.workflow.scenarios import Action

logger = logging.getLogger(__name__)
PROBE_CASE = "REQ-1842"
MODEL_FRESHNESS = timedelta(minutes=5)


class HealthStatus(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class Check(BaseModel):
    status: HealthStatus
    code: str


class DependencyHealth(BaseModel):
    checked_at: datetime
    status: HealthStatus
    storage: Check
    monitoring: Check
    catalog: Check
    runbook: Check
    manual: Check


class ModelHealth(Check):
    provider: Provider
    last_response_at: datetime | None = None
    detail: str | None = None


class FunctionalHealth(DependencyHealth):
    model: ModelHealth


class InferenceHealth:
    def __init__(self):
        self.samples: dict[Provider, tuple[InferenceResult, datetime]] = {}

    def record(self, provider: Provider, result: InferenceResult) -> None:
        self.samples[provider] = result, datetime.now(UTC)

    def check(self, provider: Provider, problem: str | None) -> ModelHealth:
        sample = self.samples.get(provider)
        if problem:
            return ModelHealth(
                status=HealthStatus.DEGRADED,
                code="model_unavailable",
                provider=provider,
                detail=problem,
            )
        if sample is None or datetime.now(UTC) - sample[1] > MODEL_FRESHNESS:
            return ModelHealth(
                status=HealthStatus.UNKNOWN, code="model_unverified", provider=provider
            )
        result, at = sample
        return ModelHealth(
            status=HealthStatus.OK if result == InferenceResult.OK else HealthStatus.DEGRADED,
            code=result,
            provider=provider,
            last_response_at=at,
        )


async def check_dependencies(
    tools: LocalTools, ready_store: Callable[[], Awaitable[RunStore | None]]
) -> DependencyHealth:
    scope = scope_for(PROBE_CASE)
    assert scope is not None
    run_id = uuid4().hex

    async def read(action: Action) -> ToolResult:
        assert action in scope.actions
        return await tools.execute(
            ToolProposal(
                action=action, resource=scope.resource, scenario_id=PROBE_CASE, run_id=run_id
            )
        )

    async def catalog_health() -> Check:
        if tools.catalog is None:
            return Check(status=HealthStatus.UNKNOWN, code="catalog_embedded")
        if await tools.catalog.alive():
            return Check(status=HealthStatus.OK, code="catalog_alive")
        return Check(status=HealthStatus.DEGRADED, code="catalog_unreachable")

    store, monitoring, runbook, catalog = await asyncio.gather(
        ready_store(), read(Action.STATUS), read(Action.INCIDENT), catalog_health()
    )
    store_health = state_check(store is not None)
    if store is None:
        manual = Check(status=HealthStatus.DEGRADED, code="storage_unavailable")
    else:
        assignment = await asyncio.to_thread(
            check_assignment, store.policy_path, INCIDENT_QUEUE, DEMO_OPERATOR
        )
        manual = Check(
            status=HealthStatus.OK
            if assignment.code == ApprovalCode.ALLOWED
            else HealthStatus.DEGRADED,
            code="manual_available" if assignment.code == ApprovalCode.ALLOWED else assignment.code,
        )
    queue = source_check(monitoring, "snapshot_ok")
    if monitoring.risk is not None and monitoring.risk.stale:
        queue = Check(status=HealthStatus.DEGRADED, code="stale_snapshot")
    search = source_check(runbook, "runbook_found")
    status = (
        HealthStatus.DEGRADED
        if any(
            check.status == HealthStatus.DEGRADED
            for check in (store_health, queue, search, catalog, manual)
        )
        else HealthStatus.OK
    )
    logger.log(
        logging.WARNING if status == HealthStatus.DEGRADED else logging.INFO,
        "Функциональная проверка состояние=%s хранилище=%s мониторинг=%s каталог=%s поиск=%s ручной_разбор=%s",
        status,
        store_health.code,
        queue.code,
        catalog.code,
        search.code,
        manual.code,
    )
    return DependencyHealth(
        checked_at=datetime.now(UTC),
        status=status,
        storage=store_health,
        monitoring=queue,
        catalog=catalog,
        runbook=search,
        manual=manual,
    )


def source_check(result: ToolResult, success_code: str) -> Check:
    if result.code == "ok":
        return Check(status=HealthStatus.OK, code=success_code)
    return Check(status=HealthStatus.DEGRADED, code=result.code)


def state_check(ready: bool) -> Check:
    if ready:
        return Check(status=HealthStatus.OK, code="storage_ready")
    return Check(status=HealthStatus.DEGRADED, code="storage_unavailable")
