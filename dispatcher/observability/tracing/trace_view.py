import logging
from datetime import UTC, datetime, timedelta
from typing import Literal

import httpx2
from pydantic import AwareDatetime, BaseModel, Field, ValidationError

from dispatcher.workflow.lifecycle import Phase
from dispatcher.workflow.triage import Run

logger = logging.getLogger(__name__)
TraceStatus = Literal["available", "pending", "disabled", "unavailable", "no_trace"]
LOOKBACK = timedelta(days=29)
QUERY_LIMIT = 300


class TraceItem(BaseModel):
    timestamp: AwareDatetime
    service: str
    kind: Literal["span", "event"]
    operation: str
    result: str
    span_id: str
    parent_span_id: str | None = None
    started_at: AwareDatetime | None = None
    duration_ms: float | None = Field(default=None, ge=0)
    provider: str | None = None
    check_level: str | None = None
    tool: str | None = None
    snapshot_at: str | None = None
    attempt: str | None = None
    actor: str | None = None
    peer: str | None = None
    message_id: str | None = None
    task_id: str | None = None
    sender: str | None = None
    recipient: str | None = None
    symptom: str | None = None
    affected_reports: int | None = Field(default=None, ge=0)


class TraceLine(TraceItem):
    service: str = ""
    trace_id: str
    run_id: str
    scenario_id: str


class TraceView(BaseModel):
    trace_id: str | None
    status: TraceStatus
    automated_ms: float
    operator_wait_ms: float | None
    items: list[TraceItem]


def elapsed_ms(start: datetime, end: datetime) -> float:
    return round(max(0, (end - start).total_seconds() * 1000), 3)


def summarize(run: Run, items: list[TraceItem], status: TraceStatus, now: datetime) -> TraceView:
    events = run.lifecycle.events
    awaiting = next(
        (i for i, item in enumerate(events) if item.phase == Phase.AWAITING_APPROVAL), None
    )
    auto_end = events[awaiting].at if awaiting is not None else events[-1].at
    timing = next(
        (
            item.duration_ms
            for item in items
            if item.operation in {"triage", "coordination_run", "hierarchy_run"}
        ),
        None,
    )
    waiting_ms = None
    if awaiting is not None:
        action_time = next(
            (
                item.started_at
                for item in items
                if item.operation == "issue_approval" and item.result == "ok"
            ),
            None,
        )
        end = action_time or (events[awaiting + 1].at if awaiting + 1 < len(events) else now)
        waiting_ms = elapsed_ms(events[awaiting].at, end)
    return TraceView(
        trace_id=run.trace_id,
        status=status,
        automated_ms=timing if timing is not None else elapsed_ms(events[0].at, auto_end),
        operator_wait_ms=waiting_ms,
        items=items,
    )


class LokiResult(BaseModel):
    values: list[tuple[str, str]]
    stream: dict[str, str] = Field(default_factory=dict)


class LokiData(BaseModel):
    resultType: Literal["streams"]
    result: list[LokiResult]


class LokiResponse(BaseModel):
    status: Literal["success"]
    data: LokiData


async def read_trace(run: Run, url: str) -> TraceView:
    now = datetime.now(UTC)
    if run.trace_id is None:
        return summarize(run, [], "no_trace", now)
    if not url:
        return summarize(run, [], "disabled", now)
    query = (
        '{app="dispatcher"} | json'
        f' | trace_id="{run.trace_id}" | run_id="{run.id}"'
        ' | kind=~"span|event" | __error__=""'
    )
    start = max(
        now - LOOKBACK,
        min(now - timedelta(seconds=1), run.lifecycle.events[0].at - timedelta(seconds=30)),
    )
    try:
        async with httpx2.AsyncClient(timeout=4, trust_env=False) as client:
            response = await client.get(
                f"{url.rstrip('/')}/loki/api/v1/query_range",
                params={
                    "query": query,
                    "limit": QUERY_LIMIT,
                    "direction": "forward",
                    "start": start.isoformat(),
                    "end": now.isoformat(),
                },
            )
        response.raise_for_status()
        streams = LokiResponse.model_validate_json(response.content).data.result
    except httpx2.HTTPError, httpx2.InvalidURL, ValidationError:
        logger.warning("Хранилище трасс недоступно прогон=%s", run.id)
        return summarize(run, [], "unavailable", now)
    entries = []
    for stream in streams:
        for _, raw in stream.values:
            try:
                item = TraceLine.model_validate_json(raw)
            except ValidationError:
                continue
            if (item.trace_id, item.run_id, item.scenario_id) == (
                run.trace_id,
                run.id,
                run.scenario_id,
            ):
                item.service = item.service or stream.stream.get("service", "")
                entries.append(item)
    entries.sort(key=lambda item: item.started_at or item.timestamp)
    return summarize(run, entries[:QUERY_LIMIT], "available" if entries else "pending", now)
