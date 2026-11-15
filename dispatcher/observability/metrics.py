import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Literal

from pydantic import BaseModel

from dispatcher.observability.tamper_evident_audit.audit import recent_events
from dispatcher.persistence.database import StoreConnection
from dispatcher.workflow.scenarios import Action


class ToolMinutes(IntEnum):
    FIVE = 5
    FIFTEEN = 15
    SIXTY = 60


DEFAULT_TOOL_MINUTES = ToolMinutes.FIFTEEN
OUTCOME_HOURS = 24
Outcome = Literal["agent", "manual", "failed"]
MetricsScope = Literal["course", "work"]
OTHER_TOOL = "other"
STATUS = Action.STATUS.value
TOOLS = frozenset(action.value for action in Action if action != Action.FINISH)


class CaseMetrics(BaseModel):
    closed: int
    agent: int
    manual: int
    failed: int
    success_rate: float | None
    agent_rate: float | None


class ToolMetrics(BaseModel):
    tool: str
    calls: int
    calls_per_minute: float
    results: dict[str, int]
    minutes: list[int]


class MetricsReport(BaseModel):
    source: Literal["live", "demo"]
    observed_at: datetime
    outcome_hours: int = OUTCOME_HOURS
    cases: CaseMetrics
    tool_window_minutes: ToolMinutes
    tool_window_start: datetime
    tool_calls: int
    tool_calls_per_minute: float
    tools: list[ToolMetrics]


def fraction(part: int, total: int) -> float | None:
    return part / total if total else None


def summarize(
    outcomes: Iterable[str],
    calls: Iterable[tuple[float, str | None, str]],
    now: datetime,
    window: ToolMinutes,
    *,
    source: Literal["live", "demo"],
) -> MetricsReport:
    closures = Counter(outcomes)
    agent, manual, failed = (closures[outcome] for outcome in ("agent", "manual", "failed"))
    closed = agent + manual + failed
    start = now - timedelta(minutes=window)
    lower, upper = start.timestamp(), now.timestamp()
    buckets: defaultdict[str, list[int]] = defaultdict(lambda: [0] * window)
    results: defaultdict[str, Counter[str]] = defaultdict(Counter)
    for at, action, result in calls:
        if not lower < at <= upper:
            continue
        tool = action if action is not None and action in TOOLS else OTHER_TOOL
        index = min(int((at - lower) // 60), window - 1)
        buckets[tool][index] += 1
        results[tool][result] += 1

    rows = [
        ToolMetrics(
            tool=tool,
            calls=sum(counts),
            calls_per_minute=round(sum(counts) / window, 2),
            results=dict(sorted(results[tool].items())),
            minutes=counts,
        )
        for tool, counts in buckets.items()
    ]
    rows.sort(key=lambda row: (-row.calls, row.tool))
    total = sum(row.calls for row in rows)
    return MetricsReport(
        source=source,
        observed_at=now,
        cases=CaseMetrics(
            closed=closed,
            agent=agent,
            manual=manual,
            failed=failed,
            success_rate=fraction(agent + manual, closed),
            agent_rate=fraction(agent, closed),
        ),
        tool_window_minutes=window,
        tool_window_start=start,
        tool_calls=total,
        tool_calls_per_minute=round(total / window, 2),
        tools=rows,
    )


def live_report(
    db: StoreConnection,
    now: datetime,
    window: ToolMinutes,
    scenario_ids: tuple[str, ...],
) -> MetricsReport:
    if not scenario_ids:
        return summarize((), (), now, window, source="live")
    placeholders = ", ".join("?" for _ in scenario_ids)
    rows = db.execute(
        f"""
        SELECT id, scenario_id, status, payload FROM runs
        WHERE scenario_id IN ({placeholders}) AND mode = 'agent'
            AND status IN ('completed', 'manual_completed', 'failed')
        """,
        scenario_ids,
    )
    first = {}
    kinds = {"completed": "agent", "manual_completed": "manual", "failed": "failed"}
    for run_id, scenario, status, payload in rows:
        run = json.loads(payload)
        if run.get("threat") is not None:
            continue
        at = datetime.fromisoformat(run["lifecycle"]["events"][-1]["at"])
        closure = (at, run_id, kinds[status])
        if scenario not in first or closure < first[scenario]:
            first[scenario] = closure
    start = now - timedelta(hours=OUTCOME_HOURS)
    tool_events = recent_events(db, scenario_ids, now - timedelta(minutes=window), now)
    return summarize(
        (outcome for at, _, outcome in first.values() if start < at <= now),
        (
            (event.at.timestamp(), event.tool, event.result)
            for _, _, event in tool_events
            if event.action == "tool_call"
        ),
        now,
        window,
        source="live",
    )


def demo_report(now: datetime) -> MetricsReport:
    outcomes: list[Outcome] = ["agent"] * 35 + ["manual"] * 10 + ["failed"] * 5
    calls = []
    start = now - timedelta(minutes=DEFAULT_TOOL_MINUTES)
    for minute in range(DEFAULT_TOOL_MINUTES):
        at = (start + timedelta(minutes=minute, seconds=30)).timestamp()
        status_checks = 2 if minute < 10 else minute
        for attempt in range(status_checks):
            calls.append((at, STATUS, "timeout" if minute >= 10 and attempt == 0 else "ok"))
        calls.extend(
            [
                (at, Action.DEPLOYMENT.value, "ok"),
                (at, Action.INCIDENT.value, "ok"),
            ]
        )
    return summarize(outcomes, calls, now, DEFAULT_TOOL_MINUTES, source="demo")
