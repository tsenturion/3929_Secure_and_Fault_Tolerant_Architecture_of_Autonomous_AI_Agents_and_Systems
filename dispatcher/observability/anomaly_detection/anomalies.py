import json
from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from itertools import batched
from typing import Literal

from pydantic import BaseModel, Field

from dispatcher.observability.metrics import OTHER_TOOL
from dispatcher.observability.tamper_evident_audit.audit import AuditEvent, recent_events
from dispatcher.observability.tracing.telemetry import RUN_PATTERN
from dispatcher.observability.tracing.trace_view import TraceView
from dispatcher.persistence.database import StoreConnection
from dispatcher.security.tool_guardrails.guardrails import scope_for
from dispatcher.workflow.lifecycle import Phase
from dispatcher.workflow.scenarios import Action

CURRENT_SECONDS = 60
BASELINE_MINUTES = 5
BUDGET_MINUTES = 5
TOOL_THRESHOLD = 6
RATE_MULTIPLIER = 2
WRITE_THRESHOLD = 3
MAX_ALERTS = 12
MAX_EVIDENCE = 6
LIMIT_RESULTS = frozenset({"action_limit_reached", "call_limit_reached"})
ADMITTED_RESULTS = frozenset(
    {"ok", "timeout", "source_rejected", "response_too_large", "not_found"}
)
WRITE_ACTIONS = frozenset({"approve_draft", "register_incident"})
AlertKind = Literal["tool_rate", "write_denials", "budget"]


class Observation(BaseModel):
    day: date
    sequence: int
    event: AuditEvent
    saved_run: bool
    trace_id: str | None


class Evidence(BaseModel):
    day: date
    sequence: int
    at: datetime
    run_id: str
    saved_run: bool
    trace_id: str | None
    operator: str | None
    action: str
    result: str
    tool: str | None
    snapshot_at: str | None


class Alert(BaseModel):
    id: str
    kind: AlertKind
    scenario_id: str
    service: str
    count: int
    threshold: int
    last_seen_at: datetime
    evidence: list[Evidence]
    tool: str | None = None
    baseline_per_minute: float | None = None
    repeated_snapshot_reads: int = 0
    budget_metric: Literal["steps", "tools", "blocked"] | None = None
    budget_limit: int | None = None


class AnomalyReport(BaseModel):
    source: Literal["live", "demo"]
    observed_at: datetime
    scenario_id: str
    window_seconds: int = CURRENT_SECONDS
    baseline_minutes: int = BASELINE_MINUTES
    budget_minutes: int = BUDGET_MINUTES
    alerts: list[Alert]
    demo_traces: dict[str, TraceView] = Field(default_factory=dict)


def evidence_for(records: list[Observation]) -> list[Evidence]:
    latest = sorted(records, key=lambda row: (row.event.at, row.sequence), reverse=True)
    return [
        Evidence(
            day=row.day,
            sequence=row.sequence,
            at=row.event.at,
            run_id=row.event.run_id,
            trace_id=row.trace_id,
            saved_run=row.saved_run,
            operator=row.event.operator,
            action=row.event.action,
            result=row.event.result,
            tool=row.event.tool,
            snapshot_at=row.event.snapshot_at,
        )
        for row in latest[:MAX_EVIDENCE]
    ]


def create_alert(
    kind: AlertKind,
    scenario_id: str,
    subject: str,
    count: int,
    threshold: int,
    records: list[Observation],
    **details,
) -> Alert:
    evidence = evidence_for(records)
    return Alert(
        id=f"{kind}:{scenario_id}:{subject}",
        kind=kind,
        scenario_id=scenario_id,
        service=records[0].event.service,
        count=count,
        threshold=threshold,
        last_seen_at=evidence[0].at,
        evidence=evidence,
        **details,
    )


def rate_alerts(scenario_id: str, observations: list[Observation], now: datetime) -> list[Alert]:
    cutoff = now - timedelta(seconds=CURRENT_SECONDS)
    baseline = Counter()
    tools: defaultdict[tuple[str, str], list[Observation]] = defaultdict(list)
    denials: defaultdict[str, list[Observation]] = defaultdict(list)
    for row in observations:
        event = row.event
        if event.action == "tool_call":
            key = (event.service, event.tool or OTHER_TOOL)
            if event.at > cutoff:
                tools[key].append(row)
            else:
                baseline[key] += 1
        if event.at > cutoff and event.action in WRITE_ACTIONS and event.decision == "deny":
            denials[event.service].append(row)
    alerts = []
    for (service, tool), rows in tools.items():
        average = baseline[service, tool] / BASELINE_MINUTES
        if len(rows) < TOOL_THRESHOLD or len(rows) < average * RATE_MULTIPLIER:
            continue
        versions = Counter(
            row.event.snapshot_version for row in rows if row.event.snapshot_version is not None
        )
        same = max(versions.values(), default=0)
        alerts.append(
            create_alert(
                "tool_rate",
                scenario_id,
                f"{service}:{tool}",
                len(rows),
                TOOL_THRESHOLD,
                rows,
                tool=tool,
                baseline_per_minute=round(average, 2),
                repeated_snapshot_reads=same if same > 1 and tool == Action.STATUS else 0,
            )
        )
    for service, rows in denials.items():
        if len(rows) >= WRITE_THRESHOLD:
            alerts.append(
                create_alert(
                    "write_denials", scenario_id, service, len(rows), WRITE_THRESHOLD, rows
                )
            )
    return alerts


def budget_alerts(scenario_id: str, observations: list[Observation], now: datetime) -> list[Alert]:
    scope = scope_for(scenario_id)
    if scope is None:
        return []
    cutoff = now - timedelta(minutes=BUDGET_MINUTES)
    runs: defaultdict[str, list[Observation]] = defaultdict(list)
    for row in observations:
        if row.event.at > cutoff and row.event.action in {"run_saved", "tool_call"}:
            runs[row.event.run_id].append(row)
    alerts = []
    for run_id, rows in runs.items():
        denied = [
            row
            for row in rows
            if row.event.action == "tool_call" and row.event.result in LIMIT_RESULTS
        ]
        if denied:
            alerts.append(
                create_alert(
                    "budget", scenario_id, run_id, len(denied), 1, denied, budget_metric="blocked"
                )
            )
            continue
        saved = next((row.event for row in rows if row.event.action == "run_saved"), None)
        if saved and saved.result != Phase.NEEDS_REVIEW:
            continue
        if saved and saved.step_limit is not None and saved.steps_used is not None:
            threshold = max(1, saved.step_limit - 1)
            if saved.steps_used >= threshold:
                alerts.append(
                    create_alert(
                        "budget",
                        scenario_id,
                        run_id,
                        saved.steps_used,
                        threshold,
                        rows,
                        budget_metric="steps",
                        budget_limit=saved.step_limit,
                    )
                )
                continue
        admitted = [
            row
            for row in rows
            if row.event.action == "tool_call"
            and (
                row.event.admitted is True
                or (row.event.admitted is None and row.event.result in ADMITTED_RESULTS)
            )
        ]
        threshold = max(1, scope.max_calls - 1)
        if len(admitted) >= threshold:
            alerts.append(
                create_alert(
                    "budget",
                    scenario_id,
                    run_id,
                    len(admitted),
                    threshold,
                    admitted,
                    budget_metric="tools",
                    budget_limit=scope.max_calls,
                )
            )
    return alerts


def read_observations(
    db: StoreConnection, scenario_id: str, start: datetime, now: datetime
) -> list[Observation]:
    kinds = WRITE_ACTIONS | {"tool_call", "run_saved"}
    rows = [
        (day, sequence, event)
        for day, sequence, event in recent_events(db, (scenario_id,), start, now)
        if event.action in kinds and RUN_PATTERN.fullmatch(event.run_id)
    ]
    traces = {}
    for batch in batched({event.run_id for _, _, event in rows}, 200):
        placeholders = ", ".join("?" for _ in batch)
        for run_id, body in db.execute(
            f"SELECT id, payload FROM runs WHERE scenario_id = ? AND id IN ({placeholders})",
            (scenario_id, *batch),
        ):
            traces[run_id] = json.loads(body).get("trace_id")
    result = []
    for day, sequence, event in rows:
        trace_id = traces.get(event.run_id) or event.trace_id
        result.append(
            Observation(
                day=day,
                sequence=sequence,
                event=event,
                saved_run=event.run_id in traces,
                trace_id=trace_id
                if isinstance(trace_id, str) and RUN_PATTERN.fullmatch(trace_id)
                else None,
            )
        )
    return result


def report(
    db: StoreConnection,
    scenario_id: str,
    now: datetime,
    *,
    source: Literal["live", "demo"] = "live",
) -> AnomalyReport:
    now = now.astimezone(UTC)
    start = now - timedelta(seconds=CURRENT_SECONDS, minutes=BASELINE_MINUTES)
    observations = read_observations(db, scenario_id, start, now)
    alerts = rate_alerts(scenario_id, observations, now) + budget_alerts(
        scenario_id, observations, now
    )
    order = {"write_denials": 0, "tool_rate": 1, "budget": 2}
    alerts.sort(key=lambda item: (order[item.kind], -item.last_seen_at.timestamp(), item.id))
    return AnomalyReport(
        source=source,
        observed_at=now,
        scenario_id=scenario_id,
        alerts=alerts[:MAX_ALERTS],
    )
