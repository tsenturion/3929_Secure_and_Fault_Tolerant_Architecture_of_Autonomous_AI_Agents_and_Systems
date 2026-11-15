from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from dispatcher.models.adapters import Model
from dispatcher.observability.anomaly_detection.anomalies import AnomalyReport
from dispatcher.observability.tracing.telemetry import TraceContext, new_trace, record_trace, span
from dispatcher.observability.tracing.trace_view import TraceItem, summarize
from dispatcher.persistence.storage import RunStore
from dispatcher.security.agent_threats.demonstrations import (
    DemonstrationModel,
    RepeatedMonitoringModel,
)
from dispatcher.security.tool_guardrails.tools import authorized_tool
from dispatcher.workflow.approval_policy import ApprovalCode, ApprovalRejected
from dispatcher.workflow.comparison import DEMO_CALLER, authorize, confirm, restore_demo_assignment
from dispatcher.workflow.execution import ToolProposal, ToolResult
from dispatcher.workflow.scenarios import SCENARIOS
from dispatcher.workflow.triage import Mode, Run, run_triage

DEMO_CASE = "REQ-1842"


class DemoExecutor:
    def __init__(self, store: RunStore):
        self.store = store

    async def execute(self, proposal: ToolProposal) -> ToolResult:
        with span("tool_execute", tool=proposal.action) as operation:
            result = await authorized_tool(DEMO_CALLER, proposal, self.store)
            operation.code = result.code
            return result


async def demo_run(
    store: RunStore, *, mode: Mode = Mode.AGENT, model: Model | None = None, steps: int = 5
) -> Run:
    with span("triage", parent=new_trace(DEMO_CASE)) as operation:
        run = await run_triage(
            SCENARIOS[DEMO_CASE], mode, model, executor=DemoExecutor(store), max_steps=steps
        )
        store.save(run, DEMO_CALLER)
        operation.code = run.status
        return run


async def demonstrate_anomalies() -> AnomalyReport:
    observed = datetime.now(UTC)
    clock = observed - timedelta(minutes=5)
    traces: defaultdict[str, list[TraceItem]] = defaultdict(list)
    runs = {}

    def collect(context: TraceContext, fields: dict) -> None:
        traces[context.run_id].append(
            TraceItem.model_validate(
                {
                    "timestamp": clock,
                    "service": "executor",
                    "span_id": context.span_id,
                    **fields,
                }
            )
        )

    with TemporaryDirectory(prefix="dispatcher-anomalies-") as directory:
        path = Path(directory)
        policy = path / "on-call.json"
        restore_demo_assignment(policy)
        store = RunStore(path / "runs.sqlite3", policy, clock=lambda: clock)
        with record_trace(collect):
            for offset in (300, 180):
                clock = observed - timedelta(seconds=offset)
                run = await demo_run(store, mode=Mode.FIXED, steps=1)
                runs[run.id] = run
            for offset in (55, 45, 35, 25):
                clock = observed - timedelta(seconds=offset)
                run = await demo_run(store, model=RepeatedMonitoringModel())
                runs[run.id] = run
            clock = observed - timedelta(seconds=24)
            run = await demo_run(store, model=DemonstrationModel(), steps=2)
            runs[run.id] = run
            clock = observed - timedelta(seconds=20)
            draft = await demo_run(store, model=DemonstrationModel())
            runs[draft.id] = draft
            with span("issue_approval", parent=draft.trace_context()):
                grant = authorize(store, draft.id)
            policy.write_text('{"assignments": {}}', encoding="utf-8")
            for offset in (17, 13, 9):
                clock = observed - timedelta(seconds=offset)
                try:
                    with span("resolve_approval", parent=draft.trace_context()):
                        confirm(store, draft.id, grant)
                except ApprovalRejected as error:
                    if error.block.code != ApprovalCode.ASSIGNMENT_MISSING:
                        raise
                else:
                    raise RuntimeError("Ожидался отказ из-за отсутствия назначения.")
        clock = observed
        report = store.anomaly_report(DEMO_CASE)
        report.source = "demo"
        evidence_runs = {item.run_id for alert in report.alerts for item in alert.evidence}
        report.demo_traces = {
            run_id: summarize(
                runs[run_id],
                sorted(traces[run_id], key=lambda item: item.timestamp),
                "available",
                datetime.now(UTC),
            )
            for run_id in evidence_runs
        }
        return report
