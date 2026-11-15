from typing import TYPE_CHECKING, Literal

from fastapi import HTTPException
from pydantic import BaseModel

from dispatcher.identity.access import NOTIFICATIONS, Caller
from dispatcher.observability.tracing.telemetry import TraceContext, new_trace, record_trace, span
from dispatcher.security.source_access.runbook_catalog import RUNBOOK_IDS
from dispatcher.security.tool_guardrails.tools import LocalTools, authorized_tool
from dispatcher.workflow.execution import ToolProposal
from dispatcher.workflow.scenarios import Action

if TYPE_CHECKING:
    from dispatcher.persistence.storage import RunStore

CASE = "REQ-1842"
URL_SAMPLE = "https://outside.invalid/telemetry"
FILE_SAMPLE = "C:/training/delivery-notes.txt"


class SourceEvent(BaseModel):
    operation: Literal["source_policy", "source_read"]
    result: str


class SourceCheck(BaseModel):
    action: Action
    reference: str
    code: str
    message: str
    observation: str | None = None
    trace: list[SourceEvent]


class SourceAccessReport(BaseModel):
    trace_id: str
    checks: list[SourceCheck]


async def demonstrate_source_access(
    caller: Caller, store: RunStore, tools: LocalTools
) -> SourceAccessReport:
    trace = new_trace(CASE)
    runbook_id = RUNBOOK_IDS[Action.INCIDENT]
    events: list[SourceEvent] = []

    def collect(_context: TraceContext, fields: dict) -> None:
        if fields["operation"] in {"source_policy", "source_read"}:
            events.append(SourceEvent(operation=fields["operation"], result=fields["result"]))

    checks = []
    for action, resource, document in (
        (Action.STATUS, NOTIFICATIONS, None),
        (Action.STATUS, URL_SAMPLE, None),
        (Action.INCIDENT, NOTIFICATIONS, runbook_id),
        (Action.INCIDENT, NOTIFICATIONS, FILE_SAMPLE),
    ):
        proposal = ToolProposal(
            action=action,
            resource=resource,
            document_id=document,
            scenario_id=CASE,
            run_id=trace.run_id,
        )
        start = len(events)
        with (
            record_trace(collect, also_log=True),
            span("tool_execute", parent=trace, tool=action) as operation,
        ):
            try:
                result = await authorized_tool(caller, proposal, store, tools=tools)
            except HTTPException as error:
                code = (error.headers or {}).get("X-Policy-Code")
                if code not in {"resource_forbidden", "document_forbidden"}:
                    raise
                message = error.detail
                observation = None
            else:
                code = result.code
                message = result.message
                observation = result.observation.summary if result.observation else None
            operation.code = code
        checks.append(
            SourceCheck(
                action=action,
                reference=document or resource,
                code=code,
                message=message,
                observation=observation,
                trace=events[start:],
            )
        )
    return SourceAccessReport(trace_id=trace.trace_id, checks=checks)
