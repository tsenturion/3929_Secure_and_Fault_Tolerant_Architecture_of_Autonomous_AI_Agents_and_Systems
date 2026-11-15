from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from dispatcher.multiagent.coordination.coordination_protocol import Participant
from dispatcher.multiagent.information_flow import FlowData, Party
from dispatcher.workflow.execution import RunId
from dispatcher.workflow.scenarios import Action, SourceKind

CASE = "REQ-1842"
RUNBOOK_ID = "RB-NOTIFY-07"


class Order(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: RunId
    run_id: RunId
    scenario_id: Literal["REQ-1842"] = CASE


class DiagnosticOrder(Order):
    role: Literal[Participant.DIAGNOSTIC] = Participant.DIAGNOSTIC


class RunbookOrder(Order):
    role: Literal[Participant.RUNBOOK] = Participant.RUNBOOK
    runbook_id: Literal["RB-NOTIFY-07"]
    queue_context: FlowData = Field(default_factory=FlowData)

    @field_validator("queue_context")
    @classmethod
    def check_context(cls, context: FlowData) -> FlowData:
        # Задание проверяется на входе: мастер не может передать регламенту лишние поля.
        if context != context.permitted(Party.MASTER, Party.RUNBOOK):
            raise ValueError("Поле недоступно агенту регламентов.")
        return context


TaskOrder = Annotated[DiagnosticOrder | RunbookOrder, Field(discriminator="role")]


class TaskStage(StrEnum):
    DELEGATED = "delegated"
    REPORTED = "reported"
    TIMEOUT = "timeout"
    FAILED = "failed"
    READY = "ready"
    MANUAL = "manual"


class SourceReference(BaseModel):
    action: Action
    kind: SourceKind
    label: str
    version: str
    summary: str


class DelegationEvent(BaseModel):
    elapsed_ms: float
    stage: TaskStage
    actor: Participant
    detail: str
    task_id: RunId | None = None
    sources: list[SourceReference] = Field(default_factory=list)
    oldest_minutes: int | None = None


class DelegationTrace(BaseModel):
    events: list[DelegationEvent]
