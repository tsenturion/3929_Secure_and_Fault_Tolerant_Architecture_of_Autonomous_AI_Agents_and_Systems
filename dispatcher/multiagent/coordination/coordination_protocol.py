from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from dispatcher.workflow.execution import RunId, ToolResult


class CoordinationMode(StrEnum):
    CENTRALIZED = "centralized"
    PEER_TO_PEER = "peer_to_peer"


class Participant(StrEnum):
    DIAGNOSTIC = "diagnostic"
    RUNBOOK = "runbook"
    COORDINATOR = "coordinator"


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    message_id: RunId
    run_id: RunId
    scenario_id: str = Field(pattern=r"^REQ-[0-9]{4}$")


class DiagnosticEvidence(Envelope):
    sender: Literal[Participant.DIAGNOSTIC] = Participant.DIAGNOSTIC
    snapshot: ToolResult
    deployment: ToolResult


class RunbookEvidence(Envelope):
    sender: Literal[Participant.RUNBOOK] = Participant.RUNBOOK
    runbook: ToolResult


Evidence = Annotated[DiagnosticEvidence | RunbookEvidence, Field(discriminator="sender")]
EventCode = Literal["catalog_wait", "sent", "stored", "duplicate", "assembled", "inconsistent"]
evidence_parser = TypeAdapter(Evidence)


class ProtocolError(ValueError):
    pass


class Inbox:
    """Принимает по одному непротиворечивому сообщению каждой роли в рамках прогона."""

    def __init__(self, run_id: str, scenario_id: str):
        self.run_id = run_id
        self.scenario_id = scenario_id
        self.messages: dict[Participant, Evidence] = {}

    def accept(self, message: Evidence) -> bool:
        if (message.run_id, message.scenario_id) != (self.run_id, self.scenario_id):
            raise ProtocolError("Сообщение относится к другому прогону.")
        previous = self.messages.get(message.sender)
        if previous == message:
            return False
        if previous is not None or any(
            item.message_id == message.message_id for item in self.messages.values()
        ):
            raise ProtocolError("Обнаружено противоречивое сообщение агента.")
        self.messages[message.sender] = message
        return True


class CoordinationEvent(BaseModel):
    at_ms: float
    code: EventCode
    actor: Participant
    peer: Participant | None = None
    message_id: RunId | None = None
    evidence_count: int | None = None


class CoordinationTrace(BaseModel):
    mode: CoordinationMode
    catalog_delay_ms: int
    events: list[CoordinationEvent]
