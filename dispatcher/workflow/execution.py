from datetime import datetime
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from dispatcher.multiagent.information_flow import FlowCheck, FlowData, Party
from dispatcher.resilience.retry_and_circuit_breaker.monitoring import MonitoringTrace
from dispatcher.security.agent_threats.boundaries import BoundaryDecision, Threat
from dispatcher.security.shield import RiskInput
from dispatcher.workflow.case_ids import ScenarioId
from dispatcher.workflow.lifecycle import Phase
from dispatcher.workflow.scenarios import Fault, Observation

Scope = Literal["incident", "individual", "uncertain"]
RunId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]


class ToolProposal(BaseModel):
    """Форма запроса на инструмент с привязкой к обращению и прогону.

    Допустимость операции и её аргументов проверяет исполнитель.
    """

    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=64)
    scenario_id: ScenarioId
    run_id: RunId
    resource: str | None = Field(default=None, max_length=80)
    document_id: str | None = Field(default=None, max_length=80)
    case_revision: int | None = Field(default=None, ge=1, strict=True)
    fault: Fault | None = None
    threat: Threat | None = None


class ToolResult(BaseModel):
    """Результат инструмента с кодом исхода и наблюдением при успешном чтении."""

    code: Literal[
        "ok",
        "not_allowed",
        "not_found",
        "timeout",
        "circuit_open",
        "source_unavailable",
        "runbook_not_found",
        "runbook_unavailable",
        "invalid_runbook",
        "source_rejected",
        "action_limit_reached",
        "call_limit_reached",
        "response_too_large",
        "run_scope_mismatch",
        "run_closed",
    ]
    message: str
    observation: Observation | None = None
    scope: Scope | None = None
    risk: RiskInput | None = None
    boundary_decisions: list[BoundaryDecision] = Field(default_factory=list)
    monitoring: MonitoringTrace | None = None
    information: FlowData = Field(default_factory=FlowData)

    @model_validator(mode="after")
    def require_observation(self):
        if self.code == "ok" and self.observation is None:
            raise ValueError("Успешное чтение должно содержать наблюдение.")
        return self

    def forward_information(
        self,
        source: Party,
        destination: Party,
        checks: list[FlowCheck] | None = None,
    ) -> ToolResult:
        return self.model_copy(
            update={"information": self.information.forward(source, destination, checks)}
        )


class AccessExample(BaseModel):
    resource: str
    allowed: bool
    code: str
    message: str
    source: str | None = None


class AccessComparison(BaseModel):
    service: str
    operator: str
    action: str
    results: list[AccessExample]


RunDecision = Literal["approve", "reject", "take_over", "complete_manual", "fail_manual"]


class ResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: RunDecision
    transaction_token: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")] | None = Field(
        default=None, repr=False
    )


class RunSummary(BaseModel):
    id: str
    status: Phase
    started_at: datetime
    threat: Threat | None = None


class ToolExecutor(Protocol):
    async def execute(self, proposal: ToolProposal) -> ToolResult: ...


class ExecutorUnavailable(RuntimeError):
    pass
