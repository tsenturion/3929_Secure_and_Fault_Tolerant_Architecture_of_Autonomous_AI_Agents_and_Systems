from collections.abc import Awaitable, Callable

from dispatcher.identity.access import denied
from dispatcher.multiagent.coordination.coordination_protocol import (
    DiagnosticEvidence,
    Evidence,
    Participant,
    RunbookEvidence,
)
from dispatcher.multiagent.hierarchy.delegation import DiagnosticOrder, TaskOrder
from dispatcher.multiagent.information_flow import Party
from dispatcher.security.tool_guardrails.guardrails import scope_for
from dispatcher.workflow.execution import ToolProposal, ToolResult
from dispatcher.workflow.scenarios import Action

ROLE_ACTIONS = {
    Participant.DIAGNOSTIC: frozenset({Action.STATUS, Action.DEPLOYMENT}),
    Participant.RUNBOOK: frozenset({Action.INCIDENT}),
}


class DelegatedReader:
    def __init__(self, order: TaskOrder, execute: Callable[[ToolProposal], Awaitable[ToolResult]]):
        self.order = order
        self._execute = execute

    async def read(self, action: Action) -> ToolResult:
        order = self.order
        scope = scope_for(order.scenario_id)
        # Полномочия пересекаются с областью сценария и ролью исполнителя перед вызовом инструмента.
        if scope is None or action not in scope.actions or action not in ROLE_ACTIONS[order.role]:
            raise denied(
                403, "delegation_scope_denied", "Действие вне полномочий подчинённого агента."
            )
        result = await self._execute(
            ToolProposal(
                action=action,
                scenario_id=order.scenario_id,
                run_id=order.run_id,
                resource=scope.resource,
            )
        )
        if action == Action.STATUS:
            return result.forward_information(Party.MONITORING, Party.DIAGNOSTIC)
        if action == Action.INCIDENT:
            return result.forward_information(Party.CATALOG, Party.RUNBOOK)
        return result


async def perform_task(reader: DelegatedReader) -> Evidence:
    order = reader.order
    binding = {
        "run_id": order.run_id,
        "message_id": order.task_id,
        "scenario_id": order.scenario_id,
    }
    if isinstance(order, DiagnosticOrder):
        snapshot = (await reader.read(Action.STATUS)).forward_information(
            Party.DIAGNOSTIC, Party.MASTER
        )
        deployment = await reader.read(Action.DEPLOYMENT)
        return DiagnosticEvidence(**binding, snapshot=snapshot, deployment=deployment)
    runbook = (await reader.read(Action.INCIDENT)).forward_information(Party.RUNBOOK, Party.MASTER)
    return RunbookEvidence(**binding, runbook=runbook)
