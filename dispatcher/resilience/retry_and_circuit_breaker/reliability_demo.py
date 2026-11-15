import asyncio
from enum import StrEnum

import httpx2
from pydantic import BaseModel, SecretStr

from dispatcher.resilience.retry_and_circuit_breaker.monitoring import (
    RECOVERY_SECONDS,
    CircuitBreaker,
    MonitoringClient,
    MonitoringTrace,
)
from dispatcher.resilience.retry_and_circuit_breaker.retry import RetryPolicy
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.security.tool_guardrails.tools import LocalTools
from dispatcher.workflow.lifecycle import Phase
from dispatcher.workflow.scenarios import SCENARIOS, Action
from dispatcher.workflow.triage import Mode, run_triage

CASE = "REQ-1842"
DEMO_POLICY = RetryPolicy(attempt_timeout=0.08, budget=0.23, delay=0.025)


class Stage(StrEnum):
    TRANSIENT = "transient"
    FIRST_TIMEOUT = "first_timeout"
    SECOND_TIMEOUT = "second_timeout"
    SKIPPED = "skipped"
    PROBE = "probe"
    RECOVERED = "recovered"


class ReliabilityStep(BaseModel):
    stage: Stage
    status: Phase
    fresh_metrics: bool
    monitoring: MonitoringTrace


class ReliabilityReport(BaseModel):
    attempt_timeout_ms: int
    budget_ms: int
    cooldown_seconds: int
    steps: list[ReliabilityStep]


async def demonstrate_reliability() -> ReliabilityReport:
    scenario = SCENARIOS[CASE]
    responses = iter((503, 200, None, None, None, None, 200, 200))
    elapsed = 0.0

    async def send(request: httpx2.Request) -> httpx2.Response:
        status = next(responses)
        if status is None:
            await asyncio.Future()
        if status == 200:
            return httpx2.Response(200, json=scenario.monitoring.model_dump())
        return httpx2.Response(503, json={"detail": "Мониторинг перегружен."})

    client = MonitoringClient(
        "http://monitoring-demo",
        SecretStr(""),
        breaker=CircuitBreaker(clock=lambda: elapsed),
        policy=DEMO_POLICY,
        transport=httpx2.MockTransport(send),
    )
    tools = LocalTools(client)
    steps = []
    for stage in Stage:
        if stage == Stage.PROBE:
            elapsed += RECOVERY_SECONDS
        run = await run_triage(scenario, Mode.AGENT, DemonstrationModel(), executor=tools)
        assert run.monitoring is not None
        steps.append(
            ReliabilityStep(
                stage=stage,
                status=run.status,
                fresh_metrics=any(
                    step.action == Action.STATUS and step.observation is not None
                    for step in run.steps
                ),
                monitoring=run.monitoring,
            )
        )
    return ReliabilityReport(
        attempt_timeout_ms=int(DEMO_POLICY.attempt_timeout * 1000),
        budget_ms=int(DEMO_POLICY.budget * 1000),
        cooldown_seconds=RECOVERY_SECONDS,
        steps=steps,
    )
