import logging
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import StrEnum
from threading import Lock
from time import monotonic
from typing import Literal

import httpx2
from pydantic import BaseModel, SecretStr, ValidationError

from dispatcher.identity.access import NOTIFICATION_REQUESTS, SERVICE_HEADER
from dispatcher.observability.tracing.telemetry import event, trace_headers
from dispatcher.resilience.retry_and_circuit_breaker.retry import (
    TEMPORARY_HTTP_STATUSES,
    RetryPolicy,
    retry,
)
from dispatcher.security.source_access.source_origin import configured_origin
from dispatcher.workflow.scenarios import Monitoring

logger = logging.getLogger(__name__)
MONITORING_RETRY = RetryPolicy(attempt_timeout=0.7, budget=1.7, delay=0.12)
FAILURE_THRESHOLD = 2
RECOVERY_SECONDS = 5
MonitoringCode = Literal["ok", "circuit_open", "timeout", "source_unavailable"]


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True)
class CallPermit:
    generation: int
    state: CircuitState


class CircuitBreaker:
    def __init__(
        self,
        *,
        threshold: int = FAILURE_THRESHOLD,
        cooldown: float = RECOVERY_SECONDS,
        clock: Callable[[], float] = monotonic,
    ):
        self._threshold = threshold
        self._cooldown = cooldown
        self._clock = clock
        self._lock = Lock()
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._generation = 0
        self._retry_at = 0.0

    def enter(self) -> CallPermit | None:
        with self._lock:
            if self._state == CircuitState.OPEN and self._clock() >= self._retry_at:
                self._transition(CircuitState.HALF_OPEN)
            elif self._state != CircuitState.CLOSED:
                return None
            return CallPermit(self._generation, self._state)

    def state(self) -> CircuitState:
        with self._lock:
            return self._state

    def finish(self, permit: CallPermit, healthy: bool | None) -> CircuitState:
        with self._lock:
            # Запоздалый ответ из прежнего состояния не должен менять новое состояние цепи.
            if permit.generation != self._generation:
                return self._state
            if permit.state == CircuitState.HALF_OPEN:
                self._transition(CircuitState.CLOSED if healthy else CircuitState.OPEN)
            elif healthy is True:
                self._failures = 0
            elif healthy is False:
                self._failures += 1
                if self._failures >= self._threshold:
                    self._transition(CircuitState.OPEN)
            return self._state

    def _transition(self, state: CircuitState) -> None:
        self._state = state
        self._generation += 1
        if state == CircuitState.OPEN:
            self._retry_at = self._clock() + self._cooldown
        elif state == CircuitState.CLOSED:
            self._failures = 0
        logger.info("Circuit breaker мониторинга состояние=%s", state)
        event("monitoring_circuit", state)


class MonitoringTrace(BaseModel):
    entry_state: CircuitState
    final_state: CircuitState
    attempts: list[str]


@dataclass(frozen=True)
class MonitoringRead:
    trace: MonitoringTrace
    snapshot: Monitoring | None = None
    code: MonitoringCode = "ok"


class SourceError(RuntimeError):
    def __init__(self, code: str, *, temporary: bool = False):
        super().__init__(code)
        self.code = code
        self.temporary = temporary


def can_retry(error: Exception) -> bool:
    return isinstance(error, TimeoutError) or isinstance(error, SourceError) and error.temporary


class MonitoringClient:
    def __init__(
        self,
        url: str,
        token: SecretStr,
        *,
        breaker: CircuitBreaker | None = None,
        policy: RetryPolicy = MONITORING_RETRY,
        transport: httpx2.AsyncBaseTransport | None = None,
    ):
        self.url = configured_origin(url)
        self.token = token
        self.breaker = breaker if breaker is not None else CircuitBreaker()
        self.policy = policy
        self.transport = transport

    async def read(self, scenario_id: str) -> MonitoringRead:
        permit = self.breaker.enter()
        if permit is None:
            state = self.breaker.state()
            event("monitoring_circuit", "circuit_open")
            return MonitoringRead(
                MonitoringTrace(entry_state=state, final_state=state, attempts=[]),
                code="circuit_open",
            )
        attempts: list[str] = []
        snapshot = None
        code = "ok"
        healthy = None
        policy = (
            # Пробный запрос после паузы не повторяется: одна ошибка снова размыкает цепь.
            replace(self.policy, attempts=1)
            if permit.state == CircuitState.HALF_OPEN
            else self.policy
        )
        try:
            async with httpx2.AsyncClient(
                base_url=self.url,
                transport=self.transport,
                trust_env=False,
                follow_redirects=False,
                timeout=None,
                headers={SERVICE_HEADER: self.token.get_secret_value(), **trace_headers()},
            ) as client:
                snapshot = await retry(
                    lambda: fetch_snapshot(client, scenario_id),
                    policy,
                    can_retry,
                    name="monitoring_attempt",
                    on_attempt=attempts.append,
                )
            healthy = True
        except TimeoutError:
            code = "timeout"
            healthy = False
        except SourceError as error:
            code = "source_unavailable"
            if error.temporary:
                healthy = False
        finally:
            state = self.breaker.finish(permit, healthy)
        return MonitoringRead(
            MonitoringTrace(entry_state=permit.state, final_state=state, attempts=attempts),
            snapshot=snapshot,
            code=code,
        )


async def fetch_snapshot(client: httpx2.AsyncClient, scenario_id: str) -> Monitoring:
    if scenario_id not in NOTIFICATION_REQUESTS:
        raise SourceError("snapshot_forbidden")
    try:
        url = client.base_url.copy_with(path=f"/snapshots/{scenario_id}")
        response = await client.get(url)
    except httpx2.TimeoutException as error:
        raise TimeoutError from error
    except httpx2.TransportError as error:
        raise SourceError("transport_error", temporary=True) from error
    if response.status_code != 200:
        raise SourceError(
            f"http_{response.status_code}",
            temporary=response.status_code in TEMPORARY_HTTP_STATUSES,
        )
    try:
        return Monitoring.model_validate_json(response.content)
    except ValidationError as error:
        raise SourceError("invalid_snapshot") from error
