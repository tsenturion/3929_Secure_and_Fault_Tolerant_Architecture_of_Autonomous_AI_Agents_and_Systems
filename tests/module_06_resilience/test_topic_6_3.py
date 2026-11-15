import asyncio

import httpx2
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from dispatcher import executor, main
from dispatcher.resilience.retry_and_circuit_breaker.monitoring import (
    CircuitBreaker,
    CircuitState,
    MonitoringClient,
)
from dispatcher.resilience.retry_and_circuit_breaker.retry import RetryPolicy, retry
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from dispatcher.workflow.client import ExecutorClient, ExecutorRejected
from dispatcher.workflow.comparison import restore_demo_assignment
from dispatcher.workflow.execution import ResolveRequest
from tests.approval_helpers import issue_approval


def test_demo_shows_retry_open_circuit_and_successful_probe():
    with TestClient(main.app) as client:
        response = client.post("/api/reliability/demo")

    assert response.status_code == 200
    steps = {step["stage"]: step for step in response.json()["steps"]}
    assert steps["transient"]["monitoring"]["attempts"] == ["http_503", "ok"]
    assert steps["transient"]["fresh_metrics"]
    assert steps["first_timeout"]["monitoring"]["attempts"] == ["timeout", "timeout"]
    assert steps["first_timeout"]["monitoring"]["final_state"] == "closed"
    assert steps["second_timeout"]["monitoring"]["final_state"] == "open"
    assert steps["skipped"]["monitoring"]["attempts"] == []
    assert steps["skipped"]["status"] == "needs_review"
    assert not steps["skipped"]["fresh_metrics"]
    assert steps["probe"]["monitoring"] == {
        "entry_state": "half_open",
        "final_state": "closed",
        "attempts": ["ok"],
    }
    assert steps["recovered"]["fresh_metrics"]


def test_shared_circuit_isolates_training_faults_and_saves_failed_reads(
    monkeypatch, access_keys, connected_executor
):
    now = 0.0
    attempts = 0
    breaker = CircuitBreaker(clock=lambda: now)

    async def overloaded(request):
        nonlocal attempts
        attempts += 1
        return httpx2.Response(503)

    monitor = MonitoringClient(
        "http://monitoring",
        SecretStr(""),
        breaker=breaker,
        policy=RetryPolicy(attempt_timeout=0.1, budget=0.3, delay=0),
        transport=httpx2.MockTransport(overloaded),
    )
    access_keys.monitoring_url = "http://monitoring"
    monkeypatch.setattr(executor, "monitoring_client", lambda url, token: monitor)
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    payload = {"scenario_id": "REQ-1842", "mode": "fixed"}

    with TestClient(main.app) as client:
        result = client.post("/api/runs", json={**payload, "fault": "stale_monitoring"})
        assert result.status_code == 200
        assert attempts == 0
        assert breaker.state() == CircuitState.CLOSED
        for _ in range(2):
            result = client.post("/api/runs", json=payload)
            assert result.status_code == 200
            assert result.json()["monitoring"]["attempts"] == ["http_503", "http_503"]
        # Другое обращение пользуется тем же состоянием зависимости.
        skipped = client.post("/api/runs", json={**payload, "scenario_id": "REQ-1843"}).json()
        assert skipped["monitoring"]["attempts"] == []
        assert skipped["status"] == "needs_review"
        assert "Нет свежих метрик" in skipped["error"]
        assert client.get(f"/api/runs/{skipped['id']}").json()["error"] == skipped["error"]
        assert attempts == 4
        now += 5
        probe = client.post("/api/runs", json=payload).json()
        assert probe["monitoring"]["attempts"] == ["http_503"]
        assert probe["monitoring"]["final_state"] == "open"
        assert connected_executor.count_incidents("REQ-1842") == 0


def test_breaker_accepts_only_one_probe_and_ignores_stale_completion():
    now = 0.0
    breaker = CircuitBreaker(threshold=1, cooldown=5, clock=lambda: now)
    old = breaker.enter()
    failure = breaker.enter()
    assert old is not None and failure is not None
    assert breaker.finish(failure, False) == CircuitState.OPEN
    assert breaker.finish(old, True) == CircuitState.OPEN
    assert breaker.enter() is None
    now += 5
    probe = breaker.enter()
    assert probe is not None and probe.state == CircuitState.HALF_OPEN
    assert breaker.enter() is None
    assert breaker.finish(probe, True) == CircuitState.CLOSED


def test_operation_budget_caps_a_slow_attempt():
    async def run():
        entered = 0

        async def hang():
            nonlocal entered
            entered += 1
            await asyncio.Future()

        with pytest.raises(TimeoutError):
            await retry(hang, RetryPolicy(1, 0.02, 0), lambda _: True, name="test")
        assert entered == 1

    asyncio.run(run())


def test_registration_reuses_token_and_key_after_lost_response(
    connected_executor, service_headers, monkeypatch, tmp_path
):
    policy = tmp_path / "on-call.json"
    restore_demo_assignment(policy)
    connected_executor.policy_path = policy
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())

    with TestClient(main.app) as http:
        draft = http.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"}).json()
        issued = issue_approval(http, f"/api/runs/{draft['id']}")
        issued.raise_for_status()
        grant = issued.json()

    seen = []

    async def run():
        server = httpx2.ASGITransport(app=executor.app)

        async def lose_first_response(request):
            seen.append((request.headers["Idempotency-Key"], request.content))
            response = await server.handle_async_request(request)
            assert response.status_code == 200
            if len(seen) == 1:
                await response.aclose()
                raise httpx2.ReadError("Ответ потерян после записи.")
            return response

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(lose_first_response),
            base_url="http://executor",
            headers=service_headers,
        ) as http:
            return await ExecutorClient(http).resolve(
                draft["id"],
                ResolveRequest(decision="approve", transaction_token=grant["token"]),
                grant["idempotency_key"],
            )

    result = asyncio.run(run())
    assert result.incident_id == "INC-3071"
    assert len(seen) == 2 and seen[0] == seen[1]
    assert connected_executor.count_incidents("REQ-1842") == 1


@pytest.mark.parametrize("status, code", [(403, "not_assigned"), (503, "policy_unavailable")])
def test_registration_policy_responses_are_final(status, code):
    async def run():
        calls = 0

        async def deny(request):
            nonlocal calls
            calls += 1
            return httpx2.Response(
                status,
                json={"detail": "Политика отклонила запись."},
                headers={"X-Policy-Code": code},
            )

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(deny),
            base_url="http://executor",
        ) as http:
            with pytest.raises(ExecutorRejected) as result:
                await ExecutorClient(http).resolve(
                    "a" * 32,
                    ResolveRequest(decision="approve", transaction_token="b" * 64),
                    "c" * 32,
                )
        assert result.value.code == code
        assert calls == 1

    asyncio.run(run())
