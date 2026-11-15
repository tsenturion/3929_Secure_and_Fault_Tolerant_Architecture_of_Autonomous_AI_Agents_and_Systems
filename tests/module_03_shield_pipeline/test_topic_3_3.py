import threading
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.security.tool_guardrails import tools
from dispatcher.settings import Settings


def proposal(action="get_service_status", **changes):
    return {
        "action": action,
        "scenario_id": "REQ-1842",
        "run_id": uuid4().hex,
        "resource": "order-notifications",
        **changes,
    }


def test_parallel_reads_share_action_budget(service_client, monkeypatch):
    reads = []
    start = threading.Barrier(2)
    original = tools.read_observation

    async def read(*args):
        reads.append(args[1])
        return await original(*args)

    monkeypatch.setattr(tools, "read_observation", read)
    body = proposal()

    def request(_):
        start.wait(timeout=5)
        response = service_client.post("/tools", json=body)
        response.raise_for_status()
        return response.json()["code"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(request, range(2))) == ["action_limit_reached", "ok"]
    assert reads == ["get_service_status"]


def test_total_budget_and_binding_are_checked_by_executor(service_client, access_keys):
    body = proposal()
    assert service_client.post("/tools", json=body).json()["code"] == "ok"
    other_case = {**body, "scenario_id": "REQ-1843"}
    assert service_client.post("/tools", json=other_case).json()["code"] == "run_scope_mismatch"
    observer = access_keys.observer_token.get_secret_value()
    denied = service_client.post(
        "/tools", json=body, headers={"Authorization": f"Bearer {observer}"}
    )
    assert denied.json()["code"] == "run_scope_mismatch"
    for action in ("get_recent_deployment", "find_incident_runbook", "find_individual_runbook"):
        assert service_client.post("/tools", json={**body, "action": action}).json()["code"] == "ok"
    assert service_client.post("/tools", json=body).json()["code"] == "call_limit_reached"


@pytest.mark.parametrize(
    ("fault", "code", "steps"),
    [
        ("repeated_monitoring", "action_limit_reached", 1),
        ("oversized_observation", "response_too_large", 0),
    ],
)
def test_guardrail_demos_preserve_only_allowed_observations(
    fault,
    code,
    steps,
    monkeypatch,
    service_client,
    connected_executor,
):
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))

    def unexpected_model(_):
        pytest.fail("Учебное ограничение не требует обращения к модели.")

    monkeypatch.setattr(main, "create_model", unexpected_model)
    with TestClient(main.app) as client:
        response = client.post(
            "/api/runs",
            json={
                "scenario_id": "REQ-1842",
                "mode": "agent",
                "fault": fault,
            },
        )
        response.raise_for_status()
        run = response.json()
        assert run["status"] == "needs_review"
        assert run["review_required"]
        assert len(run["steps"]) == steps
        assert ["policy", code] in [[item["level"], item["code"]] for item in run["shield_checks"]]
        assert (
            client.post(
                f"/api/runs/{run['id']}/resolution",
                json={"decision": "take_over"},
            ).json()["status"]
            == "manual_handoff"
        )
    followup = service_client.post("/tools", json=proposal(run_id=run["id"]))
    assert followup.json()["code"] == "run_closed"
    assert connected_executor.count_incidents("REQ-1842") == 0
