from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.identity.access import Caller, Operator
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from dispatcher.workflow.execution import ToolProposal
from tests.approval_helpers import approve


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    with TestClient(main.app) as client:
        yield client


def start(client, case="REQ-1842", **options):
    response = client.post("/api/runs", json={"scenario_id": case, "mode": "agent", **options})
    response.raise_for_status()
    return response.json()


def resolve(client, run, decision, headers=None):
    return client.post(
        f"/api/runs/{run['id']}/resolution", json={"decision": decision}, headers=headers
    )


def test_demo_calculates_rates_and_queue_status_burst(client):
    response = client.get("/api/metrics/demo")
    response.raise_for_status()
    report = response.json()
    assert report["source"] == "demo"
    assert report["cases"] == {
        "closed": 50,
        "agent": 35,
        "manual": 10,
        "failed": 5,
        "success_rate": 0.9,
        "agent_rate": 0.7,
    }
    assert report["tool_calls"] == 110
    assert report["tool_calls_per_minute"] == 7.33
    tools = {item["tool"]: item for item in report["tools"]}
    status = tools["get_service_status"]
    assert status["minutes"] == [2] * 10 + [10, 11, 12, 13, 14]
    assert status["results"] == {"ok": 75, "timeout": 5}
    assert tools["get_recent_deployment"]["minutes"] == [1] * 15
    assert client.get("/api/metrics").json()["cases"]["closed"] == 0
    assert client.get("/api/metrics").json()["tool_calls"] == 0


def test_live_manual_completion_and_failure_count_once_per_case(client, access_keys):
    observer = {"Authorization": f"Bearer {access_keys.observer_token.get_secret_value()}"}
    manual = start(client, fault="repeated_monitoring")
    assert manual["status"] == "needs_review"
    assert resolve(client, manual, "complete_manual").status_code == 409
    assert resolve(client, manual, "take_over", observer).status_code == 403
    assert resolve(client, manual, "take_over").json()["status"] == "manual_handoff"
    before = client.get("/api/metrics").json()["cases"]
    assert before["closed"] == 0
    assert before["success_rate"] is None
    assert resolve(client, manual, "complete_manual", observer).status_code == 403
    assert resolve(client, manual, "complete_manual").json()["status"] == "manual_completed"
    assert resolve(client, manual, "complete_manual").status_code == 200
    assert resolve(client, manual, "fail_manual").status_code == 409

    duplicate = start(client)
    assert approve(client, f"/api/runs/{duplicate['id']}").json()["incident_id"] == "INC-3071"
    other = start(client, "REQ-1843", fault="repeated_monitoring")
    assert resolve(client, other, "take_over").status_code == 200
    assert resolve(client, other, "fail_manual").json()["status"] == "failed"
    assert resolve(client, other, "fail_manual").status_code == 200

    response = client.get("/api/metrics?tool_minutes=5", headers=observer)
    response.raise_for_status()
    result = response.json()
    assert result["cases"] == {
        "closed": 2,
        "agent": 0,
        "manual": 1,
        "failed": 1,
        "success_rate": 0.5,
        "agent_rate": 0.0,
    }
    assert result["tool_window_minutes"] == 5
    assert result["tool_calls"] > 0
    assert any("action_limit_reached" in item["results"] for item in result["tools"])


def test_fixed_route_counts_tools_and_agent_closes_case(client):
    fixed = start(client, mode="fixed")
    assert fixed["status"] == "completed"
    metrics = client.get("/api/metrics").json()
    assert metrics["cases"]["closed"] == 0
    assert metrics["tool_calls"] > 0
    agent = start(client)
    assert approve(client, f"/api/runs/{agent['id']}").status_code == 200
    assert client.get("/api/metrics").json()["cases"]["agent"] == 1


def test_repeat_of_old_closure_does_not_enter_daily_window(client, connected_executor):
    first = start(client)
    assert approve(client, f"/api/runs/{first['id']}").status_code == 200
    closed = connected_executor.get(first["id"])
    closed.lifecycle.events[-1].at = datetime.now(UTC) - timedelta(hours=25)
    with connected_executor.connection() as db:
        connected_executor.update(db, closed)

    repeat = start(client)
    assert approve(client, f"/api/runs/{repeat['id']}").json()["incident_id"] == "INC-3071"
    assert client.get("/api/metrics").json()["cases"]["closed"] == 0


def test_window_bounds_outcomes_and_scope(client, connected_executor):
    now = datetime(2026, 11, 15, 9, 12, tzinfo=UTC)
    actor = Caller(operator=Operator.DUTY)
    tool = ToolProposal(
        action="get_service_status",
        resource="order-notifications",
        run_id=uuid4().hex,
        scenario_id="REQ-1842",
    )
    connected_executor.clock = lambda: now - timedelta(minutes=5)
    connected_executor.audit_tool(actor, tool, "ok")
    connected_executor.clock = lambda: now - timedelta(minutes=4)
    connected_executor.audit_tool(actor, tool, "timeout")
    connected_executor.clock = lambda: now
    connected_executor.audit_tool(actor, tool, "ok")
    connected_executor.audit_tool(actor, tool.model_copy(update={"scenario_id": "REQ-9999"}), "ok")
    result = client.get("/api/metrics?tool_minutes=5").json()
    assert result["tool_calls"] == 2
    assert result["tool_calls_per_minute"] == 0.4
    assert result["tools"][0]["minutes"] == [0, 1, 0, 0, 1]
    assert result["tools"][0]["results"] == {"ok": 1, "timeout": 1}
    assert client.get("/api/metrics?tool_minutes=7").status_code == 422
    assert (
        client.get("/api/metrics", headers={"Authorization": "Bearer invalid"}).status_code == 401
    )
