from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.identity.access import NOTIFICATIONS, Caller, Operator
from dispatcher.models.adapters import ModelError
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from dispatcher.workflow.execution import ToolProposal
from dispatcher.workflow.scenarios import SCENARIOS, Action

URL = "/api/anomalies?scenario_id=REQ-1842"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    with TestClient(main.app) as client:
        yield client


def start(client, **fields):
    result = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent", **fields})
    result.raise_for_status()
    return result.json()


def alerts(client, kind):
    response = client.get(URL)
    response.raise_for_status()
    return [item for item in response.json()["alerts"] if item["kind"] == kind]


def test_rate_requires_growth_over_baseline_and_distinguishes_versions(client, connected_executor):
    now = datetime(2026, 11, 15, 0, 0, 30, tzinfo=UTC)
    caller = Caller(operator=Operator.DUTY)
    proposal = ToolProposal(
        action=Action.STATUS, scenario_id="REQ-1842", run_id=uuid4().hex, resource=NOTIFICATIONS
    )
    original = SCENARIOS["REQ-1842"].read(Action.STATUS)
    changed = original.model_copy(update={"summary": "В почтовой очереди 2 030 сообщений."})

    connected_executor.clock = lambda: now - timedelta(minutes=2)
    for _ in range(20):
        connected_executor.audit_tool(caller, proposal, "ok", admitted=True, observation=original)
    connected_executor.clock = lambda: now
    for _ in range(6):
        connected_executor.audit_tool(caller, proposal, "ok", admitted=True, observation=original)
    assert alerts(client, "tool_rate") == []
    for _ in range(2):
        connected_executor.audit_tool(caller, proposal, "ok", admitted=True, observation=changed)
    [alert] = alerts(client, "tool_rate")
    assert alert["count"] == 8
    assert alert["baseline_per_minute"] == 4
    assert alert["repeated_snapshot_reads"] == 6
    assert {item["snapshot_at"] for item in alert["evidence"]} == {"14:12"}
    connected_executor.clock = lambda: now + timedelta(seconds=61)
    assert alerts(client, "tool_rate") == []


def test_live_guardrail_alert_links_saved_run_and_trace(client):
    runs = [start(client, fault="repeated_monitoring") for _ in range(3)]
    (rate,) = alerts(client, "tool_rate")
    assert rate["count"] == 6
    assert rate["repeated_snapshot_reads"] == 3
    assert {item["result"] for item in rate["evidence"]} == {"ok", "action_limit_reached"}
    budgets = alerts(client, "budget")
    assert len(budgets) == 3 and all(item["budget_metric"] == "blocked" for item in budgets)
    evidence = budgets[0]["evidence"][0]
    assert evidence["saved_run"]
    assert evidence["trace_id"] in {item["trace_id"] for item in runs}
    trace = client.get(f"/api/runs/{evidence['run_id']}/trace")
    assert trace.status_code == 200
    assert trace.json()["trace_id"] == evidence["trace_id"]


def test_unfinished_run_approaches_configured_step_limit(client, monkeypatch):
    normal = start(client)
    assert normal["status"] == "awaiting_approval"
    assert not alerts(client, "budget")

    class UnavailableModel:
        def decide(self, context, allowed):
            raise ModelError("Провайдер недоступен.")

    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None, triage_max_steps=2))
    monkeypatch.setattr(main, "create_model", lambda _: UnavailableModel())
    failed = start(client)
    assert failed["status"] == "needs_review"
    [budget] = alerts(client, "budget")
    assert budget["budget_metric"] == "steps"
    assert (budget["count"], budget["threshold"], budget["budget_limit"]) == (1, 1, 2)
    assert budget["evidence"][0]["run_id"] == failed["id"]


def test_authenticated_write_denials_are_audited_and_counted(
    client, access_keys, connected_executor
):
    run = start(client)
    observer = {"Authorization": f"Bearer {access_keys.observer_token.get_secret_value()}"}
    route = f"/api/runs/{run['id']}/resolution"
    for _ in range(2):
        assert client.post(route, json={"decision": "approve"}, headers=observer).status_code == 403
    assert not alerts(client, "write_denials")
    assert client.post(route, json={"decision": "approve"}, headers=observer).status_code == 403
    [alert] = alerts(client, "write_denials")
    assert alert["count"] == 3
    assert {item["result"] for item in alert["evidence"]} == {"operation_forbidden"}
    assert all(
        item["operator"] == "observer" and item["trace_id"] == run["trace_id"]
        for item in alert["evidence"]
    )
    assert connected_executor.count_incidents("REQ-1842") == 0
    assert client.get("/api/anomalies?scenario_id=REQ-9999").status_code == 403
    assert client.get(URL, headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_demo_traces_explain_policy_refusal_and_repeated_read_without_changing_history(
    client, connected_executor
):
    response = client.post("/api/anomalies/demo")
    response.raise_for_status()
    report = response.json()
    assert report["source"] == "demo"
    alerts_by_kind = {item["kind"]: item for item in report["alerts"]}
    assert alerts_by_kind["tool_rate"]["count"] == 10
    assert alerts_by_kind["tool_rate"]["repeated_snapshot_reads"] == 6
    write = alerts_by_kind["write_denials"]
    assert write["count"] == 3
    blocked = next(item for item in report["alerts"] if item["budget_metric"] == "blocked")
    tool_trace = report["demo_traces"][blocked["evidence"][0]["run_id"]]["items"]
    assert any(item["snapshot_at"] == "14:12" for item in tool_trace)
    assert any(item["result"] == "action_limit_reached" for item in tool_trace)
    write_trace = report["demo_traces"][write["evidence"][0]["run_id"]]["items"]
    assert (
        len(
            [
                item
                for item in write_trace
                if item["operation"] == "resolve_approval"
                and item["result"] == "assignment_missing"
            ]
        )
        == 3
    )
    assert client.get(URL).json()["alerts"] == []
    assert connected_executor.count_incidents("REQ-1842") == 0
