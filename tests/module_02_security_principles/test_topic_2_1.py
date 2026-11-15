from uuid import uuid4

from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from tests.approval_helpers import approve, issue_approval


def test_executor_validates_typed_proposals(service_client):
    proposal = {"scenario_id": "REQ-1842", "run_id": uuid4().hex, "resource": "order-notifications"}
    read = service_client.post("/tools", json={**proposal, "action": "get_service_status"})
    assert read.json()["code"] == "ok"
    assert read.json()["scope"] == "incident"
    denied = service_client.post("/tools", json={**proposal, "action": "resend_notifications"})
    assert denied.json()["code"] == "not_allowed"
    assert denied.json()["observation"] is None
    assert (
        service_client.post(
            "/tools", json={**proposal, "action": "get_service_status", "queue": "Уведомления"}
        ).status_code
        == 422
    )


def test_resolution_uses_saved_recommendation(monkeypatch, connected_executor):
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    with TestClient(main.app) as agent:
        response = agent.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"})
        response.raise_for_status()
        draft = response.json()
        assert draft["status"] == "awaiting_approval"
        assert connected_executor.count_incidents("REQ-1842") == 0
        assert [step["executor_code"] for step in draft["steps"]] == ["ok", "ok", "ok", None]
        url = f"/api/runs/{draft['id']}/resolution"
        assert agent.post(url, json={"decision": "approve", "queue": "Платежи"}).status_code == 422
        assert connected_executor.count_incidents("REQ-1842") == 0
        result = approve(agent, f"/api/runs/{draft['id']}")
        assert result.json()["incident_id"] == "INC-3071"


def test_executor_rejects_an_unexpected_queue(monkeypatch, connected_executor, service_client):
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    with TestClient(main.app) as agent:
        draft = agent.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"}).json()
    draft["id"] = uuid4().hex
    draft["recommendation"]["queue"] = "Платежи"
    assert service_client.post("/runs", json=draft).status_code == 201
    response = issue_approval(service_client, f"/runs/{draft['id']}")
    assert response.status_code == 409
    assert response.headers["X-Policy-Code"] == "invalid_draft"
    assert connected_executor.count_incidents("REQ-1842") == 0
