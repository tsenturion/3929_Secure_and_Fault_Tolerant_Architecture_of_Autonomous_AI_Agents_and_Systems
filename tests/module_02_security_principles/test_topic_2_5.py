from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.persistence import storage
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.security.tool_guardrails import tools
from dispatcher.settings import Settings
from tests.approval_helpers import issue_approval


def test_read_rejects_unknown_action_before_reading(monkeypatch, service_client):
    async def unexpected_read(*args):
        pytest.fail("Неизвестный инструмент не должен читать источник.")

    monkeypatch.setattr(tools, "read_observation", unexpected_read)
    response = service_client.post(
        "/tools",
        json={
            "action": "unknown_tool",
            "scenario_id": "REQ-1842",
            "run_id": uuid4().hex,
            "resource": "order-notifications",
        },
    )
    response.raise_for_status()
    assert response.json()["code"] == "not_allowed"


@pytest.mark.parametrize(
    "change, code", [("queue", "invalid_draft"), ("steps", "evidence_required")]
)
def test_registration_rejects_before_publication(
    change,
    code,
    monkeypatch,
    service_client,
    connected_executor,
):
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    with TestClient(main.app) as client:
        response = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"})
        response.raise_for_status()
        draft = response.json()

    def unexpected_publication(*args):
        pytest.fail("Исполнитель не должен готовить запись для отклонённого черновика.")

    monkeypatch.setattr(storage, "build_publication", unexpected_publication)
    draft["id"] = uuid4().hex
    if change == "queue":
        draft["recommendation"]["queue"] = "Платежи"
    else:
        draft["steps"] = [
            step for step in draft["steps"] if step["action"] != "find_incident_runbook"
        ]
    assert service_client.post("/runs", json=draft).status_code == 201
    response = issue_approval(service_client, f"/runs/{draft['id']}")
    assert response.status_code == 409
    assert response.headers["X-Policy-Code"] == code
    assert connected_executor.count_incidents("REQ-1842") == 0


def test_demo_compares_same_context_and_blocks_changed_queue(connected_executor):
    with TestClient(main.app) as client:
        response = client.post("/api/registration-checks-demo")
        response.raise_for_status()
    result = response.json()
    before, first, repeated, changed = result["examples"]
    assert before["decision"]["code"] == "confirmation_required"
    assert first["decision"] == repeated["decision"]
    assert first["decision"]["code"] == "allowed"
    assert changed["queue"] == "Платежи"
    assert changed["decision"]["code"] == result["rejected_code"] == "invalid_draft"
    assert result["incident_count"] == 0
    assert connected_executor.list_agent_runs("REQ-1842") == []
