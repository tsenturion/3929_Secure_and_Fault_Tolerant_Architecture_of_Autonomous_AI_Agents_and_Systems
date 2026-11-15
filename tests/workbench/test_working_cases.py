import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.models.adapters import ModelUnavailable
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from dispatcher.workflow.comparison import restore_demo_assignment
from tests.approval_helpers import approve, commit_approval, issue_approval

PRIVATE_TEXT = "Внутренний номер заказа Z93291 и личная заметка покупателя"
EMAIL = "buyer-work@example.invalid"


@pytest.fixture
def client(monkeypatch, tmp_path, connected_executor):
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None, openai_api_key=""))
    policy = tmp_path / "on-call.json"
    restore_demo_assignment(policy)
    connected_executor.policy_path = policy
    with TestClient(main.app) as api:
        yield api


def evidence(*, oldest=22, age=0):
    snapshot = datetime.now(UTC) - timedelta(minutes=age)
    return {
        "snapshot_at": snapshot.isoformat(),
        "deployment_at": (snapshot - timedelta(hours=1)).isoformat(),
        "report_count": 31,
        "queue_size": 271,
        "oldest_minutes": oldest,
        "checkout_healthy": True,
    }


def intake(client):
    response = client.post(
        "/api/cases",
        json={
            "symptom": "delayed_confirmation",
            "support": {"description": PRIVATE_TEXT, "customer_email": EMAIL},
        },
    )
    assert response.status_code == 201
    assert PRIVATE_TEXT not in response.text
    return response.json()


def update(client, case, **options):
    response = client.put(
        f"/api/cases/{case['id']}/evidence",
        json={"revision": case["revision"], "evidence": evidence(**options)},
    )
    response.raise_for_status()
    return response.json()


def start(client, case, *, rules=True):
    return client.post(
        "/api/runs", json={"scenario_id": case["id"], "mode": "agent", "rules_only": rules}
    )


def test_intake_to_incident_and_closure(client, connected_executor, access_keys):
    assert client.get("/api/metrics?scope=work").json()["tool_calls"] == 0
    case = intake(client)
    case_url = f"/api/cases/{case['id']}"
    observer = {"Authorization": f"Bearer {access_keys.observer_token.get_secret_value()}"}
    assert start(client, case).status_code == 409
    assert client.get(f"{case_url}/support-card", headers=observer).status_code == 403
    original = client.get(f"{case_url}/support-card")
    assert original.json() == {"description": PRIVATE_TEXT, "customer_email": EMAIL}
    assert original.headers["Cache-Control"] == "private, no-store"
    assert (
        client.put(
            f"{case_url}/evidence", headers=observer, json={"revision": 1, "evidence": evidence()}
        ).status_code
        == 403
    )
    case = update(client, case)
    run = start(client, case)
    run.raise_for_status()
    assert run.json()["status"] == "awaiting_approval"
    assert client.get(case_url).json()["analysis_status"] == "awaiting_approval"
    assert all(step["selected_by"] == "rule" for step in run.json()["steps"])
    assert EMAIL not in run.text and PRIVATE_TEXT not in run.text
    path = f"/api/runs/{run.json()['id']}"
    assert connected_executor.count_incidents(case["id"]) == 0
    assert issue_approval(client, path, headers=observer).status_code == 403
    incident = approve(client, path)
    incident.raise_for_status()
    registered = incident.json()
    assert registered["publication"]["affected_reports"] == 31
    assert "271" in registered["publication"]["technical_evidence"]
    assert PRIVATE_TEXT not in incident.text and EMAIL not in incident.text
    shared = client.get("/api/cases", headers=observer)
    assert shared.json()[0]["incident"]["id"] == registered["incident_id"]
    assert PRIVATE_TEXT not in shared.text and EMAIL not in shared.text
    assert not any(row["id"] == case["id"] for row in client.get("/api/scenarios").json())
    assert client.get("/api/metrics?scope=work").json()["cases"]["closed"] == 1
    assert client.get("/api/metrics?scope=course").json()["cases"]["closed"] == 0
    assert client.post(f"{case_url}/close", headers=observer).status_code == 403
    result = client.post(f"{case_url}/close").json()
    assert result["closed_at"] and result["incident"]["id"] == registered["incident_id"]
    assert start(client, case).status_code == 409
    assert client.post(f"{case_url}/close").json() == result


def test_changed_facts_invalidate_approval(client, connected_executor):
    case = update(client, intake(client))
    run = start(client, case).json()
    path = f"/api/runs/{run['id']}"
    token = issue_approval(client, path)
    token.raise_for_status()
    update(client, case, oldest=3)
    result = commit_approval(client, path, token.json())
    assert result.status_code == 409
    assert result.json()["code"] == "case_changed"
    assert connected_executor.count_incidents(case["id"]) == 0
    current = client.get(f"/api/cases/{case['id']}").json()
    analyzed = start(client, current).json()
    assert analyzed["status"] == "completed"
    assert analyzed["recommendation"]["category"] == "individual"


def test_work_model_sees_structured_facts_and_stale_snapshot_stops_registration(
    client, monkeypatch
):
    calls = []

    class InspectModel(DemonstrationModel):
        def decide(self, context, available):
            calls.append(context)
            assert PRIVATE_TEXT not in context and EMAIL not in context
            assert json.loads(context)["сводка"]["число обращений"] == 31
            return super().decide(context, available)

    monkeypatch.setattr(main, "create_model", lambda _: InspectModel())
    case = update(client, intake(client))
    run = start(client, case, rules=False)
    run.raise_for_status()
    assert calls
    assert run.json()["status"] == "awaiting_approval"
    stale = update(client, case, age=8)
    response = start(client, stale)
    assert response.json()["status"] == "needs_review"
    assert "устарел" in response.json()["error"]


def test_model_outage_can_be_resolved_on_the_same_working_case(client, monkeypatch):
    def unavailable(_settings):
        raise ModelUnavailable("Модель временно недоступна.")

    monkeypatch.setattr(main, "create_model", unavailable)
    case = update(client, intake(client))
    stopped = start(client, case, rules=False).json()
    assert stopped["status"] == "needs_review"
    assert stopped["manual_registration_available"] is True
    path = f"/api/runs/{stopped['id']}"
    handoff = client.post(f"{path}/resolution", json={"decision": "take_over"})
    assert handoff.json()["status"] == "manual_handoff"
    verified = client.post(f"{path}/manual-evidence")
    verified.raise_for_status()
    assert len(verified.json()["manual_evidence"]) == 3
    draft = client.post(f"{path}/manual-draft", json={"priority": "P2"})
    assert draft.json()["status"] == "awaiting_approval"
    result = approve(client, path)
    result.raise_for_status()
    assert result.json()["status"] == "manual_completed"
