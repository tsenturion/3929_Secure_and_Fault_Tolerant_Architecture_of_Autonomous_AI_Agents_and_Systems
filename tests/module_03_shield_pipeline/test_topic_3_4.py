from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.persistence import storage
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from tests.approval_helpers import commit_approval, issue_approval


def draft(client):
    response = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"})
    response.raise_for_status()
    return response.json()


def setup_clock(monkeypatch, store):
    now = [datetime(2026, 11, 15, 9, 12, tzinfo=UTC)]
    store.clock = lambda: now[0]
    store.approval_period = timedelta(minutes=10)
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    return now


def test_deadline_is_authoritative_at_the_boundary_and_new_run_can_be_approved(
    monkeypatch,
    connected_executor,
):
    now = setup_clock(monkeypatch, connected_executor)
    with TestClient(main.app) as client:
        expired = draft(client)
        deadline = datetime.fromisoformat(expired["approval_deadline"])
        assert deadline == now[0] + timedelta(minutes=10)
        path = f"/api/runs/{expired['id']}"
        now[0] = deadline
        rejected = issue_approval(client, path)
        assert rejected.status_code == 409
        assert rejected.json()["code"] == "approval_expired"
        record = client.get(path).json()
        assert record["status"] == "approval_expired"
        assert record["incident_id"] is None
        assert record["shield_checks"][-1]["code"] == "approval_expired"
        assert connected_executor.count_incidents("REQ-1842") == 0

        new = draft(client)
        assert new["id"] != expired["id"]
        assert datetime.fromisoformat(new["approval_deadline"]) > deadline
        new_path = f"/api/runs/{new['id']}"
        grant = issue_approval(client, new_path).json()
        approved = commit_approval(client, new_path, grant)
        approved.raise_for_status()
        assert approved.json()["incident_id"] == "INC-3071"
        now[0] += timedelta(hours=1)
        assert commit_approval(client, new_path, grant).json()["incident_id"] == "INC-3071"
        assert issue_approval(client, path).status_code == 409
    assert connected_executor.count_incidents("REQ-1842") == 1


def test_expiration_while_preparing_publication_prevents_write(monkeypatch, connected_executor):
    now = setup_clock(monkeypatch, connected_executor)
    with TestClient(main.app) as client:
        run = draft(client)
        original = storage.build_publication
        deadline = datetime.fromisoformat(run["approval_deadline"])
        now[0] = deadline - timedelta(seconds=1)
        path = f"/api/runs/{run['id']}"
        grant = issue_approval(client, path).json()

        def slow_publication(*args):
            now[0] = deadline
            return original(*args)

        monkeypatch.setattr(storage, "build_publication", slow_publication)
        response = commit_approval(client, path, grant)
        assert response.status_code == 409
        assert response.json()["code"] == "approval_expired"
    assert connected_executor.count_incidents("REQ-1842") == 0


def test_list_updates_expired_draft_and_demo_stays_isolated(monkeypatch, connected_executor):
    now = setup_clock(monkeypatch, connected_executor)
    with TestClient(main.app) as client:
        run = draft(client)
        now[0] += timedelta(minutes=11)
        assert (
            client.get("/api/runs?scenario_id=REQ-1842").json()[0]["status"] == "approval_expired"
        )
        assert client.get(f"/api/runs/{run['id']}").json()["status"] == "approval_expired"
        response = client.post("/api/approval-timeout-demo")
        response.raise_for_status()
        result = response.json()
        assert result["timely"]["incident_count"] == 1
        assert result["late"]["incident_count"] == 0
        assert result["late"]["policy_code"] == "approval_expired"
    assert connected_executor.count_incidents("REQ-1842") == 0
