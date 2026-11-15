from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.models.adapters import Decision
from dispatcher.settings import Settings
from dispatcher.workflow.scenarios import Action
from tests.approval_helpers import commit_approval, issue_approval


class TestModel:
    def decide(self, context, available):
        action = Action.DEPLOYMENT if Action.DEPLOYMENT in available else Action.INCIDENT
        return Decision(action=action, reason="Уточняем обстоятельства массовой задержки.")


@pytest.fixture
def config(monkeypatch):
    settings = Settings(_env_file=None)
    monkeypatch.setattr(main, "settings", lambda: settings)
    monkeypatch.setattr(main, "create_model", lambda _: TestModel())
    return settings


def start(client, **overrides):
    response = client.post(
        "/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent", **overrides}
    )
    response.raise_for_status()
    return response.json()


def test_approval_persists_and_concurrent_replays_share_incident(config, connected_executor):
    with TestClient(main.app) as client:
        run = start(client)
        another = start(client)
        assert run["status"] == "awaiting_approval"
        assert run["incident_id"] is None
        phases = [event["phase"] for event in run["lifecycle"]["events"]]
        assert phases == ["observe", "reason", "act"] * 4 + ["awaiting_approval"]
    with connected_executor.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM incidents").fetchone() == (0,)
    with TestClient(main.app) as client:
        listed = client.get("/api/runs?scenario_id=REQ-1842").json()
        assert {item["id"] for item in listed} == {run["id"], another["id"]}
        assert client.get(f"/api/runs/{run['id']}").json() == run

        grants = {
            draft["id"]: issue_approval(client, f"/api/runs/{draft['id']}").json()
            for draft in (run, another)
        }

        def approve(id_):
            response = commit_approval(client, f"/api/runs/{id_}", grants[id_])
            response.raise_for_status()
            return response.json()

        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(approve, [run["id"], another["id"], run["id"]]))
        for result in results:
            assert result["status"] == "completed"
            assert result["incident_id"] == "INC-3071"
            assert [event["phase"] for event in result["lifecycle"]["events"]][-4:] == [
                "observe",
                "reason",
                "act",
                "completed",
            ]
    with connected_executor.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM incidents").fetchone() == (1,)


def test_reject_is_final(config):
    with TestClient(main.app) as client:
        run = start(client)
        endpoint = f"/api/runs/{run['id']}/resolution"
        rejected = client.post(endpoint, json={"decision": "reject"})
        assert rejected.json()["status"] == "rejected"
        assert rejected.json()["incident_id"] is None
        assert issue_approval(client, f"/api/runs/{run['id']}").status_code == 409


def test_monitoring_timeout_records_failure_without_calling_model(config, monkeypatch):
    config.triage_timeout_seconds = 0.03

    def unexpected(_):
        pytest.fail("При демонстрации таймаута модель не нужна.")

    monkeypatch.setattr(main, "create_model", unexpected)
    with TestClient(main.app) as client:
        run = start(client, fault="monitoring_timeout")
        assert run["status"] == "needs_review"
        assert run["recommendation"]["category"] == "manual"
        assert run["steps"] == []
        events = run["lifecycle"]["events"]
        assert [event["phase"] for event in events] == ["observe", "reason", "act", "needs_review"]
        assert events[-2]["title"] == "Чтение завершилось таймаутом"
        assert issue_approval(client, f"/api/runs/{run['id']}").status_code == 409


def test_step_budget_preserves_observations(config):
    config.triage_max_steps = 1
    with TestClient(main.app) as client:
        run = start(client)
        assert run["status"] == "needs_review"
        assert "лимит шагов" in run["error"]
        assert [step["action"] for step in run["steps"]] == ["get_service_status"]


def test_model_timeout_ignores_late_decision(config, monkeypatch):
    config.triage_timeout_seconds = 0.15
    entered = Event()
    release = Event()

    class SlowModel:
        def decide(self, context, available):
            entered.set()
            release.wait(3)
            return Decision(action=Action.INCIDENT, reason="Ответ получен после срока.")

    monkeypatch.setattr(main, "create_model", lambda _: SlowModel())
    with TestClient(main.app) as client:
        try:
            run = start(client)
            assert entered.is_set()
            assert run["status"] == "needs_review"
            assert "срок ожидания решения модели" in run["error"]
            assert [step["action"] for step in run["steps"]] == ["get_service_status"]
        finally:
            release.set()
        assert client.get(f"/api/runs/{run['id']}").json() == run
