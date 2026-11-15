import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.models.adapters import ModelError
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.security.shield import RiskVerdict
from dispatcher.settings import Settings
from tests.approval_helpers import approve, issue_approval


@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        ("insufficient_evidence", "insufficient_evidence"),
        ("low_risk", "low_risk"),
        ("likely_incident", "likely_incident"),
        (None, "judge_unavailable"),
    ],
)
def test_stale_evidence_reaches_judge_and_human_without_registration(
    verdict,
    expected,
    monkeypatch,
    connected_executor,
):
    calls = []

    class Model(DemonstrationModel):
        def decide(self, context, available):
            pytest.fail("Устаревший снимок должен остановить планирование.")

        def judge(self, evidence):
            calls.append(evidence.model_dump())
            if verdict is None:
                raise ModelError("Ошибка провайдера.")
            return RiskVerdict(verdict=verdict, reason="Данные нуждаются в проверке.")

    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: Model())
    with TestClient(main.app) as client:
        response = client.post(
            "/api/runs",
            json={
                "scenario_id": "REQ-1842",
                "mode": "agent",
                "fault": "stale_monitoring",
            },
        )
        response.raise_for_status()
        run = response.json()
        assert run["status"] == "needs_review"
        assert run["review_required"]
        assert [(step["level"], step["code"]) for step in run["shield_checks"]] == [
            ("policy", "ok"),
            ("heuristics", "conflicting_signals"),
            ("judge", expected),
            ("hitl", "manual_review_required"),
        ]
        assert calls == [
            {
                "recent_reports": 18,
                "snapshot_age_minutes": 22,
                "oldest_message_minutes": 2,
            }
        ]
        path = f"/api/runs/{run['id']}"
        assert issue_approval(client, path).status_code == 409
        takeover = client.post(f"{path}/resolution", json={"decision": "take_over"})
        takeover.raise_for_status()
        assert takeover.json()["status"] == "manual_handoff"
        assert takeover.json()["shield_checks"][-1]["code"] == "taken_over"
        assert client.get(path).json() == takeover.json()
    assert connected_executor.count_incidents("REQ-1842") == 0


def test_fresh_monitoring_and_policy_refusal_do_not_call_judge(monkeypatch):
    class Model(DemonstrationModel):
        def judge(self, evidence):
            pytest.fail("Судья не нужен для штатного снимка или отказа политики.")

    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: Model())
    monkeypatch.setattr(main, "DemonstrationModel", Model)
    with TestClient(main.app) as client:
        normal = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"}).json()
        assert normal["status"] == "awaiting_approval"
        assert not any(check["level"] == "judge" for check in normal["shield_checks"])
        assert normal["shield_checks"][-1]["code"] == "approval_required"
        approved = approve(client, f"/api/runs/{normal['id']}")
        assert approved.json()["shield_checks"][-1]["code"] == "approved"
        denied = client.post("/api/threat-cases/tool_misuse/runs").json()
        assert denied["shield_checks"][-1]["code"] == "not_allowed"
        assert not any(check["level"] in {"judge", "hitl"} for check in denied["shield_checks"])
