import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from tests.approval_helpers import commit_approval, issue_approval

VALID = '{"assignments": {"Уведомления": "duty_operator"}}'


@pytest.mark.parametrize(
    ("policy", "status", "code"),
    [
        ('{"assignments": {}}', 403, "assignment_missing"),
        ('{"assignments": {"Уведомления": "backup_operator"}}', 403, "not_assigned"),
        ('{"assignments": {"Уведомления": ""}}', 503, "policy_unavailable"),
        ('{"assignments":', 503, "policy_unavailable"),
        (None, 503, "policy_unavailable"),
    ],
)
def test_approval_requires_a_positive_policy_decision(
    connected_executor, monkeypatch, tmp_path, policy, status, code
):
    policy_path = tmp_path / "on-call.json"
    connected_executor.policy_path = policy_path
    if policy is not None:
        policy_path.write_text(policy, encoding="utf-8")

    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    with TestClient(main.app) as client:
        draft = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"})
        draft.raise_for_status()
        run_path = f"/api/runs/{draft.json()['id']}"
        blocked = issue_approval(client, run_path)
        assert blocked.status_code == status
        assert blocked.json()["code"] == code
        assert connected_executor.count_incidents("REQ-1842") == 0
        stored = client.get(run_path).json()
        assert stored["status"] == "awaiting_approval"
        assert stored["approval_block"]["code"] == code
        assert stored["incident_id"] is None

        policy_path.write_text(VALID, encoding="utf-8")
        grant = issue_approval(client, run_path).json()
        approved = commit_approval(client, run_path, grant)
        approved.raise_for_status()
        assert approved.json()["incident_id"] == "INC-3071"
        assert approved.json()["approval_block"]["code"] == code
        policy_path.unlink()
        replay = commit_approval(client, run_path, grant)
        assert replay.json()["incident_id"] == "INC-3071"
        assert connected_executor.count_incidents("REQ-1842") == 1


def test_fail_closed_demo_uses_temporary_data(connected_executor):
    with TestClient(main.app) as client:
        response = client.post("/api/fail-closed-demo")
        response.raise_for_status()
    result = response.json()
    assert result["blocked"]["incident_count"] == 0
    assert result["blocked"]["policy_code"] == "assignment_missing"
    assert result["restored"]["incident_count"] == 1
    assert result["restored"]["policy_code"] == "allowed"
    assert connected_executor.list_agent_runs("REQ-1842") == []
