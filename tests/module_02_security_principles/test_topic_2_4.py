import json
from uuid import uuid4

from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from tests.approval_helpers import approve, issue_approval


def test_publication_policy_vetoes_approval_before_assignment_check(
    monkeypatch,
    tmp_path,
    connected_executor,
    service_client,
):
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    with TestClient(main.app) as client:
        response = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"})
        response.raise_for_status()
        safe = response.json()
        with_contacts = {
            **safe,
            "id": uuid4().hex,
            "recommendation": {
                **safe["recommendation"],
                "incident_fields": ["affected_reports", "technical_evidence", "customer_contacts"],
            },
        }
        assert service_client.post("/runs", json=with_contacts).status_code == 201
        appointments = connected_executor.policy_path
        connected_executor.policy_path = tmp_path / "missing.json"
        blocked = issue_approval(client, f"/api/runs/{with_contacts['id']}")
        assert blocked.status_code == 403
        assert blocked.json()["code"] == "data_policy_denied"
        assert (
            connected_executor.get(with_contacts["id"]).approval_block.code == "data_policy_denied"
        )
        assert connected_executor.count_incidents("REQ-1842") == 0

        blocked_safe = issue_approval(client, f"/api/runs/{safe['id']}")
        assert blocked_safe.status_code == 503
        connected_executor.policy_path = appointments
        blocked = issue_approval(client, f"/api/runs/{with_contacts['id']}")
        assert blocked.json()["code"] == "data_policy_denied"
        result = approve(client, f"/api/runs/{safe['id']}")
        result.raise_for_status()
        published = result.json()["publication"]
        assert published["affected_reports"] == 18
        assert "4 800" in published["technical_evidence"]
        assert connected_executor.count_incidents("REQ-1842") == 1
        with connected_executor.connection() as db:
            record = db.execute("SELECT publication FROM incidents").fetchone()[0]
        assert json.loads(record) == published


def test_priority_demo_compares_separate_drafts_without_writing_main_tracker(connected_executor):
    with TestClient(main.app) as client:
        response = client.post("/api/priority-hierarchy-demo")
        response.raise_for_status()
    result = response.json()
    assert result["blocked"]["policy_code"] == "data_policy_denied"
    assert result["blocked"]["incident_count"] == 0
    assert result["approved"]["policy_code"] == "allowed"
    assert result["approved"]["incident_count"] == 1
    assert result["publication"]["affected_reports"] == 18
    assert connected_executor.count_incidents("REQ-1842") == 0
