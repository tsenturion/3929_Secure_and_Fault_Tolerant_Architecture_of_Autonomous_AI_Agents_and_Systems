from uuid import uuid4

from fastapi.testclient import TestClient

from dispatcher import executor, main
from dispatcher.identity.access import SERVICE_HEADER
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from tests.approval_helpers import commit_approval, issue_approval


def test_executor_verifies_both_identities_and_checks_resource(service_headers):
    proposal = {
        "scenario_id": "REQ-1842",
        "run_id": uuid4().hex,
        "action": "get_service_status",
        "resource": "order-notifications",
    }
    with TestClient(executor.app) as service:
        without_service = service.post(
            "/tools", headers={"Authorization": service_headers["Authorization"]}, json=proposal
        )
        assert without_service.status_code == 401
        assert without_service.headers["X-Policy-Code"] == "service_unverified"
        without_user = service.post(
            "/tools", headers={SERVICE_HEADER: service_headers[SERVICE_HEADER]}, json=proposal
        )
        assert without_user.status_code == 401
        assert without_user.headers["X-Policy-Code"] == "operator_unverified"
        allowed = service.post("/tools", headers=service_headers, json=proposal)
        assert allowed.json()["code"] == "ok"
        denied = service.post(
            "/tools", headers=service_headers, json={**proposal, "resource": "payments"}
        )
        assert denied.status_code == 403
        assert denied.headers["X-Policy-Code"] == "resource_forbidden"
        assert "observation" not in denied.json()
        missing = service.post(
            "/tools", headers=service_headers, json={**proposal, "resource": None}
        )
        assert missing.status_code == 403


def test_access_uses_verified_user_and_is_checked_again_on_replay(
    monkeypatch, access_keys, connected_executor
):
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    observer = {"Authorization": f"Bearer {access_keys.observer_token.get_secret_value()}"}
    with TestClient(main.app) as client:
        assert (
            client.get("/api/identity", headers={"Authorization": "Bearer invalid"}).status_code
            == 401
        )
        draft = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"})
        draft.raise_for_status()
        path = f"/api/runs/{draft.json()['id']}"
        assert client.get(path, headers=observer).status_code == 200
        with_role_claim = {**observer, "X-Operator": "duty_operator"}
        denied = issue_approval(client, path, headers=with_role_claim)
        assert denied.status_code == 403
        assert denied.json()["code"] == "operation_forbidden"
        assert connected_executor.count_incidents("REQ-1842") == 0
        grant = issue_approval(client, path).json()
        allowed = commit_approval(client, path, grant)
        assert allowed.json()["incident_id"] == "INC-3071"
        replay = commit_approval(client, path, grant, headers=observer)
        assert replay.status_code == 403
        assert connected_executor.count_incidents("REQ-1842") == 1


def test_demo_compares_resources_under_same_identity(access_keys):
    headers = {"Authorization": f"Bearer {access_keys.observer_token.get_secret_value()}"}
    with TestClient(main.app) as client:
        response = client.post("/api/zero-trust-demo", headers=headers)
        response.raise_for_status()
    result = response.json()
    assert result["service"] == "diagnostic-agent"
    assert result["operator"] == "observer"
    assert result["action"] == "get_service_status"
    assert [(item["resource"], item["allowed"], item["code"]) for item in result["results"]] == [
        ("order-notifications", True, "ok"),
        ("payments", False, "resource_forbidden"),
    ]
