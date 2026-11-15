import httpx2
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from dispatcher import main
from dispatcher.security.tool_guardrails import tools
from dispatcher.settings import Provider, Settings
from dispatcher.workflow.scenarios import Action
from tests.approval_helpers import commit_approval, issue_approval


@pytest.fixture
def client(monkeypatch, connected_executor, tmp_path):
    config = Settings(_env_file=None, openai_api_key="test-key", model_gateway_url="")
    config.gigachat_credentials = SecretStr("")
    monkeypatch.setattr(main, "settings", lambda: config)
    policy = tmp_path / "on-call.json"
    policy.write_text('{"assignments":{"Уведомления":"duty_operator"}}', encoding="utf-8")
    connected_executor.policy_path = policy
    with TestClient(main.app) as http:
        yield http, config, policy


def start(client, **options):
    response = client.post(
        "/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent", **options}
    )
    response.raise_for_status()
    run = response.json()
    return run, f"/api/runs/{run['id']}"


@pytest.mark.parametrize("provider", list(Provider))
def test_provider_outage_preserves_observation_and_manual_registration(
    client, connected_executor, monkeypatch, tmp_path, provider
):
    http, config, _ = client
    config.model_provider = provider
    config.qwen_model_path = tmp_path / "missing-model"

    def timeout(*args, **kwargs):
        raise httpx2.ReadTimeout("Учебный таймаут HTTP")

    monkeypatch.setattr(httpx2, "post", timeout)
    run, path = start(http)
    assert run["provider"] == provider
    assert run["degradation"] == ("model_timeout" if provider == "openai" else "model_unavailable")
    assert run["status"] == "needs_review"
    assert [step["action"] for step in run["steps"]] == [Action.STATUS]
    assert "4 800" in run["steps"][0]["observation"]["summary"]
    assert http.get(path).json()["error"] == run["error"]

    taken = http.post(f"{path}/resolution", json={"decision": "take_over"})
    assert taken.json()["status"] == "manual_handoff"
    checked = http.post(f"{path}/manual-evidence")
    assert checked.status_code == 200
    assert [step["action"] for step in checked.json()["manual_evidence"]] == [
        Action.STATUS,
        Action.DEPLOYMENT,
        Action.INCIDENT,
    ]
    prepared = http.post(f"{path}/manual-draft", json={"priority": "P2"})
    assert prepared.json()["status"] == "awaiting_approval"
    assert connected_executor.count_incidents("REQ-1842") == 0
    grant = issue_approval(http, path).json()
    registered = commit_approval(http, path, grant)
    assert registered.status_code == 200
    outcome = registered.json()
    assert outcome["status"] == "manual_completed"
    assert outcome["incident_id"]
    assert outcome["steps"] == run["steps"]
    assert commit_approval(http, path, grant).json()["incident_id"] == outcome["incident_id"]
    assert connected_executor.count_incidents("REQ-1842") == 1
    assert http.get("/api/metrics").json()["cases"]["manual"] == 1


def test_manual_draft_requires_operator_evidence_and_current_assignment(
    client, connected_executor, access_keys, monkeypatch
):
    http, _, policy = client
    _, path = start(http, fault="model_unavailable")
    observer = {"Authorization": f"Bearer {access_keys.observer_token.get_secret_value()}"}
    assert http.post(f"{path}/manual-evidence", headers=observer).status_code == 403
    assert http.post(f"{path}/manual-evidence").status_code == 409
    assert http.post(f"{path}/resolution", json={"decision": "take_over"}).status_code == 200
    assert http.post(f"{path}/manual-draft", json={"priority": "P1"}).status_code == 422
    assert (
        http.post(f"{path}/manual-draft", json={"priority": "P2"}).json()["code"]
        == "evidence_required"
    )
    assert http.post(f"{path}/manual-evidence").status_code == 200
    read = tools.read_observation

    async def unavailable(scenario, action, fault):
        if action == Action.INCIDENT:
            raise TimeoutError
        return await read(scenario, action, fault)

    with monkeypatch.context() as patch:
        patch.setattr(tools, "read_observation", unavailable)
        assert http.post(f"{path}/manual-evidence").json()["code"] == "manual_evidence_unavailable"
        assert http.get(path).json()["manual_evidence"] == []
        assert http.post(f"{path}/manual-draft", json={"priority": "P2"}).status_code == 409
    assert http.post(f"{path}/manual-evidence").status_code == 200
    assert http.post(f"{path}/manual-draft", json={"priority": "P2"}).status_code == 200
    grant = issue_approval(http, path).json()
    policy.write_text('{"assignments":{}}', encoding="utf-8")
    assert commit_approval(http, path, grant).json()["code"] == "assignment_missing"
    assert connected_executor.count_incidents("REQ-1842") == 0


@pytest.mark.parametrize(
    "options",
    [{"fault": "invalid_model_output"}, {"fault": "model_unavailable", "scenario_id": "REQ-1843"}],
)
def test_output_rejection_and_healthy_queue_do_not_enable_manual_registration(client, options):
    http, _, _ = client
    run, path = start(http, **options)
    assert run["status"] == "needs_review"
    assert not run["manual_registration_available"]
    assert http.post(f"{path}/resolution", json={"decision": "take_over"}).status_code == 200
    assert http.post(f"{path}/manual-evidence").status_code == 409
