from sqlite3 import OperationalError

import httpx2
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from dispatcher import main
from dispatcher.models.adapters import ModelUnavailable
from dispatcher.resilience.functional_health import InferenceHealth
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.security.source_access import runbook_catalog_service
from dispatcher.security.source_access.runbook_catalog import RunbookCatalog
from dispatcher.settings import Settings
from dispatcher.workflow.comparison import restore_demo_assignment


@pytest.fixture
def broken_catalog(monkeypatch, tmp_path, access_keys):
    index = tmp_path / "incomplete.json"
    index.write_text('["RB-NOTIFY-03"]', encoding="utf-8")
    token = "c" * 40
    monkeypatch.setenv("RUNBOOK_INDEX_PATH", str(index))
    monkeypatch.setenv("RUNBOOK_CATALOG_TOKEN", token)
    access_keys.runbook_catalog_url = "http://catalog"
    access_keys.runbook_catalog_token = SecretStr(token)

    async def request(self, path):
        transport = httpx2.ASGITransport(app=runbook_catalog_service.app)
        async with httpx2.AsyncClient(base_url=self.url, transport=transport) as http:
            return await http.get(path, headers={"X-Service-Token": self.token.get_secret_value()})

    monkeypatch.setattr(RunbookCatalog, "request", request)
    with TestClient(runbook_catalog_service.app):
        yield token


@pytest.fixture
def client(monkeypatch, tmp_path, connected_executor):
    config = Settings(
        _env_file=None, model_provider="openai", model_gateway_url="", openai_api_key="test"
    )
    monkeypatch.setattr(main, "settings", lambda: config)
    monkeypatch.setattr(main, "inference_health", InferenceHealth())
    policy = tmp_path / "policy.json"
    restore_demo_assignment(policy)
    connected_executor.policy_path = policy
    with TestClient(main.app) as http:
        yield http


def test_incomplete_catalog_index_keeps_health_endpoints_responsive(broken_catalog):
    headers = {"X-Service-Token": broken_catalog}
    with TestClient(runbook_catalog_service.app) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 200
        assert client.get("/search/RB-NOTIFY-07").status_code == 401
        assert client.get("/search/RB-NOTIFY-07", headers=headers).status_code == 404
        assert client.get("/search/RB-NOTIFY-03", headers=headers).status_code == 200
    assert "RB-NOTIFY-07" in runbook_catalog_service.PUBLISHED


def test_functional_probe_reports_failed_search_and_preserves_business_history(
    client, connected_executor, broken_catalog
):
    result = client.get("/api/health/functional")
    assert result.status_code == 200
    report = result.json()
    assert report["status"] == "degraded"
    assert report["storage"]["status"] == "ok"
    assert report["monitoring"]["code"] == "snapshot_ok"
    assert report["catalog"]["code"] == "catalog_alive"
    assert report["runbook"]["code"] == "runbook_not_found"
    assert report["manual"]["code"] == "manual_available"
    with connected_executor.connection() as db:
        for table in ("runs", "incidents", "tool_calls", "audit_events", "transaction_approvals"):
            assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0

    workflow = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "fixed"})
    assert workflow.json()["status"] == "needs_review"
    assert "регламент" in workflow.json()["error"]


def test_state_failure_blocks_readiness_but_process_remains_live(
    service_client, monkeypatch, connected_executor
):
    assert service_client.get("/health/ready").status_code == 200

    def unavailable():
        raise OperationalError("Учебный отказ хранилища")

    monkeypatch.setattr(connected_executor, "probe_readiness", unavailable)
    assert service_client.get("/health/live").status_code == 200
    assert service_client.get("/health/ready").status_code == 503
    report = service_client.get("/health/functional").json()
    assert report["storage"]["code"] == "storage_unavailable"
    assert report["manual"]["status"] == "degraded"


def test_model_status_uses_normal_inference_and_ignores_simulated_failure(client, monkeypatch):
    initial = client.get("/api/health/functional").json()
    assert initial["model"]["code"] == "model_unverified"
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    payload = {"scenario_id": "REQ-1842", "mode": "agent"}
    assert client.post("/api/runs", json=payload).json()["status"] == "awaiting_approval"
    working = client.get("/api/health/functional").json()
    assert working["model"]["code"] == "model_response_ok"
    assert working["model"]["last_response_at"]

    result = client.post("/api/runs", json={**payload, "fault": "model_unavailable"})
    assert result.json()["status"] == "needs_review"
    assert client.get("/api/health/functional").json()["model"] == working["model"]

    class FailedModel:
        def decide(self, *_):
            raise ModelUnavailable("Учебный отказ модели")

    monkeypatch.setattr(main, "create_model", lambda _: FailedModel())
    assert client.post("/api/runs", json=payload).json()["status"] == "needs_review"
    latest = client.get("/api/health/functional").json()
    assert latest["model"]["code"] == "model_response_unavailable"
    assert latest["manual"]["code"] == "manual_available"


def test_functional_route_requires_verified_operator(client):
    response = client.get("/api/health/functional", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401
