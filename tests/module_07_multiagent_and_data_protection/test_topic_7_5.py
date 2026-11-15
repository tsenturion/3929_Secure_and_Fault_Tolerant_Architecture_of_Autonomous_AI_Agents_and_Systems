import asyncio
import json

import httpx2
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from dispatcher import main
from dispatcher.identity.access import NOTIFICATIONS, SERVICE_HEADER
from dispatcher.resilience.retry_and_circuit_breaker.monitoring import MonitoringClient
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.security.source_access import runbook_catalog_service
from dispatcher.security.source_access.runbook_catalog import CatalogError, RunbookCatalog
from dispatcher.security.source_access.source_access_demo import CASE, FILE_SAMPLE, URL_SAMPLE
from dispatcher.security.source_access.source_origin import configured_origin
from dispatcher.security.tool_guardrails import tools
from dispatcher.settings import Settings
from dispatcher.workflow.scenarios import Action


def test_demo_traces_two_actual_reads_and_two_rejections(monkeypatch):
    read = tools.read_observation
    calls = []

    async def observe(scenario, action, fault):
        calls.append(action)
        return await read(scenario, action, fault)

    monkeypatch.setattr(tools, "read_observation", observe)
    with TestClient(main.app) as client:
        response = client.post("/api/source-access-demo")
    response.raise_for_status()
    assert calls == [Action.STATUS, Action.INCIDENT]
    checks = response.json()["checks"]
    assert [check["code"] for check in checks] == [
        "ok",
        "resource_forbidden",
        "ok",
        "document_forbidden",
    ]
    for check in (checks[0], checks[2]):
        assert check["observation"]
        assert check["trace"] == [
            {"operation": "source_policy", "result": "allowed"},
            {"operation": "source_read", "result": "ok"},
        ]
    for check in (checks[1], checks[3]):
        assert check["observation"] is None
        assert check["trace"] == [{"operation": "source_policy", "result": check["code"]}]


def test_tool_rejects_extra_parameter_and_preserves_read_budget(service_client):
    proposal = {
        "action": Action.INCIDENT,
        "resource": NOTIFICATIONS,
        "scenario_id": CASE,
        "run_id": "a" * 32,
    }
    response = service_client.post("/tools", json={**proposal, "path": FILE_SAMPLE})
    assert response.status_code == 422
    assert FILE_SAMPLE not in response.text
    response = service_client.post("/tools", json={**proposal, "document_id": FILE_SAMPLE})
    assert response.status_code == 403
    assert response.headers["X-Policy-Code"] == "document_forbidden"
    assert FILE_SAMPLE not in response.text
    assert (
        service_client.post("/tools", json={**proposal, "document_id": "RB-NOTIFY-07"}).json()[
            "code"
        ]
        == "ok"
    )


def test_references_in_support_text_do_not_choose_the_source(monkeypatch):
    class InspectContext(DemonstrationModel):
        def decide(self, context, available):
            report = json.loads(context)["обращение"]
            assert URL_SAMPLE in report and FILE_SAMPLE in report
            return super().decide(context, available)

    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _settings: InspectContext())
    with TestClient(main.app) as client:
        result = client.post(
            "/api/runs",
            json={
                "mode": "agent",
                "scenario_id": CASE,
                "support_export": {
                    "description": f"Письмо задержалось. Справка {URL_SAMPLE} {FILE_SAMPLE}"
                },
            },
        )
    result.raise_for_status()
    assert result.json()["status"] == "awaiting_approval"


@pytest.mark.parametrize(
    "origin",
    [
        "http://monitoring/path",
        "http://monitoring/?q=1",
        "file:///example",
        "http://user@monitoring",
    ],
)
def test_source_config_accepts_only_http_origin(origin):
    with pytest.raises(ValueError, match="базовый адрес"):
        configured_origin(origin)


def test_monitoring_keeps_configured_origin_and_does_not_follow_redirects():
    requests = []

    def redirect(request):
        requests.append(str(request.url))
        return httpx2.Response(302, headers={"Location": URL_SAMPLE})

    monitoring = MonitoringClient(
        "http://monitoring:8004", SecretStr("sample"), transport=httpx2.MockTransport(redirect)
    )
    assert asyncio.run(monitoring.read(CASE)).code == "source_unavailable"
    assert asyncio.run(monitoring.read(URL_SAMPLE)).code == "source_unavailable"
    assert requests == ["http://monitoring:8004/snapshots/REQ-1842"]


def test_catalog_reads_only_known_route_and_does_not_follow_redirects(monkeypatch):
    requests = []
    client = httpx2.AsyncClient

    def redirect(request):
        requests.append(str(request.url))
        return httpx2.Response(307, headers={"Location": URL_SAMPLE})

    def connect(**options):
        assert options["trust_env"] is False
        assert options["follow_redirects"] is False
        return client(transport=httpx2.MockTransport(redirect), **options)

    monkeypatch.setattr(httpx2, "AsyncClient", connect)
    catalog = RunbookCatalog("http://runbook-catalog:8005", SecretStr("sample"))
    with pytest.raises(CatalogError, match="runbook_unavailable"):
        asyncio.run(catalog.find(Action.INCIDENT))
    with pytest.raises(CatalogError, match="runbook_not_found"):
        asyncio.run(catalog.request(URL_SAMPLE))
    assert requests == ["http://runbook-catalog:8005/search/RB-NOTIFY-07"]


def test_catalog_loads_index_once_and_resolves_only_published_keys(tmp_path, monkeypatch):
    path = tmp_path / "index.json"
    path.write_text('["RB-NOTIFY-07"]', encoding="utf-8")
    monkeypatch.setenv("RUNBOOK_INDEX_PATH", str(path))
    monkeypatch.setenv("RUNBOOK_CATALOG_TOKEN", "c" * 40)
    with TestClient(runbook_catalog_service.app, headers={SERVICE_HEADER: "c" * 40}) as client:
        path.write_text("[]", encoding="utf-8")
        assert client.get("/search/RB-NOTIFY-07").status_code == 200
        response = client.get("/search/delivery-notes.txt")
        assert response.status_code == 404
        assert "delivery-notes.txt" not in response.text
    with TestClient(runbook_catalog_service.app, headers={SERVICE_HEADER: "c" * 40}) as client:
        assert client.get("/search/RB-NOTIFY-07").status_code == 404
