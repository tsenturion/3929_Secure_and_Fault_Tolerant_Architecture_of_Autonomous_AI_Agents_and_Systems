import json

import httpx2
from fastapi.testclient import TestClient

from dispatcher.identity.access import SERVICE_HEADER
from dispatcher.models import gateway as model_gateway
from dispatcher.models.adapters import GatewayModel, choice_context
from dispatcher.multiagent.information_flow import FlowData
from dispatcher.settings import Settings
from dispatcher.workflow.scenarios import SCENARIOS, Action


def test_gateway_checks_service_key_and_limits_request_fields(monkeypatch):
    key = "s" * 64
    monkeypatch.setattr(
        model_gateway,
        "settings",
        lambda: Settings(
            _env_file=None,
            service_token=key,
            openai_api_key="",
        ),
    )
    body = {"provider": "openai", "model": "gpt-4.1-mini"}
    with TestClient(model_gateway.app) as client:
        assert client.post("/status", json=body).status_code == 401
        headers = {SERVICE_HEADER: key}
        response = client.post("/status", json=body, headers=headers)
        response.raise_for_status()
        assert "OPENAI_API_KEY" in response.json()["problem"]
        assert (
            client.post(
                "/status", json={**body, "url": "http://example.invalid"}, headers=headers
            ).status_code
            == 422
        )


def test_agent_sends_context_to_gateway_without_cloud_key(monkeypatch):
    settings = Settings(
        _env_file=None,
        model_gateway_url="http://model-gateway:8002",
        service_token="s" * 64,
        openai_api_key="",
    )

    def handle(request):
        assert str(request.url) == "http://model-gateway:8002/decide"
        assert request.headers[SERVICE_HEADER] == settings.service_token.get_secret_value()
        assert "authorization" not in request.headers
        context = json.loads(json.loads(request.content)["context"])
        assert context["сводка"]["число обращений"] == 18
        return httpx2.Response(200, json={"action": Action.INCIDENT, "reason": "Нужен регламент."})

    client = httpx2.Client(transport=httpx2.MockTransport(handle))
    monkeypatch.setattr("dispatcher.models.adapters.httpx2.Client", lambda **_: client)
    actions = {Action.INCIDENT: "Регламент"}
    context = choice_context(SCENARIOS["REQ-1842"], [], actions, information=FlowData(), checks=[])
    decision = GatewayModel(settings).decide(context, actions)
    assert decision.action == Action.INCIDENT
