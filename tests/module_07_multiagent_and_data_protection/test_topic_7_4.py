import asyncio
import json
import logging
from io import StringIO

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.identity.access import SERVICE_HEADER
from dispatcher.models import gateway as model_gateway
from dispatcher.models.adapters import (
    GatewayModel,
    GigaChatModel,
    OpenAIModel,
    OutputRejected,
    QwenModel,
    choice_context,
)
from dispatcher.multiagent.information_flow import FlowData, Key, queue_data
from dispatcher.observability.tracing.diagnostics import JsonLogFormatter
from dispatcher.security.data_exfiltration.exfiltration_demo import DEMO_ADDRESS, support_sample
from dispatcher.security.tool_guardrails import tools
from dispatcher.settings import Settings
from dispatcher.workflow.comparison import restore_demo_assignment
from dispatcher.workflow.execution import ToolProposal, ToolResult
from dispatcher.workflow.scenarios import SCENARIOS, Action, Observation
from tests.approval_helpers import approve

CASE = "REQ-1842"
MESSAGE_ID = "MSG-NOTIFY-1842-001"


def test_demo_keeps_contact_in_the_private_card(
    monkeypatch, connected_executor, tmp_path, access_keys
):
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None, openai_api_key=""))
    policy = tmp_path / "on-call.json"
    restore_demo_assignment(policy)
    connected_executor.policy_path = policy
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonLogFormatter("test"))
    logger = logging.getLogger("dispatcher")
    logger.addHandler(handler)
    observer = {"Authorization": f"Bearer {access_keys.observer_token.get_secret_value()}"}
    try:
        with TestClient(main.app) as client:
            response = client.post("/api/exfiltration/runs")
            response.raise_for_status()
            assert DEMO_ADDRESS not in response.text
            report = response.json()
            run = report["run"]
            assert run["status"] == "awaiting_approval"
            assert run["support_card_available"]
            assert report["requests"]
            for body in report["requests"]:
                assert body["store"] is False
                context = json.loads(body["input"])
                assert "письма о подтверждении" in context["обращение"]
                assert "[e-mail скрыт]" in context["обращение"]
                assert context["сводка"]["число обращений"] == 18
                assert MESSAGE_ID not in body["input"]
            path = f"/api/runs/{run['id']}"
            public_run = client.get(path, headers=observer)
            public_run.raise_for_status()
            assert DEMO_ADDRESS not in public_run.text
            denied = client.get(f"{path}/support-card", headers=observer)
            assert denied.status_code == 403
            assert DEMO_ADDRESS not in denied.text
            card = client.get(f"{path}/support-card")
            assert card.headers["Cache-Control"] == "private, no-store"
            assert card.json() == support_sample().model_dump()
            assert connected_executor.count_incidents(CASE) == 0
            resolved = approve(client, path)
            resolved.raise_for_status()
            publication = resolved.json()["publication"]
            assert publication["affected_reports"] == 18
            assert "письма о подтверждении" in publication["technical_evidence"]
            assert DEMO_ADDRESS not in resolved.text
    finally:
        logger.removeHandler(handler)
    assert DEMO_ADDRESS not in stream.getvalue()
    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    egress = next(item for item in events if item.get("operation") == "egress_boundary")
    assert egress["trace_id"] == run["trace_id"]
    assert egress["symptom"] == SCENARIOS[CASE].view.title
    assert int(egress["affected_reports"]) == 18


def test_adapters_reject_extra_context_fields_before_dispatch(tmp_path):
    scenario = SCENARIOS[CASE]
    actions = {Action.INCIDENT: "Регламент"}
    context = json.loads(choice_context(scenario, [], actions, information=FlowData(), checks=[]))
    context["сводка"]["customer_email"] = DEMO_ADDRESS
    config = Settings(_env_file=None)
    for adapter in (
        OpenAIModel(config),
        GigaChatModel(config),
        QwenModel(tmp_path),
        GatewayModel(config),
    ):
        with pytest.raises(OutputRejected, match="недопустимые поля") as failure:
            adapter.decide(json.dumps(context), actions)
        assert DEMO_ADDRESS not in str(failure.value)
    assert DEMO_ADDRESS not in str(failure.value.__cause__)


def test_gateway_rejection_does_not_echo_context(monkeypatch):
    config = Settings(_env_file=None, service_token="s" * 64)
    monkeypatch.setattr(model_gateway, "settings", lambda: config)
    with TestClient(model_gateway.app) as client:
        response = client.post(
            "/decide",
            headers={SERVICE_HEADER: config.service_token.get_secret_value()},
            json={
                "provider": "openai",
                "model": "demo",
                "available": [Action.INCIDENT],
                "context": json.dumps({"customer_email": DEMO_ADDRESS}),
            },
        )
    assert response.status_code == 422
    assert DEMO_ADDRESS not in response.text
    assert "customer_email" not in response.text


def test_tool_filters_prose_and_preserves_typed_information(monkeypatch):
    information = queue_data(4800, 17, "email", (MESSAGE_ID,))

    async def sample(*_):
        return ToolResult(
            code="ok",
            message=f"Контакт {DEMO_ADDRESS}",
            observation=Observation(
                source="Мониторинг",
                observed_at="14:12",
                summary=f"Очередь растёт. Сообщение {MESSAGE_ID}.",
            ),
            information=information,
        )

    monkeypatch.setattr(tools, "execute_tool", sample)
    result = asyncio.run(
        tools.LocalTools().execute(
            ToolProposal(run_id="a" * 32, scenario_id=CASE, action=Action.STATUS)
        )
    )
    assert DEMO_ADDRESS not in result.model_dump_json()
    assert result.observation.summary == "Очередь растёт. Сообщение [идентификатор скрыт]."
    assert result.information.values()[Key.MESSAGE_IDS] == (MESSAGE_ID,)


def test_log_fields_are_allowlisted_and_text_is_filtered():
    record = logging.makeLogRecord(
        {
            "msg": f"Контакт {DEMO_ADDRESS}",
            "trace_fields": {
                "operation": "egress_boundary",
                "payload": {"export": DEMO_ADDRESS},
                "symptom": f"Задержка {MESSAGE_ID}",
                "affected_reports": 18,
            },
        }
    )
    formatted = JsonLogFormatter("test").format(record)
    assert DEMO_ADDRESS not in formatted
    assert MESSAGE_ID not in formatted
    assert "payload" not in formatted
    assert json.loads(formatted)["affected_reports"] == 18
