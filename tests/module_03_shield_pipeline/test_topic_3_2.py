import json

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.models.adapters import Decision
from dispatcher.settings import Settings
from dispatcher.workflow.scenarios import Action
from tests.approval_helpers import issue_approval

EMAIL = "buyer-1842@example.invalid"
RUN = {"scenario_id": "REQ-1842", "mode": "agent"}


@pytest.mark.parametrize(
    "export",
    [
        {"description": "a" * 1601},
        {"description": " " * 1700 + "text"},
        {"description": f"{EMAIL}\x00"},
        {"description": 123},
        {"description": "Письмо не пришло", "customer_email": "bad"},
        {"description": "Письмо не пришло", "customer_email": EMAIL, "extra": EMAIL},
    ],
)
def test_invalid_input_is_rejected_without_echo(export, monkeypatch):
    def unexpected_model(_):
        pytest.fail("Некорректный ввод не должен вызывать модель.")

    monkeypatch.setattr(main, "create_model", unexpected_model)
    with TestClient(main.app) as client:
        response = client.post("/api/runs", json={**RUN, "support_export": export})
    assert response.status_code == 422
    assert response.json()["code"] == "invalid_run_input"
    assert EMAIL not in response.text
    assert "input" not in response.json()


def test_context_and_display_use_filtered_text(monkeypatch, connected_executor):
    contexts = []

    class Model:
        def decide(self, context, available):
            contexts.append(json.loads(context))
            action = Action.INCIDENT if Action.INCIDENT in available else Action.DEPLOYMENT
            return Decision.model_construct(action=action, reason=f"Объяснение {EMAIL}\x04")

    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: Model())
    with TestClient(main.app) as client:
        response = client.post(
            "/api/runs",
            json={
                **RUN,
                "support_export": {
                    "description": f"Нет письма. Контакт: {EMAIL}.",
                    "customer_email": EMAIL,
                },
            },
        )
        response.raise_for_status()
        run = response.json()
        assert run["status"] == "awaiting_approval"
        assert EMAIL not in response.text
        assert "\\u0004" not in response.text
        assert "[e-mail скрыт]" in run["steps"][1]["reason"]
        assert "[e-mail скрыт]" in run["lifecycle"]["events"][0]["detail"]
        assert [item["code"] for item in run["filter_checks"]] == [
            "input_redacted",
            "decision_validated",
        ]
        assert client.get(f"/api/runs/{run['id']}").json() == run
    assert len(contexts) == 2
    for context in contexts:
        assert "[e-mail скрыт]" in context["обращение"]
        assert context["сводка"] == {"число обращений": 18, "начало наблюдения": "14:02"}
        assert EMAIL not in json.dumps(context)
    assert connected_executor.count_incidents("REQ-1842") == 0


def test_invalid_output_is_blocked_before_next_tool(monkeypatch, connected_executor):
    def unexpected_model(_):
        pytest.fail("Учебная проверка не должна вызывать внешнюю модель.")

    monkeypatch.setattr(main, "create_model", unexpected_model)
    with TestClient(main.app) as client:
        response = client.post(
            "/api/runs",
            json={
                **RUN,
                "fault": "invalid_model_output",
                "support_export": {"description": f"Нет письма. Контакт: {EMAIL}."},
            },
        )
        response.raise_for_status()
        run = response.json()
        assert run["provider"] is None
        assert run["status"] == "needs_review"
        assert run["review_required"]
        assert [step["action"] for step in run["steps"]] == ["get_service_status"]
        assert run["filter_checks"][-1]["code"] == "invalid_model_output"
        assert EMAIL not in response.text
        path = f"/api/runs/{run['id']}/resolution"
        assert issue_approval(client, f"/api/runs/{run['id']}").status_code == 409
        assert (
            client.post(path, json={"decision": "take_over"}).json()["status"] == "manual_handoff"
        )
    assert connected_executor.count_incidents("REQ-1842") == 0
