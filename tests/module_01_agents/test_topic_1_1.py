import json

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.models.adapters import Decision, ModelError
from dispatcher.settings import Settings
from dispatcher.workflow.scenarios import Action

SCENARIOS = [
    ("REQ-1842", [Action.INCIDENT, Action.DEPLOYMENT], "incident"),
    ("REQ-1843", [Action.INDIVIDUAL], "individual"),
]


@pytest.mark.parametrize(("scenario_id", "choices", "expected"), SCENARIOS)
def test_compare_routes(monkeypatch, scenario_id, choices, expected):
    decisions = iter(choices)

    class TestModel:
        def decide(self, context, available):
            observations = json.loads(context)["наблюдения"]
            assert observations[0]["действие"] == Action.STATUS
            assert Action.STATUS not in available
            action = next(decisions)
            assert action in available
            return Decision(action=action, reason="Выбран источник по показателям очереди.")

    config = Settings(_env_file=None)
    monkeypatch.setattr(main, "settings", lambda: config)
    monkeypatch.setattr(main, "create_model", lambda settings: TestModel())
    with TestClient(main.app) as client:
        fixed = client.post("/api/runs", json={"scenario_id": scenario_id, "mode": "fixed"})
        agent = client.post("/api/runs", json={"scenario_id": scenario_id, "mode": "agent"})
    fixed.raise_for_status()
    agent.raise_for_status()
    assert fixed.json()["recommendation"]["category"] == expected
    assert agent.json()["recommendation"]["category"] == expected
    assert [step["action"] for step in fixed.json()["steps"]] == [
        Action.STATUS,
        Action.DEPLOYMENT,
        Action.INDIVIDUAL,
        Action.INCIDENT,
        Action.FINISH,
    ]
    assert [step["action"] for step in agent.json()["steps"]] == [
        Action.STATUS,
        *choices,
        Action.FINISH,
    ]
    assert [step["selected_by"] for step in agent.json()["steps"]] == [
        "rule",
        *(["model"] * len(choices)),
        "rule",
    ]


@pytest.mark.parametrize("failed_response", [Action.STATUS, None])
def test_model_failure_preserves_observation(monkeypatch, failed_response):
    class TestModel:
        def decide(self, context, available):
            if failed_response is None:
                raise ModelError("Не удалось получить ответ модели.")
            return Decision(action=failed_response, reason="Повторное чтение.")

    config = Settings(_env_file=None)
    monkeypatch.setattr(main, "settings", lambda: config)
    monkeypatch.setattr(main, "create_model", lambda settings: TestModel())
    with TestClient(main.app) as client:
        response = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"})
    response.raise_for_status()
    run = response.json()
    assert run["recommendation"]["category"] == "manual"
    assert run["error"]
    assert [step["action"] for step in run["steps"]] == [Action.STATUS]
