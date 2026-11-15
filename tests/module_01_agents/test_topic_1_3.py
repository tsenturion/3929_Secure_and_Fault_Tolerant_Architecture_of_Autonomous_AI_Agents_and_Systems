import json

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.security.agent_threats.boundaries import Threat
from dispatcher.security.agent_threats.demonstrations import (
    DemonstrationModel,
    case_scenario,
    source_candidate,
)
from dispatcher.settings import Settings
from dispatcher.workflow.scenarios import SCENARIOS, Action
from tests.approval_helpers import issue_approval


@pytest.mark.parametrize("threat", list(Threat))
def test_threat_checks_at_source_action_and_model_boundaries(
    threat, monkeypatch, connected_executor
):
    settings = Settings(_env_file=None)
    monkeypatch.setattr(main, "settings", lambda: settings)
    contexts = []

    class ObservedModel(DemonstrationModel):
        def decide(self, context, available):
            contexts.append(context)
            return super().decide(context, available)

    monkeypatch.setattr(main, "DemonstrationModel", ObservedModel)

    def unexpected_model(_):
        pytest.fail("Защитный прогон должен работать без внешней модели.")

    monkeypatch.setattr(main, "create_model", unexpected_model)
    with TestClient(main.app) as client:
        assert len(client.get("/api/threat-cases").json()) == 4
        response = client.post(f"/api/threat-cases/{threat}/runs")
        response.raise_for_status()
        run = response.json()
        assert run["threat"] == threat
        assert [decision["threat"] for decision in run["boundary_decisions"]] == [threat]
        assert run["incident_id"] is None
        assert client.get(f"/api/runs/{run['id']}").json() == run
        assert client.get("/api/runs?scenario_id=REQ-1842").json()[0]["threat"] == threat
        resolution = issue_approval(client, f"/api/runs/{run['id']}")
        assert resolution.status_code == 409

    if threat == Threat.MISUSE:
        assert run["status"] == "needs_review"
        assert [step["action"] for step in run["steps"]] == [Action.STATUS]
    else:
        assert run["status"] == "completed"
        assert run["recommendation"]["priority"] == "P2"
        assert "RB-NOTIFY-07" in json.dumps(run["steps"], ensure_ascii=False)

    assert contexts
    captured_context = "\n".join(contexts)
    candidate = source_candidate(threat, Action.INCIDENT)
    if candidate is not None:
        assert "RB-NOTIFY-07" in contexts[-1]
        assert candidate.summary not in captured_context
        assert candidate.summary not in response.text
    if threat == Threat.EXFILTRATION:
        address = case_scenario(threat, SCENARIOS["REQ-1842"]).customer_email
        assert address is not None
        assert address not in captured_context
        assert address not in response.text
        assert set(json.loads(contexts[0])) == {
            "обращение",
            "сводка",
            "наблюдения",
            "доступные действия",
        }

    with connected_executor.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM incidents").fetchone() == (0,)
