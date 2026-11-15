import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from dispatcher import main
from dispatcher.multiagent.hierarchy.delegation import RunbookOrder
from dispatcher.multiagent.information_flow import (
    DataField,
    FlowConflict,
    FlowData,
    Key,
    Level,
    Party,
    merge,
    queue_data,
)
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from dispatcher.workflow.client import ExecutorClient
from dispatcher.workflow.comparison import restore_demo_assignment
from tests.approval_helpers import approve

MESSAGE = "MSG-NOTIFY-1842-001"
AGGREGATES = {"queue_size": 4800, "oldest_minutes": 17, "channel": "email"}


@pytest.fixture
def client(monkeypatch, tmp_path, connected_executor):
    config = Settings(_env_file=None, model_gateway_url="", openai_api_key="test")
    monkeypatch.setattr(main, "settings", lambda: config)
    policy = tmp_path / "on-call.json"
    restore_demo_assignment(policy)
    connected_executor.policy_path = policy
    with TestClient(main.app) as http:
        yield http


@pytest.fixture
def observer(access_keys):
    return {"Authorization": f"Bearer {access_keys.observer_token.get_secret_value()}"}


def test_merge_keeps_strictest_label_and_denies_conflicting_value():
    baseline = queue_data(4800, 17, "email", (MESSAGE,))
    restricted = FlowData(
        fields=(DataField(key=Key.QUEUE_SIZE, level=Level.DUTY_ONLY, value=4800),)
    )
    packet = merge(baseline, restricted)
    assert packet.permitted(Party.MASTER, Party.RUNBOOK).values() == {
        "oldest_minutes": 17,
        "channel": "email",
    }
    assert packet.permitted(Party.MASTER, Party.DUTY).values()["queue_size"] == 4800
    assert not packet.permitted(Party.MODEL, Party.DUTY).fields
    conflicting = FlowData(fields=(DataField(key=Key.QUEUE_SIZE, level=Level.SHARED, value=4799),))
    with pytest.raises(FlowConflict):
        merge(packet, conflicting)
    with pytest.raises(ValidationError):
        DataField(key=Key.MESSAGE_IDS, level=Level.SHARED, value=(MESSAGE,))


def test_hierarchy_sends_only_aggregates_and_projects_the_saved_run(
    client, observer, monkeypatch, connected_executor
):
    sent = []
    perform = ExecutorClient.perform_delegation

    async def inspect(self, order):
        if isinstance(order, RunbookOrder):
            sent.append(order.queue_context.values())
            assert MESSAGE not in order.model_dump_json()
        return await perform(self, order)

    monkeypatch.setattr(ExecutorClient, "perform_delegation", inspect)
    response = client.post("/api/hierarchy/runs", json={}, headers=observer)
    assert response.status_code == 200
    assert MESSAGE not in response.text
    frame = json.loads(response.text.splitlines()[-1])
    assert frame["kind"] == "result"
    assert sent == [AGGREGATES]
    run = frame["run"]
    assert run["status"] == "awaiting_approval"
    assert list(run["flow_checks"][-1]["blocked"]) == ["message_ids"]
    assert run["flow_checks"][0]["destination"] == "runbook"
    path = f"/api/runs/{run['id']}"
    restricted = client.get(path, headers=observer)
    assert restricted.headers["cache-control"] == "private, no-store"
    assert MESSAGE not in restricted.text
    visible = client.get(path).json()
    assert {field["key"]: field["value"] for field in visible["information"]["fields"]} == {
        **AGGREGATES,
        "runbook_id": "RB-NOTIFY-07",
        "message_ids": ["MSG-NOTIFY-1842-001", "MSG-NOTIFY-1842-002"],
    }
    identifiers = connected_executor.get(run["id"]).information
    assert (
        next(field.level for field in identifiers.fields if field.key == Key.MESSAGE_IDS)
        == Level.DUTY_ONLY
    )
    registered = approve(client, path).json()
    assert registered["incident_id"] == "INC-3071"
    assert MESSAGE not in json.dumps(registered["publication"])


def test_model_boundary_builds_input_from_permitted_fields(client, monkeypatch):
    calls = []

    class InspectModel(DemonstrationModel):
        def decide(self, context, available):
            calls.append(json.loads(context))
            assert MESSAGE not in context
            return super().decide(context, available)

    monkeypatch.setattr(main, "create_model", lambda _: InspectModel())
    response = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"})
    assert response.status_code == 200
    assert calls
    assert all(
        next(obs for obs in item["наблюдения"] if obs["действие"] == "get_service_status")[
            "телеметрия очереди"
        ]
        == AGGREGATES
        for item in calls
    )
    assert MESSAGE in response.text
    assert any(
        check["destination"] == "model" and check["blocked"] == ["message_ids"]
        for check in response.json()["flow_checks"]
    )


def test_runbook_ingress_rejects_restricted_fields_without_echo(service_client):
    response = service_client.post(
        "/delegation/tasks",
        json={
            "role": "runbook",
            "task_id": "a" * 32,
            "run_id": "b" * 32,
            "runbook_id": "RB-NOTIFY-07",
            "queue_context": queue_data(4800, 17, "email", (MESSAGE,)).model_dump(mode="json"),
        },
    )
    assert response.status_code == 422
    assert MESSAGE not in response.text


def test_peer_exchange_keeps_decision_with_recipient_specific_view(client, observer):
    response = client.post(
        "/api/coordination/runs", json={"mode": "peer_to_peer"}, headers=observer
    )
    assert response.status_code == 200
    run = response.json()
    assert run["status"] == "awaiting_approval"
    assert any(
        check["source"] == "diagnostic"
        and check["destination"] == "runbook"
        and check["blocked"] == ["message_ids"]
        for check in run["flow_checks"]
    )
    assert MESSAGE not in response.text
    assert MESSAGE in client.get(f"/api/runs/{run['id']}").text


def test_comparison_nested_runs_use_the_same_view(client, observer):
    response = client.post("/api/outcome-comparison", headers=observer)
    assert response.status_code == 200
    assert MESSAGE not in response.text
