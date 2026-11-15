import json

import pytest
from fastapi.testclient import TestClient

from dispatcher import executor, main
from dispatcher.multiagent.coordination.coordination_protocol import (
    DiagnosticEvidence,
    Inbox,
    ProtocolError,
)
from dispatcher.security.source_access.runbook_catalog import CatalogError
from dispatcher.security.tool_guardrails.tools import LocalTools
from dispatcher.workflow.comparison import restore_demo_assignment
from dispatcher.workflow.execution import ToolResult
from tests.approval_helpers import commit_approval, issue_approval

URL = "/api/coordination/runs"


@pytest.fixture
def client(connected_executor, tmp_path):
    policy = tmp_path / "on-call.json"
    restore_demo_assignment(policy)
    connected_executor.policy_path = policy
    with TestClient(main.app) as http:
        yield http


def start(client, mode, **options):
    response = client.post(URL, json={"mode": mode}, **options)
    response.raise_for_status()
    return response.json()


def test_two_topologies_filter_same_delivery_and_save_one_incident(client, connected_executor):
    central = start(client, "centralized")
    peer = start(client, "peer_to_peer")
    assert central["recommendation"] == peer["recommendation"]
    assert central["recommendation"]["priority"] == "P2"
    assert connected_executor.count_incidents("REQ-1842") == 0
    for run, receiver, assemblers in (
        (central, "coordinator", {"coordinator"}),
        (peer, "runbook", {"diagnostic", "runbook"}),
    ):
        assert run["status"] == "awaiting_approval"
        saved = client.get(f"/api/runs/{run['id']}").json()
        assert saved["coordination"] == run["coordination"]
        events = saved["coordination"]["events"]
        duplicates = [event for event in events if event["code"] == "duplicate"]
        assert [event["actor"] for event in duplicates] == [receiver]
        duplicate = duplicates[0]
        assert duplicate["peer"] == "diagnostic"
        assert duplicate["evidence_count"] == 1
        sends = [
            event
            for event in events
            if event["code"] == "sent" and event["message_id"] == duplicate["message_id"]
        ]
        assert len(sends) == 2
        assert {event["actor"] for event in events if event["code"] == "assembled"} == assemblers
        assert all(event["evidence_count"] == 2 for event in events if event["code"] == "assembled")
        assert len(run["steps"]) == 3

    with connected_executor.connection() as db:
        events = [
            json.loads(payload) for (payload,) in db.execute("SELECT payload FROM audit_events")
        ]
    assert sum(event["action"] == "tool_call" for event in events) == 6

    paths = [f"/api/runs/{run['id']}" for run in (central, peer)]
    grants = [issue_approval(client, path).json() for path in paths]
    results = [commit_approval(client, path, grant) for path, grant in zip(paths, grants)]
    assert [result.status_code for result in results] == [200, 200]
    assert {result.json()["incident_id"] for result in results} == {"INC-3071"}
    assert connected_executor.count_incidents("REQ-1842") == 1


def test_inbox_rejects_other_runs_and_conflicting_redelivery():
    refused = ToolResult(code="timeout", message="Источник не ответил вовремя.")
    envelope = DiagnosticEvidence(
        run_id="a" * 32,
        message_id="b" * 32,
        scenario_id="REQ-1842",
        snapshot=refused,
        deployment=refused,
    )
    inbox = Inbox(envelope.run_id, envelope.scenario_id)
    assert inbox.accept(envelope)
    assert not inbox.accept(DiagnosticEvidence.model_validate_json(envelope.model_dump_json()))
    for change in (
        {"run_id": "c" * 32},
        {"scenario_id": "REQ-1843"},
        {"message_id": "c" * 32},
        {"deployment": ToolResult(code="source_unavailable", message="Источник недоступен.")},
    ):
        with pytest.raises(ProtocolError):
            inbox.accept(envelope.model_copy(update=change))
    assert list(inbox.messages.values()) == [envelope]


@pytest.mark.parametrize("mode", ["centralized", "peer_to_peer"])
def test_unavailable_runbook_preserves_diagnosis_and_blocks_draft(
    client, mode, connected_executor, monkeypatch
):
    class UnavailableCatalog:
        async def find(self, action):
            raise CatalogError("runbook_not_found")

    real = executor.execution_tools
    monkeypatch.setattr(
        executor,
        "execution_tools",
        lambda **options: LocalTools(real(**options).monitoring, UnavailableCatalog()),
    )
    run = start(client, mode)
    assert run["status"] == "needs_review"
    assert run["recommendation"]["priority"] is None
    assert any(
        step["observation"] and step["observation"]["kind"] == "monitoring" for step in run["steps"]
    )
    path = f"/api/runs/{run['id']}"
    assert issue_approval(client, path).status_code == 409
    assert connected_executor.count_incidents("REQ-1842") == 0


def test_observer_can_compare_but_cannot_register(client, access_keys):
    observer = {"Authorization": f"Bearer {access_keys.observer_token.get_secret_value()}"}
    run = start(client, "peer_to_peer", headers=observer)
    assert issue_approval(client, f"/api/runs/{run['id']}", headers=observer).status_code == 403
