import asyncio
import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from dispatcher import executor, main
from dispatcher.multiagent.coordination.coordination_protocol import RunbookEvidence
from dispatcher.multiagent.hierarchy.delegated_workers import DelegatedReader
from dispatcher.multiagent.hierarchy.delegation import DiagnosticOrder, RunbookOrder, TaskStage
from dispatcher.multiagent.hierarchy.master_agent import TaskFailure, collect
from dispatcher.workflow.comparison import restore_demo_assignment
from dispatcher.workflow.execution import ToolResult
from dispatcher.workflow.scenarios import Action
from tests.approval_helpers import approve, issue_approval

URL = "/api/hierarchy/runs"


@pytest.fixture
def client(connected_executor, tmp_path):
    policy = tmp_path / "on-call.json"
    restore_demo_assignment(policy)
    connected_executor.policy_path = policy
    with TestClient(main.app) as http:
        yield http


def frames(client, *, slow=False):
    response = client.post(URL, json={"slow_catalog": slow})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    return [json.loads(line) for line in response.iter_lines() if line]


def test_master_delegates_checks_sources_and_submits_normal_draft(client, connected_executor):
    reports = frames(client)
    progress = [item["event"] for item in reports[:-1]]
    assert [item["stage"] for item in progress] == [
        "delegated",
        "reported",
        "delegated",
        "reported",
    ]
    diagnose, snapshot, assign, runbook = progress
    assert diagnose["task_id"] == snapshot["task_id"]
    assert assign["task_id"] == runbook["task_id"]
    assert assign["task_id"] != diagnose["task_id"]
    assert snapshot["oldest_minutes"] == 17
    assert [source["action"] for source in snapshot["sources"]] == [
        Action.STATUS,
        Action.DEPLOYMENT,
    ]
    assert runbook["sources"][0]["label"].startswith("RB-NOTIFY-07")
    assert runbook["sources"][0]["version"] == "действующая версия"
    run = reports[-1]["run"]
    assert run["status"] == "awaiting_approval"
    assert run["recommendation"]["priority"] == "P2"
    assert run["delegation"]["events"][-1]["stage"] == "ready"
    path = f"/api/runs/{run['id']}"
    assert client.get(path).json()["delegation"] == run["delegation"]
    assert connected_executor.count_incidents("REQ-1842") == 0
    assert approve(client, path).json()["incident_id"] == "INC-3071"
    assert connected_executor.count_incidents("REQ-1842") == 1


def test_late_catalog_preserves_diagnosis_and_leaves_priority_unverified(
    client, connected_executor
):
    reports = frames(client, slow=True)
    assert reports[1]["event"]["oldest_minutes"] == 17
    assert "Приоритет ещё не проверен" in reports[2]["event"]["detail"]
    assert reports[3]["event"]["stage"] == "timeout"
    run = reports[-1]["run"]
    assert run["status"] == "needs_review"
    assert "Приоритет ещё не проверен" in run["error"]
    assert [step["action"] for step in run["steps"]] == [Action.STATUS, Action.DEPLOYMENT]
    assert run["recommendation"]["priority"] is None
    path = f"/api/runs/{run['id']}"
    assert client.get(path).json()["status"] == "needs_review"
    assert issue_approval(client, path).status_code == 409
    assert connected_executor.count_incidents("REQ-1842") == 0


def test_stale_diagnosis_stops_delegation_before_catalog(client, monkeypatch):
    original = executor.execution_tools()

    class StaleTools:
        async def execute(self, proposal):
            assert proposal.action != Action.INCIDENT
            result = await original.execute(proposal)
            if proposal.action == Action.STATUS:
                result.risk.snapshot_age_minutes = 12
            return result

    monkeypatch.setattr(executor, "execution_tools", lambda: StaleTools())
    reports = frames(client)
    assert [item["event"]["stage"] for item in reports[:-1]] == ["delegated", "reported"]
    assert reports[-1]["run"]["status"] == "needs_review"
    assert "Снимок очереди устарел" in reports[-1]["run"]["error"]


def test_role_bound_worker_rejects_even_other_read_tools():
    order = RunbookOrder(task_id="a" * 32, run_id="b" * 32, runbook_id="RB-NOTIFY-07")
    requested = []

    async def execute(proposal):
        requested.append(proposal.action)
        return ToolResult(code="timeout", message="Учебный таймаут.")

    async def check():
        reader = DelegatedReader(order, execute)
        with pytest.raises(HTTPException) as error:
            await reader.read(Action.STATUS)
        assert error.value.status_code == 403
        assert error.value.headers["X-Policy-Code"] == "delegation_scope_denied"
        await reader.read(Action.INCIDENT)

    asyncio.run(check())
    assert requested == [Action.INCIDENT]


def test_worker_contract_accepts_only_necessary_fields(service_client):
    payload = {
        "role": "runbook",
        "task_id": "a" * 32,
        "run_id": "b" * 32,
        "scenario_id": "REQ-1842",
        "runbook_id": "RB-NOTIFY-07",
    }
    endpoint = "/delegation/tasks"
    for change in (
        {"actions": ["get_service_status"]},
        {"runbook_id": "RB-NOTIFY-03"},
        {"report": "Описание обращения"},
    ):
        assert service_client.post(endpoint, json={**payload, **change}).status_code == 422
    result = service_client.post(endpoint, json=payload)
    assert result.status_code == 200
    assert result.json()["message_id"] == payload["task_id"]
    assert result.json()["runbook"]["observation"]["source"].startswith("RB-NOTIFY-07")


def test_master_rejects_response_from_other_task_and_role():
    order = DiagnosticOrder(task_id="a" * 32, run_id="b" * 32)

    async def dispatch(task):
        return RunbookEvidence(
            message_id=task.task_id,
            run_id=task.run_id,
            scenario_id=task.scenario_id,
            runbook=ToolResult(code="timeout", message="Учебный таймаут."),
        )

    with pytest.raises(TaskFailure) as error:
        asyncio.run(collect(dispatch, order, 1))
    assert error.value.stage == TaskStage.FAILED
