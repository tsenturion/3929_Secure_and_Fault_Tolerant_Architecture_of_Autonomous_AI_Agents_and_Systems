import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta
from io import StringIO

import httpx2
import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.observability.tracing import trace_view
from dispatcher.observability.tracing.diagnostics import JsonLogFormatter
from dispatcher.observability.tracing.telemetry import (
    HEADER,
    TraceContext,
    current,
    receive,
    span,
    trace_headers,
)
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from dispatcher.workflow.lifecycle import Phase
from tests.approval_helpers import commit_approval, issue_approval


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    with TestClient(main.app) as client:
        yield client


def start(client, *, headers=None):
    run = client.post(
        "/api/runs",
        json={"scenario_id": "REQ-1842", "mode": "agent"},
        headers=headers,
    )
    run.raise_for_status()
    return run.json()


def test_traces_cross_agent_executor_and_resume_after_confirmation(client):
    output = StringIO()
    log = logging.StreamHandler(output)
    log.setFormatter(JsonLogFormatter("test"))
    logger = logging.getLogger("dispatcher")
    logger.addHandler(log)
    try:
        fake_trace = "a" * 32
        run = start(client, headers={HEADER: f"00-{fake_trace}-{'b' * 16}-01"})
        path = f"/api/runs/{run['id']}"
        approval = issue_approval(client, path).json()
        result = commit_approval(client, path, approval)
        result.raise_for_status()
    finally:
        logger.removeHandler(log)
    assert run["trace_id"] != fake_trace
    assert result.json()["trace_id"] == run["trace_id"]
    assert approval["token"] not in output.getvalue()
    lines = [json.loads(line) for line in output.getvalue().splitlines()]
    records = [item for item in lines if item.get("trace_id") == run["trace_id"]]
    assert records
    assert all(item["run_id"] == run["id"] for item in records)
    spans = [item for item in records if item.get("kind") == "span"]
    root = next(item for item in spans if item["operation"] == "triage")
    assert root["parent_span_id"] is None
    tools = [item for item in spans if item["operation"] == "tool_execute"]
    calls = {item["span_id"] for item in spans if item["operation"] == "tool_request"}
    assert len(tools) == 3
    assert all(item["parent_span_id"] in calls for item in tools)
    assert any(item["operation"] == "model_decide" for item in spans)
    resumed = [
        item for item in spans if item["operation"] in {"issue_approval", "resolve_approval"}
    ]
    assert len(resumed) == 2
    assert all(item["parent_span_id"] == root["span_id"] for item in resumed)
    assert any(
        item.get("operation") == "registration" and item["result"] == "created" for item in records
    )


def test_trace_headers_reject_malformed_context_and_reset():
    context = TraceContext("a" * 32, "b" * 32, "REQ-1842")
    with span("triage", parent=context):
        headers = trace_headers()
        assert receive(headers) == current.get()
        assert receive({**headers, HEADER: f"00-{'0' * 32}-{'a' * 16}-01"}) is None
        assert receive({**headers, "X-Trace-Case": "customer@example.invalid"}) is None
        with pytest.raises(TimeoutError), span("model_decide"):
            raise TimeoutError
        assert current.get().trace_id == context.trace_id
    assert not trace_headers()


def test_query_filters_by_authorized_run_and_denies_without_identity(client, monkeypatch):
    run = start(client)
    called = []

    async def read(record, url):
        called.append(record.id)
        return trace_view.summarize(record, [], "disabled", datetime.now(UTC))

    monkeypatch.setattr(main, "read_trace", read)
    endpoint = f"/api/runs/{run['id']}/trace"
    bad = client.get(endpoint, headers={"Authorization": "Bearer invalid"})
    assert bad.status_code == 401
    assert not called
    allowed = client.get(endpoint)
    assert allowed.status_code == 200
    assert called == [run["id"]]


def test_central_trace_separates_automation_and_wait_and_discards_foreign_lines(
    client, connected_executor, monkeypatch
):
    metadata = start(client)
    run = connected_executor.get(metadata["id"])
    began = datetime.now(UTC) - timedelta(minutes=10)
    ready = began + timedelta(milliseconds=1800)
    waiting_end = ready + timedelta(minutes=7)
    run.lifecycle.events[0].at = began
    assert run.lifecycle.events[-1].phase == Phase.AWAITING_APPROVAL
    run.lifecycle.events[-1].at = ready
    base = {
        "timestamp": ready.isoformat(),
        "service": "dispatcher",
        "kind": "span",
        "result": "ok",
        "span_id": run.trace_span_id,
        "trace_id": run.trace_id,
        "run_id": run.id,
        "scenario_id": run.scenario_id,
    }
    triage = {**base, "operation": "triage", "duration_ms": 1800, "started_at": began.isoformat()}
    approval = {**base, "operation": "issue_approval", "started_at": waiting_end.isoformat()}
    unrelated = {**triage, "trace_id": "e" * 32}
    async_client = httpx2.AsyncClient

    def query(request):
        assert request.url.path == "/loki/api/v1/query_range"
        assert f'trace_id="{run.trace_id}"' in request.url.params["query"]
        return httpx2.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "resultType": "streams",
                    "result": [
                        {
                            "values": [
                                ["1", json.dumps(item)] for item in (approval, unrelated, triage)
                            ]
                        }
                    ],
                },
            },
        )

    def connect(**kwargs):
        return async_client(transport=httpx2.MockTransport(query), **kwargs)

    monkeypatch.setattr(trace_view.httpx2, "AsyncClient", connect)
    result = asyncio.run(trace_view.read_trace(run, "http://loki:3100"))
    assert result.status == "available"
    assert result.automated_ms == 1800
    assert result.operator_wait_ms == 420_000
    assert [item.operation for item in result.items] == ["triage", "issue_approval"]
