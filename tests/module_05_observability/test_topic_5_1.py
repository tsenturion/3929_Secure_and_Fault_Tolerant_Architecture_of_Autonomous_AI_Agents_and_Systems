import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.identity.access import Caller, Operator
from dispatcher.observability.tamper_evident_audit import audit
from dispatcher.observability.tamper_evident_audit.audit_witness import capture
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from dispatcher.workflow.execution import ToolProposal
from tests.approval_helpers import commit_approval, issue_approval


@pytest.fixture
def audit_app(monkeypatch, connected_executor, access_keys, tmp_path):
    now = datetime(2026, 11, 15, 9, 12, tzinfo=UTC)
    connected_executor.clock = lambda: now
    access_keys.audit_checkpoint_db = tmp_path / "witness.sqlite3"
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    with TestClient(main.app) as client:
        yield client, now, access_keys.audit_checkpoint_db


def draft(client):
    run = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"})
    run.raise_for_status()
    return f"/api/runs/{run.json()['id']}"


def test_real_incident_history_checkpoint_and_pending_suffix(audit_app, connected_executor):
    client, now, trusted = audit_app
    path = draft(client)
    grant = issue_approval(client, path).json()
    result = commit_approval(client, path, grant)
    assert result.status_code == 200
    endpoint = "/api/audit?scenario_id=REQ-1842"
    unanchored = client.get(endpoint).json()
    assert unanchored["checks"][0]["code"] == "unanchored"
    assert client.get("/api/audit?scenario_id=REQ-9999").status_code == 403

    capture(connected_executor.path, trusted, now)
    verified = client.get(endpoint)
    verified.raise_for_status()
    history = verified.json()
    assert history["checks"][0]["code"] == "verified"
    records = list(reversed(history["events"]))
    assert [record["event"]["action"] for record in records] == [
        "tool_call",
        "tool_call",
        "tool_call",
        "run_saved",
        "approve_draft",
        "register_incident",
    ]
    assert records[0]["previous_hash"] == audit.GENESIS
    for previous, current in pairwise(records):
        assert previous["event_hash"] == current["previous_hash"]
    approval = records[-2]["event"]
    assert approval["operator"] == "duty_operator"
    assert approval["priority"] == "P2"
    assert approval["approval_id"] == grant["approval_id"]
    assert records[-1]["event"]["result"] == "created"
    assert records[-1]["event"]["incident_id"] == "INC-3071"
    assert grant["token"] not in verified.text
    assert grant["idempotency_key"] not in verified.text

    assert commit_approval(client, path, grant).status_code == 200
    pending = client.get(endpoint).json()
    assert pending["checks"][0]["code"] == "pending_checkpoint"
    assert pending["checks"][0]["anchored_through"] == len(records)
    assert pending["events"][0]["event"]["decision"] == "replay"
    capture(connected_executor.path, trusted, now)
    assert client.get(endpoint).json()["checks"][0]["code"] == "verified"


@pytest.mark.parametrize("rewrite", [True, False])
def test_witness_preserves_anchor_after_rewritten_or_truncated_log(
    rewrite, audit_app, connected_executor
):
    client, now, trusted = audit_app
    path = draft(client)
    result = commit_approval(client, path, issue_approval(client, path).json())
    assert result.status_code == 200
    capture(connected_executor.path, trusted, now)
    with closing(audit.readonly(trusted)) as db:
        before = audit.checkpoints(db, audit.cutoff(now))
    partition = ("REQ-1842", now.date().isoformat())
    with connected_executor.connection() as db:
        if rewrite:
            rows = db.execute(
                """SELECT sequence, payload FROM audit_events
                   WHERE scenario_id = ? AND day = ? ORDER BY sequence""",
                partition,
            ).fetchall()
            previous = audit.GENESIS
            for sequence, payload in rows:
                event = audit.AuditEvent.model_validate_json(payload)
                payload = event.model_copy(
                    update={"at": event.at + timedelta(minutes=1)}
                ).model_dump_json(exclude_none=True)
                event_hash = audit.digest(*partition, sequence, previous, payload)
                db.execute(
                    """UPDATE audit_events SET payload = ?, previous_hash = ?, event_hash = ?
                       WHERE scenario_id = ? AND day = ? AND sequence = ?""",
                    (payload, previous, event_hash, *partition, sequence),
                )
                previous = event_hash
        else:
            db.execute("DELETE FROM audit_events WHERE scenario_id = ? AND day = ?", partition)
    check = capture(connected_executor.path, trusted, now)[partition]
    assert check.code == ("checkpoint_mismatch" if rewrite else "truncated")
    assert check.first_difference == (check.anchored_through if rewrite else 1)
    with closing(audit.readonly(trusted)) as db:
        assert audit.checkpoints(db, audit.cutoff(now)) == before
    assert client.get("/api/audit?scenario_id=REQ-1842").json()["events"] == []


def test_failure_to_record_audit_rolls_back_incident_and_receipt(audit_app, connected_executor):
    client, _, _ = audit_app
    path = draft(client)
    grant = issue_approval(client, path).json()
    with connected_executor.connection() as db:
        db.executescript("""
            CREATE TRIGGER stop_audit BEFORE INSERT ON audit_events
            WHEN json_extract(NEW.payload, '$.action') = 'register_incident'
            BEGIN SELECT RAISE(ABORT, 'ошибка записи аудита'); END;
        """)
    with pytest.raises(sqlite3.IntegrityError, match="ошибка записи аудита"):
        connected_executor.resolve(
            path.rsplit("/", 1)[-1],
            "approve",
            Caller(operator=Operator.DUTY),
            transaction_token=grant["token"],
            idempotency_key=grant["idempotency_key"],
        )
    assert connected_executor.count_incidents("REQ-1842") == 0
    with connected_executor.connection() as db:
        assert db.execute("SELECT result FROM transaction_approvals").fetchone() == (None,)
        db.execute("DROP TRIGGER stop_audit")
    assert commit_approval(client, path, grant).status_code == 200


def test_retention_removes_old_partitions_from_both_stores(audit_app, connected_executor):
    _, now, trusted = audit_app
    old = now - timedelta(days=30)
    proposal = ToolProposal(action="get_service_status", scenario_id="REQ-1842", run_id="a" * 32)
    operator = Caller(operator=Operator.DUTY)
    connected_executor.clock = lambda: old
    connected_executor.audit_tool(operator, proposal, "ok")
    capture(connected_executor.path, trusted, old)
    connected_executor.clock = lambda: now
    connected_executor.audit_tool(operator, proposal, "ok")
    connected_executor.prune_audit()
    capture(connected_executor.path, trusted, now)
    with connected_executor.connection() as db:
        assert db.execute("SELECT day, sequence FROM audit_events").fetchall() == [
            (now.date().isoformat(), 1)
        ]
    with closing(audit.readonly(trusted)) as db:
        assert list(audit.checkpoints(db, "0000-00-00")) == [("REQ-1842", now.date().isoformat())]


def test_demo_reports_first_difference_without_touching_live_audit(audit_app):
    client, _, _ = audit_app
    demo = client.post("/api/audit-demo")
    demo.raise_for_status()
    result = demo.json()
    assert result["original"]["code"] == "verified"
    assert result["modified"]["code"] == "event_modified"
    assert result["modified"]["first_difference"] == 2
    assert result["truncated"]["code"] == "truncated"
    assert result["truncated"]["first_difference"] == 2
    assert client.get("/api/audit?scenario_id=REQ-1842").json() == {"checks": [], "events": []}
