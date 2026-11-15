from datetime import UTC, datetime, timedelta
from sqlite3 import IntegrityError

import pytest
from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.identity.access import Caller, Operator
from dispatcher.identity.transactions import TRANSACTION_SECONDS
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from dispatcher.workflow.lifecycle import Phase
from tests.approval_helpers import commit_approval, issue_approval


@pytest.fixture
def configured_app(monkeypatch, connected_executor):
    clock = [datetime(2026, 11, 15, 9, 12, tzinfo=UTC)]
    connected_executor.clock = lambda: clock[0]
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    with TestClient(main.app) as client:
        yield client, clock


def start(client):
    response = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"})
    response.raise_for_status()
    return f"/api/runs/{response.json()['id']}"


def authorize(client, path):
    response = issue_approval(client, path)
    response.raise_for_status()
    assert response.headers["Cache-Control"] == "no-store"
    return response.json()


def test_token_rejects_other_action_run_key_and_unverified_operator(
    configured_app, connected_executor, access_keys, caplog
):
    client, clock = configured_app
    path, other = start(client), start(client)
    grant = authorize(client, path)
    token = grant["token"]
    key = grant["idempotency_key"]
    assert datetime.fromisoformat(grant["expires_at"]) == clock[0] + timedelta(seconds=30)
    missing = client.post(f"{path}/resolution", json={"decision": "approve"})
    assert missing.json()["code"] == "transaction_token_required"
    assert commit_approval(client, other, grant).json()["code"] == "transaction_token_invalid"
    wrong_key = {**grant, "idempotency_key": "f" * 32}
    assert commit_approval(client, path, wrong_key).json()["code"] == "transaction_token_invalid"
    denied = client.post(
        f"{path}/resolution",
        json={"decision": "reject", "transaction_token": token},
        headers={"Idempotency-Key": key},
    )
    assert denied.json()["code"] == "transaction_action_invalid"
    observer = {"Authorization": f"Bearer {access_keys.observer_token.get_secret_value()}"}
    assert issue_approval(client, path, headers=observer).status_code == 403
    assert connected_executor.count_incidents("REQ-1842") == 0
    result = commit_approval(client, path, grant)
    assert result.json()["incident_id"] == "INC-3071"
    clock[0] += timedelta(hours=1)
    assert commit_approval(client, path, grant, headers=observer).status_code == 403
    assert commit_approval(client, path, grant).json() == result.json()
    assert connected_executor.count_incidents("REQ-1842") == 1
    assert token not in result.text
    assert token not in caplog.text
    with connected_executor.connection() as db:
        (digest,) = db.execute("SELECT token_digest FROM transaction_approvals").fetchone()
    assert digest != token


def test_change_invalidates_confirmation_and_expired_token_cannot_write(
    configured_app, connected_executor
):
    client, clock = configured_app
    path = start(client)
    run_id = path.rsplit("/", 1)[-1]
    original = connected_executor.get(run_id)
    grant = authorize(client, path)
    changed = original.model_copy(deep=True)
    changed.recommendation.priority = "P1"
    with connected_executor.connection() as db:
        connected_executor.update(db, changed)
    stale = client.post(
        f"{path}/approval-token",
        json={
            "scenario_id": original.scenario_id,
            "recommendation": original.recommendation.model_dump(mode="json"),
        },
    )
    assert stale.json()["code"] == "approval_changed"
    assert commit_approval(client, path, grant).json()["code"] == "approval_changed"
    invalid = issue_approval(client, path)
    assert invalid.json()["code"] == "invalid_draft"
    with connected_executor.connection() as db:
        connected_executor.update(db, original)
    assert commit_approval(client, path, grant).json()["code"] == "transaction_token_invalid"
    new = authorize(client, path)
    clock[0] += timedelta(seconds=TRANSACTION_SECONDS)
    assert commit_approval(client, path, new).json()["code"] == "transaction_token_expired"
    assert connected_executor.count_incidents("REQ-1842") == 0
    assert commit_approval(client, path, authorize(client, path)).status_code == 200


def test_incident_and_token_receipt_roll_back_together(configured_app, connected_executor):
    client, _ = configured_app
    path = start(client)
    run_id = path.rsplit("/", 1)[-1]
    grant = authorize(client, path)
    with connected_executor.connection() as db:
        db.executescript("""
            CREATE TRIGGER stop_before_receipt BEFORE UPDATE OF result ON transaction_approvals
            BEGIN SELECT RAISE(ABORT, 'ошибка записи результата'); END;
        """)
    with pytest.raises(IntegrityError, match="ошибка записи результата"):
        connected_executor.resolve(
            run_id,
            "approve",
            Caller(operator=Operator.DUTY),
            transaction_token=grant["token"],
            idempotency_key=grant["idempotency_key"],
        )
    assert connected_executor.get(run_id).status == Phase.AWAITING_APPROVAL
    assert connected_executor.count_incidents("REQ-1842") == 0
    with connected_executor.connection() as db:
        assert db.execute("SELECT result FROM transaction_approvals").fetchone() == (None,)
        db.execute("DROP TRIGGER stop_before_receipt")
    assert commit_approval(client, path, grant).json()["incident_id"] == "INC-3071"


def test_transaction_demo_uses_separate_tracker(configured_app, connected_executor):
    client, _ = configured_app
    response = client.post("/api/transaction-token-demo")
    response.raise_for_status()
    assert response.json() == {
        "changed_code": "approval_changed",
        "incidents_after_change": 0,
        "incident_id": "INC-3071",
        "repeated_incident_id": "INC-3071",
        "incident_count": 1,
    }
    assert connected_executor.count_incidents("REQ-1842") == 0
