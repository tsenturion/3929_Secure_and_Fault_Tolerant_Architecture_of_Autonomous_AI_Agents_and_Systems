from fastapi.testclient import TestClient

from dispatcher import main
from dispatcher.resilience.forecasting.forecast import ForecastReplay, forecast_report, score
from dispatcher.resilience.forecasting.forecast_workload import (
    HORIZON,
    TEST_DAYS,
    TRAIN_DAYS,
    VALIDATION_DAYS,
    BackgroundPolicy,
    Sample,
)
from dispatcher.security.agent_threats.demonstrations import DemonstrationModel
from dispatcher.settings import Settings
from dispatcher.workflow.comparison import restore_demo_assignment
from tests.approval_helpers import approve


def test_comparison_uses_held_out_days_and_preserves_all_arrivals():
    assert max(TRAIN_DAYS) < min(VALIDATION_DAYS) <= max(VALIDATION_DAYS) < min(TEST_DAYS)
    report = forecast_report()
    assert report.test_days == len(TEST_DAYS)
    assert report.rule.lead_minutes == 0
    assert 0 < report.lstm.lead_minutes <= HORIZON
    assert report.lstm.detected + report.lstm.missed == report.rule.detected + report.rule.missed
    assert report.lstm.false_alarms > 0
    assert report.baseline.requests == report.controlled.requests
    assert report.controlled.background_checks < report.baseline.background_checks
    assert report.controlled.p95_minutes < report.baseline.p95_minutes


def test_scoring_combines_brief_dips_and_counts_unmatched_alerts():
    samples = [Sample(0, 0, 8 if minute in {11, 13} else 0) for minute in range(42)]
    alerts = [minute in {4, 24, 40} for minute in range(len(samples))]
    assert score(samples, alerts) == ([7], 0, 1)


def test_policy_limits_slowdown_when_risk_stays_high():
    policy = BackgroundPolicy(0.5)
    assert policy.period(3, None) == 1
    assert policy.period(4, 0.8) == 4
    assert policy.period(19, 0.8) == 4
    assert policy.period(20, 0.8) == 1
    assert policy.period(21, 0.4) == 1
    assert policy.period(22, 0.8) == 4


def test_replay_limits_background_only_and_expires(
    monkeypatch, tmp_path, connected_executor, access_keys
):
    now = 20.0
    replay = ForecastReplay(clock=lambda: now)
    monkeypatch.setattr(main, "forecast_replay", replay)
    monkeypatch.setattr(main, "settings", lambda: Settings(_env_file=None, model_gateway_url=""))
    monkeypatch.setattr(main, "create_model", lambda _: DemonstrationModel())
    policy = tmp_path / "on-call.json"
    restore_demo_assignment(policy)
    connected_executor.policy_path = policy
    observer = {"Authorization": f"Bearer {access_keys.observer_token.get_secret_value()}"}
    automatic = "/api/health/functional?background=true"
    manual = "/api/health/functional"

    with TestClient(main.app) as client:
        assert client.get("/api/forecast", headers=observer).status_code == 200
        assert client.post("/api/forecast/replay", headers=observer).status_code == 403
        assert client.get(automatic).status_code == 200
        started = client.post("/api/forecast/replay").json()
        assert started["active"]
        report = forecast_report()
        first = next(point.minute for point in report.timeline if point.throttled)
        now += first - report.replay_start
        assert client.post("/api/forecast/replay").json()["minute"] == first
        response = client.get(automatic)
        assert response.status_code == 429
        assert response.json()["code"] == "forecast_deferred"
        assert 0 < int(response.headers["Retry-After"]) <= 16
        assert client.get(manual).status_code == 200
        assert client.get("/api/health/live").status_code == 200

        draft = client.post("/api/runs", json={"scenario_id": "REQ-1842", "mode": "agent"}).json()
        assert draft["status"] == "awaiting_approval"
        registered = approve(client, "/api/runs/" + draft["id"])
        assert registered.status_code == 200
        assert registered.json()["incident_id"] == "INC-3071"

        now += report.replay_end - first
        assert not client.get("/api/forecast/replay").json()["active"]
        assert client.get(automatic).status_code == 200
