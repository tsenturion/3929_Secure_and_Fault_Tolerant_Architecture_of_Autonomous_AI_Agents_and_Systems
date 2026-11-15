from fastapi.testclient import TestClient

from dispatcher import main


def test_comparison_reads_isolated_state_and_retries_after_commit(connected_executor):
    with TestClient(main.app) as client:
        assert client.get("/api/runs?scenario_id=REQ-1842").json() == []
        for _ in range(2):
            response = client.post("/api/outcome-comparison")
            response.raise_for_status()
            results = {result["case"]: result for result in response.json()}
            assert len(results) == 4

            normal = results["normal"]["checkpoints"]
            assert [check["incident_count"] for check in normal] == [0, 1]
            assert [check["status"] for check in normal] == ["awaiting_approval", "completed"]

            policy = results["policy_denied"]
            assert policy["checkpoints"][0]["incident_count"] == 0
            assert policy["trace"]["boundary_decisions"][0]["threat"] == "tool_misuse"
            assert policy["trace"]["status"] == "needs_review"

            unavailable = results["model_unavailable"]
            assert unavailable["checkpoints"][0]["incident_count"] == 0
            trace = unavailable["trace"]
            assert trace["status"] == "needs_review"
            assert "Провайдер модели недоступен" in trace["error"]
            assert trace["steps"][0]["observation"]["source"].startswith("Мониторинг")

            lost = results["reply_lost_after_commit"]
            checks = lost["checkpoints"]
            assert [check["incident_count"] for check in checks] == [0, 1, 1]
            assert "таймаут" in checks[1]["operator"]
            assert checks[1]["incident_id"] == checks[2]["incident_id"] == "INC-3071"
            assert (
                sum(
                    event["title"] == "Инцидент зарегистрирован"
                    for event in lost["trace"]["lifecycle"]["events"]
                )
                == 1
            )
    assert connected_executor.list_agent_runs("REQ-1842") == []
    assert connected_executor.count_incidents("REQ-1842") == 0
