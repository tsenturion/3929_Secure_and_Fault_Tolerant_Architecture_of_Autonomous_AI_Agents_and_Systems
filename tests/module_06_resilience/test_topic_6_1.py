from fastapi.testclient import TestClient

from dispatcher import main


def test_recovery_demo_requires_postgres(connected_executor):
    with TestClient(main.app) as client:
        result = client.post("/api/resilience/demo")

    assert result.status_code == 409
    assert "start-resilience.ps1" in result.json()["detail"]
    assert connected_executor.count_incidents("REQ-1842") == 0
