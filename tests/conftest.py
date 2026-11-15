import httpx2
import pytest
from fastapi import Header
from fastapi.testclient import TestClient

from dispatcher import executor, main
from dispatcher.identity.access import SERVICE_HEADER
from dispatcher.persistence.storage import RunStore
from dispatcher.workflow.client import ExecutorClient


@pytest.fixture
def access_keys():
    return executor.ExecutorSettings(
        _env_file=None,
        service_token="s" * 64,
        duty_operator_token="d" * 64,
        observer_token="o" * 64,
    )


@pytest.fixture
def service_headers(access_keys):
    return {
        SERVICE_HEADER: access_keys.service_token.get_secret_value(),
        "Authorization": f"Bearer {access_keys.duty_operator_token.get_secret_value()}",
    }


@pytest.fixture
def service_client(service_headers):
    with TestClient(executor.app, headers=service_headers) as client:
        yield client


@pytest.fixture(autouse=True)
def connected_executor(monkeypatch, tmp_path, access_keys, service_headers):
    store = RunStore(tmp_path / "runs.sqlite3")
    monkeypatch.setattr(executor, "storage", lambda: store)
    monkeypatch.setattr(executor, "settings", lambda: access_keys)

    async def client(authorization: str = Header(default=service_headers["Authorization"])):
        transport = httpx2.ASGITransport(app=executor.app)
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="http://executor",
            headers={**service_headers, "Authorization": authorization},
        ) as http:
            yield ExecutorClient(http)

    monkeypatch.setitem(main.app.dependency_overrides, main.executor_client, client)
    return store
