import logging
import os
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Request

from dispatcher.identity.access import SERVICE_HEADER, matches
from dispatcher.observability.tracing.diagnostics import configure_logging
from dispatcher.observability.tracing.telemetry import receive, span
from dispatcher.workflow.scenarios import SCENARIOS, Monitoring

configure_logging("monitoring")
logger = logging.getLogger(__name__)
app = FastAPI(title="Мониторинг очереди уведомлений", docs_url=None, redoc_url=None)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/snapshots/{scenario_id}")
def snapshot(
    scenario_id: str,
    request: Request,
    service_token: Annotated[str, Header(alias=SERVICE_HEADER)] = "",
) -> Monitoring:
    with span("monitoring_source", parent=receive(request.headers)):
        expected = os.getenv("MONITORING_TOKEN", "")
        if len(expected) < 32:
            logger.warning("Ключ доступа к мониторингу не настроен")
            raise HTTPException(503, "Мониторинг не настроен.")
        if not matches(service_token, expected):
            logger.warning("Доступ к мониторингу отклонён")
            raise HTTPException(401, "Личность вызывающего сервиса не подтверждена.")
        scenario = SCENARIOS.get(scenario_id)
        if scenario is None:
            raise HTTPException(404, "Снимок обращения не найден.")
        return scenario.monitoring
