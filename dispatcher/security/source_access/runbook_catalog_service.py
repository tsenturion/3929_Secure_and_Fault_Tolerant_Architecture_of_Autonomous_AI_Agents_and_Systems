import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import TypeAdapter

from dispatcher.identity.access import SERVICE_HEADER, matches
from dispatcher.observability.tracing.diagnostics import configure_logging
from dispatcher.observability.tracing.telemetry import receive, span
from dispatcher.security.source_access.runbook_catalog import RUNBOOK_IDS
from dispatcher.workflow.scenarios import SOURCES, Observation

configure_logging("runbook-catalog")
logger = logging.getLogger(__name__)
PUBLISHED = {runbook_id: SOURCES[action] for action, runbook_id in RUNBOOK_IDS.items()}
MAX_INDEX_BYTES = 4096


def load_index(path: str) -> frozenset[str]:
    if not path:
        return frozenset(PUBLISHED)
    try:
        with Path(path).open("rb") as index:
            data = index.read(MAX_INDEX_BYTES + 1)
        if len(data) > MAX_INDEX_BYTES:
            raise ValueError("Индекс превышает допустимый размер.")
        entries = frozenset(TypeAdapter(list[str]).validate_json(data))
        if not entries.issubset(PUBLISHED):
            raise ValueError("Индекс содержит неопубликованные идентификаторы.")
    except (OSError, ValueError) as error:
        logger.warning("Индекс каталога недоступен")
        raise HTTPException(503, "Индекс каталога недоступен.") from error
    return entries


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        app.state.index = load_index(os.getenv("RUNBOOK_INDEX_PATH", ""))
    except HTTPException:
        app.state.index = None
    yield


app = FastAPI(
    title="Каталог опубликованных регламентов", docs_url=None, redoc_url=None, lifespan=lifespan
)


def published_index(request: Request) -> frozenset[str]:
    if request.app.state.index is None:
        raise HTTPException(503, "Индекс каталога недоступен.")
    return request.app.state.index


@app.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
def readiness(request: Request) -> dict[str, str]:
    published_index(request)
    return {"status": "ready"}


@app.get("/search/{runbook_id}")
def search(
    runbook_id: str,
    request: Request,
    service_token: Annotated[str, Header(alias=SERVICE_HEADER)] = "",
) -> Observation:
    with span("runbook_search", parent=receive(request.headers)):
        expected = os.getenv("RUNBOOK_CATALOG_TOKEN", "")
        if len(expected) < 32:
            logger.warning("Ключ доступа к каталогу не настроен")
            raise HTTPException(503, "Каталог не настроен.")
        if not matches(service_token, expected):
            logger.warning("Доступ к каталогу отклонён")
            raise HTTPException(401, "Ключ каталога не подтверждён.")
        if runbook_id not in published_index(request):
            raise HTTPException(404, "Регламент отсутствует в индексе поиска.")
        return PUBLISHED[runbook_id]
