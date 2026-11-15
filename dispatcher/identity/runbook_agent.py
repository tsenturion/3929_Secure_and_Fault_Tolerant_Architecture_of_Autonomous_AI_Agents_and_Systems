import logging
from functools import lru_cache

import httpx2
from fastapi import FastAPI, HTTPException

from dispatcher.identity.iam import RUNBOOK_CLIENT, ServiceTokens, TokenServiceUnavailable
from dispatcher.identity.workload_identity.workload import client_tls
from dispatcher.observability.tracing.diagnostics import configure_logging
from dispatcher.settings import Settings
from dispatcher.workflow.client import (
    ExecutorClient,
    ExecutorRejected,
    InteragentResult,
    ServiceTokenCheck,
)
from dispatcher.workflow.execution import ExecutorUnavailable, ResolveRequest
from dispatcher.workflow.scenarios import Observation

configure_logging("runbook-agent")
logger = logging.getLogger(__name__)
app = FastAPI(title="Агент регламентов")


@lru_cache
def settings() -> Settings:
    return Settings()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/demo")
async def demo() -> InteragentResult:
    config = settings()
    if not config.executor_url.startswith("https://"):
        raise HTTPException(503, "У исполнителя не настроен TLS.")
    try:
        tls = client_tls(config.workload_tls_dir)
        tokens = ServiceTokens(
            config.iam_issuer, RUNBOOK_CLIENT, config.iam_runbook_client_secret, tls=tls
        )
        async with httpx2.AsyncClient(
            base_url=config.executor_url, verify=tls, trust_env=False, timeout=10
        ) as http:
            client = ExecutorClient(http, tokens, bound=True)
            read = await client.request("GET", "/runbooks/RB-NOTIFY-07", Observation)
            # Проверяем действующий маршрут согласования на тестовом идентификаторе прогона.
            try:
                await client.resolve("0" * 32, ResolveRequest(decision="approve"))
            except ExecutorRejected as error:
                incident = ServiceTokenCheck(status=error.status, code=error.code)
            else:
                incident = ServiceTokenCheck(status=200, code=None)

        server_tls = client_tls(config.workload_tls_dir, present_certificate=False)
        async with httpx2.AsyncClient(
            base_url=config.executor_url, verify=server_tls, trust_env=False, timeout=10
        ) as http:
            response = await http.get(
                "/runbooks/RB-NOTIFY-07", headers=client.token_header(await tokens.get())
            )
    except ExecutorRejected, ExecutorUnavailable, TokenServiceUnavailable, httpx2.HTTPError:
        logger.warning("Агент регламентов не завершил проверку доступа")
        raise HTTPException(503, "Агент регламентов не смог завершить проверку.") from None

    unverified_transport = ServiceTokenCheck.from_response(response)
    logger.info(
        "Агент регламентов получил RB-NOTIFY-07 согласование=%s сертификат_отсутствует=%s",
        incident.status,
        unverified_transport.status,
    )
    return InteragentResult(read, incident, unverified_transport)
