import asyncio
from typing import Literal

import httpx2
from pydantic import SecretStr, ValidationError

from dispatcher.identity.access import SERVICE_HEADER
from dispatcher.observability.tracing.telemetry import trace_headers
from dispatcher.security.source_access.source_origin import configured_origin
from dispatcher.workflow.scenarios import Action, Observation, SourceKind

RUNBOOK_IDS = {Action.INDIVIDUAL: "RB-NOTIFY-03", Action.INCIDENT: "RB-NOTIFY-07"}
CATALOG_ROUTES = {"/health/live", *(f"/search/{identifier}" for identifier in RUNBOOK_IDS.values())}
CATALOG_TIMEOUT = 0.8
CatalogErrorCode = Literal["runbook_not_found", "runbook_unavailable", "invalid_runbook"]


class CatalogError(RuntimeError):
    def __init__(self, code: CatalogErrorCode):
        super().__init__(code)
        self.code = code


class RunbookCatalog:
    def __init__(self, url: str, token: SecretStr):
        self.url = configured_origin(url)
        self.token = token

    async def request(self, path: str) -> httpx2.Response:
        if path not in CATALOG_ROUTES:
            raise CatalogError("runbook_not_found")
        try:
            async with asyncio.timeout(CATALOG_TIMEOUT):
                async with httpx2.AsyncClient(trust_env=False, follow_redirects=False) as client:
                    return await client.get(
                        self.url.copy_with(path=path),
                        headers={SERVICE_HEADER: self.token.get_secret_value(), **trace_headers()},
                    )
        except (TimeoutError, httpx2.HTTPError) as error:
            raise CatalogError("runbook_unavailable") from error

    async def alive(self) -> bool:
        try:
            return (await self.request("/health/live")).status_code == 200
        except CatalogError:
            return False

    async def find(self, action: Action) -> Observation:
        runbook_id = RUNBOOK_IDS[action]
        response = await self.request(f"/search/{runbook_id}")
        if response.status_code == 404:
            raise CatalogError("runbook_not_found")
        if response.status_code != 200:
            raise CatalogError("runbook_unavailable")
        try:
            found = Observation.model_validate_json(response.content)
        except ValidationError as error:
            raise CatalogError("invalid_runbook") from error
        if found.kind != SourceKind.PUBLISHED_RUNBOOK or not found.source.startswith(
            f"{runbook_id} · "
        ):
            raise CatalogError("invalid_runbook")
        return found
