import logging
from asyncio import sleep
from dataclasses import dataclass
from typing import TypeVar
from uuid import uuid4

import httpx2
from pydantic import TypeAdapter, ValidationError

from dispatcher.identity.access import NOTIFICATIONS, SERVICE_HEADER, Caller
from dispatcher.identity.iam import REQUEST_ID_HEADER, TOKEN_EXPIRED, AccessToken, ServiceTokens
from dispatcher.identity.transactions import (
    IDEMPOTENCY_HEADER,
    ApprovalIntent,
    ApprovalToken,
    TransactionComparison,
)
from dispatcher.multiagent.coordination.coordination_protocol import Evidence
from dispatcher.multiagent.hierarchy.delegation import TaskOrder
from dispatcher.observability.anomaly_detection.anomalies import AnomalyReport
from dispatcher.observability.metrics import MetricsReport, MetricsScope, ToolMinutes
from dispatcher.observability.tamper_evident_audit.audit import AuditComparison, AuditHistory
from dispatcher.observability.tracing.telemetry import span, trace_headers
from dispatcher.resilience.distributed_recovery import ResilienceReport
from dispatcher.resilience.functional_health import DependencyHealth
from dispatcher.resilience.retry_and_circuit_breaker.reliability_demo import ReliabilityReport
from dispatcher.resilience.retry_and_circuit_breaker.retry import (
    TEMPORARY_HTTP_STATUSES,
    RetryPolicy,
    retry,
)
from dispatcher.security.filters import SupportExport
from dispatcher.security.source_access.source_access_demo import SourceAccessReport
from dispatcher.workflow.cases import CaseCreate, CaseEvidenceUpdate, WorkCase
from dispatcher.workflow.execution import (
    AccessComparison,
    ExecutorUnavailable,
    ResolveRequest,
    RunSummary,
    ToolProposal,
    ToolResult,
)
from dispatcher.workflow.registration import ManualDraft
from dispatcher.workflow.scenarios import Action, Observation
from dispatcher.workflow.triage import (
    ApprovalTimeoutComparison,
    ComparedRun,
    FailClosedComparison,
    HierarchyComparison,
    RegistrationComparison,
    Run,
)

T = TypeVar("T")
logger = logging.getLogger(__name__)
RESOLUTION_RETRY = RetryPolicy(attempt_timeout=2.5, budget=5.5, delay=0.12)


@dataclass(frozen=True)
class ServiceTokenCheck:
    status: int
    code: str | None

    @classmethod
    def from_response(cls, response: httpx2.Response) -> ServiceTokenCheck:
        return cls(response.status_code, response.headers.get("X-Policy-Code"))


@dataclass(frozen=True)
class ServiceTokenDemo:
    lifetime_seconds: int
    fresh: ServiceTokenCheck
    monitoring: ServiceTokenCheck
    expired: ServiceTokenCheck
    renewed: ServiceTokenCheck | None
    tool_result: ToolResult | None


@dataclass(frozen=True)
class InteragentResult:
    read: Observation
    incident: ServiceTokenCheck
    unverified_transport: ServiceTokenCheck


class ExecutorRejected(RuntimeError):
    def __init__(self, status: int, detail: str, code: str | None = None):
        super().__init__(detail)
        self.status = status
        self.code = code


def can_retry_resolution(error: Exception) -> bool:
    if isinstance(error, (TimeoutError, httpx2.TimeoutException, httpx2.NetworkError)):
        return True
    if isinstance(error, httpx2.RemoteProtocolError):
        return True
    if isinstance(error, httpx2.HTTPStatusError):
        return error.response.status_code in TEMPORARY_HTTP_STATUSES
    return (
        isinstance(error, ExecutorRejected)
        and error.status == 503
        and error.code == "storage_unavailable"
    )


class ExecutorClient:
    def __init__(
        self, http: httpx2.AsyncClient, tokens: ServiceTokens | None = None, *, bound: bool = False
    ):
        self.http = http
        self.tokens = tokens
        self.bound = bound

    def token_header(self, token: AccessToken) -> dict[str, str]:
        if self.bound:
            return {"Authorization": f"Bearer {token.value}"}
        return {SERVICE_HEADER: token.value}

    async def _exchange(
        self,
        method: str,
        path: str,
        *,
        initial: AccessToken | None = None,
        headers: dict[str, str] | None = None,
        **options,
    ) -> tuple[httpx2.Response, httpx2.Response | None]:
        headers = {**(headers or {}), **trace_headers()}
        if self.tokens is None:
            return await self.http.request(method, path, headers=headers, **options), None

        token = initial if initial is not None else await self.tokens.get()
        request_id = uuid4().hex
        headers.update({**self.token_header(token), REQUEST_ID_HEADER: request_id})
        response = await self.http.request(method, path, headers=headers, **options)
        if response.status_code != 401 or response.headers.get("X-Policy-Code") != TOKEN_EXPIRED:
            return response, None

        logger.info("Перевыдача токена после отказа исполнителя запрос=%s", request_id)
        new_token = await self.tokens.get(rejected=token)
        headers.update(self.token_header(new_token))
        return await self.http.request(method, path, headers=headers, **options), response

    async def request(self, method: str, path: str, response_type: type[T], **options) -> T:
        try:
            response, _ = await self._exchange(method, path, **options)
            return self._parse(response, response_type)
        except (httpx2.HTTPError, ValidationError, KeyError, ValueError, TypeError) as error:
            raise ExecutorUnavailable(
                "Исполнитель недоступен или вернул некорректный ответ."
            ) from error

    @staticmethod
    def _parse(response: httpx2.Response, response_type: type[T]) -> T:
        policy_code = response.headers.get("X-Policy-Code")
        if response.status_code in (401, 403, 404, 409) or (
            policy_code and response.status_code == 503
        ):
            raise ExecutorRejected(response.status_code, response.json()["detail"], policy_code)
        response.raise_for_status()
        return TypeAdapter(response_type).validate_json(response.content)

    async def demonstrate_service_tokens(self, monitoring: ServiceTokens) -> ServiceTokenDemo:
        if self.tokens is None:
            raise ExecutorRejected(409, "Запустите стенд с Keycloak.")

        fresh = await self.tokens.get()
        if fresh.lifetime > 30:
            raise ExecutorRejected(409, "Для демонстрации задайте в Keycloak срок до 30 секунд.")
        proposal = ToolProposal(
            action=Action.STATUS, scenario_id="REQ-1842", resource=NOTIFICATIONS, run_id=uuid4().hex
        )
        try:
            fresh_response = await self.http.get(
                "/identity", headers={SERVICE_HEADER: fresh.value, REQUEST_ID_HEADER: uuid4().hex}
            )
            self._parse(fresh_response, Caller)
            monitor = await monitoring.get()
            monitoring_response = await self.http.get(
                "/identity", headers={SERVICE_HEADER: monitor.value, REQUEST_ID_HEADER: uuid4().hex}
            )
            await sleep(fresh.lifetime + 1)
            response, expired = await self._exchange(
                "POST", "/tools", initial=fresh, json=proposal.model_dump(mode="json")
            )
            result = (
                ToolResult.model_validate_json(response.content) if response.is_success else None
            )
        except httpx2.HTTPError, ValidationError, KeyError, ValueError, TypeError:
            raise ExecutorUnavailable("Не удалось завершить проверку сервисных токенов.") from None

        return ServiceTokenDemo(
            lifetime_seconds=fresh.lifetime,
            fresh=ServiceTokenCheck.from_response(fresh_response),
            monitoring=ServiceTokenCheck.from_response(monitoring_response),
            expired=ServiceTokenCheck.from_response(expired if expired is not None else response),
            renewed=ServiceTokenCheck.from_response(response) if expired is not None else None,
            tool_result=result,
        )

    async def execute(self, proposal: ToolProposal) -> ToolResult:
        """Отправляет предложение во внутренний API и разбирает типизированный ответ."""
        with span("tool_request") as operation:
            result = await self.request(
                "POST", "/tools", ToolResult, json=proposal.model_dump(mode="json")
            )
            operation.code = result.code
            return result

    async def compare_outcomes(self) -> list[ComparedRun]:
        return await self.request("POST", "/outcome-comparison", list[ComparedRun])

    async def demonstrate_fail_closed(self) -> FailClosedComparison:
        return await self.request("POST", "/fail-closed-demo", FailClosedComparison)

    async def demonstrate_hierarchy(self) -> HierarchyComparison:
        return await self.request("POST", "/priority-hierarchy-demo", HierarchyComparison)

    async def demonstrate_registration_checks(self) -> RegistrationComparison:
        return await self.request("POST", "/registration-checks-demo", RegistrationComparison)

    async def demonstrate_approval_timeout(self) -> ApprovalTimeoutComparison:
        return await self.request("POST", "/approval-timeout-demo", ApprovalTimeoutComparison)

    async def demonstrate_zero_trust(self) -> AccessComparison:
        return await self.request("POST", "/zero-trust-demo", AccessComparison)

    async def demonstrate_source_access(self) -> SourceAccessReport:
        return await self.request("POST", "/source-access-demo", SourceAccessReport)

    async def identity(self) -> Caller:
        return await self.request("GET", "/identity", Caller)

    async def list_cases(self) -> list[WorkCase]:
        return await self.request("GET", "/cases", list[WorkCase])

    async def create_case(self, data: CaseCreate) -> WorkCase:
        return await self.request("POST", "/cases", WorkCase, json=data.model_dump(mode="json"))

    async def get_case(self, case_id: str) -> WorkCase:
        return await self.request("GET", f"/cases/{case_id}", WorkCase)

    async def update_case(self, case_id: str, data: CaseEvidenceUpdate) -> WorkCase:
        return await self.request(
            "PUT", f"/cases/{case_id}/evidence", WorkCase, json=data.model_dump(mode="json")
        )

    async def close_case(self, case_id: str) -> WorkCase:
        return await self.request("POST", f"/cases/{case_id}/close", WorkCase)

    async def case_support(self, case_id: str) -> SupportExport:
        return await self.request("GET", f"/cases/{case_id}/support-card", SupportExport)

    async def save(self, run: Run, *, support_export: SupportExport | None = None) -> Run:
        if support_export is not None:
            return await self.request(
                "POST",
                "/runs/with-support",
                Run,
                json={
                    "run": run.model_dump(mode="json"),
                    "support_export": support_export.model_dump(mode="json"),
                },
            )
        return await self.request("POST", "/runs", Run, json=run.model_dump(mode="json"))

    async def list_runs(self, scenario_id: str) -> list[RunSummary]:
        return await self.request(
            "GET", "/runs", list[RunSummary], params={"scenario_id": scenario_id}
        )

    async def get(self, run_id: str) -> Run:
        return await self.request("GET", f"/runs/{run_id}", Run)

    async def support_card(self, run_id: str) -> SupportExport:
        return await self.request("GET", f"/runs/{run_id}/support-card", SupportExport)

    async def manual_evidence(self, run_id: str) -> Run:
        return await self.request("POST", f"/runs/{run_id}/manual-evidence", Run)

    async def manual_draft(self, run_id: str, draft: ManualDraft) -> Run:
        return await self.request(
            "POST", f"/runs/{run_id}/manual-draft", Run, json=draft.model_dump()
        )

    async def issue_approval(self, run_id: str, intent: ApprovalIntent) -> ApprovalToken:
        return await self.request(
            "POST",
            f"/runs/{run_id}/approval-token",
            ApprovalToken,
            json=intent.model_dump(mode="json"),
        )

    async def demonstrate_transactions(self) -> TransactionComparison:
        return await self.request("POST", "/transaction-token-demo", TransactionComparison)

    async def audit_history(self, scenario_id: str) -> AuditHistory:
        return await self.request(
            "GET", "/audit", AuditHistory, params={"scenario_id": scenario_id}
        )

    async def demonstrate_audit(self) -> AuditComparison:
        return await self.request("POST", "/audit-demo", AuditComparison)

    async def operation_metrics(
        self, window: ToolMinutes, scope: MetricsScope = "course"
    ) -> MetricsReport:
        return await self.request(
            "GET",
            "/operation-metrics",
            MetricsReport,
            params={"tool_minutes": int(window), "scope": scope},
        )

    async def operation_metrics_demo(self) -> MetricsReport:
        return await self.request("GET", "/operation-metrics/demo", MetricsReport)

    async def anomalies(self, scenario_id: str) -> AnomalyReport:
        return await self.request(
            "GET", "/anomalies", AnomalyReport, params={"scenario_id": scenario_id}
        )

    async def anomalies_demo(self) -> AnomalyReport:
        return await self.request("POST", "/anomalies/demo", AnomalyReport)

    async def resilience_demo(self) -> ResilienceReport:
        return await self.request("POST", "/resilience/demo", ResilienceReport, timeout=28)

    async def reliability_demo(self) -> ReliabilityReport:
        return await self.request("POST", "/reliability/demo", ReliabilityReport)

    async def functional_health(self) -> DependencyHealth:
        return await self.request("GET", "/health/functional", DependencyHealth)

    async def perform_delegation(self, order: TaskOrder) -> Evidence:
        return await self.request(
            "POST", "/delegation/tasks", Evidence, json=order.model_dump(mode="json")
        )

    async def resolve(
        self, run_id: str, request: ResolveRequest, idempotency_key: str | None = None
    ) -> Run:
        path = f"/runs/{run_id}/resolution"
        headers = {IDEMPOTENCY_HEADER: idempotency_key} if idempotency_key is not None else None
        payload = request.model_dump(exclude_none=True)
        if request.decision != "approve" or request.transaction_token is None or headers is None:
            return await self.request("POST", path, Run, headers=headers, json=payload)

        async def register() -> Run:
            response, _ = await self._exchange("POST", path, headers=headers, json=payload)
            return self._parse(response, Run)

        try:
            return await retry(
                register, RESOLUTION_RETRY, can_retry_resolution, name="registration_attempt"
            )
        except (
            TimeoutError,
            httpx2.HTTPError,
            ValidationError,
            KeyError,
            ValueError,
            TypeError,
        ) as error:
            raise ExecutorUnavailable(
                "Не удалось подтвердить ответ исполнителя. Повторите регистрацию с тем же согласованием."
            ) from error
