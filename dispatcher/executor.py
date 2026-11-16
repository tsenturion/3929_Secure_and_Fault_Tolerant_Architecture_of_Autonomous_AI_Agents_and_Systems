import asyncio
import logging
import ssl
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from sqlite3 import Error as DatabaseError
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from psycopg import Error as PostgresError
from psycopg import OperationalError
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from dispatcher.identity.access import (
    NOTIFICATION_REQUESTS,
    NOTIFICATIONS,
    PAYMENTS,
    SERVICE_HEADER,
    AccessKeys,
    Caller,
    Operator,
    denied,
)
from dispatcher.identity.iam import (
    EXECUTOR_SCOPE,
    INCIDENT_SCOPE,
    OPERATOR_HEADER,
    REQUEST_ID_HEADER,
    RUNBOOK_SCOPE,
    AuthMode,
    ServiceGrant,
    TokenVerifier,
)
from dispatcher.identity.transactions import (
    IDEMPOTENCY_HEADER,
    IDEMPOTENCY_PATTERN,
    ApprovalIntent,
    ApprovalToken,
    TransactionComparison,
    TransactionRejected,
)
from dispatcher.identity.workload_identity.workload import (
    CERT_HEADER,
    Challenge,
    TpmProof,
    TpmResult,
    TpmVerifier,
    WorkloadCertificate,
    identify_certificate,
)
from dispatcher.multiagent.coordination.coordination_protocol import Evidence
from dispatcher.multiagent.hierarchy.delegated_workers import DelegatedReader, perform_task
from dispatcher.multiagent.hierarchy.delegation import TaskOrder
from dispatcher.multiagent.information_flow import Party
from dispatcher.observability.anomaly_detection.anomalies import AnomalyReport
from dispatcher.observability.anomaly_detection.anomaly_demo import DEMO_CASE, demonstrate_anomalies
from dispatcher.observability.metrics import (
    DEFAULT_TOOL_MINUTES,
    MetricsReport,
    MetricsScope,
    ToolMinutes,
    demo_report,
)
from dispatcher.observability.tamper_evident_audit.audit import AuditComparison, AuditHistory
from dispatcher.observability.tracing.diagnostics import configure_logging
from dispatcher.observability.tracing.telemetry import received_run, span
from dispatcher.persistence.cases import CaseError
from dispatcher.persistence.database import PostgresDatabase
from dispatcher.persistence.storage import (
    DEFAULT_APPROVAL_SECONDS,
    RunConflict,
    RunStore,
    RunSummary,
)
from dispatcher.resilience.distributed_recovery import CASE as RESILIENCE_CASE
from dispatcher.resilience.distributed_recovery import (
    RecoveryFailed,
    ResilienceReport,
    demonstrate_resilience,
)
from dispatcher.resilience.functional_health import PROBE_CASE, DependencyHealth, check_dependencies
from dispatcher.resilience.retry_and_circuit_breaker.monitoring import MonitoringClient
from dispatcher.resilience.retry_and_circuit_breaker.reliability_demo import (
    CASE as RELIABILITY_CASE,
)
from dispatcher.resilience.retry_and_circuit_breaker.reliability_demo import (
    ReliabilityReport,
    demonstrate_reliability,
)
from dispatcher.resilience.retry_and_circuit_breaker.retry import RetryPolicy
from dispatcher.security.filters import SupportExport
from dispatcher.security.source_access.runbook_catalog import RunbookCatalog
from dispatcher.security.source_access.source_access_demo import (
    SourceAccessReport,
    demonstrate_source_access,
)
from dispatcher.security.tool_guardrails.tools import (
    LocalTools,
    authorized_tool,
    read_manual_evidence,
)
from dispatcher.workflow.approval_policy import DEFAULT_POLICY_PATH, ApprovalCode, ApprovalRejected
from dispatcher.workflow.case_ids import WorkCaseId, is_work_case
from dispatcher.workflow.cases import CaseCreate, CaseEvidenceUpdate, WorkCase
from dispatcher.workflow.comparison import (
    compare_outcomes,
    demonstrate_approval_timeout,
    demonstrate_audit,
    demonstrate_fail_closed,
    demonstrate_hierarchy,
    demonstrate_registration_checks,
    demonstrate_transactions,
)
from dispatcher.workflow.execution import (
    AccessComparison,
    AccessExample,
    ResolveRequest,
    RunId,
    ToolProposal,
    ToolResult,
)
from dispatcher.workflow.lifecycle import Phase
from dispatcher.workflow.registration import ManualDraft
from dispatcher.workflow.scenarios import Action, Observation
from dispatcher.workflow.triage import (
    ApprovalTimeoutComparison,
    ComparedRun,
    FailClosedComparison,
    HierarchyComparison,
    RegistrationComparison,
    Run,
    RunWithSupport,
)


class ExecutorSettings(BaseSettings, AccessKeys):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    run_db_path: Path = Path("state/dispatcher.sqlite3")
    run_db_dsn: SecretStr = SecretStr("")
    run_db_password: SecretStr = SecretStr("")
    run_db_audit_role: str = ""
    on_call_policy_path: Path = DEFAULT_POLICY_PATH
    approval_timeout_seconds: int = Field(default=DEFAULT_APPROVAL_SECONDS, ge=1, le=86400)
    service_auth_mode: AuthMode = "static"
    iam_issuer: str = ""
    iam_ca_file: Path | None = None
    tpm_public_key: Path | None = None
    audit_checkpoint_db: Path | None = None
    monitoring_url: str = ""
    monitoring_token: SecretStr = SecretStr("")
    runbook_catalog_url: str = ""
    runbook_catalog_token: SecretStr = SecretStr("")


@lru_cache
def settings() -> ExecutorSettings:
    return ExecutorSettings()


@lru_cache
def storage() -> RunStore:
    """Создаёт хранилище прогонов и трекера в процессе исполнителя."""
    config = settings()
    postgres = (
        PostgresDatabase(
            config.run_db_dsn, config.run_db_password, audit_role=config.run_db_audit_role
        )
        if config.run_db_dsn.get_secret_value()
        else None
    )
    return RunStore(
        config.run_db_path,
        config.on_call_policy_path,
        approval_seconds=config.approval_timeout_seconds,
        postgres=postgres,
    )


@lru_cache(maxsize=1)
def monitoring_client(url: str, token: SecretStr) -> MonitoringClient | None:
    return MonitoringClient(url, token) if url else None


def execution_tools(*, synthetic: bool = False) -> LocalTools:
    config = settings()
    try:
        catalog = (
            RunbookCatalog(config.runbook_catalog_url, config.runbook_catalog_token)
            if config.runbook_catalog_url
            else None
        )
        if synthetic and config.monitoring_url:
            monitor = MonitoringClient(
                config.monitoring_url,
                config.monitoring_token,
                policy=RetryPolicy(attempt_timeout=0.7, budget=0.8, delay=0, attempts=1),
            )
        else:
            monitor = monitoring_client(config.monitoring_url, config.monitoring_token)
    except ValueError as error:
        raise denied(
            503, "source_config_invalid", "Базовый адрес источника не прошёл проверку."
        ) from error
    return LocalTools(monitor, catalog)


@lru_cache(maxsize=1)
def token_verifier(issuer: str) -> TokenVerifier:
    return TokenVerifier(issuer)


@lru_cache(maxsize=1)
def bound_token_verifier(issuer: str, ca: Path | None) -> TokenVerifier:
    if not issuer.startswith("https://") or ca is None:
        raise denied(503, "identity_unavailable", "Издатель mTLS-токенов не настроен.")
    try:
        tls = ssl.create_default_context(cafile=str(ca))
    except OSError:
        raise denied(
            503, "identity_unavailable", "Центр сертификации издателя недоступен."
        ) from None
    return TokenVerifier(issuer, tls=tls)


def correlation_id(request_id: str) -> str:
    try:
        return UUID(request_id).hex
    except ValueError:
        return uuid4().hex


def bound_grant(
    request: Request,
    authorization: Annotated[str, Header()] = "",
    request_id: Annotated[str, Header(alias=REQUEST_ID_HEADER)] = "",
    certificate: Annotated[str, Header(alias=CERT_HEADER)] = "",
) -> ServiceGrant | None:
    config = settings()
    if config.service_auth_mode != "mtls_oauth":
        return None
    peer = request.client.host if request.client else ""
    workload, binding = identify_certificate(peer, certificate, interagent=True)
    scheme, _, token = authorization.partition(" ")
    verifier = bound_token_verifier(config.iam_issuer, config.iam_ca_file)
    grant = verifier.verify(
        token if scheme.lower() == "bearer" else "",
        request_id=correlation_id(request_id),
        binding=binding,
    )
    request.state.workload = workload
    return grant


BoundGrant = Annotated[ServiceGrant | None, Depends(bound_grant)]


def identify(
    request: Request,
    grant: BoundGrant,
    service_token: Annotated[str, Header(alias=SERVICE_HEADER)] = "",
    authorization: Annotated[str, Header()] = "",
    operator_authorization: Annotated[str, Header(alias=OPERATOR_HEADER)] = "",
    request_id: Annotated[str, Header(alias=REQUEST_ID_HEADER)] = "",
    certificate: Annotated[str, Header(alias=CERT_HEADER)] = "",
) -> Caller:
    """Определяет сервис и оператора для защищённого запроса исполнителя."""
    config = settings()
    if grant:
        grant.require(EXECUTOR_SCOPE)
        operator = config.identify_operator(operator_authorization).operator
        return Caller(operator=operator, service=grant.service)
    if config.service_auth_mode == "static":
        return config.authenticate(service_token, authorization)
    caller = config.identify_operator(authorization)
    if config.service_auth_mode == "certificate":
        peer = request.client.host if request.client else ""
        request.state.workload, _ = identify_certificate(peer, certificate)
        return caller
    token_verifier(config.iam_issuer).verify(service_token, request_id=correlation_id(request_id))
    return caller


VerifiedCaller = Annotated[Caller, Depends(identify)]


async def maintain_audit_retention() -> None:
    while True:
        await asyncio.sleep(60)
        try:
            await asyncio.to_thread(lambda: storage().prune_audit())
        except OSError, DatabaseError, PostgresError:
            logger.warning("Не удалось удалить устаревшие записи аудита")


@asynccontextmanager
async def lifespan(app: FastAPI):
    maintenance = asyncio.create_task(maintain_audit_retention())
    try:
        yield
    finally:
        maintenance.cancel()
        with suppress(asyncio.CancelledError):
            await maintenance


configure_logging("executor")
app = FastAPI(title="Исполнитель ИТ-операций", lifespan=lifespan)
logger = logging.getLogger(__name__)
resilience_slot = asyncio.Lock()


async def ready_store() -> RunStore | None:
    def probe() -> RunStore:
        store = storage()
        store.probe_readiness()
        return store

    try:
        async with asyncio.timeout(4):
            return await asyncio.to_thread(probe)
    except (OSError, DatabaseError, PostgresError, TimeoutError) as error:
        logger.warning("Проверка готовности хранилища класс=%s", type(error).__name__)
        return None


@app.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
async def readiness():
    if await ready_store() is None:
        return JSONResponse(status_code=503, content={"status": "unavailable"})
    return {"status": "ready"}


@app.get("/health/functional")
async def functional_health(caller: VerifiedCaller) -> DependencyHealth:
    caller.require_case(PROBE_CASE, "read")
    return await check_dependencies(execution_tools(synthetic=True), ready_store)


@app.exception_handler(OperationalError)
async def database_unavailable(request: Request, error: OperationalError):
    logger.warning(
        "Недоступна операция PostgreSQL метод=%s класс=%s", request.method, type(error).__name__
    )
    return JSONResponse(
        status_code=503,
        content={"detail": "Хранилище состояния временно недоступно."},
        headers={"X-Policy-Code": "storage_unavailable"},
    )


@app.exception_handler(TransactionRejected)
async def transaction_rejected(request: Request, error: TransactionRejected):
    logger.warning("Операция согласования отклонена код=%s путь=%s", error.code, request.url.path)
    return JSONResponse(
        status_code=error.status,
        content={"detail": str(error)},
        headers={"X-Policy-Code": error.code},
    )


@app.exception_handler(ApprovalRejected)
async def approval_rejected(request: Request, error: ApprovalRejected):
    status = {
        ApprovalCode.POLICY_UNAVAILABLE: 503,
        ApprovalCode.INVALID_DRAFT: 409,
        ApprovalCode.EVIDENCE_REQUIRED: 409,
        ApprovalCode.APPROVAL_EXPIRED: 409,
    }.get(error.block.code, 403)
    return JSONResponse(
        status_code=status,
        content={"detail": error.block.message},
        headers={"X-Policy-Code": error.block.code},
    )


@app.post("/tools")
async def execute(proposal: ToolProposal, caller: VerifiedCaller, request: Request) -> ToolResult:
    """Передаёт принятое предложение на проверку и возвращает исход чтения."""
    trace = received_run(request.headers, proposal.run_id, proposal.scenario_id)
    tool = proposal.action if proposal.action in {action.value for action in Action} else None
    with span("tool_execute", parent=trace, tool=tool) as operation:
        result = await authorized_tool(caller, proposal, storage(), tools=execution_tools())
        operation.code = result.code
        return result


@app.exception_handler(CaseError)
async def case_error(_request: Request, error: CaseError):
    logger.info("Операция рабочего обращения отклонена код=%s", error.code)
    return JSONResponse(
        status_code=error.status,
        content={"detail": str(error)},
        headers={"X-Policy-Code": error.code},
    )


@app.post("/delegation/tasks")
async def delegated_task(order: TaskOrder, caller: VerifiedCaller, request: Request) -> Evidence:
    caller.require_case(order.scenario_id, "read")
    trace = received_run(request.headers, order.run_id, order.scenario_id)
    store = storage()
    tools = execution_tools()

    async def read(proposal: ToolProposal) -> ToolResult:
        with span("tool_execute", tool=proposal.action) as operation:
            result = await authorized_tool(caller, proposal, store, tools=tools)
            operation.code = result.code
            return result

    with span("delegated_task", parent=trace, actor=order.role, task_id=order.task_id) as operation:
        evidence = await perform_task(DelegatedReader(order, read))
        operation.code = "reported"
        return evidence


@app.exception_handler(RequestValidationError)
async def invalid_executor_request(request: Request, error: RequestValidationError):
    if request.url.path == "/cases" or request.url.path.startswith("/cases/"):
        return JSONResponse(
            status_code=422, content={"detail": "Данные обращения не соответствуют схеме."}
        )
    if request.url.path == "/tools":
        logger.info("Предложение инструмента отклонено проверкой схемы")
        return JSONResponse(
            status_code=422, content={"detail": "Предложение не соответствует схеме инструмента."}
        )
    if request.url.path == "/delegation/tasks":
        logger.info("Задание делегирования отклонено проверкой схемы")
        return JSONResponse(
            status_code=422, content={"detail": "Задание содержит недопустимые поля или значения."}
        )
    if request.url.path == "/runs/with-support":
        return JSONResponse(status_code=422, content={"detail": "Карточка не соответствует схеме."})
    from fastapi.exception_handlers import request_validation_exception_handler

    return await request_validation_exception_handler(request, error)


@app.get("/identity")
def identity(caller: VerifiedCaller) -> Caller:
    return caller


@app.get("/audit")
def audit_history(scenario_id: str, caller: VerifiedCaller) -> AuditHistory:
    caller.require_case(scenario_id, "read")
    try:
        return storage().audit_history(scenario_id, settings().audit_checkpoint_db)
    except (OSError, DatabaseError, ValueError) as error:
        logger.warning("Проверка аудита недоступна обращение=%s", scenario_id)
        raise HTTPException(503, "Журнал или контрольная точка недоступны.") from error


@app.post("/audit-demo")
async def audit_demo(caller: VerifiedCaller) -> AuditComparison:
    caller.require_case("REQ-1842", "read")
    return await demonstrate_audit()


@app.get("/operation-metrics")
def operation_metrics(
    caller: VerifiedCaller,
    tool_minutes: ToolMinutes = DEFAULT_TOOL_MINUTES,
    scope: MetricsScope = "course",
) -> MetricsReport:
    scenarios = tuple(sorted(NOTIFICATION_REQUESTS))
    for scenario_id in scenarios:
        caller.require_case(scenario_id, "read")
    try:
        return storage().metrics_report(tool_minutes, scenarios if scope == "course" else None)
    except (OSError, DatabaseError, PostgresError) as error:
        logger.warning("Расчёт метрик недоступен окно=%s", tool_minutes)
        raise HTTPException(503, "Хранилище метрик временно недоступно.") from error


@app.get("/operation-metrics/demo")
def operation_metrics_demo(caller: VerifiedCaller) -> MetricsReport:
    caller.require_case("REQ-1842", "read")
    return demo_report(datetime.now(UTC))


@app.get("/anomalies")
def anomalies(scenario_id: str, caller: VerifiedCaller) -> AnomalyReport:
    caller.require_case(scenario_id, "read")
    try:
        return storage().anomaly_report(scenario_id)
    except (OSError, DatabaseError, PostgresError) as error:
        logger.warning("Не удалось проверить аномалии обращение=%s", scenario_id)
        raise HTTPException(503, "Журнал событий временно недоступен.") from error


@app.post("/anomalies/demo")
async def anomalies_demo(caller: VerifiedCaller) -> AnomalyReport:
    caller.require_case(DEMO_CASE, "read")
    return await demonstrate_anomalies()


@app.post("/resilience/demo")
async def resilience_demo(caller: VerifiedCaller) -> ResilienceReport:
    caller.require_case(RESILIENCE_CASE, "read")
    database = storage().postgres
    if database is None:
        raise HTTPException(409, "Запустите профиль PostgreSQL через scripts/start-resilience.ps1.")
    if resilience_slot.locked():
        raise HTTPException(409, "Проверка восстановления уже выполняется.")
    async with resilience_slot:
        try:
            return await demonstrate_resilience(database)
        except RecoveryFailed as error:
            logger.warning("Демонстрация восстановления прервана: %s", error)
            raise HTTPException(
                503,
                str(error),
                headers={"X-Policy-Code": "recovery_demo_unavailable"},
            ) from error


@app.post("/reliability/demo")
async def reliability_demo(caller: VerifiedCaller) -> ReliabilityReport:
    caller.require_case(RELIABILITY_CASE, "read")
    return await demonstrate_reliability()


@app.get("/runbooks/RB-NOTIFY-07")
async def read_notification_runbook(grant: BoundGrant) -> Observation:
    if grant is None:
        raise HTTPException(404, "Маршрут доступен в стенде mTLS и OAuth.")
    grant.require(RUNBOOK_SCOPE)
    result = await execution_tools().execute(
        ToolProposal(action=Action.INCIDENT, scenario_id="REQ-1842", run_id=uuid4().hex)
    )
    if result.observation is None:
        raise denied(
            404 if result.code == "runbook_not_found" else 503, result.code, result.message
        )
    logger.info("Выдан регламент RB-NOTIFY-07 сервис=%s запрос=%s", grant.service, grant.request_id)
    return result.observation


@app.get("/workload-identity")
def workload_identity(request: Request, caller: VerifiedCaller) -> WorkloadCertificate:
    certificate = getattr(request.state, "workload", None)
    if certificate is None:
        raise HTTPException(409, "Запустите стенд с сертификатами.")
    return certificate


@lru_cache(maxsize=1)
def tpm_verifier(public_key: Path) -> TpmVerifier:
    return TpmVerifier(public_key)


def workload_tpm() -> TpmVerifier:
    key = settings().tpm_public_key
    if key is None:
        raise HTTPException(409, "Запустите стенд с профилем TPM.")
    return tpm_verifier(key)


@app.post("/workload-identity/challenge")
def tpm_challenge(request: Request, caller: VerifiedCaller) -> Challenge:
    return workload_tpm().issue(caller, workload_identity(request, caller))


@app.post("/workload-identity/proof")
def tpm_proof(request: Request, caller: VerifiedCaller, proof: TpmProof) -> TpmResult:
    return workload_tpm().verify(caller, workload_identity(request, caller), proof)


@app.post("/zero-trust-demo")
async def zero_trust_demo(caller: VerifiedCaller) -> AccessComparison:
    """Сравнивает доступ к двум ресурсам для одного действия и вызывающей стороны."""
    results = []
    for resource in (NOTIFICATIONS, PAYMENTS):
        proposal = ToolProposal(
            action=Action.STATUS,
            scenario_id="REQ-1842",
            resource=resource,
            run_id=uuid4().hex,
        )
        try:
            result = await authorized_tool(caller, proposal, storage())
        except HTTPException as error:
            if error.status_code != 403:
                raise
            results.append(
                AccessExample(
                    resource=resource,
                    allowed=False,
                    code=error.headers["X-Policy-Code"],
                    message=error.detail,
                )
            )
        else:
            results.append(
                AccessExample(
                    resource=resource,
                    allowed=result.code == "ok",
                    code=result.code,
                    message=result.message,
                    source=result.observation.source if result.observation else None,
                )
            )
    return AccessComparison(
        service=caller.service,
        operator=caller.operator,
        action=Action.STATUS,
        results=results,
    )


@app.post("/source-access-demo")
async def source_access_demo(caller: VerifiedCaller) -> SourceAccessReport:
    return await demonstrate_source_access(caller, storage(), execution_tools())


@app.post("/outcome-comparison")
async def outcome_comparison(caller: VerifiedCaller) -> list[ComparedRun]:
    return [
        case.model_copy(update={"trace": run_for_viewer(case.trace, caller)})
        for case in await compare_outcomes()
    ]


@app.post("/fail-closed-demo")
async def fail_closed_demo(caller: VerifiedCaller) -> FailClosedComparison:
    return await demonstrate_fail_closed()


@app.post("/priority-hierarchy-demo")
async def priority_hierarchy_demo(caller: VerifiedCaller) -> HierarchyComparison:
    return await demonstrate_hierarchy()


@app.post("/registration-checks-demo")
async def registration_checks_demo(caller: VerifiedCaller) -> RegistrationComparison:
    return await demonstrate_registration_checks()


@app.post("/approval-timeout-demo")
async def approval_timeout_demo(caller: VerifiedCaller) -> ApprovalTimeoutComparison:
    return await demonstrate_approval_timeout()


@app.post("/runs", status_code=201)
def save(run: Run, caller: VerifiedCaller, request: Request) -> Run:
    return persist_run(run, caller, request)


@app.post("/runs/with-support", status_code=201)
def save_with_support(data: RunWithSupport, caller: VerifiedCaller, request: Request) -> Run:
    return persist_run(data.run, caller, request, support_export=data.support_export)


def persist_run(
    run: Run, caller: Caller, request: Request, *, support_export: SupportExport | None = None
) -> Run:
    caller.require_case(run.scenario_id, "save")
    if (
        run.incident_id is not None
        or run.publication is not None
        or run.manual_evidence
        or (run.degradation is not None and run.status != Phase.NEEDS_REVIEW)
        or run.status
        not in {
            Phase.AWAITING_APPROVAL,
            Phase.COMPLETED,
            Phase.NEEDS_REVIEW,
        }
    ):
        raise HTTPException(409, "Исполнитель принимает только результат разбора.")
    try:
        trace = received_run(request.headers, run.id, run.scenario_id)
        with span("persist_run", parent=trace):
            storage().save(run, caller, support_export=support_export)
    except RunConflict as error:
        raise HTTPException(409, str(error)) from error
    return run_for_viewer(run, caller)


def run_for_viewer(run: Run, caller: Caller) -> Run:
    source = Party.MASTER if run.delegation or run.coordination else Party.TRIAGE
    target = Party.DUTY if caller.operator == Operator.DUTY else Party.OBSERVER
    checks = list(run.flow_checks)
    information = run.information.forward(source, target, checks)
    return run.model_copy(update={"information": information, "flow_checks": checks})


@app.get("/runs")
def list_runs(scenario_id: str, caller: VerifiedCaller) -> list[RunSummary]:
    caller.require_case(scenario_id, "read")
    store = storage()
    if is_work_case(scenario_id):
        store.cases.get(scenario_id)
    return store.list_agent_runs(scenario_id)


@app.get("/runs/{run_id}")
def get_run(run_id: RunId, caller: VerifiedCaller, response: Response) -> Run:
    try:
        run = storage().get(run_id)
        caller.require_case(run.scenario_id, "read")
        response.headers["Cache-Control"] = "no-store"
        return run_for_viewer(run, caller)
    except KeyError as error:
        raise HTTPException(404, "Прогон не найден.") from error


@app.get("/runs/{run_id}/support-card")
def support_card(run_id: RunId, caller: VerifiedCaller, response: Response) -> SupportExport:
    try:
        card = storage().support_card(run_id, caller)
    except KeyError as error:
        raise HTTPException(404, "Карточка поддержки не найдена.") from error
    logger.info("Открыта карточка поддержки прогон=%s оператор=%s", run_id, caller.operator)
    response.headers["Cache-Control"] = "private, no-store"
    return card


def require_incident_scope(grant: BoundGrant) -> None:
    if grant is not None:
        grant.require(INCIDENT_SCOPE)


@app.get("/cases")
def list_cases(caller: VerifiedCaller) -> list[WorkCase]:
    return storage().cases.list()


@app.post("/cases", status_code=201, dependencies=[Depends(require_incident_scope)])
def create_case(data: CaseCreate, caller: VerifiedCaller) -> WorkCase:
    return storage().cases.create(data, caller)


@app.get("/cases/{case_id}")
def get_case(case_id: WorkCaseId, caller: VerifiedCaller) -> WorkCase:
    caller.require_case(case_id, "read")
    return storage().cases.get(case_id)


@app.put("/cases/{case_id}/evidence", dependencies=[Depends(require_incident_scope)])
def update_case(case_id: WorkCaseId, data: CaseEvidenceUpdate, caller: VerifiedCaller) -> WorkCase:
    return storage().cases.update(case_id, data, caller)


@app.post("/cases/{case_id}/close", dependencies=[Depends(require_incident_scope)])
def close_case(case_id: WorkCaseId, caller: VerifiedCaller) -> WorkCase:
    return storage().cases.close(case_id, caller)


@app.get("/cases/{case_id}/support-card")
def case_support(case_id: WorkCaseId, caller: VerifiedCaller, response: Response) -> SupportExport:
    result = storage().cases.support(case_id, caller)
    response.headers["Cache-Control"] = "private, no-store"
    return result


def approval_trace(store: RunStore, run_id: str, caller: Caller):
    with store.connection() as db:
        run = store.load(db, run_id)
    caller.require_case(run.scenario_id, "read")
    return run.trace_context()


@app.post("/runs/{run_id}/manual-evidence", dependencies=[Depends(require_incident_scope)])
async def manual_evidence(run_id: RunId, caller: VerifiedCaller) -> Run:
    try:
        store = storage()
        run = await asyncio.to_thread(store.manual_target, run_id, caller)
        with span("verify_manual_evidence", parent=run.trace_context()) as operation:
            try:
                async with asyncio.timeout(6):
                    steps = await read_manual_evidence(run, caller, store, execution_tools())
            except TimeoutError:
                steps = []
            result = await asyncio.to_thread(store.save_manual_evidence, run_id, caller, steps)
            if not steps:
                raise denied(
                    503,
                    "manual_evidence_unavailable",
                    "Не удалось подтвердить массовую задержку по источникам. Повторите проверку.",
                )
            operation.code = "manual_evidence_verified"
            return run_for_viewer(result, caller)
    except KeyError as error:
        raise HTTPException(404, "Прогон не найден.") from error
    except RunConflict as error:
        raise HTTPException(409, str(error)) from error


@app.post("/runs/{run_id}/manual-draft", dependencies=[Depends(require_incident_scope)])
def manual_draft(run_id: RunId, draft: ManualDraft, caller: VerifiedCaller) -> Run:
    try:
        store = storage()
        with span("prepare_manual_draft", parent=approval_trace(store, run_id, caller)):
            return run_for_viewer(store.prepare_manual_draft(run_id, caller, draft), caller)
    except KeyError as error:
        raise HTTPException(404, "Прогон не найден.") from error
    except RunConflict as error:
        raise HTTPException(409, str(error)) from error


@app.post("/transaction-token-demo")
async def transaction_token_demo(caller: VerifiedCaller) -> TransactionComparison:
    caller.require_case("REQ-1842", "read")
    return await demonstrate_transactions()


@app.post("/runs/{run_id}/approval-token", dependencies=[Depends(require_incident_scope)])
def issue_approval(
    run_id: RunId, intent: ApprovalIntent, caller: VerifiedCaller, response: Response
) -> ApprovalToken:
    try:
        store = storage()
        with span("issue_approval", parent=approval_trace(store, run_id, caller)):
            grant = store.issue_approval(run_id, intent, caller)
    except KeyError as error:
        raise HTTPException(404, "Прогон не найден.") from error
    except RunConflict as error:
        raise HTTPException(409, str(error)) from error
    response.headers["Cache-Control"] = "no-store"
    return grant


@app.post("/runs/{run_id}/resolution", dependencies=[Depends(require_incident_scope)])
def resolve(
    run_id: RunId,
    request: ResolveRequest,
    caller: VerifiedCaller,
    idempotency_key: Annotated[
        str | None, Header(alias=IDEMPOTENCY_HEADER, pattern=IDEMPOTENCY_PATTERN)
    ] = None,
) -> Run:
    try:
        store = storage()
        with span("resolve_approval", parent=approval_trace(store, run_id, caller)) as operation:
            result = store.resolve(
                run_id,
                request.decision,
                caller,
                transaction_token=request.transaction_token,
                idempotency_key=idempotency_key,
            )
            operation.code = result.status
            return run_for_viewer(result, caller)
    except KeyError as error:
        raise HTTPException(404, "Прогон не найден.") from error
    except RunConflict as error:
        raise HTTPException(409, str(error)) from error
