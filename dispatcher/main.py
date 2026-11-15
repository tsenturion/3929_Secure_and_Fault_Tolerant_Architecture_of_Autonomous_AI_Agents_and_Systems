import asyncio
import logging
import ssl
from dataclasses import replace
from functools import lru_cache
from typing import Annotated

import httpx2
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from dispatcher.identity.access import SERVICE_HEADER, Caller, Operator
from dispatcher.identity.iam import (
    AGENT_CLIENT,
    MONITOR_CLIENT,
    OPERATOR_HEADER,
    ServiceTokens,
    TokenServiceUnavailable,
)
from dispatcher.identity.transactions import (
    IDEMPOTENCY_HEADER,
    IDEMPOTENCY_PATTERN,
    ApprovalIntent,
    ApprovalToken,
    TransactionComparison,
)
from dispatcher.identity.workload_identity.workload import (
    Challenge,
    TpmProof,
    TpmResult,
    TpmSignature,
    WorkloadCertificate,
    client_tls,
)
from dispatcher.models.adapters import (
    GatewayModel,
    Model,
    ModelFailure,
    ModelUnavailable,
    create_model,
    provider_problem,
)
from dispatcher.multiagent.coordination.coordination_protocol import CoordinationMode
from dispatcher.multiagent.coordination.coordinator import CASE as COORDINATION_CASE
from dispatcher.multiagent.coordination.coordinator import coordinate
from dispatcher.multiagent.hierarchy.master_agent import ErrorFrame, RunFrame, hierarchy
from dispatcher.observability.anomaly_detection.anomalies import AnomalyReport
from dispatcher.observability.metrics import (
    DEFAULT_TOOL_MINUTES,
    MetricsReport,
    MetricsScope,
    ToolMinutes,
)
from dispatcher.observability.tamper_evident_audit.audit import AuditComparison, AuditHistory
from dispatcher.observability.tracing.diagnostics import configure_logging
from dispatcher.observability.tracing.telemetry import event, new_trace, span
from dispatcher.observability.tracing.trace_view import TraceView, read_trace
from dispatcher.resilience.distributed_recovery import ResilienceReport
from dispatcher.resilience.forecasting.forecast import (
    ForecastReplay,
    ForecastReport,
    ReplayStatus,
    forecast_report,
)
from dispatcher.resilience.functional_health import (
    PROBE_CASE,
    FunctionalHealth,
    HealthStatus,
    InferenceHealth,
)
from dispatcher.resilience.retry_and_circuit_breaker.reliability_demo import ReliabilityReport
from dispatcher.security.agent_threats.boundaries import Threat
from dispatcher.security.agent_threats.demonstrations import (
    CASES,
    DemonstrationModel,
    InvalidOutputModel,
    RepeatedMonitoringModel,
    ThreatCase,
    case_scenario,
)
from dispatcher.security.data_exfiltration.exfiltration_demo import CASE as EXFILTRATION_CASE
from dispatcher.security.data_exfiltration.exfiltration_demo import (
    CapturedOpenAI,
    ExfiltrationReport,
    support_sample,
)
from dispatcher.security.filters import FilterCheck, SupportExport, display_text, redact_email
from dispatcher.security.source_access.source_access_demo import SourceAccessReport
from dispatcher.security.tool_guardrails.guardrails import scope_for
from dispatcher.settings import Provider, Settings
from dispatcher.workflow.case_ids import WorkCaseId, is_work_case
from dispatcher.workflow.cases import CaseCreate, CaseEvidenceUpdate, WorkCase
from dispatcher.workflow.client import (
    ExecutorClient,
    ExecutorRejected,
    InteragentResult,
    ServiceTokenDemo,
)
from dispatcher.workflow.execution import (
    AccessComparison,
    ExecutorUnavailable,
    ResolveRequest,
    RunId,
    RunSummary,
)
from dispatcher.workflow.registration import ManualDraft
from dispatcher.workflow.scenarios import SCENARIOS, Fault, Scenario, ScenarioView
from dispatcher.workflow.triage import (
    ApprovalTimeoutComparison,
    ComparedRun,
    FailClosedComparison,
    HierarchyComparison,
    Mode,
    RegistrationComparison,
    Run,
    run_triage,
)


@lru_cache
def settings() -> Settings:
    return Settings()


@lru_cache(maxsize=1)
def executor_tokens() -> ServiceTokens:
    config = settings()
    return ServiceTokens(config.iam_issuer, AGENT_CLIENT, config.iam_executor_client_secret)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    mode: Mode
    fault: Fault | None = None
    support_export: SupportExport | None = None
    rules_only: bool = False


class CoordinationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: CoordinationMode


class HierarchyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slow_catalog: bool = False


def executor_tls(config: Settings) -> bool | ssl.SSLContext:
    if config.service_auth_mode not in {"certificate", "mtls_oauth"}:
        return True
    if not config.executor_url.startswith("https://"):
        raise ExecutorUnavailable("У исполнителя не настроен TLS.")
    return client_tls(config.workload_tls_dir)


async def executor_client(authorization: Annotated[str, Header()] = ""):
    if not authorization.lower().startswith("bearer ") or not authorization[7:].strip():
        raise HTTPException(401, "Введите ключ пользователя.")
    config = settings()
    bound = config.service_auth_mode == "mtls_oauth"
    headers = {OPERATOR_HEADER if bound else "Authorization": authorization}
    if config.service_auth_mode == "static":
        headers[SERVICE_HEADER] = config.service_token.get_secret_value()
    tls = executor_tls(config)
    tokens = None
    if bound:
        tokens = ServiceTokens(
            config.iam_issuer, AGENT_CLIENT, config.iam_executor_client_secret, tls=tls
        )
    elif config.service_auth_mode == "oauth":
        tokens = executor_tokens()
    async with httpx2.AsyncClient(
        base_url=config.executor_url,
        timeout=10,
        trust_env=False,
        headers=headers,
        verify=tls,
    ) as http:
        yield ExecutorClient(http, tokens, bound=bound)


Executor = Annotated[ExecutorClient, Depends(executor_client)]
configure_logging("dispatcher")
app = FastAPI(
    title="Диспетчер ИТ-обращений",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,
)
logger = logging.getLogger(__name__)
inference_health = InferenceHealth()
forecast_replay = ForecastReplay()


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, error: RequestValidationError):
    if request.url.path.rstrip("/") == "/api/runs":
        logger.info("Вход прогона отклонён: нарушение формата запроса")
        return JSONResponse(
            status_code=422,
            content={
                "code": "invalid_run_input",
                "detail": "Проверьте формат обращения, допустимые поля и длину описания.",
            },
        )
    return JSONResponse(status_code=422, content={"detail": "Запрос не соответствует схеме."})


@app.exception_handler(ExecutorUnavailable)
async def unavailable(request: Request, error: ExecutorUnavailable):
    logger.warning("Ошибка обмена с исполнителем метод=%s", request.method)
    return JSONResponse(status_code=503, content={"detail": str(error)})


@app.exception_handler(ExecutorRejected)
async def rejected(request: Request, error: ExecutorRejected):
    content = {"detail": str(error)}
    if error.code is not None:
        content["code"] = error.code
    return JSONResponse(status_code=error.status, content=content)


@app.exception_handler(TokenServiceUnavailable)
async def token_service_unavailable(request: Request, error: TokenServiceUnavailable):
    return JSONResponse(
        status_code=503, content={"code": "identity_unavailable", "detail": str(error)}
    )


@app.get("/api/scenarios")
def scenarios() -> list[ScenarioView]:
    return [scenario.view for scenario in SCENARIOS.values() if scope_for(scenario.view.id)]


@app.get("/api/health/live")
def liveness() -> dict[str, str]:
    return {"status": "live"}


@app.get("/api/health/ready")
async def readiness():
    config = settings()
    try:
        async with asyncio.timeout(5):
            async with httpx2.AsyncClient(
                base_url=config.executor_url, verify=executor_tls(config), trust_env=False
            ) as http:
                response = await http.get("/health/ready")
                if response.status_code == 200 and response.json() == {"status": "ready"}:
                    return {"status": "ready"}
    except httpx2.HTTPError, ExecutorUnavailable, OSError, TimeoutError, ValueError:
        pass
    return JSONResponse(status_code=503, content={"status": "unavailable"})


def model_problem(config: Settings) -> str | None:
    if config.model_gateway_url and config.model_provider != Provider.QWEN:
        return GatewayModel(config).problem()
    return provider_problem(config)


@app.get("/api/health/functional", response_model=FunctionalHealth)
async def functional_health(
    executor: Executor, background: bool = False
) -> FunctionalHealth | JSONResponse:
    reserved = background and forecast_replay.status().throttled
    if reserved:
        await executor.identity()
        delay = forecast_replay.wait_for_background()
        if delay:
            logger.info("Фоновая проверка отложена прогнозом задержка_сек=%d", delay)
            return JSONResponse(
                status_code=429,
                content={
                    "code": "forecast_deferred",
                    "detail": "Фоновая диагностика отложена по прогнозу.",
                },
                headers={"Retry-After": str(delay)},
            )
        forecast_replay.record_background()
    config = settings()
    dependencies = await executor.functional_health()
    problem = await asyncio.to_thread(model_problem, config)
    model = inference_health.check(config.model_provider, problem)
    report = FunctionalHealth(**dependencies.model_dump(), model=model)
    if model.status == HealthStatus.DEGRADED:
        report.status = HealthStatus.DEGRADED
    if background and not reserved:
        forecast_replay.record_background()
    return report


async def load_forecast() -> ForecastReport:
    try:
        return await asyncio.to_thread(forecast_report)
    except (OSError, ValidationError) as error:
        logger.warning("Прогноз LSTM недоступен класс=%s", type(error).__name__)
        raise HTTPException(503, "Веса LSTM недоступны или не прошли проверку.") from error


@app.get("/api/forecast")
async def forecast(executor: Executor) -> ForecastReport:
    (await executor.identity()).require_case(PROBE_CASE, "read")
    return await load_forecast()


@app.get("/api/forecast/replay")
async def forecast_status(executor: Executor) -> ReplayStatus:
    (await executor.identity()).require_case(PROBE_CASE, "read")
    return forecast_replay.status()


@app.post("/api/forecast/replay")
async def start_forecast_replay(executor: Executor) -> ReplayStatus:
    caller = await executor.identity()
    caller.require_case(PROBE_CASE, "read")
    if caller.operator != Operator.DUTY:
        raise HTTPException(403, "Воспроизведение запускает дежурный.")
    return forecast_replay.start(await load_forecast())


@app.get("/api/model")
def model_configuration() -> dict[str, str | bool | None]:
    config = settings()
    return {
        "provider": config.model_provider,
        "problem": model_problem(config),
        "service_auth_mode": config.service_auth_mode,
        "tpm_enabled": bool(config.tpm_signer_url) and config.service_auth_mode == "certificate",
    }


@app.get("/api/threat-cases")
def threat_cases() -> list[ThreatCase]:
    return list(CASES.values())


@app.post("/api/threat-cases/{threat}/runs")
async def run_threat_case(threat: Threat, executor: Executor) -> Run:
    scenario = case_scenario(threat, SCENARIOS["REQ-1842"])
    with span("triage", parent=new_trace(scenario.view.id)) as operation:
        result = await run_triage(
            scenario, Mode.AGENT, DemonstrationModel(threat), threat=threat, executor=executor
        )
        stored = await executor.save(result)
        operation.code = stored.status
        return stored


@app.post("/api/outcome-comparison")
async def outcome_comparison(executor: Executor) -> list[ComparedRun]:
    return await executor.compare_outcomes()


@app.post("/api/fail-closed-demo")
async def fail_closed_demo(executor: Executor) -> FailClosedComparison:
    return await executor.demonstrate_fail_closed()


@app.post("/api/priority-hierarchy-demo")
async def priority_hierarchy_demo(executor: Executor) -> HierarchyComparison:
    return await executor.demonstrate_hierarchy()


@app.post("/api/registration-checks-demo")
async def registration_checks_demo(executor: Executor) -> RegistrationComparison:
    return await executor.demonstrate_registration_checks()


@app.post("/api/approval-timeout-demo")
async def approval_timeout_demo(executor: Executor) -> ApprovalTimeoutComparison:
    return await executor.demonstrate_approval_timeout()


@app.post("/api/zero-trust-demo")
async def zero_trust_demo(executor: Executor) -> AccessComparison:
    return await executor.demonstrate_zero_trust()


@app.post("/api/source-access-demo")
async def source_access_demo(executor: Executor) -> SourceAccessReport:
    return await executor.demonstrate_source_access()


@app.post("/api/service-token-demo")
async def service_token_demo(executor: Executor) -> ServiceTokenDemo:
    config = settings()
    if config.service_auth_mode != "oauth":
        raise HTTPException(409, "Запустите стенд с Keycloak.")
    # Ожидающий истечения токен демо не попадает в общий кэш агента.
    agent = ServiceTokens(config.iam_issuer, AGENT_CLIENT, config.iam_executor_client_secret)
    monitor = ServiceTokens(config.iam_issuer, MONITOR_CLIENT, config.iam_monitoring_client_secret)
    return await ExecutorClient(executor.http, agent).demonstrate_service_tokens(monitor)


@app.get("/api/workload-identity")
async def workload_identity(executor: Executor) -> WorkloadCertificate:
    return await executor.request("GET", "/workload-identity", WorkloadCertificate)


@app.post("/api/interagent-demo")
async def interagent_demo(executor: Executor) -> InteragentResult:
    config = settings()
    if config.service_auth_mode != "mtls_oauth" or not config.runbook_agent_url.startswith(
        "https://"
    ):
        raise HTTPException(409, "Запустите стенд межагентной аутентификации.")
    await executor.identity()
    tls = client_tls(config.workload_tls_dir)
    try:
        async with httpx2.AsyncClient(timeout=40, verify=tls, trust_env=False) as http:
            response = await http.post(f"{config.runbook_agent_url.rstrip('/')}/demo")
        response.raise_for_status()
        return TypeAdapter(InteragentResult).validate_json(response.content)
    except httpx2.HTTPError, httpx2.InvalidURL, ValidationError:
        logger.warning("Демонстрация межагентной аутентификации не завершилась")
        raise HTTPException(503, "Агент регламентов не вернул результаты проверки.") from None


class TpmDemonstration(BaseModel):
    proof: TpmResult
    replay_blocked: bool


@app.post("/api/workload-identity/tpm-proof")
async def tpm_proof(executor: Executor) -> TpmDemonstration:
    config = settings()
    if config.service_auth_mode != "certificate" or not config.tpm_signer_url:
        raise HTTPException(409, "Запустите стенд с профилем TPM.")
    challenge = await executor.request("POST", "/workload-identity/challenge", Challenge)
    try:
        async with httpx2.AsyncClient(timeout=8, trust_env=False) as http:
            response = await http.post(
                f"{config.tpm_signer_url.rstrip('/')}/sign", json=challenge.model_dump()
            )
        response.raise_for_status()
        signature = TpmSignature.model_validate_json(response.content)
    except httpx2.HTTPError, httpx2.InvalidURL, ValidationError:
        logger.warning("Не удалось получить подпись программного TPM")
        raise HTTPException(503, "Программный TPM недоступен.") from None

    proof = TpmProof(nonce=challenge.nonce, signature=signature.signature)
    path = "/workload-identity/proof"
    result = await executor.request("POST", path, TpmResult, json=proof.model_dump())
    try:
        await executor.request("POST", path, TpmResult, json=proof.model_dump())
    except ExecutorRejected as error:
        if error.status == 409 and error.code == "challenge_inactive":
            return TpmDemonstration(proof=result, replay_blocked=True)
        raise
    return TpmDemonstration(proof=result, replay_blocked=False)


@app.get("/api/identity")
async def identity(executor: Executor) -> Caller:
    return await executor.identity()


@app.get("/api/cases")
async def list_cases(executor: Executor, response: Response) -> list[WorkCase]:
    response.headers["Cache-Control"] = "private, no-store"
    return await executor.list_cases()


@app.post("/api/cases", status_code=201)
async def create_case(data: CaseCreate, executor: Executor) -> WorkCase:
    return await executor.create_case(data)


@app.get("/api/cases/{case_id}")
async def get_case(case_id: WorkCaseId, executor: Executor, response: Response) -> WorkCase:
    response.headers["Cache-Control"] = "private, no-store"
    return await executor.get_case(case_id)


@app.put("/api/cases/{case_id}/evidence")
async def update_case(
    case_id: WorkCaseId, data: CaseEvidenceUpdate, executor: Executor
) -> WorkCase:
    return await executor.update_case(case_id, data)


@app.post("/api/cases/{case_id}/close")
async def close_case(case_id: WorkCaseId, executor: Executor) -> WorkCase:
    return await executor.close_case(case_id)


@app.get("/api/cases/{case_id}/support-card")
async def case_support(
    case_id: WorkCaseId, executor: Executor, response: Response
) -> SupportExport:
    response.headers["Cache-Control"] = "private, no-store"
    return await executor.case_support(case_id)


@app.post("/api/runs")
async def run(request: RunRequest, executor: Executor) -> Run:
    if is_work_case(request.scenario_id):
        (await executor.identity()).require_duty()
        if (
            request.mode != Mode.AGENT
            or request.fault is not None
            or request.support_export is not None
        ):
            raise HTTPException(422, "Рабочий разбор использует сохранённые данные обращения.")
        case = await executor.get_case(request.scenario_id)
        if case.closed_at is not None:
            raise HTTPException(409, "Рабочее обращение закрыто.")
        if case.evidence is None:
            raise HTTPException(409, "Добавьте данные мониторинга и развёртывания.")
        # Рабочий прогон получает публичный срез с версией фактов. Оригинал хранится в закрытой карточке.
        scenario = case.scenario()
    else:
        if request.rules_only:
            raise HTTPException(422, "Разбор по регламенту доступен в рабочей очереди.")
        scenario = SCENARIOS.get(request.scenario_id)
    if scenario is None:
        raise HTTPException(404, "Обращение не найдено.")
    if scope_for(request.scenario_id) is None:
        raise HTTPException(403, "Для обращения не задана область действий.")
    with span("triage", parent=new_trace(scenario.view.id)) as operation:
        result = await process_run(request, executor, scenario)
        operation.code = result.status
        return result


@app.post("/api/exfiltration/runs")
async def exfiltration_run(executor: Executor) -> ExfiltrationReport:
    scenario = SCENARIOS[EXFILTRATION_CASE]
    capture = CapturedOpenAI()
    request = RunRequest(
        scenario_id=EXFILTRATION_CASE, mode=Mode.AGENT, support_export=support_sample()
    )
    with span("triage", parent=new_trace(EXFILTRATION_CASE)) as operation:
        result = await process_run(request, executor, scenario, model_override=capture.model)
        operation.code = result.status
        return ExfiltrationReport(run=result, requests=capture.requests)


@app.post("/api/coordination/runs")
async def coordination_run(request: CoordinationRequest, executor: Executor) -> Run:
    (await executor.identity()).require_case(COORDINATION_CASE, "read")
    with span("coordination_run", parent=new_trace(COORDINATION_CASE)) as operation:
        run = await coordinate(request.mode, executor)
        saved = await executor.save(run)
        operation.code = saved.status
        return saved


@app.post("/api/hierarchy/runs", response_class=StreamingResponse)
async def hierarchy_run(request: HierarchyRequest, executor: Executor) -> StreamingResponse:
    (await executor.identity()).require_case(COORDINATION_CASE, "read")

    async def stream():
        with span("hierarchy_run", parent=new_trace(COORDINATION_CASE)) as operation:
            try:
                async for frame in hierarchy(
                    executor.perform_delegation, slow_catalog=request.slow_catalog
                ):
                    if isinstance(frame, RunFrame):
                        frame.run = await executor.save(frame.run)
                        operation.code = frame.run.status
                    yield frame.model_dump_json() + "\n"
            except (ExecutorRejected, ExecutorUnavailable, TokenServiceUnavailable) as error:
                operation.code = "executor_unavailable"
                logger.warning("Иерархический разбор прерван класс=%s", type(error).__name__)
                yield (
                    ErrorFrame(
                        detail="Исполнитель не завершил иерархический разбор."
                    ).model_dump_json()
                    + "\n"
                )

    return StreamingResponse(
        stream(),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


async def process_run(
    request: RunRequest,
    executor: Executor,
    scenario: Scenario,
    *,
    model_override: Model | None = None,
) -> Run:
    await executor.identity()
    input_checks = ()
    if request.support_export is not None:
        report, redacted = redact_email(request.support_export.description)
        excluded = request.support_export.customer_email is not None
        input_checks = (
            FilterCheck(
                boundary="input",
                code="input_redacted" if redacted or excluded else "input_validated",
                detail=(
                    f"Адресов скрыто в тексте: {redacted}. "
                    + ("Поле контакта исключено. " if excluded else "")
                    + "Для модели подготовлены описание, число обращений и время начала наблюдения."
                ),
            ),
        )
        scenario = replace(
            scenario, view=scenario.view.model_copy(update={"report": display_text(report)})
        )
        event(
            "egress_boundary",
            "input_filtered",
            symptom=scenario.view.title,
            affected_reports=str(scenario.report_count),
        )
    config = settings()
    model = None
    judge = None
    provider = None
    model_problem = None
    if model_override is not None:
        model = model_override
    elif request.fault == Fault.MODEL_UNAVAILABLE:
        if request.mode != Mode.AGENT:
            raise HTTPException(422, "Отказ модели показывается в агентном режиме.")
        provider = config.model_provider
        model_problem = ModelUnavailable(
            "Выбранная модель не ответила после чтения состояния очереди.", ModelFailure.TIMEOUT
        )
    elif request.fault == Fault.INVALID_MODEL_OUTPUT:
        if request.mode != Mode.AGENT:
            raise HTTPException(422, "Проверка ответа модели доступна в агентном режиме.")
        model = InvalidOutputModel()
    elif request.fault == Fault.REPEATED_MONITORING:
        if request.mode != Mode.AGENT:
            raise HTTPException(422, "Повторное чтение показывается в агентном режиме.")
        model = RepeatedMonitoringModel()
    elif (
        not request.rules_only
        and request.fault not in {Fault.MONITORING_TIMEOUT, Fault.OVERSIZED_OBSERVATION}
        and (request.mode == Mode.AGENT or request.fault == Fault.STALE_MONITORING)
    ):
        provider = config.model_provider
        try:
            model = create_model(config)
            judge = model
        except ModelUnavailable as error:
            model_problem = error
    result = await run_triage(
        scenario,
        request.mode,
        model,
        provider,
        executor=executor,
        max_steps=config.triage_max_steps,
        timeout=config.triage_timeout_seconds,
        fault=request.fault,
        judge=judge,
        input_checks=input_checks,
        model_problem=model_problem,
        rules_only=request.rules_only,
    )
    if request.fault is None and result.model_result is not None and provider is not None:
        inference_health.record(provider, result.model_result)
    if request.support_export is not None:
        return await executor.save(result, support_export=request.support_export)
    return await executor.save(result)


@app.get("/api/runs")
async def list_runs(scenario_id: str, executor: Executor) -> list[RunSummary]:
    return await executor.list_runs(scenario_id)


@app.get("/api/runs/{run_id}")
async def get_run(run_id: RunId, executor: Executor, response: Response) -> Run:
    response.headers["Cache-Control"] = "private, no-store"
    return await executor.get(run_id)


@app.get("/api/runs/{run_id}/trace")
async def run_trace(run_id: RunId, executor: Executor) -> TraceView:
    run = await executor.get(run_id)
    return await read_trace(run, settings().loki_url)


@app.get("/api/runs/{run_id}/support-card")
async def read_support_card(run_id: RunId, executor: Executor, response: Response) -> SupportExport:
    card = await executor.support_card(run_id)
    response.headers["Cache-Control"] = "private, no-store"
    return card


@app.post("/api/runs/{run_id}/manual-evidence")
async def manual_evidence(run_id: RunId, executor: Executor) -> Run:
    return await executor.manual_evidence(run_id)


@app.post("/api/runs/{run_id}/manual-draft")
async def manual_draft(run_id: RunId, draft: ManualDraft, executor: Executor) -> Run:
    return await executor.manual_draft(run_id, draft)


@app.post("/api/runs/{run_id}/resolution")
async def resolve_run(
    run_id: RunId,
    request: ResolveRequest,
    executor: Executor,
    idempotency_key: Annotated[
        str | None, Header(alias=IDEMPOTENCY_HEADER, pattern=IDEMPOTENCY_PATTERN)
    ] = None,
) -> Run:
    return await executor.resolve(run_id, request, idempotency_key)


@app.post("/api/runs/{run_id}/approval-token")
async def issue_approval(
    run_id: RunId, intent: ApprovalIntent, executor: Executor, response: Response
) -> ApprovalToken:
    grant = await executor.issue_approval(run_id, intent)
    response.headers["Cache-Control"] = "no-store"
    return grant


@app.post("/api/transaction-token-demo")
async def transaction_token_demo(executor: Executor) -> TransactionComparison:
    return await executor.demonstrate_transactions()


@app.get("/api/audit")
async def audit_history(scenario_id: str, executor: Executor) -> AuditHistory:
    return await executor.audit_history(scenario_id)


@app.post("/api/audit-demo")
async def audit_demo(executor: Executor) -> AuditComparison:
    return await executor.demonstrate_audit()


@app.get("/api/metrics")
async def operation_metrics(
    executor: Executor,
    tool_minutes: ToolMinutes = DEFAULT_TOOL_MINUTES,
    scope: MetricsScope = "course",
) -> MetricsReport:
    return await executor.operation_metrics(tool_minutes, scope)


@app.get("/api/metrics/demo")
async def operation_metrics_demo(executor: Executor) -> MetricsReport:
    return await executor.operation_metrics_demo()


@app.get("/api/anomalies")
async def anomalies(scenario_id: str, executor: Executor) -> AnomalyReport:
    return await executor.anomalies(scenario_id)


@app.post("/api/anomalies/demo")
async def anomalies_demo(executor: Executor) -> AnomalyReport:
    return await executor.anomalies_demo()


@app.post("/api/resilience/demo")
async def resilience_demo(executor: Executor) -> ResilienceReport:
    return await executor.resilience_demo()


@app.post("/api/reliability/demo")
async def reliability_demo(executor: Executor) -> ReliabilityReport:
    return await executor.reliability_demo()
