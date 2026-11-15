import logging
from functools import lru_cache
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from dispatcher.identity.access import SERVICE_HEADER, matches
from dispatcher.models.adapters import (
    Decision,
    GigaChatModel,
    ModelError,
    ModelUnavailable,
    OpenAIModel,
    OutputRejected,
    provider_problem,
)
from dispatcher.observability.tracing.diagnostics import configure_logging
from dispatcher.observability.tracing.telemetry import receive, span
from dispatcher.security.data_exfiltration.egress import allowed_context
from dispatcher.security.shield import RiskInput, RiskVerdict
from dispatcher.settings import Provider, Settings
from dispatcher.workflow.scenarios import ACTION_LABELS, Action

configure_logging("model-gateway")
logger = logging.getLogger(__name__)
app = FastAPI(title="Шлюз облачных моделей", docs_url=None, redoc_url=None)


class ModelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["openai", "gigachat"]
    model: str = Field(min_length=1, max_length=120)


class DecisionRequest(ModelRequest):
    context: str = Field(max_length=16_000)
    available: list[Action] = Field(min_length=1, max_length=len(Action))

    @field_validator("context")
    @classmethod
    def filter_context(cls, context: str) -> str:
        # Сервисный токен подтверждает вызывающий компонент. Схему запроса проверяет сам шлюз.
        return allowed_context(context)


class JudgeRequest(ModelRequest):
    evidence: RiskInput


@app.exception_handler(RequestValidationError)
async def invalid_request(_request: Request, _error: RequestValidationError):
    logger.info("Запрос к модели отклонён проверкой схемы")
    return JSONResponse(status_code=422, content={"detail": "Запрос не соответствует схеме."})


@lru_cache
def settings() -> Settings:
    return Settings()


def authorized(service_token: Annotated[str, Header(alias=SERVICE_HEADER)] = "") -> None:
    expected = settings().service_token.get_secret_value()
    if len(expected) < 32:
        raise HTTPException(503, "Ключ шлюза моделей не настроен.")
    if not matches(service_token, expected):
        raise HTTPException(401, "Личность сервиса не подтверждена.")


def provider_settings(request: ModelRequest) -> Settings:
    return settings().model_copy(
        update={
            "model_provider": Provider(request.provider),
            "model_gateway_url": "",
            "openai_model": request.model,
            "gigachat_model": request.model,
        }
    )


def cloud_model(request: ModelRequest) -> OpenAIModel | GigaChatModel:
    config = provider_settings(request)
    problem = provider_problem(config)
    if problem:
        raise HTTPException(503, problem)
    return (
        OpenAIModel(config) if config.model_provider == Provider.OPENAI else GigaChatModel(config)
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/status", dependencies=[Depends(authorized)])
def status(request: ModelRequest) -> dict[str, str | None]:
    return {"problem": provider_problem(provider_settings(request))}


@app.post("/decide", dependencies=[Depends(authorized)])
def decide(request: DecisionRequest, http: Request) -> Decision:
    with span("provider_decide", parent=receive(http.headers), provider=request.provider):
        return decide_with_provider(request)


def decide_with_provider(request: DecisionRequest) -> Decision:
    model = cloud_model(request)
    try:
        result = model.decide(
            request.context, {action: ACTION_LABELS[action] for action in request.available}
        )
    except OutputRejected as error:
        logger.warning(
            "Шлюз провайдер=%s операция=decide результат=invalid_output", request.provider
        )
        raise HTTPException(422, str(error)) from error
    except ModelError as error:
        logger.warning(
            "Шлюз провайдер=%s операция=decide результат=provider_error", request.provider
        )
        headers = {"X-Model-Code": error.code} if isinstance(error, ModelUnavailable) else None
        raise HTTPException(503, str(error), headers=headers) from error
    logger.info("Шлюз провайдер=%s операция=decide результат=ok", request.provider)
    return result


@app.post("/judge", dependencies=[Depends(authorized)])
def judge(request: JudgeRequest, http: Request) -> RiskVerdict:
    with span("provider_judge", parent=receive(http.headers), provider=request.provider):
        return judge_with_provider(request)


def judge_with_provider(request: JudgeRequest) -> RiskVerdict:
    model = cloud_model(request)
    try:
        result = model.judge(request.evidence)
    except OutputRejected as error:
        logger.warning(
            "Шлюз провайдер=%s операция=judge результат=invalid_output", request.provider
        )
        raise HTTPException(422, str(error)) from error
    except ModelError as error:
        logger.warning(
            "Шлюз провайдер=%s операция=judge результат=provider_error", request.provider
        )
        raise HTTPException(503, str(error)) from error
    logger.info("Шлюз провайдер=%s операция=judge результат=ok", request.provider)
    return result
