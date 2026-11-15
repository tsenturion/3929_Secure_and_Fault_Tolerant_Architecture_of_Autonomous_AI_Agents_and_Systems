from enum import StrEnum
from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from dispatcher.identity.iam import AuthMode


class Provider(StrEnum):
    OPENAI = "openai"
    QWEN = "qwen"
    GIGACHAT = "gigachat"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    model_provider: Provider = Provider.OPENAI
    openai_api_key: SecretStr = SecretStr("")
    openai_model: str = "gpt-4.1-mini"
    gigachat_credentials: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("GIGACHAT_CREDENTIALS", "GIGACHAT_AUTH_KEY"),
    )
    gigachat_scope: str = "GIGACHAT_API_PERS"
    gigachat_model: str = "GigaChat-2"
    gigachat_ca_bundle_file: str = ""
    qwen_model_path: Path | None = None
    triage_max_steps: int = Field(default=5, ge=1, le=5)
    triage_timeout_seconds: float = Field(default=45, gt=0, le=120)
    executor_url: str = "http://127.0.0.1:8001"
    model_gateway_url: str = ""
    service_token: SecretStr = SecretStr("")
    service_auth_mode: AuthMode = "static"
    iam_issuer: str = ""
    iam_executor_client_secret: SecretStr = SecretStr("")
    iam_monitoring_client_secret: SecretStr = SecretStr("")
    iam_runbook_client_secret: SecretStr = SecretStr("")
    workload_tls_dir: Path = Path("certs/agent-identity/agent")
    tpm_signer_url: str = ""
    runbook_agent_url: str = ""
    loki_url: str = ""

    @field_validator("qwen_model_path", mode="before")
    @classmethod
    def empty_qwen_path(cls, value: object) -> object:
        # Пустой параметр в шаблоне означает, что веса ещё не выбраны.
        return None if value == "" else value
