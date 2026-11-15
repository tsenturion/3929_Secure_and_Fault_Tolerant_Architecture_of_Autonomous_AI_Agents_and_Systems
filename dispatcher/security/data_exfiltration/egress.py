from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from dispatcher.security.filters import display_text
from dispatcher.workflow.scenarios import Action

SafeText = Annotated[str, AfterValidator(display_text)]


class EgressFields(BaseModel):
    # Допустимые поля перечислены на каждом уровне, включая вложенную телеметрию.
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class QueueMetrics(EgressFields):
    queue_size: int | None = Field(default=None, ge=0)
    oldest_minutes: int | None = Field(default=None, ge=0)
    channel: Literal["email", "push", "sms"] | None = None


class ReportSummary(EgressFields):
    report_count: int = Field(alias="число обращений", ge=0)
    observed_since: SafeText = Field(alias="начало наблюдения")


class ModelObservation(EgressFields):
    action: Action = Field(alias="действие")
    source: SafeText = Field(alias="источник")
    time: SafeText = Field(alias="время")
    summary: SafeText = Field(alias="содержание")
    queue_metrics: QueueMetrics | None = Field(default=None, alias="телеметрия очереди")


class ModelContext(EgressFields):
    report: SafeText = Field(alias="обращение")
    summary: ReportSummary = Field(alias="сводка")
    observations: list[ModelObservation] = Field(alias="наблюдения")
    actions: dict[Action, SafeText] = Field(alias="доступные действия")


def allowed_context(context: str) -> str:
    return ModelContext.model_validate_json(context).model_dump_json(
        by_alias=True, exclude_none=True
    )
