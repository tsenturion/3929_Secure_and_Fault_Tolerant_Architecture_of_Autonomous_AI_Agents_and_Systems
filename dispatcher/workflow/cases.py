from datetime import UTC
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    computed_field,
    model_validator,
)

from dispatcher.security.filters import SupportExport
from dispatcher.workflow.case_ids import WorkCaseId
from dispatcher.workflow.lifecycle import Phase
from dispatcher.workflow.scenarios import (
    Monitoring,
    Observation,
    Scenario,
    ScenarioView,
    SourceKind,
)


class Symptom(StrEnum):
    DELAYED = "delayed_confirmation"
    MISSING = "missing_confirmation"


TITLES = {
    Symptom.DELAYED: "Задерживаются письма подтверждения заказа",
    Symptom.MISSING: "Покупатель не получил письмо подтверждения заказа",
}
Count = Annotated[StrictInt, Field(ge=0, le=1_000_000_000)]


class CaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    symptom: Symptom
    support: SupportExport


class CaseEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_at: AwareDatetime
    deployment_at: AwareDatetime
    report_count: Count
    queue_size: Count
    oldest_minutes: Count
    checkout_healthy: StrictBool

    @model_validator(mode="after")
    def chronology(self):
        if self.deployment_at > self.snapshot_at:
            raise ValueError("Снимок очереди должен быть снят после указанного развёртывания.")
        return self


class CaseEvidenceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: Annotated[StrictInt, Field(ge=1)]
    evidence: CaseEvidence


class CaseIncident(BaseModel):
    id: str
    run_id: str
    registered_at: AwareDatetime
    priority: Literal["P2"]


class WorkCase(BaseModel):
    id: WorkCaseId
    symptom: Symptom
    created_at: AwareDatetime
    revision: int
    closed_at: AwareDatetime | None = None
    evidence: CaseEvidence | None = None
    incident: CaseIncident | None = None
    analysis_status: Phase | None = None

    @computed_field
    @property
    def title(self) -> str:
        return TITLES[self.symptom]

    def scenario(self) -> Scenario:
        evidence = self.evidence
        assert evidence is not None
        observed_at = evidence.snapshot_at.astimezone(UTC).isoformat(timespec="minutes")
        deployment_at = evidence.deployment_at.astimezone(UTC).isoformat(timespec="minutes")
        return Scenario(
            view=ScenarioView(
                id=self.id,
                title=self.title,
                report=self.title,
                received_at=self.created_at.astimezone(UTC).isoformat(timespec="minutes"),
            ),
            monitoring=Monitoring(
                queue_size=evidence.queue_size,
                oldest_minutes=evidence.oldest_minutes,
                checkout_healthy=evidence.checkout_healthy,
                observed_at=evidence.snapshot_at.astimezone(UTC).strftime("%H:%M"),
            ),
            report_count=evidence.report_count,
            observed_since=observed_at,
            case_revision=self.revision,
            snapshot_at=evidence.snapshot_at,
            deployment=Observation(
                source="Журнал развёртываний · order-notifications",
                kind=SourceKind.DEPLOYMENT_LOG,
                observed_at=deployment_at,
                summary="Дежурный зафиксировал последнее развёртывание. Причина задержки уточняется.",
            ),
        )
