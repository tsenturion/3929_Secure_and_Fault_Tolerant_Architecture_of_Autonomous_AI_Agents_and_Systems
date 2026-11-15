from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from dispatcher.security.filters import display_text
from dispatcher.workflow.scenarios import Action, Scenario


class IncidentField(StrEnum):
    AFFECTED_REPORTS = "affected_reports"
    TECHNICAL_EVIDENCE = "technical_evidence"
    CUSTOMER_CONTACTS = "customer_contacts"


PUBLIC_FIELDS = (IncidentField.AFFECTED_REPORTS, IncidentField.TECHNICAL_EVIDENCE)


class Publication(BaseModel):
    model_config = ConfigDict(extra="forbid")

    affected_reports: int | None = None
    technical_evidence: str | None = None

    @field_validator("technical_evidence")
    @classmethod
    def filter_evidence(cls, detail: str | None) -> str | None:
        return display_text(detail) if detail is not None else None


def build_publication(scenario: Scenario, fields: list[IncidentField]) -> Publication:
    return Publication(
        affected_reports=(
            scenario.report_count if IncidentField.AFFECTED_REPORTS in fields else None
        ),
        technical_evidence=(
            f"{scenario.view.report} {scenario.read(Action.STATUS).summary}"
            if IncidentField.TECHNICAL_EVIDENCE in fields
            else None
        ),
    )
