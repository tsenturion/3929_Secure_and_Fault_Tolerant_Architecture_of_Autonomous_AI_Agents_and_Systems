from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from dispatcher.security.data_exfiltration.publication import Publication
from dispatcher.workflow.case_ids import ScenarioId
from dispatcher.workflow.triage import Recommendation

IDEMPOTENCY_HEADER = "Idempotency-Key"
IDEMPOTENCY_PATTERN = r"^[0-9a-f]{32}$"
TRANSACTION_SECONDS = 30


class ApprovalIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: ScenarioId
    recommendation: Recommendation


class ApprovedParameters(ApprovalIntent):
    # При регистрации публикация сравнивается с той, которую дежурный согласовал.
    publication: Publication


class ApprovalToken(BaseModel):
    approval_id: str
    token: str = Field(repr=False)
    idempotency_key: str
    expires_at: datetime


class TransactionRejected(Exception):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status = status
        self.code = code


class TransactionComparison(BaseModel):
    changed_code: str
    incidents_after_change: int
    incident_id: str
    repeated_incident_id: str
    incident_count: int
