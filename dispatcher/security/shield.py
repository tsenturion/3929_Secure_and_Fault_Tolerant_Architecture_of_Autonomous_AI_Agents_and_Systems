from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from dispatcher.security.filters import display_text


class ShieldCheck(BaseModel):
    level: Literal["policy", "heuristics", "judge", "hitl"]
    code: str
    detail: str


class RiskInput(BaseModel):
    recent_reports: int
    snapshot_age_minutes: int
    oldest_message_minutes: int

    @property
    def stale(self) -> bool:
        return self.snapshot_age_minutes > 5

    @property
    def conflicting_signals(self) -> bool:
        return self.recent_reports >= 5 and self.stale


class RiskVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Literal["likely_incident", "insufficient_evidence", "low_risk"]
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("reason")
    @classmethod
    def filter_reason(cls, reason: str) -> str:
        safe = display_text(reason)
        if not safe:
            raise ValueError("Объяснение должно содержать текст.")
        return safe
