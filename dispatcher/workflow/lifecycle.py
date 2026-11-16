from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Phase(StrEnum):
    OBSERVE = "observe"
    REASON = "reason"
    ACT = "act"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVAL_EXPIRED = "approval_expired"
    COMPLETED = "completed"
    NEEDS_REVIEW = "needs_review"
    MANUAL_HANDOFF = "manual_handoff"
    MANUAL_COMPLETED = "manual_completed"
    FAILED = "failed"
    REJECTED = "rejected"


class Event(BaseModel):
    phase: Phase
    title: str
    detail: str
    at: datetime


TRANSITIONS = {
    None: {Phase.OBSERVE},
    Phase.OBSERVE: {Phase.REASON, Phase.NEEDS_REVIEW},
    Phase.REASON: {Phase.ACT, Phase.NEEDS_REVIEW},
    Phase.ACT: {
        Phase.OBSERVE,
        Phase.COMPLETED,
        Phase.AWAITING_APPROVAL,
        Phase.NEEDS_REVIEW,
        Phase.REJECTED,
        Phase.MANUAL_COMPLETED,
    },
    # Решение дежурного поступает в ожидающий прогон как новое наблюдение.
    Phase.AWAITING_APPROVAL: {Phase.OBSERVE, Phase.APPROVAL_EXPIRED},
    Phase.NEEDS_REVIEW: {Phase.MANUAL_HANDOFF},
    Phase.MANUAL_HANDOFF: {Phase.AWAITING_APPROVAL, Phase.MANUAL_COMPLETED, Phase.FAILED},
}


class Lifecycle(BaseModel):
    """История переходов прогона, последнее событие которой задаёт текущую фазу."""

    events: list[Event] = Field(default_factory=list)

    @property
    def phase(self) -> Phase:
        return self.events[-1].phase

    def move(self, phase: Phase, title: str, detail: str, *, at: datetime | None = None) -> None:
        """Проверяет переход из текущей фазы и добавляет событие с моментом перехода."""
        current = self.phase if self.events else None
        if phase not in TRANSITIONS.get(current, ()):
            raise ValueError(f"Недопустимый переход {current} → {phase}.")
        self.events.append(
            Event(phase=phase, title=title, detail=detail, at=at or datetime.now(UTC))
        )
