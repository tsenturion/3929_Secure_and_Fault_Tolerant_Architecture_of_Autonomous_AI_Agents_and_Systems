from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

DEFAULT_POLICY_PATH = Path("config/on-call.json")
DEMO_OPERATOR = "duty_operator"


class ApprovalCode(StrEnum):
    ALLOWED = "allowed"
    DATA_POLICY_DENIED = "data_policy_denied"
    INVALID_DRAFT = "invalid_draft"
    CONFIRMATION_REQUIRED = "confirmation_required"
    EVIDENCE_REQUIRED = "evidence_required"
    APPROVAL_EXPIRED = "approval_expired"
    ASSIGNMENT_MISSING = "assignment_missing"
    NOT_ASSIGNED = "not_assigned"
    POLICY_UNAVAILABLE = "policy_unavailable"


class ApprovalDecision(BaseModel):
    code: ApprovalCode
    message: str


class ApprovalBlock(ApprovalDecision):
    at: datetime


class ApprovalRejected(Exception):
    def __init__(self, block: ApprovalBlock):
        super().__init__(block.message)
        self.block = block


class OnCallPolicy(BaseModel):
    """Расписание дежурных, назначенных на очереди регистрации."""

    model_config = ConfigDict(extra="forbid", strict=True)

    assignments: dict[str, Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]]


def check_assignment(path: Path, queue: str, operator: str) -> ApprovalDecision:
    """Читает расписание и разрешает запись при подтверждённом назначении оператора."""
    try:
        policy = OnCallPolicy.model_validate_json(path.read_bytes())
    except OSError, ValidationError:
        return ApprovalDecision(
            code=ApprovalCode.POLICY_UNAVAILABLE,
            message="Проверка полномочий недоступна. Повторите после восстановления расписания.",
        )

    assigned = policy.assignments.get(queue)
    if assigned is None:
        return ApprovalDecision(
            code=ApprovalCode.ASSIGNMENT_MISSING,
            message=f"Не удалось подтвердить полномочия оператора: у очереди «{queue}» нет дежурного.",
        )
    if assigned != operator:
        return ApprovalDecision(
            code=ApprovalCode.NOT_ASSIGNED,
            message=f"Регистрация доступна дежурному очереди «{queue}».",
        )
    return ApprovalDecision(
        code=ApprovalCode.ALLOWED,
        message="Полномочия дежурного подтверждены по расписанию.",
    )
