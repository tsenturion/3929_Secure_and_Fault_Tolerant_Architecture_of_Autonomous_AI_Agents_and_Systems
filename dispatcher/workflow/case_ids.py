import re
from typing import Annotated

from pydantic import StringConstraints

WORK_CASE_PATTERN = r"CASE-[0-9a-f]{32}"
CASE_PATTERN = rf"(?:REQ-[0-9]{{4}}|{WORK_CASE_PATTERN})"
ScenarioId = Annotated[str, StringConstraints(pattern=f"^{CASE_PATTERN}$")]
WorkCaseId = Annotated[str, StringConstraints(pattern=f"^{WORK_CASE_PATTERN}$")]


def is_work_case(value: str) -> bool:
    return re.fullmatch(WORK_CASE_PATTERN, value) is not None
