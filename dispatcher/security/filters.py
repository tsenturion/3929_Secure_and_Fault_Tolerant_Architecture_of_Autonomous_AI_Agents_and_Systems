import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.IGNORECASE)
QUEUE_MESSAGE_ID = re.compile(r"(?<![\w-])MSG-[A-Z0-9-]{1,48}(?![\w-])", re.IGNORECASE)
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
EMAIL_PLACEHOLDER = "[e-mail скрыт]"
MAX_REPORT_LENGTH = 1600


class SupportExport(BaseModel):
    """Схема входной выгрузки с описанием и отдельным полем контакта."""

    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)

    description: str = Field(min_length=1, max_length=MAX_REPORT_LENGTH)
    customer_email: str | None = Field(default=None, max_length=254)

    @field_validator("description", mode="before")
    @classmethod
    def valid_description(cls, text: object) -> object:
        if isinstance(text, str) and (len(text) > MAX_REPORT_LENGTH or CONTROL.search(text)):
            raise ValueError("Описание слишком длинное или содержит управляющие символы.")
        return text

    @field_validator("customer_email")
    @classmethod
    def valid_email(cls, text: str | None) -> str | None:
        if text is not None and not EMAIL.fullmatch(text):
            raise ValueError("Контакт должен быть адресом электронной почты.")
        return text


class FilterCheck(BaseModel):
    """Результат проверки входа или выхода для карточки прогона."""

    boundary: Literal["input", "output"]
    code: str
    detail: str


def redact_email(text: str) -> tuple[str, int]:
    """Возвращает очищенный текст и число адресов, заменённых маркером."""
    return EMAIL.subn(EMAIL_PLACEHOLDER, CONTROL.sub("", text))


def display_text(text: str) -> str:
    safe, _ = redact_email(text)
    return QUEUE_MESSAGE_ID.sub("[идентификатор скрыт]", safe).strip()
