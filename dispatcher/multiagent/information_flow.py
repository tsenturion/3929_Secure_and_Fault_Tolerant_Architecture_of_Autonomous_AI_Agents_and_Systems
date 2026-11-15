import logging
import re
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, model_validator

from dispatcher.observability.tracing.telemetry import event

logger = logging.getLogger(__name__)
MessageId = Annotated[str, Field(pattern=r"^MSG-[A-Z0-9-]{1,48}$")]


class Level(StrEnum):
    SHARED = "shared"
    DUTY_ONLY = "duty_only"


class Key(StrEnum):
    QUEUE_SIZE = "queue_size"
    OLDEST_MINUTES = "oldest_minutes"
    CHANNEL = "channel"
    MESSAGE_IDS = "message_ids"
    RUNBOOK_ID = "runbook_id"


class Party(StrEnum):
    MONITORING = "monitoring"
    CATALOG = "catalog"
    DIAGNOSTIC = "diagnostic"
    RUNBOOK = "runbook"
    MASTER = "master"
    TRIAGE = "triage"
    MODEL = "model"
    DUTY = "duty"
    OBSERVER = "observer"


QUEUE = frozenset({Key.QUEUE_SIZE, Key.OLDEST_MINUTES, Key.CHANNEL})
DIAGNOSIS = QUEUE | {Key.MESSAGE_IDS}
REGULATION = frozenset({Key.RUNBOOK_ID})
# Разрешение зависит одновременно от пары ролей и метки поля; отсутствие пары закрывает поток.
POLICY = {
    (Party.MONITORING, Party.DIAGNOSTIC): DIAGNOSIS,
    (Party.MONITORING, Party.TRIAGE): DIAGNOSIS,
    (Party.CATALOG, Party.RUNBOOK): REGULATION,
    (Party.DIAGNOSTIC, Party.MASTER): DIAGNOSIS,
    (Party.DIAGNOSTIC, Party.RUNBOOK): QUEUE,
    (Party.MASTER, Party.RUNBOOK): QUEUE,
    (Party.RUNBOOK, Party.MASTER): REGULATION,
    (Party.RUNBOOK, Party.DIAGNOSTIC): REGULATION,
    (Party.TRIAGE, Party.MODEL): QUEUE,
    (Party.MASTER, Party.DUTY): DIAGNOSIS | REGULATION,
    (Party.MASTER, Party.OBSERVER): QUEUE | REGULATION,
    (Party.TRIAGE, Party.DUTY): DIAGNOSIS | REGULATION,
    (Party.TRIAGE, Party.OBSERVER): QUEUE | REGULATION,
}
DUTY_READERS = {Party.DIAGNOSTIC, Party.MASTER, Party.TRIAGE, Party.DUTY}


class DataField(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key: Key
    level: Level
    value: StrictInt | StrictStr | tuple[MessageId, ...]

    @model_validator(mode="after")
    def check_value(self):
        if self.key in {Key.QUEUE_SIZE, Key.OLDEST_MINUTES}:
            valid = type(self.value) is int and 0 <= self.value
        elif self.key == Key.CHANNEL:
            valid = self.value in ("email", "push", "sms")
        elif self.key == Key.MESSAGE_IDS:
            valid = (
                self.level == Level.DUTY_ONLY
                and isinstance(self.value, tuple)
                and 0 < len(self.value) <= 8
            )
        else:
            valid = isinstance(self.value, str) and bool(
                re.fullmatch(r"RB-NOTIFY-(03|07)", self.value)
            )
        if not valid:
            raise ValueError("Поле не соответствует типу или обязательной метке доступа.")
        return self


class FlowCheck(BaseModel):
    source: Party
    destination: Party
    passed: list[Key]
    blocked: list[Key]


class FlowData(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fields: tuple[DataField, ...] = ()

    @model_validator(mode="after")
    def unique_fields(self):
        if len({field.key for field in self.fields}) != len(self.fields):
            raise ValueError("Пакет IFC содержит повтор поля.")
        return self

    def permitted(self, source: Party, destination: Party) -> FlowData:
        rules = POLICY.get((source, destination), ())
        return FlowData(
            fields=tuple(
                field
                for field in self.fields
                if field.key in rules
                and (field.level == Level.SHARED or destination in DUTY_READERS)
            )
        )

    def forward(
        self, source: Party, destination: Party, checks: list[FlowCheck] | None = None
    ) -> FlowData:
        output = self.permitted(source, destination)
        passed = [field.key for field in output.fields]
        blocked = [field.key for field in self.fields if field.key not in passed]
        if checks is not None:
            checks.append(
                FlowCheck(source=source, destination=destination, passed=passed, blocked=blocked)
            )
        event(
            "information_flow",
            "filtered" if blocked else "allowed",
            sender=source,
            recipient=destination,
        )
        if blocked:
            logger.info(
                "IFC источник=%s получатель=%s скрытые поля=%s",
                source,
                destination,
                ",".join(blocked),
            )
        return output

    def values(self) -> dict[Key, int | str | tuple[str, ...]]:
        return {field.key: field.value for field in self.fields}


class FlowConflict(ValueError):
    pass


def merge(*packets: FlowData) -> FlowData:
    """Объединяет согласованные поля, сохраняя более строгую метку доступа."""
    merged: dict[Key, DataField] = {}
    for packet in packets:
        for field in packet.fields:
            previous = merged.get(field.key)
            if previous is None:
                merged[field.key] = field
            elif previous.value != field.value:
                raise FlowConflict("Источники вернули разные значения поля IFC.")
            elif field.level == Level.DUTY_ONLY:
                merged[field.key] = field
    return FlowData(fields=tuple(merged.values()))


def queue_data(size: int, oldest: int, channel: str, messages: tuple[str, ...]) -> FlowData:
    fields = [
        DataField(key=key, level=Level.SHARED, value=value)
        for key, value in zip(
            (Key.QUEUE_SIZE, Key.OLDEST_MINUTES, Key.CHANNEL), (size, oldest, channel)
        )
    ]
    if messages:
        fields.append(DataField(key=Key.MESSAGE_IDS, level=Level.DUTY_ONLY, value=messages))
    return FlowData(fields=tuple(fields))
