import json
import logging
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from dispatcher.observability.tracing.telemetry import current
from dispatcher.security.filters import display_text

TRACE_FIELDS = frozenset(
    {
        "kind",
        "operation",
        "result",
        "parent_span_id",
        "started_at",
        "duration_ms",
        "provider",
        "check_level",
        "tool",
        "snapshot_at",
        "attempt",
        "actor",
        "peer",
        "message_id",
        "task_id",
        "sender",
        "recipient",
        "symptom",
        "affected_reports",
    }
)


class JsonLogFormatter(logging.Formatter):
    """Формирует строку JSON и добавляет идентификаторы текущей трассы."""

    def __init__(self, service: str):
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds")
        fields = {
            "timestamp": timestamp.replace("+00:00", "Z"),
            "service": self.service,
            "level": record.levelname,
            "logger": record.name,
            "message": display_text(record.getMessage()),
        }
        context = current.get()
        if context:
            fields.update(
                trace_id=context.trace_id,
                span_id=context.span_id,
                scenario_id=context.scenario_id,
                run_id=context.run_id,
            )
        for key, value in getattr(record, "trace_fields", {}).items():
            if key in TRACE_FIELDS and (
                value is None or isinstance(value, (str, int, float, bool))
            ):
                fields[key] = display_text(value) if isinstance(value, str) else value
        return json.dumps(fields, ensure_ascii=False, separators=(",", ":"))


class DailyLogHandler(logging.Handler):
    def __init__(self, directory: Path, service: str):
        super().__init__()
        self.directory = directory
        self.service = service
        self.directory.mkdir(exist_ok=True)
        self.current_day = date.today()
        self.clean_expired(self.current_day)

    def clean_expired(self, today: date) -> None:
        for path in self.directory.glob(f"{self.service}-????-??-??.log"):
            try:
                day = date.fromisoformat(path.stem.removeprefix(f"{self.service}-"))
            except ValueError:
                continue
            if day <= today - timedelta(days=30):
                path.unlink(missing_ok=True)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            today = date.today()
            if today != self.current_day:
                self.clean_expired(today)
                self.current_day = today
            with (self.directory / f"{self.service}-{today}.log").open(
                "a", encoding="utf-8"
            ) as file:
                file.write(self.format(record) + "\n")
        except OSError:
            self.handleError(record)


def configure_logging(service: str) -> None:
    logger = logging.getLogger("dispatcher")
    if any(isinstance(handler, DailyLogHandler) for handler in logger.handlers):
        return
    handler = DailyLogHandler(Path("logs"), service)
    handler.setFormatter(JsonLogFormatter(service))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
