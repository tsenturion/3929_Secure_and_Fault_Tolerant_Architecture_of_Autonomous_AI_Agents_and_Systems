import logging
import re
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from secrets import token_hex
from time import perf_counter_ns

from dispatcher.workflow.case_ids import CASE_PATTERN

logger = logging.getLogger(__name__)
HEADER = "traceparent"
RUN_HEADER = "X-Trace-Run"
CASE_HEADER = "X-Trace-Case"
TRACE_PATTERN = re.compile(r"00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}")
RUN_PATTERN = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    run_id: str
    scenario_id: str
    span_id: str | None = None


@dataclass
class SpanResult:
    code: str = "ok"


current: ContextVar[TraceContext | None] = ContextVar("trace", default=None)
trace_recorder: ContextVar[tuple[Callable[[TraceContext, dict], None], bool] | None] = ContextVar(
    "trace_recorder", default=None
)


@contextmanager
def record_trace(
    recorder: Callable[[TraceContext, dict], None], *, also_log: bool = False
) -> Iterator[None]:
    token = trace_recorder.set((recorder, also_log))
    try:
        yield
    finally:
        trace_recorder.reset(token)


def publish(context: TraceContext, message: str, fields: dict) -> None:
    sink = trace_recorder.get()
    if sink is not None:
        recorder, also_log = sink
        recorder(context, fields)
        if not also_log:
            return
    logger.info(message, extra={"trace_fields": fields})


def new_trace(scenario_id: str) -> TraceContext:
    return TraceContext(token_hex(16), token_hex(16), scenario_id)


def trace_headers() -> dict[str, str]:
    """Передаёт следующему сервису контекст трассы и текущей операции."""
    context = current.get()
    if context is None or context.span_id is None:
        return {}
    return {
        HEADER: f"00-{context.trace_id}-{context.span_id}-01",
        RUN_HEADER: context.run_id,
        CASE_HEADER: context.scenario_id,
    }


def receive(headers: Mapping[str, str]) -> TraceContext | None:
    value = headers.get(HEADER, "")
    match = TRACE_PATTERN.fullmatch(value)
    run_id = headers.get(RUN_HEADER, "")
    scenario_id = headers.get(CASE_HEADER, "")
    if (
        match is None
        or not RUN_PATTERN.fullmatch(run_id)
        or not re.fullmatch(CASE_PATTERN, scenario_id)
    ):
        return None
    trace_id, span_id = match.groups()
    if trace_id == "0" * 32 or span_id == "0" * 16:
        return None
    return TraceContext(trace_id, run_id, scenario_id, span_id)


def received_run(headers: Mapping[str, str], run_id: str, scenario_id: str) -> TraceContext | None:
    context = receive(headers)
    if context is None or (context.run_id, context.scenario_id) != (run_id, scenario_id):
        return None
    return context


def error_code(error: BaseException) -> str:
    headers = getattr(error, "headers", None)
    block = getattr(error, "block", None)
    policy = headers.get("X-Policy-Code") if headers else None
    status = (
        getattr(error, "status_code", None)
        or getattr(error, "status", None)
        or getattr(getattr(error, "response", None), "status_code", None)
    )
    return (
        policy
        or getattr(error, "code", None)
        or getattr(block, "code", None)
        or (f"http_{status}" if status else type(error).__name__)
    )


@contextmanager
def span(
    operation: str, *, parent: TraceContext | None = None, **attributes: str | None
) -> Iterator[SpanResult]:
    """Записывает длительность и результат операции с указанием её родителя."""
    parent = parent if parent is not None else current.get()
    result = SpanResult()
    if parent is None:
        yield result
        return
    context = replace(parent, span_id=token_hex(8))
    token = current.set(context)
    # Порядок задаём временем начала, длительность измеряем монотонным счётчиком.
    start_ns = perf_counter_ns()
    started_at = datetime.now(UTC)
    try:
        yield result
    except BaseException as error:
        result.code = error_code(error)
        raise
    finally:
        try:
            publish(
                context,
                "Операция трассы",
                {
                    "kind": "span",
                    "operation": operation,
                    "result": result.code,
                    "parent_span_id": parent.span_id,
                    "started_at": started_at.isoformat(),
                    "duration_ms": round((perf_counter_ns() - start_ns) / 1_000_000, 3),
                    **attributes,
                },
            )
        finally:
            current.reset(token)


def event(operation: str, code: str, **attributes: str) -> None:
    context = current.get()
    if context is not None:
        publish(
            context,
            "Событие трассы",
            {
                "kind": "event",
                "operation": operation,
                "result": code,
                **attributes,
            },
        )
