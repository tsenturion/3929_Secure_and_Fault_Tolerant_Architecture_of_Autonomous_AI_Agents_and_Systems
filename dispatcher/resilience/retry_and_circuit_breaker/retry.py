import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from random import uniform

from dispatcher.observability.tracing.telemetry import error_code, event

logger = logging.getLogger(__name__)
TEMPORARY_HTTP_STATUSES = frozenset({502, 503, 504})


@dataclass(frozen=True)
class RetryPolicy:
    attempt_timeout: float
    budget: float
    delay: float
    attempts: int = 2


async def retry[T](
    operation: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
    retryable: Callable[[Exception], bool],
    *,
    name: str,
    on_attempt: Callable[[str], None] | None = None,
) -> T:
    """Ограничивает каждую попытку и всю серию независимыми сроками ожидания."""
    async with asyncio.timeout(policy.budget):
        for attempt in range(1, policy.attempts + 1):
            try:
                async with asyncio.timeout(policy.attempt_timeout):
                    result = await operation()
            except Exception as error:
                code = "timeout" if isinstance(error, TimeoutError) else error_code(error)
                if on_attempt is not None:
                    on_attempt(code)
                event(name, code, attempt=str(attempt))
                if attempt == policy.attempts or not retryable(error):
                    raise
                delay = policy.delay * 2 ** (attempt - 1) * uniform(1.0, 1.5)
                logger.info("Повтор операции=%s попытка=%d причина=%s", name, attempt + 1, code)
                await asyncio.sleep(delay)
            else:
                if on_attempt is not None:
                    on_attempt("ok")
                event(name, "ok", attempt=str(attempt))
                return result
    raise AssertionError("Для операции нужна хотя бы одна попытка.")
