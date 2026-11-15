import logging
from collections.abc import Callable, Sequence
from functools import lru_cache
from math import ceil, exp, tanh
from pathlib import Path
from time import monotonic
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from dispatcher.resilience.forecasting.forecast_workload import (
    HORIZON,
    OVERLOAD_DELAY,
    TEST_DAYS,
    TRAIN_DAYS,
    VALIDATION_DAYS,
    WINDOW,
    BackgroundPolicy,
    Experiment,
    Sample,
    simulate,
    snapshots,
    workload,
)

logger = logging.getLogger(__name__)
ARTIFACT = Path(__file__).with_name("data") / "forecast_lstm.json"
HIDDEN = 8
BACKGROUND_SECONDS = 15
THROTTLED_SECONDS = 60


class Weights(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    trained_with: Literal["numpy", "pytorch"]
    mean: tuple[float, float, float]
    scale: tuple[float, float, float]
    inputs: list[list[float]]
    recurrent: list[list[float]]
    biases: list[float]
    output: list[float]
    intercept: float
    threshold: float

    @model_validator(mode="after")
    def dimensions(self):
        if (
            len(self.inputs) != 4 * HIDDEN
            or any(len(row) != 3 for row in self.inputs)
            or len(self.recurrent) != 4 * HIDDEN
            or any(len(row) != HIDDEN for row in self.recurrent)
            or len(self.biases) != 4 * HIDDEN
            or len(self.output) != HIDDEN
            or min(self.scale) <= 0
            or not 0 < self.threshold < 1
        ):
            raise ValueError("Некорректные размеры или параметры LSTM.")
        return self


def sigmoid(value: float) -> float:
    e = exp(-abs(value))
    return 1 / (1 + e) if value >= 0 else e / (1 + e)


def probability(weights: Weights, window: Sequence[Sample]) -> float:
    hidden = [0.0] * HIDDEN
    cell = [0.0] * HIDDEN
    for sample in window:
        x = [
            (v - mean) / scale
            for v, mean, scale in zip(sample.features(), weights.mean, weights.scale)
        ]
        gates = [
            bias + sum(a * b for a, b in zip(wx, x)) + sum(a * b for a, b in zip(wh, hidden))
            for wx, wh, bias in zip(weights.inputs, weights.recurrent, weights.biases)
        ]
        for i in range(HIDDEN):
            cell[i] = sigmoid(gates[HIDDEN + i]) * cell[i] + sigmoid(gates[i]) * tanh(
                gates[2 * HIDDEN + i]
            )
            hidden[i] = sigmoid(gates[3 * HIDDEN + i]) * tanh(cell[i])
    return sigmoid(weights.intercept + sum(a * b for a, b in zip(weights.output, hidden)))


class Evaluation(BaseModel):
    detected: int
    missed: int
    false_alarms: int
    lead_minutes: float | None


def score(series: Sequence[Sample], flags: Sequence[bool]) -> tuple[list[int], int, int]:
    """Считает начала эпизодов перегрузки и ложные серии предупреждений, а не минуты."""
    overload = [sample.overloaded for sample in series]
    leads = []
    missed = 0
    false_alarms = 0
    previous_overload = -HORIZON - 1
    for minute, (actual, alert) in enumerate(zip(overload, flags)):
        if actual and minute - previous_overload > HORIZON:
            start = max(0, minute - HORIZON)
            warning = next((index for index in range(start, minute + 1) if flags[index]), None)
            if warning is None:
                missed += 1
            else:
                leads.append(minute - warning)
        if actual:
            previous_overload = minute
        if (
            alert
            and (minute == 0 or not flags[minute - 1])
            and minute + HORIZON < len(overload)
            and not any(overload[minute : minute + HORIZON + 1])
        ):
            false_alarms += 1
    return leads, missed, false_alarms


def evaluate(days: Sequence[tuple[Sequence[Sample], Sequence[bool]]]) -> Evaluation:
    leads = []
    missed = 0
    false_alarms = 0
    for samples, flags in days:
        detected, day_missed, day_false_alarms = score(samples, flags)
        leads.extend(detected)
        missed += day_missed
        false_alarms += day_false_alarms
    return Evaluation(
        detected=len(leads),
        missed=missed,
        false_alarms=false_alarms,
        lead_minutes=round(sum(leads) / len(leads), 1) if leads else None,
    )


class Flow(BaseModel):
    requests: int
    p95_minutes: int
    background_checks: int

    @classmethod
    def from_experiment(cls, experiment: Experiment):
        return cls(
            requests=sum(experiment.waits.values()),
            p95_minutes=experiment.p95,
            background_checks=sum(tick.background for tick in experiment.ticks),
        )


class Point(BaseModel):
    minute: int
    backlog: int
    controlled_backlog: int
    arrivals: int
    delay: float
    probability: float | None
    controlled_probability: float | None
    overload: bool
    lstm_alert: bool
    throttled: bool


class ForecastReport(BaseModel):
    window_minutes: int = WINDOW
    horizon_minutes: int = HORIZON
    overload_delay: int = OVERLOAD_DELAY
    train_days: int = len(TRAIN_DAYS)
    validation_days: int = len(VALIDATION_DAYS)
    test_days: int = len(TEST_DAYS)
    threshold: float
    trained_with: str
    lstm: Evaluation
    rule: Evaluation
    baseline: Flow
    controlled: Flow
    timeline: list[Point]
    replay_start: int
    replay_end: int


def forecast_series(
    samples: Sequence[Sample],
    predict: Callable[[Sequence[Sample]], float],
) -> list[float | None]:
    """Оставляет начало ряда пустым, пока не накопится полное окно наблюдений."""
    return [None] * (WINDOW - 1) + [
        predict(samples[end - WINDOW : end]) for end in range(WINDOW, len(samples) + 1)
    ]


@lru_cache(maxsize=1)
def forecast_report() -> ForecastReport:
    """Сравнивает прогноз и правило на тестовых днях, затем проигрывает общий поток."""
    weights = Weights.model_validate_json(ARTIFACT.read_bytes())

    def predict(window: Sequence[Sample]) -> float:
        return probability(weights, window)

    lstm_days = []
    rule_days = []
    for day in TEST_DAYS:
        samples = snapshots(day)
        scores = forecast_series(samples, predict)
        lstm_days.append((samples, [p is not None and p >= weights.threshold for p in scores]))
        rule_days.append((samples, [sample.overloaded for sample in samples]))

    loads = workload(TEST_DAYS[-1])
    baseline = simulate(loads, predict)
    controlled = simulate(loads, predict, policy=BackgroundPolicy(weights.threshold))
    timeline = [
        Point(
            minute=minute,
            backlog=raw.sample.backlog,
            controlled_backlog=managed.sample.backlog,
            arrivals=raw.sample.arrivals,
            delay=round(raw.sample.delay, 1),
            probability=raw.probability,
            controlled_probability=managed.probability,
            overload=raw.sample.overloaded,
            lstm_alert=raw.probability is not None and raw.probability >= weights.threshold,
            throttled=managed.period > 1,
        )
        for minute, (raw, managed) in enumerate(zip(baseline.ticks, controlled.ticks))
    ]
    first_throttle = next((point.minute for point in timeline if point.throttled), 50)
    start = max(0, first_throttle - 4)
    return ForecastReport(
        threshold=weights.threshold,
        trained_with=weights.trained_with,
        lstm=evaluate(lstm_days),
        rule=evaluate(rule_days),
        baseline=Flow.from_experiment(baseline),
        controlled=Flow.from_experiment(controlled),
        timeline=timeline,
        replay_start=start,
        replay_end=min(len(timeline), start + 45),
    )


class ReplayStatus(BaseModel):
    active: bool
    minute: int | None = None
    probability: float | None = None
    throttled: bool = False
    background_seconds: int = BACKGROUND_SECONDS


class ForecastReplay:
    def __init__(self, clock: Callable[[], float] = monotonic):
        self.clock = clock
        self.report: ForecastReport | None = None
        self.started: float = 0
        self.last_background: float | None = None

    def start(self, report: ForecastReport) -> ReplayStatus:
        if not self.status().active:
            self.report = report
            self.started = self.clock()
            logger.info(
                "Запущено воспроизведение пика начало=%s конец=%s",
                report.replay_start,
                report.replay_end,
            )
        return self.status()

    def status(self) -> ReplayStatus:
        report = self.report
        if report is None:
            return ReplayStatus(active=False)
        minute = report.replay_start + int(self.clock() - self.started)
        if minute >= report.replay_end:
            self.report = None
            return ReplayStatus(active=False)
        point = report.timeline[minute]
        return ReplayStatus(
            active=True,
            minute=minute,
            probability=point.controlled_probability,
            throttled=point.throttled,
            background_seconds=THROTTLED_SECONDS if point.throttled else BACKGROUND_SECONDS,
        )

    def record_background(self) -> None:
        self.last_background = self.clock()

    def wait_for_background(self) -> int:
        """Ограничивает паузу концом интервала замедления во время воспроизведения."""
        status = self.status()
        if not status.throttled or self.last_background is None:
            return 0
        remaining = THROTTLED_SECONDS - (self.clock() - self.last_background)
        if remaining <= 0:
            return 0
        report = self.report
        assert report is not None and status.minute is not None
        resume = next(
            (
                i
                for i in range(status.minute + 1, report.replay_end)
                if not report.timeline[i].throttled
            ),
            report.replay_end,
        )
        return max(
            1, ceil(min(remaining, self.started + resume - report.replay_start - self.clock()))
        )
