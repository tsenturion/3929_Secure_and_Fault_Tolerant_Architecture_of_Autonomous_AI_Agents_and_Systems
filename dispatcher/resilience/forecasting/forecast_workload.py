from collections import Counter, deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from math import ceil, exp, sin
from random import Random

WINDOW = 12
HORIZON = 10
DAY_MINUTES = 150
TRAIN_DAYS = range(32)
VALIDATION_DAYS = range(32, 40)
TEST_DAYS = range(40, 48)
OVERLOAD_DELAY = 8
BACKGROUND_COST = 5
THROTTLE_MINUTES = 16
THROTTLED_PERIOD = 4


@dataclass(frozen=True)
class Load:
    arrivals: int
    capacity: int


@dataclass(frozen=True)
class Sample:
    backlog: int
    arrivals: int
    delay: float

    def features(self) -> tuple[int, int, float]:
        return self.backlog, self.arrivals, self.delay

    @property
    def overloaded(self) -> bool:
        return self.delay >= OVERLOAD_DELAY


def workload(day: int) -> list[Load]:
    random = Random(650_021 + day)
    peak = random.randint(56, 98)
    width = random.uniform(8, 18)
    amplitude = random.uniform(10, 25) + (14 if day % 3 != 1 else 0)
    short_peak = random.randint(17, 42)
    short_amplitude = random.uniform(1, 19)
    base = random.uniform(9.5, 15.0)
    capacity = random.randint(24, 31)
    return [
        Load(
            arrivals=max(
                0,
                round(
                    base
                    + 2 * sin(minute / 19)
                    + random.gauss(0, 2.0)
                    + amplitude * exp(-0.5 * ((minute - peak) / width) ** 2)
                    + short_amplitude * exp(-0.5 * ((minute - short_peak) / 3.0) ** 2)
                ),
            ),
            capacity=max(1, capacity + random.choice((-2, -1, 0, 0, 1, 2))),
        )
        for minute in range(DAY_MINUTES)
    ]


@dataclass
class BackgroundPolicy:
    threshold: float
    until: int = 0
    was_high: bool = False

    def period(self, minute: int, probability: float | None) -> int:
        high = probability is not None and probability >= self.threshold
        if high and not self.was_high and minute >= self.until:
            self.until = minute + THROTTLE_MINUTES
        self.was_high = high
        return THROTTLED_PERIOD if minute < self.until else 1


@dataclass(frozen=True)
class Tick:
    sample: Sample
    probability: float | None
    background: bool
    period: int


@dataclass(frozen=True)
class Experiment:
    ticks: list[Tick]
    waits: Counter[int]

    @property
    def p95(self) -> int:
        rank = ceil(sum(self.waits.values()) * 0.95)
        seen = 0
        for wait, count in sorted(self.waits.items()):
            seen += count
            if seen >= rank:
                return wait
        return 0


def simulate(
    loads: Sequence[Load],
    predict: Callable[[Sequence[Sample]], float] | None = None,
    *,
    policy: BackgroundPolicy | None = None,
) -> Experiment:
    pending: deque[tuple[int, int]] = deque()
    waits: Counter[int] = Counter()
    ticks: list[Tick] = []
    samples: list[Sample] = []
    backlog = 0
    last_background = -1

    def serve(minute: int, capacity: int) -> None:
        nonlocal backlog
        while pending and capacity > 0:
            entered, count = pending.popleft()
            served = min(count, capacity)
            waits[minute - entered] += served
            backlog -= served
            capacity -= served
            if served < count:
                pending.appendleft((entered, count - served))

    for minute, load in enumerate(loads):
        if load.arrivals:
            pending.append((minute, load.arrivals))
            backlog += load.arrivals
        sample = Sample(backlog, load.arrivals, backlog / load.capacity)
        samples.append(sample)
        probability = (
            predict(samples[-WINDOW:]) if predict is not None and len(samples) >= WINDOW else None
        )
        period = policy.period(minute, probability) if policy is not None else 1
        background = minute - last_background >= period
        if background:
            last_background = minute
        ticks.append(Tick(sample, probability, background, period))
        serve(minute, max(0, load.capacity - (BACKGROUND_COST if background else 0)))

    # Учитываем ожидание всех поступивших заявок, включая остаток на конце ряда.
    for minute in range(len(loads), len(loads) + backlog):
        if not pending:
            break
        serve(minute, loads[-1].capacity)
    return Experiment(ticks, waits)


def snapshots(day: int) -> list[Sample]:
    return [tick.sample for tick in simulate(workload(day)).ticks]


def windows(series: Sequence[Sample]):
    for minute in range(WINDOW - 1, len(series) - HORIZON):
        yield (
            series[minute - WINDOW + 1 : minute + 1],
            int(any(sample.overloaded for sample in series[minute : minute + HORIZON + 1])),
        )
