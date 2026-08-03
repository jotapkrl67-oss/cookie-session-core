from __future__ import annotations

import threading
from collections import Counter

METRIC_NAMES = (
    "cf_challenges_seen",
    "cf_solver_calls",
    "cf_solver_success",
    "cf_solver_errors",
    "retries_total",
    "oai_id_rotations_total",
    "oai_sentinel_skipped_rotations",
    "responses_502_total",
    "responses_429_total",
)


class Metrics:
    """Small process-local Prometheus counter registry."""

    def __init__(self) -> None:
        self._values: Counter[str] = Counter()
        self._lock = threading.Lock()

    def increment(self, name: str, amount: int = 1) -> None:
        if name not in METRIC_NAMES:
            raise ValueError(f"Unknown metric: {name}")
        with self._lock:
            self._values[name] += amount

    def render(self) -> str:
        with self._lock:
            values = dict(self._values)
        lines: list[str] = []
        for name in METRIC_NAMES:
            lines.append(f"# TYPE cookie_session_core_{name} counter")
            lines.append(f"cookie_session_core_{name} {values.get(name, 0)}")
        return "\n".join(lines) + "\n"


metrics = Metrics()
