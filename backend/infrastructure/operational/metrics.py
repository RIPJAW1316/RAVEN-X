"""Low-cardinality process-local operational counters."""

from collections import Counter
from threading import RLock


class MetricsCollector:
    def __init__(self):
        self._counts = Counter()
        self._lock = RLock()

    def increment(self, name: str, value: int = 1) -> None:
        if not isinstance(name, str) or not name or any(ch in name for ch in "\r\n"):
            raise ValueError("metric name is required")
        with self._lock:
            self._counts[name] += value

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()
