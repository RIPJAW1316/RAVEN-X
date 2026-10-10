"""Thread-safe, process-local request throttling primitives."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Callable


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after: int = 0
    reason_code: str = "allowed"


class InMemoryRateLimiter:
    """Fixed-window limiter suitable for one control-plane process.

    The clock is injectable so tests never need to sleep.  This deliberately
    makes no claim of consistency across multiple workers or hosts.
    """

    def __init__(self, limit: int = 5, window_seconds: int = 60, *, clock: Callable[[], datetime] | None = None):
        if limit <= 0 or window_seconds <= 0:
            raise ValueError("rate-limit values must be positive")
        self.limit = int(limit)
        self.window = timedelta(seconds=int(window_seconds))
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._buckets: dict[str, tuple[datetime, int]] = {}
        self._lock = RLock()

    def check(self, key: str) -> RateLimitDecision:
        if not isinstance(key, str) or not key:
            raise ValueError("rate-limit key is required")
        now = self.clock()
        with self._lock:
            started, count = self._buckets.get(key, (now, 0))
            if now - started >= self.window:
                started, count = now, 0
            if count >= self.limit:
                retry = max(1, int((self.window - (now - started)).total_seconds() + 0.999))
                return RateLimitDecision(False, 0, retry, "rate_limit_exceeded")
            count += 1
            self._buckets[key] = (started, count)
            return RateLimitDecision(True, self.limit - count, 0, "allowed")

    def reset(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()
