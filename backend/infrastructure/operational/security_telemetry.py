"""Tenant-scoped, time-windowed security telemetry.

`MetricsCollector` holds flat cumulative process counters. It cannot answer
"how many denials did this tenant see in the last two minutes", because it has
neither time windows nor dimensions. This component adds exactly those two
things for security telemetry, and keeps feeding `MetricsCollector` so the flat
process counters stay complete.

It is **not** an audit log. Nothing here is durable, nothing is per-event, and
a restart loses it. That is the point: this is the home for the high-volume
authorization telemetry that used to be written as audit rows. See
docs/architecture/audit-event-policy.md.

Like `InMemoryRateLimiter`, this is process-local and makes no claim of
consistency across workers or hosts.
"""
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Callable, Optional

from ...domain.security_signals import AuthenticationCounts, AuthorizationCounts

#: Bucket granularity. One minute is fine enough for a two-minute spike rule
#: and coarse enough to keep memory trivial.
BUCKET_SECONDS = 60

#: Rolling retention. Sixty one-minute buckets covers any window the API offers.
DEFAULT_BUCKETS = 60

#: Cardinality ceilings. Exceeding them drops the *new* series rather than
#: growing without bound, so telemetry can never become a memory-exhaustion
#: vector.
DEFAULT_MAX_ORGANIZATIONS = 500
DEFAULT_MAX_SERIES_PER_BUCKET = 400

#: Telemetry that could not be attributed to a verified tenant. Kept separate so
#: it is never reported inside any tenant's numbers.
UNATTRIBUTED = "__unattributed__"


class SecurityTelemetry:
    """Windowed counters keyed by verified organization.

    Dimension values must come from closed sets the server controls (the
    `AuthorizationAction` enum, deny reason codes). Callers never pass
    user-supplied strings — see `_safe_label`.
    """

    def __init__(self, *, metrics=None, buckets: int = DEFAULT_BUCKETS,
                 max_organizations: int = DEFAULT_MAX_ORGANIZATIONS,
                 max_series_per_bucket: int = DEFAULT_MAX_SERIES_PER_BUCKET,
                 clock: Optional[Callable[[], datetime]] = None):
        if buckets <= 0 or max_organizations <= 0 or max_series_per_bucket <= 0:
            raise ValueError("telemetry bounds must be positive")
        self.metrics = metrics
        self.buckets = int(buckets)
        self.max_organizations = int(max_organizations)
        self.max_series_per_bucket = int(max_series_per_bucket)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        # organization -> OrderedDict[bucket_start -> Counter]
        self._series: OrderedDict[str, OrderedDict[datetime, Counter]] = OrderedDict()
        self._dropped_series = 0
        self._lock = RLock()

    # ------------------------------------------------------------- recording

    def record_authorization(self, *, organization_id, allowed: bool,
                             action: str = "unknown", reason_code: Optional[str] = None) -> None:
        """Record one authorization evaluation.

        `organization_id` must be a **verified** tenant or None. Passing a
        caller-claimed organization would let an outsider write into another
        tenant's telemetry, which is the same spoofing problem the audit policy
        guards against.
        """
        action = _safe_label(action)
        owner = _owner(organization_id)
        keys = ["authz.attempts", "authz.allowed" if allowed else "authz.denied"]
        if allowed:
            keys.append(f"authz.allowed.action.{action}")
        else:
            keys.append(f"authz.denied.action.{action}")
            keys.append(f"authz.denied.reason.{_safe_label(reason_code or 'unspecified')}")
        self._add(owner, keys)
        self._flat("authorization_attempts_total")
        self._flat("authorization_allowed_total" if allowed else "authorization_denied_total")

    def record_authentication(self, *, success: bool, organization_id=None) -> None:
        """Record a human sign-in outcome.

        Authentication happens before any tenant is chosen, so this is normally
        unattributed and contributes to process-wide counters only.
        """
        owner = _owner(organization_id)
        self._add(owner, ["authn.success" if success else "authn.failure"])
        self._flat("authentication_success_total" if success else "authentication_failure_total")

    def record_operation(self, name: str, *, organization_id=None) -> None:
        """Record a security-significant operation for rate context."""
        self._add(_owner(organization_id), [f"operation.{_safe_label(name)}"])
        self._flat(f"operation_{_safe_label(name)}_total")

    # -------------------------------------------------------------- querying

    def authorization_counts(self, organization_id, *, window_minutes: int) -> AuthorizationCounts:
        totals = self._window(_owner(organization_id), window_minutes)
        return AuthorizationCounts(
            attempts=totals.get("authz.attempts", 0),
            allowed=totals.get("authz.allowed", 0),
            denied=totals.get("authz.denied", 0),
            denied_by_reason=_prefixed(totals, "authz.denied.reason."),
            denied_by_action=_prefixed(totals, "authz.denied.action."),
        )

    def authentication_counts(self, organization_id=None, *, window_minutes: int) -> AuthenticationCounts:
        totals = self._window(_owner(organization_id), window_minutes)
        return AuthenticationCounts(success=totals.get("authn.success", 0),
                                    failure=totals.get("authn.failure", 0))

    def operation_counts(self, organization_id, *, window_minutes: int) -> dict[str, int]:
        return _prefixed(self._window(_owner(organization_id), window_minutes), "operation.")

    def dropped_series(self) -> int:
        """Series rejected by the cardinality ceiling, for self-observability."""
        with self._lock:
            return self._dropped_series

    def reset(self) -> None:
        with self._lock:
            self._series.clear()
            self._dropped_series = 0

    # -------------------------------------------------------------- internals

    def _add(self, owner: str, keys) -> None:
        now = self.clock()
        bucket_start = _floor(now)
        with self._lock:
            series = self._series.get(owner)
            if series is None:
                if len(self._series) >= self.max_organizations:
                    # Evict the least recently used tenant rather than grow.
                    self._series.popitem(last=False)
                series = OrderedDict()
                self._series[owner] = series
            self._series.move_to_end(owner)

            bucket = series.get(bucket_start)
            if bucket is None:
                bucket = Counter()
                series[bucket_start] = bucket
                self._prune(series, bucket_start)

            for key in keys:
                if key not in bucket and len(bucket) >= self.max_series_per_bucket:
                    self._dropped_series += 1
                    continue
                bucket[key] += 1

    def _prune(self, series, newest: datetime) -> None:
        horizon = newest - timedelta(seconds=BUCKET_SECONDS * self.buckets)
        for start in [key for key in series if key <= horizon]:
            series.pop(start, None)
        while len(series) > self.buckets:
            series.popitem(last=False)

    def _window(self, owner: str, window_minutes: int) -> dict[str, int]:
        if not isinstance(window_minutes, int) or isinstance(window_minutes, bool) or window_minutes <= 0:
            raise ValueError("window_minutes must be a positive integer")
        if window_minutes > self.buckets:
            raise ValueError(f"window_minutes must not exceed {self.buckets}")
        cutoff = _floor(self.clock()) - timedelta(minutes=window_minutes - 1)
        totals: Counter = Counter()
        with self._lock:
            for start, bucket in self._series.get(owner, {}).items():
                if start >= cutoff:
                    totals.update(bucket)
        return dict(totals)

    def _flat(self, name: str) -> None:
        if self.metrics is not None:
            self.metrics.increment(name)


def _owner(organization_id) -> str:
    if organization_id is None:
        return UNATTRIBUTED
    value = str(organization_id).strip()
    return value or UNATTRIBUTED


def _floor(value: datetime) -> datetime:
    value = value.astimezone(timezone.utc)
    return value.replace(second=0, microsecond=0)


_ALLOWED_LABEL_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789._-")


def _safe_label(value) -> str:
    """Normalise a dimension value.

    Dimension values are expected to come from closed server-side sets. This is
    a defence-in-depth backstop: anything unexpected is lower-cased, stripped to
    a safe alphabet and truncated, so a stray caller cannot inject newlines,
    unbounded strings, or high-cardinality user input into a metric name.
    """
    text = str(getattr(value, "value", value) or "unknown").strip().lower()
    cleaned = "".join(ch if ch in _ALLOWED_LABEL_CHARS else "_" for ch in text)[:64]
    return cleaned or "unknown"


def _prefixed(totals: dict[str, int], prefix: str) -> dict[str, int]:
    return {key[len(prefix):]: count for key, count in sorted(totals.items())
            if key.startswith(prefix) and count}
