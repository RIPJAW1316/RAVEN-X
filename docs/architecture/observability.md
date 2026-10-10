# Operational observability

Raven-X keeps three concerns separate:

* **Audit** is durable security history and remains backed by the existing
  security-audit repository.
* **Logs** are operational diagnostics. HTTP logs contain method, route,
  status, duration, and request ID, never request bodies or credentials.
* **Metrics** are low-cardinality process-local counters exposed through an
  internal collector; Prometheus/exporter integration is deferred.

Every HTTP response carries `X-Request-ID`. A malformed or oversized supplied
ID is replaced by a server-generated UUID. Request IDs are not protocol
correlation IDs and are not authentication credentials.
# Scheduler operations

`AssessmentScheduleWorker` emits summary logs and low-cardinality counters for
start, stop, iteration success/failure, and processed runs. Durable audit
events remain reserved for schedule mutations/runs; operational logs and
metrics are not an audit substitute. Runtime worker status is process-local and
resets after restart.
