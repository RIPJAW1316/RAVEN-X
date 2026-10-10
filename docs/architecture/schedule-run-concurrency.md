# Schedule-run concurrency

The database uniqueness constraint on `(schedule_id, scheduled_for)` remains
the durable occurrence claim. Insert-first creation through
`add_if_absent()` prevents duplicate run rows; per-target outcomes and
assessment linkage make retries idempotent. The worker additionally prevents
overlapping `run_once()` calls within one process.

Production deployments should run one scheduler-enabled control-plane
instance until distributed leader election/claims are designed and validated
for the target database. SQLite testing demonstrates best-effort serialization
only; it is not a substitute for production database concurrency testing.
