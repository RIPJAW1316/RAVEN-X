# Worker coordination

The supported topology permits multiple API instances but exactly one
scheduler-enabled instance. Schedule occurrence uniqueness and work delivery are
database/idempotency protected; distributed leader election is not implemented.
Compliance retention is an explicit bounded `run_once` operation and is not an
autonomous distributed worker. Horizontal scheduler scaling is deferred.
