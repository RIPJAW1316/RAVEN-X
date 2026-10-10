# Compliance snapshot retention

Compliance snapshots are immutable aggregates. Retention is the only supported
deletion path and removes a complete snapshot (including frozen endpoint and
control rows) through an explicit system runner. Policies are application-level,
bounded, and protect the newest minimum number of snapshots independently for
each organization/framework/framework-version tuple. `run_once(dry_run=True)`
reports candidates without mutation; no human delete API or automatic worker is
provided yet.

Age and count limits are conservative: snapshots below the minimum are never
eligible, and framework versions are never mixed when evaluating counts.
