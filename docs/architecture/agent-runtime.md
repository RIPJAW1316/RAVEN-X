# Agent heartbeat runtime

`HeartbeatScheduler` provides a controllable `start()`, `stop()`, and
`run_once()` boundary around the existing agent runtime. It does not create a
Windows service, scheduled task, or unmanaged immortal thread. A failed send
marks the local runtime degraded while retaining the endpoint identity and
credential; the next successful send restores readiness without reenrollment.

Capability reports remain separate from heartbeat traffic and are not emitted
on every heartbeat.
