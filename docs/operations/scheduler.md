# Scheduler operations

Enable the assessment scheduler on exactly one control-plane instance. Verify
worker state and duplicate protection before enabling a second API instance;
multi-instance leader election is deferred. Disable the worker before upgrades,
restart after recovery, and inspect schedule-run audit events for failures.
