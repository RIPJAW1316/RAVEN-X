# Running scheduled assessments

Phase 3R provides a bounded, explicitly invoked scheduler primitive:

```python
from backend.api.main import assessment_schedule_runner
summary = assessment_schedule_runner.run_once()
```

The runner is not started automatically at application startup. Operators may
invoke it from a controlled process or administrative task. It uses the
configured `RAVENX_ASSESSMENT_SCHEDULE_BATCH_SIZE` and
`RAVENX_ASSESSMENT_SCHEDULE_MAX_TARGETS` bounds. Multiple control-plane
instances are not leader-elected; the durable schedule-run occurrence marker
reduces duplicates but does not provide cluster-wide coordination.
