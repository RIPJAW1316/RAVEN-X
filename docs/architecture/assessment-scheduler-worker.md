# Assessment scheduler worker

```text
Application lifespan → AssessmentScheduleWorker → AssessmentScheduleRunner
→ durable ScheduleRun → RemoteAssessment / AgentWork
```

The worker owns lifecycle, polling, interruption, and in-process concurrency.
All scheduling semantics remain in `AssessmentScheduleRunner.run_once()`.
Startup performs one immediate due evaluation when enabled, then waits the
configured interval. The worker is disabled by default and is never started by
module import or test composition unless explicitly enabled.

Only one worker thread is created per application process. Shutdown signals an
interruptible event and joins the thread. A transient runner exception marks
the worker degraded while allowing later iterations to recover it.
