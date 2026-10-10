import threading
import time

from backend.application.scheduling import AssessmentScheduleWorker, SchedulerWorkerState
from backend.infrastructure.operational import MetricsCollector


class FakeRunner:
    def __init__(self):
        self.calls = 0
        self.started = threading.Event()
        self.release = threading.Event()
        self.fail = False

    def run_once(self):
        self.calls += 1
        self.started.set()
        if self.fail:
            raise RuntimeError("synthetic failure")
        if not self.release.is_set():
            self.release.set()
        return ("run",)


def test_disabled_worker_does_not_start_and_run_once_is_safe():
    runner = FakeRunner()
    worker = AssessmentScheduleWorker(runner, enabled=False)
    assert worker.start().state is SchedulerWorkerState.STOPPED
    assert worker.run_once() == ("run",)
    assert runner.calls == 1


def test_worker_start_is_singleton_and_stop_is_idempotent():
    runner = FakeRunner()
    metrics = MetricsCollector()
    worker = AssessmentScheduleWorker(runner, enabled=True, poll_interval_seconds=60, metrics=metrics)
    worker.start()
    assert runner.started.wait(1)
    worker.start()
    worker.stop()
    worker.stop()
    assert worker.status().state is SchedulerWorkerState.STOPPED
    assert metrics.snapshot()["scheduler_worker_starts_total"] == 1


def test_iteration_failure_degrades_then_recovers():
    runner = FakeRunner(); worker = AssessmentScheduleWorker(runner, enabled=False)
    runner.fail = True
    assert worker.run_once() is None
    assert worker.status().state is SchedulerWorkerState.DEGRADED
    runner.fail = False
    assert worker.run_once() == ("run",)
    assert worker.status().state is SchedulerWorkerState.RUNNING


def test_busy_manual_run_is_skipped():
    class BlockingRunner:
        def __init__(self): self.entered=threading.Event(); self.release=threading.Event(); self.calls=0
        def run_once(self):
            self.calls += 1; self.entered.set(); self.release.wait(1); return ()
    runner=BlockingRunner(); worker=AssessmentScheduleWorker(runner, enabled=False)
    thread=threading.Thread(target=worker.run_once); thread.start(); assert runner.entered.wait(1)
    assert worker.run_once() is None
    runner.release.set(); thread.join(1)
    assert runner.calls == 1
