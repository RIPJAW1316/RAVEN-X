"""Controlled, single-process scheduler lifecycle wrapper."""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import threading
import time
import uuid


class SchedulerWorkerState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPING = "stopping"


@dataclass(frozen=True)
class SchedulerWorkerStatus:
    state: SchedulerWorkerState
    worker_instance_id: str
    started_at: datetime | None = None
    last_iteration_at: datetime | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    iterations: int = 0
    last_run_count: int = 0
    last_error_category: str | None = None

    def to_dict(self):
        def iso(value): return value.astimezone(timezone.utc).isoformat() if value else None
        return {"state": self.state.value, "worker_instance_id": self.worker_instance_id,
                "started_at": iso(self.started_at), "last_iteration_at": iso(self.last_iteration_at),
                "last_success_at": iso(self.last_success_at), "last_failure_at": iso(self.last_failure_at),
                "iterations": self.iterations, "last_run_count": self.last_run_count,
                "last_error_category": self.last_error_category}


class AssessmentScheduleWorker:
    """Owns timing and lifecycle; all schedule semantics stay in the runner."""
    def __init__(self, runner, *, poll_interval_seconds=30, enabled=False, metrics=None, logger=None,
                 wait_event=None, join_timeout_seconds=5):
        if poll_interval_seconds <= 0: raise ValueError("poll interval must be positive")
        self.runner = runner; self.poll_interval_seconds = poll_interval_seconds
        self.enabled = enabled; self.metrics = metrics; self.logger = logger
        self._stop = threading.Event(); self._run_lock = threading.Lock(); self._state_lock = threading.RLock()
        self._thread = None; self._join_timeout = join_timeout_seconds
        self._wait_event = wait_event or self._stop
        self._status = SchedulerWorkerStatus(SchedulerWorkerState.STOPPED, str(uuid.uuid4()))

    def start(self):
        with self._state_lock:
            if self._thread is not None and self._thread.is_alive(): return self.status()
            if not self.enabled: return self.status()
            self._stop.clear(); self._status = SchedulerWorkerStatus(SchedulerWorkerState.STARTING, self._status.worker_instance_id, started_at=datetime.now(timezone.utc))
            self._thread = threading.Thread(target=self._loop, name="ravenx-assessment-scheduler", daemon=True)
            self._thread.start(); self._metric("scheduler_worker_starts_total"); self._log("scheduler.worker_started")
            return self.status()

    def stop(self):
        with self._state_lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                self._status = SchedulerWorkerStatus(SchedulerWorkerState.STOPPED, self._status.worker_instance_id, started_at=self._status.started_at, last_iteration_at=self._status.last_iteration_at, last_success_at=self._status.last_success_at, last_failure_at=self._status.last_failure_at, iterations=self._status.iterations, last_run_count=self._status.last_run_count, last_error_category=self._status.last_error_category)
                return self.status()
            self._status = self._copy(state=SchedulerWorkerState.STOPPING); self._stop.set()
        thread.join(self._join_timeout)
        with self._state_lock:
            if not thread.is_alive(): self._thread = None; self._status = self._copy(state=SchedulerWorkerState.STOPPED)
            self._metric("scheduler_worker_stops_total"); self._log("scheduler.worker_stopped")
            return self.status()

    def run_once(self):
        if not self._run_lock.acquire(blocking=False): return None
        started = time.monotonic(); now = datetime.now(timezone.utc)
        with self._state_lock: self._status = self._copy(last_iteration_at=now)
        self._log("scheduler.iteration_started")
        try:
            result = self.runner.run_once()
            with self._state_lock: self._status = self._copy(state=SchedulerWorkerState.RUNNING, last_success_at=datetime.now(timezone.utc), iterations=self._status.iterations + 1, last_run_count=len(result or ()), last_error_category=None)
            self._metric("scheduler_iterations_total"); self._metric("scheduler_runs_processed_total", len(result or ()))
            self._log("scheduler.iteration_completed", runs=len(result or ()), duration_ms=round((time.monotonic()-started)*1000,2))
            return result
        except Exception as exc:
            with self._state_lock: self._status = self._copy(state=SchedulerWorkerState.DEGRADED, last_failure_at=datetime.now(timezone.utc), iterations=self._status.iterations + 1, last_error_category=type(exc).__name__)
            self._metric("scheduler_iterations_total"); self._metric("scheduler_iteration_failures_total")
            self._log("scheduler.iteration_failed", error_category=type(exc).__name__)
            return None
        finally:
            self._run_lock.release()

    def status(self):
        with self._state_lock: return self._status

    def _loop(self):
        with self._state_lock: self._status = self._copy(state=SchedulerWorkerState.RUNNING)
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self.poll_interval_seconds)

    def _copy(self, **changes):
        current = self._status
        values = {"state": current.state, "worker_instance_id": current.worker_instance_id, "started_at": current.started_at, "last_iteration_at": current.last_iteration_at, "last_success_at": current.last_success_at, "last_failure_at": current.last_failure_at, "iterations": current.iterations, "last_run_count": current.last_run_count, "last_error_category": current.last_error_category}
        values.update(changes); return SchedulerWorkerStatus(**values)
    def _metric(self, name, value=1):
        if self.metrics is not None: self.metrics.increment(name, value)
    def _log(self, event, **fields):
        if self.logger is not None: self.logger.info("%s %s", event, fields)
