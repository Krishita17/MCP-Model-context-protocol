"""Task scheduler — recurring and one-shot async security tasks."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable

import structlog

logger = structlog.get_logger()


class TaskState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScheduledTask:
    """A single scheduled task."""

    task_id: str
    name: str
    interval_seconds: float
    callback: Callable[[], Any] | Callable[[], Awaitable[Any]]
    is_async: bool = False
    state: TaskState = TaskState.PENDING
    last_run: float | None = None
    run_count: int = 0
    last_error: str | None = None
    max_runs: int | None = None  # None = unlimited


@dataclass
class TaskResult:
    """Result of a single task execution."""

    task_id: str
    success: bool
    duration_ms: float
    output: Any = None
    error: str | None = None


class TaskScheduler:
    """Schedule and execute recurring or one-shot security tasks."""

    def __init__(self) -> None:
        self._tasks: dict[str, ScheduledTask] = {}
        self._handles: dict[str, asyncio.Task[None]] = {}
        self._counter: int = 0
        self._running: bool = False
        self.log = logger.bind(component="task_scheduler")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def schedule(
        self,
        name: str,
        callback: Callable[[], Any] | Callable[[], Awaitable[Any]],
        interval_seconds: float,
        is_async: bool = False,
        max_runs: int | None = None,
    ) -> str:
        """Schedule a recurring task. Returns the task_id."""
        self._counter += 1
        task_id = f"task_{self._counter:04d}"
        task = ScheduledTask(
            task_id=task_id,
            name=name,
            interval_seconds=interval_seconds,
            callback=callback,
            is_async=is_async,
            max_runs=max_runs,
        )
        self._tasks[task_id] = task
        self.log.info("task_scheduled", task_id=task_id, name=name, interval=interval_seconds)
        return task_id

    def run_once(self, name: str, callback: Callable[[], Any] | Callable[[], Awaitable[Any]], is_async: bool = False) -> TaskResult:
        """Execute a task once synchronously and return the result."""
        start = time.monotonic()
        try:
            if is_async:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        output = pool.submit(asyncio.run, callback()).result()
                else:
                    output = loop.run_until_complete(callback())
            else:
                output = callback()
            elapsed = (time.monotonic() - start) * 1000
            return TaskResult(
                task_id="oneshot",
                success=True,
                duration_ms=round(elapsed, 3),
                output=output,
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            return TaskResult(
                task_id="oneshot",
                success=False,
                duration_ms=round(elapsed, 3),
                error=str(exc),
            )

    async def start(self) -> None:
        """Start the scheduler loop — runs all registered tasks on their intervals."""
        self._running = True
        self.log.info("scheduler_started", task_count=len(self._tasks))
        for task_id, task in self._tasks.items():
            if task_id not in self._handles:
                handle = asyncio.create_task(self._run_loop(task))
                self._handles[task_id] = handle

    async def stop(self) -> None:
        """Cancel all running task loops."""
        self._running = False
        for handle in self._handles.values():
            handle.cancel()
        for handle in self._handles.values():
            try:
                await handle
            except asyncio.CancelledError:
                pass
        self._handles.clear()
        self.log.info("scheduler_stopped")

    def cancel(self, task_id: str) -> bool:
        """Cancel a specific task."""
        task = self._tasks.get(task_id)
        if task is None:
            return False
        task.state = TaskState.CANCELLED
        handle = self._handles.pop(task_id, None)
        if handle:
            handle.cancel()
        self.log.info("task_cancelled", task_id=task_id)
        return True

    def get_task(self, task_id: str) -> ScheduledTask | None:
        return self._tasks.get(task_id)

    @property
    def all_tasks(self) -> list[ScheduledTask]:
        return list(self._tasks.values())

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _run_loop(self, task: ScheduledTask) -> None:
        """Run a single task on its interval until cancelled or max_runs reached."""
        while self._running and task.state != TaskState.CANCELLED:
            if task.max_runs is not None and task.run_count >= task.max_runs:
                task.state = TaskState.COMPLETED
                break

            task.state = TaskState.RUNNING
            start = time.monotonic()
            try:
                if task.is_async:
                    await task.callback()  # type: ignore[misc]
                else:
                    task.callback()
                task.last_error = None
            except Exception as exc:
                task.last_error = str(exc)
                task.state = TaskState.FAILED
                self.log.error("task_execution_failed", task_id=task.task_id, error=str(exc))

            task.run_count += 1
            task.last_run = time.time()
            elapsed = time.monotonic() - start

            # Wait for the remainder of the interval
            wait_time = max(0, task.interval_seconds - elapsed)
            if wait_time > 0:
                try:
                    await asyncio.sleep(wait_time)
                except asyncio.CancelledError:
                    break

        if task.state == TaskState.RUNNING:
            task.state = TaskState.COMPLETED
