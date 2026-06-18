"""Automation Engine — Pipeline orchestration, scheduling, and file/tool watching."""

__version__ = "0.1.0"

from automation.engine import AutomationEngine, PipelineResult
from automation.scheduler import TaskScheduler
from automation.watchers import FileWatcher, ToolWatcher

__all__ = [
    "AutomationEngine",
    "PipelineResult",
    "TaskScheduler",
    "FileWatcher",
    "ToolWatcher",
]
