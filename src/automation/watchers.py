"""File and tool watchers — monitor for changes and detect rug-pulls."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import structlog

from mcpshield.static_analysis.scanner import StaticScanner, ScanResult
from cryptomcp.signing.signer import compute_tool_hash

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# FileWatcher
# ---------------------------------------------------------------------------


@dataclass
class FileChangeEvent:
    """Record of a detected file change."""

    filepath: str
    change_type: str  # "created" | "modified" | "deleted"
    timestamp: float
    scan_result: ScanResult | None = None


class FileWatcher:
    """Watch a directory for MCP server file changes and auto-scan on change."""

    def __init__(
        self,
        watch_dir: str | Path,
        scanner: StaticScanner | None = None,
        extensions: list[str] | None = None,
        on_change: Callable[[FileChangeEvent], None] | None = None,
    ) -> None:
        self.watch_dir = Path(watch_dir)
        self.scanner = scanner or StaticScanner()
        self.extensions = extensions or [".json", ".yaml", ".yml", ".py"]
        self.on_change = on_change
        self._file_hashes: dict[str, str] = {}
        self._events: list[FileChangeEvent] = []
        self._running: bool = False
        self.log = logger.bind(component="file_watcher", watch_dir=str(self.watch_dir))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, str]:
        """Take a snapshot of current file hashes in the watched directory."""
        hashes: dict[str, str] = {}
        if not self.watch_dir.exists():
            return hashes
        for ext in self.extensions:
            for filepath in self.watch_dir.rglob(f"*{ext}"):
                try:
                    content = filepath.read_bytes()
                    h = hashlib.sha256(content).hexdigest()
                    hashes[str(filepath)] = h
                except (OSError, PermissionError):
                    continue
        return hashes

    def check_for_changes(self) -> list[FileChangeEvent]:
        """Compare current state against last snapshot and return change events."""
        current = self.snapshot()
        events: list[FileChangeEvent] = []
        now = time.time()

        # Detect new and modified files
        for filepath, file_hash in current.items():
            if filepath not in self._file_hashes:
                event = FileChangeEvent(
                    filepath=filepath, change_type="created", timestamp=now
                )
                event.scan_result = self._scan_file(filepath)
                events.append(event)
            elif self._file_hashes[filepath] != file_hash:
                event = FileChangeEvent(
                    filepath=filepath, change_type="modified", timestamp=now
                )
                event.scan_result = self._scan_file(filepath)
                events.append(event)

        # Detect deleted files
        for filepath in self._file_hashes:
            if filepath not in current:
                events.append(
                    FileChangeEvent(
                        filepath=filepath, change_type="deleted", timestamp=now
                    )
                )

        self._file_hashes = current

        for event in events:
            self._events.append(event)
            if self.on_change is not None:
                self.on_change(event)

        return events

    async def watch(self, poll_interval: float = 2.0) -> None:
        """Start polling loop that checks for changes periodically."""
        self._running = True
        # Take initial snapshot
        self._file_hashes = self.snapshot()
        self.log.info("file_watcher_started", file_count=len(self._file_hashes))

        while self._running:
            try:
                changes = self.check_for_changes()
                if changes:
                    self.log.info("file_changes_detected", count=len(changes))
            except Exception as exc:
                self.log.error("file_watch_error", error=str(exc))
            try:
                await asyncio.sleep(poll_interval)
            except asyncio.CancelledError:
                break

        self.log.info("file_watcher_stopped")

    def stop(self) -> None:
        """Signal the watch loop to stop."""
        self._running = False

    @property
    def events(self) -> list[FileChangeEvent]:
        return list(self._events)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _scan_file(self, filepath: str) -> ScanResult | None:
        """Attempt to parse a file as a tool descriptor and scan it."""
        path = Path(filepath)
        try:
            content = path.read_text()
        except (OSError, UnicodeDecodeError):
            return None

        # Try JSON
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            # Try YAML
            try:
                import yaml
                data = yaml.safe_load(content)
            except Exception:
                return None

        if not isinstance(data, dict):
            return None

        # If the file looks like a tool descriptor, scan it
        if "name" in data and ("description" in data or "inputSchema" in data):
            return self.scanner.scan(data)

        # If it's a list of tools, scan each and return the worst result
        tools = data.get("tools", [])
        if isinstance(tools, list) and tools:
            worst: ScanResult | None = None
            for tool in tools:
                if isinstance(tool, dict):
                    result = self.scanner.scan(tool)
                    if worst is None or result.score > worst.score:
                        worst = result
            return worst

        return None


# ---------------------------------------------------------------------------
# ToolWatcher
# ---------------------------------------------------------------------------


@dataclass
class ToolHashRecord:
    """Stored hash baseline for a tool."""

    tool_name: str
    baseline_hash: str
    recorded_at: float
    last_checked: float
    change_detected: bool = False
    current_hash: str = ""


@dataclass
class RugPullAlert:
    """Alert raised when a tool description changes unexpectedly."""

    tool_name: str
    baseline_hash: str
    current_hash: str
    timestamp: float
    severity: str = "CRITICAL"


class ToolWatcher:
    """Monitor tool descriptions for rug-pull detection via periodic hash comparison."""

    def __init__(
        self,
        on_alert: Callable[[RugPullAlert], None] | None = None,
    ) -> None:
        self._baselines: dict[str, ToolHashRecord] = {}
        self._alerts: list[RugPullAlert] = []
        self._running: bool = False
        self.on_alert = on_alert
        self.log = logger.bind(component="tool_watcher")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_tool(self, tool_descriptor: dict[str, Any]) -> ToolHashRecord:
        """Register a tool's current description as its baseline."""
        name = tool_descriptor.get("name", "unknown")
        h = compute_tool_hash(tool_descriptor)
        now = time.time()
        record = ToolHashRecord(
            tool_name=name,
            baseline_hash=h,
            recorded_at=now,
            last_checked=now,
            current_hash=h,
        )
        self._baselines[name] = record
        self.log.info("tool_baseline_registered", tool=name, hash=h[:16])
        return record

    def check_tool(self, tool_descriptor: dict[str, Any]) -> ToolHashRecord:
        """Check a tool against its baseline. Raises alert on mismatch."""
        name = tool_descriptor.get("name", "unknown")
        current_hash = compute_tool_hash(tool_descriptor)
        now = time.time()

        record = self._baselines.get(name)
        if record is None:
            # No baseline — register it now
            return self.register_tool(tool_descriptor)

        record.last_checked = now
        record.current_hash = current_hash

        if current_hash != record.baseline_hash:
            record.change_detected = True
            alert = RugPullAlert(
                tool_name=name,
                baseline_hash=record.baseline_hash,
                current_hash=current_hash,
                timestamp=now,
            )
            self._alerts.append(alert)
            self.log.warning(
                "rug_pull_detected",
                tool=name,
                baseline=record.baseline_hash[:16],
                current=current_hash[:16],
            )
            if self.on_alert is not None:
                self.on_alert(alert)

        return record

    def check_all(
        self, tool_descriptors: list[dict[str, Any]]
    ) -> list[ToolHashRecord]:
        """Check multiple tools at once."""
        return [self.check_tool(td) for td in tool_descriptors]

    async def watch(
        self,
        tool_source: Callable[[], list[dict[str, Any]]],
        poll_interval: float = 5.0,
    ) -> None:
        """Periodically fetch tool descriptors from a source and check for changes."""
        self._running = True
        self.log.info("tool_watcher_started", baseline_count=len(self._baselines))

        while self._running:
            try:
                tools = tool_source()
                self.check_all(tools)
            except Exception as exc:
                self.log.error("tool_watch_error", error=str(exc))
            try:
                await asyncio.sleep(poll_interval)
            except asyncio.CancelledError:
                break

        self.log.info("tool_watcher_stopped")

    def stop(self) -> None:
        """Signal the watch loop to stop."""
        self._running = False

    @property
    def alerts(self) -> list[RugPullAlert]:
        return list(self._alerts)

    @property
    def baselines(self) -> dict[str, ToolHashRecord]:
        return dict(self._baselines)
