"""Merkle-chained audit log for tamper-evident tool invocation records."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    timestamp: float
    tool_name: str
    tool_hash: str
    action: str
    decision: str
    previous_hash: str
    entry_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)


class MerkleAuditLog:
    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._genesis_hash = hashlib.sha256(b"GENESIS").hexdigest()

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    @property
    def chain_length(self) -> int:
        return len(self._entries)

    @property
    def latest_hash(self) -> str:
        if not self._entries:
            return self._genesis_hash
        return self._entries[-1].entry_hash

    def append(
        self,
        tool_name: str,
        tool_hash: str,
        action: str,
        decision: str,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        prev_hash = self.latest_hash
        timestamp = time.time()
        sequence = len(self._entries)

        payload = json.dumps(
            {
                "seq": sequence,
                "ts": timestamp,
                "tool": tool_name,
                "hash": tool_hash,
                "action": action,
                "decision": decision,
                "prev": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        entry = AuditEntry(
            sequence=sequence,
            timestamp=timestamp,
            tool_name=tool_name,
            tool_hash=tool_hash,
            action=action,
            decision=decision,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            metadata=metadata or {},
        )
        self._entries.append(entry)
        return entry

    def verify_chain_integrity(self) -> tuple[bool, str | None]:
        if not self._entries:
            return True, None

        if self._entries[0].previous_hash != self._genesis_hash:
            return False, "First entry does not reference genesis hash"

        for i in range(1, len(self._entries)):
            if self._entries[i].previous_hash != self._entries[i - 1].entry_hash:
                return False, f"Chain broken at entry {i}: previous_hash mismatch"

        return True, None

    def export_json(self, path: Path) -> None:
        data = {
            "genesis_hash": self._genesis_hash,
            "chain_length": self.chain_length,
            "entries": [
                {
                    "sequence": e.sequence,
                    "timestamp": e.timestamp,
                    "tool_name": e.tool_name,
                    "tool_hash": e.tool_hash,
                    "action": e.action,
                    "decision": e.decision,
                    "previous_hash": e.previous_hash,
                    "entry_hash": e.entry_hash,
                    "metadata": e.metadata,
                }
                for e in self._entries
            ],
        }
        path.write_text(json.dumps(data, indent=2))

    @classmethod
    def import_json(cls, path: Path) -> MerkleAuditLog:
        data = json.loads(path.read_text())
        log = cls()
        for entry_data in data["entries"]:
            entry = AuditEntry(**entry_data)
            log._entries.append(entry)
        return log
