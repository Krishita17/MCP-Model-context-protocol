"""Tests for CryptoMCP Merkle audit log."""

import tempfile
from pathlib import Path

import pytest

from cryptomcp.merkle.audit_log import MerkleAuditLog


@pytest.fixture
def audit_log():
    return MerkleAuditLog()


class TestMerkleAuditLog:
    def test_empty_log_valid(self, audit_log):
        valid, error = audit_log.verify_chain_integrity()
        assert valid
        assert error is None
        assert audit_log.chain_length == 0

    def test_append_entry(self, audit_log):
        entry = audit_log.append(
            tool_name="calculator",
            tool_hash="abc123",
            action="register",
            decision="approved",
        )
        assert entry.sequence == 0
        assert entry.tool_name == "calculator"
        assert audit_log.chain_length == 1

    def test_chain_integrity(self, audit_log):
        for i in range(10):
            audit_log.append(
                tool_name=f"tool_{i}",
                tool_hash=f"hash_{i}",
                action="invoke",
                decision="allowed",
            )
        valid, error = audit_log.verify_chain_integrity()
        assert valid
        assert error is None

    def test_chain_links(self, audit_log):
        e1 = audit_log.append("t1", "h1", "register", "approved")
        e2 = audit_log.append("t2", "h2", "invoke", "allowed")
        assert e2.previous_hash == e1.entry_hash

    def test_unique_hashes(self, audit_log):
        entries = []
        for i in range(5):
            entries.append(audit_log.append(f"tool_{i}", f"hash_{i}", "invoke", "allowed"))
        hashes = {e.entry_hash for e in entries}
        assert len(hashes) == 5

    def test_export_import_roundtrip(self, audit_log):
        for i in range(3):
            audit_log.append(f"tool_{i}", f"hash_{i}", "invoke", "allowed")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)

        audit_log.export_json(path)
        restored = MerkleAuditLog.import_json(path)
        assert restored.chain_length == 3
        assert restored.entries[0].tool_name == "tool_0"
        path.unlink()

    def test_tamper_detection(self, audit_log):
        audit_log.append("t1", "h1", "register", "approved")
        audit_log.append("t2", "h2", "invoke", "allowed")
        audit_log.append("t3", "h3", "invoke", "blocked")

        audit_log._entries[1] = audit_log._entries[1].__class__(
            sequence=1,
            timestamp=audit_log._entries[1].timestamp,
            tool_name="TAMPERED",
            tool_hash="fake",
            action="invoke",
            decision="allowed",
            previous_hash="wrong_hash",
            entry_hash="fake_hash",
        )

        valid, error = audit_log.verify_chain_integrity()
        assert not valid
