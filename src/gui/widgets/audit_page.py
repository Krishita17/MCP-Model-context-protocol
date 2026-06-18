"""Audit Log page — view Merkle-chained entries and verify chain integrity."""

from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QTextEdit,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QGroupBox,
)

from gui.theme import COLORS
from cryptomcp.merkle.audit_log import MerkleAuditLog


class AuditPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._log = MerkleAuditLog()
        # Seed some demo entries
        self._log.append("get_weather", "abc123", "register", "approved")
        self._log.append("calculator", "def456", "register", "blocked_static")
        self._log.append("get_weather", "abc123", "invoke", "allowed")
        self._log.append("file_reader", "ghi789", "register", "requires_approval")
        self._log.append("search_engine", "jkl012", "register", "blocked_crypto", metadata={"error": "Invalid signature"})

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        main = QVBoxLayout(container)
        main.setContentsMargins(28, 24, 28, 24)
        main.setSpacing(16)

        header = QLabel("☰ Audit Log")
        header.setStyleSheet(f"color: {COLORS['green']}; font-size: 22px; font-weight: bold;")
        main.addWidget(header)

        subtitle = QLabel("Merkle-chained tamper-evident audit trail of all tool operations")
        subtitle.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 13px;")
        main.addWidget(subtitle)

        # Controls
        ctrl_row = QHBoxLayout()
        verify_btn = QPushButton("✓  Verify Chain Integrity")
        verify_btn.setFixedHeight(38)
        verify_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['green']};
                color: #000000;
                border: none;
                border-radius: 8px;
                font-weight: bold;
                padding: 0 20px;
            }}
            QPushButton:hover {{ background-color: {COLORS['green_dark']}; color: #ffffff; }}
        """)
        verify_btn.clicked.connect(self._verify_chain)
        ctrl_row.addWidget(verify_btn)

        add_btn = QPushButton("+  Add Sample Entry")
        add_btn.setFixedHeight(38)
        add_btn.clicked.connect(self._add_sample)
        ctrl_row.addWidget(add_btn)

        refresh_btn = QPushButton("↻  Refresh")
        refresh_btn.setFixedHeight(38)
        refresh_btn.clicked.connect(self._refresh_table)
        ctrl_row.addWidget(refresh_btn)
        ctrl_row.addStretch()

        info = QLabel(f"Chain Length: {self._log.chain_length}")
        info.setObjectName("chain_info")
        info.setStyleSheet(f"color: {COLORS['cyan']}; font-weight: bold;")
        ctrl_row.addWidget(info)
        self._chain_info = info
        main.addLayout(ctrl_row)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Seq", "Tool", "Action", "Decision", "Entry Hash", "Prev Hash"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 50)
        self.table.setAlternatingRowColors(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setMinimumHeight(250)
        main.addWidget(self.table)

        # Verification output
        self.status_area = QTextEdit()
        self.status_area.setReadOnly(True)
        self.status_area.setMaximumHeight(120)
        self.status_area.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['bg_medium']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                font-family: "JetBrains Mono", "Fira Code", "Consolas", monospace;
                font-size: 12px;
                padding: 10px;
            }}
        """)
        main.addWidget(self.status_area)
        main.addStretch()

        scroll.setWidget(container)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        self._refresh_table()

    def _refresh_table(self) -> None:
        entries = self._log.entries
        self.table.setRowCount(len(entries))

        decision_colors = {
            "approved": COLORS["green"],
            "allowed": COLORS["green"],
            "blocked_static": COLORS["red"],
            "blocked_runtime": COLORS["red"],
            "blocked_policy": COLORS["red"],
            "blocked_crypto": COLORS["red"],
            "requires_approval": COLORS["yellow"],
        }

        for row, e in enumerate(entries):
            items = [
                str(e.sequence),
                e.tool_name,
                e.action,
                e.decision,
                e.entry_hash[:24] + "...",
                e.previous_hash[:24] + "...",
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 3:
                    color = decision_colors.get(e.decision, COLORS["text_secondary"])
                    item.setForeground(Qt.GlobalColor.white)
                    from PySide6.QtGui import QColor, QBrush
                    item.setForeground(QBrush(QColor(color)))
                self.table.setItem(row, col, item)

        self._chain_info.setText(f"Chain Length: {self._log.chain_length}")

    def _verify_chain(self) -> None:
        valid, error = self._log.verify_chain_integrity()
        c = COLORS
        if valid:
            self.status_area.setHtml(
                f"<span style='color:{c['green']}; font-size: 14px; font-weight: bold;'>"
                f"✓ Chain integrity VERIFIED</span><br>"
                f"<span style='color:{c['text_secondary']}'>"
                f"All {self._log.chain_length} entries form a valid Merkle chain.<br>"
                f"Genesis hash: {self._log._genesis_hash[:32]}...<br>"
                f"Latest hash: {self._log.latest_hash[:32]}...</span>"
            )
        else:
            self.status_area.setHtml(
                f"<span style='color:{c['red']}; font-size: 14px; font-weight: bold;'>"
                f"✗ Chain integrity FAILED</span><br>"
                f"<span style='color:{c['red']}'>{error}</span>"
            )

    def _add_sample(self) -> None:
        import random
        tools = ["api_gateway", "db_connector", "auth_service", "log_aggregator"]
        actions = ["register", "invoke"]
        decisions = ["approved", "allowed", "blocked_static", "requires_approval"]
        self._log.append(
            random.choice(tools),
            f"hash_{random.randint(1000, 9999)}",
            random.choice(actions),
            random.choice(decisions),
        )
        self._refresh_table()
