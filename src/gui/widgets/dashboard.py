"""Dashboard page with summary cards, quick actions, and status panel."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QScrollArea,
    QGridLayout,
)

from gui.theme import COLORS
from mcpoisoner.attacks import ATTACK_REGISTRY
from mcpshield.static_analysis.scanner import SUSPICIOUS_PATTERNS
from cryptomcp.merkle.audit_log import MerkleAuditLog


def _card(title: str, value: str, color: str, subtitle: str = "") -> QFrame:
    c = COLORS
    frame = QFrame()
    frame.setFixedSize(230, 120)
    frame.setStyleSheet(f"""
        QFrame {{
            background-color: {c['bg_card']};
            border: 1px solid {c['border']};
            border-radius: 10px;
            border-top: 3px solid {color};
        }}
    """)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(4)

    lbl_title = QLabel(title)
    lbl_title.setStyleSheet(f"color: {c['text_secondary']}; font-size: 11px; font-weight: bold; text-transform: uppercase;")
    layout.addWidget(lbl_title)

    lbl_value = QLabel(value)
    lbl_value.setStyleSheet(f"color: {color}; font-size: 32px; font-weight: bold;")
    layout.addWidget(lbl_value)

    if subtitle:
        lbl_sub = QLabel(subtitle)
        lbl_sub.setStyleSheet(f"color: {c['text_muted']}; font-size: 11px;")
        layout.addWidget(lbl_sub)

    layout.addStretch()
    return frame


class DashboardPage(QWidget):
    navigate_requested = Signal(int)

    def __init__(self) -> None:
        super().__init__()
        self._audit_log = MerkleAuditLog()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        main_layout = QVBoxLayout(container)
        main_layout.setContentsMargins(28, 24, 28, 24)
        main_layout.setSpacing(20)

        # Header
        header = QLabel("◈ Dashboard")
        header.setStyleSheet(f"color: {COLORS['cyan']}; font-size: 22px; font-weight: bold;")
        main_layout.addWidget(header)

        subtitle = QLabel("MCP Security Suite overview and quick actions")
        subtitle.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 13px;")
        main_layout.addWidget(subtitle)

        # Summary cards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(16)
        cards_layout.addWidget(_card(
            "Attack Vectors", str(len(ATTACK_REGISTRY)),
            COLORS['red'], "Available in Attack Lab"
        ))
        cards_layout.addWidget(_card(
            "Detection Rules", str(len(SUSPICIOUS_PATTERNS)),
            COLORS['cyan'], "Static analysis patterns"
        ))
        cards_layout.addWidget(_card(
            "Crypto Keys", "0",
            COLORS['purple'], "Generate in Crypto tab"
        ))
        cards_layout.addWidget(_card(
            "Audit Entries", str(self._audit_log.chain_length),
            COLORS['green'], "Merkle-chained log"
        ))
        cards_layout.addStretch()
        main_layout.addLayout(cards_layout)

        # Quick actions
        actions_label = QLabel("Quick Actions")
        actions_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 15px; font-weight: bold;")
        main_layout.addWidget(actions_label)

        actions_layout = QHBoxLayout()
        actions_layout.setSpacing(12)

        action_defs = [
            ("☠ Launch Attack Lab", 1, COLORS['red']),
            ("⛨ Run Defense Sim", 2, COLORS['cyan']),
            ("☸ Scan a Tool", 3, COLORS['yellow']),
            ("✷ Generate Keys", 4, COLORS['purple']),
        ]
        for label, page_idx, color in action_defs:
            btn = QPushButton(label)
            btn.setFixedHeight(42)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS['bg_card']};
                    color: {color};
                    border: 1px solid {color};
                    border-radius: 8px;
                    padding: 0 20px;
                    font-weight: bold;
                    font-size: 13px;
                }}
                QPushButton:hover {{
                    background-color: {color};
                    color: #ffffff;
                }}
            """)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked=False, idx=page_idx: self.navigate_requested.emit(idx))
            actions_layout.addWidget(btn)
        actions_layout.addStretch()
        main_layout.addLayout(actions_layout)

        # Status panel
        status_label = QLabel("System Status")
        status_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 15px; font-weight: bold;")
        main_layout.addWidget(status_label)

        status_frame = QFrame()
        status_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 10px;
            }}
        """)
        status_grid = QGridLayout(status_frame)
        status_grid.setContentsMargins(20, 16, 20, 16)
        status_grid.setSpacing(10)

        statuses = [
            ("MCPoisoner Engine", "Loaded", COLORS['green']),
            ("MCPShield Proxy", "Ready", COLORS['green']),
            ("Static Scanner", "Active", COLORS['green']),
            ("CryptoMCP Module", "Available", COLORS['green']),
            ("Merkle Audit Log", "Initialized", COLORS['green']),
            ("Policy Engine", "Default rules", COLORS['cyan']),
            ("Runtime Monitor", "Standby", COLORS['yellow']),
            ("Governance Model", "Loaded", COLORS['green']),
        ]
        for i, (name, status, color) in enumerate(statuses):
            row, col = divmod(i, 2)
            name_lbl = QLabel(f"  {name}")
            name_lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
            status_lbl = QLabel(f"● {status}")
            status_lbl.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: bold;")
            status_grid.addWidget(name_lbl, row, col * 2)
            status_grid.addWidget(status_lbl, row, col * 2 + 1)

        main_layout.addWidget(status_frame)
        main_layout.addStretch()

        scroll.setWidget(container)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
