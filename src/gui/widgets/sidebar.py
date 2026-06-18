"""Navigation sidebar with Unicode icons and hover effects."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
)

from gui.theme import COLORS

NAV_ITEMS = [
    ("◈", "Dashboard"),        # ◈
    ("☠", "Attack Lab"),       # ☠
    ("⛨", "Defense Lab"),      # ⛨
    ("☸", "Scanner"),          # ☸
    ("✷", "Crypto Verify"),    # ✷
    ("☰", "Audit Log"),        # ☰
    ("⚖", "Governance"),       # ⚖
    ("⚙", "Settings"),         # ⚙
]


class SidebarButton(QPushButton):
    def __init__(self, icon: str, label: str, index: int) -> None:
        super().__init__(f"  {icon}  {label}")
        self.index = index
        self.active = False
        self.setFixedHeight(44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._apply_style()

    def set_active(self, active: bool) -> None:
        self.active = active
        self._apply_style()

    def _apply_style(self) -> None:
        c = COLORS
        if self.active:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {c['purple_dark']};
                    color: #ffffff;
                    border: none;
                    border-left: 3px solid {c['cyan']};
                    border-radius: 0px;
                    text-align: left;
                    padding-left: 16px;
                    font-size: 13px;
                    font-weight: bold;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    color: {c['text_secondary']};
                    border: none;
                    border-left: 3px solid transparent;
                    border-radius: 0px;
                    text-align: left;
                    padding-left: 16px;
                    font-size: 13px;
                    font-weight: normal;
                }}
                QPushButton:hover {{
                    background-color: {c['bg_light']};
                    color: {c['text_primary']};
                    border-left: 3px solid {c['purple']};
                }}
            """)


class Sidebar(QWidget):
    page_selected = Signal(int)

    def __init__(self) -> None:
        super().__init__()
        self.setFixedWidth(220)
        c = COLORS
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {c['bg_dark']};
                border-right: 1px solid {c['border']};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Logo / title area
        title_container = QWidget()
        title_container.setFixedHeight(70)
        title_container.setStyleSheet(f"""
            QWidget {{
                background-color: {c['bg_dark']};
                border-bottom: 1px solid {c['border']};
                border-right: none;
            }}
        """)
        title_layout = QVBoxLayout(title_container)
        title_layout.setContentsMargins(16, 12, 16, 8)

        logo_label = QLabel("⚡ MCP Security")
        logo_label.setStyleSheet(f"""
            QLabel {{
                color: {c['cyan']};
                font-size: 17px;
                font-weight: bold;
                background: transparent;
            }}
        """)
        version_label = QLabel("Console v1.0")
        version_label.setStyleSheet(f"""
            QLabel {{
                color: {c['text_muted']};
                font-size: 11px;
                background: transparent;
            }}
        """)
        title_layout.addWidget(logo_label)
        title_layout.addWidget(version_label)
        layout.addWidget(title_container)

        # Navigation buttons
        self.buttons: list[SidebarButton] = []
        for i, (icon, label) in enumerate(NAV_ITEMS):
            btn = SidebarButton(icon, label, i)
            btn.clicked.connect(lambda checked=False, idx=i: self._on_click(idx))
            self.buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch(1)

        # Footer
        footer = QLabel("  ⬢ Secure Session Active")
        footer.setFixedHeight(36)
        footer.setStyleSheet(f"""
            QLabel {{
                color: {c['green']};
                font-size: 11px;
                background: transparent;
                border-top: 1px solid {c['border']};
                padding-left: 12px;
            }}
        """)
        layout.addWidget(footer)

        # Set initial active
        self.set_active(0)

    def _on_click(self, index: int) -> None:
        self.page_selected.emit(index)

    def set_active(self, index: int) -> None:
        for btn in self.buttons:
            btn.set_active(btn.index == index)
