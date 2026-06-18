"""Main application window with sidebar navigation and stacked pages."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QHBoxLayout,
    QStackedWidget,
)

from gui.theme import get_stylesheet
from gui.widgets.sidebar import Sidebar
from gui.widgets.dashboard import DashboardPage
from gui.widgets.attack_lab import AttackLabPage
from gui.widgets.defense_lab import DefenseLabPage
from gui.widgets.scanner import ScannerPage
from gui.widgets.crypto_page import CryptoPage
from gui.widgets.audit_page import AuditPage
from gui.widgets.governance_page import GovernancePage
from gui.widgets.settings_page import SettingsPage


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MCP Security Console")
        self.setMinimumSize(1100, 700)
        self.resize(1300, 800)
        self.setStyleSheet(get_stylesheet())

        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Pages
        self.stack = QStackedWidget()
        self.dashboard = DashboardPage()
        self.attack_lab = AttackLabPage()
        self.defense_lab = DefenseLabPage()
        self.scanner = ScannerPage()
        self.crypto = CryptoPage()
        self.audit = AuditPage()
        self.governance = GovernancePage()
        self.settings = SettingsPage()

        self.stack.addWidget(self.dashboard)    # 0
        self.stack.addWidget(self.attack_lab)   # 1
        self.stack.addWidget(self.defense_lab)  # 2
        self.stack.addWidget(self.scanner)      # 3
        self.stack.addWidget(self.crypto)       # 4
        self.stack.addWidget(self.audit)        # 5
        self.stack.addWidget(self.governance)   # 6
        self.stack.addWidget(self.settings)     # 7

        # Sidebar
        self.sidebar = Sidebar()
        self.sidebar.page_selected.connect(self._on_page_selected)

        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack, 1)

        # Wire dashboard quick actions
        self.dashboard.navigate_requested.connect(self._on_page_selected)

    def _on_page_selected(self, index: int) -> None:
        if 0 <= index < self.stack.count():
            self.stack.setCurrentIndex(index)
            self.sidebar.set_active(index)
