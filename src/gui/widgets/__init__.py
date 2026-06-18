"""GUI widget package for the MCP Security Console."""

from gui.widgets.sidebar import Sidebar
from gui.widgets.dashboard import DashboardPage
from gui.widgets.attack_lab import AttackLabPage
from gui.widgets.defense_lab import DefenseLabPage
from gui.widgets.scanner import ScannerPage
from gui.widgets.crypto_page import CryptoPage
from gui.widgets.audit_page import AuditPage
from gui.widgets.governance_page import GovernancePage
from gui.widgets.settings_page import SettingsPage

__all__ = [
    "Sidebar",
    "DashboardPage",
    "AttackLabPage",
    "DefenseLabPage",
    "ScannerPage",
    "CryptoPage",
    "AuditPage",
    "GovernancePage",
    "SettingsPage",
]
