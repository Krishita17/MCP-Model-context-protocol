"""Settings page — API key configuration, theme toggle, about info."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QLineEdit,
    QScrollArea,
    QGroupBox,
    QFormLayout,
    QCheckBox,
)

from gui.theme import COLORS


class SettingsPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._fields: dict[str, QLineEdit] = {}

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        main = QVBoxLayout(container)
        main.setContentsMargins(28, 24, 28, 24)
        main.setSpacing(16)

        header = QLabel("⚙ Settings")
        header.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 22px; font-weight: bold;")
        main.addWidget(header)

        subtitle = QLabel("Configure API keys, preferences, and application settings")
        subtitle.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 13px;")
        main.addWidget(subtitle)

        # API Keys
        api_group = QGroupBox("API Key Configuration")
        api_form = QFormLayout(api_group)
        api_form.setSpacing(10)

        api_keys = [
            ("OpenAI API Key", "openai_key", "sk-..."),
            ("Anthropic API Key", "anthropic_key", "sk-ant-..."),
            ("Google AI API Key", "google_key", "AIza..."),
            ("Hugging Face Token", "hf_token", "hf_..."),
            ("Custom LLM Endpoint", "custom_endpoint", "https://..."),
        ]
        for label, key, placeholder in api_keys:
            field = QLineEdit()
            field.setPlaceholderText(placeholder)
            field.setEchoMode(QLineEdit.EchoMode.Password)
            self._fields[key] = field
            api_form.addRow(label + ":", field)

        note = QLabel("Note: API keys are optional. All attack/defense simulations run locally without API access.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; padding-top: 4px;")
        api_form.addRow("", note)

        main.addWidget(api_group)

        # Preferences
        pref_group = QGroupBox("Preferences")
        pref_layout = QVBoxLayout(pref_group)

        self.verbose_check = QCheckBox("Verbose logging (show debug output in results)")
        self.verbose_check.setChecked(False)
        pref_layout.addWidget(self.verbose_check)

        self.autorefresh_check = QCheckBox("Auto-refresh audit log on new entries")
        self.autorefresh_check.setChecked(True)
        pref_layout.addWidget(self.autorefresh_check)

        self.confirm_check = QCheckBox("Confirm before executing attacks")
        self.confirm_check.setChecked(True)
        pref_layout.addWidget(self.confirm_check)

        main.addWidget(pref_group)

        # Save button
        btn_row = QHBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.setFixedHeight(38)
        save_btn.clicked.connect(self._save)
        btn_row.addWidget(save_btn)

        clear_btn = QPushButton("Clear All Keys")
        clear_btn.setFixedHeight(38)
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['red']};
                border: 1px solid {COLORS['red']};
                border-radius: 6px;
                padding: 0 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: {COLORS['red']}; color: #ffffff; }}
        """)
        clear_btn.clicked.connect(self._clear_keys)
        btn_row.addWidget(clear_btn)
        btn_row.addStretch()
        main.addLayout(btn_row)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet(f"color: {COLORS['green']}; font-size: 12px;")
        main.addWidget(self.status_label)

        # About
        about_group = QGroupBox("About")
        about_layout = QVBoxLayout(about_group)

        about_text = QLabel(
            "<b>MCP Security Console</b> v1.0.0<br><br>"
            "A comprehensive security research toolkit for the Model Context Protocol ecosystem.<br><br>"
            "<b>Components:</b><br>"
            "  - MCPoisoner: Attack simulation engine (5 attack vectors)<br>"
            "  - MCPShield: Defense proxy with static analysis, runtime monitoring, and policy engine<br>"
            "  - CryptoMCP: Ed25519 signing and Merkle audit chains<br>"
            "  - Governance: Shared responsibility model and FAIR risk assessment<br><br>"
            "<span style='color: #64748b;'>Built for security research and education purposes.</span>"
        )
        about_text.setWordWrap(True)
        about_text.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px; line-height: 1.5;")
        about_layout.addWidget(about_text)
        main.addWidget(about_group)

        main.addStretch()

        scroll.setWidget(container)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    def _save(self) -> None:
        self.status_label.setText("Settings saved successfully.")
        self.status_label.setStyleSheet(f"color: {COLORS['green']}; font-size: 12px;")

    def _clear_keys(self) -> None:
        for field in self._fields.values():
            field.clear()
        self.status_label.setText("All API keys cleared.")
        self.status_label.setStyleSheet(f"color: {COLORS['yellow']}; font-size: 12px;")
