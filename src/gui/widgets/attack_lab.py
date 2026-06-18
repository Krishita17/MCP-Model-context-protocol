"""Attack Lab page — select, configure, and execute MCP attack simulations."""

from __future__ import annotations

import asyncio
import traceback
from typing import Any

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QComboBox,
    QSpinBox,
    QFrame,
    QTextEdit,
    QScrollArea,
    QGroupBox,
    QFormLayout,
    QLineEdit,
)

from gui.theme import COLORS
from mcpoisoner.attacks import ATTACK_REGISTRY
from mcpoisoner.attacks.base import AttackConfig, AttackClass, AttackResult

ATTACK_DESCRIPTIONS = {
    "description_injection": "Injects hidden instructions into tool descriptions using invisible Unicode, "
                             "homoglyphs, and prompt injection to hijack agent behavior.",
    "tool_shadowing": "Registers a malicious tool that mimics a legitimate tool's name/description "
                      "to intercept and redirect agent calls.",
    "rug_pull": "Passes initial security checks, then mutates tool behavior post-approval "
                "to enable persistent backdoor access.",
    "return_value_poisoning": "Embeds malicious payloads in tool return values to manipulate "
                              "the agent's context and future actions.",
    "cross_tool_escalation": "Chains multiple benign-looking tool calls to achieve compound "
                             "privilege escalation the agent's policy would normally block.",
}


class AttackWorker(QThread):
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, attack_key: str, config: AttackConfig) -> None:
        super().__init__()
        self.attack_key = attack_key
        self.config = config

    def run(self) -> None:
        try:
            attack_cls = ATTACK_REGISTRY[self.attack_key]
            attack = attack_cls(self.config)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            results = loop.run_until_complete(attack.run())
            loop.close()
            self.finished.emit(results)
        except Exception as exc:
            self.error.emit(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")


class AttackLabPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._worker: AttackWorker | None = None

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        main = QVBoxLayout(container)
        main.setContentsMargins(28, 24, 28, 24)
        main.setSpacing(16)

        header = QLabel("☠ Attack Lab")
        header.setStyleSheet(f"color: {COLORS['red']}; font-size: 22px; font-weight: bold;")
        main.addWidget(header)

        subtitle = QLabel("Configure and execute MCP attack simulations against local targets")
        subtitle.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 13px;")
        main.addWidget(subtitle)

        # Config section
        config_group = QGroupBox("Attack Configuration")
        config_form = QFormLayout(config_group)
        config_form.setSpacing(10)

        self.attack_combo = QComboBox()
        for key in ATTACK_REGISTRY:
            self.attack_combo.addItem(key.replace("_", " ").title(), key)
        self.attack_combo.currentIndexChanged.connect(self._update_description)
        config_form.addRow("Attack Type:", self.attack_combo)

        self.desc_label = QLabel()
        self.desc_label.setWordWrap(True)
        self.desc_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px; padding: 4px 0;")
        config_form.addRow("", self.desc_label)

        self.llm_input = QLineEdit("mock-llm")
        config_form.addRow("LLM Backend:", self.llm_input)

        self.framework_input = QLineEdit("mock-agent")
        config_form.addRow("Agent Framework:", self.framework_input)

        self.iterations_spin = QSpinBox()
        self.iterations_spin.setRange(1, 100)
        self.iterations_spin.setValue(3)
        config_form.addRow("Iterations:", self.iterations_spin)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setSuffix(" sec")
        config_form.addRow("Timeout:", self.timeout_spin)

        main.addWidget(config_group)

        # Run button
        btn_row = QHBoxLayout()
        self.run_btn = QPushButton("▶  Execute Attack")
        self.run_btn.setFixedHeight(42)
        self.run_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['red']};
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
                padding: 0 28px;
            }}
            QPushButton:hover {{ background-color: {COLORS['red_dark']}; }}
            QPushButton:disabled {{ background-color: {COLORS['border']}; color: {COLORS['text_muted']}; }}
        """)
        self.run_btn.clicked.connect(self._run_attack)
        btn_row.addWidget(self.run_btn)
        btn_row.addStretch()
        main.addLayout(btn_row)

        # Results
        results_label = QLabel("Results")
        results_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 15px; font-weight: bold;")
        main.addWidget(results_label)

        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        self.results_area.setMinimumHeight(280)
        self.results_area.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['bg_medium']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                font-family: "JetBrains Mono", "Fira Code", "Consolas", monospace;
                font-size: 12px;
                padding: 12px;
            }}
        """)
        main.addWidget(self.results_area)
        main.addStretch()

        scroll.setWidget(container)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        self._update_description()

    def _update_description(self) -> None:
        key = self.attack_combo.currentData()
        self.desc_label.setText(ATTACK_DESCRIPTIONS.get(key, ""))

    def _run_attack(self) -> None:
        key = self.attack_combo.currentData()
        config = AttackConfig(
            attack_class=AttackClass(key),
            llm_backend=self.llm_input.text().strip() or "mock-llm",
            agent_framework=self.framework_input.text().strip() or "mock-agent",
            iterations=self.iterations_spin.value(),
            timeout_seconds=float(self.timeout_spin.value()),
        )

        self.run_btn.setEnabled(False)
        self.run_btn.setText("⟳  Running...")
        self.results_area.setHtml(f"<span style='color:{COLORS['yellow']}'>Executing {key} attack...</span>")

        self._worker = AttackWorker(key, config)
        self._worker.finished.connect(self._on_results)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_results(self, results: list[AttackResult]) -> None:
        self.run_btn.setEnabled(True)
        self.run_btn.setText("▶  Execute Attack")

        lines = [f"<h3 style='color:{COLORS['cyan']}'>Attack Results — {len(results)} iteration(s)</h3><hr>"]
        for i, r in enumerate(results):
            color = COLORS['red'] if r.success else COLORS['green']
            status = "SUCCEEDED" if r.success else "BLOCKED/FAILED"
            lines.append(f"<b style='color:{COLORS['cyan']}'>Iteration {i + 1}</b>")
            lines.append(f"  Status: <b style='color:{color}'>{status}</b>")
            lines.append(f"  Success Rate: <span style='color:{color}'>{r.attack_success_rate:.0%}</span>")
            if r.time_to_detection_ms is not None:
                lines.append(f"  Detection Time: {r.time_to_detection_ms:.1f} ms")
            lines.append(f"  Data Exfiltrated: {r.data_exfiltration_bytes} bytes")
            if r.regulatory_triggers:
                triggers = ", ".join(r.regulatory_triggers)
                lines.append(f"  Regulatory Triggers: <span style='color:{COLORS['orange']}'>{triggers}</span>")
            if r.crypto_defense_effective is not None:
                ccolor = COLORS['green'] if r.crypto_defense_effective else COLORS['red']
                lines.append(f"  Crypto Defense: <span style='color:{ccolor}'>{'Effective' if r.crypto_defense_effective else 'Bypassed'}</span>")
            if r.details:
                for dk, dv in r.details.items():
                    lines.append(f"  {dk}: {dv}")
            lines.append("")

        self.results_area.setHtml("<pre>" + "\n".join(lines) + "</pre>")

    def _on_error(self, msg: str) -> None:
        self.run_btn.setEnabled(True)
        self.run_btn.setText("▶  Execute Attack")
        self.results_area.setHtml(
            f"<pre><span style='color:{COLORS['red']}'>ERROR:\n{msg}</span></pre>"
        )
