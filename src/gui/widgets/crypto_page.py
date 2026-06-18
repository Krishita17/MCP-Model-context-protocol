"""Crypto Verify page — key generation, tool signing, and verification UI."""

from __future__ import annotations

import json
import traceback

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QTextEdit,
    QLineEdit,
    QScrollArea,
    QGroupBox,
    QFormLayout,
)

from gui.theme import COLORS
from cryptomcp.signing.keys import generate_key_pair, KeyPair
from cryptomcp.signing.signer import ToolSigner, ToolVerifier, SignedToolDescriptor

SAMPLE_TOOL = {
    "name": "safe_calculator",
    "description": "Performs basic arithmetic operations",
    "inputSchema": {
        "type": "object",
        "properties": {
            "expression": {"type": "string", "description": "Math expression to evaluate"}
        }
    }
}


class CryptoPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._key_pair: KeyPair | None = None
        self._signed_bundle: dict | None = None

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        main = QVBoxLayout(container)
        main.setContentsMargins(28, 24, 28, 24)
        main.setSpacing(16)

        header = QLabel("✷ Crypto Verify")
        header.setStyleSheet(f"color: {COLORS['purple_light']}; font-size: 22px; font-weight: bold;")
        main.addWidget(header)

        subtitle = QLabel("Generate Ed25519 keys, sign tool descriptions, and verify cryptographic integrity")
        subtitle.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 13px;")
        main.addWidget(subtitle)

        # Key generation
        key_group = QGroupBox("Key Management")
        key_layout = QVBoxLayout(key_group)

        key_form = QFormLayout()
        self.publisher_input = QLineEdit("mcp-publisher-001")
        key_form.addRow("Publisher ID:", self.publisher_input)
        key_layout.addLayout(key_form)

        key_btn_row = QHBoxLayout()
        gen_btn = QPushButton("✷  Generate Ed25519 Key Pair")
        gen_btn.setFixedHeight(38)
        gen_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['purple']};
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-weight: bold;
                padding: 0 20px;
            }}
            QPushButton:hover {{ background-color: {COLORS['purple_light']}; }}
        """)
        gen_btn.clicked.connect(self._generate_keys)
        key_btn_row.addWidget(gen_btn)
        key_btn_row.addStretch()
        key_layout.addLayout(key_btn_row)

        self.key_output = QTextEdit()
        self.key_output.setReadOnly(True)
        self.key_output.setMaximumHeight(100)
        self.key_output.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['bg_medium']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                font-family: "JetBrains Mono", "Fira Code", "Consolas", monospace;
                font-size: 11px;
                padding: 8px;
            }}
        """)
        key_layout.addWidget(self.key_output)
        main.addWidget(key_group)

        # Signing
        sign_group = QGroupBox("Tool Signing")
        sign_layout = QVBoxLayout(sign_group)

        self.tool_input = QTextEdit()
        self.tool_input.setMaximumHeight(120)
        self.tool_input.setPlainText(json.dumps(SAMPLE_TOOL, indent=2))
        self.tool_input.setPlaceholderText("Paste tool descriptor JSON...")
        sign_layout.addWidget(self.tool_input)

        sign_btn_row = QHBoxLayout()
        sign_btn = QPushButton("✍  Sign Tool")
        sign_btn.setFixedHeight(38)
        sign_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['cyan']};
                color: #000000;
                border: none;
                border-radius: 8px;
                font-weight: bold;
                padding: 0 20px;
            }}
            QPushButton:hover {{ background-color: {COLORS['cyan_dark']}; color: #ffffff; }}
        """)
        sign_btn.clicked.connect(self._sign_tool)
        sign_btn_row.addWidget(sign_btn)

        verify_btn = QPushButton("✓  Verify Signature")
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
        verify_btn.clicked.connect(self._verify_tool)
        sign_btn_row.addWidget(verify_btn)
        sign_btn_row.addStretch()
        sign_layout.addLayout(sign_btn_row)
        main.addWidget(sign_group)

        # Output
        results_label = QLabel("Output")
        results_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 15px; font-weight: bold;")
        main.addWidget(results_label)

        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        self.results_area.setMinimumHeight(240)
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

    def _generate_keys(self) -> None:
        try:
            self._key_pair = generate_key_pair()
            pub = self._key_pair.public_key_hex
            self.key_output.setHtml(
                f"<span style='color:{COLORS['green']}'>Key pair generated successfully.</span><br>"
                f"<b>Public Key:</b> {pub[:32]}...<br>"
                f"<b>Algorithm:</b> Ed25519"
            )
        except Exception as exc:
            self.key_output.setHtml(f"<span style='color:{COLORS['red']}'>Error: {exc}</span>")

    def _sign_tool(self) -> None:
        if not self._key_pair:
            self.results_area.setHtml(f"<span style='color:{COLORS['red']}'>Generate a key pair first.</span>")
            return

        try:
            tool = json.loads(self.tool_input.toPlainText())
            publisher = self.publisher_input.text().strip() or "unknown"
            signer = ToolSigner(self._key_pair, publisher)
            descriptor = signer.sign(tool, version="1.0.0")
            self._signed_bundle = descriptor.to_bundle()

            c = COLORS
            lines = [
                f"<h3 style='color:{c['cyan']}'>Tool Signed Successfully</h3><hr>",
                f"<b>Tool:</b> {tool.get('name', 'unknown')}",
                f"<b>Publisher:</b> {publisher}",
                f"<b>Hash (SHA-256):</b> {descriptor.tool_hash[:48]}...",
                f"<b>Signature:</b> {descriptor.signature[:48]}...",
                f"<b>Public Key:</b> {descriptor.public_key[:48]}...",
                f"<b>Version:</b> {descriptor.version}",
                "",
                f"<span style='color:{c['green']}'>Bundle stored in memory. Click Verify to validate.</span>",
            ]
            self.results_area.setHtml("<pre>" + "\n".join(lines) + "</pre>")
        except json.JSONDecodeError:
            self.results_area.setHtml(f"<span style='color:{COLORS['red']}'>Invalid JSON in tool input.</span>")
        except Exception as exc:
            self.results_area.setHtml(f"<pre><span style='color:{COLORS['red']}'>Error: {exc}\n{traceback.format_exc()}</span></pre>")

    def _verify_tool(self) -> None:
        if not self._signed_bundle:
            self.results_area.setHtml(f"<span style='color:{COLORS['red']}'>Sign a tool first to create a bundle.</span>")
            return

        try:
            descriptor = SignedToolDescriptor.from_bundle(self._signed_bundle)
            verifier = ToolVerifier()
            result = verifier.verify(descriptor)

            c = COLORS
            color = c['green'] if result.valid else c['red']
            status = "VALID" if result.valid else "INVALID"

            lines = [
                f"<h3 style='color:{c['cyan']}'>Verification Result</h3><hr>",
                f"Overall: <b style='color:{color}'>{status}</b>",
                "",
                f"  Hash Match: {'PASS' if result.hash_matches else 'FAIL'}  {'✓' if result.hash_matches else '✗'}",
                f"  Signature Valid: {'PASS' if result.signature_valid else 'FAIL'}  {'✓' if result.signature_valid else '✗'}",
                f"  Publisher Auth: {'PASS' if result.publisher_authenticated else 'FAIL'}  {'✓' if result.publisher_authenticated else '✗'}",
            ]
            if result.baseline_matches is not None:
                lines.append(f"  Baseline Match: {'PASS' if result.baseline_matches else 'FAIL'}  {'✓' if result.baseline_matches else '✗'}")
            if result.error:
                lines.append(f"\n<span style='color:{c['red']}'>Error: {result.error}</span>")

            self.results_area.setHtml("<pre>" + "\n".join(lines) + "</pre>")
        except Exception as exc:
            self.results_area.setHtml(f"<pre><span style='color:{COLORS['red']}'>Error: {exc}\n{traceback.format_exc()}</span></pre>")
