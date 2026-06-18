"""Governance page — shared responsibility model and FAIR risk scenarios."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QFrame,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTabWidget,
)
from PySide6.QtGui import QColor, QBrush

from gui.theme import COLORS
from governance.models.shared_responsibility import build_default_model, ActorRole
from governance.fair_assessment.risk_model import build_default_scenarios


class GovernancePage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._model = build_default_model()
        self._scenarios = build_default_scenarios()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        main = QVBoxLayout(container)
        main.setContentsMargins(28, 24, 28, 24)
        main.setSpacing(16)

        header = QLabel("⚖ Governance")
        header.setStyleSheet(f"color: {COLORS['purple_light']}; font-size: 22px; font-weight: bold;")
        main.addWidget(header)

        subtitle = QLabel("MCP shared responsibility model, security obligations, and FAIR risk assessment")
        subtitle.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 13px;")
        main.addWidget(subtitle)

        tabs = QTabWidget()

        # Tab 1: Obligations
        obligations_widget = QWidget()
        obl_layout = QVBoxLayout(obligations_widget)
        obl_layout.setContentsMargins(8, 12, 8, 8)

        obl_table = QTableWidget()
        obl_table.setColumnCount(5)
        obl_table.setHorizontalHeaderLabels(["ID", "Actor", "Obligation", "Controls", "Regulatory Refs"])
        obl_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        obl_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        obl_table.setColumnWidth(0, 70)
        obl_table.verticalHeader().setVisible(False)
        obl_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        obligations = self._model.obligations
        obl_table.setRowCount(len(obligations))
        actor_colors = {
            ActorRole.PLATFORM_DEVELOPER: COLORS["cyan"],
            ActorRole.SERVER_PUBLISHER: COLORS["purple_light"],
            ActorRole.ENTERPRISE_DEPLOYER: COLORS["yellow"],
            ActorRole.END_USER: COLORS["green"],
        }
        for row, o in enumerate(obligations):
            items = [
                o.obligation_id,
                o.actor.value.replace("_", " ").title(),
                o.description,
                ", ".join(o.controls),
                ", ".join(o.regulatory_refs),
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 1:
                    item.setForeground(QBrush(QColor(actor_colors.get(o.actor, COLORS["text_primary"]))))
                self.table_set(obl_table, row, col, item)

        obl_layout.addWidget(obl_table)
        tabs.addTab(obligations_widget, "Security Obligations")

        # Tab 2: Liability mappings
        liability_widget = QWidget()
        lia_layout = QVBoxLayout(liability_widget)
        lia_layout.setContentsMargins(8, 12, 8, 8)

        lia_table = QTableWidget()
        lia_table.setColumnCount(6)
        lia_table.setHorizontalHeaderLabels(["Attack", "Actor", "Liability", "Regulatory Basis", "Max Exposure", "Mitigation"])
        lia_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        lia_table.verticalHeader().setVisible(False)
        lia_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        mappings = self._model.liability_mappings
        lia_table.setRowCount(len(mappings))
        for row, m in enumerate(mappings):
            items = [
                m.attack_class.replace("_", " ").title(),
                m.actor.value.replace("_", " ").title(),
                m.liability_type.value.replace("_", " ").title(),
                m.regulatory_basis,
                m.max_exposure,
                m.mitigation,
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 4:
                    item.setForeground(QBrush(QColor(COLORS["red"])))
                self.table_set(lia_table, row, col, item)

        lia_layout.addWidget(lia_table)
        tabs.addTab(liability_widget, "Liability Mappings")

        # Tab 3: FAIR risk
        fair_widget = QWidget()
        fair_layout = QVBoxLayout(fair_widget)
        fair_layout.setContentsMargins(8, 12, 8, 8)

        fair_table = QTableWidget()
        fair_table.setColumnCount(8)
        fair_table.setHorizontalHeaderLabels([
            "Attack", "Description", "Frequency", "Vulnerability",
            "Loss Event Freq", "Primary Loss", "ALE Low", "ALE High"
        ])
        fair_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        fair_table.verticalHeader().setVisible(False)
        fair_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        fair_table.setRowCount(len(self._scenarios))
        for row, s in enumerate(self._scenarios):
            d = s.to_dict()
            items = [
                d["attack_class"].replace("_", " ").title(),
                d["description"],
                d["threat_event_frequency"],
                f"{d['vulnerability']:.0%}",
                str(d["loss_event_frequency"]),
                d["primary_loss"],
                d["ale_low"],
                d["ale_high"],
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col in (6, 7):
                    item.setForeground(QBrush(QColor(COLORS["red"])))
                self.table_set(fair_table, row, col, item)

        fair_layout.addWidget(fair_table)
        tabs.addTab(fair_widget, "FAIR Risk Assessment")

        main.addWidget(tabs, 1)

        scroll.setWidget(container)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    @staticmethod
    def table_set(table: QTableWidget, row: int, col: int, item: QTableWidgetItem) -> None:
        table.setItem(row, col, item)
