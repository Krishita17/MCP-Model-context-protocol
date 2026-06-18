"""Dark cybersecurity-themed stylesheet for the MCP Security Console."""

COLORS = {
    "bg_darkest": "#0a0a1a",
    "bg_dark": "#0f0f2a",
    "bg_medium": "#161638",
    "bg_light": "#1e1e4a",
    "bg_card": "#1a1a3e",
    "border": "#2a2a5a",
    "border_light": "#3a3a6a",
    "purple": "#7c3aed",
    "purple_light": "#9b6dff",
    "purple_dark": "#5b21b6",
    "cyan": "#06b6d4",
    "cyan_dark": "#0891b2",
    "green": "#22c55e",
    "green_dark": "#16a34a",
    "red": "#ef4444",
    "red_dark": "#dc2626",
    "yellow": "#eab308",
    "orange": "#f97316",
    "text_primary": "#e2e8f0",
    "text_secondary": "#94a3b8",
    "text_muted": "#64748b",
}


def get_stylesheet() -> str:
    c = COLORS
    return f"""
    /* ── Global ── */
    QMainWindow, QWidget {{
        background-color: {c['bg_darkest']};
        color: {c['text_primary']};
        font-family: "Segoe UI", "SF Pro Display", "Helvetica Neue", sans-serif;
        font-size: 13px;
    }}

    /* ── Scroll bars ── */
    QScrollBar:vertical {{
        background: {c['bg_dark']};
        width: 10px;
        border: none;
        border-radius: 5px;
    }}
    QScrollBar::handle:vertical {{
        background: {c['border_light']};
        min-height: 30px;
        border-radius: 5px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {c['purple']};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}
    QScrollBar:horizontal {{
        background: {c['bg_dark']};
        height: 10px;
        border: none;
        border-radius: 5px;
    }}
    QScrollBar::handle:horizontal {{
        background: {c['border_light']};
        min-width: 30px;
        border-radius: 5px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: {c['purple']};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0px;
    }}

    /* ── Labels ── */
    QLabel {{
        color: {c['text_primary']};
        background: transparent;
    }}

    /* ── Buttons ── */
    QPushButton {{
        background-color: {c['purple']};
        color: #ffffff;
        border: none;
        border-radius: 6px;
        padding: 8px 20px;
        font-weight: bold;
        font-size: 13px;
    }}
    QPushButton:hover {{
        background-color: {c['purple_light']};
    }}
    QPushButton:pressed {{
        background-color: {c['purple_dark']};
    }}
    QPushButton:disabled {{
        background-color: {c['border']};
        color: {c['text_muted']};
    }}

    /* ── Inputs ── */
    QLineEdit, QTextEdit, QPlainTextEdit {{
        background-color: {c['bg_medium']};
        color: {c['text_primary']};
        border: 1px solid {c['border']};
        border-radius: 6px;
        padding: 8px;
        font-family: "JetBrains Mono", "Fira Code", "Consolas", monospace;
        font-size: 12px;
        selection-background-color: {c['purple']};
    }}
    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
        border-color: {c['purple']};
    }}

    /* ── ComboBox ── */
    QComboBox {{
        background-color: {c['bg_medium']};
        color: {c['text_primary']};
        border: 1px solid {c['border']};
        border-radius: 6px;
        padding: 8px 12px;
        min-width: 200px;
    }}
    QComboBox:hover {{
        border-color: {c['purple']};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 30px;
    }}
    QComboBox::down-arrow {{
        image: none;
        border-left: 5px solid transparent;
        border-right: 5px solid transparent;
        border-top: 6px solid {c['text_secondary']};
        margin-right: 10px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {c['bg_medium']};
        color: {c['text_primary']};
        border: 1px solid {c['border']};
        selection-background-color: {c['purple']};
        selection-color: #ffffff;
        outline: none;
    }}

    /* ── SpinBox ── */
    QSpinBox {{
        background-color: {c['bg_medium']};
        color: {c['text_primary']};
        border: 1px solid {c['border']};
        border-radius: 6px;
        padding: 6px 10px;
    }}
    QSpinBox:focus {{
        border-color: {c['purple']};
    }}

    /* ── Table ── */
    QTableWidget {{
        background-color: {c['bg_dark']};
        color: {c['text_primary']};
        border: 1px solid {c['border']};
        border-radius: 6px;
        gridline-color: {c['border']};
        selection-background-color: {c['purple_dark']};
    }}
    QTableWidget::item {{
        padding: 6px;
    }}
    QHeaderView::section {{
        background-color: {c['bg_medium']};
        color: {c['cyan']};
        font-weight: bold;
        border: none;
        border-bottom: 2px solid {c['purple']};
        padding: 8px;
    }}

    /* ── Group Box ── */
    QGroupBox {{
        background-color: {c['bg_card']};
        border: 1px solid {c['border']};
        border-radius: 8px;
        margin-top: 12px;
        padding-top: 20px;
        font-weight: bold;
        color: {c['cyan']};
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 14px;
        padding: 0 6px;
    }}

    /* ── Tab Widget ── */
    QTabWidget::pane {{
        background-color: {c['bg_dark']};
        border: 1px solid {c['border']};
        border-radius: 6px;
    }}
    QTabBar::tab {{
        background-color: {c['bg_medium']};
        color: {c['text_secondary']};
        border: none;
        padding: 8px 18px;
        margin-right: 2px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
    }}
    QTabBar::tab:selected {{
        background-color: {c['bg_dark']};
        color: {c['cyan']};
        border-bottom: 2px solid {c['purple']};
    }}
    QTabBar::tab:hover {{
        background-color: {c['bg_light']};
        color: {c['text_primary']};
    }}

    /* ── Progress Bar ── */
    QProgressBar {{
        background-color: {c['bg_medium']};
        border: 1px solid {c['border']};
        border-radius: 6px;
        text-align: center;
        color: {c['text_primary']};
        height: 22px;
    }}
    QProgressBar::chunk {{
        background-color: {c['purple']};
        border-radius: 5px;
    }}

    /* ── Checkbox ── */
    QCheckBox {{
        color: {c['text_primary']};
        spacing: 8px;
    }}
    QCheckBox::indicator {{
        width: 18px;
        height: 18px;
        border: 2px solid {c['border']};
        border-radius: 4px;
        background-color: {c['bg_medium']};
    }}
    QCheckBox::indicator:checked {{
        background-color: {c['purple']};
        border-color: {c['purple']};
    }}
    """
