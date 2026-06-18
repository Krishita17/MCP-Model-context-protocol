"""MCP Security Console — PySide6 desktop GUI."""


def run() -> None:
    """Launch the MCP Security Console application."""
    import sys
    from PySide6.QtWidgets import QApplication
    from gui.app import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("MCP Security Console")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
