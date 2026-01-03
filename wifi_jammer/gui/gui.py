"""
Main GUI entry point for WiFi Jammer.
"""

import sys
from PyQt6.QtWidgets import QApplication

from wifi_jammer.gui.main_window import MainWindow


def launch_gui() -> int:
    """Launch the Qt GUI application.
    
    Returns:
        Exit code
    """
    app = QApplication(sys.argv)
    app.setApplicationName("WiFi Jammer")
    app.setOrganizationName("WiFi Jammer")
    
    # Note: High DPI scaling is enabled by default in PyQt6
    # The deprecated AA_EnableHighDpiScaling and AA_UseHighDpiPixmaps
    # attributes are no longer needed in PyQt6
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    return app.exec()


if __name__ == "__main__":
    sys.exit(launch_gui())

