"""
Main window for WiFi Jammer Qt GUI.
"""

import sys
import threading
from typing import Optional, Any
from PyQt6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QTabWidget,
    QMessageBox,
    QStatusBar,
)

from wifi_jammer.gui.network_scanner_widget import NetworkScannerWidget
from wifi_jammer.gui.attack_config_widget import AttackConfigWidget
from wifi_jammer.gui.progress_monitor_widget import ProgressMonitorWidget
from wifi_jammer.core.interfaces import NetworkInfo, AttackConfig, IAttackStrategy
from wifi_jammer.scanner import ScapyNetworkScanner
from wifi_jammer.factory import AttackFactory
from wifi_jammer.utils import RichLogger


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize the main window.

        Args:
            parent: Parent widget (optional)
        """
        super().__init__(parent)
        self.logger = RichLogger()
        self.scanner = ScapyNetworkScanner(self.logger)
        self.attack_factory = AttackFactory()
        self.current_attack: Optional[IAttackStrategy] = None
        self.current_attack_thread: Optional[threading.Thread] = None

        self._init_ui()
        self._check_permissions()

    def _init_ui(self) -> None:
        """Initialize the user interface."""
        self.setWindowTitle("WiFi Jammer - Cross-Platform GUI")
        self.setMinimumSize(900, 700)

        # Create central widget with tabs
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)

        # Create tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Network Scanner Tab
        self.scanner_widget = NetworkScannerWidget(self.scanner, self.logger)
        self.scanner_widget.network_selected.connect(self._on_network_selected)
        self.tabs.addTab(self.scanner_widget, "Network Scanner")

        # Attack Configuration Tab
        self.attack_config_widget = AttackConfigWidget(self.attack_factory, self.logger)
        self.attack_config_widget.attack_started.connect(self._on_attack_started)
        self.attack_config_widget.attack_stopped.connect(self._on_attack_stopped)
        self.tabs.addTab(self.attack_config_widget, "Attack Configuration")

        # Progress Monitor Tab
        self.progress_monitor = ProgressMonitorWidget(self.logger)
        self.tabs.addTab(self.progress_monitor, "Progress Monitor")

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

        # Legal disclaimer
        self._show_legal_disclaimer()

    def _check_permissions(self) -> None:
        """Check if running with required permissions."""
        import os

        if os.geteuid() != 0 and sys.platform != "win32":
            self.status_bar.showMessage(
                "Warning: May need root privileges for full functionality", 5000
            )

    def _show_legal_disclaimer(self) -> None:
        """Show legal disclaimer dialog."""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Legal Disclaimer")
        msg.setText(
            "⚠️ LEGAL NOTICE ⚠️\n\n"
            "This tool is for EDUCATIONAL and TESTING purposes ONLY!\n\n"
            "• Use only on networks you OWN or have EXPLICIT permission to test\n"
            "• Respect local laws and regulations\n"
            "• The authors are NOT responsible for misuse\n"
            "• Intended for security research and penetration testing education\n\n"
            "By using this tool, you agree to use it responsibly and legally."
        )
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()

    def _on_network_selected(self, network: NetworkInfo) -> None:
        """Handle network selection from scanner.

        Args:
            network: Selected network information
        """
        self.attack_config_widget.set_selected_network(network)
        self.tabs.setCurrentIndex(1)  # Switch to attack config tab
        self.status_bar.showMessage(
            f"Network selected: {network.ssid} ({network.bssid})", 3000
        )

    def _on_attack_started(self, config: AttackConfig) -> None:
        """Handle attack start.

        Args:
            config: Attack configuration
        """
        # Store reference to current attack for stats monitoring
        self.current_attack = self.attack_config_widget.current_attack
        self.progress_monitor.start_monitoring(config, self.current_attack)
        self.tabs.setCurrentIndex(2)  # Switch to progress monitor tab
        self.status_bar.showMessage(f"Attack started: {config.attack_type.value}", 3000)

    def _on_attack_stopped(self) -> None:
        """Handle attack stop."""
        self.progress_monitor.stop_monitoring()
        self.status_bar.showMessage("Attack stopped", 3000)

    def closeEvent(self, event: Any) -> None:
        """Handle window close event.

        Args:
            event: Close event
        """
        if self.current_attack and self.current_attack.is_running():
            reply = QMessageBox.question(
                self,
                "Attack in Progress",
                "An attack is currently running. Stop it and close?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.current_attack.stop()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
