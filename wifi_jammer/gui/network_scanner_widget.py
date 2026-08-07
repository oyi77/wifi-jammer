"""
Network scanner widget for Qt GUI.
"""

import threading
from typing import Optional, List, Any
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QLabel,
    QProgressBar,
    QComboBox,
    QMessageBox,
)
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QFont

from wifi_jammer.core.interfaces import INetworkScanner, NetworkInfo, ILogger


class NetworkScannerWidget(QWidget):
    """Widget for scanning and displaying WiFi networks."""

    network_selected = pyqtSignal(NetworkInfo)

    def __init__(
        self,
        scanner: INetworkScanner,
        logger: ILogger,
        parent: Optional[QWidget] = None,
    ):
        """Initialize the network scanner widget.

        Args:
            scanner: Network scanner instance
            logger: Logger instance
            parent: Parent widget (optional)
        """
        super().__init__(parent)
        self.scanner = scanner
        self.logger = logger
        self.scan_thread: Optional[threading.Thread] = None
        self.is_scanning = False
        self.networks: List[NetworkInfo] = []

        self._init_ui()
        self._load_interfaces()

    def _init_ui(self) -> None:
        """Initialize the user interface."""
        layout = QVBoxLayout(self)

        # Header
        header = QLabel("WiFi Network Scanner")
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setBold(True)
        header.setFont(header_font)
        layout.addWidget(header)

        # Interface selection
        interface_layout = QHBoxLayout()
        interface_label = QLabel("Interface:")
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(200)
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_combo)
        interface_layout.addStretch()
        layout.addLayout(interface_layout)

        # Control buttons
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Scan Networks")
        self.scan_button.clicked.connect(self._start_scan)
        self.scan_button.setMinimumHeight(40)
        self.refresh_button = QPushButton("Refresh Interfaces")
        self.refresh_button.clicked.connect(self._load_interfaces)
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.refresh_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Network table
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(6)
        self.network_table.setHorizontalHeaderLabels(
            ["SSID", "BSSID", "Channel", "RSSI", "Encryption", "Clients"]
        )
        network_header = self.network_table.horizontalHeader()
        if network_header is not None:
            network_header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.network_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.network_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.network_table.doubleClicked.connect(self._on_network_double_clicked)
        layout.addWidget(self.network_table)

        # Status label
        self.status_label = QLabel("Ready to scan")
        layout.addWidget(self.status_label)

    def _load_interfaces(self) -> None:
        """Load available network interfaces."""
        try:
            interfaces = self.scanner.get_interface_list()
            self.interface_combo.clear()
            self.interface_combo.addItems(interfaces)
            if interfaces:
                self.status_label.setText(f"Found {len(interfaces)} interface(s)")
            else:
                self.status_label.setText("No interfaces found")
        except Exception as e:
            self.logger.error(f"Error loading interfaces: {e}")
            QMessageBox.warning(self, "Error", f"Failed to load interfaces:\n{str(e)}")

    def _start_scan(self) -> None:
        """Start network scanning."""
        if self.is_scanning:
            return

        interface = self.interface_combo.currentText()
        if not interface:
            QMessageBox.warning(
                self, "No Interface", "Please select a network interface"
            )
            return

        self.is_scanning = True
        self.scan_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText("Scanning networks...")
        self.network_table.setRowCount(0)

        # Start scan in background thread
        self.scan_thread = threading.Thread(
            target=self._perform_scan, args=(interface,), daemon=True
        )
        self.scan_thread.start()

    def _perform_scan(self, interface: str) -> None:
        """Perform the actual network scan.

        Args:
            interface: Network interface to use
        """
        try:
            networks = self.scanner.scan_networks(interface)
            self.networks = networks

            # Update UI in main thread
            self._update_network_table(networks)
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            self._show_error(f"Scan failed: {str(e)}")
        finally:
            self.is_scanning = False
            self.scan_button.setEnabled(True)
            self.progress_bar.setVisible(False)
            self.status_label.setText(
                f"Scan complete: {len(self.networks)} network(s) found"
            )

    def _update_network_table(self, networks: List[NetworkInfo]) -> None:
        """Update the network table with scan results.

        Args:
            networks: List of discovered networks
        """
        self.network_table.setRowCount(len(networks))

        for row, network in enumerate(networks):
            self.network_table.setItem(row, 0, QTableWidgetItem(network.ssid))
            self.network_table.setItem(row, 1, QTableWidgetItem(network.bssid))
            self.network_table.setItem(row, 2, QTableWidgetItem(str(network.channel)))
            self.network_table.setItem(row, 3, QTableWidgetItem(f"{network.rssi} dBm"))
            self.network_table.setItem(row, 4, QTableWidgetItem(network.encryption))
            clients_count = len(network.clients) if network.clients else 0
            self.network_table.setItem(row, 5, QTableWidgetItem(str(clients_count)))

    def _on_network_double_clicked(self, index: Any) -> None:
        """Handle network double-click event.

        Args:
            index: Table index
        """
        row = index.row()
        if 0 <= row < len(self.networks):
            network = self.networks[row]
            self.network_selected.emit(network)

    def _show_error(self, message: str) -> None:
        """Show error message.

        Args:
            message: Error message
        """
        QMessageBox.critical(self, "Error", message)
