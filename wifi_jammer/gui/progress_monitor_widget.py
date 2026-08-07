"""
Progress monitoring widget for Qt GUI.
"""

from typing import Optional, Dict, Any
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QGroupBox,
    QFormLayout,
)
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont

from wifi_jammer.core.interfaces import (
    AttackConfig,
    ILogger,
    IAttackStrategy,
)


class ProgressMonitorWidget(QWidget):
    """Widget for monitoring attack progress."""

    def __init__(self, logger: ILogger, parent: Optional[QWidget] = None):
        """Initialize the progress monitor widget.

        Args:
            logger: Logger instance
            parent: Parent widget (optional)
        """
        super().__init__(parent)
        self.logger = logger
        self.current_config: Optional[AttackConfig] = None
        self.current_attack: Optional[IAttackStrategy] = None
        self.stats: Dict[str, Any] = {
            "packets_sent": 0,
            "packets_failed": 0,
            "duration": 0.0,
        }
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._update_display)

        self._init_ui()

    def _init_ui(self) -> None:
        """Initialize the user interface."""
        layout = QVBoxLayout(self)

        # Header
        header = QLabel("Attack Progress Monitor")
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setBold(True)
        header.setFont(header_font)
        layout.addWidget(header)

        # Attack info group
        info_group = QGroupBox("Current Attack")
        info_layout = QFormLayout()
        self.attack_type_label = QLabel("None")
        self.target_label = QLabel("None")
        self.interface_label = QLabel("None")
        info_layout.addRow("Attack Type:", self.attack_type_label)
        info_layout.addRow("Target:", self.target_label)
        info_layout.addRow("Interface:", self.interface_label)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        # Statistics group
        stats_group = QGroupBox("Statistics")
        stats_layout = QFormLayout()

        self.packets_sent_label = QLabel("0")
        self.packets_failed_label = QLabel("0")
        self.success_rate_label = QLabel("0%")
        self.pps_label = QLabel("0")
        self.duration_label = QLabel("0s")

        stats_layout.addRow("Packets Sent:", self.packets_sent_label)
        stats_layout.addRow("Packets Failed:", self.packets_failed_label)
        stats_layout.addRow("Success Rate:", self.success_rate_label)
        stats_layout.addRow("Packets/Second:", self.pps_label)
        stats_layout.addRow("Duration:", self.duration_label)

        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        # Progress bar
        progress_label = QLabel("Overall Progress")
        progress_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(progress_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(0)  # Indeterminate initially
        layout.addWidget(self.progress_bar)

        # Log table
        log_label = QLabel("Recent Activity")
        log_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(log_label)
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(2)
        self.log_table.setHorizontalHeaderLabels(["Time", "Message"])
        log_header = self.log_table.horizontalHeader()
        if log_header is not None:
            log_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.log_table.setMaximumHeight(200)
        layout.addWidget(self.log_table)

        layout.addStretch()

    def start_monitoring(
        self, config: AttackConfig, attack: Optional[IAttackStrategy] = None
    ) -> None:
        """Start monitoring an attack.

        Args:
            config: Attack configuration
            attack: Attack instance for stats (optional)
        """
        self.current_config = config
        self.current_attack = attack
        self.stats = {"packets_sent": 0, "packets_failed": 0, "duration": 0.0}

        # Update attack info
        self.attack_type_label.setText(config.attack_type.value)
        self.target_label.setText(f"{config.target_ssid} ({config.target_bssid})")
        self.interface_label.setText(config.interface)

        # Start update timer (update every 500ms)
        self.update_timer.start(500)
        self._add_log("Attack started")

    def stop_monitoring(self) -> None:
        """Stop monitoring."""
        self.update_timer.stop()
        self._add_log("Attack stopped")
        self.current_config = None

    def _update_display(self) -> None:
        """Update the display with current statistics."""
        if not self.current_config:
            return

        # Get stats from attack object if available
        if self.current_attack:
            stats = self.current_attack.get_stats()
            packets_sent = stats.packets_sent
            packets_failed = stats.packets_failed
            duration = stats.duration
            pps = stats.packets_per_second
            success_rate = stats.success_rate
        else:
            # Fallback to stored stats
            packets_sent = self.stats["packets_sent"]
            packets_failed = self.stats["packets_failed"]
            duration = self.stats["duration"] + 0.5  # Increment by timer interval
            self.stats["duration"] = duration

            total = packets_sent + packets_failed
            success_rate = (packets_sent / total * 100) if total > 0 else 0
            pps = packets_sent / duration if duration > 0 else 0

        self.packets_sent_label.setText(f"{packets_sent:,}")
        self.packets_failed_label.setText(f"{packets_failed:,}")
        self.success_rate_label.setText(f"{success_rate:.1f}%")
        self.pps_label.setText(f"{pps:.1f}")
        self.duration_label.setText(f"{duration:.1f}s")

        # Update progress bar
        if self.current_config.count > 0:
            progress = int((packets_sent / self.current_config.count) * 100)
            self.progress_bar.setMaximum(100)
            self.progress_bar.setValue(progress)
        else:
            # Infinite attack - show indeterminate
            self.progress_bar.setMaximum(0)

    def _add_log(self, message: str) -> None:
        """Add a log entry.

        Args:
            message: Log message
        """
        from datetime import datetime

        time_str = datetime.now().strftime("%H:%M:%S")

        row = self.log_table.rowCount()
        self.log_table.insertRow(row)
        self.log_table.setItem(row, 0, QTableWidgetItem(time_str))
        self.log_table.setItem(row, 1, QTableWidgetItem(message))

        # Auto-scroll to bottom
        self.log_table.scrollToBottom()

        # Limit to last 100 entries
        if self.log_table.rowCount() > 100:
            self.log_table.removeRow(0)

    def update_stats(self, stats: Dict[str, Any]) -> None:
        """Update statistics from attack.

        Args:
            stats: Statistics dictionary
        """
        self.stats.update(stats)
        self._update_display()
