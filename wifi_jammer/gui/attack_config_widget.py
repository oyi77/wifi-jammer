"""
Attack configuration widget for Qt GUI.
"""

import threading
from typing import Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QComboBox, QLabel, QLineEdit, QSpinBox, QDoubleSpinBox,
    QGroupBox, QFormLayout, QMessageBox, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSignal

from wifi_jammer.core.interfaces import (
    AttackConfig, AttackType, NetworkInfo, IAttackFactory, ILogger
)
from wifi_jammer.scanner import ScapyNetworkScanner


class AttackConfigWidget(QWidget):
    """Widget for configuring and launching attacks."""
    
    attack_started = pyqtSignal(AttackConfig)
    attack_stopped = pyqtSignal()
    
    def __init__(
        self,
        attack_factory: IAttackFactory,
        logger: ILogger,
        parent: Optional[QWidget] = None
    ):
        """Initialize the attack configuration widget.
        
        Args:
            attack_factory: Attack factory instance
            logger: Logger instance
            parent: Parent widget (optional)
        """
        super().__init__(parent)
        self.attack_factory = attack_factory
        self.logger = logger
        self.scanner = ScapyNetworkScanner(logger)
        self.current_attack = None
        self.attack_thread: Optional[threading.Thread] = None
        self.selected_network: Optional[NetworkInfo] = None
        
        self._init_ui()
        self._load_attack_types()
    
    def _init_ui(self) -> None:
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Attack Configuration")
        header.setStyleSheet("font-size: 16pt; font-weight: bold;")
        layout.addWidget(header)
        
        # Network info group
        network_group = QGroupBox("Selected Network")
        network_layout = QFormLayout()
        self.network_ssid_label = QLabel("None")
        self.network_bssid_label = QLabel("None")
        self.network_channel_label = QLabel("None")
        network_layout.addRow("SSID:", self.network_ssid_label)
        network_layout.addRow("BSSID:", self.network_bssid_label)
        network_layout.addRow("Channel:", self.network_channel_label)
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # Attack configuration group
        config_group = QGroupBox("Attack Settings")
        config_layout = QFormLayout()
        
        # Attack type
        self.attack_type_combo = QComboBox()
        config_layout.addRow("Attack Type:", self.attack_type_combo)
        
        # Interface
        self.interface_combo = QComboBox()
        self._load_interfaces()
        config_layout.addRow("Interface:", self.interface_combo)
        
        # Source MAC (optional)
        self.source_mac_edit = QLineEdit()
        self.source_mac_edit.setPlaceholderText("Auto (random)")
        config_layout.addRow("Source MAC:", self.source_mac_edit)
        
        # Count (0 = infinite)
        self.count_spin = QSpinBox()
        self.count_spin.setMinimum(0)
        self.count_spin.setMaximum(1000000)
        self.count_spin.setValue(0)
        self.count_spin.setSpecialValueText("Infinite")
        config_layout.addRow("Packet Count:", self.count_spin)
        
        # Delay
        self.delay_spin = QDoubleSpinBox()
        self.delay_spin.setMinimum(0.01)
        self.delay_spin.setMaximum(10.0)
        self.delay_spin.setValue(0.1)
        self.delay_spin.setSingleStep(0.01)
        self.delay_spin.setSuffix(" seconds")
        config_layout.addRow("Delay:", self.delay_spin)
        
        # Target client (optional)
        self.target_client_edit = QLineEdit()
        self.target_client_edit.setPlaceholderText("All clients (leave empty)")
        config_layout.addRow("Target Client MAC:", self.target_client_edit)
        
        # Verbose
        self.verbose_check = QCheckBox()
        self.verbose_check.setChecked(False)
        config_layout.addRow("Verbose:", self.verbose_check)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Attack")
        self.start_button.setMinimumHeight(40)
        self.start_button.clicked.connect(self._start_attack)
        self.stop_button = QPushButton("Stop Attack")
        self.stop_button.setMinimumHeight(40)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._stop_attack)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        layout.addStretch()
    
    def _load_attack_types(self) -> None:
        """Load available attack types."""
        attacks = self.attack_factory.get_available_attacks()
        for attack_type in attacks:
            self.attack_type_combo.addItem(
                attack_type.value.replace("_", " ").title(),
                attack_type
            )
    
    def _load_interfaces(self) -> None:
        """Load available network interfaces."""
        try:
            interfaces = self.scanner.get_interface_list()
            self.interface_combo.clear()
            self.interface_combo.addItems(interfaces)
        except Exception as e:
            self.logger.error(f"Error loading interfaces: {e}")
    
    def set_selected_network(self, network: NetworkInfo) -> None:
        """Set the selected network for attack.
        
        Args:
            network: Selected network information
        """
        self.selected_network = network
        self.network_ssid_label.setText(network.ssid)
        self.network_bssid_label.setText(network.bssid)
        self.network_channel_label.setText(str(network.channel))
    
    def _start_attack(self) -> None:
        """Start the configured attack."""
        if not self.selected_network:
            QMessageBox.warning(
                self,
                "No Network Selected",
                "Please select a network from the Network Scanner tab first."
            )
            return
        
        interface = self.interface_combo.currentText()
        if not interface:
            QMessageBox.warning(
                self,
                "No Interface",
                "Please select a network interface"
            )
            return
        
        attack_type = self.attack_type_combo.currentData()
        if not attack_type:
            QMessageBox.warning(
                self,
                "No Attack Type",
                "Please select an attack type"
            )
            return
        
        # Confirm attack
        reply = QMessageBox.question(
            self,
            "Confirm Attack",
            f"Start {attack_type.value} attack on {self.selected_network.ssid}?\n\n"
            "⚠️ Make sure you have permission to test this network!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Create attack config
        config = AttackConfig(
            attack_type=attack_type,
            target_bssid=self.selected_network.bssid,
            target_ssid=self.selected_network.ssid,
            source_mac=self.source_mac_edit.text() or "",
            interface=interface,
            channel=self.selected_network.channel,
            count=self.count_spin.value(),
            delay=self.delay_spin.value(),
            target_client=self.target_client_edit.text() or "",
            verbose=self.verbose_check.isChecked()
        )
        
        # Create and start attack
        try:
            self.current_attack = self.attack_factory.create_attack(
                attack_type, logger=self.logger
            )
            
            # Start attack in background thread
            self.attack_thread = threading.Thread(
                target=self._run_attack,
                args=(config,),
                daemon=True
            )
            self.attack_thread.start()
            
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.attack_started.emit(config)
            
        except Exception as e:
            self.logger.error(f"Failed to start attack: {e}")
            QMessageBox.critical(
                self,
                "Attack Failed",
                f"Failed to start attack:\n{str(e)}"
            )
    
    def _run_attack(self, config: AttackConfig) -> None:
        """Run the attack in background thread.
        
        Args:
            config: Attack configuration
        """
        try:
            self.current_attack.execute(config)
            # Wait for attack to complete
            if self.current_attack and self.current_attack._thread:
                self.current_attack._thread.join()
        except Exception as e:
            self.logger.error(f"Attack error: {e}")
        finally:
            # Reset UI in main thread
            self._attack_finished()
    
    def _stop_attack(self) -> None:
        """Stop the current attack."""
        if self.current_attack:
            self.current_attack.stop()
            self._attack_finished()
    
    def _attack_finished(self) -> None:
        """Handle attack completion."""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.current_attack = None
        self.attack_stopped.emit()

