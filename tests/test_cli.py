#!/usr/bin/env python3
"""
Tests for CLI functionality.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import platform

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_jammer.cli import WiFiJammerCLI, AttackProgressDisplay
from wifi_jammer.core.interfaces import NetworkInfo, AttackType, AttackConfig
from wifi_jammer.utils.logger import RichLogger


class TestAttackProgressDisplay(unittest.TestCase):
    """Test AttackProgressDisplay class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_console = Mock()
        self.display = AttackProgressDisplay(self.mock_console)
    
    def test_initialization(self):
        """Test AttackProgressDisplay initialization."""
        self.assertIsNotNone(self.display.layout)
        self.assertEqual(len(self.display.layout.children), 3)
    
    def test_get_layout(self):
        """Test getting the current layout."""
        layout = self.display.get_layout()
        self.assertIsNotNone(layout)
        self.assertEqual(layout, self.display.layout)
    
    def test_update_stats(self):
        """Test updating statistics display."""
        # Create mock stats object
        mock_stats = Mock()
        mock_stats.duration = 10.5
        mock_stats.packets_per_second = 25.0
        mock_stats.success_rate = 95.5
        mock_stats.packets_sent = 250
        mock_stats.packets_failed = 12
        mock_stats.errors = ["Error 1", "Error 2"]
        
        # Mock the layout update method by patching the update_stats method
        with patch.object(self.display, 'update_stats') as mock_update:
            self.display.update_stats(mock_stats)
            mock_update.assert_called_once_with(mock_stats)


class TestWiFiJammerCLI(unittest.TestCase):
    """Test WiFiJammerCLI class."""
    
    def setUp(self):
        """Set up test fixtures."""
        with patch('wifi_jammer.cli.PlatformInterfaceFactory') as mock_factory:
            mock_platform = Mock()
            mock_factory.create.return_value = mock_platform
            self.cli = WiFiJammerCLI()
    
    def test_initialization(self):
        """Test CLI initialization."""
        self.assertIsNotNone(self.cli.console)
        self.assertIsNotNone(self.cli.logger)
        self.assertIsNotNone(self.cli.scanner)
        self.assertIsNotNone(self.cli.factory)
    
    def test_show_banner(self):
        """Test banner display."""
        # Mock the console print method
        self.cli.console.print = Mock()
        
        self.cli.show_banner()
        
        # Verify banner was displayed
        self.cli.console.print.assert_called()
    
    def test_list_interfaces(self):
        """Test listing interfaces."""
        # Mock platform interface with proper return values
        mock_interface = Mock()
        
        # Create proper mock objects that return string values
        wlan0_mock = Mock()
        wlan0_mock.name = "wlan0"
        wlan0_mock.status = "Available"
        wlan0_mock.type = "Wireless"
        wlan0_mock.mac_address = "00:11:22:33:44:55"
        wlan0_mock.capabilities = ["monitor"]
        
        eth0_mock = Mock()
        eth0_mock.name = "eth0"
        eth0_mock.status = "Available"
        eth0_mock.type = "Ethernet"
        eth0_mock.mac_address = "00:11:22:33:44:66"
        eth0_mock.capabilities = []
        
        mock_interface.get_all_interfaces.return_value = [wlan0_mock, eth0_mock]
        mock_interface.get_wireless_interfaces.return_value = [wlan0_mock]
        
        self.cli.platform_interface = mock_interface
        
        # Mock the console print method
        self.cli.console.print = Mock()
        
        interfaces = self.cli.list_interfaces()
        
        # Verify interfaces were listed
        self.cli.console.print.assert_called()
        self.assertIsInstance(interfaces, list)
    
    def test_list_interfaces_no_wireless(self):
        """Test listing interfaces when no wireless available."""
        mock_interface = Mock()
        
        # Create proper mock objects that return string values
        eth0_mock = Mock()
        eth0_mock.name = "eth0"
        eth0_mock.status = "Available"
        eth0_mock.type = "Ethernet"
        eth0_mock.mac_address = "00:11:22:33:44:66"
        eth0_mock.capabilities = []
        
        mock_interface.get_all_interfaces.return_value = [eth0_mock]
        mock_interface.get_wireless_interfaces.return_value = []
        
        self.cli.platform_interface = mock_interface
        
        # Mock the console print method
        self.cli.console.print = Mock()
        
        interfaces = self.cli.list_interfaces()
        
        # Verify message about no wireless interfaces
        self.cli.console.print.assert_called()
        self.assertIsInstance(interfaces, list)
    
    def test_scan_networks(self):
        """Test network scanning."""
        # Mock scanner
        mock_networks = [
            NetworkInfo("TestNetwork", "00:11:22:33:44:55", 6, -50, "WPA2"),
            NetworkInfo("HiddenNetwork", "00:11:22:33:44:66", 11, -60, "WPA")
        ]
        self.cli.scanner.scan_networks = Mock(return_value=mock_networks)
        
        # Mock the console print method
        self.cli.console.print = Mock()
        
        networks = self.cli.scan_networks("wlan0")
        
        # Verify networks were scanned
        self.cli.scanner.scan_networks.assert_called_once_with("wlan0", None)
        self.assertEqual(networks, mock_networks)
    
    def test_display_networks(self):
        """Test displaying networks."""
        networks = [
            NetworkInfo("TestNetwork", "00:11:22:33:44:55", 6, -50, "WPA2"),
            NetworkInfo("HiddenNetwork", "00:11:22:33:44:66", 11, -60, "WPA")
        ]
        
        # Mock the console print method
        self.cli.console.print = Mock()
        
        self.cli.display_networks(networks)
        
        # Verify networks were displayed
        self.cli.console.print.assert_called()
    
    def test_display_networks_empty(self):
        """Test displaying empty network list."""
        # Mock the console print method
        self.cli.console.print = Mock()
        
        # Mock the logger warning method
        self.cli.logger.warning = Mock()
        
        self.cli.display_networks([])
        
        # Verify warning was logged
        self.cli.logger.warning.assert_called_with("No networks found!")
    
    def test_select_network(self):
        """Test network selection."""
        networks = [
            NetworkInfo("TestNetwork", "00:11:22:33:44:55", 6, -50, "WPA2"),
            NetworkInfo("HiddenNetwork", "00:11:22:33:44:66", 11, -60, "WPA")
        ]
        
        # Mock prompt to return first network
        with patch('wifi_jammer.cli.Prompt.ask', return_value="1"):
            selected = self.cli.select_network(networks)
            self.assertEqual(selected, networks[0])
    
    def test_select_attack(self):
        """Test attack selection."""
        # Mock prompt to return deauth attack
        with patch('wifi_jammer.cli.Prompt.ask', return_value="1"):
            selected = self.cli.select_attack()
            self.assertEqual(selected, AttackType.DEAUTH)
    
    def test_configure_attack(self):
        """Test attack configuration."""
        # Mock prompts with proper side effects
        with patch('wifi_jammer.cli.Prompt.ask') as mock_prompt, \
             patch('wifi_jammer.cli.Confirm.ask') as mock_confirm:
            
            mock_prompt.side_effect = ["00:11:22:33:44:55", "wlan0", "6", "100", "0.1", ""]
            mock_confirm.return_value = False
            
            config = self.cli.configure_attack(AttackType.DEAUTH)
            
            self.assertEqual(config.attack_type, AttackType.DEAUTH)
            self.assertEqual(config.target_bssid, "00:11:22:33:44:55")
            self.assertEqual(config.interface, "wlan0")
            self.assertEqual(config.channel, 6)
            self.assertEqual(config.count, 100)
            self.assertEqual(config.delay, 0.1)
    
    @patch('platform.system', return_value="Linux")
    def test_check_root_linux(self, mock_platform):
        """Test root check on Linux."""
        with patch('os.geteuid', return_value=0):
            result = self.cli.check_root()
            self.assertTrue(result)
    
    @patch('platform.system', return_value="Linux")
    def test_check_root_linux_not_root(self, mock_platform):
        """Test root check on Linux when not root."""
        with patch('os.geteuid', return_value=1000):
            result = self.cli.check_root()
            self.assertFalse(result)
