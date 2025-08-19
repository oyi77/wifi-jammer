#!/usr/bin/env python3
"""
Tests for network scanner functionality.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import platform

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_jammer.scanner.network_scanner import ScapyNetworkScanner
from wifi_jammer.core.interfaces import NetworkInfo
from wifi_jammer.utils.logger import RichLogger


class TestScapyNetworkScanner(unittest.TestCase):
    """Test ScapyNetworkScanner class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=RichLogger)
        self.scanner = ScapyNetworkScanner(self.mock_logger)
    
    def test_initialization(self):
        """Test scanner initialization."""
        self.assertIsNotNone(self.scanner.logger)
        self.assertFalse(self.scanner._scanning)
        self.assertEqual(self.scanner._networks, [])
        self.assertIsNotNone(self.scanner._platform_interface)
    
    def test_is_scanning(self):
        """Test scanning status check."""
        self.assertFalse(self.scanner.is_scanning())
        
        self.scanner._scanning = True
        self.assertTrue(self.scanner.is_scanning())
    
    def test_get_networks(self):
        """Test getting scanned networks."""
        # Test empty networks
        networks = self.scanner.get_networks()
        self.assertEqual(networks, [])
        
        # Test with some networks
        test_networks = [
            NetworkInfo("TestNetwork", "00:11:22:33:44:55", 6, -50, "WPA2"),
            NetworkInfo("HiddenNetwork", "00:11:22:33:44:66", 11, -60, "WPA")
        ]
        self.scanner._networks = test_networks
        
        networks = self.scanner.get_networks()
        self.assertEqual(networks, test_networks)
    
    @patch('wifi_jammer.scanner.network_scanner.PlatformInterfaceFactory')
    def test_get_interface_list(self, mock_factory):
        """Test getting interface list."""
        # Mock platform interface
        mock_platform = Mock()
        mock_interface = Mock()
        mock_interface.name = "wlan0"
        mock_interface.status = "Available"
        mock_platform.get_wireless_interfaces.return_value = [mock_interface]
        mock_factory.create.return_value = mock_platform
        
        # Create new scanner with mocked platform
        scanner = ScapyNetworkScanner(self.mock_logger)
        interfaces = scanner.get_interface_list()
        
        self.assertEqual(interfaces, ["wlan0"])
    
    @patch('wifi_jammer.scanner.network_scanner.PlatformInterfaceFactory')
    def test_get_interface_list_no_interfaces(self, mock_factory):
        """Test getting interface list when no interfaces available."""
        # Mock platform interface
        mock_platform = Mock()
        mock_platform.get_wireless_interfaces.return_value = []
        mock_factory.create.return_value = mock_platform
        
        # Create new scanner with mocked platform
        scanner = ScapyNetworkScanner(self.mock_logger)
        interfaces = scanner.get_interface_list()
        
        self.assertEqual(interfaces, [])
    
    @patch('wifi_jammer.scanner.network_scanner.platform_system')
    def test_scan_networks_linux(self, mock_platform):
        """Test network scanning on Linux."""
        mock_platform.system.return_value = "Linux"
        
        # Mock platform interface
        mock_interface_info = Mock()
        mock_interface_info.status = "Available"
        
        # Create a new scanner with mocked platform interface
        with patch('wifi_jammer.scanner.network_scanner.PlatformInterfaceFactory') as mock_factory:
            mock_platform_interface = Mock()
            mock_platform_interface.get_interface_info.return_value = mock_interface_info
            mock_factory.create.return_value = mock_platform_interface
            
            scanner = ScapyNetworkScanner(self.mock_logger)
            
            # Mock the standard scanning method
            with patch.object(scanner, '_scan_standard_networks') as mock_scan:
                scanner.scan_networks("wlan0")
                mock_scan.assert_called_once_with("wlan0", None)
    
    @patch('wifi_jammer.scanner.network_scanner.platform_system')
    def test_scan_networks_macos(self, mock_platform):
        """Test network scanning on macOS."""
        mock_platform.system.return_value = "Darwin"
        
        # Mock platform interface
        mock_interface_info = Mock()
        mock_interface_info.status = "Available"
        
        # Create a new scanner with mocked platform interface
        with patch('wifi_jammer.scanner.network_scanner.PlatformInterfaceFactory') as mock_factory:
            mock_platform_interface = Mock()
            mock_platform_interface.get_interface_info.return_value = mock_interface_info
            mock_factory.create.return_value = mock_platform_interface
            
            scanner = ScapyNetworkScanner(self.mock_logger)
            
            # Mock the macOS scanning method
            with patch.object(scanner, '_scan_macos_networks') as mock_scan:
                scanner.scan_networks("wlan0")
                mock_scan.assert_called_once_with("wlan0", None)
    
    def test_scan_networks_interface_not_available(self):
        """Test network scanning with unavailable interface."""
        # Mock platform interface
        mock_interface_info = Mock()
        mock_interface_info.status = "Not Available"
        
        # Create a new scanner with mocked platform interface
        with patch('wifi_jammer.scanner.network_scanner.PlatformInterfaceFactory') as mock_factory:
            mock_platform_interface = Mock()
            mock_platform_interface.get_interface_info.return_value = mock_interface_info
            mock_factory.create.return_value = mock_platform_interface
            
            scanner = ScapyNetworkScanner(self.mock_logger)
            
            networks = scanner.scan_networks("wlan0")
            
            self.assertEqual(networks, [])
            # The scanning state should be False after the scan completes
            # Note: The scanning state is set to False in the scan_networks method
            # regardless of whether the interface is available or not
            self.assertFalse(scanner._scanning)


if __name__ == '__main__':
    unittest.main()
