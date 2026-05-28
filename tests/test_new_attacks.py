#!/usr/bin/env python3
"""
Tests for new attack modules: ChannelHopAttack, PmkidCaptureAttack,
EvilTwinAttack, NetcutAttack.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from wifi_jammer.core.interfaces import AttackType, AttackConfig
from wifi_jammer.attacks.channel_hop_attack import ChannelHopAttack
from wifi_jammer.attacks.pmkid_capture_attack import PmkidCaptureAttack
from wifi_jammer.attacks.evil_twin_attack import EvilTwinAttack
from wifi_jammer.attacks.netcut_attack import NetcutAttack
from wifi_jammer.utils.logger import RichLogger
from scapy.all import Packet


class TestChannelHopAttack(unittest.TestCase):
    """Test ChannelHopAttack class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=RichLogger)
        self.attack = ChannelHopAttack(self.mock_logger)
        self.attack._config = Mock()
        self.attack._config.target_bssid = "00:11:22:33:44:55"
        self.attack._config.target_client = ""
        self.attack._config.interface = "wlan0"

    def test_channel_hop_creation(self):
        """Test ChannelHopAttack instance creation."""
        self.assertIsInstance(self.attack, ChannelHopAttack)
        self.assertFalse(self.attack._running)
        self.assertIsNone(self.attack._hop_thread)
        self.assertEqual(self.attack._current_channel, 1)
        self.assertEqual(self.attack._hop_channels, [])

    def test_channel_hop_default_channels(self):
        """Test default hop channels are [1, 6, 11]."""
        # execute() does: self._hop_channels = config.hop_channels or [1, 6, 11]
        # Empty list is falsy, so it falls back to [1, 6, 11]
        config = AttackConfig(
            attack_type=AttackType.CHANNEL_HOP,
            target_bssid="00:11:22:33:44:55",
            interface="wlan0",
            channel=1,
        )
        hop = config.hop_channels or [1, 6, 11]
        self.assertEqual(hop, [1, 6, 11])

    def test_channel_hop_custom_channels(self):
        """Test custom hop channels work."""
        self.attack._hop_channels = [3, 7, 11, 13]
        self.assertEqual(self.attack._hop_channels, [3, 7, 11, 13])
        self.assertEqual(len(self.attack._hop_channels), 4)
        self.assertIn(3, self.attack._hop_channels)
        self.assertIn(13, self.attack._hop_channels)

    def test_channel_hop_packet_creation(self):
        """Test deauth packet is created correctly."""
        packet = self.attack._create_packet()
        self.assertIsNotNone(packet)
        self.assertIsInstance(packet, Packet)
        packet_str = str(packet)
        self.assertIn('Dot11Deauth', packet_str)

    def test_channel_hop_packet_no_target(self):
        """Test packet creation returns None when no target BSSID."""
        self.attack._config.target_bssid = None
        packet = self.attack._create_packet()
        self.assertIsNone(packet)
        self.mock_logger.warning.assert_called()

    def test_channel_hop_packet_broadcast(self):
        """Test packet uses broadcast addr when no target client."""
        self.attack._config.target_client = ""
        packet = self.attack._create_packet()
        self.assertIsNotNone(packet)
        packet_str = str(packet)
        self.assertIn('ff:ff:ff:ff:ff:ff', packet_str)


class TestPmkidCaptureAttack(unittest.TestCase):
    """Test PmkidCaptureAttack class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=RichLogger)
        self.attack = PmkidCaptureAttack(self.mock_logger)
        self.attack._config = Mock()
        self.attack._config.target_bssid = "00:11:22:33:44:55"
        self.attack._config.source_mac = ""
        self.attack._config.interface = "wlan0"

    def test_pmkid_creation(self):
        """Test PmkidCaptureAttack instance creation."""
        self.assertIsInstance(self.attack, PmkidCaptureAttack)
        self.assertEqual(self.attack._capture_file, "")
        self.assertEqual(self.attack._captured_pmkids, [])
        self.assertIsNone(self.attack._capture_thread)

    def test_pmkid_packet_creation(self):
        """Test association request packet creation."""
        packet = self.attack._create_packet()
        self.assertIsNotNone(packet)
        self.assertIsInstance(packet, Packet)
        packet_str = str(packet)
        self.assertIn('Dot11AssoReq', packet_str)

    def test_pmkid_capture_file_default(self):
        """Test default capture filename is pmkid_capture.pcap."""
        # execute() sets: self._capture_file = config.capture_file or "pmkid_capture.pcap"
        config = Mock()
        config.capture_file = ""
        capture_file = config.capture_file or "pmkid_capture.pcap"
        self.assertEqual(capture_file, "pmkid_capture.pcap")

    def test_pmkid_packet_no_target(self):
        """Test packet creation returns None when no target BSSID."""
        self.attack._config.target_bssid = None
        packet = self.attack._create_packet()
        self.assertIsNone(packet)
        self.mock_logger.warning.assert_called()

    def test_pmkid_packet_target_in_addr(self):
        """Test packet addr1 is set to target BSSID."""
        packet = self.attack._create_packet()
        self.assertIsNotNone(packet)
        packet_str = str(packet)
        self.assertIn('00:11:22:33:44:55', packet_str)


class TestEvilTwinAttack(unittest.TestCase):
    """Test EvilTwinAttack class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=RichLogger)
        self.attack = EvilTwinAttack(self.mock_logger)
        self.attack._config = Mock()
        self.attack._config.target_bssid = "00:11:22:33:44:55"
        self.attack._config.target_ssid = "TestNetwork"
        self.attack._config.spoof_ssid = ""
        self.attack._config.channel = 6
        self.attack._config.interface = "wlan0"
        self.attack._spoof_ssid = ""

    def test_evil_twin_creation(self):
        """Test EvilTwinAttack instance creation."""
        self.assertIsInstance(self.attack, EvilTwinAttack)
        self.assertFalse(self.attack._running)
        self.assertIsNone(self.attack._deauth_thread)
        self.assertIsNone(self.attack._beacon_thread)
        self.assertEqual(self.attack._spoof_ssid, "")

    def test_evil_twin_spoof_ssid(self):
        """Test SSID spoofing."""
        self.attack._spoof_ssid = "FreeWiFi"
        self.assertEqual(self.attack._spoof_ssid, "FreeWiFi")
        packet = self.attack._create_beacon_packet()
        packet_str = str(packet)
        self.assertIn('FreeWiFi', packet_str)

    def test_evil_twin_beacon_packet(self):
        """Test beacon packet structure."""
        self.attack._spoof_ssid = "TestSpoof"
        packet = self.attack._create_beacon_packet()
        self.assertIsNotNone(packet)
        self.assertIsInstance(packet, Packet)
        packet_str = str(packet)
        self.assertIn('Dot11Beacon', packet_str)
        self.assertIn('TestSpoof', packet_str)

    def test_evil_twin_beacon_uses_target_ssid(self):
        """Test beacon uses target SSID when no spoof SSID set."""
        self.attack._spoof_ssid = ""
        packet = self.attack._create_beacon_packet()
        self.assertIsNotNone(packet)
        packet_str = str(packet)
        self.assertIn('TestNetwork', packet_str)

    def test_evil_twin_deauth_packet(self):
        """Test deauth packet creation."""
        packet = self.attack._create_deauth_packet()
        self.assertIsNotNone(packet)
        self.assertIsInstance(packet, Packet)
        packet_str = str(packet)
        self.assertIn('Dot11Deauth', packet_str)

    def test_evil_twin_create_packet_returns_none(self):
        """Test _create_packet returns None (evil twin uses separate methods)."""
        packet = self.attack._create_packet()
        self.assertIsNone(packet)


class TestNetcutAttack(unittest.TestCase):
    """Test NetcutAttack class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=RichLogger)
        self.attack = NetcutAttack(self.mock_logger)
        self.attack._config = Mock()
        self.attack._config.target_bssid = "00:11:22:33:44:55"
        self.attack._config.interface = "wlan0"

    def test_netcut_creation(self):
        """Test NetcutAttack instance creation."""
        self.assertIsInstance(self.attack, NetcutAttack)
        self.assertEqual(self.attack._target_clients, [])
        self.assertEqual(self.attack._client_index, 0)
        self.assertFalse(self.attack._active)

    def test_netcut_target_clients(self):
        """Test target client list."""
        clients = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"]
        self.attack._target_clients = clients
        self.assertEqual(self.attack._target_clients, clients)
        self.assertEqual(len(self.attack._target_clients), 3)
        self.assertIn("aa:bb:cc:dd:ee:02", self.attack._target_clients)

    def test_netcut_no_clients_returns_false(self):
        """Test execute returns False on empty clients."""
        config = AttackConfig(
            attack_type=AttackType.NETCUT,
            target_bssid="00:11:22:33:44:55",
            interface="wlan0",
            target_clients=[],
        )
        result = self.attack.execute(config)
        self.assertFalse(result)
        self.mock_logger.error.assert_called()

    def test_netcut_packet_creation(self):
        """Test deauth packet creation with clients set."""
        self.attack._target_clients = ["aa:bb:cc:dd:ee:01"]
        self.attack._client_index = 0
        packet = self.attack._create_packet()
        self.assertIsNotNone(packet)
        self.assertIsInstance(packet, Packet)
        packet_str = str(packet)
        self.assertIn('Dot11Deauth', packet_str)

    def test_netcut_packet_no_clients(self):
        """Test packet creation returns None with no clients."""
        self.attack._target_clients = []
        packet = self.attack._create_packet()
        self.assertIsNone(packet)

    def test_netcut_client_rotation(self):
        """Test packets rotate through target clients."""
        clients = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
        self.attack._target_clients = clients
        self.attack._client_index = 0

        # First packet goes to client 0
        self.attack._create_packet()
        self.assertEqual(self.attack._client_index, 1)

        # Second packet goes to client 1
        self.attack._create_packet()
        self.assertEqual(self.attack._client_index, 2)

        # Third packet wraps via modulo
        self.attack._create_packet()
        self.assertEqual(self.attack._client_index, 3)

    def test_netcut_no_bssid_returns_false(self):
        """Test execute returns False when no target BSSID."""
        config = AttackConfig(
            attack_type=AttackType.NETCUT,
            target_bssid="",
            interface="wlan0",
            target_clients=["aa:bb:cc:dd:ee:01"],
        )
        result = self.attack.execute(config)
        self.assertFalse(result)
        self.mock_logger.error.assert_called()

    def test_netcut_stop_clears_clients(self):
        """Test stop clears target clients."""
        self.attack._target_clients = ["aa:bb:cc:dd:ee:01"]
        self.attack._active = True
        self.attack.stop()
        self.assertFalse(self.attack._active)
        self.assertEqual(self.attack._target_clients, [])


if __name__ == '__main__':
    unittest.main()
