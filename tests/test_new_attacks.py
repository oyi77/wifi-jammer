#!/usr/bin/env python3
"""
Tests for new attack types: Channel Hopping, PMKID Capture, Evil Twin, NetCut.
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
        self.attack._config.target_client = None

    def test_initialization(self):
        """Test ChannelHopAttack initialization attributes."""
        attack = ChannelHopAttack(self.mock_logger)
        self.assertIsNone(attack._hop_thread)
        self.assertEqual(attack._current_channel, 1)
        self.assertEqual(attack._hop_channels, [])

    def test_create_packet(self):
        """Test deauth packet creation with valid config."""
        packet = self.attack._create_packet()
        self.assertIsNotNone(packet)
        self.assertIsInstance(packet, Packet)
        packet_str = str(packet)
        self.assertIn('Dot11Deauth', packet_str)

    def test_create_packet_no_config(self):
        """Test packet creation returns None when no target BSSID."""
        self.attack._config.target_bssid = None
        packet = self.attack._create_packet()
        self.assertIsNone(packet)
        self.mock_logger.warning.assert_called()

    @patch('wifi_jammer.attacks.channel_hop_attack.threading.Thread')
    def test_execute(self, mock_thread_cls):
        """Test execute starts hop thread with configured channels."""
        mock_base_thread = MagicMock()
        mock_hop_thread = MagicMock()
        mock_thread_cls.side_effect = [mock_base_thread, mock_hop_thread]

        config = AttackConfig(
            attack_type=AttackType.CHANNEL_HOP,
            target_bssid="00:11:22:33:44:55",
            interface="wlan0",
            channel=6,
            hop_channels=[1, 6, 11],
        )

        with patch('wifi_jammer.attacks.base_attack.validate_attack_config', return_value=(True, "")), \
             patch('wifi_jammer.attacks.base_attack.is_unix_like', return_value=False):
            result = self.attack.execute(config)

        self.assertTrue(result)
        self.assertEqual(self.attack._hop_channels, [1, 6, 11])
        mock_hop_thread.start.assert_called_once()

    def test_stop(self):
        """Test stop joins the hop thread."""
        mock_hop_thread = MagicMock()
        mock_hop_thread.is_alive.return_value = True
        self.attack._hop_thread = mock_hop_thread
        self.attack._running = True

        self.attack.stop()
        mock_hop_thread.join.assert_called_once_with(timeout=2)


class TestPmkidCaptureAttack(unittest.TestCase):
    """Test PmkidCaptureAttack class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=RichLogger)
        self.attack = PmkidCaptureAttack(self.mock_logger)
        self.attack._config = Mock()
        self.attack._config.target_bssid = "00:11:22:33:44:55"
        self.attack._config.source_mac = "aa:bb:cc:dd:ee:ff"

    def test_initialization(self):
        """Test PmkidCaptureAttack initialization attributes."""
        attack = PmkidCaptureAttack(self.mock_logger)
        self.assertEqual(attack._capture_file, "")
        self.assertEqual(attack._captured_pmkids, [])

    def test_create_packet(self):
        """Test association request packet creation."""
        packet = self.attack._create_packet()
        self.assertIsNotNone(packet)
        self.assertIsInstance(packet, Packet)

    @patch('wifi_jammer.attacks.pmkid_capture_attack.threading.Thread')
    def test_execute(self, mock_thread_cls):
        """Test execute starts capture thread."""
        mock_base_thread = MagicMock()
        mock_capture_thread = MagicMock()
        mock_thread_cls.side_effect = [mock_base_thread, mock_capture_thread]

        config = AttackConfig(
            attack_type=AttackType.PMKID_CAPTURE,
            target_bssid="00:11:22:33:44:55",
            interface="wlan0",
            channel=6,
            capture_file="test.pcap",
        )

        with patch('wifi_jammer.attacks.base_attack.validate_attack_config', return_value=(True, "")), \
             patch('wifi_jammer.attacks.base_attack.is_unix_like', return_value=False):
            result = self.attack.execute(config)

        self.assertTrue(result)
        self.assertEqual(self.attack._capture_file, "test.pcap")
        # execute starts both capture thread and base attack send thread
        self.assertGreaterEqual(mock_capture_thread.start.call_count, 1)


class TestEvilTwinAttack(unittest.TestCase):
    """Test EvilTwinAttack class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=RichLogger)
        self.attack = EvilTwinAttack(self.mock_logger)
        self.attack._config = Mock()
        self.attack._config.target_bssid = "00:11:22:33:44:55"
        self.attack._config.target_ssid = "TestNetwork"
        self.attack._config.channel = 6
        self.attack._spoof_ssid = "FakeNetwork"

    def test_initialization(self):
        """Test EvilTwinAttack initialization attributes."""
        attack = EvilTwinAttack(self.mock_logger)
        self.assertEqual(attack._spoof_ssid, "")

    def test_create_packet(self):
        """Test _create_packet returns None (evil twin uses beacon/deauth)."""
        packet = self.attack._create_packet()
        self.assertIsNone(packet)

    def test_create_beacon_packet(self):
        """Test beacon packet contains spoof SSID."""
        packet = self.attack._create_beacon_packet()
        self.assertIsNotNone(packet)
        self.assertIsInstance(packet, Packet)
        packet_str = str(packet)
        self.assertIn('Dot11Beacon', packet_str)
        self.assertIn('FakeNetwork', packet_str)

    def test_create_deauth_packet(self):
        """Test deauth packet is broadcast."""
        packet = self.attack._create_deauth_packet()
        self.assertIsNotNone(packet)
        self.assertIsInstance(packet, Packet)
        packet_str = str(packet)
        self.assertIn('Dot11Deauth', packet_str)
        self.assertIn('ff:ff:ff:ff:ff:ff', packet_str)


class TestNetcutAttack(unittest.TestCase):
    """Test NetcutAttack class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=RichLogger)
        self.attack = NetcutAttack(self.mock_logger)
        self.attack._config = Mock()
        self.attack._config.target_bssid = "00:11:22:33:44:55"
        self.attack._target_clients = [
            "aa:bb:cc:dd:ee:01",
            "aa:bb:cc:dd:ee:02",
        ]
        self.attack._client_index = 0

    def test_initialization(self):
        """Test NetcutAttack initialization attributes."""
        attack = NetcutAttack(self.mock_logger)
        self.assertEqual(attack._target_clients, [])

    def test_create_packet(self):
        """Test packet cycles through target clients."""
        packet1 = self.attack._create_packet()
        self.assertIsNotNone(packet1)
        packet_str1 = str(packet1)
        self.assertIn('aa:bb:cc:dd:ee:01', packet_str1)
        self.assertIn('Dot11Deauth', packet_str1)

        packet2 = self.attack._create_packet()
        self.assertIsNotNone(packet2)
        packet_str2 = str(packet2)
        self.assertIn('aa:bb:cc:dd:ee:02', packet_str2)

    def test_create_packet_no_clients(self):
        """Test returns None with empty target_clients."""
        self.attack._target_clients = []
        packet = self.attack._create_packet()
        self.assertIsNone(packet)

    def test_execute_no_clients(self):
        """Test execute returns False with empty target_clients."""
        config = AttackConfig(
            attack_type=AttackType.NETCUT,
            target_bssid="00:11:22:33:44:55",
            interface="wlan0",
            channel=6,
            target_clients=[],
        )
        result = self.attack.execute(config)
        self.assertFalse(result)
        self.mock_logger.error.assert_called()


if __name__ == '__main__':
    unittest.main()
