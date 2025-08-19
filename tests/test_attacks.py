#!/usr/bin/env python3
"""
Tests for attack implementations.
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from wifi_jammer.core.interfaces import AttackType, AttackConfig
from wifi_jammer.attacks.base_attack import AttackStats
from wifi_jammer.attacks.deauth_attack import DeauthAttack, DisassocAttack
from wifi_jammer.attacks.flood_attacks import BeaconFloodAttack
from wifi_jammer.utils.logger import RichLogger
from scapy.all import Packet


class TestAttackStats(unittest.TestCase):
    """Test AttackStats class."""
    
    def test_attack_stats_initialization(self):
        """Test AttackStats initialization."""
        stats = AttackStats()
        self.assertEqual(stats.packets_sent, 0)
        self.assertEqual(stats.packets_failed, 0)
        self.assertIsNone(stats.start_time)
        self.assertIsNone(stats.last_packet_time)
        self.assertEqual(stats.errors, [])
    
    def test_duration_property(self):
        """Test duration property calculation."""
        stats = AttackStats()
        stats.start_time = 100.0
        
        with patch('time.time', return_value=110.0):
            self.assertEqual(stats.duration, 10.0)
    
    def test_packets_per_second(self):
        """Test packets per second calculation."""
        stats = AttackStats()
        stats.start_time = 100.0
        stats.packets_sent = 50
        
        with patch('time.time', return_value=110.0):
            self.assertEqual(stats.packets_per_second, 5.0)
    
    def test_success_rate(self):
        """Test success rate calculation."""
        stats = AttackStats()
        stats.packets_sent = 80
        stats.packets_failed = 20
        
        self.assertEqual(stats.success_rate, 80.0)


class TestDeauthAttack(unittest.TestCase):
    """Test DeauthAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=RichLogger)
        self.attack = DeauthAttack(self.mock_logger)
        self.attack._config = Mock()
        self.attack._config.target_bssid = "00:11:22:33:44:55"
    
    def test_create_packet(self):
        """Test deauth packet creation."""
        packet = self.attack._create_packet()
        self.assertIsNotNone(packet)
        # Check if it's a deauth packet by looking at the packet structure
        self.assertIsInstance(packet, Packet)
        # The packet should have Dot11Deauth layer - check the packet structure
        packet_str = str(packet)
        self.assertIn('Dot11Deauth', packet_str)
    
    def test_create_packet_no_target(self):
        """Test packet creation without target BSSID."""
        self.attack._config.target_bssid = None
        packet = self.attack._create_packet()
        self.assertIsNone(packet)
        self.mock_logger.warning.assert_called()


class TestDisassocAttack(unittest.TestCase):
    """Test DisassocAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=RichLogger)
        self.attack = DisassocAttack(self.mock_logger)
        self.attack._config = Mock()
        self.attack._config.target_bssid = "00:11:22:33:44:55"
    
    def test_create_packet(self):
        """Test disassoc packet creation."""
        packet = self.attack._create_packet()
        self.assertIsNotNone(packet)
        # Check if it's a disassoc packet by looking at the packet structure
        self.assertIsInstance(packet, Packet)
        # The packet should have Dot11Disas layer - check the packet structure
        packet_str = str(packet)
        self.assertIn('Dot11Disas', packet_str)
    
    def test_create_packet_no_target(self):
        """Test packet creation without target BSSID."""
        self.attack._config.target_bssid = None
        packet = self.attack._create_packet()
        self.assertIsNone(packet)
        self.mock_logger.warning.assert_called()


class TestFloodAttacks(unittest.TestCase):
    """Test flood attack classes."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_logger = Mock(spec=RichLogger)
        self.attack = BeaconFloodAttack(self.mock_logger)
        self.attack._config = Mock()
    
    def test_beacon_flood_packet_creation(self):
        """Test beacon flood packet creation."""
        packet = self.attack._create_packet()
        self.assertIsNotNone(packet)
        # Check if it's a beacon packet by looking at the packet structure
        self.assertIsInstance(packet, Packet)
        # The packet should have Dot11Beacon layer - check the packet structure
        packet_str = str(packet)
        self.assertIn('Dot11Beacon', packet_str)


if __name__ == '__main__':
    unittest.main()
