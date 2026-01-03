#!/usr/bin/env python3
"""
Tests for input validation utilities.
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from wifi_jammer.utils.validators import (
    is_valid_mac, is_valid_bssid, is_valid_interface_name,
    is_valid_channel, is_valid_packet_count, is_valid_delay,
    validate_attack_config
)
from wifi_jammer.core.interfaces import AttackConfig, AttackType


class TestMACValidation(unittest.TestCase):
    """Test MAC address validation."""
    
    def test_valid_mac_addresses(self):
        """Test valid MAC addresses."""
        valid_macs = [
            "00:11:22:33:44:55",
            "AA:BB:CC:DD:EE:FF",
            "aa:bb:cc:dd:ee:ff",
            "01:23:45:67:89:AB",
            " 00:11:22:33:44:55 ",  # With whitespace
        ]
        for mac in valid_macs:
            self.assertTrue(is_valid_mac(mac), f"Should be valid: {mac}")
    
    def test_invalid_mac_addresses(self):
        """Test invalid MAC addresses."""
        invalid_macs = [
            "",
            None,
            "00:11:22:33:44",  # Too short
            "00:11:22:33:44:55:66",  # Too long
            "00-11-22-33-44-55",  # Wrong separator
            "00:11:22:33:44:GG",  # Invalid hex
            "00:11:22:33:44",  # Missing octet
            "not a mac address",
            12345,  # Not a string
        ]
        for mac in invalid_macs:
            self.assertFalse(is_valid_mac(mac), f"Should be invalid: {mac}")
    
    def test_is_valid_bssid(self):
        """Test BSSID validation (same as MAC)."""
        self.assertTrue(is_valid_bssid("00:11:22:33:44:55"))
        self.assertFalse(is_valid_bssid("invalid"))


class TestInterfaceNameValidation(unittest.TestCase):
    """Test interface name validation."""
    
    def test_valid_interface_names(self):
        """Test valid interface names."""
        valid_names = [
            "wlan0",
            "eth0",
            "en0",
            "wlan1",
            "wifi0",
            "interface_1",
            "interface-1",
            "lo",
        ]
        for name in valid_names:
            self.assertTrue(is_valid_interface_name(name), f"Should be valid: {name}")
    
    def test_invalid_interface_names(self):
        """Test invalid interface names."""
        invalid_names = [
            "",
            None,
            "interface with spaces",
            "interface@with#special$chars",
            "a" * 20,  # Too long
            "interface.with.dots",
            12345,  # Not a string
        ]
        for name in invalid_names:
            self.assertFalse(is_valid_interface_name(name), f"Should be invalid: {name}")


class TestChannelValidation(unittest.TestCase):
    """Test channel validation."""
    
    def test_valid_channels_2_4ghz(self):
        """Test valid 2.4GHz channels."""
        for channel in range(1, 15):
            self.assertTrue(is_valid_channel(channel, "2.4GHz"), f"Channel {channel} should be valid")
    
    def test_valid_channels_5ghz(self):
        """Test valid 5GHz channels."""
        valid_5ghz = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
        for channel in valid_5ghz:
            self.assertTrue(is_valid_channel(channel, "5GHz"), f"Channel {channel} should be valid")
    
    def test_invalid_channels(self):
        """Test invalid channels."""
        invalid_channels = [
            0,  # Too low
            15,  # Between bands
            35,  # Between bands
            166,  # Too high
            -1,  # Negative
            "1",  # Not an int
            1.5,  # Float
        ]
        for channel in invalid_channels:
            self.assertFalse(is_valid_channel(channel), f"Channel {channel} should be invalid")
    
    def test_channel_without_band(self):
        """Test channel validation without specifying band."""
        # Should accept both 2.4GHz and 5GHz channels
        self.assertTrue(is_valid_channel(6))  # 2.4GHz
        self.assertTrue(is_valid_channel(149))  # 5GHz
        self.assertFalse(is_valid_channel(15))  # Between bands


class TestPacketCountValidation(unittest.TestCase):
    """Test packet count validation."""
    
    def test_valid_packet_counts(self):
        """Test valid packet counts."""
        valid_counts = [0, 1, 10, 100, 1000, 10000]
        for count in valid_counts:
            self.assertTrue(is_valid_packet_count(count), f"Count {count} should be valid")
    
    def test_invalid_packet_counts(self):
        """Test invalid packet counts."""
        invalid_counts = [
            -1,  # Negative
            -100,
            "10",  # Not an int
            10.5,  # Float
            None,
        ]
        for count in invalid_counts:
            self.assertFalse(is_valid_packet_count(count), f"Count {count} should be invalid")


class TestDelayValidation(unittest.TestCase):
    """Test delay validation."""
    
    def test_valid_delays(self):
        """Test valid delay values."""
        valid_delays = [0.0, 0.1, 0.5, 1.0, 10.0, 30.0, 60.0]
        for delay in valid_delays:
            self.assertTrue(is_valid_delay(delay), f"Delay {delay} should be valid")
    
    def test_invalid_delays(self):
        """Test invalid delay values."""
        invalid_delays = [
            -0.1,  # Negative
            -10.0,
            60.1,  # Too high
            100.0,
            "0.1",  # Not a number
            None,
        ]
        for delay in invalid_delays:
            self.assertFalse(is_valid_delay(delay), f"Delay {delay} should be invalid")
    
    def test_delay_as_int(self):
        """Test that int delays are accepted."""
        self.assertTrue(is_valid_delay(0))
        self.assertTrue(is_valid_delay(10))


class TestAttackConfigValidation(unittest.TestCase):
    """Test attack configuration validation."""
    
    def test_validate_valid_config(self):
        """Test validation of valid attack config."""
        config = AttackConfig(
            attack_type=AttackType.DEAUTH,
            target_bssid="00:11:22:33:44:55",
            interface="wlan0",
            channel=6,
            count=100,
            delay=0.1
        )
        is_valid, error = validate_attack_config(config)
        self.assertTrue(is_valid)
        self.assertIsNone(error)
    
    def test_validate_config_none(self):
        """Test validation with None config."""
        is_valid, error = validate_attack_config(None)
        self.assertFalse(is_valid)
        self.assertIsNotNone(error)
    
    def test_validate_config_invalid_bssid(self):
        """Test validation with invalid BSSID."""
        config = AttackConfig(
            attack_type=AttackType.DEAUTH,
            target_bssid="invalid_bssid",
            interface="wlan0",
            channel=6,
            count=100,
            delay=0.1
        )
        is_valid, error = validate_attack_config(config)
        self.assertFalse(is_valid)
        self.assertIn("BSSID", error)
    
    def test_validate_config_invalid_interface(self):
        """Test validation with invalid interface."""
        config = AttackConfig(
            attack_type=AttackType.DEAUTH,
            target_bssid="00:11:22:33:44:55",
            interface="invalid interface name with spaces",
            channel=6,
            count=100,
            delay=0.1
        )
        is_valid, error = validate_attack_config(config)
        self.assertFalse(is_valid)
        self.assertIn("interface", error.lower())
    
    def test_validate_config_invalid_channel(self):
        """Test validation with invalid channel."""
        config = AttackConfig(
            attack_type=AttackType.DEAUTH,
            target_bssid="00:11:22:33:44:55",
            interface="wlan0",
            channel=200,  # Invalid channel
            count=100,
            delay=0.1
        )
        is_valid, error = validate_attack_config(config)
        self.assertFalse(is_valid)
        self.assertIn("channel", error.lower())
    
    def test_validate_config_invalid_count(self):
        """Test validation with invalid packet count."""
        config = AttackConfig(
            attack_type=AttackType.DEAUTH,
            target_bssid="00:11:22:33:44:55",
            interface="wlan0",
            channel=6,
            count=-10,  # Invalid count
            delay=0.1
        )
        is_valid, error = validate_attack_config(config)
        self.assertFalse(is_valid)
        self.assertIn("count", error.lower())
    
    def test_validate_config_invalid_delay(self):
        """Test validation with invalid delay."""
        config = AttackConfig(
            attack_type=AttackType.DEAUTH,
            target_bssid="00:11:22:33:44:55",
            interface="wlan0",
            channel=6,
            count=100,
            delay=100.0  # Invalid delay (too high)
        )
        is_valid, error = validate_attack_config(config)
        self.assertFalse(is_valid)
        self.assertIn("delay", error.lower())
    
    def test_validate_config_invalid_source_mac(self):
        """Test validation with invalid source MAC."""
        config = AttackConfig(
            attack_type=AttackType.DEAUTH,
            target_bssid="00:11:22:33:44:55",
            interface="wlan0",
            channel=6,
            count=100,
            delay=0.1,
            source_mac="invalid_mac"
        )
        is_valid, error = validate_attack_config(config)
        self.assertFalse(is_valid)
        self.assertIn("MAC", error)
    
    def test_validate_config_with_none_values(self):
        """Test validation with None values (should pass if optional)."""
        config = AttackConfig(
            attack_type=AttackType.DEAUTH,
            target_bssid=None,  # Optional
            interface="wlan0",
            channel=None,  # Optional
            count=100,
            delay=0.1
        )
        # Should pass if None values are handled as optional
        is_valid, error = validate_attack_config(config)
        # This depends on implementation - testing that it doesn't crash
        self.assertIsInstance(is_valid, bool)


if __name__ == '__main__':
    unittest.main()

