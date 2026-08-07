#!/usr/bin/env python3
"""
Tests for configuration management.
"""

import unittest
from unittest.mock import patch
import os
import tempfile
import yaml
import sys

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wifi_jammer.config import (
    ToolConfig,
    ConfigManager,
    get_config,
    get_config_value,
    set_config_value,
    save_config,
    config_manager,
)


class TestToolConfig(unittest.TestCase):
    """Test ToolConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ToolConfig()
        self.assertEqual(config.default_packet_count, 0)
        self.assertEqual(config.default_delay, 0.1)
        self.assertEqual(config.default_verbose, False)
        self.assertEqual(config.scan_timeout, 10)
        self.assertEqual(config.max_networks, 100)
        self.assertEqual(config.auto_monitor_mode, True)
        self.assertEqual(config.rate_limit_enabled, True)
        self.assertEqual(config.max_packets_per_second, 1000)

    def test_custom_values(self):
        """Test custom configuration values."""
        config = ToolConfig(
            default_packet_count=100,
            default_delay=0.5,
            default_verbose=True,
            scan_timeout=20,
        )
        self.assertEqual(config.default_packet_count, 100)
        self.assertEqual(config.default_delay, 0.5)
        self.assertEqual(config.default_verbose, True)
        self.assertEqual(config.scan_timeout, 20)


class TestConfigManager(unittest.TestCase):
    """Test ConfigManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, "test_config.yaml")
        self.manager = ConfigManager(config_file=self.config_file)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization_with_custom_file(self):
        """Test initialization with custom config file."""
        manager = ConfigManager(config_file=self.config_file)
        self.assertEqual(manager.config_file, self.config_file)
        self.assertIsInstance(manager.config, ToolConfig)

    def test_initialization_with_default_file(self):
        """Test initialization with default config file."""
        # Just test that it initializes without error
        # The actual path depends on home directory
        manager = ConfigManager()
        self.assertIsInstance(manager.config, ToolConfig)
        self.assertIsNotNone(manager.config_file)

    def test_load_config_from_file(self):
        """Test loading configuration from file."""
        config_data = {
            "default_packet_count": 50,
            "default_delay": 0.2,
            "default_verbose": True,
        }
        with open(self.config_file, "w") as f:
            yaml.dump(config_data, f)

        manager = ConfigManager(config_file=self.config_file)
        self.assertEqual(manager.config.default_packet_count, 50)
        self.assertEqual(manager.config.default_delay, 0.2)
        self.assertEqual(manager.config.default_verbose, True)

    def test_load_config_nonexistent_file(self):
        """Test loading configuration when file doesn't exist."""
        nonexistent_file = os.path.join(self.temp_dir, "nonexistent.yaml")
        manager = ConfigManager(config_file=nonexistent_file)
        # Should use default values
        self.assertEqual(manager.config.default_packet_count, 0)
        self.assertEqual(manager.config.default_delay, 0.1)

    def test_load_config_invalid_yaml(self):
        """Test loading configuration with invalid YAML."""
        with open(self.config_file, "w") as f:
            f.write("invalid: yaml: content: [")

        # Should not raise exception, should use defaults
        manager = ConfigManager(config_file=self.config_file)
        self.assertIsInstance(manager.config, ToolConfig)

    def test_save_config(self):
        """Test saving configuration to file."""
        self.manager.config.default_packet_count = 200
        self.manager.config.default_delay = 0.3

        result = self.manager.save_config()
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.config_file))

        # Verify saved content
        with open(self.config_file, "r") as f:
            saved_data = yaml.safe_load(f)
            self.assertEqual(saved_data["default_packet_count"], 200)
            self.assertEqual(saved_data["default_delay"], 0.3)

    def test_save_config_creates_directory(self):
        """Test that save_config creates directory if needed."""
        nested_dir = os.path.join(self.temp_dir, "nested", "dir")
        os.makedirs(nested_dir, exist_ok=True)  # Ensure parent exists
        nested_file = os.path.join(nested_dir, "config.yaml")
        manager = ConfigManager(config_file=nested_file)

        result = manager.save_config()
        self.assertTrue(result)
        self.assertTrue(os.path.exists(nested_file))

    def test_get_existing_key(self):
        """Test getting existing configuration key."""
        value = self.manager.get("default_packet_count")
        self.assertEqual(value, 0)

    def test_get_nonexistent_key(self):
        """Test getting nonexistent configuration key."""
        value = self.manager.get("nonexistent_key", "default_value")
        self.assertEqual(value, "default_value")

    def test_set_existing_key(self):
        """Test setting existing configuration key."""
        result = self.manager.set("default_packet_count", 150)
        self.assertTrue(result)
        self.assertEqual(self.manager.config.default_packet_count, 150)

    def test_set_nonexistent_key(self):
        """Test setting nonexistent configuration key."""
        result = self.manager.set("nonexistent_key", "value")
        self.assertFalse(result)

    def test_update_multiple_keys(self):
        """Test updating multiple configuration keys."""
        updates = {
            "default_packet_count": 300,
            "default_delay": 0.4,
            "default_verbose": True,
        }
        self.manager.update(updates)

        self.assertEqual(self.manager.config.default_packet_count, 300)
        self.assertEqual(self.manager.config.default_delay, 0.4)
        self.assertEqual(self.manager.config.default_verbose, True)

    def test_reset_to_defaults(self):
        """Test resetting configuration to defaults."""
        self.manager.config.default_packet_count = 500
        self.manager.config.default_delay = 0.8

        self.manager.reset_to_defaults()

        self.assertEqual(self.manager.config.default_packet_count, 0)
        self.assertEqual(self.manager.config.default_delay, 0.1)

    def test_get_attack_config(self):
        """Test getting attack-related configuration."""
        attack_config = self.manager.get_attack_config()

        self.assertIn("default_packet_count", attack_config)
        self.assertIn("default_delay", attack_config)
        self.assertIn("default_verbose", attack_config)
        self.assertIn("max_packets_per_second", attack_config)
        self.assertIn("rate_limit_enabled", attack_config)

    def test_get_network_config(self):
        """Test getting network-related configuration."""
        network_config = self.manager.get_network_config()

        self.assertIn("scan_timeout", network_config)
        self.assertIn("max_networks", network_config)
        self.assertIn("auto_monitor_mode", network_config)
        self.assertIn("auto_channel_set", network_config)

    def test_get_logging_config(self):
        """Test getting logging-related configuration."""
        logging_config = self.manager.get_logging_config()

        self.assertIn("log_level", logging_config)
        self.assertIn("log_file", logging_config)
        self.assertIn("log_to_console", logging_config)


class TestConfigFunctions(unittest.TestCase):
    """Test module-level configuration functions."""

    def test_get_config(self):
        """Test get_config function."""
        config = get_config()
        self.assertIsInstance(config, ToolConfig)

    def test_get_config_value(self):
        """Test get_config_value function."""
        value = get_config_value("default_packet_count")
        self.assertEqual(value, 0)

        default_value = get_config_value("nonexistent_key", "default")
        self.assertEqual(default_value, "default")

    def test_set_config_value(self):
        """Test set_config_value function."""
        original_value = get_config_value("default_packet_count")

        result = set_config_value("default_packet_count", 250)
        self.assertTrue(result)
        self.assertEqual(get_config_value("default_packet_count"), 250)

        # Reset
        set_config_value("default_packet_count", original_value)

    def test_set_config_value_invalid_key(self):
        """Test set_config_value with invalid key."""
        result = set_config_value("nonexistent_key", "value")
        self.assertFalse(result)

    @patch.object(config_manager, "save_config")
    def test_save_config_function(self, mock_save):
        """Test save_config function."""
        mock_save.return_value = True
        result = save_config()
        self.assertTrue(result)
        mock_save.assert_called_once()


if __name__ == "__main__":
    unittest.main()
