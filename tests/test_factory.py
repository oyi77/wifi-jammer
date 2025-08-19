#!/usr/bin/env python3
"""
Tests for attack factory.
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from wifi_jammer.core.interfaces import AttackType, IAttackStrategy
from wifi_jammer.factory.attack_factory import AttackFactory


class TestAttackFactory(unittest.TestCase):
    """Test AttackFactory class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.factory = AttackFactory()
    
    def test_initialization(self):
        """Test factory initialization."""
        self.assertIsInstance(self.factory._attack_classes, dict)
        self.assertGreater(len(self.factory._attack_classes), 0)
    
    def test_get_available_attacks(self):
        """Test getting available attack types."""
        attacks = self.factory.get_available_attacks()
        self.assertIsInstance(attacks, list)
        self.assertGreater(len(attacks), 0)
        
        # Check if all expected attack types are available
        expected_types = [
            AttackType.DEAUTH,
            AttackType.DISASSOC,
            AttackType.BEACON_FLOOD,
            AttackType.AUTH_FLOOD,
            AttackType.ASSOC_FLOOD,
            AttackType.PROBE_RESPONSE
        ]
        
        for attack_type in expected_types:
            self.assertIn(attack_type, attacks)
    
    def test_create_attack_success(self):
        """Test successful attack creation."""
        for attack_type in AttackType:
            attack = self.factory.create_attack(attack_type)
            self.assertIsInstance(attack, IAttackStrategy)
    
    def test_create_attack_invalid_type(self):
        """Test creating attack with invalid type."""
        with self.assertRaises(ValueError):
            self.factory.create_attack("invalid_type")
    
    def test_register_attack(self):
        """Test registering new attack type."""
        mock_attack_class = Mock(spec=IAttackStrategy)
        new_attack_type = AttackType.DEAUTH  # Reuse existing type for testing
        
        self.factory.register_attack(new_attack_type, mock_attack_class)
        
        # Verify the attack class was registered
        self.assertEqual(self.factory._attack_classes[new_attack_type], mock_attack_class)


if __name__ == '__main__':
    unittest.main()
