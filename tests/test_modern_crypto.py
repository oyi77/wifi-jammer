#!/usr/bin/env python3
"""
Tests for modern cryptography utilities.
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from wifi_jammer.utils.modern_crypto import ModernCrypto, get_modern_crypto


class TestModernCrypto(unittest.TestCase):
    """Test ModernCrypto class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.crypto = ModernCrypto()
    
    def test_initialization(self):
        """Test crypto initialization."""
        self.assertIsInstance(self.crypto, ModernCrypto)
    
    def test_generate_secure_key(self):
        """Test secure key generation."""
        key_128 = self.crypto.generate_secure_key(128)
        key_256 = self.crypto.generate_secure_key(256)
        
        self.assertEqual(len(key_128), 16)  # 128 bits = 16 bytes
        self.assertEqual(len(key_256), 32)  # 256 bits = 32 bytes
        
        # Keys should be different
        self.assertNotEqual(key_128, key_256)
    
    def test_generate_rsa_key(self):
        """Test RSA key generation."""
        private_key = self.crypto.generate_rsa_key(2048)
        
        self.assertIsNotNone(private_key)
        self.assertEqual(private_key.key_size, 2048)
        
        # Should have public key
        public_key = private_key.public_key()
        self.assertIsNotNone(public_key)
    
    def test_encrypt_decrypt_aes_gcm(self):
        """Test AES-GCM encryption and decryption."""
        key = self.crypto.generate_secure_key(256)
        data = b"Hello, World! This is a test message."
        
        # Encrypt
        encrypted = self.crypto.encrypt_aes(data, key, "GCM")
        
        self.assertIn('ciphertext', encrypted)
        self.assertIn('iv', encrypted)
        self.assertIn('tag', encrypted)
        
        # Decrypt
        decrypted = self.crypto.decrypt_aes(encrypted, key, "GCM")
        
        self.assertEqual(data, decrypted)
    
    def test_encrypt_decrypt_aes_cbc(self):
        """Test AES-CBC encryption and decryption."""
        key = self.crypto.generate_secure_key(256)
        data = b"Hello, World! This is a test message."
        
        # Encrypt
        encrypted = self.crypto.encrypt_aes(data, key, "CBC")
        
        self.assertIn('ciphertext', encrypted)
        self.assertIn('iv', encrypted)
        
        # Decrypt
        decrypted = self.crypto.decrypt_aes(encrypted, key, "CBC")
        
        self.assertEqual(data, decrypted)
    
    def test_hash_data(self):
        """Test data hashing."""
        data = b"Test data for hashing"
        
        # Test different hash algorithms
        sha256_hash = self.crypto.hash_data(data, "SHA256")
        sha384_hash = self.crypto.hash_data(data, "SHA384")
        sha512_hash = self.crypto.hash_data(data, "SHA512")
        
        self.assertEqual(len(sha256_hash), 32)  # SHA256 = 256 bits = 32 bytes
        self.assertEqual(len(sha384_hash), 48)  # SHA384 = 384 bits = 48 bytes
        self.assertEqual(len(sha512_hash), 64)  # SHA512 = 512 bits = 64 bytes
        
        # Same data should produce same hash
        sha256_hash2 = self.crypto.hash_data(data, "SHA256")
        self.assertEqual(sha256_hash, sha256_hash2)
    
    def test_hmac_sign(self):
        """Test HMAC signature creation."""
        key = self.crypto.generate_secure_key(256)
        data = b"Data to sign"
        
        signature = self.crypto.hmac_sign(data, key, "SHA256")
        
        self.assertIsInstance(signature, bytes)
        self.assertEqual(len(signature), 32)  # SHA256 HMAC = 256 bits = 32 bytes
    
    def test_derive_key(self):
        """Test key derivation."""
        password = b"test_password"
        salt = os.urandom(16)
        
        derived_key = self.crypto.derive_key(password, salt, 32)
        
        self.assertEqual(len(derived_key), 32)
        
        # Same password and salt should produce same key
        derived_key2 = self.crypto.derive_key(password, salt, 32)
        self.assertEqual(derived_key, derived_key2)
    
    def test_rsa_signature(self):
        """Test RSA signature creation and verification."""
        private_key = self.crypto.generate_rsa_key(2048)
        public_key = private_key.public_key()
        data = b"Data to sign with RSA"
        
        # Create signature
        signature = self.crypto.create_rsa_signature(data, private_key)
        
        self.assertIsInstance(signature, bytes)
        
        # Verify signature
        is_valid = self.crypto.verify_rsa_signature(data, signature, public_key)
        self.assertTrue(is_valid)
        
        # Verify with wrong data should fail
        wrong_data = b"Wrong data"
        is_valid = self.crypto.verify_rsa_signature(wrong_data, signature, public_key)
        self.assertFalse(is_valid)
    
    def test_invalid_mode(self):
        """Test invalid encryption mode handling."""
        key = self.crypto.generate_secure_key(256)
        data = b"Test data"
        
        with self.assertRaises(ValueError):
            self.crypto.encrypt_aes(data, key, "INVALID_MODE")
    
    def test_invalid_hash_algorithm(self):
        """Test invalid hash algorithm handling."""
        data = b"Test data"
        
        with self.assertRaises(ValueError):
            self.crypto.hash_data(data, "INVALID_ALGORITHM")
    
    def test_get_modern_crypto(self):
        """Test global crypto instance."""
        crypto_instance = get_modern_crypto()
        
        self.assertIsInstance(crypto_instance, ModernCrypto)
        
        # Should return the same instance
        crypto_instance2 = get_modern_crypto()
        self.assertIs(crypto_instance, crypto_instance2)


if __name__ == '__main__':
    unittest.main()
