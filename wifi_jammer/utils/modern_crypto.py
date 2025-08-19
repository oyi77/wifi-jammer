"""
Modern cryptography utilities for WiFi Jammer Tool.
Uses latest cryptography library and avoids deprecated algorithms.
"""

import os
import warnings
from typing import Optional, Union, Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


class ModernCrypto:
    """Modern cryptography utilities avoiding deprecated algorithms."""
    
    def __init__(self):
        """Initialize modern crypto utilities."""
        # Suppress deprecation warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        warnings.filterwarnings("ignore", message=".*TripleDES.*")
        
        # Set environment variables to disable FIPS and deprecated algorithms
        os.environ['CRYPTOGRAPHY_DISABLE_FIPS'] = '1'
        os.environ['CRYPTOGRAPHY_OPENSSL_NO_LEGACY'] = '1'
    
    @staticmethod
    def generate_secure_key(key_size: int = 256) -> bytes:
        """Generate a secure random key using modern algorithms."""
        return os.urandom(key_size // 8)
    
    @staticmethod
    def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
        """Generate RSA key pair using modern key sizes."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
    
    @staticmethod
    def encrypt_aes(data: bytes, key: bytes, mode: str = "GCM") -> Dict[str, bytes]:
        """Encrypt data using AES with modern modes (avoiding deprecated algorithms)."""
        if mode.upper() == "GCM":
            # Use AES-GCM (Galois/Counter Mode) - modern and secure
            iv = os.urandom(12)  # 96-bit IV for GCM
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            return {
                'ciphertext': ciphertext,
                'iv': iv,
                'tag': encryptor.tag
            }
        
        elif mode.upper() == "CBC":
            # Use AES-CBC with proper padding (more secure than TripleDES)
            iv = os.urandom(16)  # 128-bit IV for CBC
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # PKCS7 padding
            block_size = 16
            padding_length = block_size - (len(data) % block_size)
            padded_data = data + bytes([padding_length] * padding_length)
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            return {
                'ciphertext': ciphertext,
                'iv': iv
            }
        
        else:
            raise ValueError(f"Unsupported mode: {mode}. Use 'GCM' or 'CBC'")
    
    @staticmethod
    def decrypt_aes(encrypted_data: Dict[str, bytes], key: bytes, mode: str = "GCM") -> bytes:
        """Decrypt data using AES with modern modes."""
        if mode.upper() == "GCM":
            cipher = Cipher(algorithms.AES(key), modes.GCM(encrypted_data['iv'], encrypted_data['tag']))
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
            return plaintext
        
        elif mode.upper() == "CBC":
            cipher = Cipher(algorithms.AES(key), modes.CBC(encrypted_data['iv']))
            decryptor = cipher.decryptor()
            
            padded_plaintext = decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
            
            # Remove PKCS7 padding
            padding_length = padded_plaintext[-1]
            return padded_plaintext[:-padding_length]
        
        else:
            raise ValueError(f"Unsupported mode: {mode}. Use 'GCM' or 'CBC'")
    
    @staticmethod
    def hash_data(data: bytes, algorithm: str = "SHA256") -> bytes:
        """Hash data using modern hash algorithms."""
        if algorithm.upper() == "SHA256":
            digest = hashes.Hash(hashes.SHA256())
        elif algorithm.upper() == "SHA384":
            digest = hashes.Hash(hashes.SHA384())
        elif algorithm.upper() == "SHA512":
            digest = hashes.Hash(hashes.SHA512())
        elif algorithm.upper() == "BLAKE2B":
            digest = hashes.Hash(hashes.BLAKE2b(64))
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        digest.update(data)
        return digest.finalize()
    
    @staticmethod
    def hmac_sign(data: bytes, key: bytes, algorithm: str = "SHA256") -> bytes:
        """Create HMAC signature using modern algorithms."""
        if algorithm.upper() == "SHA256":
            h = hmac.HMAC(key, hashes.SHA256())
        elif algorithm.upper() == "SHA384":
            h = hmac.HMAC(key, hashes.SHA384())
        elif algorithm.upper() == "SHA512":
            h = hmac.HMAC(key, hashes.SHA512())
        else:
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
        
        h.update(data)
        return h.finalize()
    
    @staticmethod
    def derive_key(password: bytes, salt: bytes, key_length: int = 32) -> bytes:
        """Derive key from password using PBKDF2 with modern parameters."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,  # Modern iteration count
        )
        return kdf.derive(password)
    
    @staticmethod
    def verify_rsa_signature(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
        """Verify RSA signature using modern padding."""
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def create_rsa_signature(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Create RSA signature using modern padding."""
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )


# Global instance for easy access
modern_crypto = ModernCrypto()


def get_modern_crypto() -> ModernCrypto:
    """Get the global modern crypto instance."""
    return modern_crypto
