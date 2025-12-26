"""
Branch: AES-GCM Encryptor

AEAD encryption using AES-GCM (hardware-accelerated).
Suitable for: high-performance, hardware AES-NI support
"""

import secrets
from typing import Dict, Any
from core.skeleton import IEncryptionScheme, CryptoPackage

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class AESGCMEncryptor(IEncryptionScheme):
    """AES-256-GCM AEAD encryption"""
    
    def __init__(self, key: bytes = None):
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required")
        
        self.key = key or secrets.token_bytes(32)  # 256-bit key
        self.cipher = AESGCM(self.key)
        self.operation_count = 0
        self.max_operations = 2**32 - 1  # GCM nonce limit
    
    def encrypt(self, plaintext: bytes, associated_data: bytes) -> CryptoPackage:
        """Encrypt with AES-GCM"""
        nonce = secrets.token_bytes(12)  # 96-bit nonce recommended for GCM
        
        ciphertext = self.cipher.encrypt(nonce, plaintext, associated_data)
        
        # ciphertext includes authentication tag
        tag = ciphertext[-16:]
        ct = ciphertext[:-16]
        
        self.operation_count += 1
        if self.operation_count >= self.max_operations:
            self.rotate_keys()
        
        return CryptoPackage(
            ciphertext=ct,
            nonce=nonce,
            tag=tag,
            metadata={'algorithm': 'AES-256-GCM'}
        )
    
    def decrypt(self, package: CryptoPackage) -> bytes:
        """Decrypt with verification"""
        full_ciphertext = package.ciphertext + package.tag
        
        plaintext = self.cipher.decrypt(
            package.nonce,
            full_ciphertext,
            package.metadata.get('associated_data', b'')
        )
        
        return plaintext
    
    def rotate_keys(self) -> None:
        """Rotate encryption key"""
        self.key = secrets.token_bytes(32)
        self.cipher = AESGCM(self.key)
        self.operation_count = 0
