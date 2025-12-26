"""
Branch: ChaCha20-Poly1305 Encryptor

AEAD encryption using ChaCha20-Poly1305.
Suitable for: general use, software implementations
"""

import secrets
from typing import Dict, Any
from core.skeleton import IEncryptionScheme, CryptoPackage

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class ChaCha20Encryptor(IEncryptionScheme):
    """ChaCha20-Poly1305 AEAD encryption"""
    
    def __init__(self, key: bytes = None):
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required")
        
        self.key = key or secrets.token_bytes(32)
        self.cipher = ChaCha20Poly1305(self.key)
        self.operation_count = 0
        self.max_operations = 1000
    
    def encrypt(self, plaintext: bytes, associated_data: bytes) -> CryptoPackage:
        """Encrypt with ChaCha20-Poly1305"""
        nonce = secrets.token_bytes(12)  # 96-bit nonce
        
        ciphertext = self.cipher.encrypt(nonce, plaintext, associated_data)
        
        # ciphertext includes the Poly1305 tag (last 16 bytes)
        tag = ciphertext[-16:]
        ct = ciphertext[:-16]
        
        self.operation_count += 1
        if self.operation_count >= self.max_operations:
            self.rotate_keys()
        
        return CryptoPackage(
            ciphertext=ct,
            nonce=nonce,
            tag=tag,
            metadata={'algorithm': 'ChaCha20-Poly1305'}
        )
    
    def decrypt(self, package: CryptoPackage) -> bytes:
        """Decrypt with verification"""
        # Reconstruct full ciphertext (ct + tag)
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
        self.cipher = ChaCha20Poly1305(self.key)
        self.operation_count = 0
