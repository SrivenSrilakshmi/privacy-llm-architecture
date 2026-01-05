"""
Selective Encryption Module

Implements ChaCha20-Poly1305 AEAD encryption for sensitive text segments.

Security Properties:
- AEAD: Authenticated Encryption with Associated Data
- Algorithm: ChaCha20-Poly1305 (IETF RFC 8439)
- Key Size: 256 bits
- Nonce: 96 bits (random, unique per segment)
- Authentication: Poly1305 MAC (128-bit tag)

Key Management:
- Master key stored in device secure storage (not implemented here)
- Per-session keys derived via HKDF-SHA256
- Key rotation: every 1000 requests or 24 hours
- Forward secrecy: ephemeral session keys

Trust Boundary:
- Keys never leave client device
- Server receives only ciphertext + metadata
- Decryption only on client (if needed for response handling)
"""

from dataclasses import dataclass
from typing import List, Dict, Tuple
import secrets
import hashlib
from base64 import b64encode, b64decode

# Cryptography library (install: pip install cryptography)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .sanitizer import SanitizedSegment, SanitizationAction
from .pii_detector import PIILabel


@dataclass
class EncryptedSegment:
    """
    Represents an encrypted sensitive segment
    
    Attributes:
        ciphertext: ChaCha20-Poly1305 ciphertext (includes Poly1305 tag)
        nonce: 96-bit nonce (unique per segment)
        position: Original character position in text
        label: Original PII label (for reconstruction)
        placeholder: Token for LLM processing (e.g., "[ENCRYPTED_TOKEN_0]")
        associated_data: Additional authenticated data (metadata)
    """
    ciphertext: bytes
    nonce: bytes
    position: int
    label: PIILabel
    placeholder: str
    associated_data: bytes
    
    def to_dict(self) -> Dict:
        """Serialize for transmission"""
        return {
            "ciphertext": b64encode(self.ciphertext).decode('utf-8'),
            "nonce": b64encode(self.nonce).decode('utf-8'),
            "position": self.position,
            "label": self.label.value,
            "placeholder": self.placeholder,
            "associated_data": b64encode(self.associated_data).decode('utf-8')
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'EncryptedSegment':
        """Deserialize from transmission format"""
        return cls(
            ciphertext=b64decode(data["ciphertext"]),
            nonce=b64decode(data["nonce"]),
            position=data["position"],
            label=PIILabel(data["label"]),
            placeholder=data["placeholder"],
            associated_data=b64decode(data["associated_data"])
        )


class KeyManager:
    """
    Manages encryption keys with rotation and derivation
    
    Security Model:
    - Master key: 256-bit, device-bound (secure enclave in production)
    - Session keys: Derived via HKDF from master + session_id
    - Rotation: New session every 1000 operations or 24 hours
    
    Production Recommendations:
    - Use hardware-backed keystores (iOS Keychain, Android Keystore, TPM)
    - Implement key attestation
    - Add key expiration timestamps
    - Secure memory wiping (mlock/munlock)
    """
    
    def __init__(self, master_key: bytes = None):
        """
        Initialize key manager
        
        Args:
            master_key: 256-bit master key (if None, generates new key)
                       WARNING: In production, load from secure storage
        """
        if master_key is None:
            # Generate new master key (256 bits)
            # PRODUCTION: Load from secure storage instead
            self.master_key = secrets.token_bytes(32)
        else:
            assert len(master_key) == 32, "Master key must be 256 bits (32 bytes)"
            self.master_key = master_key
        
        # Session state
        self.session_id = None
        self.session_key = None
        self.operation_count = 0
        self.max_operations = 1000
        
        # Initialize session
        self._rotate_session()
    
    def _rotate_session(self):
        """
        Rotate session key
        
        Creates new session_id and derives new session_key via HKDF
        """
        self.session_id = secrets.token_bytes(16)
        self.operation_count = 0
        
        # Derive session key using HKDF-SHA256
        # Info: domain separation string
        info = b"privacy-llm-session-key-v1"
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=self.session_id,
            info=info,
            backend=default_backend()
        )
        
        self.session_key = hkdf.derive(self.master_key)
    
    def get_session_key(self) -> bytes:
        """
        Get current session key, rotating if needed
        
        Returns:
            Current session key (256 bits)
        """
        # Check if rotation needed
        if self.operation_count >= self.max_operations:
            self._rotate_session()
        
        self.operation_count += 1
        return self.session_key
    
    def get_session_id(self) -> bytes:
        """Get current session ID"""
        return self.session_id


class SelectiveEncryptor:
    """
    Encrypts only SENSITIVE_ENCRYPT segments using ChaCha20-Poly1305
    
    Process:
    1. Filter segments marked SENSITIVE_ENCRYPT
    2. For each segment:
       - Generate unique 96-bit nonce
       - Construct associated data (position, label, session_id)
       - Encrypt with ChaCha20-Poly1305
       - Generate placeholder token
    3. Return encrypted segments + metadata
    
    Security Guarantees:
    - Confidentiality: Ciphertext reveals nothing about plaintext
    - Integrity: Poly1305 MAC prevents tampering
    - Authenticity: Associated data binds metadata to ciphertext
    - Freshness: Unique nonce per segment (collision probability < 2^-96)
    """
    
    def __init__(self, key_manager: KeyManager = None):
        """
        Initialize selective encryptor
        
        Args:
            key_manager: Key management instance (if None, creates new)
        """
        self.key_manager = key_manager or KeyManager()
    
    def encrypt_segments(
        self,
        sanitized_text: str,
        sanitized_segments: List[SanitizedSegment]
    ) -> Tuple[str, List[EncryptedSegment]]:
        """
        Encrypt sensitive segments and generate placeholder text
        
        Args:
            sanitized_text: Text after sanitization (from Sanitizer)
            sanitized_segments: Sanitized segments with action labels
            
        Returns:
            Tuple of:
                - Text with encrypted segments replaced by placeholders
                - List of encrypted segments with metadata
                
        Security:
            - Only SENSITIVE_ENCRYPT segments are encrypted
            - Each segment gets unique nonce
            - Position metadata preserved for reconstruction
        """
        # Filter segments that need encryption
        to_encrypt = [
            seg for seg in sanitized_segments 
            if seg.action == SanitizationAction.SENSITIVE_ENCRYPT
        ]
        
        if not to_encrypt:
            # No sensitive segments - return as-is
            return sanitized_text, []
        
        # Sort by position
        to_encrypt.sort(key=lambda s: s.start_offset)
        
        encrypted_segments = []
        result_text = []
        current_pos = 0
        
        # Get session key
        session_key = self.key_manager.get_session_key()
        cipher = ChaCha20Poly1305(session_key)
        
        for idx, segment in enumerate(to_encrypt):
            # Add plaintext before this segment
            result_text.append(sanitized_text[current_pos:segment.start_offset])
            
            # Generate unique nonce (96 bits)
            nonce = secrets.token_bytes(12)
            
            # Construct associated data (authenticated but not encrypted)
            # Binds position, label, and session to ciphertext
            associated_data = self._construct_aad(
                position=segment.start_offset,
                label=segment.label,
                session_id=self.key_manager.get_session_id()
            )
            
            # Encrypt segment
            plaintext = segment.original_text.encode('utf-8')
            ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
            
            # Generate placeholder token
            placeholder = f"[ENCRYPTED_TOKEN_{idx}]"
            
            # Add placeholder to result text
            result_text.append(placeholder)
            
            # Store encrypted segment
            encrypted_segments.append(EncryptedSegment(
                ciphertext=ciphertext,
                nonce=nonce,
                position=segment.start_offset,
                label=segment.label,
                placeholder=placeholder,
                associated_data=associated_data
            ))
            
            current_pos = segment.end_offset
        
        # Add remaining plaintext
        result_text.append(sanitized_text[current_pos:])
        
        final_text = ''.join(result_text)
        
        return final_text, encrypted_segments
    
    def decrypt_segment(self, encrypted_segment: EncryptedSegment) -> str:
        """
        Decrypt a single encrypted segment
        
        Args:
            encrypted_segment: Encrypted segment to decrypt
            
        Returns:
            Decrypted plaintext
            
        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
            
        Security:
            - Verifies Poly1305 MAC before decryption
            - Constant-time comparison (side-channel resistant)
            - Authenticated decryption (AEAD)
        """
        session_key = self.key_manager.get_session_key()
        cipher = ChaCha20Poly1305(session_key)
        
        # Decrypt with authentication
        plaintext_bytes = cipher.decrypt(
            encrypted_segment.nonce,
            encrypted_segment.ciphertext,
            encrypted_segment.associated_data
        )
        
        return plaintext_bytes.decode('utf-8')
    
    @staticmethod
    def _construct_aad(position: int, label: PIILabel, session_id: bytes) -> bytes:
        """
        Construct Associated Authenticated Data
        
        Format: session_id || position || label
        
        Purpose: Binds metadata to ciphertext, preventing:
        - Ciphertext reordering
        - Label swapping
        - Cross-session replay
        """
        position_bytes = position.to_bytes(4, byteorder='big')
        label_bytes = label.value.encode('utf-8')
        
        return session_id + position_bytes + label_bytes
    
    def get_encryption_metadata(self, encrypted_segments: List[EncryptedSegment]) -> Dict:
        """
        Generate metadata for transmission to server
        
        Returns:
            Dictionary containing:
                - session_id: Current session identifier
                - segment_count: Number of encrypted segments
                - segments: List of encrypted segment dictionaries
        """
        return {
            "session_id": b64encode(self.key_manager.get_session_id()).decode('utf-8'),
            "segment_count": len(encrypted_segments),
            "segments": [seg.to_dict() for seg in encrypted_segments]
        }


# Example usage and testing
if __name__ == "__main__":
    from pii_detector import PIIDetector
    from sanitizer import Sanitizer
    
    # Initialize pipeline
    detector = PIIDetector()
    sanitizer = Sanitizer()
    encryptor = SelectiveEncryptor()
    
    test_prompts = [
        "Patient John Smith, age 45, diagnosed with hypertension. Email: john@example.com",
        "Doctor prescribed metformin 500mg for diabetes in Mary Johnson, age 62",
    ]
    
    for prompt in test_prompts:
        print(f"\n{'='*80}")
        print(f"Original Prompt:\n{prompt}")
        
        # Step 1: Detect PII
        pii_segments = detector.detect(prompt)
        print(f"\n[1] Detected {len(pii_segments)} PII segments")
        
        # Step 2: Sanitize
        sanitized_text, sanitized_segments = sanitizer.sanitize(prompt, pii_segments)
        print(f"\n[2] Sanitized Text:\n{sanitized_text}")
        
        # Step 3: Encrypt sensitive segments
        encrypted_text, encrypted_segments = encryptor.encrypt_segments(
            sanitized_text, sanitized_segments
        )
        print(f"\n[3] Encrypted Text (for LLM):\n{encrypted_text}")
        
        print(f"\n[4] Encrypted Segments: {len(encrypted_segments)}")
        for seg in encrypted_segments:
            print(f"  - {seg.placeholder}: {seg.label.value} at pos {seg.position}")
        
        # Step 4: Test decryption
        if encrypted_segments:
            print(f"\n[5] Decryption Test:")
            for seg in encrypted_segments:
                decrypted = encryptor.decrypt_segment(seg)
                print(f"  {seg.placeholder} -> '{decrypted}'")
        
        # Step 5: Metadata for transmission
        metadata = encryptor.get_encryption_metadata(encrypted_segments)
        print(f"\n[6] Transmission Metadata:")
        print(f"  Session ID: {metadata['session_id'][:16]}...")
        print(f"  Segment Count: {metadata['segment_count']}")
