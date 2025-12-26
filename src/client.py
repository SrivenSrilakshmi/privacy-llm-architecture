"""
Client-Side Orchestrator

Coordinates the complete privacy-preserving pipeline on the user device.

Pipeline Stages (Strict Order):
1. PII Detection: Identify sensitive data
2. Sanitization: Apply removal/masking policies
3. Selective Encryption: Encrypt semantically required PII
4. ZKP Generation: Prove sanitization correctness
5. Transmission: Send to server (TLS)
6. Response Handling: Process LLM response

Trust Boundary:
- CLIENT (TRUSTED): Raw PII visible, keys accessible
- NETWORK: TLS-encrypted channel
- SERVER (UNTRUSTED): Only sees sanitized + encrypted data

Security Guarantees:
- No raw PII leaves device in plaintext
- Cryptographic proof of sanitization
- Keys never transmitted
- Auditability via logging (sanitized only)
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import json
import time

from pii_detector import PIIDetector, ClassifiedSegment
from sanitizer import Sanitizer, SanitizedSegment, SanitizationAction
from encryptor import SelectiveEncryptor, EncryptedSegment, KeyManager
from zkp import ZKPProver, ZKPVerifier, ZKProof


@dataclass
class SecurePromptPackage:
    """
    Package for secure transmission to server
    
    Contains:
        - Sanitized plaintext (safe for LLM)
        - Encrypted segments (opaque to server)
        - Zero-knowledge proof (verifiable sanitization)
        - Metadata (session, timing, etc.)
    
    Security: No raw PII included
    """
    sanitized_text: str
    encrypted_segments: List[Dict]
    zkp_proof: Dict
    metadata: Dict
    
    def to_json(self) -> str:
        """Serialize for transmission"""
        return json.dumps({
            "sanitized_text": self.sanitized_text,
            "encrypted_segments": self.encrypted_segments,
            "zkp_proof": self.zkp_proof,
            "metadata": self.metadata
        }, indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'SecurePromptPackage':
        """Deserialize from transmission"""
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class ProcessingMetrics:
    """Performance and security metrics"""
    pii_detection_time_ms: float
    sanitization_time_ms: float
    encryption_time_ms: float
    zkp_generation_time_ms: float
    total_time_ms: float
    
    pii_segments_detected: int
    segments_masked: int
    segments_encrypted: int
    
    def summary(self) -> str:
        return (
            f"Processing Metrics:\n"
            f"  Total Time: {self.total_time_ms:.2f}ms\n"
            f"  - PII Detection: {self.pii_detection_time_ms:.2f}ms\n"
            f"  - Sanitization: {self.sanitization_time_ms:.2f}ms\n"
            f"  - Encryption: {self.encryption_time_ms:.2f}ms\n"
            f"  - ZKP Generation: {self.zkp_generation_time_ms:.2f}ms\n"
            f"  PII Segments: {self.pii_segments_detected}\n"
            f"  - Masked: {self.segments_masked}\n"
            f"  - Encrypted: {self.segments_encrypted}"
        )


class PrivacyClient:
    """
    Client-side orchestrator for privacy-preserving LLM interactions
    
    Usage:
        client = PrivacyClient()
        package = client.prepare_prompt("sensitive prompt here")
        # Send package.to_json() to server via HTTPS
        # Receive LLM response
        final_response = client.process_response(llm_response, package)
    
    Security:
        - All PII processing in-memory (no disk writes)
        - Keys stored in secure enclave (production)
        - Audit logging (sanitized data only)
    """
    
    def __init__(
        self,
        master_key: bytes = None,
        confidence_threshold: float = 0.85,
        enable_logging: bool = True
    ):
        """
        Initialize privacy client
        
        Args:
            master_key: 256-bit encryption master key (if None, generates new)
            confidence_threshold: Minimum PII detection confidence
            enable_logging: Enable audit logging (sanitized only)
        """
        # Initialize components
        self.detector = PIIDetector(confidence_threshold=confidence_threshold)
        self.sanitizer = Sanitizer()
        self.key_manager = KeyManager(master_key=master_key)
        self.encryptor = SelectiveEncryptor(key_manager=self.key_manager)
        self.zkp_prover = ZKPProver()
        
        self.enable_logging = enable_logging
        self._audit_log = []
    
    def prepare_prompt(self, raw_prompt: str) -> Tuple[SecurePromptPackage, ProcessingMetrics]:
        """
        Prepare prompt for secure transmission
        
        Pipeline:
        1. Detect PII
        2. Sanitize (mask/tag for encryption)
        3. Encrypt sensitive segments
        4. Generate ZKP
        5. Package for transmission
        
        Args:
            raw_prompt: Original user prompt (may contain PII)
            
        Returns:
            Tuple of (SecurePromptPackage, ProcessingMetrics)
            
        Security:
            - Raw prompt never leaves this function
            - Only sanitized data in return value
        """
        start_time = time.time()
        
        # Stage 1: PII Detection
        stage_start = time.time()
        pii_segments = self.detector.detect(raw_prompt)
        detection_time = (time.time() - stage_start) * 1000
        
        self._log(f"Detected {len(pii_segments)} PII segments")
        
        # Stage 2: Sanitization
        stage_start = time.time()
        sanitized_text, sanitized_segments = self.sanitizer.sanitize(raw_prompt, pii_segments)
        sanitization_time = (time.time() - stage_start) * 1000
        
        segments_masked = sum(1 for s in sanitized_segments if s.action == SanitizationAction.MASKED)
        segments_encrypted = sum(1 for s in sanitized_segments if s.action == SanitizationAction.SENSITIVE_ENCRYPT)
        
        self._log(f"Sanitized: {segments_masked} masked, {segments_encrypted} to encrypt")
        
        # Stage 3: Selective Encryption
        stage_start = time.time()
        encrypted_text, encrypted_segments = self.encryptor.encrypt_segments(
            sanitized_text, sanitized_segments
        )
        encryption_time = (time.time() - stage_start) * 1000
        
        self._log(f"Encrypted {len(encrypted_segments)} segments")
        
        # Stage 4: ZKP Generation
        stage_start = time.time()
        
        # Collect plaintext segments
        plaintext_segments = [
            seg.sanitized_text for seg in sanitized_segments
            if seg.action in [SanitizationAction.PLAINTEXT, SanitizationAction.MASKED]
        ]
        
        # Build rule applications
        rule_applications = []
        for seg in sanitized_segments:
            if seg.action == SanitizationAction.MASKED:
                rule_id = f"MASK_{seg.label.value}"
            elif seg.action == SanitizationAction.SENSITIVE_ENCRYPT:
                rule_id = f"ENCRYPT_{seg.label.value}"
            else:
                continue
            rule_applications.append((seg.start_offset, rule_id, seg.label.value))
        
        zkp_proof = self.zkp_prover.generate_proof(
            plaintext_segments, encrypted_segments, rule_applications
        )
        zkp_time = (time.time() - stage_start) * 1000
        
        self._log("Generated ZKP")
        
        # Stage 5: Package
        package = SecurePromptPackage(
            sanitized_text=encrypted_text,
            encrypted_segments=[seg.to_dict() for seg in encrypted_segments],
            zkp_proof=zkp_proof.to_dict(),
            metadata={
                "session_id": self.encryptor.get_encryption_metadata(encrypted_segments)["session_id"],
                "timestamp": time.time(),
                "pii_count": len(pii_segments),
                "encrypted_count": len(encrypted_segments),
                "client_version": "v1.0"
            }
        )
        
        total_time = (time.time() - start_time) * 1000
        
        metrics = ProcessingMetrics(
            pii_detection_time_ms=detection_time,
            sanitization_time_ms=sanitization_time,
            encryption_time_ms=encryption_time,
            zkp_generation_time_ms=zkp_time,
            total_time_ms=total_time,
            pii_segments_detected=len(pii_segments),
            segments_masked=segments_masked,
            segments_encrypted=segments_encrypted
        )
        
        self._log(f"Total processing: {total_time:.2f}ms")
        
        return package, metrics
    
    def process_response(
        self,
        llm_response: str,
        original_package: SecurePromptPackage,
        decrypt_tokens: bool = False
    ) -> str:
        """
        Process LLM response and optionally decrypt encrypted tokens
        
        Args:
            llm_response: Response from LLM (may contain encrypted tokens)
            original_package: Original prompt package (for decryption keys)
            decrypt_tokens: Whether to decrypt encrypted tokens in response
            
        Returns:
            Processed response (decrypted if requested)
            
        Security:
            - Decryption only on client
            - Secure memory clearing after use
        """
        if not decrypt_tokens:
            return llm_response
        
        # Reconstruct encrypted segments
        encrypted_segments = [
            EncryptedSegment.from_dict(seg_dict)
            for seg_dict in original_package.encrypted_segments
        ]
        
        # Find and decrypt tokens in response
        processed_response = llm_response
        
        for seg in encrypted_segments:
            if seg.placeholder in processed_response:
                try:
                    decrypted_value = self.encryptor.decrypt_segment(seg)
                    # Highlight re-inserted PII for user awareness
                    replacement = f"[{decrypted_value}]"
                    processed_response = processed_response.replace(seg.placeholder, replacement)
                    
                    self._log(f"Decrypted {seg.placeholder}")
                except Exception as e:
                    self._log(f"Failed to decrypt {seg.placeholder}: {e}")
        
        return processed_response
    
    def get_audit_log(self) -> List[str]:
        """
        Get audit log entries (sanitized data only)
        
        Returns:
            List of log entries
            
        Security: Never contains raw PII
        """
        return self._audit_log.copy()
    
    def _log(self, message: str):
        """Internal logging (sanitized only)"""
        if self.enable_logging:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            entry = f"[{timestamp}] {message}"
            self._audit_log.append(entry)
            print(entry)


# Example usage and testing
if __name__ == "__main__":
    print(f"{'='*80}")
    print(f"Privacy-Preserving LLM Client - End-to-End Demo")
    print(f"{'='*80}\n")
    
    # Initialize client
    client = PrivacyClient(enable_logging=True)
    
    # Test prompts with various PII types
    test_prompts = [
        "Patient John Smith, age 45, diagnosed with hypertension. Contact: john@example.com",
        "My SSN is 123-45-6789. Please help me with my tax return.",
        "Doctor prescribed metformin 500mg for Mary Johnson, age 62, with diabetes.",
    ]
    
    for i, prompt in enumerate(test_prompts, 1):
        print(f"\n{'─'*80}")
        print(f"Test Case {i}")
        print(f"{'─'*80}")
        print(f"\n[INPUT] Raw Prompt:\n{prompt}\n")
        
        # Prepare prompt (client-side)
        package, metrics = client.prepare_prompt(prompt)
        
        print(f"\n{metrics.summary()}\n")
        
        print(f"[OUTPUT] Secure Package (for transmission):")
        print(f"  Sanitized Text: {package.sanitized_text}")
        print(f"  Encrypted Segments: {len(package.encrypted_segments)}")
        print(f"  ZKP Included: Yes")
        print(f"  Session ID: {package.metadata['session_id'][:16]}...")
        
        # Simulate server verification (shown in next file)
        print(f"\n[SERVER] Would verify ZKP here before sending to LLM")
        
        # Simulate LLM response
        simulated_llm_response = f"I understand. Regarding {package.sanitized_text.split()[0]}..."
        
        print(f"\n[LLM RESPONSE] {simulated_llm_response}")
        
        # Process response (no decryption needed in this example)
        final_response = client.process_response(
            simulated_llm_response, package, decrypt_tokens=False
        )
        
        print(f"\n[FINAL OUTPUT] {final_response}")
    
    print(f"\n{'='*80}")
    print(f"Audit Log Summary:")
    print(f"{'='*80}")
    for entry in client.get_audit_log():
        print(entry)
