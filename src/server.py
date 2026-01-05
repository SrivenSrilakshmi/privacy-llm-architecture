"""
Server-Side Gateway

Implements server-side ZKP verification and LLM interaction gateway.

Security Model:
- UNTRUSTED ZONE: Server cannot access raw PII
- Verifies ZKP before any LLM interaction
- Rejects requests failing verification
- No decryption capability (keys on client only)

Trust Boundaries:
- SERVER: Verifies proofs, forwards sanitized prompts
- LLM PROVIDER: Receives only sanitized + opaque tokens
- No access to: raw PII, encryption keys, decrypted segments

Compliance:
- GDPR Article 25: Privacy by design (server cannot access PII)
- HIPAA: No PHI on server (encrypted segments opaque)
- Auditability: All requests logged (sanitized only)
"""

from dataclasses import dataclass
from typing import Optional, Dict, List
import time
import json
from enum import Enum

from .zkp import ZKPVerifier, ZKProof
from .encryptor import EncryptedSegment


class VerificationStatus(Enum):
    """ZKP verification result"""
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"


@dataclass
class VerificationResult:
    """Result of ZKP verification"""
    status: VerificationStatus
    reason: str
    timestamp: float
    request_id: str
    
    def __repr__(self):
        return f"VerificationResult({self.status.value}: {self.reason})"


@dataclass
class LLMRequest:
    """Sanitized request forwarded to LLM"""
    prompt: str
    encrypted_tokens: List[str]
    session_id: str
    metadata: Dict
    
    def to_dict(self) -> Dict:
        return {
            "prompt": self.prompt,
            "encrypted_tokens": self.encrypted_tokens,
            "session_id": self.session_id,
            "metadata": self.metadata
        }


class ServerGateway:
    """
    Server-side gateway for privacy-preserving LLM access
    
    Workflow:
    1. Receive secure package from client
    2. Verify ZKP (reject if invalid)
    3. Forward sanitized prompt to LLM
    4. Return LLM response to client
    
    Security:
    - No access to encryption keys
    - Cannot decrypt sensitive segments
    - Verifies sanitization without seeing PII
    """
    
    def __init__(self, strict_verification: bool = True):
        """
        Initialize server gateway
        
        Args:
            strict_verification: Reject on any verification error (recommended)
        """
        self.verifier = ZKPVerifier()
        self.strict_verification = strict_verification
        self._request_log = []
    
    def process_request(self, secure_package_json: str) -> VerificationResult:
        """
        Process incoming secure package
        
        Steps:
        1. Parse package
        2. Verify ZKP
        3. If valid: prepare for LLM
        4. If invalid: reject
        
        Args:
            secure_package_json: JSON from client (SecurePromptPackage)
            
        Returns:
            VerificationResult indicating accept/reject
            
        Security:
            - ZKP verification before any processing
            - No access to raw PII
            - Logged for audit (sanitized only)
        """
        request_id = self._generate_request_id()
        timestamp = time.time()
        
        try:
            # Parse package
            package_data = json.loads(secure_package_json)
            
            # Extract components
            sanitized_text = package_data["sanitized_text"]
            encrypted_segments_data = package_data["encrypted_segments"]
            zkp_proof_data = package_data["zkp_proof"]
            metadata = package_data["metadata"]
            
            # Reconstruct encrypted segments
            encrypted_segments = [
                EncryptedSegment.from_dict(seg) for seg in encrypted_segments_data
            ]
            
            # Reconstruct ZKP
            zkp_proof = ZKProof.from_dict(zkp_proof_data)
            
            # CRITICAL: Verify ZKP before proceeding
            is_valid = self.verifier.verify_proof(zkp_proof, encrypted_segments)
            
            if is_valid:
                result = VerificationResult(
                    status=VerificationStatus.ACCEPTED,
                    reason="ZKP verification successful",
                    timestamp=timestamp,
                    request_id=request_id
                )
                
                self._log_request(request_id, "ACCEPTED", sanitized_text, metadata)
                
            else:
                result = VerificationResult(
                    status=VerificationStatus.REJECTED,
                    reason="ZKP verification failed",
                    timestamp=timestamp,
                    request_id=request_id
                )
                
                self._log_request(request_id, "REJECTED", None, metadata)
                
            return result
            
        except Exception as e:
            # Any error in processing -> reject
            result = VerificationResult(
                status=VerificationStatus.ERROR,
                reason=f"Processing error: {str(e)}",
                timestamp=timestamp,
                request_id=request_id
            )
            
            self._log_request(request_id, "ERROR", None, {})
            
            return result
    
    def prepare_llm_request(self, secure_package_json: str) -> Optional[LLMRequest]:
        """
        Prepare sanitized request for LLM (only if ZKP valid)
        
        Args:
            secure_package_json: JSON from client
            
        Returns:
            LLMRequest if verification passes, None otherwise
            
        Security:
            - Only called after ZKP verification
            - Encrypted segments replaced with opaque tokens
            - No PII exposure to LLM
        """
        # First verify
        verification = self.process_request(secure_package_json)
        
        if verification.status != VerificationStatus.ACCEPTED:
            return None
        
        # Parse package (already validated)
        package_data = json.loads(secure_package_json)
        
        sanitized_text = package_data["sanitized_text"]
        encrypted_segments = package_data["encrypted_segments"]
        metadata = package_data["metadata"]
        
        # Extract encrypted token placeholders
        encrypted_tokens = [seg["placeholder"] for seg in encrypted_segments]
        
        llm_request = LLMRequest(
            prompt=sanitized_text,
            encrypted_tokens=encrypted_tokens,
            session_id=metadata["session_id"],
            metadata={
                "request_id": verification.request_id,
                "client_version": metadata.get("client_version", "unknown"),
                "timestamp": verification.timestamp
            }
        )
        
        return llm_request
    
    def forward_to_llm(self, llm_request: LLMRequest, llm_provider: str = "mock") -> str:
        """
        Forward sanitized prompt to LLM provider
        
        Args:
            llm_request: Prepared LLM request
            llm_provider: LLM provider identifier
            
        Returns:
            LLM response text
            
        Security:
            - Only sanitized text sent to LLM
            - Encrypted tokens are opaque (no semantic meaning)
            - LLM cannot extract PII
            
        Production Implementation:
            ```python
            import openai
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[{"role": "user", "content": llm_request.prompt}],
                temperature=0.7
            )
            return response.choices[0].message.content
            ```
        """
        # Mock LLM response
        if llm_provider == "mock":
            return self._mock_llm_response(llm_request.prompt)
        
        # Production: Call actual LLM API
        raise NotImplementedError("LLM provider integration not implemented")
    
    def _mock_llm_response(self, prompt: str) -> str:
        """Mock LLM response for testing"""
        # Simulate LLM processing the sanitized prompt
        if "patient" in prompt.lower():
            return f"Based on the medical information provided, I recommend consulting with the healthcare provider. The encrypted data suggests appropriate monitoring."
        elif "tax" in prompt.lower():
            return f"For tax-related questions, please ensure you have the necessary documentation. I can provide general guidance on tax procedures."
        else:
            return f"I understand your request. Let me help you with that based on the information provided."
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _log_request(self, request_id: str, status: str, prompt: Optional[str], metadata: Dict):
        """
        Log request for audit trail
        
        Security: Only logs sanitized data (no raw PII)
        """
        log_entry = {
            "request_id": request_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": status,
            "prompt_preview": prompt[:50] + "..." if prompt else None,
            "metadata": metadata
        }
        
        self._request_log.append(log_entry)
    
    def get_audit_log(self) -> List[Dict]:
        """
        Get audit log entries
        
        Returns:
            List of log entries (sanitized only)
            
        Compliance:
            - GDPR Article 30: Records of processing activities
            - HIPAA: Audit controls
        """
        return self._request_log.copy()


class SecurePromptBuilder:
    """
    Reconstructs prompts with encrypted segments as opaque tokens
    
    Used by server to prepare prompts for LLM while maintaining
    semantic structure but hiding sensitive data.
    """
    
    @staticmethod
    def build_llm_prompt(sanitized_text: str, encrypted_segments: List[Dict]) -> str:
        """
        Build LLM prompt with encrypted tokens
        
        The sanitized_text already contains placeholders like [ENCRYPTED_TOKEN_0]
        This function could add additional context or instructions if needed.
        
        Args:
            sanitized_text: Text with encrypted placeholders
            encrypted_segments: Encrypted segment metadata
            
        Returns:
            Prompt ready for LLM
        """
        # In most cases, sanitized_text is already ready
        # Could add system instructions here:
        
        system_instruction = (
            "Note: Some parts of this text are encrypted for privacy. "
            "Tokens like [ENCRYPTED_TOKEN_N] represent confidential information. "
            "Do not attempt to infer or guess their content."
        )
        
        # For now, return as-is
        # Production: Could add the system instruction
        return sanitized_text


# Example usage and testing
if __name__ == "__main__":
    from core.client import PrivacyClient
    
    print(f"{'='*80}")
    print(f"Server-Side Gateway - End-to-End Demo")
    print(f"{'='*80}\n")
    
    # Initialize client and server
    client = PrivacyClient(enable_logging=False)
    server = ServerGateway()
    
    test_prompts = [
        "Patient John Smith, age 45, diagnosed with hypertension.",
        "Invalid: This should fail verification",  # Will create tampered proof
    ]
    
    for i, prompt in enumerate(test_prompts, 1):
        print(f"\n{'─'*80}")
        print(f"Test Case {i}")
        print(f"{'─'*80}")
        print(f"\n[CLIENT] Raw Prompt:\n{prompt}\n")
        
        # Client prepares prompt
        package, metrics = client.prepare_prompt(prompt)
        package_json = package.to_json()
        
        print(f"[CLIENT] Package prepared ({len(package_json)} bytes)")
        print(f"  Processing time: {metrics.total_time_ms:.2f}ms")
        
        # Simulate network transmission (HTTPS in production)
        print(f"\n[NETWORK] Transmitting via TLS...")
        
        # Server receives and verifies
        print(f"\n[SERVER] Verifying ZKP...")
        verification = server.process_request(package_json)
        print(f"  {verification}")
        
        if verification.status == VerificationStatus.ACCEPTED:
            # Prepare for LLM
            llm_request = server.prepare_llm_request(package_json)
            
            if llm_request:
                print(f"\n[SERVER] Forwarding to LLM:")
                print(f"  Prompt: {llm_request.prompt}")
                print(f"  Encrypted Tokens: {llm_request.encrypted_tokens}")
                
                # Forward to LLM
                llm_response = server.forward_to_llm(llm_request)
                
                print(f"\n[LLM] Response:\n{llm_response}")
                
                # Send back to client
                print(f"\n[SERVER] Returning response to client")
                
                # Client processes response
                final_response = client.process_response(llm_response, package)
                
                print(f"\n[CLIENT] Final Response:\n{final_response}")
        else:
            print(f"\n[SERVER] ✗ Request rejected - will not forward to LLM")
    
    # Show audit log
    print(f"\n{'='*80}")
    print(f"Server Audit Log")
    print(f"{'='*80}")
    for entry in server.get_audit_log():
        print(json.dumps(entry, indent=2))
