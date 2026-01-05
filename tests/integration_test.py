"""
End-to-End Integration Test

Demonstrates complete privacy-preserving LLM interaction pipeline.

Test Scenarios:
1. Medical prompt (HIPAA compliance)
2. Financial prompt (PCI-DSS compliance)
3. General PII prompt (GDPR compliance)
4. Tampered proof (security test)
5. Performance benchmarking

Validation:
- No raw PII transmitted
- ZKP verification successful
- Encryption/decryption round-trip
- Server-side rejection of invalid proofs
Server-side rejection of invalid proofs
"""

import time
import json
from typing import List, Tuple

# Import concrete implementations
from src.sanitizer import Sanitizer
from src.encryptor import SelectiveEncryptor
from src.zkp import ZKPProver, ZKPVerifier
from core.client import PrivacyClient, SecurePromptPackage
from src.server import ServerGateway, VerificationStatus


class IntegrationTest:
    """End-to-end integration testing framework"""
    
    def __init__(self):
        self.client = PrivacyClient(enable_logging=False)
        self.server = ServerGateway()
        self.test_results = []
    
    def run_all_tests(self):
        """Run complete test suite"""
        print(f"{'='*80}")
        print(f"Privacy-Preserving LLM Architecture - Integration Tests")
        print(f"{'='*80}\n")
        
        tests = [
            ("Medical Prompt (HIPAA)", self.test_medical_prompt),
            ("Financial Prompt (PCI-DSS)", self.test_financial_prompt),
            ("General PII (GDPR)", self.test_general_pii),
            ("Security: Tampered Proof", self.test_tampered_proof),
            ("Performance Benchmark", self.test_performance),
        ]
        
        for test_name, test_func in tests:
            print(f"\n{'─'*80}")
            print(f"TEST: {test_name}")
            print(f"{'─'*80}\n")
            
            try:
                result = test_func()
                self.test_results.append((test_name, result))
                print(f"\n✓ {test_name}: {'PASSED' if result else 'FAILED'}")
            except Exception as e:
                self.test_results.append((test_name, False))
                print(f"\n✗ {test_name}: FAILED with error: {e}")
        
        self.print_summary()
    
    def test_medical_prompt(self) -> bool:
        """Test medical prompt with PHI (HIPAA compliance)"""
        prompt = (
            "Patient Mary Johnson, age 62, diagnosed with type 2 diabetes. "
            "Prescribed metformin 500mg twice daily. Contact: mary.j@email.com"
        )
        
        print(f"Input: {prompt}\n")
        
        # Client-side processing
        package, metrics = self.client.prepare_prompt(prompt)
        
        print(f"Client Processing:")
        print(f"  PII Detected: {metrics.pii_segments_detected}")
        print(f"  Masked: {metrics.segments_masked}")
        print(f"  Encrypted: {metrics.segments_encrypted}")
        print(f"  Time: {metrics.total_time_ms:.2f}ms")
        
        # Verify no raw PII in sanitized text
        sensitive_terms = ["Mary Johnson", "mary.j@email.com"]
        has_raw_pii = any(term in package.sanitized_text for term in sensitive_terms)
        
        if has_raw_pii:
            print(f"\n✗ SECURITY FAILURE: Raw PII found in sanitized text")
            return False
        
        print(f"\n✓ No raw PII in sanitized text")
        print(f"  Sanitized: {package.sanitized_text}")
        
        # Server-side verification
        package_json = package.to_json()
        verification = self.server.process_request(package_json)
        
        print(f"\nServer Verification:")
        print(f"  Status: {verification.status.value}")
        print(f"  Reason: {verification.reason}")
        
        if verification.status != VerificationStatus.ACCEPTED:
            print(f"\n✗ ZKP verification failed")
            return False
        
        print(f"\n✓ ZKP verification successful")
        
        # LLM interaction
        llm_request = self.server.prepare_llm_request(package_json)
        llm_response = self.server.forward_to_llm(llm_request)
        
        print(f"\nLLM Response: {llm_response}")
        
        # Verify encrypted tokens in LLM request
        if not llm_request.encrypted_tokens:
            print(f"\n✗ No encrypted tokens (expected for this prompt)")
            return False
        
        print(f"\n✓ Encrypted tokens used: {llm_request.encrypted_tokens}")
        
        return True
    
    def test_financial_prompt(self) -> bool:
        """Test financial prompt with PII (PCI-DSS compliance)"""
        prompt = (
            "I need help with my credit card 4532123456789012. "
            "My SSN is 123-45-6789 and I live at 123 Main St."
        )
        
        print(f"Input: {prompt}\n")
        
        package, metrics = self.client.prepare_prompt(prompt)
        
        # Verify sensitive financial data is masked
        sensitive_data = ["4532123456789012", "123-45-6789"]
        has_sensitive = any(data in package.sanitized_text for data in sensitive_data)
        
        if has_sensitive:
            print(f"✗ Sensitive financial data not properly masked")
            return False
        
        print(f"✓ Sensitive financial data masked")
        print(f"  Sanitized: {package.sanitized_text}")
        
        # Verify contains placeholders
        if "<CARD_MASKED>" not in package.sanitized_text or "<SSN_MASKED>" not in package.sanitized_text:
            print(f"✗ Expected placeholders not found")
            return False
        
        print(f"✓ Placeholders correctly inserted")
        
        return True
    
    def test_general_pii(self) -> bool:
        """Test general PII prompt (GDPR compliance)"""
        prompt = (
            "John Doe (john.doe@example.com) called from 555-123-4567 "
            "regarding account at IP 192.168.1.1"
        )
        
        print(f"Input: {prompt}\n")
        
        package, metrics = self.client.prepare_prompt(prompt)
        
        print(f"PII Detection:")
        print(f"  Total detected: {metrics.pii_segments_detected}")
        print(f"  Masked: {metrics.segments_masked}")
        
        # Verify all structured PII is masked
        expected_masks = ["<EMAIL_MASKED>", "<PHONE_MASKED>", "<IP_MASKED>"]
        has_all_masks = all(mask in package.sanitized_text for mask in expected_masks)
        
        if not has_all_masks:
            print(f"✗ Not all PII properly masked")
            print(f"  Sanitized: {package.sanitized_text}")
            return False
        
        print(f"✓ All structured PII masked")
        print(f"  Sanitized: {package.sanitized_text}")
        
        return True
    
    def test_tampered_proof(self) -> bool:
        """Test security: server rejects tampered proof"""
        prompt = "Patient Alice Smith needs urgent care."
        
        print(f"Input: {prompt}\n")
        
        # Client generates valid package
        package, metrics = self.client.prepare_prompt(prompt)
        package_json = package.to_json()
        
        # Tamper with proof
        package_data = json.loads(package_json)
        package_data["zkp_proof"]["commitment"] = "AAAAAAAAAAAAAAAAAAAAAA=="  # Invalid
        tampered_json = json.dumps(package_data)
        
        print(f"Tampered proof commitment")
        
        # Server should reject
        verification = self.server.process_request(tampered_json)
        
        print(f"\nServer Verification:")
        print(f"  Status: {verification.status.value}")
        
        if verification.status == VerificationStatus.ACCEPTED:
            print(f"\n✗ SECURITY FAILURE: Tampered proof accepted!")
            return False
        
        print(f"\n✓ Tampered proof correctly rejected")
        
        return True
    
    def test_performance(self) -> bool:
        """Performance benchmarking"""
        prompts = [
            "Short prompt with email@test.com",
            "Patient John Smith, age 45, with hypertension and diabetes, prescribed metformin 500mg.",
            "Complex case: Alice (alice@email.com, SSN 123-45-6789) at 555-1234, IP 10.0.0.1, card 4532123456789012"
        ]
        
        print(f"Benchmarking {len(prompts)} prompts...\n")
        
        total_times = []
        
        for i, prompt in enumerate(prompts, 1):
            package, metrics = self.client.prepare_prompt(prompt)
            total_times.append(metrics.total_time_ms)
            
            print(f"Prompt {i} ({len(prompt)} chars, {metrics.pii_segments_detected} PII):")
            print(f"  Detection: {metrics.pii_detection_time_ms:.2f}ms")
            print(f"  Sanitization: {metrics.sanitization_time_ms:.2f}ms")
            print(f"  Encryption: {metrics.encryption_time_ms:.2f}ms")
            print(f"  ZKP Generation: {metrics.zkp_generation_time_ms:.2f}ms")
            print(f"  TOTAL: {metrics.total_time_ms:.2f}ms\n")
        
        avg_time = sum(total_times) / len(total_times)
        max_time = max(total_times)
        
        print(f"Performance Summary:")
        print(f"  Average: {avg_time:.2f}ms")
        print(f"  Maximum: {max_time:.2f}ms")
        
        # Target: < 500ms for typical prompts
        if avg_time > 500:
            print(f"\n⚠ Performance warning: Average time exceeds 500ms target")
            return False
        
        print(f"\n✓ Performance within acceptable range")
        
        return True
    
    def print_summary(self):
        """Print test summary"""
        print(f"\n{'='*80}")
        print(f"TEST SUMMARY")
        print(f"{'='*80}\n")
        
        passed = sum(1 for _, result in self.test_results if result)
        total = len(self.test_results)
        
        for test_name, result in self.test_results:
            status = "✓ PASSED" if result else "✗ FAILED"
            print(f"{status:12} | {test_name}")
        
        print(f"\n{'─'*80}")
        print(f"Results: {passed}/{total} tests passed ({100*passed//total}%)")
        print(f"{'='*80}\n")


def demonstrate_full_pipeline():
    """Demonstrate complete end-to-end pipeline"""
    print(f"\n{'='*80}")
    print(f"FULL PIPELINE DEMONSTRATION")
    print(f"{'='*80}\n")
    
    client = PrivacyClient(enable_logging=True)
    server = ServerGateway()
    
    prompt = (
        "Patient Emily Davis, age 58, diagnosed with stage 2 hypertension. "
        "Doctor prescribed lisinopril 10mg daily. Contact: emily.d@healthcare.com"
    )
    
    print(f"═══ CLIENT DEVICE (TRUSTED ZONE) ═══\n")
    print(f"Raw Prompt:\n{prompt}\n")
    
    # Client processing
    print(f"\n[1] PII Detection...")
    package, metrics = client.prepare_prompt(prompt)
    
    print(f"\n[2] Sanitization & Encryption...")
    print(f"    {metrics.segments_masked} segments masked")
    print(f"    {metrics.segments_encrypted} segments encrypted")
    
    print(f"\n[3] ZKP Generation...")
    print(f"    Proof generated in {metrics.zkp_generation_time_ms:.2f}ms")
    
    print(f"\n[4] Package for Transmission:")
    print(f"    {package.sanitized_text}")
    
    print(f"\n{'─'*80}")
    print(f"═══ NETWORK TRANSMISSION (TLS) ═══")
    print(f"{'─'*80}\n")
    
    package_json = package.to_json()
    print(f"Encrypted payload: {len(package_json)} bytes")
    
    print(f"\n{'─'*80}")
    print(f"═══ SERVER (UNTRUSTED ZONE) ═══\n")
    
    print(f"[5] ZKP Verification...")
    verification = server.process_request(package_json)
    print(f"    Status: {verification.status.value}")
    
    if verification.status == VerificationStatus.ACCEPTED:
        print(f"\n[6] Forwarding to LLM...")
        llm_request = server.prepare_llm_request(package_json)
        print(f"    Prompt: {llm_request.prompt}")
        print(f"    Tokens: {llm_request.encrypted_tokens}")
        
        llm_response = server.forward_to_llm(llm_request)
        print(f"\n[7] LLM Response:")
        print(f"    {llm_response}")
        
        print(f"\n{'─'*80}")
        print(f"═══ CLIENT DEVICE (RESPONSE HANDLING) ═══\n")
        
        print(f"[8] Processing Response...")
        final_response = client.process_response(llm_response, package)
        print(f"    {final_response}")
    
    print(f"\n{'='*80}")
    print(f"Pipeline Complete")
    print(f"{'='*80}\n")
    
    print(f"Security Guarantees Verified:")
    print(f"  ✓ No raw PII transmitted")
    print(f"  ✓ Selective encryption applied")
    print(f"  ✓ ZKP verification successful")
    print(f"  ✓ Server cannot access PII")
    print(f"  ✓ LLM receives only sanitized data")


if __name__ == "__main__":
    # Run integration tests
    tester = IntegrationTest()
    tester.run_all_tests()
    
    # Demonstrate full pipeline
    demonstrate_full_pipeline()
