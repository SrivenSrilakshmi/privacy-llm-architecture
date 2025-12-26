# Privacy-Preserving LLM Interaction Architecture

## System Overview

A cryptographically-secured architecture for LLM interactions that ensures:
- **PII Confidentiality**: Raw user prompts never leave the device in plaintext
- **Regulatory Compliance**: GDPR/HIPAA compatible through selective encryption
- **Verifiable Integrity**: Zero-Knowledge Proofs ensure sanitization correctness
- **Selective Processing**: Only non-sensitive segments exposed to LLM

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT DEVICE                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 1. PII DETECTOR (NLP/NER)                                  │ │
│  │    Input: Raw prompt                                       │ │
│  │    Output: Classified segments [(text, label, offset)]    │ │
│  └──────────────────────┬─────────────────────────────────────┘ │
│                         │                                        │
│  ┌──────────────────────▼─────────────────────────────────────┐ │
│  │ 2. SANITIZER                                               │ │
│  │    • Mask removable PII (email → EMAIL_MASKED)             │ │
│  │    • Preserve semantic PII (name in medical context)       │ │
│  │    • Tag: PLAINTEXT | SENSITIVE_ENCRYPT                    │ │
│  └──────────────────────┬─────────────────────────────────────┘ │
│                         │                                        │
│  ┌──────────────────────▼─────────────────────────────────────┐ │
│  │ 3. SELECTIVE ENCRYPTOR (ChaCha20)                          │ │
│  │    • Encrypt SENSITIVE_ENCRYPT segments                    │ │
│  │    • Preserve PLAINTEXT segments                           │ │
│  │    • Generate position metadata                            │ │
│  └──────────────────────┬─────────────────────────────────────┘ │
│                         │                                        │
│  ┌──────────────────────▼─────────────────────────────────────┐ │
│  │ 4. ZKP PROVER                                              │ │
│  │    Proves without revealing:                               │ │
│  │    • PII sanitization applied correctly                    │ │
│  │    • Declared segments encrypted                           │ │
│  │    • No raw PII in plaintext portions                      │ │
│  │    Commitment: H(plaintext || enc_metadata || rules)       │ │
│  └──────────────────────┬─────────────────────────────────────┘ │
│                         │                                        │
└─────────────────────────┼─────────────────────────────────────┘
                          │
         ┌────────────────▼────────────────┐
         │   TRANSMISSION LAYER (TLS)      │
         │   • Sanitized plaintext         │
         │   • Encrypted segments          │
         │   • ZKP proof                   │
         │   • Position metadata           │
         └────────────────┬────────────────┘
                          │
┌─────────────────────────▼─────────────────────────────────────┐
│                        SERVER                                  │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ 5. ZKP VERIFIER                                        │   │
│  │    • Verify proof validity                             │   │
│  │    • Check commitment integrity                        │   │
│  │    • REJECT if verification fails                      │   │
│  └──────────────────────┬─────────────────────────────────┘   │
│                         │                                      │
│  ┌──────────────────────▼─────────────────────────────────┐   │
│  │ 6. SECURE PROMPT BUILDER                               │   │
│  │    • Reconstruct prompt with placeholders              │   │
│  │    • Replace encrypted segments: [ENCRYPTED_TOKEN_N]   │   │
│  │    • Maintain semantic coherence                       │   │
│  └──────────────────────┬─────────────────────────────────┘   │
│                         │                                      │
│  ┌──────────────────────▼─────────────────────────────────┐   │
│  │ 7. LLM GATEWAY                                         │   │
│  │    • Forward sanitized prompt to LLM                   │   │
│  │    • LLM processes plaintext + opaque tokens           │   │
│  │    • Prevent memorization via token rotation           │   │
│  └──────────────────────┬─────────────────────────────────┘   │
└─────────────────────────┼─────────────────────────────────────┘
                          │
         ┌────────────────▼────────────────┐
         │      RESPONSE CHANNEL           │
         │      LLM Response → Client      │
         └────────────────┬────────────────┘
                          │
┌─────────────────────────▼─────────────────────────────────────┐
│                    CLIENT DEVICE                               │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ 8. RESPONSE HANDLER                                    │   │
│  │    • Receive LLM response                              │   │
│  │    • Decrypt sensitive context (if needed)             │   │
│  │    • Re-bind PII safely                                │   │
│  └────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

## Trust Boundaries

```
┌──────────────────────┐
│   TRUSTED ZONE       │  Client Device
│   • Raw PII visible  │  • User controls key material
│   • Decryption keys  │  • PII processing in memory
│   • Full context     │  • No persistent PII storage
└──────────────────────┘

┌──────────────────────┐
│   UNTRUSTED ZONE     │  Server / LLM Provider
│   • No raw PII       │  • Cannot decrypt sensitive data
│   • Opaque tokens    │  • Verifies proofs only
│   • No keys          │  • Processes sanitized prompts
└──────────────────────┘

┌──────────────────────┐
│   CRYPTOGRAPHIC      │  Zero-Knowledge Proof
│   BOUNDARY           │  • Proves correctness
│                      │  • Reveals nothing about PII
└──────────────────────┘
```

## Security Properties

1. **PII Confidentiality**: Sensitive data encrypted with ChaCha20; keys never leave client
2. **Integrity**: ZKP ensures sanitization rules applied; tamper-evident
3. **Minimal Disclosure**: Only necessary plaintext exposed to LLM
4. **Verifiability**: Server cryptographically verifies compliance without seeing PII
5. **Forward Secrecy**: Ephemeral keys per session; rotation on token refresh
6. **Non-Repudiation**: Commitments bind client to declared sanitization

## Compliance Mapping

- **GDPR Article 32**: Encryption of personal data (ChaCha20)
- **GDPR Article 25**: Privacy by design (selective encryption)
- **HIPAA §164.312(a)(2)(iv)**: Encryption/decryption (at-rest via client keys)
- **HIPAA §164.312(e)(2)(ii)**: Transmission security (TLS + selective encryption)

## Implementation Status

See `src/` for modular components implementing each pipeline stage.
