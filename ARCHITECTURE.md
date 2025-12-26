# Detailed Component Architecture

## Module Breakdown

### 1. PII Detector (`pii_detector.py`)

**Purpose**: Identify and classify PII/PHI in user prompts using NLP/NER

**Input**: Raw text prompt  
**Output**: List of classified segments with positions

```python
ClassifiedSegment = {
    "text": str,           # Original text span
    "label": str,         # PII type: PERSON, EMAIL, SSN, MEDICAL_CONDITION, etc.
    "start_offset": int,  # Character position start
    "end_offset": int,    # Character position end
    "confidence": float   # Detection confidence [0,1]
}
```

**Detection Strategy**:
- Transformer-based NER (e.g., fine-tuned BERT)
- Regex patterns for structured PII (emails, SSN, phone)
- Medical entity recognition for PHI
- Contextual classification (reduce false positives)

---

### 2. Sanitizer (`sanitizer.py`)

**Purpose**: Apply sanitization policy: mask removable PII, preserve semantic PII

**Classification Rules**:

| PII Type | Context | Action | Reason |
|----------|---------|--------|--------|
| EMAIL | Any | MASK → `<EMAIL_MASKED>` | Not semantically required |
| PHONE | Any | MASK → `<PHONE_MASKED>` | Contact info removable |
| SSN | Any | MASK → `<SSN_MASKED>` | High-risk identifier |
| PERSON | Medical/Legal | ENCRYPT | Semantic context required |
| LOCATION | Medical/Legal | ENCRYPT | Diagnosis/jurisdiction link |
| AGE | Medical | ENCRYPT | Health correlation |
| DATE | Medical | ENCRYPT | Timeline semantic value |
| MEDICATION | Any | ENCRYPT | Protected health info |

**Output Tags**:
- `PLAINTEXT`: Safe for LLM exposure
- `MASKED`: Replaced with placeholder (no encryption needed)
- `SENSITIVE_ENCRYPT`: Must be encrypted before transmission

---

### 3. Selective Encryptor (`encryptor.py`)

**Purpose**: Encrypt only `SENSITIVE_ENCRYPT` segments using ChaCha20

**Cryptographic Scheme**:
- **Algorithm**: ChaCha20-Poly1305 (AEAD)
- **Key Derivation**: HKDF-SHA256 from user master key
- **Nonce**: 96-bit random per segment (collision-resistant)
- **Associated Data**: Segment metadata (position, label)

**Key Management**:
- Master key: 256-bit, stored in device secure enclave
- Per-session keys: Derived via HKDF with session salt
- Key rotation: Every 1000 requests or 24 hours

**Output Structure**:
```python
EncryptedSegment = {
    "ciphertext": bytes,      # ChaCha20-Poly1305 ciphertext
    "nonce": bytes,           # 96-bit nonce
    "tag": bytes,             # Poly1305 authentication tag
    "position": int,          # Original segment position
    "label": str,             # PII type (for reconstruction)
    "placeholder": str        # Token for LLM: [ENCRYPTED_TOKEN_N]
}
```

---

### 4. ZKP Prover (`zkp_prover.py`)

**Purpose**: Generate proof of correct sanitization without revealing PII

**Proof Statement**:  
"I have applied sanitization rules R to prompt P, resulting in plaintext segments S_plain and encrypted segments S_enc, such that:
1. All PII in S_plain has been masked/removed
2. All segments in S_enc are encrypted
3. The sanitization is complete (no raw PII leaked)"

**ZKP Construction** (Sigma Protocol):

**Commitment Phase**:
```
commitment = H(S_plain || metadata(S_enc) || rules_applied || salt)
```

**Challenge-Response**:
- Server sends random challenge c
- Prover computes response r using:
  - Hash of plaintext segments (no raw PII)
  - Encryption metadata (nonces, positions, labels)
  - Merkle proof of rule application
  - Blinded commitment opening

**Verification**:
- Server checks: `Verify(commitment, challenge, response) → {accept, reject}`
- Properties: **Zero-knowledge**, **sound**, **complete**

**Implementation**: Uses Schnorr-like protocol over elliptic curves (secp256k1)

**Public Parameters**:
- Generator point G
- Sanitization rule commitment (published, auditable)

---

### 5. ZKP Verifier (`zkp_verifier.py`)

**Purpose**: Verify proof validity before LLM interaction

**Verification Steps**:
1. Parse proof components (commitment, response)
2. Recompute challenge from commitment
3. Verify elliptic curve equation holds
4. Check Merkle proof of rule application
5. Validate metadata consistency (no tampering)

**Rejection Criteria**:
- Proof computation error
- Commitment mismatch
- Invalid cryptographic signature
- Metadata integrity failure

**Security**: Soundness error probability < 2^-128

---

### 6. Secure Prompt Builder (`prompt_builder.py`)

**Purpose**: Reconstruct prompt with encrypted segments replaced by placeholders

**Algorithm**:
1. Sort segments by position (ascending)
2. Interleave:
   - Plaintext segments (as-is)
   - Masked segments (placeholder text)
   - Encrypted segments (opaque tokens: `[ENCRYPTED_TOKEN_0]`, `[ENCRYPTED_TOKEN_1]`, ...)
3. Maintain semantic coherence (spacing, punctuation)

**Example**:
```
Original: "Patient John Doe, age 45, diagnosed with hypertension"
Sanitized: "Patient [ENCRYPTED_TOKEN_0], age [ENCRYPTED_TOKEN_1], diagnosed with [ENCRYPTED_TOKEN_2]"
```

**Metadata Preservation**:
- Store mapping: token_id → (ciphertext, nonce, tag, label)
- Required for client-side decryption (if needed)

---

### 7. LLM Gateway (`llm_gateway.py`)

**Purpose**: Forward sanitized prompts to LLM; prevent memorization

**Security Measures**:
- **Token Rotation**: Change placeholder format per session
- **Rate Limiting**: Prevent enumeration attacks
- **Prompt Injection Defense**: Escape special characters in plaintext
- **Logging**: Audit all requests (sanitized only)

**LLM Configuration**:
- Temperature: 0.7 (balance creativity/determinism)
- Top-p: 0.9
- No fine-tuning on user prompts (prevent memorization)

---

### 8. Response Handler (`response_handler.py`)

**Purpose**: Client-side response processing and PII re-binding

**Operations**:
1. Receive LLM response
2. (Optional) Detect if response references encrypted tokens
3. Decrypt relevant segments using local keys
4. Re-bind PII safely:
   - Replace tokens with decrypted values
   - Highlight re-inserted PII to user
5. Securely clear decrypted data from memory

**Security**:
- Constant-time decryption (side-channel resistant)
- Memory wiping after use (prevent leakage)

---

## Data Flow Summary

```
Raw Prompt
  ↓
PII Detector → Classified Segments
  ↓
Sanitizer → (Plaintext, Masked, Sensitive)
  ↓
Selective Encryptor → (Plaintext, Masked, Encrypted)
  ↓
ZKP Prover → Proof of Sanitization
  ↓
[TRANSMISSION: Plaintext + Encrypted + Proof]
  ↓
ZKP Verifier → Accept/Reject
  ↓ (if Accept)
Prompt Builder → Sanitized Prompt with Tokens
  ↓
LLM Gateway → LLM Processing
  ↓
LLM Response
  ↓
[TRANSMISSION: Response]
  ↓
Response Handler → (Optional) Decrypt & Re-bind
  ↓
Final Output to User
```

## Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|-----------|-----------|---------|
| AEAD Encryption | ChaCha20-Poly1305 | Segment encryption + authentication |
| Hash Function | SHA3-256 | Commitments, Merkle trees |
| KDF | HKDF-SHA256 | Key derivation from master key |
| ZKP Curve | secp256k1 | Elliptic curve operations |
| Random Oracle | SHAKE256 | Challenge generation |

## Performance Characteristics

- **PII Detection**: ~50ms per 1000 tokens (GPU-accelerated NER)
- **Encryption**: ~1ms per segment (ChaCha20)
- **ZKP Generation**: ~100ms (single-core)
- **ZKP Verification**: ~50ms (server-side)
- **Total Client Overhead**: ~200ms for typical prompt
- **Network Overhead**: +5-10% payload size (metadata)

## Academic Publication Readiness

**Novel Contributions**:
1. Selective encryption with semantic preservation
2. ZKP-based sanitization verification (no trusted third party)
3. Trust boundary separation (client/server)
4. Compliance-by-construction architecture

**Comparison to Related Work**:
- **Differential Privacy**: No utility loss from noise injection
- **Homomorphic Encryption**: No full-prompt encryption overhead
- **Trusted Execution Environments**: No hardware requirements
- **Federated Learning**: Real-time inference, not training

**Threat Model**: Honest-but-curious server, malicious LLM provider, network adversary
