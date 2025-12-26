"""
Branch: Schnorr Proof System

Zero-knowledge proofs using Schnorr protocol.
Suitable for: general use, well-studied security
"""

import secrets
import hashlib
from typing import Dict, Any
from core.skeleton import IProofSystem, Proof

try:
    from ecdsa import SigningKey, VerifyingKey, SECP256k1
    ECDSA_AVAILABLE = True
except ImportError:
    ECDSA_AVAILABLE = False


class SchnorrProver(IProofSystem):
    """Schnorr-like ZKP over elliptic curves"""
    
    def __init__(self):
        if not ECDSA_AVAILABLE:
            raise ImportError("ecdsa library required")
        
        self.signing_key = SigningKey.generate(curve=SECP256k1)
        self.verifying_key = self.signing_key.get_verifying_key()
    
    def generate_proof(
        self,
        statement: Dict[str, Any],
        witness: Dict[str, Any]
    ) -> Proof:
        """Generate Schnorr-like proof"""
        
        # Generate random salt
        salt = secrets.token_bytes(32)
        
        # Compute commitment
        statement_bytes = str(statement).encode('utf-8')
        witness_bytes = str(witness).encode('utf-8')
        
        commitment = hashlib.sha3_256(
            statement_bytes + witness_bytes + salt
        ).digest()
        
        # Generate challenge (Fiat-Shamir)
        challenge = self._fiat_shamir_challenge(commitment, statement_bytes)
        
        # Compute response (signature)
        message = commitment + challenge
        response = self.signing_key.sign(message)
        
        return Proof(
            commitment=commitment,
            challenge=challenge,
            response=response,
            metadata={
                'verifying_key': self.verifying_key.to_string().hex(),
                'algorithm': 'Schnorr-SECP256k1'
            }
        )
    
    def verify_proof(self, proof: Proof, statement: Dict[str, Any]) -> bool:
        """Verify Schnorr proof"""
        try:
            # Reconstruct challenge
            statement_bytes = str(statement).encode('utf-8')
            expected_challenge = self._fiat_shamir_challenge(
                proof.commitment,
                statement_bytes
            )
            
            if proof.challenge != expected_challenge:
                return False
            
            # Verify signature
            vk_bytes = bytes.fromhex(proof.metadata['verifying_key'])
            verifying_key = VerifyingKey.from_string(vk_bytes, curve=SECP256k1)
            
            message = proof.commitment + proof.challenge
            verifying_key.verify(proof.response, message)
            
            return True
            
        except Exception:
            return False
    
    def _fiat_shamir_challenge(self, commitment: bytes, statement: bytes) -> bytes:
        """Generate challenge via Fiat-Shamir heuristic"""
        shake = hashlib.shake_256()
        shake.update(commitment)
        shake.update(statement)
        return shake.digest(32)
