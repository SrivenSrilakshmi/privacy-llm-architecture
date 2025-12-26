"""
Branch: Contextual Protection Policy

Smart policy - preserve semantic PII, mask identifiers.
Suitable for: balanced privacy/utility, medical/legal contexts
"""

from typing import Dict, Any
from core.skeleton import IProtectionPolicy, DetectedEntity, ProtectionStrategy, PIICategory


class ContextualPolicy(IProtectionPolicy):
    """Context-aware protection decisions"""
    
    # Always mask these
    ALWAYS_MASK = {
        PIICategory.IDENTIFIER,
        PIICategory.FINANCIAL,
    }
    
    # Context-dependent
    CONTEXTUAL = {
        PIICategory.PERSON,
        PIICategory.LOCATION,
        PIICategory.TEMPORAL,
    }
    
    # Always encrypt (PHI)
    ALWAYS_ENCRYPT = {
        PIICategory.HEALTH,
    }
    
    def __init__(self):
        self.medical_keywords = {'patient', 'diagnosis', 'doctor', 'hospital', 'treatment'}
        self.legal_keywords = {'court', 'defendant', 'plaintiff', 'attorney', 'contract'}
    
    def determine_strategy(self, entity: DetectedEntity, context: str) -> ProtectionStrategy:
        """Determine based on category and context"""
        
        # Always mask identifiers
        if entity.category in self.ALWAYS_MASK:
            return ProtectionStrategy.MASK
        
        # Always encrypt health data
        if entity.category in self.ALWAYS_ENCRYPT:
            return ProtectionStrategy.ENCRYPT
        
        # Contextual decision
        if entity.category in self.CONTEXTUAL:
            if self._is_sensitive_context(context):
                return ProtectionStrategy.ENCRYPT
            else:
                return ProtectionStrategy.MASK
        
        return ProtectionStrategy.PLAINTEXT
    
    def _is_sensitive_context(self, context: str) -> bool:
        """Check if context requires preservation"""
        context_lower = context.lower()
        
        is_medical = any(kw in context_lower for kw in self.medical_keywords)
        is_legal = any(kw in context_lower for kw in self.legal_keywords)
        
        return is_medical or is_legal
    
    def get_policy_rules(self) -> Dict[str, Any]:
        """Return policy definition"""
        return {
            'name': 'ContextualPolicy',
            'strategy': 'context_aware',
            'always_mask': [cat.value for cat in self.ALWAYS_MASK],
            'always_encrypt': [cat.value for cat in self.ALWAYS_ENCRYPT],
            'contextual': [cat.value for cat in self.CONTEXTUAL]
        }
