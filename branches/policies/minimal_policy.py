"""
Branch: Minimal Protection Policy

Conservative policy - mask all PII.
Suitable for: maximum privacy, simple use cases
"""

from typing import Dict, Any
from core.skeleton import IProtectionPolicy, DetectedEntity, ProtectionStrategy, PIICategory


class MinimalPolicy(IProtectionPolicy):
    """Mask all detected PII"""
    
    def __init__(self):
        self.rules = {
            PIICategory.IDENTIFIER: ProtectionStrategy.MASK,
            PIICategory.PERSON: ProtectionStrategy.MASK,
            PIICategory.LOCATION: ProtectionStrategy.MASK,
            PIICategory.TEMPORAL: ProtectionStrategy.MASK,
            PIICategory.HEALTH: ProtectionStrategy.MASK,
            PIICategory.FINANCIAL: ProtectionStrategy.MASK,
            PIICategory.OTHER: ProtectionStrategy.MASK,
        }
    
    def determine_strategy(self, entity: DetectedEntity, context: str) -> ProtectionStrategy:
        """Always mask"""
        return self.rules.get(entity.category, ProtectionStrategy.MASK)
    
    def get_policy_rules(self) -> Dict[str, Any]:
        """Return policy definition"""
        return {
            'name': 'MinimalPolicy',
            'strategy': 'mask_all',
            'rules': {cat.value: strat.value for cat, strat in self.rules.items()}
        }
