"""
Branch: GDPR/HIPAA Compliance Policy

Regulatory-compliant protection policy.
Suitable for: regulated industries, compliance requirements
"""

from typing import Dict, Any
from core.skeleton import IProtectionPolicy, DetectedEntity, ProtectionStrategy, PIICategory


class CompliancePolicy(IProtectionPolicy):
    """
    Compliance-driven protection
    
    Implements:
    - GDPR Article 32 (encryption requirements)
    - HIPAA §164.312 (PHI protection)
    - PCI-DSS (financial data)
    """
    
    def __init__(self, regulation: str = 'GDPR'):
        self.regulation = regulation
        
        if regulation == 'GDPR':
            self.rules = self._gdpr_rules()
        elif regulation == 'HIPAA':
            self.rules = self._hipaa_rules()
        elif regulation == 'PCI-DSS':
            self.rules = self._pci_rules()
        else:
            self.rules = self._gdpr_rules()  # Default
    
    def _gdpr_rules(self) -> Dict[PIICategory, ProtectionStrategy]:
        """GDPR Article 32 - Encryption of personal data"""
        return {
            PIICategory.IDENTIFIER: ProtectionStrategy.ENCRYPT,
            PIICategory.PERSON: ProtectionStrategy.ENCRYPT,
            PIICategory.LOCATION: ProtectionStrategy.ENCRYPT,
            PIICategory.TEMPORAL: ProtectionStrategy.MASK,
            PIICategory.HEALTH: ProtectionStrategy.ENCRYPT,
            PIICategory.FINANCIAL: ProtectionStrategy.ENCRYPT,
            PIICategory.OTHER: ProtectionStrategy.MASK,
        }
    
    def _hipaa_rules(self) -> Dict[PIICategory, ProtectionStrategy]:
        """HIPAA §164.312 - Protected Health Information"""
        return {
            PIICategory.IDENTIFIER: ProtectionStrategy.ENCRYPT,
            PIICategory.PERSON: ProtectionStrategy.ENCRYPT,  # Patient names
            PIICategory.LOCATION: ProtectionStrategy.ENCRYPT,
            PIICategory.TEMPORAL: ProtectionStrategy.ENCRYPT,  # Dates
            PIICategory.HEALTH: ProtectionStrategy.ENCRYPT,  # All PHI
            PIICategory.FINANCIAL: ProtectionStrategy.ENCRYPT,
            PIICategory.OTHER: ProtectionStrategy.ENCRYPT,
        }
    
    def _pci_rules(self) -> Dict[PIICategory, ProtectionStrategy]:
        """PCI-DSS - Payment card data"""
        return {
            PIICategory.IDENTIFIER: ProtectionStrategy.MASK,
            PIICategory.PERSON: ProtectionStrategy.MASK,
            PIICategory.LOCATION: ProtectionStrategy.MASK,
            PIICategory.TEMPORAL: ProtectionStrategy.MASK,
            PIICategory.HEALTH: ProtectionStrategy.MASK,
            PIICategory.FINANCIAL: ProtectionStrategy.ENCRYPT,  # Card data
            PIICategory.OTHER: ProtectionStrategy.MASK,
        }
    
    def determine_strategy(self, entity: DetectedEntity, context: str) -> ProtectionStrategy:
        """Apply regulatory rules"""
        return self.rules.get(entity.category, ProtectionStrategy.MASK)
    
    def get_policy_rules(self) -> Dict[str, Any]:
        """Return policy definition"""
        return {
            'name': 'CompliancePolicy',
            'regulation': self.regulation,
            'strategy': 'regulatory_compliant',
            'rules': {cat.value: strat.value for cat, strat in self.rules.items()}
        }
