"""
Sanitizer Module

Applies sanitization policies to classified PII segments:
1. MASK: Removable PII replaced with placeholders
2. ENCRYPT: Semantically required PII marked for encryption
3. PLAINTEXT: Non-sensitive text passed through

Policy decisions based on PII type and contextual requirements.

Security Properties:
- Deterministic sanitization (same input → same output)
- Auditable policy rules (logged for compliance)
- Minimal data retention (semantic preservation only)
"""

from dataclasses import dataclass
from typing import List, Tuple, Dict
from enum import Enum
from pii_detector import ClassifiedSegment, PIILabel


class SanitizationAction(Enum):
    """Sanitization policy actions"""
    PLAINTEXT = "PLAINTEXT"          # Safe for LLM exposure
    MASKED = "MASKED"                 # Replace with placeholder
    SENSITIVE_ENCRYPT = "SENSITIVE_ENCRYPT"  # Must encrypt before transmission


@dataclass
class SanitizedSegment:
    """
    Represents a sanitized text segment after policy application
    
    Attributes:
        original_text: Original text (stored for encryption, not transmitted)
        sanitized_text: Text after sanitization (may be placeholder)
        action: Sanitization action applied
        label: Original PII label
        start_offset: Original character position start
        end_offset: Original character position end
        context_required: Whether segment is semantically necessary
    """
    original_text: str
    sanitized_text: str
    action: SanitizationAction
    label: PIILabel
    start_offset: int
    end_offset: int
    context_required: bool
    
    def __repr__(self):
        return (f"SanitizedSegment(sanitized='{self.sanitized_text[:20]}...', "
                f"action={self.action.value}, label={self.label.value})")


class SanitizationPolicy:
    """
    Defines context-aware sanitization rules
    
    Policy Matrix:
    - EMAIL, PHONE, SSN, CREDIT_CARD, IP_ADDRESS → MASKED (never semantically required)
    - PERSON, LOCATION, AGE, DATE → ENCRYPT (medical/legal context)
    - MEDICATION, MEDICAL_CONDITION, PROCEDURE → ENCRYPT (PHI)
    
    Rationale:
    - Structured identifiers (email, SSN) can be abstracted without semantic loss
    - Contextual PII (names in medical records) requires preservation for coherence
    - All PHI must be encrypted (HIPAA compliance)
    """
    
    # Non-contextual masking (always removable)
    ALWAYS_MASK = {
        PIILabel.EMAIL,
        PIILabel.PHONE,
        PIILabel.SSN,
        PIILabel.CREDIT_CARD,
        PIILabel.IP_ADDRESS
    }
    
    # Contextual encryption (preserve semantics)
    CONTEXT_ENCRYPT = {
        PIILabel.PERSON,
        PIILabel.LOCATION,
        PIILabel.AGE,
        PIILabel.DATE
    }
    
    # Always encrypt (PHI)
    ALWAYS_ENCRYPT = {
        PIILabel.MEDICATION,
        PIILabel.MEDICAL_CONDITION,
        PIILabel.PROCEDURE
    }
    
    # Placeholder templates
    MASK_TEMPLATES = {
        PIILabel.EMAIL: "<EMAIL_MASKED>",
        PIILabel.PHONE: "<PHONE_MASKED>",
        PIILabel.SSN: "<SSN_MASKED>",
        PIILabel.CREDIT_CARD: "<CARD_MASKED>",
        PIILabel.IP_ADDRESS: "<IP_MASKED>"
    }
    
    @classmethod
    def determine_action(cls, segment: ClassifiedSegment, context: str) -> SanitizationAction:
        """
        Determine sanitization action based on PII type and context
        
        Args:
            segment: Classified PII segment
            context: Surrounding text for context analysis
            
        Returns:
            Sanitization action to apply
        """
        # Always mask these types
        if segment.label in cls.ALWAYS_MASK:
            return SanitizationAction.MASKED
        
        # Always encrypt PHI
        if segment.label in cls.ALWAYS_ENCRYPT:
            return SanitizationAction.SENSITIVE_ENCRYPT
        
        # Contextual decision for PERSON, LOCATION, AGE, DATE
        if segment.label in cls.CONTEXT_ENCRYPT:
            if cls._requires_context(segment, context):
                return SanitizationAction.SENSITIVE_ENCRYPT
            else:
                return SanitizationAction.MASKED
        
        # Default: plaintext (should not occur with proper PII detection)
        return SanitizationAction.PLAINTEXT
    
    @classmethod
    def _requires_context(cls, segment: ClassifiedSegment, context: str) -> bool:
        """
        Determine if segment is semantically required based on context
        
        Heuristics:
        - Medical context: patient names, ages, dates (diagnosis timeline)
        - Legal context: person names, locations (jurisdiction)
        - General context: likely removable
        
        Production: Use fine-tuned classifier for context analysis
        """
        context_lower = context.lower()
        
        # Medical context indicators
        medical_keywords = {
            'patient', 'diagnosis', 'treatment', 'symptom', 'doctor',
            'hospital', 'clinic', 'prescribed', 'medication', 'condition'
        }
        
        # Legal context indicators
        legal_keywords = {
            'court', 'lawsuit', 'plaintiff', 'defendant', 'attorney',
            'contract', 'agreement', 'jurisdiction', 'statute'
        }
        
        is_medical = any(keyword in context_lower for keyword in medical_keywords)
        is_legal = any(keyword in context_lower for keyword in legal_keywords)
        
        # If medical or legal context, preserve semantic PII
        if is_medical or is_legal:
            return True
        
        # Default: not required
        return False
    
    @classmethod
    def get_mask_template(cls, label: PIILabel) -> str:
        """Get placeholder template for masked PII"""
        return cls.MASK_TEMPLATES.get(label, f"<{label.value}_MASKED>")


class Sanitizer:
    """
    Applies sanitization policies to PII segments
    
    Process:
    1. Receive classified segments from PII detector
    2. Apply context-aware sanitization policy
    3. Generate sanitized segments with metadata
    4. Preserve original text for encryption (not transmitted in plaintext)
    """
    
    def __init__(self, policy: SanitizationPolicy = None):
        """
        Initialize sanitizer
        
        Args:
            policy: Sanitization policy (default: SanitizationPolicy)
        """
        self.policy = policy or SanitizationPolicy()
    
    def sanitize(self, text: str, pii_segments: List[ClassifiedSegment]) -> Tuple[str, List[SanitizedSegment]]:
        """
        Sanitize text by applying policy to PII segments
        
        Args:
            text: Original text
            pii_segments: Classified PII segments from detector
            
        Returns:
            Tuple of:
                - Sanitized text (with placeholders, ready for encryption)
                - List of sanitized segments with metadata
                
        Security Guarantee:
            - Original text with sensitive PII never transmitted
            - Sanitized output contains only: plaintext, placeholders, or encryption targets
        """
        if not pii_segments:
            # No PII detected - entire text is plaintext
            return text, []
        
        sanitized_segments = []
        
        # Process each PII segment
        for segment in pii_segments:
            # Extract context window (±50 chars)
            context_start = max(0, segment.start_offset - 50)
            context_end = min(len(text), segment.end_offset + 50)
            context = text[context_start:context_end]
            
            # Determine sanitization action
            action = self.policy.determine_action(segment, context)
            
            # Apply sanitization
            if action == SanitizationAction.MASKED:
                sanitized_text = self.policy.get_mask_template(segment.label)
                context_required = False
            elif action == SanitizationAction.SENSITIVE_ENCRYPT:
                # Keep original text for encryption (will be replaced with token later)
                sanitized_text = segment.text
                context_required = True
            else:  # PLAINTEXT
                sanitized_text = segment.text
                context_required = False
            
            sanitized_segments.append(SanitizedSegment(
                original_text=segment.text,
                sanitized_text=sanitized_text,
                action=action,
                label=segment.label,
                start_offset=segment.start_offset,
                end_offset=segment.end_offset,
                context_required=context_required
            ))
        
        # Reconstruct text with masked segments
        sanitized_text = self._reconstruct_text(text, sanitized_segments)
        
        return sanitized_text, sanitized_segments
    
    def _reconstruct_text(self, original_text: str, sanitized_segments: List[SanitizedSegment]) -> str:
        """
        Reconstruct text with masked segments replaced
        
        Note: SENSITIVE_ENCRYPT segments retain original text here.
        They will be replaced with encryption tokens later by the encryptor.
        """
        if not sanitized_segments:
            return original_text
        
        # Sort segments by position
        sanitized_segments.sort(key=lambda s: s.start_offset)
        
        result = []
        current_pos = 0
        
        for segment in sanitized_segments:
            # Add text before this segment
            result.append(original_text[current_pos:segment.start_offset])
            
            # Add sanitized segment
            if segment.action == SanitizationAction.MASKED:
                result.append(segment.sanitized_text)
            else:
                # Keep original (will be encrypted later)
                result.append(segment.sanitized_text)
            
            current_pos = segment.end_offset
        
        # Add remaining text
        result.append(original_text[current_pos:])
        
        return ''.join(result)
    
    def get_plaintext_segments(self, sanitized_text: str, sanitized_segments: List[SanitizedSegment]) -> List[str]:
        """
        Extract plaintext segments (safe for LLM exposure)
        
        Returns segments that are either:
        - Original non-PII text
        - Masked placeholders
        
        Excludes segments marked SENSITIVE_ENCRYPT (handled separately)
        """
        plaintext_parts = []
        current_pos = 0
        
        for segment in sorted(sanitized_segments, key=lambda s: s.start_offset):
            # Add non-PII text before this segment
            if segment.start_offset > current_pos:
                plaintext_parts.append(sanitized_text[current_pos:segment.start_offset])
            
            # Add segment if masked or plaintext
            if segment.action in [SanitizationAction.MASKED, SanitizationAction.PLAINTEXT]:
                plaintext_parts.append(segment.sanitized_text)
            
            current_pos = segment.end_offset
        
        # Add remaining text
        if current_pos < len(sanitized_text):
            plaintext_parts.append(sanitized_text[current_pos:])
        
        return plaintext_parts


# Example usage and testing
if __name__ == "__main__":
    from pii_detector import PIIDetector
    
    detector = PIIDetector(confidence_threshold=0.75)
    sanitizer = Sanitizer()
    
    test_cases = [
        "Patient John Smith, age 45, diagnosed with hypertension. Contact: john@email.com",
        "My SSN is 123-45-6789 and credit card is 4532123456789012",
        "Doctor prescribed metformin 500mg for diabetes management",
        "Call me at 555-1234 or email support@company.com for questions"
    ]
    
    for text in test_cases:
        print(f"\n{'='*70}")
        print(f"Original: {text}")
        
        # Detect PII
        pii_segments = detector.detect(text)
        print(f"\nDetected PII: {len(pii_segments)} segments")
        for seg in pii_segments:
            print(f"  {seg}")
        
        # Sanitize
        sanitized_text, sanitized_segments = sanitizer.sanitize(text, pii_segments)
        print(f"\nSanitized: {sanitized_text}")
        print(f"\nSanitized Segments:")
        for seg in sanitized_segments:
            print(f"  {seg}")
