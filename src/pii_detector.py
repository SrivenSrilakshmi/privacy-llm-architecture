"""
PII Detection Module

Identifies and classifies Personally Identifiable Information (PII) and 
Protected Health Information (PHI) using NLP/NER techniques.

Security Properties:
- Operates entirely on client device (trusted zone)
- No network communication during detection
- Memory-safe processing (no PII leakage to disk)
"""

from dataclasses import dataclass
from typing import List, Tuple
from enum import Enum
import re


class PIILabel(Enum):
    """PII/PHI classification labels"""
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    LOCATION = "LOCATION"
    DATE = "DATE"
    AGE = "AGE"
    MEDICATION = "MEDICATION"
    MEDICAL_CONDITION = "MEDICAL_CONDITION"
    PROCEDURE = "PROCEDURE"
    IP_ADDRESS = "IP_ADDRESS"
    NONE = "NONE"


@dataclass
class ClassifiedSegment:
    """
    Represents a classified text segment with PII metadata
    
    Attributes:
        text: Original text span
        label: PII classification type
        start_offset: Character position start (inclusive)
        end_offset: Character position end (exclusive)
        confidence: Detection confidence score [0.0, 1.0]
    """
    text: str
    label: PIILabel
    start_offset: int
    end_offset: int
    confidence: float
    
    def __repr__(self):
        return (f"ClassifiedSegment(text='{self.text[:20]}...', "
                f"label={self.label.value}, pos=[{self.start_offset}:{self.end_offset}], "
                f"conf={self.confidence:.2f})")


class PIIDetector:
    """
    Multi-strategy PII detector combining:
    1. Pattern-based detection (regex) for structured PII
    2. NER-based detection for contextual PII
    3. Medical entity recognition for PHI
    
    Implementation Note:
    In production, replace regex-based detection with transformer models:
    - General PII: fine-tuned BERT/RoBERTa on PII datasets
    - Medical PHI: BioClinicalBERT or PubMedBERT
    - Ensemble voting for high-confidence detection
    """
    
    # Regex patterns for structured PII
    PATTERNS = {
        PIILabel.EMAIL: r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        PIILabel.PHONE: r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
        PIILabel.SSN: r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
        PIILabel.CREDIT_CARD: r'\b(?:4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|3[47]\d{1}[-\s]?\d{6}[-\s]?\d{5})\b',
        PIILabel.IP_ADDRESS: r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        PIILabel.DATE: r'\b(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b',
        PIILabel.PERSON: r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b',
    }
    
    # Medical terminology patterns (simplified - use BioClinicalBERT in production)
    MEDICATION_KEYWORDS = {
        'aspirin', 'ibuprofen', 'lisinopril', 'metformin', 'omeprazole',
        'simvastatin', 'levothyroxine', 'amlodipine', 'metoprolol', 'atorvastatin'
    }
    
    CONDITION_KEYWORDS = {
        'hypertension', 'diabetes', 'copd', 'asthma', 'depression', 'anxiety',
        'arthritis', 'cancer', 'heart disease', 'stroke', 'pneumonia'
    }
    
    def __init__(self, confidence_threshold: float = 0.85):
        """
        Initialize PII detector
        
        Args:
            confidence_threshold: Minimum confidence score for detection (default: 0.85)
        """
        self.confidence_threshold = confidence_threshold
        
    def detect(self, text: str) -> List[ClassifiedSegment]:
        """
        Detect and classify all PII segments in text
        
        Args:
            text: Raw input text to scan
            
        Returns:
            List of classified segments, sorted by start_offset
            
        Security Guarantee:
            - All processing in-memory
            - No external API calls
            - No disk writes
        """
        segments = []
        
        # Pattern-based detection
        segments.extend(self._detect_patterns(text))
        
        # Contextual NER (simulated - use transformer in production)
        segments.extend(self._detect_contextual(text))
        
        # Medical entity detection
        segments.extend(self._detect_medical(text))
        
        # Deduplicate overlapping segments (keep highest confidence)
        segments = self._deduplicate_segments(segments)
        
        # Filter by confidence threshold
        segments = [s for s in segments if s.confidence >= self.confidence_threshold]
        
        # Sort by position
        segments.sort(key=lambda s: s.start_offset)
        
        return segments
    
    def _detect_patterns(self, text: str) -> List[ClassifiedSegment]:
        """Regex-based pattern matching for structured PII"""
        segments = []
        
        for label, pattern in self.PATTERNS.items():
            for match in re.finditer(pattern, text):
                segments.append(ClassifiedSegment(
                    text=match.group(),
                    label=label,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    confidence=0.95  # High confidence for regex matches
                ))
        
        return segments
    
    def _detect_contextual(self, text: str) -> List[ClassifiedSegment]:
        """
        Contextual NER detection (simulated)
        
        Production Implementation:
        ```python
        from transformers import pipeline
        ner = pipeline("ner", model="dslim/bert-base-NER")
        entities = ner(text)
        # Map entities to PIILabel
        ```
        """
        segments = []
        
        # Enhanced name detection
        # Pattern: Capitalized words that might be names (2-3 words)
        name_pattern = r'\b([A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+)\b'
        for match in re.finditer(name_pattern, text):
            matched_text = match.group()
            
            # Skip common non-person patterns
            skip_patterns = ['Patient Care', 'Health Center', 'Type 2', 'Lab Results']
            if any(skip in matched_text for skip in skip_patterns):
                continue
            
            # Higher confidence if near person indicators
            context = text[max(0, match.start()-30):min(len(text), match.end()+30)].lower()
            person_indicators = ['patient', 'dr.', 'doctor', 'mr.', 'mrs.', 'ms.', 'name:', 'contact:']
            
            confidence = 0.85 if any(ind in context for ind in person_indicators) else 0.70
            
            segments.append(ClassifiedSegment(
                text=matched_text,
                label=PIILabel.PERSON,
                start_offset=match.start(),
                end_offset=match.end(),
                confidence=confidence
            ))
        
        return segments
    
    def _detect_medical(self, text: str) -> List[ClassifiedSegment]:
        """
        Medical entity detection (PHI)
        
        Production Implementation:
        ```python
        from transformers import pipeline
        ner = pipeline("ner", model="emilyalsentzer/Bio_ClinicalBERT")
        entities = ner(text)
        ```
        """
        segments = []
        text_lower = text.lower()
        
        # Medication detection
        for med in self.MEDICATION_KEYWORDS:
            pattern = r'\b' + re.escape(med) + r'\b'
            for match in re.finditer(pattern, text_lower):
                segments.append(ClassifiedSegment(
                    text=text[match.start():match.end()],
                    label=PIILabel.MEDICATION,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    confidence=0.90
                ))
        
        # Medical condition detection
        for condition in self.CONDITION_KEYWORDS:
            pattern = r'\b' + re.escape(condition) + r'\b'
            for match in re.finditer(pattern, text_lower):
                segments.append(ClassifiedSegment(
                    text=text[match.start():match.end()],
                    label=PIILabel.MEDICAL_CONDITION,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    confidence=0.90
                ))
        
        # Age detection (medical context)
        age_pattern = r'\b(?:age[d]?\s+)?(\d{1,3})\s*(?:years?\s+old|y/?o)\b'
        for match in re.finditer(age_pattern, text, re.IGNORECASE):
            segments.append(ClassifiedSegment(
                text=match.group(),
                label=PIILabel.AGE,
                start_offset=match.start(),
                end_offset=match.end(),
                confidence=0.85
            ))
        
        return segments
    
    def _deduplicate_segments(self, segments: List[ClassifiedSegment]) -> List[ClassifiedSegment]:
        """
        Remove overlapping segments, keeping highest confidence
        
        Strategy: If two segments overlap, keep the one with higher confidence.
        If confidence is equal, keep the longer segment.
        """
        if not segments:
            return []
        
        # Sort by start position, then by confidence (descending)
        segments.sort(key=lambda s: (s.start_offset, -s.confidence))
        
        deduplicated = []
        
        for segment in segments:
            # Check if overlaps with any kept segment
            overlaps = False
            for kept in deduplicated:
                if self._segments_overlap(segment, kept):
                    # Keep the higher confidence one
                    if segment.confidence > kept.confidence:
                        deduplicated.remove(kept)
                        deduplicated.append(segment)
                    overlaps = True
                    break
            
            if not overlaps:
                deduplicated.append(segment)
        
        return deduplicated
    
    @staticmethod
    def _segments_overlap(seg1: ClassifiedSegment, seg2: ClassifiedSegment) -> bool:
        """Check if two segments overlap"""
        return not (seg1.end_offset <= seg2.start_offset or seg2.end_offset <= seg1.start_offset)


# Example usage and testing
if __name__ == "__main__":
    detector = PIIDetector(confidence_threshold=0.75)
    
    test_prompts = [
        "My email is john.doe@example.com and my phone is 555-123-4567",
        "Patient John Smith, age 45, diagnosed with hypertension",
        "SSN: 123-45-6789, Card: 4532123456789012",
        "Doctor prescribed metformin for diabetes management",
        "Contact me at 192.168.1.1 or call (555) 987-6543"
    ]
    
    for prompt in test_prompts:
        print(f"\nPrompt: {prompt}")
        segments = detector.detect(prompt)
        for seg in segments:
            print(f"  {seg}")
