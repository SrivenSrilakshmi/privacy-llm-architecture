"""
Branch: Regex-Based PII Detector

Lightweight pattern-based detection for structured PII.
Suitable for: prototyping, low-latency requirements, structured data
"""

import re
from typing import List, Dict, Any
from core.skeleton import IPIIDetector, DetectedEntity, PIICategory


class RegexDetector(IPIIDetector):
    """Pattern-based PII detector using regex"""
    
    PATTERNS = {
        PIICategory.IDENTIFIER: {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
            'ssn': r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
        },
        PIICategory.FINANCIAL: {
            'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
        },
        PIICategory.IDENTIFIER: {
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        }
    }
    
    def __init__(self, confidence: float = 0.95):
        self.confidence = confidence
        self.enabled_patterns = set(PIICategory)
    
    def detect(self, text: str) -> List[DetectedEntity]:
        """Detect using regex patterns"""
        entities = []
        
        for category, patterns in self.PATTERNS.items():
            if category not in self.enabled_patterns:
                continue
            
            for pattern_name, pattern in patterns.items():
                for match in re.finditer(pattern, text):
                    entities.append(DetectedEntity(
                        text=match.group(),
                        category=category,
                        start=match.start(),
                        end=match.end(),
                        confidence=self.confidence,
                        metadata={'pattern': pattern_name}
                    ))
        
        return entities
    
    def configure(self, config: Dict[str, Any]) -> None:
        """Configure detector"""
        if 'confidence' in config:
            self.confidence = config['confidence']
        if 'enabled_categories' in config:
            self.enabled_patterns = set(config['enabled_categories'])
