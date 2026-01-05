"""
Branch: Hybrid PII Detector

Ensemble detector combining multiple strategies.
Suitable for: production, high accuracy requirements
"""
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from typing import List, Dict, Any
from core.skeleton import IPIIDetector, DetectedEntity, PIICategory


class HybridDetector(IPIIDetector):
    """
    Hybrid ensemble detector
    
    Combines:
    - Regex for structured PII (high precision)
    - Transformer for contextual PII (high recall)
    - Voting/merging strategy
    """
    
    def __init__(self, detectors: List[IPIIDetector]):
        self.detectors = detectors
        self.merge_strategy = 'union'  # or 'intersection', 'voting'
    
    def detect(self, text: str) -> List[DetectedEntity]:
        """Run all detectors and merge results"""
        all_entities = []
        
        for detector in self.detectors:
            entities = detector.detect(text)
            all_entities.extend(entities)
        
        # Merge overlapping entities
        merged = self._merge_entities(all_entities)
        return merged
    
    def _merge_entities(self, entities: List[DetectedEntity]) -> List[DetectedEntity]:
        """Merge overlapping entities"""
        if not entities:
            return []
        
        # Sort by start position
        sorted_entities = sorted(entities, key=lambda e: e.start)
        merged = [sorted_entities[0]]
        
        for entity in sorted_entities[1:]:
            last = merged[-1]
            
            # Check overlap
            if entity.start <= last.end:
                # Keep higher confidence entity
                if entity.confidence > last.confidence:
                    merged[-1] = entity
            else:
                merged.append(entity)
        
        return merged
    
    def configure(self, config: Dict[str, Any]) -> None:
        """Configure ensemble"""
        if 'merge_strategy' in config:
            self.merge_strategy = config['merge_strategy']
        
        # Configure child detectors
        for detector in self.detectors:
            detector.configure(config)
