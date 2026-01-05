"""Core facade for the PrivacyClient orchestrator.

This module re-exports the main client-side orchestrator types from src.client
so callers can depend on core.client instead of importing src.client directly.
"""

from src.client import PrivacyClient, SecurePromptPackage, ProcessingMetrics

__all__ = ["PrivacyClient", "SecurePromptPackage", "ProcessingMetrics"]
