"""
base.py — Abstract base class for all DAST scanners.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List


@dataclass
class RawFinding:
    """Represents a raw vulnerability finding from any scanner."""
    title: str
    vuln_type: str
    endpoint: str
    severity: str           # Critical | High | Medium | Low | Info
    description: str = ""
    evidence: str = ""
    confidence: str = "Low" # High | Medium | Low
    scanner_name: str = ""
    extra: dict = field(default_factory=dict)


class BaseScanner(ABC):
    """Abstract scanner — all scanners must implement `scan()`."""

    name: str = "BaseScanner"

    @abstractmethod
    def scan(self, target_url: str, endpoints: List[str]) -> List[RawFinding]:
        """
        Run the scanner against the target.

        Args:
            target_url: The base URL of the target.
            endpoints: List of discovered endpoint URLs.

        Returns:
            List of RawFinding objects.
        """
        raise NotImplementedError

    def is_available(self) -> bool:
        """Check if the underlying tool is installed."""
        return True
