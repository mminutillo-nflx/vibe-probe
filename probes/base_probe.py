"""Base probe class for all OSINT probes"""

from abc import ABC, abstractmethod
from typing import Dict, Any
import logging


class BaseProbe(ABC):
    """Abstract base class for all probes"""

    def __init__(self, target: str, config: Any):
        self.target = target
        self.config = config
        self.logger = logging.getLogger('vibe-probe')

    @abstractmethod
    async def scan(self) -> Dict[str, Any]:
        """Execute the probe and return results"""
        pass

    def _create_finding(
        self,
        severity: str,
        title: str,
        description: str,
        data: Any = None,
        recommendation: str = None
    ) -> Dict[str, Any]:
        """Create a standardized finding"""
        finding = {
            "severity": severity,  # critical, high, medium, low, info
            "title": title,
            "description": description,
        }

        if data is not None:
            finding["data"] = data

        if recommendation:
            finding["recommendation"] = recommendation

        return finding
