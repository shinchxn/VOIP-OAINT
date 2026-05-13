"""
VoIP OSINT APEX — Core Plugin Architecture
Defines the interface for all investigative modules.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class PluginMetadata:
    name: str
    version: str
    description: str
    author: str
    category: str  # e.g., "intel", "network", "forensic"
    dependencies: List[str] = field(default_factory=list)
    requires_api_key: Optional[str] = None

class BasePlugin(ABC):
    """
    Abstract Base Class for all VoIP OSINT APEX plugins.
    Ensures consistent interface for the pipeline orchestrator.
    """

    def __init__(self):
        self.metadata = self.get_metadata()
        self.enabled = True
        self._results = {}

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin identification and requirements."""
        pass

    @abstractmethod
    async def run(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute the primary investigative logic.
        
        Args:
            target: The primary target (Phone Number, IP, Domain, or File Path).
            context: Shared investigative context (e.g., previous results, API keys).
            
        Returns:
            Dictionary containing findings and risk markers.
        """
        pass

    def validate_target(self, target: str) -> bool:
        """Check if the target format is valid for this plugin."""
        return True

    def get_results(self) -> Dict[str, Any]:
        """Return the last execution results."""
        return self._results
