"""
Base Scanner Interface for CLI Multipurpose Security Assessment Modules.
Enforces a uniform contract for all scanners: structured input/output,
active/passive classification, scope validation, and dependency disclosure.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from core.models import ScanResult, ScanStatus
from core.scope import ScopePolicy


class BaseScanner(ABC):
    """Abstract Base Class for all security assessment scanners and detectors."""

    scanner_id: str = "base_scanner"
    name: str = "Base Scanner"
    description: str = "Base scanner implementation"
    version: str = "1.0.0"
    is_active: bool = False
    category: str = "general"
    required_tools: List[str] = []

    def can_run(self, scope: ScopePolicy) -> tuple[bool, str]:
        """
        Pre-flight check verifying if this scanner is permitted to run under the given scope.
        For active checks, scope.active_checks must be True.
        """
        if self.is_active and not scope.active_checks:
            return False, f"Scanner '{self.scanner_id}' requires active intrusive checks, which are disabled in scope."
        return True, "Scanner permitted."

    @abstractmethod
    def run(self, target: str, scope: ScopePolicy, config: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Executes security assessment against the target within the boundaries of scope.
        Returns a standardized ScanResult object.
        """
        pass
