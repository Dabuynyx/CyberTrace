"""Core interfaces and data models for CyberTrace forensic modules."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class Finding(BaseModel):
    """Structured forensic finding backed by technical observations."""
    category: str
    title: str
    description: str
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    source_technical: str
    supporting_evidence: Dict[str, Any] = Field(default_factory=dict)
    limitations: Optional[str] = None
    timestamp: str = Field(default_factory=utc_now_iso)

class ModuleResult(BaseModel):
    """Standardized output from any forensic analysis module."""
    module_name: str
    target_path: str
    status: str = "SUCCESS"  # SUCCESS, PARTIAL, ERROR
    execution_time_seconds: float = 0.0
    findings: List[Finding] = Field(default_factory=list)
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    analyzed_at: str = Field(default_factory=utc_now_iso)

class BaseForensicModule(ABC):
    """Abstract base class for all forensic analysis modules."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Module name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Module description."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if optional system tools / dependencies are present."""
        pass

    @abstractmethod
    def analyze(self, target_path: str, **kwargs) -> ModuleResult:
        """Run analysis on target file and return structured ModuleResult."""
        pass
