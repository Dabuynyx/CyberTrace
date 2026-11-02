"""CyberTrace Core Exceptions."""

class CyberTraceError(Exception):
    """Base exception for all CyberTrace errors."""
    pass

class EvidenceNotFoundError(CyberTraceError):
    """Raised when specified evidence file or record is not found."""
    pass

class CaseNotFoundError(CyberTraceError):
    """Raised when specified case is not found."""
    pass

class ForensicIntegrityError(CyberTraceError):
    """Raised when evidence hash does not match original acquisition hash."""
    pass

class SecurityBoundaryError(CyberTraceError):
    """Raised when security boundaries (path traversal, file limits) are breached."""
    pass

class AnalysisModuleError(CyberTraceError):
    """Raised when a forensic module encounters an unrecoverable error."""
    pass
