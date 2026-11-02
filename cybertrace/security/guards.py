"""Security boundary validation and threat protection for CyberTrace."""

import os
from pathlib import Path
from cybertrace.core.exceptions import SecurityBoundaryError

# Safe defaults
DEFAULT_MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB

def validate_safe_path(base_dir: str, target_path: str) -> Path:
    """
    Prevent path traversal by verifying that the resolved target_path 
    remains within the resolved base_dir.
    """
    base = Path(base_dir).resolve()
    target = Path(target_path).resolve()
    
    try:
        target.relative_to(base)
    except ValueError:
        raise SecurityBoundaryError(f"Path traversal detected: {target_path} is outside allowed directory {base_dir}")
        
    return target

def validate_file_size(file_path: str, max_size_bytes: int = DEFAULT_MAX_FILE_SIZE) -> int:
    """Validate that file does not exceed safe processing limits."""
    size = os.path.getsize(file_path)
    if size > max_size_bytes:
        raise SecurityBoundaryError(
            f"File {file_path} size ({size} bytes) exceeds maximum allowable limit ({max_size_bytes} bytes)"
        )
    return size

def sanitize_for_output(text: str) -> str:
    """Escape control characters and normalize for display."""
    if not isinstance(text, str):
        return str(text)
    return "".join(ch if (ch.isprintable() or ch in "\n\r\t") else f"\\x{ord(ch):02x}" for ch in text)
