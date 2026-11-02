"""Forensic utility functions for cryptographic hashing, entropy, and formatting."""

import hashlib
import math
import os
from typing import Dict

def calculate_hashes(file_path: str, chunk_size: int = 65536) -> Dict[str, str]:
    """
    Calculate MD5, SHA-1, and SHA-256 in a single streaming pass to preserve performance 
    and avoid high memory consumption.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }

def calculate_entropy(file_path: str, max_bytes: int = 5 * 1024 * 1024) -> float:
    """
    Calculate Shannon entropy of the file (0.0 to 8.0).
    Values > 7.2 typically indicate compression, packing, or encryption.
    """
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return 0.0

    byte_counts = [0] * 256
    total_bytes = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            for b in chunk:
                byte_counts[b] += 1
            total_bytes += len(chunk)
            if total_bytes >= max_bytes:
                break

    if total_bytes == 0:
        return 0.0

    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p_x = float(count) / total_bytes
            entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)

def format_bytes(size: int) -> str:
    """Human-readable size string."""
    power = 2**10
    n = 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power and n < 4:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"
