"""Module 1: File Intelligence & Signature Verification."""

import os
import time
from pathlib import Path
from typing import Dict, Any, List

from cybertrace.core.interfaces import BaseForensicModule, ModuleResult, Finding
from cybertrace.utils.crypto import calculate_hashes, calculate_entropy, format_bytes

# Magic bytes signature database for local deterministic identification
MAGIC_SIGNATURES = [
    (b"\x7fELF", "application/x-executable", "ELF Executable/Binary", [".elf", ".bin", ""]),
    (b"MZ", "application/x-dosexec", "PE Windows Executable/DLL", [".exe", ".dll", ".sys", ".scr"]),
    (b"%PDF-", "application/pdf", "PDF Document", [".pdf"]),
    (b"PK\x03\x04", "application/zip", "ZIP Archive or ZIP-based container", [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]),
    (b"\x1f\x8b\x08", "application/gzip", "GZIP Compressed Archive", [".gz", ".tgz"]),
    (b"Rar!\x1a\x07\x00", "application/x-rar-compressed", "RAR Archive v4", [".rar"]),
    (b"Rar!\x1a\x07\x01\x00", "application/x-rar-compressed", "RAR Archive v5", [".rar"]),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip Archive", [".7z"]),
    (b"\xff\xd8\xff", "image/jpeg", "JPEG Image", [".jpg", ".jpeg"]),
    (b"\x89PNG\r\n\x1a\n", "image/png", "PNG Image", [".png"]),
    (b"GIF87a", "image/gif", "GIF Image (87a)", [".gif"]),
    (b"GIF89a", "image/gif", "GIF Image (89a)", [".gif"]),
    (b"SQLite format 3\x00", "application/vnd.sqlite3", "SQLite 3 Database", [".db", ".sqlite", ".sqlite3"]),
    (b"\xca\xfe\xba\xbe", "application/java-vm", "Java Class or Mach-O Universal Binary", [".class", ".dylib", ""]),
    (b"\xfe\xed\xfa\xce", "application/x-mach-binary", "Mach-O 32-bit", [""]),
    (b"\xfe\xed\xfa\xcf", "application/x-mach-binary", "Mach-O 64-bit", [""]),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary", "Mach-O 64-bit (reverse byte order)", [""]),
    (b"<!DOCTYPE html", "text/html", "HTML Document", [".html", ".htm"]),
    (b"<html", "text/html", "HTML Document", [".html", ".htm"]),
    (b"<?xml", "application/xml", "XML Document", [".xml"]),
    (b"{\"", "application/json", "JSON Document", [".json"]),
    (b"[{\"", "application/json", "JSON Document", [".json"]),
    (b"#!\x2f", "text/x-shellscript", "Shell Script (Shebang)", [".sh", ".bash", ".py", ".pl"]),
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf", 
    ".wsh", ".hta", ".cmd", ".bat", ".ps1", ".jar", ".cpl", ".iso"
}

class FileIntelligenceModule(BaseForensicModule):
    """Deep file intelligence: signature, MIME type, hashes, entropy, and extension validation."""

    @property
    def name(self) -> str:
        return "FileIntelligence"

    @property
    def description(self) -> str:
        return "Deterministic file signature matching, cryptographic hashing, entropy analysis, and extension validation."

    def is_available(self) -> bool:
        return True

    def identify_magic(self, file_path: str) -> Dict[str, Any]:
        """Detect file format using magic bytes."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(512)
        except Exception as e:
            return {"error": str(e), "mime_type": "application/octet-stream", "format": "Unknown (Read Error)"}

        for magic_bytes, mime, fmt, valid_exts in MAGIC_SIGNATURES:
            if header.startswith(magic_bytes):
                return {
                    "mime_type": mime,
                    "format": fmt,
                    "valid_extensions": valid_exts,
                    "matched_magic_hex": magic_bytes.hex()
                }

        # Check for plain ASCII / UTF-8 text
        try:
            header.decode("utf-8")
            return {
                "mime_type": "text/plain",
                "format": "Plain Text (UTF-8 / ASCII)",
                "valid_extensions": [".txt", ".log", ".conf", ".cfg", ".csv"],
                "matched_magic_hex": ""
            }
        except UnicodeDecodeError:
            pass

        return {
            "mime_type": "application/octet-stream",
            "format": "Unknown Binary or Raw Data",
            "valid_extensions": [".bin", ".dat"],
            "matched_magic_hex": header[:8].hex() if header else ""
        }

    def analyze(self, target_path: str, **kwargs) -> ModuleResult:
        start_time = time.time()
        findings: List[Finding] = []
        warnings: List[str] = []
        limitations: List[str] = [
            "Signature identification is based on the first 512 bytes header database.",
            "Files with non-standard wrappers or obfuscated headers may require deeper unpacking."
        ]

        if not os.path.exists(target_path):
            return ModuleResult(
                module_name=self.name,
                target_path=target_path,
                status="ERROR",
                warnings=[f"File does not exist: {target_path}"]
            )

        file_stat = os.stat(target_path)
        file_size = file_stat.st_size
        hashes = calculate_hashes(target_path)
        entropy = calculate_entropy(target_path)
        magic_info = self.identify_magic(target_path)

        path_obj = Path(target_path)
        declared_ext = path_obj.suffix.lower()

        # Check for extension vs header mismatch
        valid_exts = magic_info.get("valid_extensions", [])
        mismatch = False
        if valid_exts and declared_ext and declared_ext not in valid_exts:
            # Special case: .bin / empty extension might be intentional
            if declared_ext != ".bin":
                mismatch = True
                findings.append(Finding(
                    category="FILE_INTELLIGENCE",
                    title="Extension and Magic Signature Mismatch",
                    description=f"File extension '{declared_ext}' does not match detected format '{magic_info.get('format')}'. This often indicates file masquerading or intentional obfuscation.",
                    severity="HIGH",
                    source_technical="cybertrace.modules.file_intelligence",
                    supporting_evidence={
                        "declared_extension": declared_ext,
                        "detected_format": magic_info.get("format"),
                        "expected_extensions": valid_exts,
                        "magic_bytes": magic_info.get("matched_magic_hex")
                    }
                ))

        # Check for double extension
        file_name = path_obj.name
        suffixes = path_obj.suffixes
        if len(suffixes) > 1:
            findings.append(Finding(
                category="FILE_INTELLIGENCE",
                title="Multiple File Extensions Detected",
                description=f"File has compound extensions '{'.'.join(suffixes)}', which is frequently used in phishing/social engineering attacks.",
                severity="MEDIUM",
                source_technical="cybertrace.modules.file_intelligence",
                supporting_evidence={"extensions": suffixes, "filename": file_name}
            ))

        # High entropy check
        if entropy > 7.2:
            findings.append(Finding(
                category="FILE_INTELLIGENCE",
                title="High Shannon Entropy Detected",
                description=f"File entropy is {entropy}/8.0, indicating packed, encrypted, or highly compressed content.",
                severity="MEDIUM",
                source_technical="cybertrace.utils.crypto.calculate_entropy",
                supporting_evidence={"entropy": entropy, "threshold": 7.2}
            ))

        # Suspicious executable extension
        if declared_ext in SUSPICIOUS_EXTENSIONS:
            findings.append(Finding(
                category="FILE_INTELLIGENCE",
                title="Executable or Script Extension",
                description=f"The extension '{declared_ext}' is an executable/scripting format capable of running arbitrary commands on host systems.",
                severity="LOW",
                source_technical="cybertrace.modules.file_intelligence",
                supporting_evidence={"extension": declared_ext}
            ))

        metadata = {
            "file_name": file_name,
            "file_size_bytes": file_size,
            "file_size_human": format_bytes(file_size),
            "hashes": hashes,
            "entropy": entropy,
            "detected_mime": magic_info.get("mime_type"),
            "detected_format": magic_info.get("format"),
            "declared_extension": declared_ext,
            "extension_mismatch": mismatch,
            "filesystem_timestamps": {
                "created": file_stat.st_ctime,
                "modified": file_stat.st_mtime,
                "accessed": file_stat.st_atime
            }
        }

        return ModuleResult(
            module_name=self.name,
            target_path=target_path,
            status="SUCCESS",
            execution_time_seconds=round(time.time() - start_time, 4),
            findings=findings,
            raw_metadata=metadata,
            warnings=warnings,
            limitations=limitations
        )
