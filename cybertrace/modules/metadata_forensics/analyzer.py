"""Module 2: Advanced Metadata Forensics with ExifTool & Native Fallback."""

import os
import json
import shutil
import subprocess
import time
from typing import Dict, Any, List
from PIL import Image, ExifTags

from cybertrace.core.interfaces import BaseForensicModule, ModuleResult, Finding

class MetadataForensicsModule(BaseForensicModule):
    """Deep metadata extraction, camera/device profiling, and timestamp inconsistency checks."""

    def __init__(self):
        self.exiftool_bin = shutil.which("exiftool")

    @property
    def name(self) -> str:
        return "MetadataForensics"

    @property
    def description(self) -> str:
        return "Extracts and audits document, image, and media metadata; detects chronological inconsistencies and device traces."

    def is_available(self) -> bool:
        return True

    def _run_exiftool(self, file_path: str) -> Dict[str, Any]:
        """Safely extract metadata via ExifTool subprocess without shell=True."""
        if not self.exiftool_bin:
            return {}
        try:
            cmd = [self.exiftool_bin, "-json", "-G", file_path]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False
            )
            if proc.returncode == 0 and proc.stdout:
                parsed = json.loads(proc.stdout)
                if isinstance(parsed, list) and len(parsed) > 0:
                    return parsed[0]
        except Exception:
            pass
        return {}

    def _run_pillow_fallback(self, file_path: str) -> Dict[str, Any]:
        """Native Python Pillow fallback for image metadata."""
        meta: Dict[str, Any] = {}
        try:
            with Image.open(file_path) as img:
                meta["Image:Format"] = img.format
                meta["Image:Mode"] = img.mode
                meta["Image:Width"] = img.width
                meta["Image:Height"] = img.height

                exif = img.getexif()
                if exif:
                    for tag_id, value in exif.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                        # Filter binary/bytes for serialization
                        if isinstance(value, bytes):
                            meta[f"EXIF:{tag_name}"] = value.hex()[:64]
                        else:
                            meta[f"EXIF:{tag_name}"] = str(value)
        except Exception:
            pass
        return meta

    def analyze(self, target_path: str, **kwargs) -> ModuleResult:
        start_time = time.time()
        findings: List[Finding] = []
        warnings: List[str] = []
        limitations: List[str] = [
            "Metadata can be stripped or forged by anti-forensics tools; observed values reflect embedded headers only.",
            "Timestamp inconsistencies suggest potential clock skew, time zone mismatch, or alteration, but are not definitive proof of manipulation."
        ]

        if not os.path.exists(target_path):
            return ModuleResult(
                module_name=self.name,
                target_path=target_path,
                status="ERROR",
                warnings=[f"Target does not exist: {target_path}"]
            )

        metadata: Dict[str, Any] = {}
        source_used = "native"

        if self.exiftool_bin:
            metadata = self._run_exiftool(target_path)
            if metadata:
                source_used = "exiftool"
            else:
                warnings.append("ExifTool returned empty metadata; attempting native fallback.")
                metadata = self._run_pillow_fallback(target_path)
        else:
            warnings.append("ExifTool is not installed on host. Running native Python fallback parser.")
            metadata = self._run_pillow_fallback(target_path)

        # Analyze extracted metadata
        # 1. GPS coordinates extraction
        gps_lat = None
        gps_lon = None
        for k, v in metadata.items():
            k_lower = k.lower()
            if "gpslatitude" in k_lower and "ref" not in k_lower:
                gps_lat = v
            elif "gpslongitude" in k_lower and "ref" not in k_lower:
                gps_lon = v

        if gps_lat is not None and gps_lon is not None:
            findings.append(Finding(
                category="METADATA_GEOLOCATION",
                title="Geographical Coordinates Discovered in Metadata",
                description=f"Artifact contains embedded GPS coordinates: Lat {gps_lat}, Lon {gps_lon}.",
                severity="LOW",
                source_technical=f"{source_used}:GPS",
                supporting_evidence={"latitude": str(gps_lat), "longitude": str(gps_lon)}
            ))

        # 2. Camera / Device fingerprinting
        make = None
        model = None
        software = None
        for k, v in metadata.items():
            k_lower = k.lower()
            if "make" in k_lower:
                make = v
            elif "model" in k_lower and "lens" not in k_lower:
                model = v
            elif "software" in k_lower or "creator" in k_lower or "producer" in k_lower:
                software = v

        if make or model:
            findings.append(Finding(
                category="METADATA_DEVICE",
                title="Device Hardware Fingerprint Discovered",
                description=f"Artifact was captured or modified with hardware: {make or ''} {model or ''}".strip(),
                severity="INFO",
                source_technical=f"{source_used}:HardwareProfile",
                supporting_evidence={"make": str(make), "model": str(model)}
            ))

        if software:
            findings.append(Finding(
                category="METADATA_SOFTWARE",
                title="Authoring/Editing Software Identified",
                description=f"Embedded software/tool signature detected: {software}",
                severity="INFO",
                source_technical=f"{source_used}:SoftwareSignature",
                supporting_evidence={"software": str(software)}
            ))

        # 3. Timestamp analysis & inconsistency detection
        create_date = None
        modify_date = None
        for k, v in metadata.items():
            k_lower = k.lower()
            if "createdate" in k_lower or "datetimeoriginal" in k_lower:
                create_date = str(v)
            elif "modifydate" in k_lower or "filemodifydate" in k_lower:
                modify_date = str(v)

        if create_date and modify_date:
            # Check string comparison if dates are in standard YYYY:MM:DD HH:MM:SS format
            # If modify date is strictly before creation date, that is an anomaly
            clean_create = create_date.split("+")[0].strip()
            clean_modify = modify_date.split("+")[0].strip()
            if clean_create and clean_modify and len(clean_create) >= 10 and len(clean_modify) >= 10:
                if clean_modify < clean_create:
                    findings.append(Finding(
                        category="METADATA_INCONSISTENCY",
                        title="Chronological Timestamp Anomaly Detected",
                        description=f"Recorded modification timestamp ({modify_date}) precedes creation timestamp ({create_date}).",
                        severity="MEDIUM",
                        source_technical=f"{source_used}:TimestampAuditor",
                        supporting_evidence={"create_date": create_date, "modify_date": modify_date},
                        limitations="Clock resetting, time zone normalization shifts, or metadata alteration can produce this pattern."
                    ))

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
