"""Module 3: Digital Artifact Analysis (Browser Databases, System Logs, SQLite Forensics)."""

import os
import re
import sqlite3
import time
from typing import Dict, Any, List
from datetime import datetime, timezone, timedelta

from cybertrace.core.interfaces import BaseForensicModule, ModuleResult, Finding

# Chrome/WebKit epoch starts Jan 1, 1601 UTC in microseconds
CHROME_EPOCH_START = datetime(1601, 1, 1, tzinfo=timezone.utc)
# Unix epoch starts Jan 1, 1970 UTC
UNIX_EPOCH_START = datetime(1970, 1, 1, tzinfo=timezone.utc)

def chrome_time_to_iso(microseconds: int) -> str:
    """Convert Chrome WebKit timestamp to standard ISO-8601 UTC string."""
    try:
        dt = CHROME_EPOCH_START + timedelta(microseconds=microseconds)
        return dt.isoformat()
    except Exception:
        return "INVALID_TIMESTAMP"

class ArtifactAnalysisModule(BaseForensicModule):
    """Parses digital forensics artifacts: Browser history, SQLite stores, auth/system logs."""

    @property
    def name(self) -> str:
        return "ArtifactAnalysis"

    @property
    def description(self) -> str:
        return "Parses digital artifacts from browsers (history, downloads), system/auth logs, and forensic SQLite databases."

    def is_available(self) -> bool:
        return True

    def _parse_sqlite_artifact(self, db_path: str) -> Dict[str, Any]:
        """Inspect and parse SQLite artifacts safely in read-only mode."""
        res: Dict[str, Any] = {"tables": {}, "artifact_type": "generic_sqlite", "records": []}
        uri = f"file:{os.path.abspath(db_path)}?mode=ro"
        
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Enumerate tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row["name"] for row in cursor.fetchall()]
            res["table_names"] = tables

            # Detect Chrome / Edge / Brave history database
            if "urls" in tables:
                res["artifact_type"] = "chromium_history"
                cursor.execute("""
                    SELECT urls.url, urls.title, urls.visit_count, urls.last_visit_time
                    FROM urls
                    ORDER BY urls.last_visit_time DESC
                    LIMIT 200;
                """)
                rows = cursor.fetchall()
                for r in rows:
                    res["records"].append({
                        "type": "browser_url",
                        "url": r["url"],
                        "title": r["title"] or "",
                        "visit_count": r["visit_count"],
                        "raw_time": r["last_visit_time"],
                        "timestamp": chrome_time_to_iso(r["last_visit_time"]) if r["last_visit_time"] else None
                    })

                # Check downloads table if present
                if "downloads" in tables:
                    cursor.execute("""
                        SELECT target_path, tab_url, total_bytes, start_time, end_time
                        FROM downloads
                        LIMIT 100;
                    """)
                    d_rows = cursor.fetchall()
                    for dr in d_rows:
                        res["records"].append({
                            "type": "browser_download",
                            "target_path": dr["target_path"],
                            "url": dr["tab_url"],
                            "bytes": dr["total_bytes"],
                            "timestamp": chrome_time_to_iso(dr["start_time"]) if dr["start_time"] else None
                        })

            # Detect Firefox places database
            elif "moz_places" in tables and "moz_historyvisits" in tables:
                res["artifact_type"] = "firefox_history"
                cursor.execute("""
                    SELECT url, title, visit_count, last_visit_date
                    FROM moz_places
                    WHERE last_visit_date IS NOT NULL
                    ORDER BY last_visit_date DESC
                    LIMIT 200;
                """)
                for r in cursor.fetchall():
                    # Firefox uses microseconds since Unix epoch
                    ts_iso = None
                    if r["last_visit_date"]:
                        ts_iso = (UNIX_EPOCH_START + timedelta(microseconds=r["last_visit_date"])).isoformat()
                    res["records"].append({
                        "type": "browser_url",
                        "url": r["url"],
                        "title": r["title"] or "",
                        "visit_count": r["visit_count"],
                        "timestamp": ts_iso
                    })

            conn.close()
        except Exception as e:
            res["error"] = str(e)

        return res

    def _parse_text_logs(self, file_path: str) -> Dict[str, Any]:
        """Extract IPs, usernames, authentications, and event timestamps from system/auth logs."""
        res: Dict[str, Any] = {"artifact_type": "system_log", "records": [], "extracted_ips": set()}
        
        # Regex patterns for common log events
        ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        failed_ssh_pattern = re.compile(r"Failed password for (?:invalid user )?(\w+) from ([0-9.]+)")
        accepted_ssh_pattern = re.compile(r"Accepted \w+ for (\w+) from ([0-9.]+)")
        sudo_pattern = re.compile(r"(\w+) : TTY=.*COMMAND=(.*)")

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[:1000]  # Process initial 1000 lines safely
                for idx, line in enumerate(lines):
                    line_clean = line.strip()
                    if not line_clean:
                        continue

                    # Search for IPs
                    ips = ip_pattern.findall(line_clean)
                    for ip in ips:
                        if not (ip.startswith("127.") or ip == "0.0.0.0"):
                            res["extracted_ips"].add(ip)

                    # Check failed ssh
                    m_failed = failed_ssh_pattern.search(line_clean)
                    if m_failed:
                        res["records"].append({
                            "type": "auth_failure",
                            "username": m_failed.group(1),
                            "ip": m_failed.group(2),
                            "line_num": idx + 1,
                            "raw_event": line_clean[:200]
                        })
                        continue

                    # Check accepted ssh
                    m_acc = accepted_ssh_pattern.search(line_clean)
                    if m_acc:
                        res["records"].append({
                            "type": "auth_success",
                            "username": m_acc.group(1),
                            "ip": m_acc.group(2),
                            "line_num": idx + 1,
                            "raw_event": line_clean[:200]
                        })
                        continue

                    # Check sudo
                    m_sudo = sudo_pattern.search(line_clean)
                    if m_sudo:
                        res["records"].append({
                            "type": "privilege_elevation",
                            "username": m_sudo.group(1),
                            "command": m_sudo.group(2),
                            "line_num": idx + 1,
                            "raw_event": line_clean[:200]
                        })

        except Exception as e:
            res["error"] = str(e)

        res["extracted_ips"] = list(res["extracted_ips"])
        return res

    def analyze(self, target_path: str, **kwargs) -> ModuleResult:
        start_time = time.time()
        findings: List[Finding] = []
        warnings: List[str] = []
        limitations: List[str] = [
            "Log and database parsers extract forensic records within defined boundary limits.",
            "Browser history records reflect local profile state and can be cleared by user activity."
        ]

        if not os.path.exists(target_path):
            return ModuleResult(
                module_name=self.name,
                target_path=target_path,
                status="ERROR",
                warnings=[f"Target does not exist: {target_path}"]
            )

        # Check if file is SQLite database
        is_sqlite = False
        try:
            with open(target_path, "rb") as f:
                header = f.read(16)
                if header.startswith(b"SQLite format 3\x00"):
                    is_sqlite = True
        except Exception:
            pass

        if is_sqlite:
            parsed = self._parse_sqlite_artifact(target_path)
            artifact_type = parsed.get("artifact_type", "sqlite")
            records = parsed.get("records", [])

            if "chromium" in artifact_type:
                findings.append(Finding(
                    category="BROWSER_FORENSICS",
                    title="Chromium-based Navigation History Identified",
                    description=f"Extracted {len(records)} chronological browsing / download entries from SQLite profile store.",
                    severity="INFO",
                    source_technical="cybertrace.modules.artifact_analysis.chromium",
                    supporting_evidence={"total_records": len(records), "sample": records[:5]}
                ))
            elif "firefox" in artifact_type:
                findings.append(Finding(
                    category="BROWSER_FORENSICS",
                    title="Firefox Places Navigation History Identified",
                    description=f"Extracted {len(records)} entries from Firefox places database.",
                    severity="INFO",
                    source_technical="cybertrace.modules.artifact_analysis.firefox",
                    supporting_evidence={"total_records": len(records), "sample": records[:5]}
                ))
            else:
                findings.append(Finding(
                    category="DATABASE_FORENSICS",
                    title="Forensic SQLite Database Store Parsed",
                    description=f"Identified database with tables: {', '.join(parsed.get('table_names', []))}",
                    severity="INFO",
                    source_technical="cybertrace.modules.artifact_analysis.sqlite",
                    supporting_evidence={"tables": parsed.get("table_names", [])}
                ))

            return ModuleResult(
                module_name=self.name,
                target_path=target_path,
                status="SUCCESS",
                execution_time_seconds=round(time.time() - start_time, 4),
                findings=findings,
                raw_metadata=parsed,
                warnings=warnings,
                limitations=limitations
            )

        # Otherwise attempt text/system log parsing
        parsed_logs = self._parse_text_logs(target_path)
        records = parsed_logs.get("records", [])
        extracted_ips = parsed_logs.get("extracted_ips", [])

        if records or extracted_ips:
            auth_failures = [r for r in records if r["type"] == "auth_failure"]
            auth_success = [r for r in records if r["type"] == "auth_success"]

            if auth_failures:
                findings.append(Finding(
                    category="LOG_FORENSICS",
                    title="Authentication Failure Events Detected",
                    description=f"Identified {len(auth_failures)} authentication failure records in log artifact.",
                    severity="MEDIUM" if len(auth_failures) > 5 else "LOW",
                    source_technical="cybertrace.modules.artifact_analysis.logs",
                    supporting_evidence={"total_failures": len(auth_failures), "sample": auth_failures[:5]}
                ))

            if extracted_ips:
                findings.append(Finding(
                    category="LOG_FORENSICS",
                    title="External IP Addresses Extracted from Log",
                    description=f"Extracted {len(extracted_ips)} distinct IP addresses from event traces.",
                    severity="INFO",
                    source_technical="cybertrace.modules.artifact_analysis.logs",
                    supporting_evidence={"ips": extracted_ips[:20]}
                ))

        return ModuleResult(
            module_name=self.name,
            target_path=target_path,
            status="SUCCESS",
            execution_time_seconds=round(time.time() - start_time, 4),
            findings=findings,
            raw_metadata=parsed_logs,
            warnings=warnings,
            limitations=limitations
        )
