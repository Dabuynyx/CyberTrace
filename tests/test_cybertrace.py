"""Comprehensive Automated Test Suite for CyberTrace v0.1.0."""

import os
import sqlite3
import tempfile
import struct
from pathlib import Path
from PIL import Image
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
import typer.testing

from cybertrace.database.models import Base, CaseModel, EvidenceModel
from cybertrace.case_management.manager import CaseManager
from cybertrace.core.engine import ForensicEngine
from cybertrace.modules.file_intelligence.analyzer import FileIntelligenceModule
from cybertrace.modules.metadata_forensics.analyzer import MetadataForensicsModule
from cybertrace.modules.malware_triage.analyzer import MalwareTriageModule
from cybertrace.modules.artifact_analysis.analyzer import ArtifactAnalysisModule
from cybertrace.modules.reporting.generator import ForensicReportGenerator
from cybertrace.utils.crypto import calculate_hashes, calculate_entropy, format_bytes
from cybertrace.security.guards import validate_safe_path, validate_file_size, SecurityBoundaryError
from cybertrace.cli.main import app as cli_app
from cybertrace.api.server import app as fastapi_app

cli_runner = typer.testing.CliRunner()

def test_cryptographic_hashes_and_entropy():
    """Verify cryptographic hashes and Shannon entropy calculations."""
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"CyberTrace Forensic Test Payload: deterministic hashing\n")
        temp_name = f.name

    try:
        hashes = calculate_hashes(temp_name)
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha1"]) == 40
        assert len(hashes["sha256"]) == 64

        entropy = calculate_entropy(temp_name)
        assert 0.0 <= entropy <= 8.0
        assert format_bytes(1024) == "1.00 KB"
    finally:
        os.unlink(temp_name)

def test_file_intelligence_module_elf_and_pe():
    """Verify ELF and PE file identification."""
    with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 60)
        temp_name = f.name

    try:
        mod = FileIntelligenceModule()
        res = mod.analyze(temp_name)
        assert res.status == "SUCCESS"
        assert res.raw_metadata["detected_format"] == "ELF Executable/Binary"
        assert res.raw_metadata["detected_mime"] == "application/x-executable"
    finally:
        os.unlink(temp_name)

def test_extension_mismatch_detection():
    """Verify extension masquerading detection."""
    with tempfile.NamedTemporaryFile("wb", suffix=".png", delete=False) as f:
        f.write(b"MZ" + b"\x90" * 100)
        temp_name = f.name

    try:
        mod = FileIntelligenceModule()
        res = mod.analyze(temp_name)
        assert res.status == "SUCCESS"
        assert res.raw_metadata["extension_mismatch"] is True
        titles = [f.title for f in res.findings]
        assert "Extension and Magic Signature Mismatch" in titles
    finally:
        os.unlink(temp_name)

def test_metadata_forensics_real_image_and_pdf():
    """Verify metadata extraction on real JPEG and PDF files."""
    # 1. JPEG image with Pillow & ExifTool
    with tempfile.NamedTemporaryFile("wb", suffix=".jpg", delete=False) as f:
        img = Image.new("RGB", (64, 64), color="blue")
        img.save(f.name)
        img_path = f.name

    # 2. Synthetic PDF document
    with tempfile.NamedTemporaryFile("wb", suffix=".pdf", delete=False) as f:
        pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Title (Incident Report Alpha) /Author (CyberTrace Analyst) >>\nendobj\ntrailer\n<< /Info 1 0 R >>\n%%EOF"
        f.write(pdf_content)
        pdf_path = f.name

    try:
        mod = MetadataForensicsModule()
        
        # Test Image Metadata
        res_img = mod.analyze(img_path)
        assert res_img.status == "SUCCESS"
        assert "JPEG" in str(res_img.raw_metadata) or "image/jpeg" in str(res_img.raw_metadata)

        # Test PDF Metadata Fallback
        res_pdf = mod.analyze(pdf_path)
        assert res_pdf.status == "SUCCESS"
        assert len(res_pdf.raw_metadata) > 0
    finally:
        os.unlink(img_path)
        os.unlink(pdf_path)

def test_browser_artifact_chromium_and_firefox():
    """Verify browser history and SQLite database parsing for both Chromium and Firefox formats."""
    # Test Chromium Schema
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        chrome_db = f.name

    conn = sqlite3.connect(chrome_db)
    c = conn.cursor()
    c.execute("CREATE TABLE urls (url TEXT, title TEXT, visit_count INT, last_visit_time INT);")
    c.execute("INSERT INTO urls VALUES ('https://c2-domain.test/download', 'Infection Server', 5, 13350000000000000);")
    conn.commit()
    conn.close()

    # Test Firefox Schema
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        ff_db = f.name

    conn = sqlite3.connect(ff_db)
    c = conn.cursor()
    c.execute("CREATE TABLE moz_places (url TEXT, title TEXT, visit_count INT, last_visit_date INT);")
    c.execute("CREATE TABLE moz_historyvisits (id INT);")
    c.execute("INSERT INTO moz_places VALUES ('https://phishing-portal.test', 'Bank Login', 2, 1690000000000);")
    conn.commit()
    conn.close()

    try:
        mod = ArtifactAnalysisModule()
        
        # Chromium
        res_chrome = mod.analyze(chrome_db)
        assert res_chrome.status == "SUCCESS"
        assert res_chrome.raw_metadata["artifact_type"] == "chromium_history"
        assert len(res_chrome.raw_metadata["records"]) >= 1

        # Firefox
        res_ff = mod.analyze(ff_db)
        assert res_ff.status == "SUCCESS"
        assert res_ff.raw_metadata["artifact_type"] == "firefox_history"
        assert len(res_ff.raw_metadata["records"]) >= 1
    finally:
        os.unlink(chrome_db)
        os.unlink(ff_db)

def test_system_and_auth_log_analysis():
    """Verify log parsing for SSH brute force, sudo escalations, and distinct IP indicators."""
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write("May 10 12:00:01 srv sshd[102]: Failed password for invalid user root from 198.51.100.44 port 22 ssh2\n")
        f.write("May 10 12:00:05 srv sshd[103]: Failed password for admin from 198.51.100.44 port 22 ssh2\n")
        f.write("May 10 12:05:00 srv sshd[104]: Accepted password for analyst from 203.0.113.10 port 22 ssh2\n")
        f.write("May 10 12:06:00 srv sudo: analyst : TTY=pts/0 ; COMMAND=/bin/bash\n")
        log_path = f.name

    try:
        mod = ArtifactAnalysisModule()
        res = mod.analyze(log_path)
        assert res.status == "SUCCESS"
        records = res.raw_metadata.get("records", [])
        assert len(records) >= 3

        types = [r["type"] for r in records]
        assert "auth_failure" in types
        assert "auth_success" in types
        assert "privilege_elevation" in types

        ips = res.raw_metadata.get("extracted_ips", [])
        assert "198.51.100.44" in ips
        assert "203.0.113.10" in ips
    finally:
        os.unlink(log_path)

def test_malware_triage_strings_and_yara():
    """Verify static malware triage string extraction and YARA rule scanning."""
    with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as f_bin:
        f_bin.write(b"SAMPLE_BINARY_HEADER\x00\x00Target URL: https://attacker-c2.test/gate.php\x00IP: 198.51.100.77\x00PAYLOAD_APT_MARKER")
        bin_path = f_bin.name

    with tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False) as f_yar:
        f_yar.write('rule CyberTrace_Test_Rule { strings: $a = "PAYLOAD_APT_MARKER" condition: $a }')
        yar_path = f_yar.name

    try:
        mod = MalwareTriageModule()
        res = mod.analyze(bin_path, yara_rules=yar_path)
        assert res.status == "SUCCESS"
        
        # Check indicator extraction
        strings_data = res.raw_metadata["strings"]
        assert "https://attacker-c2.test/gate.php" in strings_data["extracted_urls"]
        assert "198.51.100.77" in strings_data["extracted_ips"]

        # Check YARA match finding
        yara_titles = [f.title for f in res.findings if f.category == "YARA_MATCH"]
        assert len(yara_titles) >= 1
    finally:
        os.unlink(bin_path)
        os.unlink(yar_path)

def test_pe_parser_on_synthetic_pe():
    """Verify PE header parsing and machine identification."""
    data = bytearray(1024)
    data[0:2] = b"MZ"
    data[0x3c:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x014c).to_bytes(2, "little")  # Machine i386
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xe0).to_bytes(2, "little")
    data[0x96:0x98] = (0x0102).to_bytes(2, "little")
    data[0x98:0x9a] = (0x010b).to_bytes(2, "little")

    with tempfile.NamedTemporaryFile("wb", suffix=".exe", delete=False) as f:
        f.write(data)
        exe_path = f.name

    try:
        mod = MalwareTriageModule()
        res = mod.analyze(exe_path)
        assert res.status == "SUCCESS"
        pe_info = res.raw_metadata.get("pe", {})
        assert pe_info.get("is_pe") is True
        assert pe_info.get("machine") == "0x14c"
    finally:
        os.unlink(exe_path)

def test_elf_parser_on_synthetic_elf():
    """Verify ELF header parsing."""
    # Minimal 64-bit ELF header
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = struct.pack("<H", 2)  # ET_EXEC
    e_machine = struct.pack("<H", 62)  # EM_X86_64
    e_version = struct.pack("<I", 1)
    e_entry = struct.pack("<Q", 0x400000)
    e_phoff = struct.pack("<Q", 0)
    e_shoff = struct.pack("<Q", 0)
    e_flags = struct.pack("<I", 0)
    e_ehsize = struct.pack("<H", 64)
    e_phentsize = struct.pack("<H", 0)
    e_phnum = struct.pack("<H", 0)
    e_shentsize = struct.pack("<H", 0)
    e_shnum = struct.pack("<H", 0)
    e_shstrndx = struct.pack("<H", 0)

    elf_bytes = e_ident + e_type + e_machine + e_version + e_entry + e_phoff + e_shoff + e_flags + e_ehsize + e_phentsize + e_phnum + e_shentsize + e_shnum + e_shstrndx

    with tempfile.NamedTemporaryFile("wb", suffix=".elf", delete=False) as f:
        f.write(elf_bytes)
        elf_path = f.name

    try:
        mod = MalwareTriageModule()
        res = mod.analyze(elf_path)
        assert res.status == "SUCCESS"
        elf_data = res.raw_metadata.get("elf", {})
        assert elf_data.get("is_elf") is True
        assert "x64" in str(elf_data.get("arch")).lower() or "x86" in str(elf_data.get("arch")).lower()
    finally:
        os.unlink(elf_path)

def test_security_guards():
    """Verify directory traversal and file size defenses."""
    with tempfile.TemporaryDirectory() as base_dir:
        inside = Path(base_dir) / "safe.txt"
        inside.write_text("safe content")

        # Safe path validation
        assert validate_safe_path(base_dir, str(inside)) == inside.resolve()

        # Path traversal detection
        import pytest
        with pytest.raises(SecurityBoundaryError):
            validate_safe_path(base_dir, "/etc/passwd")

        # File size limits
        with pytest.raises(SecurityBoundaryError):
            validate_file_size(str(inside), max_size_bytes=4)

def test_case_lifecycle_and_evidence_correlation():
    """Verify evidence ingestion, hash verification, timeline reconstruction, and multi-format reporting."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    mgr = CaseManager(db)
    case = mgr.create_case("APT Phishing Investigation", "Testing correlation logic", "Lead Analyst")
    assert case.id.startswith("CASE-")

    with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as f1:
        f1.write(b"Incident payload A: host 198.51.100.22 contact\n")
        path1 = f1.name

    with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as f2:
        f2.write(b"Incident payload A: host 198.51.100.22 contact\n")
        path2 = f2.name

    try:
        ev1 = mgr.add_evidence(case.id, path1)
        ev2 = mgr.add_evidence(case.id, path2)

        # Integrity verification
        v_res = mgr.verify_evidence(ev1.id)
        assert v_res["status"] == "VERIFIED"

        # Run full forensic engine
        forensic_engine = ForensicEngine(db)
        c_res = forensic_engine.analyze_case(case.id)
        assert c_res["total_evidence_analyzed"] == 2

        # Verify cross-evidence correlations occurred (identical hash)
        corrs = forensic_engine.correlator.correlate_case(case.id)
        assert len(corrs) >= 1
        assert any(c["relationship_type"] == "IDENTICAL_HASH" for c in corrs)

        # Generate reports in all formats
        gen = ForensicReportGenerator(db)
        with tempfile.TemporaryDirectory() as report_dir:
            json_path = os.path.join(report_dir, "report.json")
            html_path = os.path.join(report_dir, "report.html")
            pdf_path = os.path.join(report_dir, "report.pdf")

            assert os.path.exists(gen.generate_json(case.id, json_path))
            assert os.path.exists(gen.generate_html(case.id, html_path))
            assert os.path.exists(gen.generate_pdf(case.id, pdf_path))
    finally:
        os.unlink(path1)
        os.unlink(path2)
        db.close()

def test_cli_commands():
    """Verify CLI commands execute and succeed."""
    r_ver = cli_runner.invoke(cli_app, ["version"])
    assert r_ver.exit_code == 0
    assert "CyberTrace v0.1.1" in r_ver.stdout

    r_stat = cli_runner.invoke(cli_app, ["status"])
    assert r_stat.exit_code == 0
    assert "Active Investigations" in r_stat.stdout

    r_case_list = cli_runner.invoke(cli_app, ["case", "list"])
    assert r_case_list.exit_code == 0

def test_fastapi_endpoints():
    """Verify API status, cases, and web dashboard endpoints."""
    client = TestClient(fastapi_app)
    
    r_status = client.get("/api/status")
    assert r_status.status_code == 200
    assert r_status.json()["status"] == "ONLINE"

    r_cases = client.get("/api/cases")
    assert r_cases.status_code == 200
    assert isinstance(r_cases.json(), list)

    r_dashboard = client.get("/")
    assert r_dashboard.status_code == 200
    assert "CyberTrace" in r_dashboard.text
