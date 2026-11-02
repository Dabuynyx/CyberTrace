"""Automated comprehensive test suite for CyberTrace."""

import os
import sqlite3
import tempfile
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cybertrace.database.models import Base, CaseModel, EvidenceModel
from cybertrace.case_management.manager import CaseManager
from cybertrace.core.engine import ForensicEngine
from cybertrace.modules.file_intelligence.analyzer import FileIntelligenceModule
from cybertrace.modules.metadata_forensics.analyzer import MetadataForensicsModule
from cybertrace.modules.malware_triage.analyzer import MalwareTriageModule
from cybertrace.modules.artifact_analysis.analyzer import ArtifactAnalysisModule
from cybertrace.modules.reporting.generator import ForensicReportGenerator
from cybertrace.utils.crypto import calculate_hashes, calculate_entropy
from cybertrace.security.guards import validate_safe_path, validate_file_size, SecurityBoundaryError

def test_cryptographic_hashes_and_entropy():
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
    finally:
        os.unlink(temp_name)

def test_file_intelligence_module():
    # Test ELF header recognition
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
    # Write a PE executable but name it innocent.png
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

def test_artifact_analysis_sqlite():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("CREATE TABLE urls (url TEXT, title TEXT, visit_count INT, last_visit_time INT);")
    c.execute("INSERT INTO urls VALUES ('https://malicious-c2.test', 'Malicious Portal', 3, 13350000000000000);")
    conn.commit()
    conn.close()

    try:
        mod = ArtifactAnalysisModule()
        res = mod.analyze(db_path)
        assert res.status == "SUCCESS"
        assert res.raw_metadata["artifact_type"] == "chromium_history"
        assert len(res.raw_metadata["records"]) >= 1
    finally:
        os.unlink(db_path)

def test_security_guards():
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
