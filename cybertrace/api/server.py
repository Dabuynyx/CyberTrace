"""FastAPI Backend Server & Web Dashboard Router for CyberTrace."""

import os
import shutil
from typing import List, Optional
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from cybertrace.database.models import init_db, get_db, CaseModel, EvidenceModel, FindingModel, CorrelationModel, TimelineEventModel
from cybertrace.case_management.manager import CaseManager
from cybertrace.core.engine import ForensicEngine
from cybertrace.modules.reporting.generator import ForensicReportGenerator
from cybertrace.modules.file_intelligence.analyzer import FileIntelligenceModule
from cybertrace.modules.metadata_forensics.analyzer import MetadataForensicsModule
from cybertrace.modules.malware_triage.analyzer import MalwareTriageModule
from cybertrace.modules.artifact_analysis.analyzer import ArtifactAnalysisModule

init_db()

app = FastAPI(
    title="CyberTrace API",
    description="Digital Forensics & Investigation Framework API",
    version="0.1.0"
)

# Schemas
class CaseCreateSchema(BaseModel):
    title: str
    description: Optional[str] = ""
    investigator: Optional[str] = "Forensic Analyst"

# Static files and frontend template paths
FRONTEND_DIR = Path(__file__).parent.parent.parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/api/status")
def get_system_status(db: Session = Depends(get_db)):
    """Fetch live system and repository stats."""
    cases_cnt = db.query(CaseModel).count()
    ev_cnt = db.query(EvidenceModel).count()
    findings_cnt = db.query(FindingModel).count()
    correlations_cnt = db.query(CorrelationModel).count()

    return {
        "status": "ONLINE",
        "version": "0.1.0",
        "total_cases": cases_cnt,
        "total_evidence": ev_cnt,
        "total_findings": findings_cnt,
        "total_correlations": correlations_cnt,
        "storage_location": str(Path.home() / ".cybertrace")
    }

@app.get("/api/cases")
def list_cases(db: Session = Depends(get_db)):
    mgr = CaseManager(db)
    return mgr.list_cases()

@app.post("/api/cases")
def create_case(payload: CaseCreateSchema, db: Session = Depends(get_db)):
    mgr = CaseManager(db)
    case = mgr.create_case(payload.title, payload.description or "", payload.investigator or "Forensic Analyst")
    return case

@app.get("/api/cases/{case_id}")
def get_case_detail(case_id: str, db: Session = Depends(get_db)):
    mgr = CaseManager(db)
    case = mgr.get_case(case_id)
    evidence = db.query(EvidenceModel).filter_by(case_id=case_id).all()
    correlations = db.query(CorrelationModel).filter_by(case_id=case_id).all()
    timeline = db.query(TimelineEventModel).filter_by(case_id=case_id).order_by(TimelineEventModel.timestamp.asc()).all()
    findings = (
        db.query(FindingModel)
        .join(EvidenceModel, FindingModel.evidence_id == EvidenceModel.id)
        .filter(EvidenceModel.case_id == case_id)
        .all()
    )

    return {
        "case": case,
        "evidence": evidence,
        "findings": findings,
        "correlations": correlations,
        "timeline": timeline
    }

@app.post("/api/cases/{case_id}/evidence/upload")
async def upload_evidence(case_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload evidence file safely to temp and ingest into case manager."""
    mgr = CaseManager(db)
    temp_dir = Path.home() / ".cybertrace" / "uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / file.filename

    with open(temp_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    try:
        ev = mgr.add_evidence(case_id, str(temp_path))
    finally:
        if temp_path.exists():
            temp_path.unlink()

    return ev

@app.post("/api/cases/{case_id}/analyze")
def run_case_analysis(case_id: str, db: Session = Depends(get_db)):
    engine = ForensicEngine(db)
    return engine.analyze_case(case_id)

@app.get("/api/cases/{case_id}/verify")
def verify_case_evidence(case_id: str, db: Session = Depends(get_db)):
    mgr = CaseManager(db)
    evidence = db.query(EvidenceModel).filter_by(case_id=case_id).all()
    results = [mgr.verify_evidence(e.id) for e in evidence]
    return {"case_id": case_id, "verification_results": results}

@app.get("/api/cases/{case_id}/report")
def download_report(case_id: str, format: str = "html", db: Session = Depends(get_db)):
    gen = ForensicReportGenerator(db)
    reports_dir = Path.home() / ".cybertrace" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_file = str(reports_dir / f"{case_id}_report.{format.lower()}")

    if format.lower() == "html":
        gen.generate_html(case_id, out_file)
        return FileResponse(out_file, media_type="text/html", filename=f"{case_id}_report.html")
    elif format.lower() == "json":
        gen.generate_json(case_id, out_file)
        return FileResponse(out_file, media_type="application/json", filename=f"{case_id}_report.json")
    elif format.lower() == "pdf":
        gen.generate_pdf(case_id, out_file)
        return FileResponse(out_file, media_type="application/pdf", filename=f"{case_id}_report.pdf")
    else:
        raise HTTPException(status_code=400, detail="Invalid report format.")

# Dashboard HTML entry point
@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    index_file = FRONTEND_DIR / "templates" / "index.html"
    if index_file.exists():
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>CyberTrace Backend Online</h1><p>API available at <a href='/docs'>/docs</a></p>")
