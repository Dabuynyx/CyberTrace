"""Core Forensic Engine Orchestrator."""

import json
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from cybertrace.case_management.manager import CaseManager
from cybertrace.modules.file_intelligence.analyzer import FileIntelligenceModule
from cybertrace.modules.metadata_forensics.analyzer import MetadataForensicsModule
from cybertrace.modules.artifact_analysis.analyzer import ArtifactAnalysisModule
from cybertrace.modules.malware_triage.analyzer import MalwareTriageModule
from cybertrace.modules.evidence_correlation.correlator import EvidenceCorrelationEngine
from cybertrace.database.models import FindingModel, TimelineEventModel, EvidenceModel
from cybertrace.core.interfaces import ModuleResult

class ForensicEngine:
    """Orchestrates forensic modules, stores findings, and generates timelines."""

    def __init__(self, db: Session):
        self.db = db
        self.case_mgr = CaseManager(db)
        self.mod_file = FileIntelligenceModule()
        self.mod_meta = MetadataForensicsModule()
        self.mod_artifact = ArtifactAnalysisModule()
        self.mod_malware = MalwareTriageModule()
        self.correlator = EvidenceCorrelationEngine(db)

    def analyze_evidence(self, evidence_id: str, yara_rules: Optional[str] = None) -> Dict[str, Any]:
        """Run all applicable forensic modules against a specific evidence item."""
        ev: EvidenceModel = self.db.query(EvidenceModel).filter_by(id=evidence_id).first()
        if not ev:
            raise ValueError(f"Evidence {evidence_id} not found.")

        target = ev.stored_path
        results: Dict[str, ModuleResult] = {}

        # 1. File Intelligence
        res_file = self.mod_file.analyze(target)
        results["file_intelligence"] = res_file
        if res_file.raw_metadata:
            ev.file_type = res_file.raw_metadata.get("detected_format")
            ev.mime_type = res_file.raw_metadata.get("detected_mime")

        # 2. Metadata Forensics
        res_meta = self.mod_meta.analyze(target)
        results["metadata_forensics"] = res_meta

        # 3. Artifact Analysis (if SQLite or log)
        res_artifact = self.mod_artifact.analyze(target)
        results["artifact_analysis"] = res_artifact

        # 4. Malware Triage
        res_malware = self.mod_malware.analyze(target, yara_rules=yara_rules)
        results["malware_triage"] = res_malware

        # Persist findings to database
        # Remove old findings for this evidence to allow clean re-analysis
        self.db.query(FindingModel).filter_by(evidence_id=ev.id).delete()
        self.db.query(TimelineEventModel).filter_by(evidence_id=ev.id).delete()

        all_findings = []
        for mod_key, res in results.items():
            for f in res.findings:
                finding_rec = FindingModel(
                    evidence_id=ev.id,
                    category=f.category,
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    source_technical=f.source_technical,
                    supporting_data_json=json.dumps(f.supporting_evidence),
                    limitations=f.limitations
                )
                self.db.add(finding_rec)
                all_findings.append(f)

        # Reconstruct timeline events from extracted artifact records & filesystem timestamps
        if res_file.raw_metadata.get("filesystem_timestamps"):
            ts = res_file.raw_metadata["filesystem_timestamps"]
            import datetime
            m_iso = datetime.datetime.fromtimestamp(ts["modified"], tz=datetime.timezone.utc).isoformat()
            c_iso = datetime.datetime.fromtimestamp(ts["created"], tz=datetime.timezone.utc).isoformat()

            self.db.add(TimelineEventModel(
                case_id=ev.case_id,
                evidence_id=ev.id,
                timestamp=m_iso,
                timestamp_type="FILESYSTEM_MODIFY",
                source_description="Filesystem st_mtime",
                event_summary=f"Evidence file '{ev.file_name}' modified"
            ))

        # Check artifact events (browser visits etc.)
        if res_artifact.raw_metadata and "records" in res_artifact.raw_metadata:
            for rec in res_artifact.raw_metadata["records"]:
                if rec.get("timestamp") and rec["timestamp"] != "INVALID_TIMESTAMP":
                    summary = rec.get("url") or rec.get("raw_event") or rec.get("target_path") or "Artifact Event"
                    self.db.add(TimelineEventModel(
                        case_id=ev.case_id,
                        evidence_id=ev.id,
                        timestamp=rec["timestamp"],
                        timestamp_type=rec.get("type", "ARTIFACT"),
                        source_description=res_artifact.raw_metadata.get("artifact_type", "artifact"),
                        event_summary=str(summary)[:200]
                    ))

        self.db.commit()

        # Run correlation across case items
        self.correlator.correlate_case(ev.case_id)

        return {
            "evidence_id": ev.id,
            "findings_count": len(all_findings),
            "modules_executed": list(results.keys()),
            "status": "COMPLETED"
        }

    def analyze_case(self, case_id: str, yara_rules: Optional[str] = None) -> Dict[str, Any]:
        """Analyze all evidence items in an entire case."""
        case = self.case_mgr.get_case(case_id)
        evidence_items = self.db.query(EvidenceModel).filter_by(case_id=case_id).all()

        analyzed = []
        for ev in evidence_items:
            res = self.analyze_evidence(ev.id, yara_rules=yara_rules)
            analyzed.append(res)

        return {
            "case_id": case.id,
            "total_evidence_analyzed": len(analyzed),
            "results": analyzed
        }
