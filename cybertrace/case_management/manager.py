"""Case and Evidence Management Services."""

import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from cybertrace.database.models import CaseModel, EvidenceModel, AuditLogModel, FindingModel
from cybertrace.core.exceptions import CaseNotFoundError, EvidenceNotFoundError, ForensicIntegrityError
from cybertrace.utils.crypto import calculate_hashes
from cybertrace.security.guards import validate_safe_path, validate_file_size

def get_storage_dir() -> Path:
    storage = Path.home() / ".cybertrace" / "storage"
    storage.mkdir(parents=True, exist_ok=True)
    return storage

class CaseManager:
    """Manages investigation cases, forensic evidence acquisition, verification, and audit logs."""

    def __init__(self, db: Session):
        self.db = db
        self.storage_dir = get_storage_dir()

    def create_case(self, title: str, description: str = "", investigator: str = "Forensic Analyst") -> CaseModel:
        """Create a new forensic investigation case."""
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        case = CaseModel(
            id=case_id,
            title=title,
            description=description,
            investigator=investigator,
            status="ACTIVE"
        )
        self.db.add(case)

        # Audit log entry
        audit = AuditLogModel(
            case_id=case_id,
            action="CASE_CREATED",
            details=f"Case '{title}' created by {investigator}"
        )
        self.db.add(audit)
        self.db.commit()
        self.db.refresh(case)
        return case

    def get_case(self, case_id: str) -> CaseModel:
        """Retrieve case by ID."""
        case = self.db.query(CaseModel).filter_by(id=case_id).first()
        if not case:
            raise CaseNotFoundError(f"Case with ID '{case_id}' was not found.")
        return case

    def list_cases(self) -> List[CaseModel]:
        """List all registered cases."""
        return self.db.query(CaseModel).order_by(CaseModel.created_at.desc()).all()

    def add_evidence(self, case_id: str, file_path: str) -> EvidenceModel:
        """
        Ingests evidence into the forensic repository:
        1. Validates file existence and size boundaries.
        2. Computes initial cryptographic hashes (MD5, SHA1, SHA256).
        3. Copies file into immutable evidence store preserving original.
        4. Logs acquisition into case audit trail.
        """
        self.get_case(case_id)  # Validate case exists
        
        if not os.path.isfile(file_path):
            raise EvidenceNotFoundError(f"Source file does not exist: {file_path}")

        validate_file_size(file_path)
        hashes = calculate_hashes(file_path)
        file_size = os.path.getsize(file_path)
        orig_name = Path(file_path).name

        ev_id = f"EV-{uuid.uuid4().hex[:8].upper()}"
        dest_filename = f"{ev_id}_{orig_name}"
        stored_path = str(self.storage_dir / dest_filename)

        # Copy evidence to preserve original
        shutil.copy2(file_path, stored_path)

        evidence = EvidenceModel(
            id=ev_id,
            case_id=case_id,
            source_path=os.path.abspath(file_path),
            stored_path=stored_path,
            file_name=orig_name,
            file_size=file_size,
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            sha256=hashes["sha256"],
            acquired_at=datetime.now(timezone.utc),
            integrity_status="VERIFIED"
        )
        self.db.add(evidence)

        # Audit log
        audit = AuditLogModel(
            case_id=case_id,
            action="EVIDENCE_ACQUIRED",
            details=f"Acquired evidence {ev_id} ({orig_name}) SHA256={hashes['sha256']}"
        )
        self.db.add(audit)
        self.db.commit()
        self.db.refresh(evidence)
        return evidence

    def verify_evidence(self, evidence_id: str) -> Dict[str, Any]:
        """
        Recalculates cryptographic hashes on stored evidence to prove 
        zero tampering or degradation.
        """
        ev = self.db.query(EvidenceModel).filter_by(id=evidence_id).first()
        if not ev:
            raise EvidenceNotFoundError(f"Evidence {evidence_id} not found")

        current_hashes = calculate_hashes(ev.stored_path)
        is_intact = (current_hashes["sha256"] == ev.sha256)

        ev.verified_at = datetime.now(timezone.utc)
        ev.integrity_status = "VERIFIED" if is_intact else "MISMATCH"
        self.db.commit()

        if not is_intact:
            raise ForensicIntegrityError(
                f"INTEGRITY FAILURE on {evidence_id}: Stored hash {current_hashes['sha256']} does not match acquisition hash {ev.sha256}"
            )

        return {
            "evidence_id": ev.id,
            "file_name": ev.file_name,
            "status": "VERIFIED",
            "expected_sha256": ev.sha256,
            "calculated_sha256": current_hashes["sha256"],
            "verified_at": ev.verified_at.isoformat()
        }
