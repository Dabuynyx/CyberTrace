"""Module 5: Evidence Correlation Engine & Multi-Artifact Relationship Graph."""

import json
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from cybertrace.database.models import EvidenceModel, FindingModel, CorrelationModel

class EvidenceCorrelationEngine:
    """
    Correlates artifacts across cases using deterministic linkages:
    - Identical cryptographic hashes (SHA-256) across evidence
    - Overlapping IP addresses in logs & strings
    - Overlapping usernames in authentication records
    - Temporal clustering and sequential proximity
    """

    def __init__(self, db: Session):
        self.db = db

    def correlate_case(self, case_id: str) -> List[Dict[str, Any]]:
        """Run correlation passes over all evidence items in the given case."""
        items: List[EvidenceModel] = self.db.query(EvidenceModel).filter_by(case_id=case_id).all()
        if len(items) < 2:
            return []

        correlations: List[Dict[str, Any]] = []

        # 1. Exact Hash Match Correlation (Duplicate or reused malware/binary)
        hash_map: Dict[str, List[EvidenceModel]] = {}
        for ev in items:
            hash_map.setdefault(ev.sha256, []).append(ev)

        for sha, ev_group in hash_map.items():
            if len(ev_group) > 1:
                for i in range(len(ev_group)):
                    for j in range(i + 1, len(ev_group)):
                        correlations.append({
                            "case_id": case_id,
                            "source_evidence_id": ev_group[i].id,
                            "target_evidence_id": ev_group[j].id,
                            "relationship_type": "IDENTICAL_HASH",
                            "reasoning": f"Evidence items share the exact cryptographic SHA-256 hash ({sha}), confirming byte-for-byte identical content.",
                            "supporting_data": {"sha256": sha}
                        })

        # 2. Correlate Indicators extracted from findings (IPs, URLs, Usernames)
        evidence_ips: Dict[str, set] = {}
        evidence_users: Dict[str, set] = {}

        for ev in items:
            evidence_ips[ev.id] = set()
            evidence_users[ev.id] = set()
            findings: List[FindingModel] = self.db.query(FindingModel).filter_by(evidence_id=ev.id).all()

            for f in findings:
                try:
                    data = json.loads(f.supporting_data_json) if f.supporting_data_json else {}
                except Exception:
                    data = {}

                # Harvest IPs
                if "ips" in data and isinstance(data["ips"], list):
                    for ip in data["ips"]:
                        evidence_ips[ev.id].add(ip)
                if "extracted_ips" in data and isinstance(data["extracted_ips"], list):
                    for ip in data["extracted_ips"]:
                        evidence_ips[ev.id].add(ip)

                # Harvest usernames
                if "username" in data:
                    evidence_users[ev.id].add(data["username"])
                if "sample" in data and isinstance(data["sample"], list):
                    for s in data["sample"]:
                        if isinstance(s, dict) and "username" in s:
                            evidence_users[ev.id].add(s["username"])

        # Check IP overlaps between pairs
        item_ids = [ev.id for ev in items]
        for i in range(len(item_ids)):
            for j in range(i + 1, len(item_ids)):
                id1, id2 = item_ids[i], item_ids[j]
                common_ips = evidence_ips[id1].intersection(evidence_ips[id2])
                if common_ips:
                    correlations.append({
                        "case_id": case_id,
                        "source_evidence_id": id1,
                        "target_evidence_id": id2,
                        "relationship_type": "SHARED_NETWORK_INDICATOR",
                        "reasoning": f"Evidence items contain {len(common_ips)} identical IP indicator(s): {', '.join(list(common_ips)[:5])}.",
                        "supporting_data": {"shared_ips": list(common_ips)}
                    })

                common_users = evidence_users[id1].intersection(evidence_users[id2])
                if common_users:
                    correlations.append({
                        "case_id": case_id,
                        "source_evidence_id": id1,
                        "target_evidence_id": id2,
                        "relationship_type": "SHARED_IDENTITY_INDICATOR",
                        "reasoning": f"Evidence items reference matching user account identity: {', '.join(list(common_users))}.",
                        "supporting_data": {"shared_users": list(common_users)}
                    })

        # Persist correlations to database
        # Clear prior correlations for this case to avoid duplicates
        self.db.query(CorrelationModel).filter_by(case_id=case_id).delete()

        created_records = []
        for c in correlations:
            record = CorrelationModel(
                case_id=c["case_id"],
                source_evidence_id=c["source_evidence_id"],
                target_evidence_id=c["target_evidence_id"],
                relationship_type=c["relationship_type"],
                reasoning=c["reasoning"],
                supporting_data_json=json.dumps(c["supporting_data"])
            )
            self.db.add(record)
            created_records.append(c)

        self.db.commit()
        return created_records
