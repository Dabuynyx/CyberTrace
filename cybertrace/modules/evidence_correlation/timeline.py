"""Timeline Reconstruction Engine."""

from typing import List, Dict, Any
from sqlalchemy.orm import Session
from cybertrace.database.models import TimelineEventModel

class TimelineEngine:
    """Chronologically reconstructs multi-source investigation events."""

    def __init__(self, db: Session):
        self.db = db

    def get_case_timeline(self, case_id: str) -> List[Dict[str, Any]]:
        """Fetch and order all timeline events for a given case."""
        events: List[TimelineEventModel] = (
            self.db.query(TimelineEventModel)
            .filter_by(case_id=case_id)
            .order_by(TimelineEventModel.timestamp.asc())
            .all()
        )

        results = []
        for ev in events:
            results.append({
                "id": ev.id,
                "case_id": ev.case_id,
                "evidence_id": ev.evidence_id,
                "timestamp": ev.timestamp,
                "timestamp_type": ev.timestamp_type,
                "source_description": ev.source_description,
                "event_summary": ev.event_summary,
            })
        return results
