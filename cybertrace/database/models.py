"""Database models and persistence setup for CyberTrace."""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine, Column, String, Integer, Float, Text, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

Base = declarative_base()

def default_db_path() -> str:
    home = Path.home() / ".cybertrace"
    home.mkdir(parents=True, exist_ok=True)
    return str(home / "cybertrace.db")

DATABASE_URL = os.getenv("CYBERTRACE_DB_URL", f"sqlite:///{default_db_path()}")

# Engine creation
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class CaseModel(Base):
    __tablename__ = "cases"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    investigator = Column(String(128), default="Investigator")
    status = Column(String(32), default="ACTIVE")  # ACTIVE, CLOSED, ARCHIVED
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    evidence_items = relationship("EvidenceModel", back_populates="case", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLogModel", back_populates="case", cascade="all, delete-orphan")
    correlations = relationship("CorrelationModel", back_populates="case", cascade="all, delete-orphan")

class EvidenceModel(Base):
    __tablename__ = "evidence"

    id = Column(String(64), primary_key=True, index=True)
    case_id = Column(String(64), ForeignKey("cases.id"), nullable=False, index=True)
    source_path = Column(String(1024), nullable=False)
    stored_path = Column(String(1024), nullable=False)
    file_name = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)
    file_type = Column(String(128), nullable=True)
    mime_type = Column(String(128), nullable=True)
    md5 = Column(String(32), nullable=False)
    sha1 = Column(String(40), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    acquired_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    verified_at = Column(DateTime, nullable=True)
    integrity_status = Column(String(32), default="VERIFIED")  # VERIFIED, MISMATCH, UNCHECKED

    case = relationship("CaseModel", back_populates="evidence_items")
    findings = relationship("FindingModel", back_populates="evidence", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEventModel", back_populates="evidence", cascade="all, delete-orphan")

class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String(64), ForeignKey("evidence.id"), nullable=False, index=True)
    category = Column(String(64), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), default="INFO")
    source_technical = Column(String(255), nullable=False)
    supporting_data_json = Column(Text, default="{}")
    limitations = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    evidence = relationship("EvidenceModel", back_populates="findings")

class TimelineEventModel(Base):
    __tablename__ = "timeline_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = Column(String(64), ForeignKey("evidence.id"), nullable=True, index=True)
    timestamp = Column(String(64), nullable=False, index=True)
    timestamp_type = Column(String(64), default="OBSERVED")  # MACB, EMBEDDED, LOG_EVENT
    source_description = Column(String(255), nullable=False)
    event_summary = Column(Text, nullable=False)
    technical_details_json = Column(Text, default="{}")

    evidence = relationship("EvidenceModel", back_populates="timeline_events")

class CorrelationModel(Base):
    __tablename__ = "correlations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.id"), nullable=False, index=True)
    source_evidence_id = Column(String(64), nullable=False)
    target_evidence_id = Column(String(64), nullable=False)
    relationship_type = Column(String(64), nullable=False)  # SHARED_HASH, SHARED_IP, CHRONOLOGICAL, etc.
    reasoning = Column(Text, nullable=False)
    supporting_data_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    case = relationship("CaseModel", back_populates="correlations")

class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.id"), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    details = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    case = relationship("CaseModel", back_populates="audit_logs")

def init_db(custom_engine=None):
    """Initialize database tables."""
    eng = custom_engine or engine
    Base.metadata.create_all(bind=eng)

def get_db() -> Generator[Session, None, None]:
    """Dependency helper for database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
