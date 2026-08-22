"""
SQLAlchemy database models for DomainThreat, Case, and ScanRecord.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Float,
    Integer,
    DateTime,
    JSON,
    Boolean,
    ForeignKey,
    Text,
)
from sqlalchemy.orm import relationship
from db import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class ScanRecord(Base):
    """
    Tracks execution history and results of openSquat brand scans.
    """
    __tablename__ = "scan_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    brand_list = Column(JSON, nullable=False)
    status = Column(String(32), default="RUNNING", index=True)  # RUNNING, COMPLETED, FAILED
    results_count = Column(Integer, default=0)
    output_file = Column(String(255), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    threats = relationship("DomainThreat", back_populates="scan", cascade="all, delete-orphan")


class DomainThreat(Base):
    """
    Represents suspicious lookalike/typosquatted domains discovered by openSquat.
    """
    __tablename__ = "domain_threats"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scan_records.id", ondelete="SET NULL"), nullable=True, index=True)
    domain = Column(String(255), nullable=False, index=True)
    brand = Column(String(100), nullable=False, index=True)
    similarity_score = Column(Float, nullable=False)  # 0.0 to 1.0 (Levenshtein ratio)
    registration_date = Column(String(50), nullable=True)
    vt_reputation = Column(JSON, nullable=True)  # VirusTotal or third-party reputation flags
    status = Column(
        String(32),
        default="PENDING_ANALYSIS",
        index=True
    )  # PENDING_ANALYSIS, ANALYZING, ANALYZED, FAILED
    trustlens_score = Column(Float, nullable=True)  # Trust score from TrustLens (0-100)
    trustlens_reasons = Column(JSON, nullable=True)  # Detailed reasons list / dict
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    scan = relationship("ScanRecord", back_populates="threats")
    case = relationship("Case", back_populates="threat", uselist=False, cascade="all, delete-orphan")


class Case(Base):
    """
    Synthesized security case combining domain squatting signals with
    explainable deep URL inspection from TrustLens-AI.
    Pipeline fields: threat_dna, campaign_id, mutation_class, intent_class.
    """
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    threat_id = Column(String(36), ForeignKey("domain_threats.id", ondelete="SET NULL"), nullable=True, index=True)
    channel = Column(String(50), default="web_domain", index=True)
    target = Column(String(512), nullable=False, index=True)  # e.g., https://paypa1-secure-login.com
    risk_score = Column(Integer, nullable=False, index=True)  # 0 to 100
    risk_level = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
    reasons = Column(JSON, nullable=False, default=list)  # Combined human-readable explanation strings
    evidence = Column(JSON, nullable=False, default=dict)  # Screenshot, HTML snapshot, DNS, SSL, engine details
    analysis_complete = Column(Boolean, default=True, index=True)
    antigravity_event_id = Column(String(100), nullable=True, index=True)
    # Pipeline stage outputs
    threat_dna = Column(String(255), nullable=True, index=True)    # e.g. phishing_keyword:paypal:credential_harvest:HIGH
    campaign_id = Column(String(64), nullable=True, index=True)    # e.g. camp_a3f2b19c
    mutation_class = Column(String(64), nullable=True)             # homoglyph | omission | phishing_keyword | ...
    intent_class = Column(String(64), nullable=True)               # phishing | informational | benign | ...
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    threat = relationship("DomainThreat", back_populates="case")
