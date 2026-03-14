"""
SQLAlchemy ORM models for the Extension Risk Intelligence Platform.

Tables:
  - extensions:    tracked extensions (Chrome/Edge/VSCode)
  - scan_jobs:     async analysis jobs with progress tracking
  - scan_results:  completed scan results with summary metrics
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text, ForeignKey, Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from api.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Extension(Base):
    __tablename__ = "extensions"

    id = Column(String(256), primary_key=True)  # "abcde..." or "publisher.name"
    name = Column(String(512), nullable=True)
    publisher = Column(String(256), nullable=True)
    browser_type = Column(String(16), nullable=False)  # chrome | edge | vscode
    current_version = Column(String(64), nullable=True)
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)
    last_version_hash = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    jobs = relationship("ScanJob", back_populates="extension", lazy="dynamic")
    results = relationship("ScanResult", back_populates="extension", lazy="dynamic")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    extension_id = Column(
        String(256), ForeignKey("extensions.id"), nullable=False, index=True
    )
    browser_type = Column(String(16), nullable=False)
    fast_mode = Column(Integer, default=0)  # 0=full, 1=fast (skip VT/OSINT)
    status = Column(String(16), default="queued", nullable=False)
    progress_percent = Column(Integer, default=0)
    progress_message = Column(String(512), default="")
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    result_id = Column(
        UUID(as_uuid=True), ForeignKey("scan_results.id"), nullable=True
    )

    extension = relationship("Extension", back_populates="jobs")
    result = relationship("ScanResult", foreign_keys=[result_id])

    __table_args__ = (
        Index("ix_scan_jobs_status", "status"),
    )


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    extension_id = Column(
        String(256), ForeignKey("extensions.id"), nullable=False, index=True
    )
    version = Column(String(64), nullable=True)
    version_hash = Column(String(128), nullable=True, index=True)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(16), default="UNKNOWN")
    threat_classification = Column(Text, nullable=True)  # JSON or short summary; was String(128)
    findings_count = Column(Integer, default=0)
    json_report_path = Column(String(512), nullable=True)
    html_report_path = Column(String(512), nullable=True)
    # Report content stored in DB (source of truth; paths kept for backward compatibility)
    report_json = Column(Text, nullable=True)
    report_html = Column(Text, nullable=True)
    scanned_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Summary metrics for quick API responses
    vuln_count = Column(Integer, default=0)
    malicious_domains = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)

    extension = relationship("Extension", back_populates="results")

    __table_args__ = (
        Index("ix_scan_results_ext_scanned", "extension_id", "scanned_at"),
    )
