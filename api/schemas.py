"""
Pydantic schemas for API request / response validation.
"""

from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field


# ── Request schemas ──────────────────────────────────────────────────

class NpmAnalyzeRequest(BaseModel):
    package_spec: str = Field(
        ...,
        description="npm package with optional version, e.g. lodash@4.17.21 or @types/node@20.1.0",
        examples=["lodash@4.17.21"],
    )


class AnalyzeRequest(BaseModel):
    extension_id: str = Field(
        ...,
        description="Extension identifier: 32-char Chrome/Edge ID or publisher.name for VSCode",
        examples=["abcdefghijklmnopqrstuvwxyzabcdef", "shd101wyy.markdown-preview-enhanced"],
    )
    browser: Literal["chrome", "edge", "vscode"] = Field(
        default="chrome",
        description="Extension marketplace type",
    )
    fast_mode: bool = Field(
        default=False,
        description="Skip VirusTotal and OSINT lookups for faster scans",
    )


# ── Response schemas ─────────────────────────────────────────────────

class AnalyzeResponse(BaseModel):
    job_id: str
    status: str = "queued"
    message: str = "Analysis queued"


class JobStatusResponse(BaseModel):
    job_id: str
    extension_id: str
    status: str
    progress_percent: int = 0
    progress_message: str = ""
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    report_url: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None


class ReportSummary(BaseModel):
    extension_id: str
    name: str = ""
    version: str = ""
    risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    threat_classification: str = ""
    findings_count: int = 0
    vuln_count: int = 0
    malicious_domains: int = 0
    critical_findings: int = 0
    scanned_at: datetime
    report_url: str
    html_report_url: str


class ExtensionInfo(BaseModel):
    extension_id: str
    name: str = ""
    publisher: str = ""
    browser_type: str = ""
    current_version: str = ""
    last_scanned_at: Optional[datetime] = None
    latest_report: Optional[ReportSummary] = None


class ExtensionHistory(BaseModel):
    extension_id: str
    name: str = ""
    scans: list[ReportSummary] = []


class ErrorResponse(BaseModel):
    detail: str
