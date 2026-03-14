"""
GET /api/v1/reports/{job_id}              — JSON report summary (by job)
GET /api/v1/reports/{job_id}/html         — full HTML report (by job)
GET /api/v1/reports/{job_id}/full         — complete JSON analysis (by job)
GET /api/v1/reports/by-extension/{ext_id} — summary for latest report (by extension_id)
GET /api/v1/reports/by-extension/{ext_id}/html  — HTML for latest report
GET /api/v1/reports/by-extension/{ext_id}/full — full JSON for latest report
"""

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from sqlalchemy.orm import Session
from pathlib import Path

from api.database import get_db
from api.auth import require_api_key
from api.models import ScanJob, ScanResult, Extension
from api.schemas import ReportSummary

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


def _get_result(job_id: str, db: Session) -> tuple[ScanJob, ScanResult]:
    """Look up job and its result; raise 404 if not found or incomplete."""
    try:
        uid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job ID format.")

    job = db.query(ScanJob).filter(ScanJob.id == uid).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    if not job.result_id:
        if job.status in ("queued", "running"):
            raise HTTPException(status_code=202, detail="Analysis still in progress.")
        raise HTTPException(status_code=404, detail="No result available for this job.")

    result = db.query(ScanResult).filter(ScanResult.id == job.result_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Result record missing.")

    return job, result


def _result_to_report_summary(result: ScanResult, job_id: str, extension: Extension) -> ReportSummary:
    """Build ReportSummary from a ScanResult and optional job_id for URLs."""
    return ReportSummary(
        extension_id=result.extension_id,
        name=extension.name or "" if extension else "",
        version=result.version or "",
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        threat_classification=result.threat_classification or "",
        findings_count=result.findings_count,
        vuln_count=result.vuln_count,
        malicious_domains=result.malicious_domains,
        critical_findings=result.critical_findings,
        scanned_at=result.scanned_at,
        report_url=f"/api/v1/reports/{job_id}/full" if job_id else "",
        html_report_url=f"/api/v1/reports/{job_id}/html" if job_id else "",
    )


# By extension_id (defined before /{job_id} so "by-extension" is not captured as job_id)
@router.get("/by-extension/{extension_id}", response_model=ReportSummary)
def get_report_by_extension_summary(
    extension_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Return the latest stored report summary for the given extension_id."""
    result = (
        db.query(ScanResult)
        .filter(ScanResult.extension_id == extension_id)
        .order_by(ScanResult.scanned_at.desc())
        .first()
    )
    if not result:
        raise HTTPException(status_code=404, detail="No report found for this extension.")
    ext = db.query(Extension).filter(Extension.id == extension_id).first()
    job = db.query(ScanJob).filter(ScanJob.result_id == result.id).first()
    job_id = str(job.id) if job else ""
    summary = _result_to_report_summary(result, job_id, ext or Extension(id=extension_id, browser_type=""))
    if not job_id:
        summary.report_url = f"/api/v1/reports/by-extension/{extension_id}/full"
        summary.html_report_url = f"/api/v1/reports/by-extension/{extension_id}/html"
    return summary


@router.get("/by-extension/{extension_id}/html")
def get_report_by_extension_html(
    extension_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Return the latest stored HTML report for the given extension_id."""
    result = (
        db.query(ScanResult)
        .filter(ScanResult.extension_id == extension_id)
        .order_by(ScanResult.scanned_at.desc())
        .first()
    )
    if not result:
        raise HTTPException(status_code=404, detail="No report found for this extension.")
    if result.report_html:
        return HTMLResponse(content=result.report_html)
    if result.html_report_path:
        path = Path(result.html_report_path)
        if path.exists():
            return FileResponse(path, media_type="text/html")
    raise HTTPException(status_code=404, detail="HTML report not available.")


@router.get("/by-extension/{extension_id}/full")
def get_report_by_extension_full(
    extension_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Return the latest stored full JSON report for the given extension_id."""
    result = (
        db.query(ScanResult)
        .filter(ScanResult.extension_id == extension_id)
        .order_by(ScanResult.scanned_at.desc())
        .first()
    )
    if not result:
        raise HTTPException(status_code=404, detail="No report found for this extension.")
    if result.report_json:
        try:
            data = json.loads(result.report_json)
            return JSONResponse(content=data)
        except json.JSONDecodeError:
            pass
    if result.json_report_path:
        path = Path(result.json_report_path)
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return JSONResponse(content=data)
    raise HTTPException(status_code=404, detail="JSON report not available.")


@router.get("/{job_id}", response_model=ReportSummary)
def get_report_summary(
    job_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Return structured summary of the scan result."""
    job, result = _get_result(job_id, db)

    extension = db.query(Extension).filter(Extension.id == result.extension_id).first()
    return _result_to_report_summary(result, job_id, extension or Extension(id=result.extension_id, browser_type=""))


@router.get("/{job_id}/html")
def get_html_report(
    job_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Serve the full HTML threat analysis report (from DB or file)."""
    _, result = _get_result(job_id, db)
    if result.report_html:
        return HTMLResponse(content=result.report_html)
    if result.html_report_path:
        path = Path(result.html_report_path)
        if path.exists():
            return FileResponse(path, media_type="text/html")
    raise HTTPException(status_code=404, detail="HTML report not available.")


@router.get("/{job_id}/full")
def get_full_json_report(
    job_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Return the complete JSON analysis data (from DB or file)."""
    _, result = _get_result(job_id, db)
    if result.report_json:
        try:
            data = json.loads(result.report_json)
            return JSONResponse(content=data)
        except json.JSONDecodeError:
            pass
    if result.json_report_path:
        path = Path(result.json_report_path)
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return JSONResponse(content=data)
    raise HTTPException(status_code=404, detail="JSON report not available.")
