"""
GET /api/v1/extensions/{ext_id}          — latest scan for an extension
GET /api/v1/extensions/{ext_id}/history  — all scans ordered by date
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.database import get_db
from api.auth import require_api_key
from api.models import Extension, ScanResult, ScanJob
from api.schemas import ExtensionInfo, ExtensionHistory, ReportSummary

router = APIRouter(prefix="/api/v1/extensions", tags=["extensions"])


def _result_to_summary(result: ScanResult, ext: Extension) -> ReportSummary:
    """Convert a ScanResult row into a ReportSummary schema."""
    # Find the job that produced this result
    job_id = ""
    if result.id:
        # We need a job_id for URLs — find the job that references this result
        from api.database import SessionLocal
        db2 = SessionLocal()
        try:
            job = (
                db2.query(ScanJob)
                .filter(ScanJob.result_id == result.id)
                .first()
            )
            if job:
                job_id = str(job.id)
        finally:
            db2.close()

    return ReportSummary(
        extension_id=result.extension_id,
        name=ext.name or "",
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


@router.get("/{ext_id}", response_model=ExtensionInfo)
def get_extension(
    ext_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Get extension info with the latest scan result."""
    ext = db.query(Extension).filter(Extension.id == ext_id).first()
    if not ext:
        raise HTTPException(status_code=404, detail="Extension not found.")

    latest = (
        db.query(ScanResult)
        .filter(ScanResult.extension_id == ext_id)
        .order_by(ScanResult.scanned_at.desc())
        .first()
    )

    latest_report = _result_to_summary(latest, ext) if latest else None

    return ExtensionInfo(
        extension_id=ext.id,
        name=ext.name or "",
        publisher=ext.publisher or "",
        browser_type=ext.browser_type,
        current_version=ext.current_version or "",
        last_scanned_at=ext.last_scanned_at,
        latest_report=latest_report,
    )


@router.get("/{ext_id}/history", response_model=ExtensionHistory)
def get_extension_history(
    ext_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Get all scan results for an extension, newest first."""
    ext = db.query(Extension).filter(Extension.id == ext_id).first()
    if not ext:
        raise HTTPException(status_code=404, detail="Extension not found.")

    results = (
        db.query(ScanResult)
        .filter(ScanResult.extension_id == ext_id)
        .order_by(ScanResult.scanned_at.desc())
        .limit(50)
        .all()
    )

    scans = [_result_to_summary(r, ext) for r in results]

    return ExtensionHistory(
        extension_id=ext.id,
        name=ext.name or "",
        scans=scans,
    )
