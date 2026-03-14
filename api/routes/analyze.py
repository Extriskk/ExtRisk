"""
POST /api/v1/analyze  — queue a new scan job
GET  /api/v1/jobs/{job_id} — poll job status / progress
POST /api/v1/jobs/{job_id}/cancel — cancel a running job
"""

import re
import uuid
from datetime import datetime, timezone
import json
import sys

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.config import settings
from api.database import get_db
from api.auth import require_api_key
from api.models import Extension, ScanJob, ScanResult
from api.schemas import AnalyzeRequest, AnalyzeResponse, JobStatusResponse
from scan_service import ScanService, ScanRequest, ScanStore

try:
    from redis import Redis
    from rq import Queue

    _QUEUE_AVAILABLE = True
except Exception:
    Redis = None  # type: ignore
    Queue = None  # type: ignore
    _QUEUE_AVAILABLE = False

# RQ workers are not supported on native Windows (require fork());
# force synchronous fallback there even if redis/rq import succeeds.
if sys.platform == "win32":
    _QUEUE_AVAILABLE = False

router = APIRouter(prefix="/api/v1", tags=["analyze"])

# Extension ID format validators
_CHROME_RE = re.compile(r"^[a-z]{32}$")
_VSCODE_RE = re.compile(r"^[\w-]+\.[\w-]+$")  # publisher.extension-name


def _validate_extension_id(ext_id: str, browser: str) -> None:
    if browser in ("chrome", "edge"):
        if not _CHROME_RE.match(ext_id):
            raise HTTPException(
                status_code=400,
                detail="Chrome/Edge extension ID must be 32 lowercase letters.",
            )
    elif browser == "vscode":
        if not _VSCODE_RE.match(ext_id):
            raise HTTPException(
                status_code=400,
                detail="VSCode extension ID must be publisher.extension-name.",
            )


def _get_redis() -> Redis:
    if not _QUEUE_AVAILABLE:
        raise RuntimeError("Redis/RQ queue not available on this platform.")
    return Redis.from_url(settings.REDIS_URL)


@router.post("/analyze", response_model=AnalyzeResponse)
def start_analysis(
    req: AnalyzeRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Queue a new extension analysis job."""
    ext_id = req.extension_id.strip()
    if req.browser in ("chrome", "edge"):
        ext_id = ext_id.lower()
    _validate_extension_id(ext_id, req.browser)

    # Upsert extension record
    extension = db.query(Extension).filter(Extension.id == ext_id).first()
    if not extension:
        extension = Extension(
            id=ext_id,
            browser_type=req.browser,
        )
        db.add(extension)
        db.flush()

    # Check for a running job on the same extension
    running = (
        db.query(ScanJob)
        .filter(ScanJob.extension_id == ext_id, ScanJob.status.in_(["queued", "running"]))
        .first()
    )
    if running:
        return AnalyzeResponse(
            job_id=str(running.id),
            status=running.status,
            message=f"Analysis already {running.status} for this extension.",
        )

    # Check cache: same version hash → return previous result
    if extension.last_version_hash:
        cached = (
            db.query(ScanResult)
            .filter(
                ScanResult.extension_id == ext_id,
                ScanResult.version_hash == extension.last_version_hash,
            )
            .order_by(ScanResult.scanned_at.desc())
            .first()
        )
        if cached:
            # Create a job that immediately points to cached result
            job = ScanJob(
                extension_id=ext_id,
                browser_type=req.browser,
                fast_mode=1 if req.fast_mode else 0,
                status="complete",
                progress_percent=100,
                progress_message="Returned cached result (same version)",
                completed_at=datetime.now(timezone.utc),
                result_id=cached.id,
            )
            db.add(job)
            db.commit()
            return AnalyzeResponse(
                job_id=str(job.id),
                status="complete",
                message="Cached result returned — extension version unchanged.",
            )

    # Create new job
    job = ScanJob(
        extension_id=ext_id,
        browser_type=req.browser,
        fast_mode=1 if req.fast_mode else 0,
        status="queued",
        progress_message="Waiting in queue...",
    )
    db.add(job)
    db.commit()

    # If Redis/RQ is available (Linux/WSL), enqueue job as usual
    if _QUEUE_AVAILABLE:
        redis_conn = _get_redis()
        q = Queue(settings.QUEUE_NAME, connection=redis_conn)
        q.enqueue(
            "api.worker.run_scan",
            str(job.id),
            job_timeout=settings.JOB_TIMEOUT,
        )
        return AnalyzeResponse(
            job_id=str(job.id),
            status="queued",
            message="Analysis queued.",
        )

    # Fallback for platforms without fork/RQ support (e.g. Windows):
    # run the scan synchronously in this request and update job/result directly.
    scan_service = ScanService(settings.REPORTS_DIR)
    if req.browser == "vscode":
        store = ScanStore.VSCODE
    elif req.browser == "edge":
        store = ScanStore.EDGE
    else:
        store = ScanStore.CHROME

    scan_request = ScanRequest(
        extension_id=ext_id,
        store=store,
        fast_mode=bool(req.fast_mode),
    )

    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    job.progress_message = "Running analysis (synchronous fallback)..."
    db.commit()

    output = scan_service.run(scan_request)

    if not output.success or not output.results:
        job.status = "error"
        job.error_message = output.error or "Analysis failed in synchronous mode."
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        return AnalyzeResponse(
            job_id=str(job.id),
            status=job.status,
            message=job.error_message or "Analysis failed.",
        )

    results = output.results

    # Compute summary metrics (mirror worker logic)
    supply = results.get("supply_chain", {}) or {}
    dep_vulns = supply.get("dependency_vulns", []) or []
    bundled_vulns = supply.get("bundled_js_vulns", []) or []
    patterns = results.get("malicious_patterns", []) or []
    vt_results = results.get("virustotal_results", []) or []

    vuln_count = sum(len(d.get("vulns", [])) for d in dep_vulns) + sum(
        len(b.get("vulns", [])) for b in bundled_vulns
    )
    malicious_domains = sum(
        1 for r in vt_results if r.get("threat_level") == "MALICIOUS"
    )
    critical_findings = sum(
        1 for p in patterns if p.get("severity") == "critical"
    )

    # Normalize threat_classification to string for DB
    threat_classification = results.get("threat_classification", "")
    if isinstance(threat_classification, dict):
        threat_classification = json.dumps(threat_classification)

    scan_result = ScanResult(
        extension_id=ext_id,
        version=results.get("version", ""),
        version_hash="",  # optional: compute via _compute_package_hash if needed
        risk_score=results.get("risk_score", 0.0),
        risk_level=results.get("risk_level", "UNKNOWN"),
        threat_classification=threat_classification,
        findings_count=len(patterns),
        json_report_path=output.json_report_path,
        html_report_path=output.html_report_path,
        vuln_count=vuln_count,
        malicious_domains=malicious_domains,
        critical_findings=critical_findings,
    )
    db.add(scan_result)
    db.flush()

    # Store report content in DB (single source of truth for report API)
    if output.json_report_path:
        try:
            with open(output.json_report_path, "r", encoding="utf-8") as f:
                scan_result.report_json = f.read()
        except Exception:
            pass
    if output.html_report_path:
        try:
            with open(output.html_report_path, "r", encoding="utf-8") as f:
                scan_result.report_html = f.read()
        except Exception:
            pass

    job.status = "complete"
    job.progress_percent = 100
    job.progress_message = "Analysis complete (synchronous fallback)"
    job.completed_at = datetime.now(timezone.utc)
    job.result_id = scan_result.id

    # Update extension record
    extension = db.query(Extension).filter(Extension.id == ext_id).first()
    if extension:
        extension.name = results.get("name", extension.name)
        extension.publisher = results.get("publisher", extension.publisher)
        extension.current_version = results.get("version", "")
        extension.last_scanned_at = datetime.now(timezone.utc)

    db.commit()

    return AnalyzeResponse(
        job_id=str(job.id),
        status="complete",
        message="Analysis completed synchronously (Windows/RQ fallback).",
    )


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
def get_job_status(
    job_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Get current status and progress for a scan job."""
    try:
        uid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job ID format.")

    job = db.query(ScanJob).filter(ScanJob.id == uid).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    report_url = None
    risk_score = None
    risk_level = None

    if job.result_id:
        result = db.query(ScanResult).filter(ScanResult.id == job.result_id).first()
        if result:
            report_url = f"/api/v1/reports/{job_id}"
            risk_score = result.risk_score
            risk_level = result.risk_level

    return JobStatusResponse(
        job_id=str(job.id),
        extension_id=job.extension_id,
        status=job.status,
        progress_percent=job.progress_percent,
        progress_message=job.progress_message,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        error_message=job.error_message,
        report_url=report_url,
        risk_score=risk_score,
        risk_level=risk_level,
    )


@router.post("/jobs/{job_id}/cancel")
def cancel_job(
    job_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Cancel a queued or running job."""
    try:
        uid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job ID format.")

    job = db.query(ScanJob).filter(ScanJob.id == uid).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    if job.status not in ("queued", "running"):
        return {"status": job.status, "message": f"Job is already {job.status}."}

    job.status = "cancelled"
    job.completed_at = datetime.now(timezone.utc)
    job.progress_message = "Cancelled by user"
    db.commit()

    return {"status": "cancelled", "message": "Job cancelled."}
