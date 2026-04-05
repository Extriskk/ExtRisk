"""
POST /api/v1/npm/analyze — queue or run npm-mal-scan for an npm package spec.

Job status: GET /api/v1/jobs/{job_id} (shared with extension scans).
"""

import hashlib
import sys
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.config import settings
from api.database import get_db
from api.auth import require_api_key
from api.models import Extension, ScanJob, ScanResult
from api.schemas import AnalyzeResponse, NpmAnalyzeRequest

try:
    from redis import Redis
    from rq import Queue

    _QUEUE_AVAILABLE = True
except Exception:
    Redis = None  # type: ignore
    Queue = None  # type: ignore
    _QUEUE_AVAILABLE = False

if sys.platform == "win32":
    _QUEUE_AVAILABLE = False

router = APIRouter(prefix="/api/v1/npm", tags=["npm"])


def _get_redis():
    if not _QUEUE_AVAILABLE:
        raise RuntimeError("Redis/RQ queue not available on this platform.")
    return Redis.from_url(settings.REDIS_URL)


@router.post("/analyze", response_model=AnalyzeResponse)
def start_npm_analysis(
    req: NpmAnalyzeRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    from npm_mal_scan_service import npm_extension_id, validate_npm_package_spec

    spec = (req.package_spec or "").strip()
    verr = validate_npm_package_spec(spec)
    if verr:
        raise HTTPException(status_code=400, detail=verr)

    ext_id = npm_extension_id(spec)

    extension = db.query(Extension).filter(Extension.id == ext_id).first()
    if not extension:
        extension = Extension(
            id=ext_id,
            browser_type="npm",
        )
        db.add(extension)
        db.flush()

    running = (
        db.query(ScanJob)
        .filter(ScanJob.extension_id == ext_id, ScanJob.status.in_(["queued", "running"]))
        .first()
    )
    if running:
        return AnalyzeResponse(
            job_id=str(running.id),
            status=running.status,
            message=f"Analysis already {running.status} for this package.",
        )

    from npm_mal_scan_service import normalize_npm_package_spec

    spec_hash = hashlib.sha256(normalize_npm_package_spec(spec).encode("utf-8")).hexdigest()

    if extension.last_version_hash:
        cached = (
            db.query(ScanResult)
            .filter(
                ScanResult.extension_id == ext_id,
                ScanResult.version_hash == spec_hash,
            )
            .order_by(ScanResult.scanned_at.desc())
            .first()
        )
        if cached:
            job = ScanJob(
                extension_id=ext_id,
                browser_type="npm",
                fast_mode=0,
                status="complete",
                progress_percent=100,
                progress_message="Returned cached result (same package spec)",
                completed_at=datetime.now(timezone.utc),
                result_id=cached.id,
            )
            db.add(job)
            db.commit()
            return AnalyzeResponse(
                job_id=str(job.id),
                status="complete",
                message="Cached npm-mal-scan result for this package spec.",
            )

    job = ScanJob(
        extension_id=ext_id,
        browser_type="npm",
        fast_mode=0,
        status="queued",
        progress_message="Waiting in queue...",
    )
    db.add(job)
    db.commit()

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
            message="npm-mal-scan queued.",
        )

    from npm_mal_scan_service import run_npm_package_scan

    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    job.progress_message = "Running npm-mal-scan (synchronous)..."
    db.commit()

    output = run_npm_package_scan(spec, settings.REPORTS_DIR, timeout=settings.JOB_TIMEOUT)

    if not output.success:
        job.status = "error"
        job.error_message = output.error or "npm-mal-scan failed."
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        return AnalyzeResponse(
            job_id=str(job.id),
            status=job.status,
            message=job.error_message or "npm-mal-scan failed.",
        )

    from api.npm_scan_finalize import commit_npm_scan_to_job

    job_id_str = str(job.id)
    try:
        commit_npm_scan_to_job(db, job, output)
    except Exception as e:
        db.rollback()
        job_row = db.query(ScanJob).filter(ScanJob.id == job.id).first()
        if job_row:
            job_row.status = "error"
            job_row.error_message = str(e)[:2000]
            job_row.completed_at = datetime.now(timezone.utc)
            db.commit()
        return AnalyzeResponse(
            job_id=job_id_str,
            status="error",
            message="Failed to persist npm-mal-scan result.",
        )

    return AnalyzeResponse(
        job_id=str(job.id),
        status="complete",
        message="npm-mal-scan completed (synchronous).",
    )
