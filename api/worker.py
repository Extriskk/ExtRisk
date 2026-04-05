"""
RQ worker — processes scan jobs from the Redis queue.

Run with:
    python -m api.worker          (starts the worker loop)
    python -m api.worker --burst  (process queue then exit — for testing)

Or via rq:
    rq worker scans --url redis://localhost:6379/0
"""

import os
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timezone

# Ensure project paths are available
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "src"))
os.chdir(PROJECT_ROOT)

from sqlalchemy.orm import Session
from api.database import SessionLocal
from api.models import ScanJob, ScanResult, Extension
from api.config import settings
from scan_service import ScanService, ScanRequest, ScanStore
import json


def _compute_package_hash(extension_dir: str) -> str:
    """SHA-256 hash of the manifest file to detect version changes."""
    manifest = Path(extension_dir) / "manifest.json"
    if not manifest.exists():
        # VSCode: try package.json
        manifest = Path(extension_dir) / "package.json"
    if not manifest.exists():
        return ""
    return hashlib.sha256(manifest.read_bytes()).hexdigest()


def run_scan(job_id: str) -> None:
    """
    Execute an extension analysis job.

    Called by RQ — receives job_id, loads job from DB, runs analyzer,
    stores result.
    """
    db: Session = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            return

        if job.status == "cancelled":
            return

        # Mark running
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        job.progress_message = "Starting analysis..."
        db.commit()

        # Progress callback — updates DB periodically
        _last_commit = [0.0]

        def progress_callback(percent: int, step_name: str, detail: str):
            # Re-read job status to check for cancellation
            db.refresh(job)
            if job.status == "cancelled":
                raise InterruptedError("Job cancelled by user")

            job.progress_percent = percent
            job.progress_message = f"{step_name}: {detail}" if detail else step_name

            # Throttle DB commits to avoid overhead (every 2 seconds)
            import time
            now = time.time()
            if now - _last_commit[0] > 2.0:
                db.commit()
                _last_commit[0] = now

        # npm-mal-scan (registry package heuristics)
        if job.browser_type == "npm":
            from api.npm_scan_finalize import commit_npm_scan_to_job
            from npm_mal_scan_service import (
                NPKG_PREFIX,
                npm_spec_from_extension_id,
                run_npm_package_scan,
                validate_npm_package_spec,
            )

            if not job.extension_id.lower().startswith(NPKG_PREFIX):
                job.status = "error"
                job.error_message = "Invalid npm job: extension_id must start with npkg:"
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
                return

            spec = npm_spec_from_extension_id(job.extension_id)
            verr = validate_npm_package_spec(spec)
            if verr:
                job.status = "error"
                job.error_message = verr[:2000]
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
                return

            job.progress_message = "Running npm-mal-scan..."
            db.commit()

            scan_output = run_npm_package_scan(
                spec, settings.REPORTS_DIR, timeout=settings.JOB_TIMEOUT
            )

            if not scan_output.success:
                job.status = "error"
                job.error_message = scan_output.error or "npm-mal-scan failed."
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
                return

            job_pk = job.id
            try:
                commit_npm_scan_to_job(db, job, scan_output)
            except Exception as e:
                db.rollback()
                job_row = db.query(ScanJob).filter(ScanJob.id == job_pk).first()
                if job_row:
                    job_row.status = "error"
                    job_row.error_message = str(e)[:2000]
                    job_row.completed_at = datetime.now(timezone.utc)
                    db.commit()
            return

        # Build scan request and run through ScanService
        if job.browser_type == "vscode":
            store = ScanStore.VSCODE
        elif job.browser_type == "edge":
            store = ScanStore.EDGE
        else:
            store = ScanStore.CHROME

        scan_service = ScanService(settings.REPORTS_DIR)
        scan_request = ScanRequest(
            extension_id=job.extension_id,
            store=store,
            fast_mode=bool(job.fast_mode),
        )
        scan_output = scan_service.run(scan_request, progress_callback=progress_callback)

        if not scan_output.success or not scan_output.results:
            job.status = "error"
            job.error_message = (
                scan_output.error
                or "Analysis returned no results — extension may not exist or is inaccessible."
            )
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        results = scan_output.results

        # Compute version hash for caching
        ext_dir = scan_output.extension_dir
        version_hash = _compute_package_hash(ext_dir) if ext_dir else ""

        # Report file paths (normalized via ScanService)
        ext_id = job.extension_id
        json_path = scan_output.json_report_path
        html_path = scan_output.html_report_path

        # Extract summary metrics from results
        patterns = results.get("malicious_patterns", [])
        vt_results = results.get("virustotal_results", [])
        supply = results.get("supply_chain", {})
        dep_vulns = supply.get("dependency_vulns", [])
        bundled_vulns = supply.get("bundled_js_vulns", [])

        vuln_count = sum(len(d.get("vulns", [])) for d in dep_vulns) + sum(
            len(b.get("vulns", [])) for b in bundled_vulns
        )
        malicious_domains = sum(
            1 for r in vt_results if r.get("threat_level") == "MALICIOUS"
        )
        critical_findings = sum(
            1 for p in patterns if p.get("severity") == "critical"
        )

        # Create ScanResult (ensure threat_classification is stored as JSON string)
        threat_classification = results.get("threat_classification", "")
        if isinstance(threat_classification, dict):
            threat_classification = json.dumps(threat_classification)

        scan_result = ScanResult(
            extension_id=ext_id,
            version=results.get("version", ""),
            version_hash=version_hash,
            risk_score=results.get("risk_score", 0.0),
            risk_level=results.get("risk_level", "UNKNOWN"),
            threat_classification=threat_classification,
            findings_count=len(patterns),
            json_report_path=json_path,
            html_report_path=html_path,
            vuln_count=vuln_count,
            malicious_domains=malicious_domains,
            critical_findings=critical_findings,
        )
        db.add(scan_result)
        db.flush()

        # Store report content in DB (single source of truth for report API)
        if json_path:
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    scan_result.report_json = f.read()
            except Exception:
                pass
        if html_path:
            try:
                with open(html_path, "r", encoding="utf-8") as f:
                    scan_result.report_html = f.read()
            except Exception:
                pass

        # Update job
        job.status = "complete"
        job.progress_percent = 100
        job.progress_message = "Analysis complete"
        job.completed_at = datetime.now(timezone.utc)
        job.result_id = scan_result.id

        # Update extension record
        extension = db.query(Extension).filter(Extension.id == ext_id).first()
        if extension:
            extension.name = results.get("name", extension.name)
            extension.publisher = results.get("publisher", extension.publisher)
            extension.current_version = results.get("version", "")
            extension.last_scanned_at = datetime.now(timezone.utc)
            extension.last_version_hash = version_hash

        db.commit()

    except InterruptedError:
        job.status = "cancelled"
        job.completed_at = datetime.now(timezone.utc)
        job.progress_message = "Cancelled during execution"
        db.commit()

    except Exception as e:
        db.rollback()
        try:
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if job:
                job.status = "error"
                job.error_message = str(e)[:2000]
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass

    finally:
        db.close()


# ── CLI entry point ──────────────────────────────────────────────────
if __name__ == "__main__":
    from redis import Redis
    from rq import Worker, Queue

    redis_conn = Redis.from_url(settings.REDIS_URL)
    queues = [Queue(settings.QUEUE_NAME, connection=redis_conn)]

    burst = "--burst" in sys.argv

    print(f"Starting RQ worker on queue '{settings.QUEUE_NAME}'...")
    print(f"Redis: {settings.REDIS_URL}")
    print(f"Burst mode: {burst}")

    worker = Worker(queues, connection=redis_conn)
    worker.work(burst=burst)
