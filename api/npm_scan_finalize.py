"""
Shared DB commit path for completed npm-mal-scan jobs.

Keeps worker and API synchronous handler aligned (single place for ScanResult fields).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from api.models import Extension, ScanJob, ScanResult


def commit_npm_scan_to_job(db: Session, job: ScanJob, scan_output) -> None:
    """
    Persist ScanResult, load report blobs into DB, complete job, update Extension.

    Args:
        scan_output: NpmScanApiResult from npm_mal_scan_service.run_npm_package_scan
    """
    if not getattr(scan_output, "success", False):
        raise ValueError("commit_npm_scan_to_job requires a successful scan output")

    ext_id = job.extension_id
    results = scan_output.results
    patterns = results.get("malicious_patterns", []) or []
    threat_classification = results.get("threat_classification", "")
    if isinstance(threat_classification, dict):
        threat_classification = json.dumps(threat_classification)

    scan_result = ScanResult(
        extension_id=ext_id,
        version=results.get("version", ""),
        version_hash=scan_output.version_hash,
        risk_score=results.get("risk_score", 0.0),
        risk_level=results.get("risk_level", "UNKNOWN"),
        threat_classification=threat_classification,
        findings_count=len(patterns),
        json_report_path=scan_output.json_report_path,
        html_report_path=scan_output.html_report_path,
        vuln_count=0,
        malicious_domains=0,
        critical_findings=sum(1 for p in patterns if p.get("severity") == "critical"),
    )
    db.add(scan_result)
    db.flush()

    if scan_output.json_report_path:
        try:
            with open(scan_output.json_report_path, "r", encoding="utf-8") as f:
                scan_result.report_json = f.read()
        except OSError:
            pass
    if scan_output.html_report_path:
        try:
            with open(scan_output.html_report_path, "r", encoding="utf-8") as f:
                scan_result.report_html = f.read()
        except OSError:
            pass

    job.status = "complete"
    job.progress_percent = 100
    job.progress_message = "npm-mal-scan complete"
    job.completed_at = datetime.now(timezone.utc)
    job.result_id = scan_result.id

    extension = db.query(Extension).filter(Extension.id == ext_id).first()
    if extension:
        extension.name = results.get("name", extension.name)
        extension.publisher = "npm"
        extension.current_version = results.get("version", "")
        extension.last_scanned_at = datetime.now(timezone.utc)
        extension.last_version_hash = scan_output.version_hash

    db.commit()
