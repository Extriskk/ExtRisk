"""
Persist scan results to the API database so the Report API can serve them.

Used by the CLI analyzer after generating reports, so that GET
/api/v1/reports/by-extension/{extension_id} returns the latest run without
requiring a separate import step. Single source of truth: ScanResult.report_json
and report_html (see Brain.md section 4, docs/AI_CONTEXT.md).

This module is optional: if DATABASE_URL is not set or the DB is unavailable,
persist is skipped and the CLI continues normally.
"""

import json
from pathlib import Path
from typing import Optional

# Lazy imports to avoid pulling in api when running analyzer from CLI without DB
_SessionLocal = None
_Extension = None
_ScanResult = None
_settings = None


def _ensure_imports():
    global _SessionLocal, _Extension, _ScanResult, _settings
    if _SessionLocal is not None:
        return True
    try:
        from api.database import SessionLocal as SL
        from api.models import Extension, ScanResult
        from api.config import settings
        _SessionLocal = SL
        _Extension = Extension
        _ScanResult = ScanResult
        _settings = settings
        return True
    except Exception:
        return False


def _compute_version_hash(extension_dir: Optional[str]) -> str:
    """SHA-256 of manifest.json or package.json for cache key."""
    if not extension_dir:
        return ""
    base = Path(extension_dir)
    for name in ("manifest.json", "package.json"):
        p = base / name
        if p.exists():
            try:
                import hashlib
                return hashlib.sha256(p.read_bytes()).hexdigest()
            except Exception:
                pass
    return ""


def _summary_metrics_from_results(results: dict) -> tuple:
    """Return (vuln_count, malicious_domains, critical_findings)."""
    supply = results.get("supply_chain", {}) or {}
    dep_vulns = supply.get("dependency_vulns", []) or []
    bundled_vulns = supply.get("bundled_js_vulns", []) or []
    vuln_count = sum(len(d.get("vulns", [])) for d in dep_vulns) + sum(
        len(b.get("vulns", [])) for b in bundled_vulns
    )
    vt_results = results.get("virustotal_results", []) or []
    malicious_domains = sum(
        1 for r in vt_results if r.get("threat_level") == "MALICIOUS"
    )
    patterns = results.get("malicious_patterns", []) or []
    critical_findings = sum(
        1 for p in patterns if p.get("severity") == "critical"
    )
    return vuln_count, malicious_domains, critical_findings


def persist_scan_result_to_db(
    extension_id: str,
    browser_type: str,
    results: dict,
    json_report_path: Optional[str] = None,
    html_report_path: Optional[str] = None,
    extension_dir: Optional[str] = None,
    version_hash: Optional[str] = None,
) -> bool:
    """
    Persist a completed scan result into the API database so the Report API
    can serve it by extension_id (GET /api/v1/reports/by-extension/{id}).

    Call this from the CLI analyzer after generating report files. If the DB
    is unavailable or DATABASE_URL is not set, returns False and does not
    raise so the CLI run still succeeds.

    Args:
        extension_id: Extension ID (Chrome 32-char or publisher.name for VSCode).
        browser_type: "chrome", "edge", "vscode", or "npm".
        results: Full analysis results dict (for summary fields).
        json_report_path: Path to the JSON report file (content stored in DB).
        html_report_path: Path to the HTML report file (content stored in DB).
        extension_dir: Optional path to unpacked extension for version_hash.
        version_hash: If set, used instead of hashing manifest/package.json (e.g. npm spec).

    Returns:
        True if persisted, False if skipped or failed.
    """
    if not _ensure_imports():
        return False
    if not extension_id or not extension_id.strip():
        return False

    extension_id = extension_id.strip()
    if browser_type == "edge":
        extension_id = extension_id.lower()

    # Skip if persistence is explicitly disabled (no DB connection opened)
    url = getattr(_settings, "DATABASE_URL", "") or ""
    if url.strip().lower() in ("", "off", "skip"):
        return False

    db = None
    try:
        db = _SessionLocal()

        vuln_count, malicious_domains, critical_findings = _summary_metrics_from_results(results)
        patterns = results.get("malicious_patterns", []) or []
        threat_classification = results.get("threat_classification", "")
        if isinstance(threat_classification, dict):
            threat_classification = json.dumps(threat_classification)
        else:
            threat_classification = str(threat_classification or "")

        if version_hash is not None:
            version_hash = version_hash.strip()
        else:
            version_hash = _compute_version_hash(extension_dir) if extension_dir else ""

        report_json_content = None
        if json_report_path:
            p = Path(json_report_path)
            if p.is_file():
                try:
                    report_json_content = p.read_text(encoding="utf-8")
                except Exception:
                    pass
        report_html_content = None
        if html_report_path:
            p = Path(html_report_path)
            if p.is_file():
                try:
                    report_html_content = p.read_text(encoding="utf-8")
                except Exception:
                    pass

        # Upsert extension
        ext = db.query(_Extension).filter(_Extension.id == extension_id).first()
        name = results.get("name", "")
        publisher = results.get("publisher", "")
        if isinstance(publisher, dict):
            publisher = publisher.get("displayName", "") or str(publisher)
        store_meta = results.get("store_metadata") or {}
        if not publisher and isinstance(store_meta.get("publisher"), str):
            publisher = store_meta.get("publisher", "")
        version = results.get("version", "")

        if not ext:
            ext = _Extension(
                id=extension_id,
                name=name or None,
                publisher=publisher or None,
                browser_type=browser_type,
                current_version=version or None,
            )
            db.add(ext)
            db.flush()
        else:
            ext.name = name or ext.name
            ext.publisher = publisher or ext.publisher
            ext.current_version = version or ext.current_version
            ext.last_scanned_at = None  # set below via ScanResult.scanned_at for "latest"

        scan_result = _ScanResult(
            extension_id=extension_id,
            version=version or None,
            version_hash=version_hash or None,
            risk_score=float(results.get("risk_score", 0.0)),
            risk_level=results.get("risk_level", "UNKNOWN") or "UNKNOWN",
            threat_classification=threat_classification or None,
            findings_count=len(patterns),
            json_report_path=json_report_path,
            html_report_path=html_report_path,
            report_json=report_json_content,
            report_html=report_html_content,
            vuln_count=vuln_count,
            malicious_domains=malicious_domains,
            critical_findings=critical_findings,
        )
        db.add(scan_result)
        db.flush()

        ext.last_scanned_at = scan_result.scanned_at
        ext.last_version_hash = version_hash or ext.last_version_hash
        db.commit()
        return True
    except Exception:
        if db:
            try:
                db.rollback()
            except Exception:
                pass
        return False
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass
