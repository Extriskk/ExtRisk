"""
Import existing report files from reports/ into the API database.

Scans reports/*_analysis.json, reads matching *_threat_analysis_report.html,
and creates/updates Extension and ScanResult rows with report content stored in DB.

Run from repo root (with venv active and DATABASE_URL set if needed):
  python scripts/import_reports_to_db.py
  python scripts/import_reports_to_db.py --reports-dir path/to/reports --dry-run
"""

import json
import re
import sys
from pathlib import Path

# Project root and api on path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from api.database import SessionLocal
from api.models import Extension, ScanResult


def _extension_type_to_browser(extension_type: str) -> str:
    if extension_type == "vscode":
        return "vscode"
    return "chrome"


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Import report files into API DB")
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=REPO_ROOT / "reports",
        help="Directory containing *_analysis.json and *_threat_analysis_report.html",
    )
    parser.add_argument("--dry-run", action="store_true", help="Do not write to DB")
    args = parser.parse_args()

    reports_dir = args.reports_dir.resolve()
    if not reports_dir.is_dir():
        print(f"[!] Not a directory: {reports_dir}")
        sys.exit(1)

    # Find all *_analysis.json (skip *_analysis.json from other naming if any)
    json_files = list(reports_dir.glob("*_analysis.json"))
    if not json_files:
        print(f"[i] No *_analysis.json files in {reports_dir}")
        return

    db = SessionLocal()
    imported = 0
    errors = 0

    try:
        for json_path in sorted(json_files):
            stem = json_path.stem  # e.g. "vscode_vscode.vscode-theme-seti_analysis" -> need base
            base = re.sub(r"_analysis$", "", stem)
            html_path = reports_dir / f"{base}_threat_analysis_report.html"

            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                print(f"[!] Failed to read {json_path.name}: {e}")
                errors += 1
                continue

            extension_id = data.get("extension_id") or data.get("identifier")
            if not extension_id:
                print(f"[!] No extension_id/identifier in {json_path.name}")
                errors += 1
                continue

            version = data.get("version", "")
            risk_score = float(data.get("risk_score", 0))
            risk_level = data.get("risk_level", "UNKNOWN")
            threat_classification = data.get("threat_classification")
            if isinstance(threat_classification, dict):
                threat_classification = json.dumps(threat_classification)
            else:
                threat_classification = str(threat_classification or "")

            patterns = data.get("malicious_patterns", [])
            supply = data.get("supply_chain", {}) or {}
            dep_vulns = supply.get("dependency_vulns", []) or []
            bundled_vulns = supply.get("bundled_js_vulns", []) or []
            vuln_count = sum(len(d.get("vulns", [])) for d in dep_vulns) + sum(
                len(b.get("vulns", [])) for b in bundled_vulns
            )
            vt_results = data.get("virustotal_results", []) or []
            malicious_domains = sum(1 for r in vt_results if r.get("threat_level") == "MALICIOUS")
            critical_findings = sum(1 for p in patterns if p.get("severity") == "critical")

            report_json_content = json_path.read_text(encoding="utf-8")
            report_html_content = ""
            if html_path.exists():
                report_html_content = html_path.read_text(encoding="utf-8")

            extension_type = data.get("extension_type", "chrome")
            browser_type = _extension_type_to_browser(extension_type)
            name = data.get("name", "")
            publisher = data.get("publisher", "")
            if isinstance(publisher, dict):
                publisher = publisher.get("displayName", "") or str(publisher)
            store_meta = data.get("store_metadata") or {}
            if not publisher and isinstance(store_meta.get("publisher"), str):
                publisher = store_meta.get("publisher", "")

            if args.dry_run:
                print(f"[dry-run] Would import: {extension_id} v{version} ({json_path.name})")
                imported += 1
                continue

            # Upsert extension
            ext = db.query(Extension).filter(Extension.id == extension_id).first()
            if not ext:
                ext = Extension(
                    id=extension_id,
                    name=name,
                    publisher=publisher,
                    browser_type=browser_type,
                    current_version=version,
                )
                db.add(ext)
                db.flush()
            else:
                ext.name = name or ext.name
                ext.publisher = publisher or ext.publisher
                ext.current_version = version or ext.current_version

            # Create ScanResult with report content in DB
            scan_result = ScanResult(
                extension_id=extension_id,
                version=version,
                version_hash="",
                risk_score=risk_score,
                risk_level=risk_level,
                threat_classification=threat_classification or None,
                findings_count=len(patterns),
                json_report_path=str(json_path),
                html_report_path=str(html_path) if html_path.exists() else None,
                report_json=report_json_content,
                report_html=report_html_content if report_html_content else None,
                vuln_count=vuln_count,
                malicious_domains=malicious_domains,
                critical_findings=critical_findings,
            )
            db.add(scan_result)
            db.flush()
            imported += 1
            db.commit()  # commit after each so we don't hold a long-lived lock
            print(f"[+] Imported: {extension_id} v{version}")

        if not args.dry_run:
            # already committed per-record above
            pass
        print(f"\n[i] Imported {imported} report(s). Errors: {errors}")
    except Exception as e:
        db.rollback()
        print(f"[!] Error: {e}")
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
