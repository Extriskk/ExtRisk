"""
Central store writer: ingest analysis report(s) into the central JSON store.

Run after the post-enhancement re-run (or on-demand) to upsert the final report
into central_store for API consumption. Does not write first-run reports unless
invoked explicitly.

Usage (from repo root):
  python scripts/central_store_writer.py --report reports/vscode_dbaeumer.vscode-eslint_analysis.json
  python scripts/central_store_writer.py --manifest batch_runs/batch_manifest_sample_small_2026-02-21.json
  python scripts/central_store_writer.py --manifest batch_runs/... --only-success
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def repo_root():
    return Path(__file__).resolve().parent.parent


def safe_identifier(extension_id: str) -> str:
    """Safe filename segment for extension ID."""
    return re.sub(r"[^\w\-.]", "_", extension_id)


def load_report(path: Path) -> dict | None:
    """Load and return report JSON, or None on error."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def build_store_record(report: dict, source: str = "batch") -> dict:
    """Wrap report with store metadata."""
    extension_id = report.get("extension_id") or report.get("identifier") or "unknown"
    version = report.get("version") or ""
    return {
        "extension_id": extension_id,
        "platform": report.get("extension_type") or "vscode",
        "version_analyzed": version,
        "analyzed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "report_schema": "v1",
        "payload": report,
    }


def write_to_store(store_dir: Path, record: dict) -> Path:
    """Write one record to central_store/vscode/<safe_id>.json. Returns path written."""
    store_dir.mkdir(parents=True, exist_ok=True)
    safe_id = safe_identifier(record["extension_id"])
    # Flat layout: central_store/vscode/<safe_id>.json
    sub = store_dir / "vscode"
    sub.mkdir(parents=True, exist_ok=True)
    out_path = sub / f"{safe_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return out_path


def main():
    parser = argparse.ArgumentParser(
        description="Ingest analysis report(s) into the central store (run after post-enhancement re-run)."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--report", type=Path, help="Path to one report JSON")
    group.add_argument("--manifest", type=Path, help="Path to batch manifest (ingest all report_json)")
    parser.add_argument(
        "--only-success",
        action="store_true",
        help="With --manifest: only ingest extensions that have success=true",
    )
    parser.add_argument(
        "--store-dir",
        type=Path,
        default=None,
        help="Central store root (default: repo central_store/)",
    )
    args = parser.parse_args()

    repo = repo_root()
    store_dir = (args.store_dir or repo / "central_store").resolve()

    if args.report:
        report_path = args.report.resolve()
        if not report_path.is_file():
            print(f"[!] Report not found: {report_path}", file=sys.stderr)
            sys.exit(1)
        report = load_report(report_path)
        if not report:
            print(f"[!] Failed to load report: {report_path}", file=sys.stderr)
            sys.exit(1)
        record = build_store_record(report, source="single")
        out = write_to_store(store_dir, record)
        print(f"[+] Wrote {record['extension_id']} -> {out}")
        return

    # --manifest
    manifest_path = args.manifest.resolve()
    if not manifest_path.is_file():
        print(f"[!] Manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    extensions = manifest.get("extensions", [])
    if args.only_success:
        extensions = [e for e in extensions if e.get("success")]
    written = 0
    for ext in extensions:
        report_json = ext.get("report_json")
        if not report_json:
            continue
        path = Path(report_json)
        if not path.is_absolute():
            path = repo / report_json
        if not path.is_file():
            print(f"[!] Skip {ext.get('id')}: report not found {path}", file=sys.stderr)
            continue
        report = load_report(path)
        if not report:
            print(f"[!] Skip {ext.get('id')}: failed to load report", file=sys.stderr)
            continue
        record = build_store_record(report, source="batch")
        write_to_store(store_dir, record)
        written += 1
        print(f"  {record['extension_id']}")
    print(f"[+] Ingested {written} reports into {store_dir / 'vscode'}")


if __name__ == "__main__":
    main()
