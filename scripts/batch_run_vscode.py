"""
Batch runner for VSCode extension analysis (marketplace validation pipeline).

Runs the existing analyzer on each extension in a cohort, then builds a manifest
(extension_id -> report paths, extraction path) for Bablu review and validation.
Does not modify the analyzer; calls it via subprocess.

Supports parallel workers: use --workers N to run N analyses at once (default 1).
When workers > 1, analyzer stdout/stderr are suppressed to avoid interleaved output.
Success = analyzer exit 0 (low risk), 1 (medium), 2 (high), or 3 (critical); only
exit 4 (analysis failed) or timeout is treated as FAIL. On FAIL in parallel mode,
the last 25 lines of stderr are printed for debugging.

Usage (from repo root):
  python scripts/batch_run_vscode.py data/cohorts/sample_small.json
  python scripts/batch_run_vscode.py data/cohorts/sample_small.json --workers 4 --fast
  python scripts/batch_run_vscode.py data/cohorts/sample_small.json --skip-vt --limit 2

Output:
  - Reports in reports/ (existing analyzer behavior)
  - Extracted extensions in data/vscode_extensions/ (existing unpacker behavior)
  - Manifest: batch_runs/batch_manifest_<cohort>_<date>.json
"""

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple


def repo_root():
    """Project root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def safe_identifier(extension_id: str) -> str:
    """Same as vscode_analyzer save_report: safe filename segment."""
    return re.sub(r"[^\w\-.]", "_", extension_id)


def discover_report_paths(reports_dir: Path, extension_id: str) -> Tuple[Optional[Path], Optional[Path]]:
    """Discover JSON and HTML report paths for an extension (after analyzer run)."""
    safe = safe_identifier(extension_id)
    json_path = reports_dir / f"vscode_{safe}_analysis.json"
    html_path = reports_dir / f"vscode_{safe}_threat_analysis_report.html"
    return (json_path if json_path.exists() else None, html_path if html_path.exists() else None)


def discover_extension_dir(extract_base: Path, extension_id: str) -> Optional[Path]:
    """
    Discover extraction directory for an extension.
    Unpacker uses extract_base / <vsix_stem> / "extension" or extract_base / <vsix_stem>.
    vsix_stem = publisher.name-version (e.g. ms-python.python-2024.1.0).
    """
    if not extract_base.exists():
        return None
    prefix = f"{extension_id}-"
    candidates = []
    for d in extract_base.iterdir():
        if not d.is_dir():
            continue
        if d.name.startswith(prefix) or d.name == extension_id:
            ext_sub = d / "extension"
            if ext_sub.exists():
                candidates.append((ext_sub, d.stat().st_mtime))
            else:
                candidates.append((d, d.stat().st_mtime))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]


def load_cohort(path: Path) -> list[str]:
    """Load extension IDs from a cohort JSON file."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    ids = data.get("extension_ids") or data.get("extensions") or []
    if isinstance(ids, list) and ids and isinstance(ids[0], str):
        return ids
    return []


# Analyzer exit codes: 0=low risk, 1=medium, 2=high, 3=critical, 4=analysis failed
# Batch treats 0-3 as success (report generated), 4 or timeout/exception as failure.
ANALYZER_SUCCESS_CODES = (0, 1, 2, 3)


def run_analyzer(
    extension_id: str,
    repo: Path,
    skip_vt: bool = False,
    fast: bool = False,
    capture_output: bool = False,
) -> tuple[bool, str | None]:
    """Run the analyzer for one extension. Returns (success, stderr_or_none)."""
    cmd = [sys.executable, str(repo / "src" / "analyzer.py"), extension_id, "--vscode"]
    if skip_vt:
        cmd.append("--skip-vt")
    if fast:
        cmd.append("--fast")
    try:
        result = subprocess.run(
            cmd,
            cwd=str(repo),
            capture_output=capture_output,
            timeout=600,
        )
        ok = result.returncode in ANALYZER_SUCCESS_CODES
        stderr = None
        if capture_output and result.stderr:
            stderr = result.stderr.decode("utf-8", errors="replace")
        return (ok, stderr)
    except subprocess.TimeoutExpired:
        return (False, "Timeout after 600s")
    except Exception as e:
        return (False, str(e))


def main():
    parser = argparse.ArgumentParser(
        description="Batch run VSCode extension analysis and build manifest for review."
    )
    parser.add_argument(
        "cohort",
        type=Path,
        help="Path to cohort JSON (e.g. data/cohorts/sample_small.json)",
    )
    parser.add_argument(
        "--skip-vt",
        action="store_true",
        help="Skip VirusTotal checks (pass --skip-vt to analyzer)",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Fast mode: skip VT and OSINT (pass --fast to analyzer)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max number of extensions to run (0 = all)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for batch manifest (default: batch_runs/)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help="Number of parallel workers (default 1). Use 4–6 to speed up batch runs.",
    )
    args = parser.parse_args()

    workers = max(1, min(args.workers, 32))
    if args.workers != workers:
        print(f"[i] Workers clamped to {workers}")

    repo = repo_root()
    cohort_path = args.cohort.resolve()
    if not cohort_path.is_file():
        print(f"[!] Cohort file not found: {cohort_path}")
        sys.exit(1)

    extension_ids = load_cohort(cohort_path)
    if not extension_ids:
        print(f"[!] No extension_ids in {cohort_path}")
        sys.exit(1)

    cohort_name = cohort_path.stem
    if args.limit:
        extension_ids = extension_ids[: args.limit]
        print(f"[i] Limited to first {args.limit} extensions")

    reports_dir = repo / "reports"
    extract_base = repo / "data" / "vscode_extensions"
    out_dir = args.output_dir or repo / "batch_runs"
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "cohort": cohort_name,
        "cohort_path": str(cohort_path),
        "run_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "extensions": [],
    }
    total = len(extension_ids)
    capture_output = workers > 1

    if workers == 1:
        # Sequential: same behavior as before, with analyzer output visible
        for i, ext_id in enumerate(extension_ids, 1):
            print(f"\n[{i}/{total}] {ext_id}")
            ok, _ = run_analyzer(ext_id, repo, skip_vt=args.skip_vt, fast=args.fast, capture_output=False)
            json_report, html_report = discover_report_paths(reports_dir, ext_id)
            ext_dir = discover_extension_dir(extract_base, ext_id)
            entry = {
                "id": ext_id,
                "success": ok,
                "report_json": str(json_report) if json_report else None,
                "report_html": str(html_report) if html_report else None,
                "extraction_path": str(ext_dir) if ext_dir else None,
            }
            manifest["extensions"].append(entry)
            if not ok:
                print(f"    [!] Analyzer failed (exit 4) or timed out")
            else:
                print(f"    JSON: {json_report}")
                print(f"    HTML: {html_report}")
                print(f"    Dir:  {ext_dir}")
    else:
        # Parallel: run N workers, suppress analyzer stdout/stderr, print progress only
        print(f"[i] Running with {workers} workers (analyzer output suppressed)")
        results = {}  # ext_id -> (success, stderr_or_none)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_id = {
                executor.submit(
                    run_analyzer,
                    ext_id,
                    repo,
                    args.skip_vt,
                    args.fast,
                    capture_output,
                ): ext_id
                for ext_id in extension_ids
            }
            done = 0
            for future in as_completed(future_to_id):
                ext_id = future_to_id[future]
                done += 1
                try:
                    ok, stderr = future.result()
                except Exception as e:
                    ok, stderr = False, str(e)
                results[ext_id] = (ok, stderr)
                status = "OK" if ok else "FAIL"
                print(f"    [{done}/{total}] {ext_id}: {status}")
                if not ok and stderr:
                    # Show last 25 lines of stderr so failures are debuggable
                    lines = stderr.strip().splitlines()
                    tail = lines[-25:] if len(lines) > 25 else lines
                    for line in tail:
                        print(f"        | {line}")

        for ext_id in extension_ids:
            ok = results.get(ext_id, (False, None))[0]
            json_report, html_report = discover_report_paths(reports_dir, ext_id)
            ext_dir = discover_extension_dir(extract_base, ext_id)
            manifest["extensions"].append({
                "id": ext_id,
                "success": ok,
                "report_json": str(json_report) if json_report else None,
                "report_html": str(html_report) if html_report else None,
                "extraction_path": str(ext_dir) if ext_dir else None,
            })

    date_str = manifest["run_date"][:10]
    manifest_path = out_dir / f"batch_manifest_{cohort_name}_{date_str}.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n[+] Manifest written: {manifest_path}")
    success_count = sum(1 for e in manifest["extensions"] if e["success"])
    print(f"    {success_count}/{total} extensions analyzed successfully.")


if __name__ == "__main__":
    main()
