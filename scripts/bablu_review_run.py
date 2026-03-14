"""
Run Bablu review: compare report findings to main JS and produce bablu_review_<id>.json.

For each extension in the manifest: loads report, gets main JS list, filters code_analysis
findings to those in main JS (or dist/out/src app code), verifies each finding against
source (evidence at cited line), and writes batch_runs/bablu_reviews/bablu_review_<id>.json.

Usage (from repo root):
  python scripts/bablu_review_run.py --manifest batch_runs/batch_manifest_recent_10_2026-02-22.json
  python scripts/bablu_review_run.py --manifest batch_runs/... --id ms-python.isort
"""

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def repo_root():
    return Path(__file__).resolve().parent.parent


def safe_id(extension_id: str) -> str:
    return re.sub(r"[^\w\-.]", "_", extension_id)


def get_main_js_files(extension_dir: Path, repo: Path) -> list[str]:
    """Return list of main JS relative paths (forward slashes)."""
    cmd = [
        sys.executable,
        str(repo / "scripts" / "list_main_js.py"),
        "--path",
        str(extension_dir),
        "--json",
    ]
    try:
        out = subprocess.run(cmd, cwd=str(repo), capture_output=True, text=True, timeout=10)
        if out.returncode != 0:
            return []
        data = json.loads(out.stdout)
        return [p.replace("\\", "/") for p in data.get("main_js_relative", [])]
    except Exception:
        return []


def normalize_finding_file(f: str) -> str:
    return f.replace("\\", "/").lstrip("/")


def finding_in_main_js_scope(norm_file: str, main_js_relative: list[str]) -> bool:
    """True if this finding file is in main JS set or under dist/out/src (app code)."""
    if not norm_file or "node_modules" in norm_file:
        return False
    for m in main_js_relative:
        if norm_file == m or norm_file.startswith(m.split("/")[0] + "/"):
            return True
    if norm_file.startswith("dist/") or norm_file.startswith("out/") or norm_file.startswith("src/"):
        return True
    return norm_file in main_js_relative


def read_line_or_context(file_path: Path, line_num: int, context_lines: int = 2) -> str:
    """Read line(s) around line_num (1-based). Returns up to context_lines before + line + context_lines after."""
    if not file_path.exists():
        return ""
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return ""
    if line_num < 1 or line_num > len(lines):
        return ""
    start = max(0, line_num - 1 - context_lines)
    end = min(len(lines), line_num + context_lines)
    return "".join(lines[start:end])


# DETECTION_GAPS_LOG: allowlisted domains (publisher mismatch / suspicious domain -> FP)
_BENIGN_DOMAIN_SUBSTRINGS = (
    "jsdelivr", "cdnjs", "unpkg", "npmjs.com", "w3.org", "kroki.io", "shields.io",
    "localhost", "127.0.0.1", "schemas.microsoft.com", "code.visualstudio.com",
    "schemastore.org", "json.schemastore.org",
)


def verify_finding(extraction_path: Path, finding: dict, repo: Path) -> tuple[str, str]:
    """
    Check if finding evidence appears at cited file/line. Return (verdict, notes).
    Verdict: TP, FP, NEEDS_REVIEW. Applies DETECTION_GAPS_LOG FP rules.
    """
    norm_file = normalize_finding_file(finding.get("file", ""))
    line_num = finding.get("line", 0)
    evidence = (finding.get("evidence") or "").strip()
    path_type = finding.get("path_type", "app")
    category = finding.get("category", "")
    name = finding.get("name", "")

    if path_type == "dependency":
        return ("FP", "Finding in dependency path; not app code.")

    # DETECTION_GAPS_LOG: .eval( / this.eval( are method calls, not global eval
    if "eval" in name.lower() or "eval" in category.lower():
        if ".eval(" in evidence or "this.eval(" in evidence:
            return ("FP", "Method call, not global eval (library internal).")

    # DETECTION_GAPS_LOG: base64 with hex-only (no + or /) -> color/hash, not base64
    if "base64" in name.lower() or "base64" in category.lower():
        matched = evidence.strip("'\"").rstrip("=")
        if matched and len(matched) >= 20 and all(c in "0123456789abcdefABCDEF" for c in matched):
            return ("FP", "Hex-only string, no + or /; likely color/hash, not base64.")

    # DETECTION_GAPS_LOG: allowlisted CDN/infra in URL findings
    if "url" in category.lower() or "http" in name.lower() or "domain" in category.lower():
        ev_lower = evidence.lower()
        if any(d in ev_lower for d in _BENIGN_DOMAIN_SUBSTRINGS):
            return ("FP", "Allowlisted CDN/infra domain.")

    full_path = (Path(extraction_path) / norm_file).resolve()
    if not full_path.exists():
        return ("NEEDS_REVIEW", "File not found at extraction path.")

    context = read_line_or_context(full_path, line_num)
    if not context:
        return ("NEEDS_REVIEW", "Could not read line or line out of range.")

    # Evidence might be truncated; check if key part appears in context
    evidence_clean = evidence[:80].replace("\n", " ")
    if evidence_clean in context or (len(evidence_clean) > 20 and evidence_clean[:30] in context):
        if "navigator.userAgent" in evidence and "telemetry" in category.lower():
            return ("TP", "Legitimate telemetry/fingerprinting in app code.")
        if "shell:!0" in evidence or "shell: true" in evidence:
            if "spawnSync" in context or "copilot" in context.lower():
                return ("TP", "Legitimate shell use for CLI check (Copilot).")
        if "child_process" in evidence and "require(" in context:
            return ("TP", "child_process import present.")
        return ("TP", "Evidence found at cited line.")
    if evidence[:30] in context or (len(evidence) >= 30 and evidence[-30:] in context):
        return ("TP", "Evidence fragment found at cited line.")
    return ("NEEDS_REVIEW", "Evidence not found in cited line context.")


def run_review_for_extension(
    extension_id: str,
    report_path: Path,
    extraction_path: Path,
    repo: Path,
) -> dict:
    """Load report, get main JS, verify findings in scope, return review dict."""
    if not report_path.exists():
        return {"extension_id": extension_id, "error": "Report not found", "findings_verified": []}
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    main_js = get_main_js_files(Path(extraction_path), repo)
    all_findings = report.get("code_analysis", {}).get("all_findings", [])
    if not all_findings:
        all_findings = report.get("malicious_patterns", [])

    findings_in_scope = []
    for f in all_findings:
        norm = normalize_finding_file(f.get("file", ""))
        if not finding_in_main_js_scope(norm, main_js):
            continue
        findings_in_scope.append(f)

    findings_verified = []
    for f in findings_in_scope:
        verdict, notes = verify_finding(Path(extraction_path), f, repo)
        findings_verified.append({
            "name": f.get("name"),
            "file": normalize_finding_file(f.get("file", "")),
            "line": f.get("line"),
            "severity": f.get("severity"),
            "category": f.get("category"),
            "evidence": (f.get("evidence") or "")[:200],
            "verdict": verdict,
            "notes": notes,
        })

    risk_score = report.get("risk_score", 0)
    risk_level = report.get("risk_level", "UNKNOWN")

    # Include metadata, supply-chain, and package.json deep findings for full Bablu review
    metadata_findings = report.get("metadata_risk", {}).get("findings", [])
    supply_findings = report.get("supply_chain", {}).get("findings", [])
    pkg_deep_findings = report.get("package_json_deep", {}).get("findings", [])

    return {
        "extension_id": extension_id,
        "reviewed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "report_json": str(report_path),
        "extraction_path": str(extraction_path),
        "main_js_files": main_js,
        "risk_score_reported": risk_score,
        "risk_level_reported": risk_level,
        "findings_verified": findings_verified,
        "metadata_findings": metadata_findings,
        "supply_chain_findings": supply_findings,
        "package_json_deep_findings": pkg_deep_findings,
        "corrections": [],
        "gaps": [],
        "risk_score_feedback": None,
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run Bablu review: report vs main JS, write bablu_review_<id>.json")
    parser.add_argument("--manifest", type=Path, required=True, help="Batch manifest JSON")
    parser.add_argument("--id", type=str, default=None, help="Single extension ID (default: all success)")
    args = parser.parse_args()

    repo = repo_root()
    manifest_path = args.manifest.resolve()
    if not manifest_path.is_file():
        print(f"[!] Manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    review_dir = repo / "batch_runs" / "bablu_reviews"
    review_dir.mkdir(parents=True, exist_ok=True)

    extensions = manifest.get("extensions", [])
    if args.id:
        extensions = [e for e in extensions if e.get("id") == args.id]
    else:
        extensions = [e for e in extensions if e.get("success") and e.get("extraction_path")]

    cohort_name = manifest.get("cohort", "cohort")
    reviewed_count = 0
    for ext in extensions:
        ext_id = ext["id"]
        report_json = ext.get("report_json")
        extraction_path = ext.get("extraction_path")
        if not report_json or not extraction_path:
            print(f"[skip] {ext_id}: no report or extraction path")
            continue
        report_path = Path(report_json) if Path(report_json).is_absolute() else repo / report_json
        ext_path = Path(extraction_path) if Path(extraction_path).is_absolute() else repo / extraction_path
        if not ext_path.is_dir():
            print(f"[skip] {ext_id}: extraction path not found")
            continue
        print(f"[review] {ext_id} ...")
        review = run_review_for_extension(ext_id, report_path, str(ext_path), repo)
        out_file = review_dir / f"bablu_review_{safe_id(ext_id)}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(review, f, indent=2)
        n = len(review.get("findings_verified", []))
        tp = sum(1 for x in review.get("findings_verified", []) if x.get("verdict") == "TP")
        fp = sum(1 for x in review.get("findings_verified", []) if x.get("verdict") == "FP")
        nr = sum(1 for x in review.get("findings_verified", []) if x.get("verdict") == "NEEDS_REVIEW")
        print(f"    -> {out_file.name} ({n} findings: {tp} TP, {fp} FP, {nr} NEEDS_REVIEW)")
        reviewed_count += 1
    print(f"[+] Wrote {reviewed_count} review(s) to {review_dir}")

    # Cohort review summary (JSON + Markdown)
    if reviewed_count > 0:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        summary = {
            "cohort": cohort_name,
            "manifest": str(manifest_path),
            "reviewed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "extensions_reviewed": reviewed_count,
            "by_extension": [],
            "totals": {"findings": 0, "TP": 0, "FP": 0, "NEEDS_REVIEW": 0},
        }
        for ext in extensions:
            ext_id = ext.get("id")
            if not ext_id:
                continue
            rf = review_dir / f"bablu_review_{safe_id(ext_id)}.json"
            if not rf.exists():
                continue
            with open(rf, encoding="utf-8") as f:
                r = json.load(f)
            fv = r.get("findings_verified", [])
            tp = sum(1 for x in fv if x.get("verdict") == "TP")
            fp = sum(1 for x in fv if x.get("verdict") == "FP")
            nr = sum(1 for x in fv if x.get("verdict") == "NEEDS_REVIEW")
            summary["by_extension"].append({
                "extension_id": ext_id,
                "risk_score_reported": r.get("risk_score_reported"),
                "risk_level_reported": r.get("risk_level_reported"),
                "findings_count": len(fv),
                "TP": tp,
                "FP": fp,
                "NEEDS_REVIEW": nr,
            })
            summary["totals"]["findings"] += len(fv)
            summary["totals"]["TP"] += tp
            summary["totals"]["FP"] += fp
            summary["totals"]["NEEDS_REVIEW"] += nr
        summary_path = review_dir / f"review_summary_{cohort_name}_{date_str}.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        md_path = review_dir / f"review_summary_{cohort_name}_{date_str}.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# Bablu review summary: {cohort_name}\n\n")
            f.write(f"**Reviewed:** {summary['reviewed_at']}  \n")
            f.write(f"**Extensions:** {summary['extensions_reviewed']}  \n\n")
            f.write("## Totals (code findings verified)\n\n")
            t = summary["totals"]
            f.write(f"| Metric | Count |\n|--------|-------|\n")
            f.write(f"| Total findings | {t['findings']} |\n")
            f.write(f"| TP | {t['TP']} |\n")
            f.write(f"| FP | {t['FP']} |\n")
            f.write(f"| NEEDS_REVIEW | {t['NEEDS_REVIEW']} |\n\n")
            f.write("## Per extension\n\n")
            f.write("| Extension | Risk | Findings | TP | FP | NEEDS_REVIEW |\n")
            f.write("|-----------|------|----------|----|----|---------------|\n")
            for e in summary["by_extension"]:
                f.write(f"| {e['extension_id']} | {e['risk_level_reported']} ({e['risk_score_reported']}) | {e['findings_count']} | {e['TP']} | {e['FP']} | {e['NEEDS_REVIEW']} |\n")
            f.write("\n")
        print(f"[+] Summary: {summary_path.name} + {md_path.name}")


if __name__ == "__main__":
    main()
