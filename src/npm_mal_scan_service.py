"""
Run npm-mal-scan for API/web flows and write reports under reports/npm_packages/.

Produces JSON + a small HTML wrapper compatible with ScanResult / report_store.

Security / review notes (for humans and LLM-assisted audits):
- Package spec is validated before any subprocess or path operation (see validate_npm_package_spec).
- Scanner is invoked with shell=False, argv list, stdin=DEVNULL (see npm_mal_scan_runner).
- Report output directory is constrained under reports_dir/npm_packages via resolve + relative_to.
- stdout/stderr are truncated before JSON parse and disk write to cap memory/DB growth.
- HTML report uses html.escape on all dynamic text (stored XSS safe when served as text/html).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from npm_mal_scan_runner import (
    npm_mal_scan_unavailable_reason,
    run_npm_mal_scan_captured,
)
from npm_scan_report_html import build_npm_scan_html_report

NPM_REPORTS_SUBDIR = "npm_packages"
NPKG_PREFIX = "npkg:"

# Caps (defense in depth; tune if npm-mal-scan legitimately emits more)
_MAX_PACKAGE_SPEC_CHARS = 256
_MAX_STORED_STDOUT_CHARS = 1_500_000
_MAX_STORED_STDERR_CHARS = 512_000
_MAX_JSON_PARSE_INPUT_CHARS = 400_000


def npm_spec_from_extension_id(extension_id: str) -> str:
    """Recover package spec from DB extension id (npkg:foo@1.0.0); prefix match is case-insensitive."""
    eid = (extension_id or "").strip()
    if eid.lower().startswith(NPKG_PREFIX):
        return eid[len(NPKG_PREFIX) :]
    return eid


def normalize_npm_package_spec(spec: str) -> str:
    s = (spec or "").strip()
    if not s:
        return ""
    return s.lower()


def npm_extension_id(spec: str) -> str:
    return f"{NPKG_PREFIX}{normalize_npm_package_spec(spec)}"


def spec_to_reports_dir_name(spec: str) -> str:
    """Filesystem-safe directory name under reports/npm_packages/."""
    n = normalize_npm_package_spec(spec)
    n = n.replace("@", "_at_").replace("/", "_")
    n = re.sub(r"[^\w.\-]", "_", n)
    return (n or "unknown")[:200]


def parse_name_version(spec: str) -> tuple[str, str]:
    """Parse display name and version; matches validate_npm_package_spec splitting."""
    return _split_package_and_version(spec)


def _split_package_and_version(spec: str) -> tuple[str, str]:
    """
    Split into (package-ish, version-ish).

    Handles @scope/name@version vs @scope/name vs lodash@version vs lodash.
    """
    s = spec.strip()
    if not s:
        return "", ""
    if s.startswith("@"):
        slash = s.find("/")
        if slash == -1:
            return s, ""
        after_slash = s[slash + 1 :]
        at = after_slash.rfind("@")
        if at != -1:
            return s[: slash + 1 + at], after_slash[at + 1 :]
        return s, ""
    left, sep, right = s.rpartition("@")
    if not sep:
        return s, ""
    return left, right


def validate_npm_package_spec(spec: str) -> Optional[str]:
    """
    Return error message if invalid, else None.

    Rules (keep in sync with docs/NPM_PACKAGE_SCAN_REVIEW_CHECKLIST.md):
    - Single line, no NUL/control chars (except tab blocked in package segment).
    - No path/backslash tricks, no URL schemes, no parent-dir segments in package part.
    - No shell metacharacters that could confuse downstream tooling (; & ` $).
    - Spaces allowed only in the version/range segment (after last @), not in package name.
    - Does not validate full npm semver grammar; rejects obvious abuse.
    """
    s = (spec or "").strip()
    if not s:
        return "Package spec is required (e.g. lodash@4.17.21)."
    if len(s) > _MAX_PACKAGE_SPEC_CHARS:
        return "Package spec is too long."
    if "\n" in s or "\r" in s or "\x00" in s:
        return "Invalid characters in package spec."
    if "://" in s or s.startswith(("/", "\\")):
        return "Invalid package spec."
    if any(c in s for c in ";&`$"):
        return "Package spec contains disallowed characters."
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", s):
        return "Package spec contains control characters."

    pkg, ver = _split_package_and_version(s)
    if not pkg:
        return "Invalid package spec."
    if ".." in pkg or "\\" in pkg or "%" in pkg:
        return "Invalid package name segment."
    if any(x in pkg for x in (" ", "\t")):
        return "Spaces are not allowed in the package name; use a single version/range after @."

    # Scoped name: @scope/name — scope and name segments
    if pkg.startswith("@"):
        rest = pkg[1:]
        if "/" not in rest:
            return "Scoped packages must use @scope/name (with a slash)."
        scope, _, name = rest.partition("/")
        if not scope or not name:
            return "Invalid scoped package name."
        if not re.match(r"^[a-z0-9-]{1,214}$", scope, re.I):
            return "Invalid package scope."
        if not re.match(r"^[a-z0-9._-]{1,214}$", name, re.I):
            return "Invalid scoped package base name."
    else:
        if not re.match(r"^[a-z0-9._-]{1,214}$", pkg, re.I):
            return "Invalid package name."

    if ver:
        if len(ver) > 512:
            return "Version or range segment is too long."
        if ".." in ver or "\\" in ver or "://" in ver:
            return "Invalid version segment."

    return None


def _truncate_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    marker = "\n\n[truncated by ExtRisk npm scan service]\n"
    keep = max(0, max_chars - len(marker))
    return text[:keep] + marker


def _try_parse_scanner_json(stdout: str) -> Any | None:
    t = (stdout or "").strip()
    if not t or len(t) > _MAX_JSON_PARSE_INPUT_CHARS:
        return None
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        return None


def _risk_from_parsed(parsed: Any, exit_code: int) -> tuple[float, str, int]:
    """Derive (risk_score, risk_level, findings_count) from scanner output."""
    findings_count = 0
    if isinstance(parsed, dict):
        for key in ("findings", "issues", "signals", "alerts", "flags"):
            v = parsed.get(key)
            if isinstance(v, list):
                findings_count = len(v)
                break
        for key in ("riskScore", "risk_score", "score", "totalRisk"):
            v = parsed.get(key)
            if isinstance(v, (int, float)):
                score = float(v)
                score = max(0.0, min(10.0, score))
                level = _level_from_score(score)
                return score, level, findings_count or (1 if exit_code != 0 else 0)
    if isinstance(parsed, list):
        findings_count = len(parsed)
    if exit_code != 0:
        return 6.5, "MEDIUM", max(findings_count, 1)
    return 2.0, "LOW", findings_count


def _level_from_score(score: float) -> str:
    if score >= 8.5:
        return "CRITICAL"
    if score >= 6.5:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 2.0:
        return "LOW"
    return "MINIMAL"


@dataclass
class NpmScanApiResult:
    success: bool
    error: Optional[str]
    extension_id: str
    report_payload: dict[str, Any]
    json_report_path: str
    html_report_path: str
    results: dict[str, Any]
    version_hash: str = ""


def run_npm_package_scan(
    package_spec: str,
    reports_dir: Path,
    timeout: int | None = 600,
) -> NpmScanApiResult:
    """
    Run npm-mal-scan for one package spec (e.g. lodash@4.17.21).

    Writes:
      reports_dir / npm_packages / <safe_spec> / npm_mal_scan_<utc>.json
      reports_dir / npm_packages / <safe_spec> / npm_mal_scan_<utc>.html
    """
    err = validate_npm_package_spec(package_spec)
    if err:
        return NpmScanApiResult(
            success=False,
            error=err,
            extension_id="",
            report_payload={},
            json_report_path="",
            html_report_path="",
            results={},
            version_hash="",
        )

    reason = npm_mal_scan_unavailable_reason()
    if reason:
        return NpmScanApiResult(
            success=False,
            error=reason,
            extension_id="",
            report_payload={},
            json_report_path="",
            html_report_path="",
            results={},
            version_hash="",
        )

    ext_id = npm_extension_id(package_spec)
    name, version = parse_name_version(package_spec)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    reports_root = reports_dir.resolve()
    base_dir = (reports_root / NPM_REPORTS_SUBDIR).resolve()
    safe_name = spec_to_reports_dir_name(package_spec)
    sub = (base_dir / safe_name).resolve()
    try:
        sub.relative_to(base_dir)
    except ValueError:
        return NpmScanApiResult(
            success=False,
            error="Refusing to write outside reports/npm_packages (path safety).",
            extension_id=ext_id,
            report_payload={},
            json_report_path="",
            html_report_path="",
            results={},
            version_hash="",
        )

    sub.mkdir(parents=True, exist_ok=True)
    json_name = f"npm_mal_scan_{stamp}.json"
    html_name = f"npm_mal_scan_{stamp}.html"
    json_path = sub / json_name
    html_path = sub / html_name

    try:
        argv_spec = normalize_npm_package_spec(package_spec).strip()
        proc = run_npm_mal_scan_captured([argv_spec], timeout=timeout)
    except subprocess.TimeoutExpired:
        return NpmScanApiResult(
            success=False,
            error="npm-mal-scan timed out.",
            extension_id=ext_id,
            report_payload={},
            json_report_path="",
            html_report_path="",
            results={},
            version_hash="",
        )
    except Exception as e:
        return NpmScanApiResult(
            success=False,
            error=f"npm-mal-scan failed to run: {e}",
            extension_id=ext_id,
            report_payload={},
            json_report_path="",
            html_report_path="",
            results={},
            version_hash="",
        )

    if proc is None:
        return NpmScanApiResult(
            success=False,
            error=npm_mal_scan_unavailable_reason() or "npm-mal-scan unavailable.",
            extension_id=ext_id,
            report_payload={},
            json_report_path="",
            html_report_path="",
            results={},
            version_hash="",
        )

    exit_code = int(proc.returncode)
    stdout = _truncate_text(proc.stdout or "", _MAX_STORED_STDOUT_CHARS)
    stderr = _truncate_text(proc.stderr or "", _MAX_STORED_STDERR_CHARS)
    parsed = _try_parse_scanner_json(stdout)
    completed = datetime.now(timezone.utc).isoformat()

    payload: dict[str, Any] = {
        "scan_type": "npm_mal_scan",
        "package_spec": normalize_npm_package_spec(package_spec),
        "scanner_exit_code": exit_code,
        "completed_at": completed,
        "scanner_stdout": stdout,
        "scanner_stderr": stderr,
        "parsed_output": parsed,
    }

    risk_score, risk_level, _findings_n = _risk_from_parsed(parsed, exit_code)
    patterns: list[dict[str, Any]] = []
    if exit_code != 0:
        detail = (stderr or stdout or "").strip()[:800]
        patterns.append(
            {
                "name": "npm-mal-scan",
                "severity": "medium",
                "description": detail or f"Scanner exited with code {exit_code}.",
            }
        )

    version_hash = hashlib.sha256(normalize_npm_package_spec(package_spec).encode("utf-8")).hexdigest()

    file_record = {
        **payload,
        "name": name or normalize_npm_package_spec(package_spec),
        "version": version,
        "publisher": "npm",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "malicious_patterns": patterns,
        "threat_classification": "npm_mal_scan",
    }
    json_path.write_text(json.dumps(file_record, indent=2, ensure_ascii=False), encoding="utf-8")
    html_path.write_text(build_npm_scan_html_report(file_record), encoding="utf-8")

    results: dict[str, Any] = {
        "name": name or normalize_npm_package_spec(package_spec),
        "version": version,
        "publisher": "npm",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threat_classification": "npm_mal_scan",
        "malicious_patterns": patterns,
        "npm_mal_scan": payload,
    }

    return NpmScanApiResult(
        success=True,
        error=None,
        extension_id=ext_id,
        report_payload=file_record,
        json_report_path=str(json_path.resolve()),
        html_report_path=str(html_path.resolve()),
        results=results,
        version_hash=version_hash,
    )
