"""
Bundled JavaScript vulnerability scanner using Retire.js.

Scans compiled/bundled JS files (e.g. dist/extension.js, out/extension.js) for
known vulnerable library signatures that OSV and package.json-based scanning miss.

Install: from repo root run `npm install` (adds retire to node_modules).
The analyzer runs the bundled-JS scan whenever the extension contains JS files.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def _find_retire_cmd() -> tuple[list[str], Path | None]:
    """
    Return (argv, cwd) to run Retire: either [retire, ...] from PATH,
    or [npx, retire, ...] from repo root (after npm install).
    cwd is only used for npx (repo root).
    """
    retire_path = shutil.which("retire")
    if retire_path:
        return [retire_path], None

    # Try npx retire from repo root (project has package.json with retire)
    try:
        src_dir = Path(__file__).resolve().parent
        repo_root = src_dir.parent
        node_bin = repo_root / "node_modules" / ".bin" / "retire"
        if node_bin.exists():
            return [str(node_bin)], None
        npx_path = shutil.which("npx")
        if npx_path and (repo_root / "package.json").exists():
            return [npx_path, "retire"], repo_root
    except Exception:
        pass
    return [], None


def _vuln_id_from_identifiers(identifiers: dict) -> str:
    """Extract primary CVE/GHSA id from Retire vulnerability identifiers."""
    if not identifiers:
        return "unknown"
    cve = identifiers.get("CVE") or identifiers.get("cve")
    if cve:
        return cve[0] if isinstance(cve, list) else cve
    ghsa = identifiers.get("summary") or identifiers.get("githubID")
    if ghsa:
        return ghsa if isinstance(ghsa, str) else str(ghsa)
    return "unknown"


def _vuln_link(vuln_id: str) -> str:
    if vuln_id.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    if vuln_id.startswith("GHSA-"):
        return f"https://github.com/advisories/{vuln_id}"
    return ""


def scan_bundled_js(extension_dir: Path) -> dict[str, Any]:
    """
    Run Retire.js on extension directory to find vulnerable libraries inside
    bundled/compiled JavaScript (e.g. single dist/extension.js).

    Returns:
      bundled_js_vulns: list of {
          "file": relative path,
          "package": component name,
          "version": version string,
          "vulns": [ { "id", "severity", "link", "info" } ]
        }
      findings: list of supply_chain findings (type: bundled_library_vulnerability)
      risk_delta: suggested addition to supply chain risk score
      retire_available: True if retire CLI was run successfully
    """
    extension_dir = Path(extension_dir).resolve()
    empty = {
        "bundled_js_vulns": [],
        "findings": [],
        "risk_delta": 0,
        "retire_available": False,
    }

    retire_argv, npx_cwd = _find_retire_cmd()
    if not retire_argv:
        return empty

    out_path = Path(tempfile.gettempdir()) / f"retire_scan_{extension_dir.name}.json"
    run_cwd = str(npx_cwd) if npx_cwd else str(extension_dir)
    try:
        subprocess.run(
            retire_argv
            + [
                "--path",
                str(extension_dir),
                "--outputformat",
                "json",
                "--outputpath",
                str(out_path),
                "--exitwith",
                "0",
            ],
            capture_output=True,
            timeout=300,
            cwd=run_cwd,
            text=True,
        )
        raw = ""
        if out_path.exists():
            raw = out_path.read_text(encoding="utf-8", errors="ignore")
        if not raw or not raw.strip():
            return {**empty, "retire_available": True}

        data = json.loads(raw)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return empty
    finally:
        try:
            out_path.unlink(missing_ok=True)
        except OSError:
            pass

    # Retire.js JSON: data array of { file, results: [ { component, version, vulnerabilities } ] }
    data_list = data.get("data") if isinstance(data, dict) else []
    if not data_list:
        return {**empty, "retire_available": True}

    bundled_js_vulns: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    risk_delta = 0

    for entry in data_list:
        if not isinstance(entry, dict):
            continue
        file_path = entry.get("file") or entry.get("path") or ""
        results = entry.get("results") or entry.get("vulnerabilities") or []
        try:
            file_rel = Path(file_path).relative_to(extension_dir) if file_path else Path(file_path)
        except ValueError:
            file_rel = Path(file_path)

        for res in results:
            if not isinstance(res, dict):
                continue
            component = res.get("component") or res.get("name") or "unknown"
            version = res.get("version") or res.get("vulnerableVersion") or ""
            vuln_list = res.get("vulnerabilities") or res.get("vulns") or []
            if not vuln_list:
                continue

            vulns_out = []
            for v in vuln_list:
                if not isinstance(v, dict):
                    continue
                ids = v.get("identifiers") or {}
                vuln_id = _vuln_id_from_identifiers(ids)
                severity = (v.get("severity") or "medium").lower()
                info = v.get("info") or []
                link = info[0] if isinstance(info, list) and info else _vuln_link(vuln_id)
                # Extract summary from identifiers
                summary = ""
                if isinstance(ids.get("summary"), str):
                    summary = ids["summary"]
                # Extract fix version from "below" field
                fix_version = v.get("below") or ""
                # Extract affected-from version from "atOrAbove" field
                affected_from = v.get("atOrAbove") or ""
                # Collect all CVE aliases
                aliases = []
                cve_list = ids.get("CVE") or ids.get("cve") or []
                if isinstance(cve_list, list):
                    aliases = [c for c in cve_list if isinstance(c, str)]
                elif isinstance(cve_list, str):
                    aliases = [cve_list]
                ghsa_id = ids.get("githubID")
                if isinstance(ghsa_id, str) and ghsa_id not in aliases:
                    aliases.append(ghsa_id)

                entry = {
                    "id": vuln_id,
                    "severity": severity,
                    "link": link,
                    "info": info,
                }
                if summary:
                    entry["summary"] = summary
                if fix_version:
                    entry["fix_version"] = fix_version
                if affected_from:
                    entry["affected_from"] = affected_from
                if aliases:
                    entry["aliases"] = aliases
                vulns_out.append(entry)
                findings.append({
                    "type": "bundled_library_vulnerability",
                    "severity": severity,
                    "package": component,
                    "version": version,
                    "file": str(file_rel),
                    "cve_id": vuln_id,
                    "link": link,
                    "detail": f"Bundled JS: {component}@{version} in {file_rel} has {vuln_id}",
                })
                if severity in ("critical", "high"):
                    risk_delta += 0.5
                elif severity == "medium":
                    risk_delta += 0.25
                if risk_delta >= 3:
                    break
            if vulns_out:
                bundled_js_vulns.append({
                    "file": str(file_rel),
                    "package": component,
                    "version": version,
                    "vulns": vulns_out,
                })
            if risk_delta >= 3:
                break
        if risk_delta >= 3:
            break

    risk_delta = min(3, risk_delta)
    return {
        "bundled_js_vulns": bundled_js_vulns,
        "findings": findings,
        "risk_delta": risk_delta,
        "retire_available": True,
    }
