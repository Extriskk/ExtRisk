"""
Dependency vulnerability scanner using OSV (Open Source Vulnerabilities) API.

Resolves package versions from package.json and optional package-lock.json,
queries https://api.osv.dev/v1/querybatch for known CVEs, and returns
results for merge into the supply chain layer.
"""

import json
import re
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any


OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
OSV_ECOSYSTEM_NPM = "npm"
# Max items per batch (OSV accepts large batches; 100 is conservative)
OSV_BATCH_SIZE = 100
# Per-vuln enrichment timeout
OSV_ENRICH_TIMEOUT = 5


def _parse_version_from_spec(spec: str) -> str:
    """Strip npm version range prefix to get a single version for OSV (best effort)."""
    if not spec or spec == "*" or spec == "latest":
        return ""
    spec = spec.strip()
    # Remove leading ^ ~ >= > <= <
    spec = re.sub(r"^[\^~\s]+", "", spec)
    spec = re.sub(r"^[><=]+\s*", "", spec)
    # Take first version-like part (e.g. "1.2.3 - 1.2.5" -> "1.2.3")
    part = spec.split()[0] if spec else ""
    # If it looks like a single version, return it
    if re.match(r"^\d+\.\d+\.\d+", part):
        return part
    if re.match(r"^\d+\.\d+", part):
        return part
    return spec


def resolve_versions(pkg: dict, extension_dir: Path) -> list[tuple[str, str, str]]:
    """
    Resolve (name, version, dep_type) for all dependencies.
    dep_type is 'runtime' for dependencies, 'dev' for devDependencies.
    Uses package-lock.json or yarn.lock resolved versions when present; else package.json spec.
    """
    deps = pkg.get("dependencies", {})
    dev_deps = pkg.get("devDependencies", {})
    all_deps = {**deps, **dev_deps}
    if not all_deps:
        return []

    dev_names = set(dev_deps.keys())
    result: list[tuple[str, str, str]] = []
    resolved: dict[str, str] = {}

    # Prefer package-lock.json (npm)
    lock_path = extension_dir / "package-lock.json"
    if lock_path.exists():
        try:
            with open(lock_path, "r", encoding="utf-8", errors="ignore") as f:
                lock = json.load(f)
            # lock v2+: "packages" has "node_modules/<pkg>" -> version
            packages = lock.get("packages", {})
            for key, val in packages.items():
                if not isinstance(val, dict):
                    continue
                ver = val.get("version")
                if not ver:
                    continue
                name = key.replace("node_modules/", "") if key.startswith("node_modules/") else key
                if "/" not in name or name.startswith("@"):
                    resolved[name] = ver
            # lock v1: "dependencies" at top level
            if not resolved and "dependencies" in lock:
                for dep_name, meta in lock["dependencies"].items():
                    if isinstance(meta, dict) and meta.get("version"):
                        resolved[dep_name] = meta["version"]
        except (json.JSONDecodeError, OSError):
            pass

    # Yarn: yarn.lock has "pkg@version" blocks with resolved version
    yarn_path = extension_dir / "yarn.lock"
    if yarn_path.exists() and not resolved:
        try:
            content = yarn_path.read_text(encoding="utf-8", errors="ignore")
            for dep_name in all_deps:
                # Match first occurrence of "dep_name@..." and take version from block
                escaped = re.escape(dep_name)
                match = re.search(
                    rf'"{escaped}@[^"]*"[^"]*version\s+"([^"]+)"',
                    content,
                    re.MULTILINE | re.DOTALL,
                )
                if match:
                    resolved[dep_name] = match.group(1)
        except OSError:
            pass

    for name, spec in all_deps.items():
        version = resolved.get(name) or _parse_version_from_spec(spec) or spec
        if version:
            dep_type = 'dev' if name in dev_names else 'runtime'
            result.append((name, version, dep_type))
    return result


def _vuln_link(vuln_id: str) -> str:
    if vuln_id.startswith("GHSA-"):
        return f"https://github.com/advisories/{vuln_id}"
    if vuln_id.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    return f"https://osv.dev/vulnerability/{vuln_id}"


def _osv_severity_to_label(db_severity: str) -> str:
    """Map OSV database_specific.severity to standard label."""
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MODERATE": "medium",
        "MEDIUM": "medium",
        "LOW": "low",
    }
    return mapping.get((db_severity or "").upper(), "medium")


def _extract_fix_version(affected: list) -> str:
    """Extract the earliest fix version from OSV affected[].ranges[].events."""
    for aff in affected or []:
        if not isinstance(aff, dict):
            continue
        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict) and "fixed" in event:
                    return event["fixed"]
    return ""


def _enrich_vulns(vuln_ids: list[str]) -> dict[str, dict[str, Any]]:
    """
    Fetch full vulnerability details from OSV /v1/vulns/{id} for each ID.
    Returns {id: {summary, severity, cwe_ids, fix_version, aliases, cvss_vector}}.
    Gracefully returns empty dict entries on failure.
    """
    enriched: dict[str, dict[str, Any]] = {}
    for vid in vuln_ids:
        url = f"{OSV_VULN_URL}/{vid}"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=OSV_ENRICH_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
            enriched[vid] = {}
            continue

        summary = data.get("summary") or ""
        aliases = data.get("aliases") or []

        # Severity from database_specific or severity[] CVSS
        db_specific = data.get("database_specific") or {}
        severity_label = _osv_severity_to_label(db_specific.get("severity", ""))
        cwe_ids = db_specific.get("cwe_ids") or []

        # CVSS vector from severity[] array
        cvss_vector = ""
        for sev_entry in data.get("severity") or []:
            if isinstance(sev_entry, dict) and sev_entry.get("type", "").startswith("CVSS"):
                cvss_vector = sev_entry.get("score", "")
                break

        fix_version = _extract_fix_version(data.get("affected"))

        enriched[vid] = {
            "summary": summary,
            "severity": severity_label,
            "cwe_ids": cwe_ids,
            "fix_version": fix_version,
            "aliases": aliases,
            "cvss_vector": cvss_vector,
        }
    return enriched


def query_osv_batch(
    package_version_list: list[tuple[str, str, str]],
    ecosystem: str = OSV_ECOSYSTEM_NPM,
) -> list[dict[str, Any]]:
    """
    Query OSV API batch endpoint. Returns one item per input:
    { "package": name, "version": version, "dep_type": "runtime"|"dev",
      "vulns": [ {"id": "...", "link": "..."} ] }
    """
    if not package_version_list:
        return []

    results: list[dict[str, Any]] = []
    for i in range(0, len(package_version_list), OSV_BATCH_SIZE):
        chunk = package_version_list[i : i + OSV_BATCH_SIZE]
        queries = [
            {
                "package": {"name": name, "ecosystem": ecosystem},
                "version": version,
            }
            for name, version, _dt in chunk
        ]
        body = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(
            OSV_QUERYBATCH_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
            # On any error, return empty vulns for this chunk
            for name, version, dep_type in chunk:
                results.append({"package": name, "version": version, "dep_type": dep_type, "vulns": []})
            continue

        raw_results = data.get("results") or []
        for idx, (name, version, dep_type) in enumerate(chunk):
            vulns_list: list[dict[str, str]] = []
            if idx < len(raw_results):
                for v in raw_results[idx].get("vulns") or []:
                    vid = v.get("id") or ""
                    if vid:
                        vulns_list.append({"id": vid, "link": _vuln_link(vid)})
            results.append({"package": name, "version": version, "dep_type": dep_type, "vulns": vulns_list})

    return results


def scan_dependencies(pkg: dict, extension_dir: Path) -> dict[str, Any]:
    """
    Run dependency CVE scan. Returns:
      dependency_vulns: list of { package, version, vulns: [ { id, link } ] }
      findings: list of supply_chain findings (type: dependency_vulnerability)
      risk_delta: suggested addition to supply chain risk score (capped)
    """
    extension_dir = Path(extension_dir)
    package_version_list = resolve_versions(pkg, extension_dir)
    if not package_version_list:
        return {
            "dependency_vulns": [],
            "findings": [],
            "risk_delta": 0,
        }

    osv_results = query_osv_batch(package_version_list)
    dependency_vulns = [r for r in osv_results if r.get("vulns")]

    # Enrich vulns with full details from OSV /v1/vulns/{id}
    all_vuln_ids = []
    for item in dependency_vulns:
        for v in item.get("vulns", []):
            vid = v.get("id", "")
            if vid and vid not in all_vuln_ids:
                all_vuln_ids.append(vid)

    enriched = {}
    if all_vuln_ids:
        try:
            enriched = _enrich_vulns(all_vuln_ids)
        except Exception:
            pass  # graceful fallback — report still works with just id+link

    # Merge enriched data into vuln entries
    for item in dependency_vulns:
        for v in item.get("vulns", []):
            extra = enriched.get(v.get("id", ""), {})
            if extra:
                for key in ("summary", "severity", "cwe_ids", "fix_version", "aliases", "cvss_vector"):
                    val = extra.get(key)
                    if val:
                        v[key] = val

    findings: list[dict[str, Any]] = []
    risk_delta = 0
    for item in dependency_vulns:
        pkg_name = item["package"]
        version = item["version"]
        vulns = item["vulns"]
        for v in vulns:
            # Use enriched severity when available, else heuristic
            severity = v.get("severity") or ("high" if v["id"].startswith(("CVE-", "GHSA-")) else "medium")
            summary = v.get("summary", "")
            fix_ver = v.get("fix_version", "")
            detail = f"{pkg_name}@{version} has known vulnerability {v['id']}"
            if summary:
                detail += f" — {summary}"
            if fix_ver:
                detail += f" (fix: >={fix_ver})"
            findings.append({
                "type": "dependency_vulnerability",
                "severity": severity,
                "package": pkg_name,
                "version": version,
                "cve_id": v["id"],
                "link": v.get("link", _vuln_link(v["id"])),
                "detail": detail,
            })
            if severity == "critical" or (severity == "high" and risk_delta < 2):
                risk_delta += 0.5
            if risk_delta >= 3:
                break
        if risk_delta >= 3:
            break
    risk_delta = min(3, risk_delta)

    return {
        "dependency_vulns": dependency_vulns,
        "findings": findings,
        "risk_delta": risk_delta,
    }
