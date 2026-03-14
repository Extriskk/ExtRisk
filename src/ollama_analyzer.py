"""
Ollama integration for extension security analysis.

Uses a local Ollama instance to analyze extension manifest and code excerpts
and produce a short security assessment included in the report.
Optional: run with --ollama; requires Ollama running (e.g. ollama serve).
"""

from pathlib import Path
import json
import re

# Lazy import to avoid hard dependency
def _requests():
    import requests
    return requests


DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2"
MAX_FILE_CHARS = 6000
MAX_FILES = 6
TOTAL_CONTEXT_CHARS = 32000
GENERATE_TIMEOUT = 300  # 5 minutes; large models or CPU can be slow


def check_available(base_url=DEFAULT_BASE_URL):
    """Return True if Ollama is reachable."""
    try:
        r = _requests().get(f"{base_url.rstrip('/')}/api/tags", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def list_models(base_url=DEFAULT_BASE_URL):
    """Return list of model names from Ollama, or empty list on error."""
    try:
        r = _requests().get(f"{base_url.rstrip('/')}/api/tags", timeout=5)
        if r.status_code != 200:
            return []
        data = r.json()
        models = data.get("models") or []
        return [m.get("name") for m in models if m.get("name")]
    except Exception:
        return []


def _pick_model(preferred, available):
    if not available:
        return None
    if preferred and preferred in available:
        return preferred
    # Prefer codellama/llama for code; fallback to first
    for name in (preferred, "codellama", "llama3.2", "llama3.1", "llama3", "llama2"):
        if name and name in available:
            return name
    return available[0]


def _collect_extension_context(extension_dir, results, max_chars=TOTAL_CONTEXT_CHARS):
    """Build a single text block: manifest + key JS/TS files (excerpts)."""
    extension_dir = Path(extension_dir)
    if not extension_dir.is_dir():
        return ""

    parts = []
    used = 0

    manifest_path = extension_dir / "manifest.json"
    package_path = extension_dir / "package.json"
    manifest_file = manifest_path if manifest_path.is_file() else (package_path if package_path.is_file() else None)
    if manifest_file:
        try:
            raw = manifest_file.read_text(encoding="utf-8", errors="replace")
            label = manifest_file.name
            parts.append(f"=== {label} ===\n" + raw)
            used += len(raw) + 80
        except Exception:
            pass

    # Collect JS/TS files: background, content_scripts, then remaining
    js_ext = (".js", ".mjs", ".cjs")
    ts_ext = (".ts",)
    priority_names = set()
    manifest = {}
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass
    elif package_path.is_file():
        try:
            manifest = json.loads(package_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass
    for key in ("background", "content_scripts", "browser_action", "page_action", "action"):
        val = manifest.get(key)
        if isinstance(val, dict) and val.get("scripts"):
            for s in val["scripts"]:
                priority_names.add(Path(s).name)
        if isinstance(val, list):
            for entry in val:
                if isinstance(entry, dict):
                    for s in entry.get("js", []) + entry.get("ts", []):
                        priority_names.add(Path(s).name)

    all_js = []
    for p in extension_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in js_ext or p.suffix.lower() in ts_ext:
            rel = p.relative_to(extension_dir)
            if "node_modules" in rel.parts or rel.name.startswith("."):
                continue
            name = p.name
            all_js.append((name in priority_names, name, p))

    all_js.sort(key=lambda x: (not x[0], x[1]))
    for _, _, path in all_js[:MAX_FILES]:
        if used >= max_chars:
            break
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            excerpt = raw[:MAX_FILE_CHARS] if len(raw) > MAX_FILE_CHARS else raw
            if len(raw) > MAX_FILE_CHARS:
                excerpt += "\n... [truncated]"
            rel = path.relative_to(extension_dir)
            parts.append(f"\n=== {rel} ===\n{excerpt}")
            used += len(excerpt) + 60
        except Exception:
            continue

    return "\n".join(parts).strip() if parts else ""


def _findings_summary(results):
    """One short paragraph of automated findings for the prompt."""
    name = results.get("name", "Extension")
    risk = results.get("risk_score", 0)
    level = results.get("risk_level", "UNKNOWN")
    patterns = results.get("malicious_patterns") or []
    pii = (results.get("pii_classification") or {}).get("data_types_count", 0)
    vt = results.get("virustotal_results") or []
    vt_positive = sum(1 for v in vt if isinstance(v, dict) and v.get("positives", 0) and v.get("positives", 0) > 0)
    adv = results.get("advanced_detection") or {}
    adv_findings = adv.get("findings") or []
    bc = results.get("behavioral_correlations") or {}
    bc_corr = (bc.get("correlations") or [])[:3]
    lines = [
        f"Extension: {name}. Risk score: {risk}/10 ({level}).",
        f"Malicious patterns: {len(patterns)}; PII/data types: {pii}; VirusTotal positives: {vt_positive}.",
    ]
    if adv_findings:
        lines.append(f"Advanced findings: {len(adv_findings)}.")
    if bc_corr:
        lines.append(f"Behavioral correlations: {len(bc_corr)} highlighted.")
    return " ".join(lines)


def generate_assessment(context_text, findings_summary, model, base_url=DEFAULT_BASE_URL, timeout=None):
    """
    Call Ollama to generate a short security assessment.
    timeout: seconds to wait (default GENERATE_TIMEOUT).
    Returns (response_text, error_message). One of them will be None.
    """
    timeout = timeout if timeout is not None and timeout > 0 else GENERATE_TIMEOUT
    prompt = f"""You are a security analyst. Below are the manifest and code excerpts from a browser or editor extension, plus a one-line summary of our automated scan.

Automated scan summary: {findings_summary}

Extension manifest and code excerpts:
---
{context_text[:TOTAL_CONTEXT_CHARS]}
---

Provide a short security assessment (2 to 4 paragraphs): main risks, any suspicious patterns you notice in the code, and concrete recommendations. Be concise and factual. Do not repeat the scan summary verbatim."""

    url = f"{base_url.rstrip('/')}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    try:
        r = _requests().post(url, json=payload, timeout=timeout)
        if r.status_code != 200:
            return None, f"Ollama returned HTTP {r.status_code}"
        data = r.json()
        response = (data.get("response") or "").strip()
        if not response:
            return None, "Empty response from Ollama"
        return response, None
    except Exception as e:
        try:
            req = _requests()
            if hasattr(req, "exceptions") and isinstance(e, req.exceptions.Timeout):
                return None, "Ollama request timed out"
        except Exception:
            pass
        return None, str(e)


def analyze(extension_dir, results, model=None, base_url=None, timeout=None):
    """
    Run Ollama-enhanced analysis: gather context from extension_dir and results,
    call Ollama, return a dict for inclusion in results['ollama_analysis'].

    base_url: Ollama API base (e.g. http://localhost:11434). None = use default.
    timeout: seconds to wait for generate (None = use GENERATE_TIMEOUT).

    Returns:
        dict with keys: available (bool), model (str|None), report_section (str),
        summary (str), error (str|None).
    """
    base_url = (base_url or "").strip() or DEFAULT_BASE_URL
    timeout = timeout if timeout is not None and timeout > 0 else GENERATE_TIMEOUT
    out = {
        "available": False,
        "model": None,
        "report_section": "",
        "summary": "",
        "error": None,
    }
    if not check_available(base_url):
        out["error"] = "Ollama is not reachable (is it running on " + base_url + "?)"
        return out

    models = list_models(base_url)
    chosen = _pick_model(model, models)
    if not chosen:
        out["error"] = "No Ollama models found. Run: ollama pull llama3.2"
        return out

    context = _collect_extension_context(extension_dir, results)
    if not context.strip():
        out["error"] = "No extension files could be read for context"
        return out

    findings = _findings_summary(results)
    response_text, err = generate_assessment(context, findings, chosen, base_url, timeout=timeout)
    if err:
        out["error"] = err
        return out

    out["available"] = True
    out["model"] = chosen
    out["report_section"] = response_text
    # One-line summary: first sentence or first 200 chars
    summary = re.split(r"[.!?]\s+", response_text)[0].strip()
    if not summary.endswith("."):
        summary = response_text[:200].strip()
        if len(response_text) > 200:
            summary += "..."
    out["summary"] = summary
    return out
