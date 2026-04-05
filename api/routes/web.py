"""
Public webapp UI for Extension Risk Intelligence (mounted at /app).
Replicates extension-analyser UI/UX: landing, summary, full report with nav.
Flow unchanged: cached result or new scan → persist → show (summary then full report).
"""
import html as html_module
import json
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse

from api.database import SessionLocal
from api.models import Extension, ScanResult
from api.config import settings
from scan_service import ScanService, ScanRequest, ScanStore


router = APIRouter(prefix="/app", tags=["web"])

# ---------------------------------------------------------------------------
# CSS: shared design system (from extension-analyser)
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg-deep: #030712;
  --bg-card: rgba(15, 23, 42, 0.55);
  --bg-card-solid: #0f172a;
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --accent: #38bdf8;
  --accent-green: #22c55e;
  --accent-red: #ef4444;
  --accent-amber: #f59e0b;
  --accent-purple: #a78bfa;
  --border: rgba(255,255,255,0.08);
  --border-focus: rgba(56,189,248,0.5);
  --radius: 16px;
  --radius-sm: 10px;
  --radius-xs: 6px;
  --shadow-card: 0 8px 32px rgba(0,0,0,0.4);
  --font: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", system-ui, sans-serif;
  --mono: "SF Mono", "Cascadia Code", "Fira Code", Consolas, monospace;
}

*,*::before,*::after { box-sizing: border-box; }

body {
  margin: 0; padding: 0;
  font-family: var(--font);
  color: var(--text-primary);
  background: var(--bg-deep);
  background-image:
    radial-gradient(ellipse 80% 60% at 10% 20%, rgba(56,189,248,0.08) 0%, transparent 60%),
    radial-gradient(ellipse 60% 50% at 90% 80%, rgba(139,92,246,0.07) 0%, transparent 60%),
    radial-gradient(ellipse 70% 50% at 50% 50%, rgba(34,197,94,0.05) 0%, transparent 60%);
  background-attachment: fixed;
  min-height: 100vh;
}

body::before {
  content: '';
  position: fixed; inset: 0;
  background:
    radial-gradient(ellipse 50% 40% at 20% 30%, rgba(56,189,248,0.06) 0%, transparent 70%),
    radial-gradient(ellipse 40% 50% at 80% 70%, rgba(139,92,246,0.06) 0%, transparent 70%);
  animation: meshShift 20s ease-in-out infinite alternate;
  pointer-events: none;
  z-index: 0;
}
@keyframes meshShift {
  0%   { transform: translate(0,0) scale(1); }
  50%  { transform: translate(-3%,2%) scale(1.05); }
  100% { transform: translate(2%,-1%) scale(1); }
}
@media (prefers-reduced-motion: reduce) {
  body::before { animation: none; }
}

.shell {
  position: relative; z-index: 1;
  min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  padding: 40px 16px;
}

.card {
  width: 100%; max-width: 740px;
  background: var(--bg-card);
  backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px);
  border-radius: var(--radius);
  border: 1px solid var(--border);
  box-shadow: var(--shadow-card);
  padding: 32px 36px;
}

.brand {
  font-size: 28px; font-weight: 700;
  background: linear-gradient(135deg, var(--accent), var(--accent-green));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
  letter-spacing: -0.02em;
  margin-bottom: 6px;
}
.tagline {
  font-size: 14px; color: var(--text-secondary);
  line-height: 1.5; margin-bottom: 24px;
}

.feature-pills {
  display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 24px;
}
.pill {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 5px 12px; border-radius: 999px;
  background: rgba(56,189,248,0.08);
  border: 1px solid rgba(56,189,248,0.15);
  font-size: 11px; font-weight: 500;
  color: var(--accent);
  transition: background 0.2s;
}
.pill:hover { background: rgba(56,189,248,0.14); }
.pill svg { width: 12px; height: 12px; }

.field-label {
  font-size: 12px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted); margin-bottom: 8px;
}
.input-wrap {
  position: relative; margin-bottom: 12px;
}
.input-wrap input {
  width: 100%; padding: 12px 14px 12px 40px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: rgba(2,7,23,0.6);
  color: var(--text-primary); font-size: 14px;
  outline: none; transition: border 0.2s, box-shadow 0.2s;
}
.input-wrap input:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 3px rgba(56,189,248,0.12);
}
.input-wrap .search-icon {
  position: absolute; left: 12px; top: 50%; transform: translateY(-50%);
  color: var(--text-muted); pointer-events: none;
}

/* Store pills + primary CTA on one row (wraps on narrow screens) */
.store-toolbar {
  display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
  gap: 12px 16px; margin-bottom: 18px;
}
.store-toolbar .store-selector {
  display: flex; gap: 6px; flex-wrap: wrap; flex: 1; min-width: 0; margin-bottom: 0;
}
.store-toolbar .scan-cta {
  display: flex; flex-direction: column; align-items: flex-end; gap: 6px;
  flex-shrink: 0;
}
@media (max-width: 520px) {
  .store-toolbar .scan-cta { align-items: stretch; width: 100%; }
  .store-toolbar .scan-cta .btn-primary { width: 100%; justify-content: center; }
}

.store-selector {
  display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 16px;
}
.store-pill {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 7px 14px; border-radius: 999px;
  border: 1px solid var(--border); background: transparent;
  color: var(--text-secondary); font-size: 12px; font-weight: 500;
  cursor: pointer; transition: all 0.2s;
}
.store-pill:hover { border-color: var(--accent); color: var(--text-primary); }
.store-pill.active {
  background: rgba(56,189,248,0.12); border-color: var(--accent);
  color: var(--accent); font-weight: 600;
}

.examples { margin-bottom: 18px; }
.examples.hidden { display: none; }
.examples span { font-size: 11px; color: var(--text-muted); margin-right: 6px; }
.chip {
  display: inline-block; padding: 3px 10px; margin: 2px 4px 2px 0;
  border-radius: var(--radius-xs); background: rgba(255,255,255,0.04);
  border: 1px solid var(--border);
  font-family: var(--mono); font-size: 11px; color: var(--text-secondary);
  cursor: pointer; transition: all 0.15s;
}
.chip:hover { background: rgba(56,189,248,0.1); color: var(--accent); border-color: var(--accent); }

.btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 11px 24px; border-radius: 999px; border: none;
  font-size: 14px; font-weight: 600; cursor: pointer;
  transition: transform 0.15s, box-shadow 0.15s;
}
.btn:active { transform: scale(0.97); }
.btn-primary {
  background: linear-gradient(135deg, #0ea5e9, #22c55e);
  color: #0b1120;
  box-shadow: 0 4px 20px rgba(14,165,233,0.3);
}
.btn-primary:hover { box-shadow: 0 6px 28px rgba(14,165,233,0.45); }
.btn-primary:disabled { opacity: 0.5; cursor: default; transform: none; box-shadow: none; }
.btn-secondary {
  background: rgba(255,255,255,0.06); color: var(--text-primary);
  border: 1px solid var(--border);
}
.btn-secondary:hover { background: rgba(255,255,255,0.1); }

.actions-row {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; margin-top: 6px;
}
.hint { font-size: 11px; color: var(--text-muted); }
code { font-family: var(--mono); font-size: 0.92em; }

.progress-panel { margin-top: 20px; display: none; }
.progress-panel.visible { display: block; }
.steps { display: flex; gap: 0; margin-bottom: 12px; }
.step {
  flex: 1; text-align: center; position: relative;
  font-size: 11px; color: var(--text-muted); padding-top: 18px;
}
.step::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0;
  height: 3px; border-radius: 2px;
  background: rgba(255,255,255,0.06);
}
.step.active::before {
  background: linear-gradient(90deg, var(--accent), var(--accent-green));
  animation: stepPulse 1.5s ease-in-out infinite;
}
.step.done::before { background: var(--accent-green); }
@keyframes stepPulse {
  0%,100% { opacity: 0.6; } 50% { opacity: 1; }
}
.step .dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--text-muted);
  display: inline-block; margin-bottom: 4px;
}
.step.active .dot { background: var(--accent); animation: dotPulse 1s infinite; }
.step.done .dot { background: var(--accent-green); }
@keyframes dotPulse {
  0%,100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.6); opacity: 0.6; }
}
.elapsed { font-size: 11px; color: var(--text-muted); margin-top: 4px; }

.recent { margin-top: 28px; border-top: 1px solid var(--border); padding-top: 16px; }
.recent-title { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin-bottom: 12px; }
.recent-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
.recent-item {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  padding: 11px 14px; font-size: 12px;
  border-radius: var(--radius-sm);
  background: rgba(255,255,255,0.03);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  transition: background 0.15s, border-color 0.15s;
}
.recent-item:hover { background: rgba(56,189,248,0.06); border-color: rgba(56,189,248,0.2); }
.recent-item.recent-item-npm { border-left-color: var(--accent-purple); }
.recent-item.recent-item-npm:hover { background: rgba(167,139,250,0.06); border-color: rgba(167,139,250,0.2); }
.recent-item .recent-main { display: flex; align-items: center; gap: 10px; flex: 1; min-width: 0; }
.recent-item a { color: var(--accent); text-decoration: none; font-family: var(--mono); font-size: 11px; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.recent-item a:hover { text-decoration: underline; }
.recent-source {
  font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
  padding: 3px 8px; border-radius: 999px; flex-shrink: 0;
  background: rgba(56,189,248,0.12); color: var(--accent); border: 1px solid rgba(56,189,248,0.25);
}
.recent-source.recent-source-npm {
  background: rgba(167,139,250,0.12); color: var(--accent-purple); border-color: rgba(167,139,250,0.28);
}
.risk-badge {
  display: inline-block; padding: 2px 8px; border-radius: 999px;
  font-size: 10px; font-weight: 700; text-transform: uppercase;
}
.risk-critical { background: rgba(239,68,68,0.15); color: #f87171; }
.risk-high { background: rgba(245,158,11,0.15); color: #fbbf24; }
.risk-medium { background: rgba(245,158,11,0.1); color: #fcd34d; }
.risk-low { background: rgba(34,197,94,0.12); color: #4ade80; }
.risk-minimal { background: rgba(34,197,94,0.08); color: #86efac; }
.risk-unknown { background: rgba(148,163,184,0.1); color: var(--text-muted); }

.summary-header {
  display: flex; align-items: flex-start; gap: 24px;
  margin-bottom: 28px; flex-wrap: wrap;
}
.gauge-wrap { flex-shrink: 0; text-align: center; }
.gauge {
  width: 110px; height: 110px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 28px; font-weight: 700;
  border: 4px solid var(--border);
}
.gauge-label { font-size: 11px; color: var(--text-muted); margin-top: 6px; }
.meta-block { flex: 1; min-width: 200px; }
.meta-block h2 { font-size: 20px; font-weight: 700; margin: 0 0 4px; }
.meta-row { font-size: 12px; color: var(--text-secondary); margin: 2px 0; }

.stats-row {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px; margin-bottom: 24px;
}
.stat-card {
  background: rgba(255,255,255,0.03); border: 1px solid var(--border);
  border-radius: var(--radius-sm); padding: 14px 16px; text-align: center;
}
.stat-value { font-size: 24px; font-weight: 700; }
.stat-label { font-size: 11px; color: var(--text-muted); margin-top: 2px; }

details.finding-group {
  border: 1px solid var(--border); border-radius: var(--radius-sm);
  margin-bottom: 8px; overflow: hidden;
}
details.finding-group summary {
  padding: 10px 16px; cursor: pointer;
  font-size: 13px; font-weight: 600;
  background: rgba(255,255,255,0.02);
  list-style: none; display: flex; align-items: center; gap: 8px;
}
details.finding-group summary::before {
  content: '\\25B6'; font-size: 9px; transition: transform 0.2s;
}
details.finding-group[open] summary::before { transform: rotate(90deg); }
details.finding-group .finding-list { padding: 0 16px 12px; }
.finding-item {
  padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.03);
  font-size: 12px;
}
.finding-item:last-child { border-bottom: none; }
.finding-name { font-weight: 600; }
.finding-file { font-family: var(--mono); font-size: 11px; color: var(--text-muted); }

.report-nav {
  position: sticky; top: 0; z-index: 9999;
  display: flex; align-items: center; gap: 12px;
  padding: 10px 20px;
  background: rgba(15,23,42,0.92);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
  font-family: var(--font);
}
.report-nav a { color: var(--accent); text-decoration: none; font-size: 13px; }
.report-nav a:hover { text-decoration: underline; }
.report-nav .spacer { flex: 1; }
.report-nav .btn { padding: 6px 14px; font-size: 12px; text-decoration: none; }
.report-nav .btn:hover { text-decoration: none; }

.error-icon { font-size: 48px; margin-bottom: 12px; }
.error-title { font-size: 20px; font-weight: 700; margin-bottom: 8px; }
.error-msg { font-size: 13px; color: var(--text-secondary); margin-bottom: 20px; line-height: 1.5; }
"""


def _render_page(body_html: str, title: str = "ExtRisk Intel") -> HTMLResponse:
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>{_CSS}</style>
</head>
<body>
<div class="shell">
<div class="card">
{body_html}
</div>
</div>
</body>
</html>"""
    return HTMLResponse(content=html)


def _render_error(
    title: str,
    message: str,
    back_link: str = "/app/",
) -> HTMLResponse:
    body = f"""
    <div style="text-align:center;padding:20px 0;">
      <div class="error-icon">&#9888;</div>
      <div class="error-title">{title}</div>
      <div class="error-msg">{message}</div>
      <a href="{back_link}" class="btn btn-primary" style="text-decoration:none">&larr; Go back</a>
    </div>
    """
    return _render_page(body, title=f"ExtRisk Intel — {title}")


def _risk_badge_class(level: str) -> str:
    level = (level or "").upper()
    if level == "CRITICAL":
        return "risk-critical"
    if level == "HIGH":
        return "risk-high"
    if level == "MEDIUM":
        return "risk-medium"
    if level == "LOW":
        return "risk-low"
    if level == "MINIMAL":
        return "risk-minimal"
    return "risk-unknown"


def _gauge_color(score: float) -> str:
    if score >= 8:
        return "#ef4444"
    if score >= 6:
        return "#f59e0b"
    if score >= 3.5:
        return "#fbbf24"
    return "#22c55e"


def _recent_scans_html() -> str:
    db = SessionLocal()
    try:
        rows = (
            db.query(ScanResult)
            .order_by(ScanResult.scanned_at.desc())
            .limit(5)
            .all()
        )
        if not rows:
            return ""
        items = ""
        for r in rows:
            ext_id = r.extension_id or ""
            display_id = ext_id[:28] + "..." if len(ext_id) > 30 else ext_id
            badge_cls = _risk_badge_class(r.risk_level)
            score_str = f"{r.risk_score:.1f}" if r.risk_score else "?"
            when = r.scanned_at.strftime("%b %d, %H:%M") if r.scanned_at else ""
            enc = quote(ext_id, safe="")
            ext_row = db.query(Extension).filter(Extension.id == ext_id).first()
            bt = (ext_row.browser_type or "").lower() if ext_row else ""
            is_npm = bt == "npm"
            row_cls = "recent-item recent-item-npm" if is_npm else "recent-item recent-item-ext"
            if is_npm:
                src_label = "npm"
                src_cls = "recent-source recent-source-npm"
            elif bt == "vscode":
                src_label = "VSCode"
                src_cls = "recent-source"
            elif bt == "edge":
                src_label = "Edge"
                src_cls = "recent-source"
            elif bt == "chrome":
                src_label = "Chrome"
                src_cls = "recent-source"
            else:
                src_label = "Scan"
                src_cls = "recent-source"
            items += f"""<li class="{row_cls}">
              <div class="recent-main">
                <span class="{src_cls}">{src_label}</span>
                <a href="/app/reports/{enc}/summary" title="{html_module.escape(ext_id, quote=True)}">{display_id}</a>
              </div>
              <span class="risk-badge {badge_cls}">{r.risk_level or '?'} {score_str}</span>
              <span class="hint" style="margin-left:auto">{when}</span>
            </li>"""
        return f"""<div class="recent">
          <div class="recent-title">Recent scans</div>
          <ul class="recent-list">{items}</ul>
        </div>"""
    except Exception:
        return ""
    finally:
        db.close()


def _build_findings_html(result: ScanResult) -> str:
    report_json_str = result.report_json
    if not report_json_str and result.json_report_path:
        p = Path(result.json_report_path)
        if p.exists():
            try:
                report_json_str = p.read_text(encoding="utf-8")
            except Exception:
                pass
    if not report_json_str:
        return '<div class="hint">No detailed findings available.</div>'
    try:
        data = json.loads(report_json_str)
    except Exception:
        return '<div class="hint">Could not parse findings data.</div>'
    patterns = data.get("malicious_patterns", []) or []
    if not patterns:
        return '<div class="hint" style="margin-top:8px;">No findings detected.</div>'
    by_severity: dict[str, dict[str, list]] = {}
    for p in patterns:
        sev = (p.get("severity") or "info").lower()
        name = p.get("name") or "Unknown"
        sev_bucket = by_severity.setdefault(sev, {})
        sev_bucket.setdefault(name, []).append(p)
    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_colors = {
        "critical": "#ef4444", "high": "#f59e0b", "medium": "#fbbf24",
        "low": "#4ade80", "info": "#94a3b8",
    }
    html = '<div style="margin-top:4px;">'
    for sev in severity_order:
        rules = by_severity.get(sev, {})
        if not rules:
            continue
        col = severity_colors.get(sev, "#94a3b8")
        open_attr = ' open' if sev in ("critical", "high") else ""
        rule_count = len(rules)
        html += f'<details class="finding-group"{open_attr}>'
        html += f'<summary><span class="risk-badge" style="background:rgba(255,255,255,0.05);color:{col}">{sev.upper()}</span> {rule_count} rule{"s" if rule_count != 1 else ""}</summary>'
        html += '<div class="finding-list">'
        for name, occurrences in list(rules.items())[:40]:
            example = occurrences[0]
            desc = (example.get("description") or "")[:120]
            fname = example.get("file", "")
            line = example.get("line", "")
            loc = f"{fname}:{line}" if fname else ""
            count = len(occurrences)
            html += f'<div class="finding-item"><span class="finding-name">{name}</span>'
            if loc:
                html += f' <span class="finding-file">{loc}</span>'
            html += f' <span class="risk-badge risk-unknown" style="margin-left:6px;">× {count}</span>'
            if desc:
                html += f'<br><span class="hint">{desc}</span>'
            html += '</div>'
        if len(rules) > 40:
            html += f'<div class="hint">+ {len(rules) - 40} more rules</div>'
        html += '</div></details>'
    html += '</div>'
    return html


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
def landing_page() -> HTMLResponse:
    recent = _recent_scans_html()
    body = f"""
    <div class="brand">ExtRisk Intel</div>
    <div class="tagline">
      Deep security analysis for Chrome, Edge &amp; VSCode extensions and <strong>npm registry</strong> packages.<br>
      Get a risk score, threat findings, and remediation guidance in under a minute.
    </div>

    <div class="feature-pills">
      <span class="pill">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Static Analysis
      </span>
      <span class="pill">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        Threat Intel
      </span>
      <span class="pill">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
        Risk Scoring
      </span>
      <span class="pill">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg>
        Pro Reports
      </span>
    </div>

    <form id="analyze-form" method="post" action="/app/analyze">

      <div class="field-label" id="target-field-label">Extension identifier</div>
      <div class="input-wrap">
        <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        <input type="text" id="scan-target-input" name="extension_id" placeholder="Paste extension ID or publisher.name" required autocomplete="off"/>
      </div>

      <div class="examples examples-ext" id="examples-ext">
        <span>Try:</span>
        <span class="chip" data-id="cjpalhdlnbpafiamejdnhcphjbkeiagm" data-store="chrome">uBlock Origin</span>
        <span class="chip" data-id="dknlfmjaanfblgfdfebhijalfmhmjjjo" data-store="chrome">dknlf...mjjjo</span>
        <span class="chip" data-id="shd101wyy.markdown-preview-enhanced" data-store="vscode">Markdown Preview</span>
      </div>
      <div class="examples examples-npm hidden" id="examples-npm">
        <span>Try:</span>
        <span class="chip" data-npm="lodash@4.17.21" data-store="npm">lodash</span>
        <span class="chip" data-npm="left-pad@1.3.0" data-store="npm">left-pad</span>
      </div>

      <div class="field-label">Store or registry</div>
      <input type="hidden" id="store-input" name="store" value="chrome"/>
      <div class="store-toolbar">
        <div class="store-selector">
          <button type="button" class="store-pill active" data-store="chrome">Chrome</button>
          <button type="button" class="store-pill" data-store="edge">Edge</button>
          <button type="button" class="store-pill" data-store="vscode">VSCode</button>
          <button type="button" class="store-pill" data-store="openvsx">Open VSX</button>
          <button type="button" class="store-pill" data-store="npm">npm registry</button>
        </div>
        <div class="scan-cta">
          <button type="submit" id="submit-btn" class="btn btn-primary">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span id="submit-btn-label">Run security analysis</span>
          </button>
          <span class="hint" id="scan-hint">Cached reports load instantly.</span>
        </div>
      </div>
    </form>

    <div id="progress-panel" class="progress-panel">
      <div class="steps" id="progress-steps">
        <div class="step active" id="step-0"><span class="dot"></span><br>Metadata</div>
        <div class="step" id="step-1"><span class="dot"></span><br>Download</div>
        <div class="step" id="step-2"><span class="dot"></span><br>Analysis</div>
        <div class="step" id="step-3"><span class="dot"></span><br>Report</div>
      </div>
      <div class="elapsed" id="elapsed">Running for 0s&hellip;</div>
    </div>

    {recent}

    <script>
    (function() {{
      var pills = document.querySelectorAll('.store-pill');
      var storeInput = document.getElementById('store-input');
      var mainInput = document.getElementById('scan-target-input');
      var labelEl = document.getElementById('target-field-label');
      var exExt = document.getElementById('examples-ext');
      var exNpm = document.getElementById('examples-npm');
      var btnLabel = document.getElementById('submit-btn-label');
      var hintEl = document.getElementById('scan-hint');
      var form = document.getElementById('analyze-form');
      var step1 = document.getElementById('step-1');

      function applyStoreMode(store) {{
        if (store === 'npm') {{
          labelEl.textContent = 'npm package';
          mainInput.placeholder = 'e.g. lodash@4.17.21 or @types/node@20.1.0';
          mainInput.setAttribute('name', 'package_spec');
          storeInput.removeAttribute('name');
          exExt.classList.add('hidden');
          exNpm.classList.remove('hidden');
          btnLabel.textContent = 'Run npm-mal-scan';
          hintEl.innerHTML = 'Reports under <code>reports/npm_packages/</code> · cached when unchanged.';
          if (step1) step1.innerHTML = '<span class="dot"></span><br>Registry';
        }} else {{
          labelEl.textContent = 'Extension identifier';
          mainInput.placeholder = 'Paste extension ID or publisher.name';
          mainInput.setAttribute('name', 'extension_id');
          storeInput.setAttribute('name', 'store');
          exExt.classList.remove('hidden');
          exNpm.classList.add('hidden');
          btnLabel.textContent = 'Run security analysis';
          hintEl.textContent = 'Cached reports load instantly.';
          if (step1) step1.innerHTML = '<span class="dot"></span><br>Download';
        }}
      }}

      pills.forEach(function(p) {{
        p.addEventListener('click', function() {{
          pills.forEach(function(x) {{ x.classList.remove('active'); }});
          p.classList.add('active');
          storeInput.value = p.dataset.store;
          applyStoreMode(p.dataset.store);
        }});
      }});

      var chips = document.querySelectorAll('.chip[data-id], .chip[data-npm]');
      chips.forEach(function(c) {{
        c.addEventListener('click', function() {{
          if (c.dataset.npm) {{
            mainInput.value = c.dataset.npm;
            var st = c.dataset.store || 'npm';
            storeInput.value = st;
            pills.forEach(function(x) {{ x.classList.remove('active'); }});
            var tp = document.querySelector('.store-pill[data-store="' + st + '"]');
            if (tp) tp.classList.add('active');
            applyStoreMode(st);
          }} else if (c.dataset.id) {{
            mainInput.value = c.dataset.id;
            if (c.dataset.store) {{
              storeInput.value = c.dataset.store;
              pills.forEach(function(x) {{ x.classList.remove('active'); }});
              var t = document.querySelector('.store-pill[data-store="' + c.dataset.store + '"]');
              if (t) t.classList.add('active');
              applyStoreMode(c.dataset.store);
            }}
          }}
        }});
      }});

      applyStoreMode(storeInput.value);

      var panel = document.getElementById('progress-panel');
      var btn = document.getElementById('submit-btn');
      form.addEventListener('submit', function() {{
        var store = storeInput.value;
        if (store === 'npm') {{
          form.action = '/app/npm/analyze';
          mainInput.setAttribute('name', 'package_spec');
          storeInput.removeAttribute('name');
        }} else {{
          form.action = '/app/analyze';
          mainInput.setAttribute('name', 'extension_id');
          storeInput.setAttribute('name', 'store');
        }}
        panel.classList.add('visible');
        btn.disabled = true;
        var busy = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> ';
        btn.innerHTML = busy + (store === 'npm' ? 'Scanning\\u2026' : 'Analyzing\\u2026');
        var start = Date.now();
        var stepTimings = [0, 4000, 10000, 25000];
        var steps = document.querySelectorAll('.step');
        var elapsed = document.getElementById('elapsed');
        setInterval(function() {{
          var t = Date.now() - start;
          elapsed.textContent = 'Running for ' + Math.floor(t/1000) + 's\\u2026';
          for (var i = 0; i < stepTimings.length; i++) {{
            if (t >= stepTimings[i]) {{
              for (var j = 0; j < i; j++) {{ steps[j].className = 'step done'; }}
              steps[i].className = 'step active';
            }}
          }}
        }}, 500);
      }});
    }})();
    </script>
    """
    return _render_page(body)


@router.post("/analyze")
def analyze_extension(
    extension_id: str = Form(...),
    store: str = Form("chrome"),
):
    ext_id = (extension_id or "").strip()
    if not ext_id:
        return _render_error("Invalid input", "Extension ID is required.", back_link="/app/")

    browser = store.lower().strip() or "chrome"
    if browser == "npm":
        return _render_error(
            "Wrong form target",
            "npm package scans use the npm registry tab. Go back, choose npm registry, then submit again.",
            back_link="/app/",
        )
    if browser in ("chrome", "edge"):
        ext_id = ext_id.lower()

    db = SessionLocal()
    try:
        existing = (
            db.query(ScanResult)
            .filter(ScanResult.extension_id == ext_id)
            .order_by(ScanResult.scanned_at.desc())
            .first()
        )
        if existing:
            return RedirectResponse(
                url=f"/app/reports/{ext_id}/summary?cached=1", status_code=303
            )
    finally:
        db.close()

    scan_service = ScanService(settings.REPORTS_DIR)
    if browser == "vscode":
        store_enum = ScanStore.VSCODE
    elif browser == "edge":
        store_enum = ScanStore.EDGE
    else:
        store_enum = ScanStore.CHROME

    scan_request = ScanRequest(extension_id=ext_id, store=store_enum, fast_mode=False)
    output = scan_service.run(scan_request)

    if not output.success or not output.results:
        return _render_error(
            "Analysis failed",
            output.error or "The extension could not be analyzed. It may not exist or the store may be unreachable.",
            back_link="/app/",
        )

    from api.report_store import persist_scan_result_to_db
    persist_scan_result_to_db(
        extension_id=ext_id,
        browser_type="vscode" if browser in ("vscode", "openvsx") else browser,
        results=output.results,
        json_report_path=output.json_report_path,
        html_report_path=output.html_report_path,
        extension_dir=output.extension_dir,
    )

    return RedirectResponse(url=f"/app/reports/{ext_id}/summary", status_code=303)


@router.post("/npm/analyze")
def analyze_npm_package(package_spec: str = Form(...)):
    from npm_mal_scan_service import (
        npm_extension_id,
        run_npm_package_scan,
        validate_npm_package_spec,
    )
    from api.report_store import persist_scan_result_to_db

    spec = (package_spec or "").strip()
    verr = validate_npm_package_spec(spec)
    if verr:
        return _render_error("Invalid package", verr, back_link="/app/")

    ext_id = npm_extension_id(spec)

    db = SessionLocal()
    try:
        existing = (
            db.query(ScanResult)
            .filter(ScanResult.extension_id == ext_id)
            .order_by(ScanResult.scanned_at.desc())
            .first()
        )
        if existing:
            enc = quote(ext_id, safe="")
            return RedirectResponse(
                url=f"/app/reports/{enc}/summary?cached=1", status_code=303
            )
    finally:
        db.close()

    output = run_npm_package_scan(spec, settings.REPORTS_DIR, timeout=settings.JOB_TIMEOUT)

    if not output.success:
        return _render_error(
            "npm-mal-scan failed",
            output.error or "The scanner could not complete.",
            back_link="/app/",
        )

    persist_scan_result_to_db(
        extension_id=output.extension_id,
        browser_type="npm",
        results=output.results,
        json_report_path=output.json_report_path,
        html_report_path=output.html_report_path,
        extension_dir=None,
        version_hash=output.version_hash,
    )

    enc = quote(ext_id, safe="")
    return RedirectResponse(url=f"/app/reports/{enc}/summary", status_code=303)


@router.get("/reports/{extension_id}/summary", response_class=HTMLResponse)
def report_summary(
    extension_id: str,
    cached: Optional[str] = Query(None),
) -> HTMLResponse:
    ext_id = (extension_id or "").strip()
    if not ext_id:
        return _render_error("Invalid input", "Extension ID is required.", back_link="/app/")

    db = SessionLocal()
    try:
        result = (
            db.query(ScanResult)
            .filter(ScanResult.extension_id == ext_id)
            .order_by(ScanResult.scanned_at.desc())
            .first()
        )
        if not result:
            return _render_error(
                "No report found",
                f"We haven't scanned <code>{ext_id}</code> yet.",
                back_link="/app/",
            )

        score = result.risk_score or 0.0
        level = result.risk_level or "UNKNOWN"
        badge_cls = _risk_badge_class(level)
        gauge_col = _gauge_color(score)
        version = result.version or "?"
        when = result.scanned_at.strftime("%Y-%m-%d %H:%M UTC") if result.scanned_at else "?"
        findings_html = _build_findings_html(result)
        cached_badge = '<span class="pill" style="margin-left:auto">Loaded from cache</span>' if cached else ""
        enc_id = quote(ext_id, safe="")
        is_npm = ext_id.startswith("npkg:")
        rescan_npm = ""
        if is_npm:
            raw_spec = ext_id[5:]
            safe_spec = html_module.escape(raw_spec, quote=True)
            rescan_npm = f"""
          <form method="post" action="/app/npm/analyze" style="display:inline">
            <input type="hidden" name="package_spec" value="{safe_spec}"/>
            <button type="submit" class="btn btn-secondary">Re-scan</button>
          </form>"""
        rescan_ext = ""
        if not is_npm:
            safe_eid = html_module.escape(ext_id, quote=True)
            rescan_ext = f"""
          <form method="post" action="/app/analyze" style="display:inline">
            <input type="hidden" name="extension_id" value="{safe_eid}"/>
            <input type="hidden" name="store" value="chrome"/>
            <button type="submit" class="btn btn-secondary">Re-scan</button>
          </form>"""

        h2_display = html_module.escape(ext_id[5:] if is_npm else ext_id)
        npm_source_row = ""
        if is_npm:
            npm_source_row = f"""
            <div class="meta-row" style="margin-top:8px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
              <span class="recent-source recent-source-npm">npm registry</span>
              <span class="hint">npm-mal-scan · Report id <code>{html_module.escape(ext_id)}</code></span>
            </div>"""

        body = f"""
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
          <a href="/app/" class="btn btn-secondary" style="padding:7px 14px;font-size:12px;">&larr; Back</a>
          {cached_badge}
        </div>

        <div class="summary-header">
          <div class="gauge-wrap">
            <div class="gauge" style="border-color:{gauge_col}; color:{gauge_col}">
              {score:.1f}
            </div>
            <div class="gauge-label"><span class="risk-badge {badge_cls}">{level}</span></div>
          </div>
          <div class="meta-block">
            <h2 style="margin-bottom:6px;">{h2_display}</h2>
            <div class="meta-row">Version: <strong>{html_module.escape(version)}</strong></div>
            <div class="meta-row">Scanned: {when}</div>
            {npm_source_row}
          </div>
        </div>

        <div class="stats-row">
          <div class="stat-card">
            <div class="stat-value" style="color:{gauge_col}">{score:.1f}</div>
            <div class="stat-label">Risk Score</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">{result.findings_count or 0}</div>
            <div class="stat-label">Findings</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">{result.vuln_count or 0}</div>
            <div class="stat-label">Vulnerabilities</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">{result.malicious_domains or 0}</div>
            <div class="stat-label">Malicious Domains</div>
          </div>
        </div>

        {findings_html}

        <div class="actions-row" style="margin-top:20px;">
          <a href="/app/reports/{enc_id}" class="btn btn-primary">View full report</a>
          {rescan_npm if is_npm else rescan_ext}
        </div>
        """
        return _render_page(body, title=f"ExtRisk Intel — {ext_id}")
    finally:
        db.close()


@router.get("/reports/{extension_id}", response_class=HTMLResponse)
def view_report(extension_id: str) -> HTMLResponse:
    ext_id = (extension_id or "").strip()
    if not ext_id:
        return _render_error("Invalid input", "Extension ID is required.", back_link="/app/")

    db = SessionLocal()
    try:
        result = (
            db.query(ScanResult)
            .filter(ScanResult.extension_id == ext_id)
            .order_by(ScanResult.scanned_at.desc())
            .first()
        )
        if not result:
            return _render_error(
                "No report found",
                f"No report exists for <code>{ext_id}</code>. Run an analysis first.",
                back_link="/app/",
            )

        html_content = ""
        if result.report_html:
            html_content = result.report_html
        elif result.html_report_path:
            path = Path(result.html_report_path)
            if path.exists():
                html_content = path.read_text(encoding="utf-8")

        if not html_content:
            try:
                ext = db.query(Extension).filter(Extension.id == ext_id).first()
            except Exception:
                ext = None
            browser_type = (ext.browser_type if ext else "chrome") or "chrome"
            output = None
            if browser_type == "vscode":
                store = ScanStore.VSCODE
            elif browser_type == "edge":
                store = ScanStore.EDGE
            elif browser_type == "npm":
                store = None
            else:
                store = ScanStore.CHROME
            if browser_type != "npm" and store is not None:
                scan_service = ScanService(settings.REPORTS_DIR)
                scan_request = ScanRequest(extension_id=ext_id, store=store, fast_mode=False)
                output = scan_service.run(scan_request)
            if output and output.success and output.html_report_path:
                regen_path = Path(output.html_report_path)
                if regen_path.exists():
                    html_content = regen_path.read_text(encoding="utf-8")
                    result.html_report_path = output.html_report_path
                    if output.json_report_path:
                        result.json_report_path = output.json_report_path
                    result.report_html = html_content
                    db.commit()

        if not html_content:
            enc = quote(ext_id, safe="")
            return _render_error(
                "Report unavailable",
                "The HTML report file is missing or could not be loaded.",
                back_link=f"/app/reports/{enc}/summary",
            )

        level = result.risk_level or "?"
        badge_cls = _risk_badge_class(level)
        score = result.risk_score or 0
        nav_bar = f"""<div class="report-nav">
  <span style="color:#94a3b8;font-size:13px">{ext_id}</span>
  <span class="risk-badge {badge_cls}" style="font-size:10px">{level} {score:.1f}</span>
  <span class="spacer"></span>
  <a href="/app/" class="btn btn-secondary">New scan</a>
</div>"""

        if "<body" in html_content:
            insert_pos = html_content.find(">", html_content.find("<body")) + 1
            html_content = html_content[:insert_pos] + nav_bar + html_content[insert_pos:]
        else:
            html_content = nav_bar + html_content

        return HTMLResponse(content=html_content)
    finally:
        db.close()
