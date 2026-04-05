"""
Rich HTML for npm-mal-scan results — professional layout aligned with threat intel reports.

- No monospace “CLI” body text; Inter (and optional Source Sans 3) for prose.
- Hides internal 10-step pipeline from end-user view (still in verbatim stdout).
- IOC section: URLs, domains, IPv4 extracted only from malware/network/supply-chain context.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any, Optional
from urllib.parse import urlparse

_DASH_SEP = re.compile(r"^[─\-\u2500]{25,}\s*$")
# Box-drawing / dash “lines” embedded in scanner stdout (strip from UI)
_FILLER_LINE_RE = re.compile(
    r"^[\s\u2500-\u257F\u2014\u2015=\-·•_|]+$"
)
_VERDICT_IN_LINE = re.compile(r"Verdict\s*:", re.I)
_DEPCONF_IN_LINE = re.compile(r"DepConfusion", re.I)

# IOC extraction (aligned with patterns used in static_analyzer URL/host logic)
_URL_PATTERN = re.compile(r"(https?://[^\s'\"<>\)\]]+)", re.I)
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_REF_URL_PATTERN = re.compile(r"Ref:\s*[^\n]*?(https?://[^\s\)\]]+)", re.I)

# Hosts that are normal package distribution, not attacker infrastructure
_BENIGN_IOC_HOSTS = frozenset(
    {
        "registry.npmjs.org",
        "www.npmjs.org",
        "registry.yarnpkg.com",
        "www.npmjs.com",
    }
)


def _split_stdout_sections(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Split npm-mal-scan stdout into preamble and (title, body) sections."""
    lines = text.splitlines()
    preamble: list[str] = []
    sections: list[tuple[str, str]] = []
    i = 0
    n = len(lines)

    def is_title_candidate(line: str) -> bool:
        s = line.strip()
        if not s or len(s) > 130:
            return False
        if line.startswith((" ", "\t", "╔", "║", "╚", "│")):
            return False
        if s.startswith("═") or _DASH_SEP.match(s):
            return False
        return True

    while i < n:
        line = lines[i]
        if (
            i + 1 < n
            and is_title_candidate(line)
            and _DASH_SEP.match(lines[i + 1])
        ):
            title = line.strip()
            i += 2
            body_lines: list[str] = []
            while i < n:
                nxt = lines[i]
                if (
                    i + 1 < n
                    and is_title_candidate(nxt)
                    and _DASH_SEP.match(lines[i + 1])
                ):
                    break
                body_lines.append(nxt)
                i += 1
            sections.append((title, "\n".join(body_lines).rstrip()))
        else:
            preamble.append(line)
            i += 1

    return "\n".join(preamble).strip(), sections


def _extract_preamble_kv(preamble: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in preamble.splitlines():
        m = re.match(
            r"^\s{0,2}(Package|License|Published|Scanned at|dist\.shasum|dist\.integrity|npm user)\s*:\s*(.+)$",
            line,
            re.I,
        )
        if m:
            key = m.group(1).strip().lower().replace(" ", "_")
            out[key] = m.group(2).strip()
    return out


def _extract_maintainers_block(preamble: str) -> str:
    lines = preamble.splitlines()
    buf: list[str] = []
    in_m = False
    for line in lines:
        if re.match(r"^\s*Maintainers\s*\(registry\)\s*:\s*$", line, re.I):
            in_m = True
            continue
        if in_m:
            if line.strip() and not line.strip().startswith("•") and ":" in line[:20]:
                break
            if line.strip().startswith("•") or (line.strip() and "@" in line):
                buf.append(line.strip().lstrip("•").strip())
            elif not line.strip():
                if buf:
                    break
    return " · ".join(buf) if buf else ""


def _parse_overall_risk(body: str) -> dict[str, str]:
    risks: dict[str, str] = {}
    for line in body.splitlines():
        m = re.match(
            r"^\s*Malware Risk:\s*(\S+)", line, re.I
        ) or re.match(r"^\s*Vulnerability Risk:\s*(\S+)", line, re.I)
        if m:
            if "malware" in line.lower():
                risks["malware"] = m.group(1).strip()
            elif "vulnerability" in line.lower():
                risks["vulnerability"] = m.group(1).strip()
        m2 = re.match(r"^\s*Dep Confusion Risk:\s*(\S+)", line, re.I)
        if m2:
            risks["dep_confusion"] = m2.group(1).strip()
    return risks


def _extract_verdict(stdout: str) -> Optional[str]:
    m = re.search(r"Verdict:\s*(\w+)", stdout, re.I)
    return m.group(1).upper() if m else None


def _severity_badge_class(level: str) -> str:
    u = (level or "").upper()
    if u == "CRITICAL":
        return "critical"
    if u == "HIGH":
        return "high"
    if u == "MEDIUM":
        return "medium"
    if u == "LOW":
        return "low"
    if u in ("NONE", "MINIMAL", "BENIGN"):
        return "benign"
    return "medium"


def _split_finding_blocks(body: str) -> list[tuple[str, str, str]]:
    blocks: list[tuple[str, str, str]] = []
    current_sev: Optional[str] = None
    current_head: str = ""
    buf: list[str] = []

    def flush() -> None:
        nonlocal current_sev, current_head, buf
        if current_sev and (current_head or buf):
            blocks.append(
                (current_sev, current_head, "\n".join(buf).strip())
            )
        current_sev = None
        current_head = ""
        buf = []

    for line in body.splitlines():
        m = re.match(
            r"^(\s{2,})(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)\s+(\[.+)$",
            line,
        )
        if m:
            flush()
            current_sev = m.group(2)
            current_head = m.group(3).strip()
            continue
        if current_sev is not None:
            buf.append(line)
    flush()
    return blocks


def _host_from_url(url: str) -> str:
    try:
        p = urlparse(url.split("?", 1)[0])
        h = (p.hostname or "").lower()
        return h
    except Exception:
        return ""


def _is_network_related_finding(head: str, det: str) -> bool:
    h = (head + " " + det).upper()
    keys = (
        "NETWORK",
        "HTTP",
        "C2",
        "TCP",
        "SOCKET",
        "REQUEST",
        "DOWNLOAD",
        "URL",
        "POST(",
        "BEACON",
        "EXFIL",
        "IPv4",
        "DNS",
    )
    return any(k in h for k in keys)


def _auxiliary_ioc_context(sections: list[tuple[str, str]]) -> str:
    """Install hooks + network-download section text (supplements finding snippets)."""
    parts: list[str] = []
    for title, body in sections:
        u = title.upper()
        if "INSTALL LIFECYCLE" in u or "LIFECYCLE HOOK" in u:
            parts.append(body)
        if "NETWORK" in u and "DOWNLOAD" in u:
            parts.append(body)
        if "BEHAVIOR" in u and "RECONSTRUCT" in u:
            parts.append(body)
    return "\n".join(parts)


def _reference_intel_text(sections: list[tuple[str, str]]) -> str:
    parts: list[str] = []
    for title, body in sections:
        u = title.upper()
        if "SUPPLY-CHAIN" in u or ("CAMPAIGN" in u and "INTEL" in u):
            parts.append(body)
    return "\n".join(parts)


def _ioc_text_from_malware_findings(
    blocks: list[tuple[str, str, str]], full_malware_body: str
) -> str:
    """
    Prefer network/C2-related finding blocks; fall back to full malware section if none match.
    """
    parts: list[str] = []
    for _sev, head, det in blocks:
        blob = f"{head}\n{det}"
        if _is_network_related_finding(head, det):
            parts.append(blob)
            continue
        if _URL_PATTERN.search(det) or _IPV4_PATTERN.search(det):
            parts.append(blob)
    core = "\n".join(parts).strip()
    return core if core else full_malware_body


def _extract_iocs(
    observed_text: str, reference_text: str
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    """
    Returns (urls, domains, ipv4s). Deduplicate across types.
    source_tag: 'observed' | 'reference'
    """
    seen_url: set[str] = set()
    seen_dom: set[str] = set()
    seen_ip: set[str] = set()
    urls_o: list[dict[str, str]] = []
    domains_o: list[dict[str, str]] = []
    ips_o: list[dict[str, str]] = []

    def add_url(raw: str, source: str) -> None:
        u = raw.rstrip(".,;)]\"'")
        if not u or u in seen_url:
            return
        host = _host_from_url(u)
        if host in _BENIGN_IOC_HOSTS:
            return
        seen_url.add(u)
        urls_o.append({"value": u, "source_tag": source, "note": ""})

    def add_domain(d: str, source: str) -> None:
        d = d.lower().rstrip(".")
        if not d or d in seen_dom or "." not in d:
            return
        if d in _BENIGN_IOC_HOSTS:
            return
        seen_dom.add(d)
        domains_o.append({"value": d, "source_tag": source, "note": ""})

    def add_ip(ip: str, source: str) -> None:
        if ip in seen_ip:
            return
        seen_ip.add(ip)
        note = "Loopback / local service" if ip.startswith("127.") else ""
        ips_o.append({"value": ip, "source_tag": source, "note": note})

    for m in _URL_PATTERN.finditer(observed_text):
        add_url(m.group(1), "observed")
    for m in _IPV4_PATTERN.finditer(observed_text):
        add_ip(m.group(0), "observed")

    for m in _REF_URL_PATTERN.finditer(reference_text):
        add_url(m.group(1), "reference")
    for m in _URL_PATTERN.finditer(reference_text):
        add_url(m.group(1), "reference")

    for m in _URL_PATTERN.finditer(observed_text):
        u = m.group(1).rstrip(".,;)]\"'")
        h = _host_from_url(u)
        if h and h not in _BENIGN_IOC_HOSTS:
            add_domain(h, "observed")
    for m in _URL_PATTERN.finditer(reference_text):
        u = m.group(1).rstrip(".,;)]\"'")
        h = _host_from_url(u)
        if h and h not in _BENIGN_IOC_HOSTS:
            add_domain(h, "reference")

    return urls_o, domains_o, ips_o


def _format_finding_detail(det: str) -> str:
    """Turn File:/Snippet:/Detail: lines into structured HTML (sans-serif)."""
    if not det.strip():
        return ""
    parts: list[str] = []
    for line in det.splitlines():
        raw = line.rstrip()
        if not raw.strip():
            continue
        m = re.match(r"^\s*(File|Snippet|Detail|Ref)\s*:\s*(.*)$", raw, re.I)
        if m:
            k, v = m.group(1).title(), m.group(2).strip()
            if k.lower() == "snippet":
                parts.append(
                    f"<div class='fd-block'><span class='fd-k'>{html.escape(k)}</span>"
                    f"<code class='fd-code'>{html.escape(v)}</code></div>"
                )
            else:
                parts.append(
                    f"<div class='fd-block'><span class='fd-k'>{html.escape(k)}</span>"
                    f"<span class='fd-v'>{html.escape(v)}</span></div>"
                )
        else:
            parts.append(f"<p class='fd-p'>{html.escape(raw.strip())}</p>")
    return "".join(parts) if parts else f"<p class='fd-p'>{html.escape(det)}</p>"


def _render_package_overview(
    spec: str, meta: dict[str, str], maintainers: str, preamble: str
) -> str:
    """Replace ASCII box with a clean overview card."""
    pkg = html.escape(meta.get("package", spec))
    lic = html.escape(meta.get("license", "—"))
    pub = html.escape(meta.get("published", "—"))
    scanned = html.escape(meta.get("scanned_at", "—"))
    maint = html.escape(maintainers) if maintainers else "—"
    shasum = meta.get("dist_shasum", "")
    integrity = meta.get("dist_integrity", "")
    tech = ""
    if shasum or integrity:
        sh_e = html.escape(shasum[:24] + "…") if len(shasum) > 28 else html.escape(shasum)
        int_short = integrity[:36] + "…" if len(integrity) > 40 else integrity
        tech = f"""<details class="tech-fingerprints">
  <summary>Technical integrity (hashes)</summary>
  <div class="fd-block"><span class="fd-k">dist.shasum</span><code class="fd-code sm">{html.escape(shasum)}</code></div>
  <div class="fd-block"><span class="fd-k">dist.integrity</span><code class="fd-code sm">{html.escape(integrity)}</code></div>
</details>"""
    return f"""<section class="section section-tight">
  <div class="section-header">
    <div class="section-icon">&#128230;</div>
    <h2 class="section-title">Package overview</h2>
  </div>
  <div class="overview-card">
    <div class="overview-primary">
      <div class="overview-name">{pkg}</div>
      <div class="overview-sub">Maintainers (registry): <strong>{maint}</strong></div>
    </div>
    <div class="overview-grid">
      <div><span class="ov-label">License</span><span class="ov-value">{lic}</span></div>
      <div><span class="ov-label">Published</span><span class="ov-value">{pub}</span></div>
      <div><span class="ov-label">Scanned</span><span class="ov-value">{scanned}</span></div>
    </div>
    {tech}
  </div>
</section>"""


def _render_ioc_section(
    urls: list[dict[str, str]],
    domains: list[dict[str, str]],
    ips: list[dict[str, str]],
) -> str:
    if not urls and not domains and not ips:
        return ""

    def rows(items: list[dict[str, str]], kind: str) -> str:
        if not items:
            return ""
        lis = []
        for it in items[:80]:
            tag = "Observed in scan" if it["source_tag"] == "observed" else "Intel reference"
            note = f" · {html.escape(it['note'])}" if it.get("note") else ""
            lis.append(
                f"""<li class="ioc-line">
  <span class="ioc-val">{html.escape(it['value'])}</span>
  <span class="ioc-meta">{html.escape(tag)}{note}</span>
</li>"""
            )
        return f"""<div class="ioc-category">
  <div class="ioc-category-title">{kind}</div>
  <ul class="ioc-ul">{"".join(lis)}</ul>
</div>"""

    return f"""<section class="section ioc-section">
  <div class="section-header">
    <div class="section-icon">&#9889;</div>
    <h2 class="section-title">Indicators of compromise (IOCs)</h2>
  </div>
  <p class="ioc-intro">URLs, hosts, and IP literals extracted from <strong>network-related findings</strong>, 
  install-hook analysis, and <strong>supply-chain intel</strong> blocks in this scan. 
  Registry tarball URLs are omitted when they are standard npm distribution endpoints.</p>
  <div class="ioc-grid">
    {rows(urls, "URLs")}
    {rows(domains, "Domains / hosts")}
    {rows(ips, "IPv4 addresses")}
  </div>
</section>"""


def _is_filler_only_line(line: str) -> bool:
    t = line.strip()
    if len(t) < 10:
        return False
    return bool(_FILLER_LINE_RE.match(t))


def _humanize_section_title(title: str) -> str:
    """Turn ALL-CAPS scanner headings into title case for the report chrome."""
    parts: list[str] = []
    for w in title.split():
        if w.isupper() and len(w) > 1 and w.replace("-", "").isalpha():
            parts.append(w.capitalize())
        else:
            parts.append(w)
    return " ".join(parts)


def _strip_edge_fillers(s: str) -> str:
    t = s
    for _ in range(4):
        t2 = re.sub(r"^[\s\u2500-\u257F\u2014\u2015=\-·•_|]+", "", t)
        t2 = re.sub(r"[\s\u2500-\u257F\u2014\u2015=\-·•_|]+$", "", t2)
        if t2 == t:
            break
        t = t2
    return t.strip()


def _verdict_bar_html(line: str) -> str:
    """
    Parse scanner lines like:
    ─── Verdict: LOW | Malware LOW · CVE NONE ───
    into a compact pill row (no ASCII separators).
    """
    if not (_VERDICT_IN_LINE.search(line) or _DEPCONF_IN_LINE.search(line)):
        return ""
    cleaned = _strip_edge_fillers(line)
    cleaned = cleaned.replace("·", "|")
    segments = [s.strip() for s in cleaned.split("|") if s.strip()]
    if not segments:
        return ""
    pills: list[str] = []
    for seg in segments:
        if ":" in seg:
            k, v = seg.split(":", 1)
            key, val = k.strip(), v.strip()
        else:
            parts = seg.split(None, 1)
            key = parts[0].strip()
            val = parts[1].strip() if len(parts) > 1 else ""
        cls = _severity_badge_class(val.split()[0] if val else key)
        vm = cls if cls in ("critical", "high", "medium", "low", "benign") else ""
        pills.append(
            f"""<div class="scanner-verdict-pill">
  <div class="vp-k">{html.escape(key)}</div>
  <div class="vp-v {vm}">{html.escape(val or "—")}</div>
</div>"""
        )
    return f'<div class="scanner-verdict-bar" role="group">{"".join(pills)}</div>'


def _is_inventory_section_title(title: str) -> bool:
    u = title.upper()
    return "INVENTORY" in u or ("TARBALL" in u and "FILE" in u)


def _merge_path_tokens(tokens: list[str]) -> list[str]:
    """Attach trailing [bin] / [scope] tags to the previous path token."""
    out: list[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if (
            i + 1 < len(tokens)
            and tokens[i + 1].startswith("[")
            and tokens[i + 1].endswith("]")
        ):
            out.append(f"{t} {tokens[i + 1]}")
            i += 2
        else:
            out.append(t)
            i += 1
    return out


def _render_inventory_section(body: str) -> str:
    """Structured tarball / file list (replaces long dashed CLI rows)."""
    raw_lines = [ln.rstrip() for ln in body.splitlines()]
    lines = [ln for ln in raw_lines if not _is_filler_only_line(ln)]
    stats: list[str] = []
    path_blocks: list[str] = []
    prose_tail: list[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i].strip()
        if not ln:
            i += 1
            continue
        if _VERDICT_IN_LINE.search(ln) or _DEPCONF_IN_LINE.search(ln):
            prose_tail.append(lines[i])
            i += 1
            continue
        m = re.match(r"^Total files:\s*(\d+)\s*$", ln, re.I)
        if m:
            stats.append(
                f"""<div class="inventory-stat">
  <div class="is-k">Total files</div>
  <div class="is-v">{html.escape(m.group(1))}</div>
</div>"""
            )
            i += 1
            continue
        m = re.match(
            r"^Executable scripts\s*(?:\((\d+)\))?\s*:\s*(.*)$", ln, re.I
        )
        if m:
            ex_count, rest = m.group(1), (m.group(2) or "").strip()
            sub = (
                f" ({html.escape(ex_count)} paths)"
                if ex_count
                else ""
            )
            collected: list[str] = []
            if rest:
                collected.extend(_merge_path_tokens(rest.split()))
            i += 1
            while i < len(lines):
                nxt = lines[i].strip()
                if not nxt:
                    break
                if _VERDICT_IN_LINE.search(nxt) or _DEPCONF_IN_LINE.search(nxt):
                    prose_tail.append(lines[i])
                    i += 1
                    break
                if re.match(r"^[A-Za-z][^:]*:\s*\S", nxt) and not nxt.startswith(
                    ("/", ".", "src", "bin", "lib", "dist", "out", "pkg", "@")
                ):
                    if not re.match(r"^[\w./@[\]-]+\.\w+", nxt):
                        break
                collected.extend(_merge_path_tokens(nxt.split()))
                i += 1
            lis = "".join(
                f"<li><code class='path-chip'>{html.escape(p)}</code></li>"
                for p in collected
            )
            path_blocks.append(
                f"""<div class="inventory-path-block">
  <div class="ipb-title">Executable scripts{sub}</div>
  <ul class="inventory-path-list">{lis}</ul>
</div>"""
            )
            continue
        prose_tail.append(lines[i])
        i += 1

    parts: list[str] = []
    if stats:
        parts.append(f'<div class="inventory-stats">{"".join(stats)}</div>')
    parts.extend(path_blocks)
    tail_txt = "\n".join(prose_tail).strip()
    if tail_txt:
        for ln in tail_txt.splitlines():
            vb = _verdict_bar_html(ln)
            if vb:
                parts.append(vb)
            elif not _is_filler_only_line(ln) and ln.strip():
                parts.append(
                    f"<p class='prose-p'>{html.escape(ln.strip())}</p>"
                )
    if not parts:
        return _section_body_generic(body)
    return "".join(parts)


def _section_body_generic(body: str) -> str:
    """Render non-finding sections as readable prose, not monospace dump."""
    lines = body.splitlines()
    chunks: list[str] = []
    buf: list[str] = []
    for line in lines:
        if _is_filler_only_line(line):
            continue
        stripped = line.strip()
        if _VERDICT_IN_LINE.search(stripped) or _DEPCONF_IN_LINE.search(stripped):
            if buf:
                chunks.append(_section_body_generic_paras("\n".join(buf)))
                buf = []
            vb = _verdict_bar_html(line)
            if vb:
                chunks.append(vb)
            else:
                buf.append(line)
        else:
            buf.append(line)
    if buf:
        chunks.append(_section_body_generic_paras("\n".join(buf)))
    return "".join(chunks)


def _section_body_generic_paras(body: str) -> str:
    paras = [p.strip() for p in re.split(r"\n{2,}", body) if p.strip()]
    if not paras:
        return ""
    out: list[str] = []
    for p in paras:
        lines = p.splitlines()
        if all(
            ln.strip().startswith(("•", "-", "→", "http"))
            or re.match(r"^\s*\[\w+\]", ln)
            for ln in lines
            if ln.strip()
        ):
            items = []
            for ln in lines:
                s = ln.strip()
                if s:
                    items.append(f"<li>{html.escape(s)}</li>")
            out.append("<ul class='prose-list'>" + "".join(items) + "</ul>")
        else:
            out.append(f"<p class='prose-p'>{html.escape(p)}</p>")
    return "".join(out)


def _normalize_section_body(body: str) -> str:
    """Drop standalone dash-separator lines before rendering."""
    return "\n".join(
        ln for ln in body.splitlines() if not _is_filler_only_line(ln)
    )


def _render_section_body(title: str, body: str) -> str:
    body = _normalize_section_body(body)
    if not body.strip():
        return ""
    if _is_inventory_section_title(title):
        inv = _render_inventory_section(body)
        if inv.strip():
            return inv
    return _section_body_generic(body)


def _parsed_json_section(parsed: Any) -> str:
    if not isinstance(parsed, (dict, list)):
        return ""
    try:
        pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        pretty = str(parsed)
    return f"""<section class="section">
  <div class="section-header">
    <div class="section-icon">&#123; &#125;</div>
    <h2 class="section-title">Structured scanner output (JSON)</h2>
  </div>
  <div class="section-body"><pre class="json-pre">{html.escape(pretty)}</pre></div>
</section>"""


def build_npm_scan_html_report(file_record: dict[str, Any]) -> str:
    spec = str(file_record.get("package_spec", "") or "")
    exit_code = int(file_record.get("scanner_exit_code", -1))
    completed = str(file_record.get("completed_at", "") or "")
    stdout = str(file_record.get("scanner_stdout", "") or "")
    stderr = str(file_record.get("scanner_stderr", "") or "")
    risk_level = str(file_record.get("risk_level", "") or "UNKNOWN")
    risk_score = file_record.get("risk_score")
    parsed_json = file_record.get("parsed_output")

    preamble, sections = _split_stdout_sections(stdout)
    meta = _extract_preamble_kv(preamble)
    if "package" not in meta and spec:
        meta["package"] = spec
    maintainers = _extract_maintainers_block(preamble)
    verdict = _extract_verdict(stdout)

    malware_bodies = [
        body
        for title, body in sections
        if "MALWARE" in title.upper() and "FINDING" in title.upper()
    ]
    full_malware_body = "\n\n".join(malware_bodies)
    findings_blocks_for_ioc: list[tuple[str, str, str]] = []
    for mb in malware_bodies:
        findings_blocks_for_ioc.extend(_split_finding_blocks(mb))
    ioc_core = _ioc_text_from_malware_findings(
        findings_blocks_for_ioc, full_malware_body
    )
    obs_text = (ioc_core + "\n" + _auxiliary_ioc_context(sections)).strip()
    ref_text = _reference_intel_text(sections)
    urls, domains, ips = _extract_iocs(obs_text, ref_text)

    overall: dict[str, str] = {}
    section_html_parts: list[str] = []

    for title, body in sections:
        t_up = title.upper()
        if t_up == "OVERALL RISK":
            overall = _parse_overall_risk(body)
            continue
        if "10-STEP" in t_up or "ANALYSIS PIPELINE" in t_up:
            continue
        display_title = _humanize_section_title(title)
        esc_title = html.escape(display_title)

        if "MALWARE" in t_up and "FINDING" in t_up:
            blocks = _split_finding_blocks(body)
            if blocks:
                cards = []
                for sev, head, det in blocks:
                    cls = _severity_badge_class(sev)
                    ti = (
                        "critical"
                        if sev == "CRITICAL"
                        else (cls if cls in ("high", "medium", "low") else "medium")
                    )
                    net_badge = ""
                    if _is_network_related_finding(head, det):
                        net_badge = '<span class="net-badge">Network / C2 signal</span>'
                    detail_html = _format_finding_detail(det)
                    cards.append(
                        f"""<div class="threat-item {ti}">
  <div class="threat-header">
    <span class="threat-name">{html.escape(head[:220])}</span>
    <span class="threat-severity {cls}">{html.escape(sev)}</span>
  </div>
  {net_badge}
  <div class="finding-body">{detail_html}</div>
</div>"""
                    )
                inner = '<div class="findings-stack">' + "".join(cards) + "</div>"
            else:
                inner = _render_section_body(title, body)
        else:
            inner = _render_section_body(title, body)
            if not inner.strip():
                inner = f"<p class='prose-p muted'>No displayable content for this section.</p>"

        section_html_parts.append(
            f"""<section class="section">
  <div class="section-header">
    <div class="section-icon">&#9670;</div>
    <h2 class="section-title">{esc_title}</h2>
  </div>
  <div class="section-body prose-section">{inner}</div>
</section>"""
        )

    malware_r = overall.get("malware", verdict or risk_level)
    vuln_r = overall.get("vulnerability", "—")
    dep_r = overall.get("dep_confusion", "—")
    exec_cls = "critical" if (malware_r or "").upper() == "CRITICAL" else (
        "high" if (malware_r or "").upper() == "HIGH" else ""
    )

    bluf = (
        f"npm-mal-scan rated <strong>malware risk {html.escape(malware_r or 'UNKNOWN')}</strong> "
        f"for this package. "
        f"Vulnerability signal: {html.escape(vuln_r)}; dependency confusion: {html.escape(dep_r)}."
    )
    if verdict:
        bluf += f" Scanner verdict: <strong>{html.escape(verdict)}</strong>."

    meta_grid = ""
    if meta:
        cells = []
        for k, v in list(meta.items())[:6]:
            if k in ("dist_shasum", "dist_integrity"):
                continue
            cells.append(
                f"""<div class="meta-cell">
  <div class="meta-label">{html.escape(k.replace('_', ' ').title())}</div>
  <div class="meta-value">{html.escape(v[:280])}</div>
</div>"""
            )
        meta_grid = '<div class="header-meta">' + "".join(cells) + "</div>"

    risk_cards = f"""
<div class="risk-strip">
  <div class="risk-card">
    <div class="risk-card-label">Malware risk</div>
    <span class="threat-badge {_severity_badge_class(malware_r)}">{html.escape(malware_r or '—')}</span>
  </div>
  <div class="risk-card">
    <div class="risk-card-label">Vulnerability risk</div>
    <span class="threat-badge {_severity_badge_class(vuln_r)}">{html.escape(vuln_r)}</span>
  </div>
  <div class="risk-card">
    <div class="risk-card-label">Dep confusion</div>
    <span class="threat-badge {_severity_badge_class(dep_r)}">{html.escape(dep_r)}</span>
  </div>
</div>"""

    score_s = f"{float(risk_score):.1f}" if isinstance(risk_score, (int, float)) else "—"

    overview_html = _render_package_overview(spec, meta, maintainers, preamble)
    ioc_html = _render_ioc_section(urls, domains, ips)

    verbatim = f"""<details class="verbatim-block">
  <summary>Technical appendix: full scanner stdout</summary>
  <pre class="verbatim-pre">{html.escape(stdout)}</pre>
</details>"""
    stderr_block = ""
    if stderr.strip():
        stderr_block = f"""<details class="verbatim-block">
  <summary>Scanner stderr</summary>
  <pre class="verbatim-pre">{html.escape(stderr)}</pre>
</details>"""

    css = """
:root {
  --color-critical: #ef4444;
  --color-high: #f97316;
  --color-medium: #eab308;
  --color-low: #22c55e;
  --font-sans: 'Inter', 'Source Sans 3', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  --font-mono: 'JetBrains Mono', 'Cascadia Code', ui-monospace, monospace;
  --bg-primary: #0f172a;
  --bg-secondary: #1e293b;
  --bg-card: #334155;
  --text-primary: #f1f5f9;
  --text-secondary: #94a3b8;
  --border-color: #475569;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--font-sans);
  line-height: 1.65;
  font-size: 15px;
  color: var(--text-primary);
  background: var(--bg-primary);
}
.report-container { max-width: 1200px; margin: 0 auto; background: var(--bg-secondary);
  box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
.report-header {
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
  color: #fff;
  padding: 36px 40px 28px;
  border-bottom: 4px solid #0ea5e9;
}
.report-header.critical-edge { border-bottom-color: #dc2626; }
.header-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 20px; flex-wrap: wrap; }
.report-title h1 { font-size: 26px; font-weight: 700; letter-spacing: -0.5px; margin-bottom: 6px; font-family: var(--font-sans); }
.report-title .subtitle { font-size: 14px; opacity: 0.85; font-weight: 400; }
.classification-badge {
  padding: 10px 20px; border-radius: 8px; font-weight: 700; font-size: 13px;
  text-transform: uppercase; letter-spacing: 0.06em;
  background: linear-gradient(135deg, #0ea5e9, #22c55e); color: #0b1120;
  font-family: var(--font-sans);
}
.classification-badge.critical { background: #dc2626; color: #fff; }
.classification-badge.high { background: #ea580c; color: #fff; }
.header-meta {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 14px; margin-top: 22px; padding-top: 18px; border-top: 1px solid rgba(255,255,255,0.1);
}
.meta-cell { text-align: left; }
.meta-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; opacity: 0.7; margin-bottom: 4px; }
.meta-value { font-size: 14px; font-weight: 600; word-break: break-word; }

.executive-summary {
  padding: 28px 40px;
  background: linear-gradient(135deg, rgba(14,165,233,0.12) 0%, rgba(34,197,94,0.06) 100%);
  border-left: 6px solid #0ea5e9;
}
.executive-summary.critical {
  background: linear-gradient(135deg, rgba(239,68,68,0.2) 0%, rgba(239,68,68,0.05) 100%);
  border-left-color: #ef4444;
}
.executive-summary h2 { font-size: 18px; font-weight: 700; margin-bottom: 12px; color: #7dd3fc; font-family: var(--font-sans); }
.executive-summary.critical h2 { color: #fca5a5; }
.bluf {
  font-size: 15px; font-weight: 500; line-height: 1.75;
  padding: 14px 16px; background: rgba(0,0,0,0.2); border-radius: 8px;
}
.bluf strong { font-weight: 700; }

.risk-strip {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px;
  padding: 20px 40px; background: rgba(0,0,0,0.12);
  border-bottom: 1px solid var(--border-color);
}
@media (max-width: 640px) { .risk-strip { grid-template-columns: 1fr; } }
.risk-card {
  background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px;
  padding: 16px; text-align: center;
}
.risk-card-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 8px; }

.threat-badge {
  display: inline-block; padding: 6px 14px; border-radius: 999px; font-size: 12px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.04em; font-family: var(--font-sans);
}
.threat-badge.critical { background: var(--color-critical); color: #fff; }
.threat-badge.high { background: var(--color-high); color: #fff; }
.threat-badge.medium { background: var(--color-medium); color: #1e293b; }
.threat-badge.low { background: var(--color-low); color: #052e16; }
.threat-badge.benign { background: #10b981; color: #fff; }

.section { padding: 28px 40px 32px; border-bottom: 1px solid var(--border-color); }
.section-tight { padding-top: 20px; }
.section-header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.section-icon {
  width: 38px; height: 38px; background: var(--bg-card); border-radius: 8px;
  display: flex; align-items: center; justify-content: center; font-size: 18px;
}
.section-title {
  font-size: 19px; font-weight: 700; font-family: var(--font-sans);
  text-transform: none; letter-spacing: -0.02em; line-height: 1.25;
}

.scanner-verdict-bar {
  display: flex; flex-wrap: wrap; gap: 12px; margin: 18px 0 10px; align-items: stretch;
}
.scanner-verdict-pill {
  flex: 1 1 160px; min-width: 140px; max-width: 300px;
  background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px;
  padding: 12px 14px;
}
.scanner-verdict-pill .vp-k {
  font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--text-secondary); margin-bottom: 6px; font-family: var(--font-sans);
}
.scanner-verdict-pill .vp-v {
  font-size: 15px; font-weight: 700; font-family: var(--font-sans); line-height: 1.35; word-break: break-word;
}
.scanner-verdict-pill .vp-v.critical { color: #fca5a5; }
.scanner-verdict-pill .vp-v.high { color: #fdba74; }
.scanner-verdict-pill .vp-v.medium { color: #fde047; }
.scanner-verdict-pill .vp-v.low { color: #86efac; }
.scanner-verdict-pill .vp-v.benign { color: #6ee7b7; }

.inventory-stats { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px; }
.inventory-stat {
  background: rgba(0,0,0,0.18); border: 1px solid var(--border-color); border-radius: 10px;
  padding: 14px 18px; min-width: 130px;
}
.inventory-stat .is-k {
  font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-secondary);
  margin-bottom: 6px; font-family: var(--font-sans);
}
.inventory-stat .is-v {
  font-size: 22px; font-weight: 700; font-family: var(--font-sans); color: #f1f5f9;
}
.inventory-path-block { margin-top: 16px; }
.ipb-title {
  font-size: 13px; font-weight: 700; color: #7dd3fc; margin-bottom: 10px; font-family: var(--font-sans);
}
.inventory-path-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 6px; }
.path-chip {
  display: block; font-family: var(--font-mono); font-size: 12px; line-height: 1.45;
  background: #0c1222; padding: 9px 12px; border-radius: 8px; border: 1px solid var(--border-color);
  color: #cbd5e1; word-break: break-all;
}

.overview-card {
  background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px;
  padding: 22px 24px;
}
.overview-primary { margin-bottom: 18px; }
.overview-name { font-size: 22px; font-weight: 700; letter-spacing: -0.02em; margin-bottom: 8px; }
.overview-sub { font-size: 14px; color: var(--text-secondary); line-height: 1.5; }
.overview-sub strong { color: var(--text-primary); font-weight: 600; }
.overview-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 14px;
}
.ov-label { display: block; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-secondary); margin-bottom: 4px; }
.ov-value { font-size: 14px; font-weight: 600; }

.tech-fingerprints { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border-color); }
.tech-fingerprints summary { cursor: pointer; font-size: 13px; font-weight: 600; color: #7dd3fc; margin-bottom: 10px; }

.ioc-section { background: rgba(239,68,68,0.04); }
.ioc-intro { font-size: 14px; color: var(--text-secondary); margin-bottom: 18px; max-width: 900px; line-height: 1.6; }
.ioc-grid { display: grid; gap: 18px; }
.ioc-category {
  background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px;
  padding: 18px 20px; border-left: 4px solid #f87171;
}
.ioc-category-title { font-size: 15px; font-weight: 700; margin-bottom: 12px; color: #fca5a5; }
.ioc-ul { list-style: none; padding: 0; margin: 0; }
.ioc-line {
  padding: 10px 12px; margin-bottom: 8px; background: rgba(0,0,0,0.15); border-radius: 8px;
  border: 1px solid rgba(255,255,255,0.06);
}
.ioc-val { display: block; font-size: 14px; font-weight: 600; word-break: break-all; color: #fecaca; }
.ioc-meta { display: block; font-size: 11px; color: var(--text-secondary); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.04em; }

.prose-section .prose-p { margin-bottom: 12px; color: var(--text-primary); font-size: 15px; line-height: 1.7; }
.prose-section .prose-p.muted { color: var(--text-secondary); font-size: 14px; }
.prose-list { margin: 10px 0 10px 1.2em; color: var(--text-primary); font-size: 14px; line-height: 1.65; }
.prose-list li { margin: 6px 0; }

.findings-stack { display: flex; flex-direction: column; gap: 14px; }
.threat-item {
  background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px;
  padding: 18px 20px; border-left: 4px solid #64748b;
}
.threat-item.critical { border-left-color: #dc2626; background: rgba(239,68,68,0.06); }
.threat-item.high { border-left-color: #ef4444; }
.threat-item.medium { border-left-color: #eab308; }
.threat-item.low { border-left-color: #64748b; }
.threat-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
.threat-name { font-size: 15px; font-weight: 700; flex: 1; min-width: 0; word-break: break-word; line-height: 1.4; }
.threat-severity {
  font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 4px 10px; border-radius: 999px; flex-shrink: 0;
  font-family: var(--font-sans);
}
.threat-severity.critical { background: rgba(239,68,68,0.25); color: #fca5a5; }
.threat-severity.high { background: rgba(249,115,22,0.2); color: #fdba74; }
.threat-severity.medium { background: rgba(234,179,8,0.2); color: #fde047; }
.threat-severity.low { background: rgba(100,116,139,0.25); color: #cbd5e1; }
.net-badge {
  display: inline-block; margin-top: 8px; font-size: 10px; font-weight: 700; text-transform: uppercase;
  padding: 4px 10px; border-radius: 999px; background: rgba(59,130,246,0.2); color: #93c5fd; letter-spacing: 0.04em;
}
.finding-body { margin-top: 12px; }
.fd-block { margin-bottom: 10px; }
.fd-k { display: block; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 4px; }
.fd-v { font-size: 14px; color: var(--text-primary); line-height: 1.5; display: block; }
.fd-code {
  display: block; font-family: var(--font-mono); font-size: 12px; line-height: 1.5;
  background: #0c1222; padding: 12px 14px; border-radius: 8px; border: 1px solid var(--border-color);
  overflow-x: auto; white-space: pre-wrap; word-break: break-word; color: #e2e8f0; margin-top: 4px;
}
.fd-code.sm { font-size: 11px; }
.fd-p { font-size: 14px; color: var(--text-secondary); margin-top: 6px; }

.json-pre, .verbatim-pre {
  font-family: var(--font-mono); font-size: 11px; line-height: 1.5;
  background: #0c1222; border: 1px solid var(--border-color); border-radius: 8px;
  padding: 16px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; color: #cbd5e1;
}
.verbatim-pre { max-height: 420px; overflow-y: auto; }

.verbatim-block { margin: 20px 40px 32px; }
.verbatim-block summary { cursor: pointer; font-size: 13px; font-weight: 600; color: #7dd3fc; padding: 8px 0; }

.footer-bar {
  padding: 16px 40px; font-size: 13px; color: var(--text-secondary);
  border-top: 1px solid var(--border-color); display: flex; flex-wrap: wrap; gap: 16px; justify-content: space-between;
}
"""

    header_crit = (
        "critical-edge"
        if (malware_r or "").upper() == "CRITICAL" or (verdict or "").upper() == "CRITICAL"
        else ""
    )
    badge_level = verdict or malware_r or risk_level
    badge_cls = _severity_badge_class(badge_level)
    badge_mod = badge_cls if badge_cls in ("critical", "high", "medium", "low", "benign") else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>npm-mal-scan — {html.escape(spec)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Source+Sans+3:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
  <style>{css}</style>
</head>
<body>
<div class="report-container">
  <header class="report-header {header_crit}">
    <div class="header-top">
      <div class="report-title">
        <h1>NPM supply-chain scan</h1>
        <p class="subtitle">Professional summary · Technical details in appendix</p>
      </div>
      <div class="classification-badge {badge_mod}">{html.escape(badge_level)}</div>
    </div>
    {meta_grid}
  </header>

  <div class="executive-summary {exec_cls}">
    <h2>Executive summary</h2>
    <p class="bluf">{bluf}</p>
    <p class="bluf" style="margin-top:10px;padding:10px 14px;font-size:13px;">
      ExtRisk heuristic score: <strong>{html.escape(score_s)}</strong> / 10 ·
      Exit code: <strong>{exit_code}</strong>
      {f" · Completed {html.escape(completed)}" if completed else ""}
    </p>
  </div>

  {risk_cards}

  {overview_html}

  {ioc_html}

  {"".join(section_html_parts)}

  {stderr_block}
  {verbatim}

  {_parsed_json_section(parsed_json)}

  <div class="footer-bar">
    <span>ExtRisk npm integration</span>
    <span>Package: <strong>{html.escape(spec)}</strong></span>
  </div>
</div>
</body>
</html>"""
