# Detection gaps and review mistakes log

This log records **gaps** (false negatives: issues in code the tool did not report) and **mistakes** (false positives or wrong severity/category) found during Bablu’s extension reviews. It is the source of truth for improving the analyzer and for Bablu’s skill: read it before reviewing and add new entries when you find issues.

**Skill:** When acting as Bablu, read `docs/DETECTION_GAPS_LOG.md` (and this section) and apply the lessons below so reviews get better over time.

---

## How to use this log

- **Before/during review:** Read “Lessons from past reviews” and the open gaps/mistakes so you don’t repeat the same misclassifications and you look for previously missed patterns.
- **When you find a gap (false negative):** Add an entry under **Gaps (false negatives)** with: extension ID, file, line/snippet, description of the missing pattern, and date.
- **When you find a mistake (FP or wrong severity):** Add an entry under **Mistakes (false positives / wrong severity)** with: extension ID, finding ID/category, correction (e.g. “FP: library code”, “Severity should be LOW”), and date.
- **When a gap is closed:** Move the gap to **Closed gaps** and note the rule/finding name that now covers it.

---

## Lessons from past reviews (apply every time)

Use these to avoid repeating known mistakes and to align with the analyzer’s intended behavior:

### App code vs dependency code

- **Dependency code is not app code.** Findings in `node_modules/`, vendor files, or known library bundles (vega, d3, reveal.js, mermaid, katex, etc.) should be treated as dependency findings: do not count them in headline “app code” threat counts; note them as dependency/vendor and expect the report to flag them as `dependency_suppressed` or in a dependency section.
- When verifying a finding, check the **file path**: if it’s inside `node_modules/` or a known vendor bundle, mark as FP for “app-code” headline or suggest severity downgrade / dependency_suppressed.

### Extension UI and benign patterns

- **Extension UI files (new tab, popup, options, settings, background):** Form submit, IndexedDB open, and DevTools detection in these files are often benign (search form, settings storage, minified bundle). The analyzer suppresses or downgrades them; when reviewing, confirm the finding is not on an extension-owned page before treating as malicious.

### Pattern and severity accuracy

- **eval / Function(…)( ):**
  - Exclude **method calls** like `.eval(` or `this.eval(` (library internals). If the report flags these, mark as FP and note “method call, not global eval”.
  - Only global `eval(` or dynamic `Function(...)()` used on user/network data should be treated as high risk.
- **Base64-like strings:**
  - **Hex-only** strings (`[0-9a-fA-F]+`) are often color palettes or hashes, not base64 payloads. If the report flags hex-only as “base64”, mark as FP and note “hex-only, no + or /”.
  - Real base64 typically contains at least one of `+` or `/` (or padding `=`).
- **Severity:** Prefer **severity from the advisory** (e.g. CVE/OSV/Retire.js). Do not assume all CVEs are “high”; if the report shows a CVE as high but the advisory says LOW/MODERATE, note the mistake.

### Domains and network

- **Benign domains:** Publisher-domain mismatch or “suspicious domain” findings should **allowlist** CDNs (jsdelivr, cdnjs, unpkg), package registries (npmjs.com), standards (w3.org), well-known services (kroki.io, shields.io), and localhost. If the report flags these as suspicious, mark as FP and note “allowlisted CDN/infra”.
- **Where is the data going?** For `chrome.cookies`, `chrome.storage`, or `fetch`/XHR: confirm the **destination**. Internal IPC (`chrome.runtime.sendMessage`) or same-origin/known API is lower risk than exfiltration to an unknown domain.

### Report and BLUF

- **BLUF must be specific.** If the report says “Multiple suspicious behaviors detected” without naming CVE IDs, severity counts, or app vs dependency, note it as a mistake: BLUF should state exactly what was found.
- **Every finding needs “Why this matters”.** Raw pattern matches (eval, base64, HTTP) without context are misleading; note if a finding lacks explanation so the report can be improved.

### Scope of review (VSCode / main JS)

- Review focuses on **main JS files** (package.json `main`/`browser`, contributes entry points, top-level .js/.ts in src/out/dist). Do not treat every file under `node_modules` as app code; use the main-JS list from the batch manifest or package.json when deciding what to verify first.

### Security-research-derived detection rules

- **Fetch hook + MAIN world**: Extensions that run content scripts in `world: "MAIN"` and override `window.fetch` or read `Authorization` headers are capable of session/account theft (e.g. ChatGPT-style campaign). The analyzer now flags: (1) `content_scripts[].world: "MAIN"` in manifest, (2) fetch override/hook patterns, (3) Authorization header extraction in code. When reviewing, confirm whether the extension targets authenticated AI or SaaS pages; if so, treat as high risk.
- **DOM XSS / XSS evasion / Annex (sold-extension)**: Patterns from OWASP DOM XSS Prevention, XSS Prevention, XSS Filter Evasion, and Annex Security (e.g. Pixel Perfect–style) are in `src/static_analyzer.py`. See `docs/OWASP_ANNEX_DETECTION_PATTERNS.md` for the full list and references. When reviewing, confirm source is user-controllable and sink receives unencoded data; framework escape hatches (dangerouslySetInnerHTML, etc.) can be legitimate when value is sanitized.
- **L crawler**: Run `python scripts/l_crawler.py --write-lessons` to refresh IOCs and detection hints from L blog; see `docs/L_LESSONS_LEARNT.md`.
- **K crawler**: Run `python scripts/k_crawler.py --write-lessons` to refresh IOCs from K blog (RedDirection, DarkSpectre, GhostPoster, SpyVPN, VK Styles, etc.); see `docs/K_LESSONS_LEARNT.md`. Use for Bablu comparison and IOC/blocklist updates.

---

## Gaps (false negatives)

*Add when you see a suspicious or malicious pattern in the code that the tool did **not** report.*

| Date       | Extension ID / name | File:line | Missing pattern / behavior | Status   |
|-----------|----------------------|-----------|----------------------------|----------|
| *(none yet)* | — | — | — | open |

---

## Mistakes (false positives / wrong severity)

*Add when the report is wrong: FP, wrong category, or wrong severity.*

| Date       | Extension ID / name | Finding / category | Correction (e.g. FP: reason; or severity LOW) | Status   |
|-----------|----------------------|--------------------|-----------------------------------------------|----------|
| *(none open)* | — | — | — | — |

---

## Closed mistakes (fixed in analyzer)

*Mistakes from Bablu review that were fixed in code.*

| Date closed | Extension ID | Finding / category | Correction applied |
|-------------|--------------|--------------------|--------------------|
| 2026-02-27 | fogdlfdfpjlpmpmnmeepffaikefkacnc (Radial New Tab) | Form Submit Interception | FP in extension UI: suppress when file is newtab/popup/options/background/settings (own search form). |
| 2026-02-27 | fogdlfdfpjlpmpmnmeepffaikefkacnc | IndexedDB Data Harvesting | FP in extension UI: suppress when file is extension UI (settings/shortcuts storage). |
| 2026-02-27 | fogdlfdfpjlpmpmnmeepffaikefkacnc | Screen Capture Capability (combination warning) | FP: remove warning when extension does not use captureVisibleTab (evidence-based). |
| 2026-02-27 | fogdlfdfpjlpmpmnmeepffaikefkacnc | DevTools Detection | Downgrade to low when in extension UI file (common in minified new tab bundles). |
| 2026-02-27 | fogdlfdfpjlpmpmnmeepffaikefkacnc | Phishing Overlay / Evasion-Wrapped Payload | Require high/critical severity on phishing/evasion findings before firing correlation. |
| 2026-02-22 | eamodio.gitlens | Localhost HTTP access (localhost_access) | FP: localhost:11434 = Ollama; localhost:4318 = OTLP exporter. Suppress in Rule 5c. |
| 2026-02-22 | eamodio.gitlens | Localhost HTTP access (localhost_access) | FP: telemetry exporter localhost:4318. Suppress in Rule 5c. |
| 2026-02-22 | GitHub.copilot-chat | Localhost HTTP access (localhost_access) | FP: `new URL(..., "http://localhost")` used as base URL only. Suppress in Rule 5c. |

**Rule 5c** in `vscode_analyzer._filter_vscode_false_positives`: suppress "Localhost HTTP access from extension code" when evidence shows localhost:11434 (Ollama), localhost:4318 (OpenTelemetry), or `new URL(..., "http://localhost")` as base URL only.

---

## Closed gaps

*When a gap is fixed in the detection library, move it here and note the rule/finding name.*

| Date closed | Original gap (short) | Rule / finding name that now covers it |
|-------------|------------------------|----------------------------------------|
| *(none yet)* | — | — |

---

## FP reduction implementation summary (2026-02-27)

Completed to-dos from the FP reduction task:

1. **Tune taint analyzer (password→sendMessage FP)**  
   In `src/taint_analyzer.py` regex fallback: password/password-field flow is only reported when the sink is **fetch**, **XMLHttpRequest**, or **sendBeacon**. Flow to `chrome.runtime.sendMessage` alone is no longer reported, reducing FPs where content script sends "form submitted" or similar to background without exfil.

2. **Domain / preset allowlist (favicon API, shortcut lists)**  
   In `src/network_capture.py`: added to `DOMAIN_ALLOWLIST` favicon-related hosts (`www.google.com`, `t0.gstatic.com`–`t3.gstatic.com`). Added to `KNOWN_SAAS_PATHS`: `/s2/favicons?` and `/favicon.ico` so favicon/shortcut-list fetches are treated as benign and not scored as suspicious.

3. **Document changes and run tests**  
   This section documents the changes. Run the analyzer on previously reviewed extensions (e.g. `python src/analyzer.py fogdlfdfpjlpmpmnmeepffaikefkacnc`) to confirm fewer FPs (suppressed Form Submit/IndexedDB in extension UI, no Screen Capture warning without captureVisibleTab, no Phishing Overlay / Evasion-Wrapped when only low-severity evasion/phishing, no taint alert for password→sendMessage only).

