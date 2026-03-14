# Architecture: Dependency Vulnerability Scanning & Detection Pattern Refinements

**Status:** Plan (for decision)  
**Last updated:** 2026-02-19

---

## 1. Clarification: What Was Not Done

- **No changes were made to the HTML report** – The threat analysis report (`vscode_shd101wyy.markdown-preview-enhanced_threat_analysis_report.html`) was only analyzed and findings classified (FP vs confirmed). The file was not edited.
- **No new detection patterns were added** – The VSCode analyzer (`src/vscode_analyzer.py`) and static analyzer were not modified. The previous session only fixed syntax and the “skip large library” heuristic so analysis could complete.

This document describes **recommended** pattern refinements and a **proposed** architecture for dependency vulnerability scanning. Implementation is left for your decision.

---

## 2. Detection Pattern Refinements & New Patterns

### 2.1 Reduce False Positives (Existing Patterns)

| Issue | Current behavior | Recommended change |
|-------|------------------|--------------------|
| **child_process.exec with dynamic args** | Pattern `(?:child_process\s*\.\s*exec\|exec)\s*\(...` matches **any** `exec(` with template/var (e.g. `Es.exec(x[M1])` in minified code = regex `.exec()`, not shell). | **Option A:** Require `exec` to be preceded by `child_process` or `require\s*\(\s*['"]child_process` (drop bare `\|exec`). **Option B:** Exclude matches where the token before `.exec` is a known regex/array name (e.g. regex var or `\[.*\]\.exec`). Prefer A for simplicity. |
| **Webview innerHTML** in dependencies | All `.innerHTML` in extension tree are flagged; most are in third-party libs (reveal.js, remarkable, etc.). | **Tag findings by path:** If file path is under `node_modules` or `dependencies/`, assign a lower severity or a separate category (e.g. `webview_risk_dependency`) so report/risk scoring can treat app code vs dependency code differently. |
| **Plaintext HTTP endpoint** | Matches any `http://` string; triggers on XML namespace URLs (`http://www.w3.org/1999/xhtml`) and comments. | **Exclude:** Known namespace/standards URLs (w3.org, schemas, xmlns) and optionally only flag when URL is in a runtime context (e.g. `fetch(`, `location=`, `src=`) not in string literals used for XML/HTML namespaces. |
| **OAuth / credential / identity harvesting** | Evidence is often minified parser “token” (e.g. `g.token`, `content=n(...)`). | **Tighten:** Require presence of auth-related identifiers (e.g. `oauth`, `token`, `credential`, `cookie`) in same line or small window, and/or exclude files under `dependencies/` or known lib paths. |

### 2.2 Other Patterns to Consider (Research)

- **enableScripts: true in webview options** – Already in analyzer; ensure it is reported prominently when present (directly related to CVE-2025-65716-style issues).
- **User-controlled content → innerHTML in extension app code** – Heuristic: file under `webview/` or `preview/` (not under `dependencies/`) and contains both `.innerHTML` (or equivalent) and receipt of markdown/HTML from message or doc. Could elevate severity or add a “preview XSS” category.
- **localhost / 127.0.0.1 in fetch or XHR** – Already have localhost_access; consider correlating with “preview” or “webview” context for CVE-style “port scan from preview” narrative.
- **command: URI in webview or notebook** – Already have `command:` URI pattern; ensure it appears in report when present.
- **Dependency vs app path tagging** – Add a single “origin” or “path_type” field to each code finding: `app` vs `dependency` (derived from path containing `node_modules` or `dependencies/`). Enables filtering and separate scoring without changing pattern set.

---

## 3. Architecture: Dependency Vulnerability Scanning

### 3.1 Goal

- For each extension (Chrome/Edge manifest or VSCode `package.json`), **resolve dependencies** (names + versions).
- For each resolved dependency, **query one or more vulnerability sources** to see if that package@version is affected by known CVEs.
- **Flag vulnerable dependencies** in the existing supply-chain layer and optionally in the report (e.g. “Dependency CVEs” section).
- Prefer **open source or free APIs** to minimize cost and licensing.

### 3.2 Current Flow (Relevant Parts)

```
[Download/Unpack] → extension_dir
       ↓
[Layer 1] Metadata (manifest/package.json)
[Layer 1.5] Deep package.json (URLs, publisher mismatch)
[Layer 2] Supply chain: _analyze_supply_chain(extension_dir, pkg)
          - deps = pkg['dependencies'] + pkg['devDependencies']
          - SUSPICIOUS_PACKAGES, wildcard versions, typosquatting
          - node_modules size, native binaries, lifecycle scripts
          - NO CVE lookup today
       ↓
[Layer 3] Code analysis (pattern scan, correlations)
[Layer 4] Risk scoring, report generation
```

### 3.3 Proposed Addition: Dependency CVE Scan

Insert a **Dependency CVE Scan** step that runs after we have `pkg` (and optionally a resolved dependency tree) and before or as part of Layer 2. Output is merged into `supply_chain` (or a new `dependency_vulns` block) and reflected in the report.

```
[Layer 2] Supply chain
    ├── (existing) suspicious packages, wildcards, typosquatting, node_modules, scripts
    └── (new) Dependency CVE Scan
              Input:  list of (name, version) from package.json (and optionally lockfile / node_modules)
              Output: list of { package, version, vulns: [ { id, summary, severity, link } ] }
              → add to supply_chain.findings as type: 'dependency_vulnerability'
              → optionally raise supply_chain.risk_score
```

### 3.4 Open Source / Free Options for Dependency CVEs

| Tool / API | Type | Ecosystem | Auth | Integration effort | Notes |
|------------|------|------------|------|--------------------|--------|
| **OSV (osv.dev)** | REST API | npm, PyPI, Go, etc. | No | Low | POST /v1/query or /v1/querybatch with `{ "package": { "name", "ecosystem" }, "version" }`. Returns vuln IDs, summary, severity. Rate limit: none. Best first choice. |
| **Retire.js** | CLI (Node) | JS (bundled/compiled) | No | Low | Scans **bundled JS** (dist/extension.js, etc.) for vulnerable library signatures. Catches lodash, minimist, jquery, moment, serialize-javascript inside bundles. **Integrated** in Layer 2 via `retirejs_scanner.py`. Install: `npm install -g retire`. |
| **OSV-Scanner** | CLI / Go lib | Multi | No | Medium | Wraps OSV; can run as subprocess on extension dir and parse JSON output; or use OSV API directly from Python. |
| **npm audit** | CLI | npm only | No | Low | Run `npm audit --json` in a dir with package.json (and optionally node_modules); parse JSON. No API key. Good for npm-only. |
| **Sonatype OSS Index** | REST API | npm, Maven, etc. | Yes (free tier) | Medium | AuditJS uses it; need to register for API token. Good if you want a second source. |
| **OWASP Dependency-Check** | CLI / Java | Multi (CPE-based) | No | Medium–High | Subprocess; outputs JSON/HTML. Heavier (NVD DB); good for offline or air-gapped. |
| **Snyk** | API / CLI | Multi | Yes (free tier) | Medium | Strong data; requires Snyk account and token for API. |

**Recommendation:** Start with **OSV API** from Python (no CLI dependency, no auth, supports npm and others). Optionally add **npm audit** for npm-only extensions to get ecosystem-specific advice (fix available, etc.). Add OSS Index or Snyk later if you need a second source or Snyk’s fix data.

### 3.5 High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Chrome / VSCode Extension Security Analyzer                 │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────────────────┐
  │  Download /  │───▶│  Unpack      │───▶│  Layer 1: Metadata & package.json    │
  │  Fetch VSIX  │    │  extension   │    │  (existing)                          │
  └──────────────┘    └──────────────┘    └──────────────────────────────────────┘
                                                     │
                                                     ▼
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │  Layer 2: Supply Chain                                                         │
  │  ┌─────────────────────────────────┐   ┌─────────────────────────────────────┐ │
  │  │  Existing                       │   │  NEW: Dependency CVE Scan             │ │
  │  │  - Suspicious packages          │   │  - Input: deps from package.json    │ │
  │  │  - Wildcard versions           │   │  - Resolve versions (lockfile/installed)│ │
  │  │  - Typosquatting               │   │  - Query OSV API (batch)              │ │
  │  │  - node_modules size/native     │   │  - Optional: npm audit (npm only)     │ │
  │  │  - Lifecycle scripts           │   │  - Output: supply_chain.dependency_  │ │
  │  │                                 │   │    vulns[] + findings[]              │ │
  │  └─────────────────────────────────┘   └─────────────────────────────────────┘ │
  └──────────────────────────────────────────────────────────────────────────────┘
                                                     │
                                                     ▼
  ┌──────────────────────────────────────┐    ┌──────────────────────────────────┐
  │  Layer 3: Code analysis (existing)   │    │  Layer 4: Risk & report (existing)│
  │  + optional: path_type = app/dep     │    │  + dependency vulns in report     │
  └──────────────────────────────────────┘    └──────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────┐
  │  External (open source / free)                                                │
  │  - OSV API (api.osv.dev) – primary CVE source                                 │
  │  - npm audit (CLI) – optional, npm only                                        │
  │  - OSS Index / Snyk – optional second source                                   │
  └─────────────────────────────────────────────────────────────────────────────┘
```

### 3.6 Component Design: Dependency CVE Scanner

- **Module name (suggestion):** `dependency_vuln_scanner.py` (or under `src/`).
- **Inputs:**  
  - `pkg`: parsed `package.json` (dependencies + devDependencies).  
  - Optionally: `extension_dir` to read `package-lock.json` / `yarn.lock` / `node_modules/<pkg>/package.json` for resolved versions.
- **Version resolution:**  
  - If lockfile present, use resolved version for each dependency.  
  - Else use version from package.json as-is (may be range; OSV can accept and often still match).
- **OSV batch query:**  
  - Build list of `{ "package": { "name": "<name>", "ecosystem": "npm" }, "version": "<version>" }`.  
  - POST to `https://api.osv.dev/v1/querybatch`.  
  - Parse response; for each package with `vulns`, add to results.
- **Output shape (merge into supply_chain):**

  ```python
  supply_chain['dependency_vulns'] = [
      {
          'package': 'lodash',
          'version': '4.17.15',
          'vulns': [
              { 'id': 'GHSA-xxx', 'summary': '...', 'severity': 'HIGH', 'link': '...' }
          ]
      }
  ]
  # And for each vuln, append to supply_chain['findings']:
  # { 'type': 'dependency_vulnerability', 'severity': '...', 'package': '...', 'cve': '...', ... }
  ```

- **Risk scoring:** Add to Layer 2 risk when `dependency_vulns` has critical/high entries (e.g. +1 per critical, +0.5 per high, cap at 2–3).

### 3.7 VSCode vs Chrome Extensions

- **VSCode:** Use `package.json`; ecosystem is npm. OSV + optional npm audit fit.
- **Chrome/Edge:** Often no `package.json`; dependencies are bundled. Options: (1) Skip dependency CVE scan for Chrome; (2) If a manifest or build hints at npm, try to find a lockfile in repo or accept “no deps”; (3) Future: extract package names from bundled JS (heuristic) and query OSV without version (less accurate). Recommendation: implement for VSCode first; Chrome can be “not supported” or best-effort later.

### 3.8 Report Changes (When Implemented)

- **Supply chain section:** Add subsection “Dependency vulnerabilities” listing package@version and CVE IDs with links.
- **Executive summary / BLUF:** If any dependency vuln is critical/high, add one line: “N dependency vulnerability(ies) detected (see Supply Chain).”
- **JSON report:** Include `supply_chain.dependency_vulns` and findings with `type: 'dependency_vulnerability'` so downstream tools can consume them.

---

## 4. Implementation Order (Suggested)

1. **OSV client** – Small Python helper: `query_osv_batch(package_version_list) -> list[dict]`. Unit test with a known vulnerable package.
2. **Version resolution** – From `package.json` + optional `package-lock.json` (or yarn.lock), produce list of `(name, version)`.
3. **Integration in VSCode analyzer** – After `_analyze_supply_chain`, call the new scanner, merge `dependency_vulns` and findings, adjust risk score.
4. **Report** – Add dependency vuln block to HTML and JSON (professional_report + VSCode report path).
5. **Pattern refinements** – Tighten command_injection (exec) and optionally add path_type (app vs dependency) for code findings.
6. **(Optional)** npm audit subprocess for npm extensions; OSS Index as second source.

---

## 5. References

- OSV API: https://google.github.io/osv.dev/api/  
- OSV query batch: https://google.github.io/osv.dev/post-v1-querybatch/  
- OSV-Scanner: https://google.github.io/osv-scanner/  
- Sonatype OSS Index: https://ossindex.sonatype.org/  
- OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/  
- npm audit: https://docs.npmjs.com/cli/v8/commands/npm-audit  
