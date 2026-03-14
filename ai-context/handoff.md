# Handoff Document

## Last Session Summary
**Date:** 2026-02-22
**Session Focus:** Extension Risk Intelligence Platform — Phase 1 MVP API

### What was accomplished (2026-02-22 — V12 API Platform)

1. **Full REST API** (`api/` package — 12 new files)
   - FastAPI app at `api/main.py` with CORS, lifespan (auto-create tables), health checks
   - `POST /api/v1/analyze` — queue scan job (Chrome/Edge/VSCode), cache check, duplicate detection
   - `GET /api/v1/jobs/{id}` — poll job status + progress
   - `POST /api/v1/jobs/{id}/cancel` — cancel running/queued jobs
   - `GET /api/v1/reports/{id}` — JSON summary, `GET .../html` — HTML report, `GET .../full` — complete JSON
   - `GET /api/v1/extensions/{id}` — latest scan, `GET .../history` — all scans

2. **PostgreSQL database** (`api/models.py`)
   - `Extension` — tracked extensions with version hash for caching
   - `ScanJob` — async jobs with status/progress tracking
   - `ScanResult` — completed results with summary metrics (risk, vulns, domains, critical findings)

3. **Redis + RQ worker** (`api/worker.py`)
   - Dequeues jobs, dispatches to correct analyzer method (VSCode vs Chrome/Edge)
   - Progress callback updates DB every 2 seconds
   - Cancellation support: checks job status before each progress update
   - Version caching: SHA-256 of manifest → skip re-scan if unchanged

4. **Auth + rate limiting** (`api/auth.py`)
   - X-API-Key header authentication
   - Sliding-window rate limiter (60 req/min default)
   - Dev mode: no keys configured = allow all

5. **Docker deployment** (`docker-compose.yml`, `Dockerfile`)
   - PostgreSQL 16, Redis 7, API server, 2 worker replicas
   - Health checks, volume mounts for reports + source (dev mode)
   - `.env.example` for environment variables

6. **Alembic migrations** (`alembic/`)
   - Configured env.py with model imports, DATABASE_URL from env

7. **Dependencies** — Added psycopg2-binary, alembic, redis, rq to requirements.txt

### Key Files Created (2026-02-22 — V12)

| File | Action | Description |
|------|--------|-------------|
| `api/__init__.py` | NEW | API package |
| `api/config.py` | NEW | Environment config |
| `api/database.py` | NEW | SQLAlchemy engine + sessions |
| `api/models.py` | NEW | ORM models (Extension, ScanJob, ScanResult) |
| `api/schemas.py` | NEW | Pydantic request/response schemas |
| `api/auth.py` | NEW | API key auth + rate limiting |
| `api/main.py` | NEW | FastAPI app |
| `api/worker.py` | NEW | RQ worker |
| `api/routes/analyze.py` | NEW | /analyze, /jobs endpoints |
| `api/routes/reports.py` | NEW | /reports endpoints |
| `api/routes/extensions.py` | NEW | /extensions endpoints |
| `docker-compose.yml` | NEW | Docker services |
| `Dockerfile` | NEW | Container build |
| `alembic.ini` + `alembic/` | NEW | DB migrations |
| `.env.example` | NEW | Env template |
| `requirements.txt` | MODIFIED | +psycopg2-binary, alembic, redis, rq |

---

### Previous Session (2026-02-21 — V11 Report Quality + Vuln Enrichment)
**Session Focus:** Report quality overhaul (12-fix plan), vulnerability data enrichment (OSV + Retire.js), performance fixes, CLAUDE.md code quality rules

### What was accomplished (2026-02-21 — V11 Report Quality + Vuln Enrichment)

1. **12-fix report quality plan** (from senior threat analyst review of Markdown Preview Enhanced report)
   - **Scanner fixes** (`vscode_analyzer.py`): Dependency noise suppression (Rule 7), base64 hex FP fix, eval() method FP fix, CDN allowlist expansion (~30 domains), %displayName% NLS resolution, CVE-2025-65716 risk_context + mitigation_note, benign lifecycle scripts (husky).
   - **Report fixes** (`professional_report.py`): BLUF rewrite (app-only counts, specific text), app vs dependency visual separation (collapsed `<details>` for deps), evidence explanations (FINDING_EXPLANATIONS dict, 15 categories), unverified publisher suppression for high-install, devDependency BUILD-TIME ONLY badge.

2. **Vulnerability data enrichment**
   - **OSV** (`dependency_vuln_scanner.py`): Added `_enrich_vulns()` — calls `GET /v1/vulns/{id}` per vuln. Extracts summary, severity (from `database_specific.severity`), CVSS vector, CWE IDs, fix version, aliases. Graceful fallback.
   - **Retire.js** (`retirejs_scanner.py`): Extracts `below` → fix_version, `identifiers.summary` → summary, all CVE aliases, `atOrAbove` → affected_from.
   - **Report** (`professional_report.py`): Both sections now show severity badges, summary text, fix version guidance, CWE IDs, alias IDs, additional advisory URLs. BLUF shows severity breakdown.

3. **Performance fixes** (`vscode_analyzer.py`): O(n) line-number computation replaced with bisect binary search. Widened skip heuristic (500KB threshold, vendor/chunk/polyfill patterns, >2MB unconditional skip).

4. **CLAUDE.md code quality rules**: Added learned-from-mistakes section covering external API data extraction, report accuracy/presentation, false positive prevention, performance.

### Key Files Modified (2026-02-21 — V11)

| File | Action | Description |
|------|--------|-------------|
| `src/vscode_analyzer.py` | MODIFIED | 7 scanner fixes + performance (bisect line index, skip heuristic) |
| `src/professional_report.py` | MODIFIED | 5 report fixes + enriched vuln rendering + FINDING_EXPLANATIONS |
| `src/dependency_vuln_scanner.py` | MODIFIED | OSV `/v1/vulns/{id}` enrichment, dep_type tracking, enriched findings |
| `src/retirejs_scanner.py` | MODIFIED | Extract fix_version, summary, aliases, affected_from |
| `CLAUDE.md` | MODIFIED | Code quality rules (API extraction, report accuracy, FP prevention, performance) |

---

### Previous Session (2026-02-19 — V10 Dependency Scan + Risk/BLUF + Patterns)

1. **Dependency vulnerability scan (VSCode)**
   - New `src/dependency_vuln_scanner.py`: `resolve_versions()` from package.json + package-lock.json/yarn.lock; `query_osv_batch()` to OSV API; `scan_dependencies()` returns `dependency_vulns`, findings, `risk_delta`.
   - Wired into `vscode_analyzer._analyze_supply_chain()`: calls scanner, merges findings and `dependency_vulns`, adds `risk_delta` to supply risk.
   - Report: Supply Chain "Dependency vulnerabilities" block (package@version + CVE links); executive key-finding; JSON `supply_chain.dependency_vulns`. Tested with `tomphilbin.lodash-snippets` (lodash@4.17.4, 8 GHSA).

2. **Risk score and BLUF when dependency vulns present**
   - `_calculate_risk_score()`: when `dependency_vulns` non-empty, supply component floor 1.0; +0.5 if ≥5 vulns or ≥2 packages; if level would be MINIMAL, set to LOW or MEDIUM (≥5 vulns or ≥2 packages → MEDIUM).
   - `professional_report._generate_executive_summary()`: early `supply`/`dependency_vulns`; new BLUF branch: *"N dependency vulnerability(ies) in M package(s) detected in supply chain. Upgrade affected packages or conduct security review before use."*

3. **Detection pattern refinements (FP reduction)**
   - Command injection: pattern only `child_process.exec(` (no bare `exec` → avoids regex `.exec()` FP).
   - App vs dependency: `_is_dependency_path()`, `path_type` on findings; webview_risk in dependency suppressed or medium; innerHTML in dependency suppressed in filter.
   - Plaintext HTTP: skip when evidence contains w3.org/schemas/xmlns etc. (`HTTP_NAMESPACE_URL_INDICATORS`).
   - OAuth/identity: tightened to explicit auth tokens; bare `.token` removed to avoid parser-token FP.

4. **Documentation**
   - `docs/ARCHITECTURE_DEPENDENCY_SCANNING_AND_PATTERNS.md` — dependency scan architecture, OSV/npm options, pattern notes.
   - `docs/BABLU_DETECTION_LIBRARY_REVIEW.md` — Bablu review: coverage, gaps vs CVEs, missing patterns (preview XSS, unauthenticated server, webhook exfil, port-scan-from-preview), implementation order.

5. **ai-context**
   - `ai-context/STATUS.md` updated with V10 section (dependency scan, risk/BLUF, pattern refinements, docs); Architecture table and How to Run include VSCode + dependency scanner.

---

### Previous Session (2026-02-18 — V9 VSCode Extension CVE & Pattern Coverage)

1. **CVE-aware VSCode extension identification**
   - Added a `KNOWN_VULNERABLE_EXTENSIONS` map in `src/vscode_analyzer.py` keyed by VSCode extension identifier (`publisher.name`).
   - Currently covers:
     - `ritwickdey.LiveServer` (CVE-2025-65717, localhost dev-server file exfiltration; OX research).
     - `formulahendry.code-runner` (CVE-2025-65715, settings-driven RCE via `child_process.spawn(..., { shell: true })`).
     - `shd101wyy.markdown-preview-enhanced` (CVE-2025-65716, Markdown → webview JS → localhost port scanning / exfil).
     - `vsciot-vscode.vscode-arduino` (CVE-2024-43488, Arduino extension remote RCE).
     - `ms-vscode.live-server` and `MS-SarifVSCode.sarif-viewer` (Trail of Bits Live Preview/SARIF webview escape & file exfil class).
   - `_analyze_metadata()` now emits a `known_vulnerable_extension` metadata finding (with CVE + reference URL) and bumps metadata risk to at least 8/10 when identifiers match.

2. **Generic detection patterns for IDE-style vulnerabilities**
   - **Localhost access:** Added a `localhost_access` HTTP pattern to flag any `https?://localhost|127.0.0.1|0.0.0.0` usage from extension code; meant to correlate with workspace harvesting + base64 exfil to detect Live Server / Markdown Preview Enhanced / Live Preview style behaviors.
   - **Code Runner settings RCE:** Added a focused pattern in `VSCODE_API_ABUSE_PATTERNS` that detects calls to `getConfiguration('code-runner').update('executorMap', ...)`, covering the Code Runner CVE scenario where executorMap is weaponized.
   - **Command URIs:** Added:
     - A JS/TS pattern for string literals starting with `command:` (used by notebooks/webviews to trigger commands).
     - An HTML/webview pattern in `vscode_html_analyzer.py` for `href="command:..."` links, which is the root of several command-URI RCEs.

3. **Reporting**
   - Existing VSCode report sections in `professional_report.py` now surface these new metadata and code findings clearly under “Metadata Risk Signals” and “Deep Code Analysis & Behavioral Profiling”.
   - Combined with prior workspace harvesting / base64 exfil / webview XSS patterns, this gives good coverage for 2022–2025 VSCode extension CVEs and research (OX Security, Trail of Bits).

---

### Previous Session (2026-02-16 — V8 IOC Enrichment)

1. **Merged external campaign IOCs into single global DB**
   - Parsed `reports/detection_ioc.txt` (LayerX, Koi, GitLab Threat Intel, Sekoia, Hunters Axon, ExtensionTotal, Cyberhaven, Unit 42, Malwarebytes, etc.) as a campaigns JSON and merged indicators into the root `iocs.json`.
   - Added campaign `c2_domains`, `phishing_domains`, and squatting domains (`additional_iocs.squatting_domains`) as MALICIOUS domains in `iocs.json["domains"]` with neutral reputation and no VT metadata (intel-only).
   - Added all **Chrome** extension IDs from each campaign into `iocs.json["extensions"]` with `risk_score: 10.0` so they are treated as confirmed malicious/supply-chain-risk when encountered in scans.
   - Removed the legacy `src/iocs.json` so there is **one IOC source of truth**; `IOCManager` now reads only the root `iocs.json`.

2. **Added IOC merge helper script**
   - New file: `scripts/merge_detection_ioc.py`.
   - Normalizes curly-quote JSON from `reports/detection_ioc.txt`, parses the `campaigns` structure, and idempotently merges new domains and Chrome extension IDs into `iocs.json`.
   - Operates offline only (no URL fetching, no VT lookups); safe to re-run when `detection_ioc.txt` is updated with new campaigns.

3. **Updated AI context documentation**
   - `ai-context/STATUS.md` updated to describe V8 IOC enrichment, new domain/extension counts, and the single-DB architecture.
   - This handoff file updated to reflect latest work and to clarify that any future IOC intel should be funneled through `iocs.json` + the merge script.

4. **IOC-aware risk floors wired into analysis**
   - `src/analyzer.py`: after all scoring and OSINT/attribution floors, we now:
     - Raise any extension whose ID appears in `iocs.json` to **at least 7.0 risk** (HIGH), and to **≥9.0** if it was already ≥5.0.
     - Raise any extension whose VT domains intersect IOC DB domains to **at least 7.0 risk**.
   - These run alongside existing VT file-hash logic (MALICIOUS hash → floor 8.0 + critical finding), so IOC DB + VT now act as strong final risk floors.

---

## Previous Session (2026-02-16 — Post-V6)
**Session Focus:** Report quality (snippet caps, dedup), first-party → LOW, example.com benign, VT runtime filter

### What was accomplished
- **Code snippet caps**: static_analyzer truncates context lines to 350 chars, `context_with_lines` capped at 4000 chars; professional_report limits snippets to 15 lines and 250–280 chars/line.
- **Deduplication**: Findings deduped by (name, file, line); _MAX_PER_NAME = 2; added Web Crypto API Usage and High Entropy String to _CONTEXTUAL_CAP_PATTERNS.
- **First-party → LOW**: Trusted publisher extensions always get LOW risk (final_score capped at 3.5 when is_trusted_publisher).
- **example.com benign**: RFC 2606 domains in false_positive_filter, report_validator, static_analyzer FIRST_PARTY_DOMAINS, virustotal_checker; is_benign_domain null/empty guard.
- **VT runtime**: filter_virustotal_results() applied to new_domains from dynamic analysis; update_risk_with_virustotal uses full vt_results.
- **EXFIL-006**: CSRF cookie rule ID fixed (was duplicate EXFIL-002).
- **README**: chromewebstore.google.com URL, detection library, first-party/listing docs.

---

## Previous Session (2026-02-15)
**Session Focus:** V6 — Store metadata, first-party, detection library, VK Styles, generic wording

### What was accomplished (2026-02-15 — V6)

1. **File Hash VT Integration**
   - Added `check_file_hash()` and `check_multiple_file_hashes()` to `virustotal_checker.py` — calls VT `GET /files/{hash}`, caches with `file:` prefix, respects rate limiting.
   - Added `_compute_file_hashes()` to `static_analyzer.py` — SHA-256 of manifest.json, manifest.js (if present), background scripts (service worker / MV2 scripts), and content scripts. Popup/web-accessible resources excluded (not payloads, wastes API calls).
   - Wired into `analyzer.py` — after domain VT check, runs file hash VT check. Any MALICIOUS result → critical finding + risk floor 8.0.
   - Added "File Hash IOCs (SHA-256)" section to `professional_report.py` IOC block with MALICIOUS/SUSPICIOUS/CLEAN/NOT IN VT badges and VT links.

2. **Domain Extraction False Positive Fix**
   - Root cause: `_QUOTED_FQDN_PATTERN` matched JS identifiers like `Permissions.PermissionsAdded`, `InternalAnalytics.TrackEvent` because they look like `word.word` with TLD-length suffix.
   - Fix: Rewrote `_is_plausible_host()` in `static_analyzer.py` to reject CamelCase strings (`[A-Z][a-z]+[A-Z]`), known API namespace prefixes (30+), and strings whose last label is not in a curated valid TLD set (~140 TLDs). Also requires at least one dot (no single-label strings).
   - Added parallel `_is_real_domain()` gate in `analyzer.py` `_check_virustotal()` so even if junk leaks through `urls_in_code`, it never reaches VT API.

3. **JS Scan Scope Optimization**
   - `_prioritize_js_files_for_security()` rewritten: now only scans manifest-referenced files (background, content scripts, service worker) + high-value attacker filenames (`inject.js`, `helper.js`, `payload.js`, `stealer.js`, `find-password.js`, `manifest.js`, etc.).
   - Bundled libraries, polyfills, and framework code are skipped entirely. Makes analysis faster and cleaner.

4. **Unified Top 5 Domains in IOC Section**
   - Replaced 3 separate domain blocks (Malicious Domains, Exfil Destinations, Domains in Code/Manifest) with one "Top Domains (sorted by threat score)" block.
   - Collects from all sources (VT results, AST exfil, code URLs, manifest URLs) into unified map.
   - Sorts by malicious vendor count (primary) + community negative votes (secondary), shows top 5 with color-coded badges, source tags, VT links.

5. **Report Validator ("Bablu Review")**
   - New `src/report_validator.py` — automated post-analysis validation that reads analysis JSON + actual extension source code and classifies every finding.
   - 12+ FP check categories: webpack globalThis polyfill, reflect-metadata keystroke arrays, chrome.storage.sync settings, idb library IndexedDB, credit card targeting, prototype references, localStorage/tab.url low-severity, domains from comments, filter rule .txt files, VT 1-vendor noise, behavioral chain FP propagation.
   - CLI: `python report_validator.py --count 10 --json report.json`
   - Tested on 10 extensions: 38.4% overall FP rate, attributed malware TP rate 1.4%.

6. **FP Analysis of Urban AdBlocker report**
   - Conducted thorough manual review of `feflcgofneboehfdeebcfglbodaceghj` (Urban AdBlocker) report.
   - 7 specific findings cross-referenced with actual source: ALL 7 were false positives (webpack polyfills, library code, domains from code comments and filter rules, 1-vendor VT detections).
   - This analysis drove the design of the automated validation engine.

7. **V6 — Store metadata, first-party, detection library**
   - Chrome Web Store: fetch from chromewebstore.google.com; parse author, version, users, featured, trader (new store layout).
   - Trusted publisher list + first-party badge; positive_reduction cap 2.5 for trusted; malice floor when crit_count ≥ 1.
   - `data/known_malicious_extensions.json`: VK Styles campaign (5 IDs). `data/detection_artefacts.json`: standard artefacts per campaign.
   - New patterns: meta-tag C2, computed R-A- ID, remixsec/CSRF cookie. Generic attribution wording ("Security research").

---

## Previous Session (2026-02-14)
**Session Focus:** V4 — Slice safety, fallback scan, scan coverage, threat intel canonical, sinkhole/rule-engine validation, test extension, infrastructure score

### What was accomplished (2026-02-14)
- Slice safety & fallback: `_safe_slice`/`_safe_int`; on `scan_code()` failure -> `_scan_code_minimal()`; `scan_coverage` in results and report.
- Threat intel: Canonical reference for DarkSpectre; `_normalize_source_articles()` filters awesome-BrowserRelated, puts canonical first.
- Sinkhole detection: `_detect_sinkhole_and_infra_signals()`; when all C2/exfil localhost -> sinkhole_or_lab_c2, report "Sinkhole C2 -- Rule Engine Validation".
- Infrastructure score: exfil_endpoint_count, has_websocket_c2, has_beaconing -> Component 4.
- Test extension: `test_fixtures/malicious_test_extension/` (sinkhole only). --local CLI; reports to repo root.
- Cookie replay detection: `Fetch with credentials include (cookie replay)` pattern.
- C2 domain gap fix: `_extract_urls_and_hosts_from_code()` + manifest URL extraction for infrastructure detection.
- Web UI fixes: Recent scans limited to 5, "View Full Report" link fix.

## Previous Session (2026-02-13)
V3 Enhancement Sprint — regex safety, taint guard, VT threshold, Remote C2, sensitive targets, attack narrative, campaign fingerprint, report sections.

## Previous Session (2026-02-12)
Static analysis robustness — large file hang fix, progress bar, AST caps.

## Previous Session (2026-02-09)
V2 Enhancement — behavioral engine, permission attack paths, CSP analysis, risk scoring V2, dynamic analysis (Playwright/CDP), version diff.

---

## Pending Tasks (Priority Order)

### 1. Wire IOC DB more deeply into analysis (HIGH)
- Use the enriched `iocs.json` during analysis to:
  - Flag extensions whose IDs appear in the IOC DB as **CONFIRMED malicious/supply-chain-risk** regardless of heuristic score.
  - Surface campaign names / actor notes (from `detection_ioc.txt` / threat attribution) in the professional report when a match is found.

### 2. Implement FP fixes in detection engine (HIGH)
The validator identified specific FP categories. These patterns in `static_analyzer.py` still need tightening:
- Keystroke Buffer Array: require nearby `addEventListener('keydown')`.
- Dynamic Function: whitelist `new Function('return this')` webpack polyfill.
- Chrome Storage Sync: only flag when paired with sensitive data sources.
- IndexedDB: only flag when paired with sensitive data access.
- Domain extraction: strip comments before regex, skip `.txt` filter files.
- VT 1-vendor: don't penalize at all (or only +0.1).

### 3. End-to-end test V5/V8 pipeline (HIGH)
- Re-run Urban AdBlocker and other known cases to verify FP fixes and that IOC DB matches show up clearly in risk scores and report narratives.

### 4. Regression test benign extensions (MEDIUM)
- Bitwarden, uBlock Origin, React DevTools — verify LOW/MINIMAL scores and ensure new IOC enrichment doesn’t introduce regressions.

### 5. Test dynamic analysis (MEDIUM)
- `--dynamic` with API mocking and canary tokens.

### 6. Clean up debug instrumentation (LOW)
- Remove `# #region agent log` blocks from `ast_analyzer.py` and `static_analyzer.py`.

---

## Key Files Modified/Created (2026-02-19 — V10)

| File | Action | Description |
|------|--------|-------------|
| `src/dependency_vuln_scanner.py` | NEW | OSV API batch query, version resolution (package.json + lockfile), scan_dependencies() |
| `src/vscode_analyzer.py` | MODIFIED | Supply chain calls scanner; _calculate_risk_score() dependency vuln floor + level bump; pattern refinements (exec, path_type, HTTP namespace, OAuth) |
| `src/professional_report.py` | MODIFIED | BLUF branch for dependency_vulns; Supply Chain "Dependency vulnerabilities" block; early supply/dependency_vulns in executive summary |
| `src/analyzer.py` | MODIFIED | Layer 2 print includes [DEPENDENCY CVE] when dependency_vulns present |
| `docs/ARCHITECTURE_DEPENDENCY_SCANNING_AND_PATTERNS.md` | NEW | Dependency scan architecture, OSV/npm options, pattern notes |
| `docs/BABLU_DETECTION_LIBRARY_REVIEW.md` | NEW | Bablu detection library review, gaps vs CVEs, missing patterns |
| `ai-context/STATUS.md` | MODIFIED | V10 section, Architecture table, How to Run (VSCode) |

## Key Files Modified/Created (2026-02-16 — V7 Hardening)

| File | Action | Description |
|------|--------|-------------|
| `src/static_analyzer.py` | MODIFIED | Expanded `trusted_publishers` (26→75), `FIRST_PARTY_DOMAINS` (34→70), supply chain safety fix |
| `src/false_positive_filter.py` | MODIFIED | Expanded `BENIGN_DOMAINS` (43→75) |
| `src/store_metadata.py` | MODIFIED | `_detect_verified_badge()` with 4 strategies, developer info extraction from embedded array |
| `src/threat_attribution.py` | MODIFIED | `_search_unit42_repo()` Unit42 GitHub IOC search |

## Key Files Modified/Created (2026-02-15 — V5/V6)

| File | Action | Description |
|------|--------|-------------|
| `src/virustotal_checker.py` | MODIFIED | `check_file_hash()`, `check_multiple_file_hashes()` for VT file hash lookup |
| `src/static_analyzer.py` | MODIFIED | `_compute_file_hashes()`, `_is_plausible_host()`, manifest-only JS scan; trusted publisher, malice floor, VK Styles patterns |
| `src/analyzer.py` | MODIFIED | File hash VT wiring + critical floor, `_is_real_domain()` domain gate |
| `src/professional_report.py` | MODIFIED | File Hash IOC section, unified Top 5 Domains; First-party badge, Listing details |
| `src/report_validator.py` | NEW | Automated "Bablu Review" validation engine |
| `src/store_metadata.py` | MODIFIED | chromewebstore.google.com, new store parsing, featured/trader |
| `src/threat_attribution.py` | MODIFIED | Generic "Security research" labels; VK Styles keywords |
| `src/detection_rules.json` | MODIFIED | INJECT-003, OBF-007, EXFIL-006 (CSRF); EXFIL-002 = History Exfil; INJECT-002 window 500 |
| `data/known_malicious_extensions.json` | NEW | VK Styles campaign (5 extension IDs) |
| `data/detection_artefacts.json` | NEW | Standard detection artefacts per campaign |
| `docs/DETECTION_LIBRARY.md` | NEW | Standard detection library layout |
| `.gitignore` | MODIFIED | Allow data/ detection library files; ignore caches/generated dirs |
