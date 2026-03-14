# Chrome Extension Security Analyzer - Current Status

**Last Updated:** 2026-02-22

## Current State Summary

The tool performs end-to-end security analysis of Chrome and VSCode extensions: download, unpack, static analysis (AST + pattern scan), domain intel, VirusTotal (domains + file hashes), advanced/enhanced detection, behavioral correlation, PII classification, threat attribution (OSINT + Unit42), and professional HTML/JSON reports. A web UI runs analysis in the background with a progress bar and cancel support. An automated **report validator** ("Bablu Review") cross-references findings with actual extension source code to identify false positives. **Detection library:** known malicious campaigns and artefacts live in `data/known_malicious_extensions.json` and `data/detection_artefacts.json` (campaigns identified in open web search by researchers). Attribution and sources use generic labels (e.g. "Security research"). **Trusted publisher system:** ~75 known publishers get LOW risk cap (3.5) with supply chain safety (cap skipped when critical findings exist). **Verified badge:** Detects Chrome Web Store verified developer badge from embedded data arrays. **API Platform (V12):** Full REST API at `api/` package — FastAPI with PostgreSQL + Redis + RQ job queue, API key auth, version caching, Docker deployment. Supports all 3 extension types (Chrome/Edge/VSCode) via structured endpoints.

---

## Recent Changes & Fixes (V12 — 2026-02-22 Extension Risk Intelligence Platform — Phase 1 MVP)

### API Platform Architecture
Converted the CLI-only tool into a full API-driven platform. New `api/` package with:
- **FastAPI REST API** (`api/main.py`): Versioned endpoints at `/api/v1/`. Health check, CORS, auto-table creation on startup.
- **Database models** (`api/models.py`): PostgreSQL via SQLAlchemy — `extensions` (tracked extensions), `scan_jobs` (async job queue with progress), `scan_results` (completed results with summary metrics).
- **API routes**: `POST /api/v1/analyze` (queue scan), `GET /api/v1/jobs/{id}` (poll progress), `GET /api/v1/reports/{id}` (JSON summary), `GET /api/v1/reports/{id}/html` (HTML report), `GET /api/v1/extensions/{id}` (latest report), `GET /api/v1/extensions/{id}/history` (version history).
- **Auth** (`api/auth.py`): X-API-Key header, rate limiting (60 req/min default), dev mode (no keys = allow all).
- **Worker** (`api/worker.py`): RQ job processor — dequeues from Redis, runs analyzer, stores result in DB, updates extension record. Dispatches to `analyze_vscode_extension()` for VSCode, `analyze_extension()` for Chrome/Edge.
- **Version caching**: SHA-256 hash of manifest/package.json. If same hash already scanned, returns cached result instantly.
- **Docker setup**: `docker-compose.yml` with PostgreSQL 16, Redis 7, API server, 2 worker replicas. `Dockerfile` with Python 3.12 + Node.js 20 (for Retire.js).
- **Alembic**: Database migration framework configured (`alembic/env.py`, `alembic.ini`).
- **Dependencies**: Added `psycopg2-binary`, `alembic`, `redis`, `rq` to requirements.txt.

---

## Recent Changes & Fixes (V11 — 2026-02-21 Report Quality, FP Suppression, Vuln Data Enrichment)

### Report Quality & False Positive Fixes (12-fix plan)
Fixes applied to `vscode_analyzer.py`, `professional_report.py`, `dependency_vuln_scanner.py`, `retirejs_scanner.py` based on a senior threat analyst review of the Markdown Preview Enhanced report.

**Scanner fixes (`vscode_analyzer.py`):**
- **Dependency noise suppression**: Rule 7 in `_filter_vscode_false_positives()` downgrades dependency-path findings (critical→low, medium→info). Findings tagged `dependency_suppressed: true` with `original_severity`.
- **Base64 hex validation**: Post-match check skips hex-only strings (color palettes) — `_post_validate: 'base64_not_hex'`.
- **eval() FP fix**: Negative lookbehind `(?<!\.)` excludes `.eval()` method calls (Vega.js, etc.).
- **CDN allowlist**: `infra_domains` expanded to ~30 entries (jsdelivr, cdnjs, unpkg, npmjs.com, w3.org, kroki.io, plantuml.com, localhost, etc.).
- **%displayName% NLS resolution**: `_resolve_nls()` resolves `%placeholder%` from `package.nls.json`.
- **CVE-2025-65716**: Added `risk_context: 'localhost_exposure'` and `mitigation_note` for calibrated BLUF.
- **Benign lifecycle scripts**: `husky install` and similar benign scripts downgraded to `info`.

**Report fixes (`professional_report.py`):**
- **BLUF rewrite**: Counts only app-code findings in headline; specific text replaces generic "suspicious behaviors detected".
- **App vs dependency separation**: Threat Analysis splits app findings (shown normally) from dependency findings (collapsed `<details>` section grouped by category). Deep Code Analysis header shows "Critical (App Code)" counts.
- **Evidence explanations**: `FINDING_EXPLANATIONS` dict (15 categories) renders "Why This Matters" block under each finding. Dependency findings auto-annotated with library source note.
- **Unverified publisher**: `⚠️ Unverified` badge suppressed when `install_count >= 1M`.
- **devDependency context**: `dep_type` field tracks runtime vs dev dependencies. BUILD-TIME ONLY badge and dimmed border for devDependency CVEs.

### Vulnerability Data Enrichment
- **OSV enrichment** (`dependency_vuln_scanner.py`): After querybatch, calls `GET /v1/vulns/{id}` for each discovered vuln. Extracts `summary`, `severity` (from `database_specific.severity`), `cvss_vector`, `cwe_ids`, `fix_version` (from `affected[].ranges[].events[{fixed}]`), `aliases`. Graceful fallback on failure.
- **Retire.js enrichment** (`retirejs_scanner.py`): Extracts `below` → `fix_version`, `identifiers.summary` → `summary`, all CVE aliases, `atOrAbove` → `affected_from`.
- **Report rendering** (`professional_report.py`): Both OSV and Retire.js sections now show severity badges (color-coded), summary text, fix version guidance ("Fix: upgrade to >= X.Y.Z"), CWE IDs, alias IDs, additional advisory URLs. BLUF and key findings show severity breakdown ("3 high, 2 medium").

### Performance Fixes (`vscode_analyzer.py`)
- **O(n) line-number fix**: Pre-built newline index + `bisect.bisect_right()` replaces `content[:offset].count('\n')`.
- **Widened skip heuristic**: 500KB threshold (was 1MB) + vendor/chunk/polyfill patterns; >2MB unconditional skip.

---

## Recent Changes & Fixes (V9 — 2026-02-18 VSCode Extension Vulnerability Patterns)

### VSCode Extension CVE & Pattern Coverage
- **New target:** The analyzer now handles **VSCode Marketplace extensions** via `--vscode` (see examples below) and applies a four-layer risk model similar to Chrome.
- **Known vulnerable VSCode extensions:** Added a `KNOWN_VULNERABLE_EXTENSIONS` registry in `vscode_analyzer.py` that flags high-profile CVE-backed extensions at metadata layer:
  - `ritwickdey.LiveServer` → CVE-2025-65717 (localhost dev-server file exfiltration) ([OX blog](https://www.ox.security/blog/cve-2025-65717-live-server-vscode-vulnerability/)).
  - `formulahendry.code-runner` → CVE-2025-65715 (settings-driven RCE via `child_process.spawn(..., { shell: true })`) ([OX blog](https://www.ox.security/blog/cve-2025-65715-code-runner-vscode-rce/)).
  - `shd101wyy.markdown-preview-enhanced` → CVE-2025-65716 (Markdown → webview JS execution + localhost port scan / exfil) ([OX blog](https://www.ox.security/blog/cve-2025-65716-markdown-preview-enhanced-vscode-vulnerability/)).
  - `vsciot-vscode.vscode-arduino` → CVE-2024-43488 (Arduino extension remote RCE, missing auth on critical functionality).
  - `ms-vscode.live-server` and `MS-SarifVSCode.sarif-viewer` → high-risk based on Trail of Bits research into Live Preview / SARIF Viewer webview escapes and file exfiltration.
- **Behavioral patterns for IDE vulns:** Extended `vscode_analyzer.py` / `vscode_html_analyzer.py` with high-fidelity regexes for IDE-style attacks:
  - **Localhost access primitives:** Detects `https?://localhost|127.0.0.1|0.0.0.0` usages from extension code as `localhost_access` so we can correlate with workspace harvesting / base64 exfil (Live Server, Markdown Preview Enhanced class).
  - **Settings-based RCE:** Detects calls that mutate `code-runner.executorMap` in VS Code configuration (weaponizing Code Runner executors for RCE).
  - **Command URI abuse:** Flags `command:` URI strings in extension code and `href="command:..."` links inside webviews/HTML (covers CVE-2022-41034-style command-URI abuse in notebooks/webviews).
- **Report impact:** These findings appear under the VSCode “Metadata Risk Signals” and “Deep Code Analysis” sections in `professional_report.py`, and they push VSCode extension risk scores into HIGH/CRITICAL ranges when present.

---

## Recent Changes & Fixes (V10 — 2026-02-19 Dependency Scan + Risk/BLUF + Pattern Refinements)

### Dependency vulnerability scan pipeline (VSCode)
- **New module:** `src/dependency_vuln_scanner.py` — resolves package versions from `package.json` and optional `package-lock.json` / `yarn.lock`, queries **OSV API** (`POST /v1/querybatch`) for npm ecosystem, returns `dependency_vulns` and supply-chain findings.
- **Integration:** `vscode_analyzer._analyze_supply_chain()` calls `scan_dependencies()`; merges `dependency_vulns` and `findings` (type `dependency_vulnerability`), adds `risk_delta` to supply chain risk.
- **Report:** Supply Chain section shows "Dependency vulnerabilities" block (package@version + CVE links); executive summary key-finding "N dependency vulnerability(ies) in M package(s)"; JSON has `supply_chain.dependency_vulns`.
- **Test extension:** `tomphilbin.lodash-snippets` (lodash@4.17.4, 8 GHSA vulns) validates the pipeline.

### Risk score and BLUF when dependency vulns present
- **Risk bump:** In `_calculate_risk_score()`, when `supply_chain.dependency_vulns` is non-empty: supply chain component gets a **floor of 1.0**; if vuln count ≥5 or affected packages ≥2, an extra +0.5 is added (capped at 2.0). Prevents "0.0/10 MINIMAL" when extensions have known CVEs in deps.
- **Level bump:** If computed level would be MINIMAL but dependency vulns exist, level is set to **LOW** (any vulns) or **MEDIUM** (≥5 vulns or ≥2 packages).
- **BLUF:** In `professional_report._generate_executive_summary()`, a dedicated branch when `dependency_vulns` is present: *"N dependency vulnerability(ies) in M package(s) detected in supply chain. Upgrade affected packages or conduct security review before use."*

### Detection pattern refinements (FP reduction)
- **Command injection:** First pattern now matches only `child_process.exec(` (removed bare `exec`), avoiding false positives on regex `.exec()` in minified code.
- **App vs dependency path:** `_is_dependency_path()`, `path_type` on every finding; webview_risk in dependency code suppressed or downgraded; "Webview innerHTML" in dependency paths suppressed in `_filter_vscode_false_positives`.
- **Plaintext HTTP:** Matches on XML/HTML namespace URLs (w3.org, schemas, xmlns, etc.) are skipped via `HTTP_NAMESPACE_URL_INDICATORS`.
- **OAuth/identity:** Pattern tightened to explicit auth tokens; bare `.token` no longer flagged (avoids parser-token FPs in minified code).

### Documentation
- **docs/ARCHITECTURE_DEPENDENCY_SCANNING_AND_PATTERNS.md** — Architecture for dependency CVE scanning, OSV/npm audit options, implementation order; pattern refinement notes.
- **docs/BABLU_DETECTION_LIBRARY_REVIEW.md** — Bablu-style review: current coverage, gaps vs CVEs, missing patterns (preview XSS, unauthenticated server, webhook exfil, port-scan-from-preview correlation), recommended implementation order.

---

## Recent Changes & Fixes (V8 — 2026-02-16 IOC Enrichment + Risk Floors + Large File Guard)

### Global IOC Database Enrichment
- **IOC source aggregation**: Ingested a consolidated `detection_ioc.txt` campaigns file (LayerX, Koi Security, GitLab Threat Intel, Sekoia, Hunters Axon, ExtensionTotal, Cyberhaven, Unit 42, Malwarebytes, etc.) and **merged all Chrome-focused indicators into the single root `iocs.json`**.
- **Domains**: Added C2 / phishing / squatting domains from campaign `c2_domains`, `phishing_domains`, and `additional_iocs.squatting_domains` (e.g. DarkSpectre, Cyberhaven supply-chain, Unit42 prompt hijacker, sleeper hijacking campaigns). New entries are marked `threat_level: "MALICIOUS"` with neutral reputation and no VT metadata (intel-only IOCs).
- **Extensions**: Added all Chrome extension IDs from the campaigns into `iocs.json["extensions"]` with `risk_score: 10.0` so they are treated as confirmed malicious/supply-chain-risk extensions when seen in scans.
- **Single source of truth**: Removed the old `src/iocs.json` so **only the root `iocs.json` is used** by `IOCManager` and by the analyzer/AI context.
- **Counts after merge**: `total_domains: 125`, `total_extensions: 182` (see `metadata` in `iocs.json`).

### IOC Merge Helper Script
- **File**: `scripts/merge_detection_ioc.py`
- **Role**: Offline utility that normalizes curly-quote JSON from `reports/detection_ioc.txt`, parses the campaigns structure, and safely merges new domains/Chrome extension IDs into `iocs.json` without making any network calls.
- **Safety**: Treats all ingested indicators as pre-vetted intel (no URL fetching, no VT lookups); only writes to `iocs.json`.

### IOC-Aware Risk Floors (Extension IDs + Domains)
- **Extension ID matches IOC DB**: At the end of `analyze_extension()`, if the current extension ID exists in `IOCManager`:
  - If the computed `risk_score < 5.0`, it is bumped to **7.0 (HIGH)**.
  - If the computed `risk_score ≥ 5.0`, it is floored at **9.0 (CRITICAL range, capped at 10)**.
- **Domain matches IOC DB**: If any VirusTotal domain result appears in `IOCManager`:
  - The final `risk_score` is raised to **at least 7.0 (HIGH)** if it was lower.
  - This sits alongside existing VT file-hash logic, where any MALICIOUS file hash already enforces a **risk floor of 8.0** and adds a critical finding.

### Large JavaScript Bundle Safeguard
- **Problem**: Very large single-file bundles (multi-megabyte `background.js` etc.) could cause the full-context regex scanner to run extremely slowly, making the UI appear stuck around 30–40% during static analysis.
- **Fix**: In `static_analyzer.py` the main JS scan loop now:
  - Uses a **size threshold of 600 KiB**; files larger than this skip the heavy `scan_code()` path and instead use `_scan_code_minimal()` (pattern-only, no expensive context building).
  - Adds a `Large JS bundle (partial scan only)` finding to make it explicit in the report that only a partial scan was run and that the file may warrant manual review.
  - Logs debug timing/size information to `.cursor/debug.log` (behind the agent debug logger) to help diagnose future performance issues.

---

## Recent Changes & Fixes (V7 — 2026-02-16 Hardening)

### Trusted Publisher Expansion (26 → ~75)
- **Added categories**: Security vendors (Norton, Avast, McAfee, Kaspersky, etc.), cloud/SaaS (Amazon, AWS, Salesforce, Okta), productivity (Evernote, Canva, Figma), enterprise (IBM, Oracle, SAP), web platforms (Spotify, Netflix, Reddit, PayPal).
- **Matching logic unchanged**: CWS verified badge OR full author name OR first-word match.
- **Location**: `static_analyzer.py` `trusted_publishers` frozenset.

### Benign Domain Expansion
- **FIRST_PARTY_DOMAINS (34 → ~70)**: Cloud infra (cloudfront.net, s3.amazonaws.com, vercel.app), auth (okta.com, auth0.com), monitoring (sentry.io, datadog.com), fonts (fonts.googleapis.com), dev refs (stackoverflow.com, w3.org), SaaS (intercom.io, zendesk.com), social (reddit.com, wikipedia.org).
- **BENIGN_DOMAINS (43 → ~75)**: Kept in sync with FIRST_PARTY_DOMAINS additions.
- **Location**: `static_analyzer.py`, `false_positive_filter.py`.

### Supply Chain Safety Fix
- **Problem**: Trusted publisher 3.5 cap applied even when extension had critical findings (e.g., compromised Google extension scored LOW instead of CRITICAL).
- **Fix**: Cap only applies when `crit_count == 0 AND bc_crit == 0 AND no malicious VT file hash`. Checks `results['file_hashes']` for MALICIOUS status.
- **Location**: `static_analyzer.py` risk scoring section.

### Verified Badge Detection Fix (New CWS)
- **Problem**: `author_verified` always returned `False` on chromewebstore.google.com — old CSS class check broken on SPA.
- **Root cause**: New CWS embeds developer data in serialized arrays, not DOM elements.
- **Fix**: Added `_detect_verified_badge(soup, text)` with 4 strategies: (1) embedded dev array parsing (`VERIFIED_FLAG = 1`), (2) JSON-LD, (3) DOM badges, (4) text markers.
- **Developer info**: Also extracts author name from embedded array as reliable fallback.
- **Tested**: Google Translate → True, Honey → False.
- **Location**: `store_metadata.py`.

### Unit42 Threat Intel Integration
- **Added**: `_search_unit42_repo()` in `threat_attribution.py` — GitHub API code search + raw file fallback for 7 known IOC files.
- **Priority**: 1.5 in `search_threat_campaigns()` (after DB, before name patterns).

---

## Previous Changes (V6 — 2026-02-15)

### File Hash VT Integration
- **SHA-256 hashing**: `_compute_file_hashes()` in `static_analyzer.py` computes hashes of manifest.json, manifest.js (if present), background scripts, and content scripts.
- **VT lookup**: `check_file_hash()` and `check_multiple_file_hashes()` in `virustotal_checker.py` call `GET /files/{hash}` on VirusTotal.
- **Critical risk floor**: Any file hash flagged MALICIOUS → risk floor 8.0 + critical finding added.
- **Report IOC section**: "File Hash IOCs (SHA-256)" shows each file's hash with MALICIOUS/SUSPICIOUS/CLEAN/NOT IN VT badges and VT links.

### Domain Extraction False Positive Fix
- **Problem**: `_QUOTED_FQDN_PATTERN` was matching JS identifiers like `Permissions.PermissionsAdded`, `InternalAnalytics.TrackEvent`, `BlockElementModule.Options` — these were sent to VT as "domains."
- **Fix in `static_analyzer.py`**: `_is_plausible_host()` now rejects CamelCase strings, known API namespaces (`chrome.`, `Permissions.`, etc.), and strings whose last label is not a valid public TLD (curated set of ~140 TLDs).
- **Fix in `analyzer.py`**: `_check_virustotal()` has a parallel `_is_real_domain()` gate before adding to `unique_domains`.

### JS Scan Scope (Performance + FP Reduction)
- **Problem**: `_prioritize_js_files_for_security()` was scanning up to 300 JS files including bundled libraries, producing false positives and slowing analysis.
- **Fix**: Now only scans manifest-referenced files (background, content scripts, service worker) plus high-value filenames (`inject.js`, `helper.js`, `payload.js`, `stealer.js`, `find-password.js`, `manifest.js`, etc.). Everything else (libraries, polyfills, framework code) is skipped.

### Unified Top 5 Domains in IOC Section
- **Before**: Three separate domain blocks dumping all domains (Malicious Domains, Exfil Destinations, Domains in Code/Manifest).
- **After**: Single "Top Domains (sorted by threat score)" block. Collects from all sources (VT, AST exfil, code URLs, manifest URLs), sorts by malicious vendor count + negative community votes, shows only top 5 with badges and VT links.

### Report Validator ("Bablu Review")
- **New file**: `src/report_validator.py` — automated post-analysis validation job.
- **What it does**: For each analyzed extension, reads the analysis JSON + actual extension source code, then classifies every finding as TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW.
- **FP checks implemented**: Webpack globalThis polyfill, reflect-metadata keystroke arrays, chrome.storage.sync settings vs credentials, idb library IndexedDB, credit card targeting verification, prototype references, localStorage/tab.url low-severity, domains from comments, domains from filter rule .txt files, VT 1-vendor noise, behavioral correlations built on FP evidence.
- **Usage**: `python report_validator.py --count 10` validates last 10 extensions; `--json out.json` saves full report.
- **Test results**: 10 extensions reviewed — 38.4% overall FP rate, attributed malware TP rate 1.4% (needs improvement in detection specificity).

### V6 — Store metadata, first-party, detection library, VK Styles (2026-02-15)
- **Chrome Web Store metadata**: Switched to `chromewebstore.google.com` URL; added regex/DOM parsing for new store layout (author, version, users, featured, trader). Fixes "Unknown" metadata for extensions like Google Translate.
- **Trusted publisher / first-party**: Trusted publisher list (Google, Microsoft, Mozilla, etc.) + CWS verified badge; when set, positive_reduction cap 2.5 and LOW_RISK summary explains "First-party or trusted publisher." Report shows First-party badge and Listing details (Developer, Flags, Users, Version).
- **Known malicious DB**: `data/known_malicious_extensions.json` — VK Styles campaign (5 extension IDs). Match → CONFIRMED attribution, risk floor CRITICAL (≥9.0).
- **Detection artefacts**: `data/detection_artefacts.json` — standard per-campaign artefacts (extension_ids, domains_and_urls, cookie_names, patterns). Single file for all campaigns; no vendor-specific docs.
- **Risk logic**: Positive_reduction zeroed when critical code finding (`crit_count > 0`). Malice floor: `crit_count >= 1` → raw_score ≥ 4.0 (MEDIUM).
- **Detection patterns**: INJECT-003 (C2 from meta tag), OBF-007 (computed R-A- analytics ID), EXFIL-002 (remixsec/CSRF cookie); same in static_analyzer SECURITY_PATTERNS. INJECT-002 window 200→500 chars.
- **Generic wording**: All attribution/source labels use "Security research" or "Public threat research"; no vendor names in output. Removed campaign-specific validation MD; added `docs/DETECTION_LIBRARY.md` for standard library layout.

### Post-V6 — Report quality, first-party LOW, benign domains (2026-02-16)
- **Code snippet caps**: Context lines in static_analyzer truncated to 350 chars/line; `context_with_lines` capped at 4000 chars. Report: snippets limited to 15 lines and 250–280 chars/line so minified code doesn’t flood the report.
- **Deduplication**: Findings deduped by `(name, file, line)` (was `(name, file)`). Contextual patterns capped at 2 per extension (`_MAX_PER_NAME = 2`); added "Web Crypto API Usage" and "High Entropy String (Obfuscation)" to `_CONTEXTUAL_CAP_PATTERNS`.
- **First-party → LOW**: Trusted publisher (first-party) extensions are always downgraded to **LOW** risk: `final_score = min(final_score, 3.5)` when `is_trusted_publisher`, so risk level is never MEDIUM+ for Adobe/Google/Microsoft etc.
- **example.com benign**: RFC 2606 domains (`example.com`, `example.org`, `example.net`, etc.) added to `false_positive_filter.BENIGN_DOMAINS`, `report_validator._BENIGN_DOMAIN_PATTERNS`, `static_analyzer.FIRST_PARTY_DOMAINS`, and `virustotal_checker` skip list so they are never flagged as malicious.
- **VT runtime domains**: Newly discovered domains from dynamic analysis are filtered with `filter_virustotal_results()` before merging; `update_risk_with_virustotal` uses full `vt_results` (initial + runtime) for consistency.
- **Duplicate rule ID**: CSRF cookie rule ID changed from `EXFIL-002` to `EXFIL-006` in `detection_rules.json` (EXFIL-002 remains "History Exfiltration").
- **README**: Chrome Web Store URL updated to `chromewebstore.google.com`; detection library and first-party/listing details documented.

---

## Architecture

| Component | File | Role |
|-----------|------|------|
| Main pipeline | `analyzer.py` | Orchestrates steps, progress_callback at each phase |
| Static analysis | `static_analyzer.py` | Manifest, permissions, pattern scan, file hashing, sinkhole detection |
| AST analysis | `ast_analyzer.py` | esprima, config extraction; accepts optional `js_file_list` |
| VT checker | `virustotal_checker.py` | Domain reputation + file hash lookup |
| Store metadata | `store_metadata.py` | CWS metadata, verified badge detection (embedded array), developer info |
| Threat attribution | `threat_attribution.py` | DB check, Unit42 GitHub, dorking, web search, threat-context filter |
| Report | `professional_report.py` | HTML/JSON reports with file hash IOCs, top 5 domains |
| Report validator | `report_validator.py` | Automated FP detection — "Bablu Review" |
| Dependency vuln scan (VSCode) | `dependency_vuln_scanner.py` | OSV querybatch + per-vuln `/v1/vulns/{id}` enrichment (summary, severity, CVSS, CWE, fix version, aliases) |
| Bundled JS vuln scan (VSCode) | `retirejs_scanner.py` | Retire.js CLI scan; extracts severity, summary, fix version (`below`), aliases, advisory URLs |
| VSCode analyzer | `vscode_analyzer.py` | Four-layer VSCode analysis, supply chain + dependency vulns, pattern scan |
| Detection library | `data/known_malicious_extensions.json`, `data/detection_artefacts.json` | Known campaigns + artefacts (open web research) |
| Web backend (legacy) | `web/app.py` | Basic FastAPI UI, background _run_analysis, progress_callback, /cancel |
| Web frontend (legacy) | `web/templates/index.html` | Progress bar, step text, cancel button, status polling |
| API platform | `api/main.py` | FastAPI REST API, CORS, lifespan, route mounting |
| API routes | `api/routes/analyze.py`, `reports.py`, `extensions.py` | /analyze, /jobs, /reports, /extensions endpoints |
| API models | `api/models.py` | PostgreSQL ORM: Extension, ScanJob, ScanResult |
| API auth | `api/auth.py` | X-API-Key auth + rate limiting middleware |
| API worker | `api/worker.py` | RQ worker for async scan job processing |
| API config | `api/config.py`, `api/database.py` | Environment config, DB engine/session |

---

## Key Limits

| Limit | Value | Location |
|-------|-------|----------|
| AST file size | 1 MiB | ast_analyzer.py |
| Config file size | 512 KiB | ast_analyzer.py |
| Pattern-scan read | 2 MiB | static_analyzer.py |
| Snippet context line | 350 chars | static_analyzer.py |
| Snippet context total | 4000 chars | static_analyzer.py |
| Report snippet | 15 lines, 280 chars/line | professional_report.py |
| Obfuscation sample | 300 KiB | static_analyzer.py |
| Max JS files | 300 (manifest-referenced + high-value names) | static_analyzer.py |
| AST traverse depth | 10,000 | ast_analyzer.py |
| Two-pass gap threshold | 50 | static_analyzer.py |
| VT file hash max checks | 10 | virustotal_checker.py |
| VT domain max checks | 10 | analyzer.py |
| Valid TLD set | ~140 TLDs | static_analyzer.py, analyzer.py |
| Trusted publishers | ~75 | static_analyzer.py |
| First-party domains | ~70 | static_analyzer.py |
| Benign domains | ~75 | false_positive_filter.py |

---

## How to Run

- **CLI (Chrome store extension):** `python -m src.analyzer <extension_id>` (from project root)
- **CLI (VSCode extension):** `python -m src.analyzer <publisher.name> --vscode` (e.g. `tomphilbin.lodash-snippets`, `shd101wyy.markdown-preview-enhanced`)
- **CLI (local unpacked):** `python -m src.analyzer test_fixtures/malicious_test_extension --local --fast`
- **Legacy Web UI:** `python web/app.py` -> http://localhost:8000
- **API Platform (Docker):** `docker-compose up` -> API at http://localhost:8000, Swagger docs at http://localhost:8000/docs
- **API Platform (local dev):** `uvicorn api.main:app --reload` (requires PostgreSQL + Redis running)
- **Worker:** `python -m api.worker` (or `rq worker scans --url redis://localhost:6379/0`)
- **Validate reports:** `python src/report_validator.py --count 10` (Bablu Review)

Reports: Chrome — `reports/<extension_id>_threat_analysis_report.html` and `reports/<extension_id>_analysis.json`. VSCode — `reports/vscode_<id>_threat_analysis_report.html` and `reports/vscode_<id>_analysis.json`.
