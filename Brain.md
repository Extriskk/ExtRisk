## chrome-extension-security-analyzer – Architecture Brain

This file is the **single source of truth for architecture**.  
When planning or changing anything non‑trivial, **start here first**.

---

## Index

- **1. Top‑level flows**
- **2. Core analysis engine (`src/`)**
  - 2.1 CLI & orchestration
  - 2.2 Static analysis engines
  - 2.3 Threat intelligence & attribution
  - 2.4 Reporting
- **3. VSCode marketplace / Open VSX pipeline**
- **4. API service (`api/`)**
- **5. Web UI (`web/`)**
- **6. Batch / Bablu / central store scripts (`scripts/`)**
- **7. Support libraries & utilities**
- **8. Tests & fixtures**
- **9. Developer tooling (code-review-graph, npm-mal-scan)**

Use these section numbers when referring to components (e.g. “see 2.2.1”).

---

## 1. Top‑level flows

- **Browser extension (Chrome/Edge) CLI**
  - Entry: `src/analyzer.py:main()` → `ChromeExtensionAnalyzer` methods.
  - Downloads `.crx` (`src/downloader.py`) → unpacks (`src/unpacker.py`) → runs static + behavioral + supply‑chain analysis → VirusTotal/domain intel → renders reports (`src/professional_report.py`, `src/report_generator.py`).

- **VSCode extension CLI**
  - Entry: `src/analyzer.py:main()` with `--vscode` or `--openvsx`.
  - Downloads `.vsix` from **VS Marketplace** or **Open VSX** (`src/vscode_downloader.py`) → unpacks (`src/vscode_unpacker.py`) → runs VSCode multi‑layer analyzer (`src/vscode_analyzer.py`) → optional supply‑chain (`src/dependency_vuln_scanner.py`, `src/retirejs_scanner.py`) → reporting.

- **Batch marketplace validation**
  - Cohort JSON (`data/cohorts/*.json`) → `scripts/batch_run_vscode.py` (spawns CLI scans) → manifest (`batch_runs/batch_manifest_*.json`) → Bablu review + central store ingest (`scripts/bablu_review_run.py`, `scripts/central_store_writer.py`).

- **API / worker path**
  - External clients hit FastAPI (`api/main.py`, `api/routes/*`) → enqueue / run scans through CLI / worker (`api/worker.py`) → results stored via SQLAlchemy models (`api/models.py`) and surfaced back as JSON/HTML.

- **Web UI**
  - Two entry points:
    - Legacy dev UI: `web/app.py` (simple local app for submitting extension IDs and viewing status/results).
    - Public webapp UI: FastAPI router `api/routes/web.py` mounts under `/app` with the same UI/UX as extension-analyser: landing (feature pills, store selector pills, example chips, progress stepper, recent scans) → `/app/analyze` → `/app/reports/{id}/summary` (gauge, stats, collapsible findings, “View full report” / “Re-scan”) → `/app/reports/{id}` (full HTML report with sticky nav bar). Cached results redirect to summary; new scans run synchronously then redirect. Error states render HTML error pages with a back link.
  - Designed so the `/app` UI can be exposed on a cloud host (e.g. Render) alongside the JSON API.

---

## 2. Core analysis engine (`src/`)

### 2.1 CLI & orchestration

- **`src/analyzer.py`**
  - **Class `ChromeExtensionAnalyzer`** (primary orchestrator):
    - Scans Chrome, Edge, and VSCode extensions (VSCode variants via helper methods).
    - Wires together: downloader, unpacker, `EnhancedStaticAnalyzer`, network capture, VT checker, domain intelligence, taint engine, professional report generator, threat attribution, version diff, IOC manager, and optional Ollama analysis.
  - **`analyze_vscode_extension(extension_identifier, store='vscode')`**
    - Complete VSCode/VS Marketplace or Open VSX pipeline (see section 3).
  - **`analyze_vscode_extension_local(extension_path)`**
    - Same as above, but for an already‑unpacked local VSCode extension directory.
  - **`parse_cli_args()` / `main()`**
    - CLI parsing (Chrome / Edge / VSCode / local), fast‑mode flags, VT/OSINT toggles.
    - Decides which analyzer path to run and translates final `risk_level` into exit codes.
  - **Helper `_safe_stdout_stderr()`**
    - Wraps stdio on Windows to avoid Unicode encoding errors in rich reports.

### 2.2 Static analysis engines

- **`src/static_analyzer.py`**
  - **Function `_agent_debug_log(...)`**
    - Structured logging hook for advanced analysis/debugging.
  - **Class `EnhancedStaticAnalyzer`**
    - Core JavaScript static analyzer for browser extensions.
    - Responsibilities:
      - Code pattern scanning (eval, dynamic scripts, offscreen/eval chains, remote iframe UI, beacon/WebSocket exfiltration, EventSource, dynamic `import("https://…")`, etc.).
      - Data‑flow / taint analysis hooks (cooperates with `TaintAnalyzer`).
      - Aggregates per‑file findings into a normalized result format for reporting.
      - VirusTotal integration:
        - `update_risk_with_virustotal(...)` merges `virustotal_results` into the result and adjusts `risk_score` based on domain threat level and detection counts.
        - Also inspects VT `domain_age` and adds a small +1 **newly‑registered domain** penalty (age \< 150 days) when any contacted domain is very new (marked via `results["newly_registered_domain"]`).

- **`src/ast_analyzer.py`**
  - **Class `JavaScriptASTAnalyzer`**
    - Deeper AST‑driven analysis, used to understand JS control/data flows, detect complex patterns that simple regex misses.
  - **`test_ast_analyzer()`**
    - Internal verification of AST logic (unit test helper).

- **`src/taint_analyzer.py`**
  - **Classes**:
    - `TaintSource`, `TaintSink`, `TaintedVariable`, `TaintFlow`, `TaintAnalyzer`, `EntropyAnalyzer`.
  - **Role:**
    - Tracks sensitive data origins (e.g. cookies, tokens, clipboard, history, screenshots, passwords) through JS.
    - Taint sinks include `fetch`, `XMLHttpRequest`, `navigator.sendBeacon`, `WebSocket`, `EventSource`, `.send(...)`, `Image`, etc.
    - Produces `taint_flows` that drive the **Data Exfiltration Pipeline** correlation rule and the HTML **Data Flows & Exfiltration Map** section.
    - Identifies flows to sinks (network, storage, logs).
    - `EntropyAnalyzer` helps flag high‑entropy strings (keys, secrets).

- **`src/enhanced_detection.py`**
  - **Classes:**
    - `SensitiveDataDetector`, `ObfuscationDetector`, `EnhancedDetectionEngine`,
      `WalletHijackDetector`, `PhishingDetector`.
  - **Role:**
    - High‑level detectors that sit on top of static + taint analysis and classify behaviors into risk categories (PII exfil, phishing flows, wallet hijack signatures, etc.).

- **`src/advanced_detection.py`**
  - **Class `AdvancedDetector`**
    - Experimental / advanced detector bundle for newer pattern families.
  - **`test_advanced_detector()`**
    - Regression test helper for advanced detectors.

- **`src/behavioral_engine.py`**
  - **Class `BrowserBehavioralEngine`**
    - Correlates events, permissions, network behavior, and patterns into higher‑level behaviors and risk signals.

- **`src/network_capture.py`**
  - **Helpers**: `_is_allowlisted(domain)`, `_is_static_resource(url, resource_type)`, `score_request(req)`.
  - **Class `NetworkCaptureAnalyzer`**
    - Processes captured network traces to identify suspicious hosts, config downloads, C2‑like patterns, and relates them back to extensions.

### 2.3 Threat intelligence & attribution

- **`src/threat_attribution.py`**
  - **Class `ThreatAttribution`**
    - Maps extensions and behaviors to known threat campaigns / indicators.
    - Used late in the pipeline to add campaign context to reports.

- **`src/domain_intelligence.py`**
  - **Class `DomainIntelligence`**
    - Enriches domains (reputation, TLD risk, known C2 lists, etc.).
    - Consumed by both static findings and network capture.

- **`src/virustotal_checker.py`**
  - **Class `VirusTotalChecker`**
    - Handles VT API calls and result summarization.
  - **`test_virustotal()`**
    - Internal sanity check for VT integration.

- **`src/campaign_detector.py`**
  - **Class `CampaignFingerprinter`**
    - Looks for recurring behavior/domain fingerprints that imply shared campaigns.

- **`src/sensitive_target_detector.py`**
  - **Class `SensitiveTargetDetector`**
    - Flags when extensions interact with high‑value targets (banking, wallets, major SaaS).

### 2.4 Reporting

- **`src/professional_report.py`**
  - **Class `ProfessionalReportGenerator`**
    - Builds HTML + JSON reports with BLUF, severity breakdowns, and deep explanations.
    - Applies “Why this matters” copy and calibrated messaging rules.
    - Renders high‑fidelity **code snippets** for findings:
      - For `malicious_patterns` entries with `matched_text`, resolves `file_hashes → file_path`, reads the original JS, and generates snippets centered on the matched pattern (e.g. `navigator.sendBeacon(`) so evidence is always visible.
      - For suspicious VT domains that also appear in `urls_in_code`, pulls a contextual snippet from the corresponding JS file showing how that domain is used.
    - IOC / VT presentation:
      - IOC section aggregates file hashes, search‑hijack URLs, and **domains flagged by VirusTotal** (vendor counts, community votes, and source tags).
      - Newly created domains (VT `domain_age.age_days` \< 150) are explicitly labeled **“NEW DOMAIN (< 5 months)”** and show creation date/age.
    - Data‑flow visualization:
      - **“Data Flows & Exfiltration Map”** section renders `enhanced_detection["taint_flows"]` as a table (source API/category → encoding/transform hints → sink function/type → best‑effort destination → file:line), aligning the report with the detection‑enhancement workflow.

- **`src/report_generator.py`**
  - **Class `ExecutiveReportGenerator`**
    - Higher‑level / executive summary style reporting.

- **`src/report_validator.py`**
  - **Class `ReportValidator`**, `main()`
    - Validates reports against expected invariants and schemas.

- **`src/false_positive_filter.py`**
  - **Class `FalsePositiveFilter`**
    - Shared FP filtering rules for noisy patterns.
  - **`test_false_positive_filter()`**
    - Regression tests for FP rules.

---

## 3. VSCode marketplace / Open VSX pipeline

- **Downloader – `src/vscode_downloader.py`**
  - **Class `VSCodeExtensionDownloader`**
    - `parse_identifier(...)` – parses `publisher.name` or VS Marketplace / Open VSX URLs.
    - `fetch_metadata(..., store='vscode'|'openvsx')` – pulls metadata from VS Marketplace or Open VSX.
    - `download_extension(..., store=...)` – downloads `.vsix` from the right registry.
    - `download_by_identifier(identifier, store=...)` – one‑shot identifier → vsix + metadata.

- **Unpacker – `src/vscode_unpacker.py`**
  - **Class `VSCodeExtensionUnpacker`**
    - `unpack(vsix_path)` – extract `.vsix` to `data/vscode_extensions/<id>-<version>/extension/`.
    - `read_vsixmanifest(...)` and helpers – parse VSIX manifest / metadata.
    - `get_file_inventory(...)` – counts files by type, size, node_modules footprint.

- **VSCode analyzer – `src/vscode_analyzer.py`**
  - **Class `VSCodeStaticAnalyzer`** (implied by usage)
    - Layered analysis for VSCode:
      - Layer 1: metadata & publisher (activation events, contributes, categories).
      - Layer 2: supply chain (OSV + `dependency_vuln_scanner`, `retirejs_scanner`).
      - Layer 3: code patterns (JS/TS scanning, pattern engine, taint hooks).
      - Layer 3.5: HTML/webview security.
      - Layer 4: risk scoring and calibration.
    - Contains:
      - Chunked pattern scanning for large files.
      - VSCode‑specific FP filters (e.g., library innerHTML, localhost allowances).
      - Risk score composition with supply‑chain floors.

---

## 4. API service (`api/`)

- **`api/main.py`**
  - FastAPI app entrypoint.
  - **Endpoints:**
    - `root()` – basic index.
    - `health()` – health check.
    - Mounts API routers (`analyze`, `reports`, `extensions`) and the public web router (`web`, mounted at `/app`).

- **`api/routes/analyze.py`**
  - **Helpers:**
    - `_validate_extension_id(ext_id, browser)` – checks ID shape/store.
    - `_get_redis()` – returns Redis connection handle (for job queue/status).
  - **Route handlers:**
    - `start_analysis(...)` – enqueue or trigger a scan; on Windows (sync path) runs scan and **writes report content into `ScanResult.report_json` / `report_html`**.
    - `get_job_status(...)` – poll job status.
    - `cancel_job(...)` – best‑effort cancellation.

- **`api/routes/extensions.py`**
  - `_result_to_summary(...)` – converts stored results to response summaries.
  - `get_extension(...)` – extension overview endpoint.
  - `get_extension_history(...)` – prior scans for an extension.

- **`api/routes/reports.py`**
- **`api/routes/web.py`**
  - **Landing + web flow (mounted at `/app`):**
    - `GET /app` – public landing page with extension ID + store selector.
    - `POST /app/analyze` – handles form submission:
      - If a `ScanResult` exists for the extension, redirects straight to `/app/reports/{extension_id}?cached=1` (cached report from DB).
      - Otherwise, runs a synchronous scan via `ScanService` and `ChromeExtensionAnalyzer`, persists the result into the API DB via `persist_scan_result_to_db(...)`, then redirects to `/app/reports/{extension_id}`.
    - `GET /app/reports/{extension_id}` – renders the latest HTML report for that extension directly from `ScanResult.report_html` or from the stored `html_report_path`.
  - Intended as the primary public web interface (same HTML report UI as local runs), while `/api/v1/*` stays API-key protected.

  - **Report storage (DB as source of truth):** `ScanResult` has `report_json` and `report_html` (Text). Report API serves from these columns first; falls back to `json_report_path` / `html_report_path` if content not in DB.
  - **By job_id:** `_get_result(job_id, db)` – shared DB lookup helper. `get_report_summary(...)`, `get_html_report(...)`, `get_full_json_report(...)` – return summary, HTML, or full JSON for a completed job.
  - **By extension_id:** `get_report_by_extension_summary(extension_id)` – latest report summary for extension. `get_report_by_extension_html(extension_id)` – latest HTML body. `get_report_by_extension_full(extension_id)` – latest full JSON. Use when you have extension ID but not job ID (e.g. “give me the stored report for this extension”).

- **`api/worker.py`**
  - `_compute_package_hash(extension_dir)` – stability key for caching/dedup.
  - `run_scan(job_id)` – worker entry; runs the analyzer, persists result, and **reads generated report files into `ScanResult.report_json` / `report_html`** so reports are stored in the single DB.

- **`api/report_store.py`**
  - **CLI → DB:** When the analyzer is run from the CLI (`src/analyzer.py`) and reports are generated, **results are automatically persisted** to the same API DB via `persist_scan_result_to_db(...)`. Extension + ScanResult are upserted/created with report content so GET by `extension_id` serves the latest run. No-op if `DATABASE_URL` is unset or DB unavailable; never fails the CLI.

- **`api/auth.py`**
  - `_check_rate_limit(api_key)` – simple rate‑limit / auth gate.

- **`api/schemas.py`**
  - Pydantic models:
    - `AnalyzeRequest`, `AnalyzeResponse`, `JobStatusResponse`,
      `ReportSummary`, `ExtensionInfo`, `ExtensionHistory`, `ErrorResponse`.

- **`api/models.py`**
  - SQLAlchemy models:
    - `Extension`, `ScanJob`, `ScanResult`.
  - **`ScanResult`** also has `report_json` (Text) and `report_html` (Text) – full report content stored in DB so report API can serve without relying on report files.
  - `_utcnow()` – default timestamp helper.

- **`api/database.py`**
  - `get_db()` – session dependency factory.

- **`api/config.py`**
  - `Settings` – environment / config for the API (DB URL, Redis, secrets, etc.).

- **Migrations:** `alembic/versions/` – 001 widen `threat_classification` to Text; 002 add `report_json`, `report_html` to `scan_results`. Run `alembic upgrade head` after pulling.

- **Deployment shape (cloud, e.g. Render):**
  - Web service container runs `uvicorn api.main:app --host 0.0.0.0 --port 8000` and exposes both the JSON API and `/app` web UI.
  - Background worker container runs `python -m api.worker` and processes queued jobs from Redis (when `REDIS_URL` is configured and `_QUEUE_AVAILABLE` is true).
  - Both services point at the same Postgres `DATABASE_URL` so `Extension`, `ScanJob`, and `ScanResult` are shared; report content (`report_html`/`report_json`) is always loaded from DB in the cloud environment.

---

## 5. Web UI (`web/`)

- **`web/app.py`**
  - **Classes:**
    - `AnalysisCancelledError` – custom exception for user cancellations.
    - `AnalysisRequest`, `AnalysisStatus` – Pydantic models for web forms/API.
  - **Functions:**
    - `validate_extension_id(extension_id)` – input validation for IDs.
    - `_run_analysis(extension_id)` – background/async call into analyzer.
  - Used to provide a simple browser UI over the CLI / API.

---

## 6. Batch / Bablu / central store scripts (`scripts/`)

- **`scripts/batch_run_vscode.py`**
  - `repo_root()` – locate repo root.
  - `safe_identifier(extension_id)` – filesystem‑safe key.
  - `discover_report_paths(...)`, `discover_extension_dir(...)` – locate outputs.
  - `load_cohort(path)` – load cohort JSON (`data/cohorts/*.json`).
  - `run_analyzer(...)` – worker that invokes `src/analyzer.py` (subprocess).
  - `main()` – orchestrates multi‑worker batch run and writes manifest under `batch_runs/`.

- **`scripts/fetch_recent_vscode_extensions.py`**
  - `repo_root()` – repo helper.
  - `fetch_extensions_page(...)` – VS Marketplace `extensionquery` API call.
  - `main()` – writes `data/cohorts/recent_N.json` (recently updated extensions).

- **`scripts/list_main_js.py`**
  - `repo_root()`, `_normalize_path(...)`, `_collect_script_paths_from_value(...)`.
  - `list_main_js(extension_dir)` – derive main JS entry points from VSCode `package.json` and structure.
  - `main()` – CLI for listing main JS for an extension or a manifest.

- **`scripts/bablu_review_run.py`**
  - `repo_root()`, `safe_id(...)` – helpers.
  - `get_main_js_files(...)`, `normalize_finding_file(...)`,
    `finding_in_main_js_scope(...)`, `read_line_or_context(...)`.
  - `verify_finding(...)` – checks that a report finding really exists at cited file/line.
  - `run_review_for_extension(...)` – runs Bablu review for one extension.
  - `main()` – iterates over manifest, writes `bablu_review_*.json` + cohort summaries.

- **`scripts/central_store_writer.py`**
  - `repo_root()`, `safe_identifier(...)`.
  - `load_report(path)` – read a report JSON.
  - `build_store_record(report, source="batch")` – normalize into central‑store schema.
  - `write_to_store(store_dir, record)` – write `central_store/vscode/*.json`.
  - `main()` – CLI for ingesting manifest into the central store.

- **`scripts/cleanup_after_review.py`**
  - `repo_root()`, `safe_identifier(...)`, `has_review_file(...)`.
  - `main()` – deletes extraction directories only for extensions with review files.

- **`scripts/merge_detection_ioc.py`**
  - `normalize_json_quotes(raw)` – small helper for fixing JSON quoting.
  - `add_domains(...)` – merges new domains/I0Cs into existing JSON.
  - `main()` – CLI utility for updating IOC datasets.

- **`scripts/l_crawler.py`**
  - Crawls security research blog (L) for extension-analysis posts.
  - Extracts extension IDs, domains, TTPs, and code-snippet references; writes `data/l/l_posts.json` and `l_consolidated.json`.
  - With `--write-lessons`, updates `docs/L_LESSONS_LEARNT.md` with consolidated IOCs and detection hints for Bablu and the detection library.
  - Run: `python scripts/l_crawler.py [--max-posts N] [--write-lessons]`.

- **`scripts/k_crawler.py`**
  - Crawls security research blog (K) for extension and VS Code malware posts (DarkSpectre, GhostPoster, RedDirection, SpyVPN, VK Styles, GreedyBear, etc.).
  - Extracts extension IDs, domains, and behavior keywords; writes `data/k/k_posts.json` and `k_consolidated.json`.
  - With `--write-lessons`, updates `docs/K_LESSONS_LEARNT.md`.
  - Run: `python scripts/k_crawler.py [--max-posts N] [--write-lessons]`.

- **`scripts/import_reports_to_db.py`**
  - One‑time or recurring import of existing report files into the API DB.
  - Scans `reports/*_analysis.json`, reads matching `*_threat_analysis_report.html`, and creates/updates `Extension` and `ScanResult` with **report content in DB** (`report_json`, `report_html`). Use after adding existing `reports/` to the project so the Report API can serve them by `extension_id` or `job_id`.
  - Run: `python scripts/import_reports_to_db.py` (optional `--reports-dir`, `--dry-run`).

---

## 7. Support libraries & utilities (`src/`)

- **`src/downloader.py`**
  - **Class `BrowserType`** – Chrome vs Edge enum.
  - **Class `ExtensionDownloader`**
    - `download_extension(...)`, `download_chrome_extension(...)`,
      `download_edge_extension(...)`, `download_multiple(...)`, `detect_browser_store(...)`.
  - `main()` – manual downloader test harness.

- **`src/unpacker.py`**
  - **Class `ExtensionUnpacker`**
    - Handles extracting `.crx` into unpacked directories.
  - `main()` – CLI utility for unpacking previously downloaded `.crx` files.

- **`src/store_metadata.py`**
  - **Class `StoreMetadata`**
    - Fetches and normalizes Chrome/Edge store metadata (installs, ratings, etc.).

- **`src/version_diff.py`**
  - **Class `VersionDiffAnalyzer`**
    - Compares current scan to baseline; tracks changes across versions.

- **`src/ioc_manager.py`**
  - **Class `IOCManager`**
    - Manages indicator‑of‑compromise data, merges scan outputs with IOC DB.

- **`src/dependency_vuln_scanner.py`**
  - `_parse_version_from_spec(...)`, `resolve_versions(...)`,
    `_vuln_link(...)`, `_osv_severity_to_label(...)`,
    `_extract_fix_version(...)`, `_enrich_vulns(...)`.
  - `query_osv_batch(...)`, `scan_dependencies(...)`.
  - **Role:** OSV integration and dependency vulnerability enrichment.

- **`src/retirejs_scanner.py`**
  - `_find_retire_cmd(...)`, `_vuln_id_from_identifiers(...)`, `_vuln_link(...)`.
  - `scan_bundled_js(...)` – Retire.js integration for bundled JS.

- **`src/ollama_analyzer.py`**
  - `_requests()`, `check_available(...)`, `list_models(...)`, `_pick_model(...)`.
  - `_collect_extension_context(...)`, `_findings_summary(...)`.
  - `generate_assessment(...)`, `analyze(...)`.
  - **Role:** Optional LLM assessment over findings/context (Ollama).

- **`src/host_permissions_analyzer.py`**
  - **Class `HostPermissionsAnalyzer`**
    - Analyzes extension host/URL permissions and flags risky scopes.

- **`src/pii_classifier.py`**
  - **Class `PIIClassifier`**
    - Classifies strings/fields as potential PII and feeds into detectors.

- **`src/utils.py`**
  - `calculate_file_hash(...)`, `save_json(...)`, `load_json(...)`,
    `get_timestamp(...)`, `format_bytes(...)`.

---

## 8. Tests & fixtures

- **Manual testing: Report storage and Report API**  
  See **docs/TESTING_REPORT_STORAGE_AND_API.md** for step-by-step: migrations, import script, POST /analyze, GET report by `job_id`, GET report by `extension_id`.

- **`tests/test_fast_flag.py`**
  - `test_parse_fast()`, `test_fast_short_circuit_vt()` – ensure `--fast` behaves correctly.

- **`tests/test_skip_vt.py`**
  - `test_skip_vt_short_circuit()` – validates VT skip behavior.

- **`tests/regenerate_report.py`**
  - `main()` – helper to regenerate reports for test fixtures.

---

## 9. Developer tooling (code-review-graph, npm-mal-scan)

- **code-review-graph (Cursor MCP)**  
  Indexes this Python/JS codebase so assistants can query callers, tests, and review context with fewer tokens. Setup: `pip install -r requirements-dev.txt`, then `python -m code_review_graph install --platform cursor` and `python -m code_review_graph build` from repo root (on Windows, use `python -m …` if the `code-review-graph` command is not found). Agent guidance lives in `AGENTS.md` and `.cursorrules`; MCP config is `.cursor/mcp.json` (use the same Python that has the package installed).

- **npm-mal-scan (npm registry package scanner)**  
  Optional **npm-mal-scan** integration for analyzing npm packages (malware / supply-chain heuristics), separate from Retire.js bundled-JS scanning. Resolve path via `tools/npm-mal-scan` (submodule/junction), sibling `../npm-project`, or `NPM_MAL_SCAN_ROOT`. Entry: `src/npm_mal_scan_runner.py` (forwards argv to the Node CLI after `npm run build` in the scanner repo). See `tools/npm-mal-scan/README.md`.

---

## How to use this Brain

- **Design & refactors**
  - Start by locating affected components here (by section number).
  - Prefer adding/changing code in the **most central, reusable layer** rather than patching multiple call sites.

- **Feature work**
  - For new behaviors or data sources, decide:
    - Does it belong in **core analysis** (2.x), **VSCode pipeline** (3), **API** (4), or **scripts** (6)?
  - Then wire it through from entrypoint → engine → reporting.

- **Bablu / review workflows**
  - When adjusting detection logic based on Bablu review, trace:
    - Pattern engine (2.2) → FP filter / calibration (2.4) → report wording (2.4) → batch/Bablu scripts (6).

