# AI context (chrome-extension-security-analyzer)

Short reference for AI assistants working in this repo. For full rules and code-quality notes see **`CLAUDE.md`** (project root). For API/report architecture details see **`Brain.md`** section 4.

---

## What this project does

- **Security analyzer** for Chrome, Edge, and VSCode extensions: static analysis, dependency scanning (OSV + Retire.js), behavioral correlations, optional VirusTotal. Outputs JSON + HTML threat reports.
- **API service** — FastAPI: POST `/api/v1/analyze` to run scans; reports stored in DB and served by `job_id` or `extension_id`. See **Report storage** below.
- **Public webapp** — FastAPI router under `/app`: form to submit an extension, instant redirect to cached report if we already have `ScanResult` for that `extension_id`, or a new synchronous scan + persist + redirect when it’s a new extension.
- **Marketplace validation pipeline:** batch run over cohorts → Bablu review (report vs main JS) → enhancements → re-run → central store; optional cleanup of extracted extension dirs after review.

---

## Report storage (API)

- **Single DB:** Report content lives in `ScanResult.report_json` and `ScanResult.report_html`. API serves from DB first; falls back to file paths if columns empty.
- **Endpoints:**
  - By job: `GET /api/v1/reports/{job_id}`, `/{job_id}/html`, `/{job_id}/full`
  - By extension (latest): `GET /api/v1/reports/by-extension/{extension_id}`, `.../html`, `.../full`
- **Population:** Worker and sync (Windows) analyze path both write report content into the DB after generating files. **CLI runs** (`python src/analyzer.py ...`) also persist automatically via `api/report_store.py` when reports are generated, so the Report API can serve the latest run by `extension_id` without a separate import. Existing `reports/*_analysis.json` + matching HTML can be imported once with `scripts/import_reports_to_db.py` (set `DATABASE_URL` to match the API DB, e.g. SQLite for local).
- **Local run without PostgreSQL:** `api/database.py` supports SQLite when `DATABASE_URL` starts with `sqlite`. Use `scripts/run_api_sqlite.ps1` or `$env:DATABASE_URL="sqlite:///./api_local.db"; python -m uvicorn api.main:app --host 127.0.0.1 --port 8000`. Then run import with the same `DATABASE_URL` so reports appear in the API.
- **Testing:** See `docs/TESTING_REPORT_STORAGE_AND_API.md` for step-by-step (migrations, import, POST analyze, GET by job_id / extension_id).

---

## Web app & deployment (FastAPI `/app`)

- **Web flow (public):**
  - `GET /app` – landing page (extension ID + store selector).
  - `POST /app/analyze` – if there is an existing `ScanResult` for the extension, redirects to `/app/reports/{extension_id}?cached=1`; otherwise runs a synchronous scan via `ScanService`, persists via `persist_scan_result_to_db(...)`, and then redirects to `/app/reports/{extension_id}`.
  - `GET /app/reports/{extension_id}` – renders the latest HTML report from `ScanResult.report_html` or the fallback file path.
- **Cloud deployment shape (Render-style):**
  - Web service: Docker image running `uvicorn api.main:app --host 0.0.0.0 --port 8000` with `DATABASE_URL` (Postgres) and `REDIS_URL` (Key Value/Redis).
  - Background worker: same image running `python -m api.worker` to process queued jobs.
  - Both talk to the same Postgres DB so the `/app` UI and `/api/v1/*` share `ScanResult` rows and report content.

---

## Commands (repo root)

| Goal | Command |
|------|--------|
| Analyze Chrome extension | `python src/analyzer.py <32-char-id>` |
| Analyze Edge extension | `python src/analyzer.py <id> --edge` |
| Analyze VSCode (marketplace) | `python src/analyzer.py publisher.name --vscode` |
| Analyze VSCode (Open VSX) | `python src/analyzer.py publisher.name --openvsx` (e.g. jtl.vscode-theme-seti) |
| VSCode local dir | `python src/analyzer.py path/to/extension --vscode --local` |
| Fast (no VT/OSINT) | add `--fast` |
| Fetch 10 recent marketplace extensions | `python scripts/fetch_recent_vscode_extensions.py` |
| Batch run cohort | `python scripts/batch_run_vscode.py data/cohorts/<name>.json --workers 4 --fast` |
| List main JS for extension | `python scripts/list_main_js.py --from-manifest batch_runs/... --id <id>` |
| Run Bablu review | `python scripts/bablu_review_run.py --manifest batch_runs/...` |
| Ingest reports to central store | `python scripts/central_store_writer.py --manifest batch_runs/... --only-success` |
| Cleanup after review | `python scripts/cleanup_after_review.py --manifest batch_runs/...` |
| Run API (SQLite, no Postgres) | `.\scripts\run_api_sqlite.ps1` or set `DATABASE_URL=sqlite:///./api_local.db` then `python -m uvicorn api.main:app --host 127.0.0.1 --port 8000` |
| Import reports into API DB | `python scripts/import_reports_to_db.py` (set `DATABASE_URL` to same as API, e.g. SQLite for local) |

---

## Key paths

- **Reports:** `reports/` (JSON + HTML per run; can be imported into API DB via `scripts/import_reports_to_db.py`).
- **API DB:** When using SQLite for local dev, `api_local.db` in repo root. Migrations: `alembic upgrade head` (Postgres or SQLite).
- **Cohorts:** `data/cohorts/*.json` (extension ID lists).
- **Extracted extensions:** `data/vscode_extensions/<id>-<version>/extension/`.
- **Batch manifest:** `batch_runs/batch_manifest_<cohort>_<date>.json`.
- **Bablu reviews:** `batch_runs/bablu_reviews/bablu_review_<id>.json`, `review_summary_<cohort>_<date>.json` / `.md`.
- **Central store:** `central_store/vscode/<safe_id>.json`.
- **Docs:** `docs/` — `VSCODE_MARKETPLACE_VALIDATION_AND_HIGH_FIDELITY_PLAN.md`, `BABLU_MAIN_JS_REVIEW_AND_CENTRAL_STORE.md`, `DETECTION_GAPS_LOG.md`, `TESTING_REPORT_STORAGE_AND_API.md` (API/report testing).

---

## Key modules

- `src/analyzer.py` — CLI, orchestration, VSCode entry.
- `src/vscode_analyzer.py` — VSCode 5-layer analysis; pattern scan with chunked parallel scan for large files.
- `src/dependency_vuln_scanner.py` — OSV; `src/retirejs_scanner.py` — Retire.js for bundled JS.
- `src/professional_report.py` — HTML/JSON reports.
- **API:** `api/main.py`, `api/routes/analyze.py`, `api/routes/reports.py`, `api/worker.py`, `api/models.py` (ScanResult has `report_json`/`report_html`), `api/database.py` (SQLite supported when `DATABASE_URL` is sqlite).
- **Scripts:** `scripts/README.md` — batch runner, list_main_js, central_store_writer, cleanup_after_review, bablu_review_run, fetch_recent_vscode_extensions; `scripts/import_reports_to_db.py` (reports → API DB); `scripts/run_api_sqlite.ps1` (start API with SQLite).

---

## Workflow (marketplace validation)

1. **Cohort** — Define or fetch extension IDs → `data/cohorts/<name>.json`.
2. **Batch run** — `scripts/batch_run_vscode.py` → reports + manifest with `report_json`, `report_html`, `extraction_path` per extension. Use `--workers N` for parallel runs. Analyzer exit 0–3 = success (risk level), 4 = failure.
3. **Bablu review** — `scripts/bablu_review_run.py --manifest ...` compares report findings to main JS, writes `bablu_review_<id>.json` (findings_verified with TP/FP/NEEDS_REVIEW) and cohort summary. Review includes metadata_findings, supply_chain_findings, package_json_deep_findings. Apply lessons from `docs/DETECTION_GAPS_LOG.md`.
4. **Enhancements** — Update scanner from review corrections and gaps (see DETECTION_GAPS_LOG).
5. **Re-run** — Same cohort with updated scanner.
6. **Central store** — `scripts/central_store_writer.py --manifest ...` ingests **post-enhancement** reports into `central_store/vscode/`.
7. **Cleanup** — `scripts/cleanup_after_review.py` deletes extraction dirs for extensions that have a `bablu_review_<id>.json`.

---

## Bablu skill

- `.cursor/skills/bablu/SKILL.md` — Use when the user says "bablu" or requests extension JS analysis / scan comparison. Read `docs/DETECTION_GAPS_LOG.md` and apply lessons; add new gaps/mistakes to the log.
