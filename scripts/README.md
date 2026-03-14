# Marketplace validation pipeline scripts

This folder contains automation for the **marketplace validation + API** flow (branch `feature/marketplace-validation-api`). The existing analyzer in `src/analyzer.py` is not modified; these scripts call it.

## Fetch recent extensions (cohort from marketplace)

- **`fetch_recent_vscode_extensions.py`** — Fetches recently updated VSCode extensions from the **VS Marketplace** API and writes a cohort JSON. Uses `lastUpdated` to pick the N most recently updated. For extensions that exist only on **Open VSX** (e.g. some themes), run the analyzer directly: `python src/analyzer.py publisher.extension-name --openvsx`.

```bash
# Default: 10 extensions -> data/cohorts/recent_10.json
python scripts/fetch_recent_vscode_extensions.py

# Custom count and output path
python scripts/fetch_recent_vscode_extensions.py --count 20 --out data/cohorts/recent_20.json
```

---

## Batch runner

- **`batch_run_vscode.py`** — Runs the analyzer on each extension in a cohort and writes a manifest (extension_id → report paths, extraction path) for Bablu review and for report_validator.

### Usage (from repo root)

```bash
# Run full cohort (default: reports to reports/, manifest to batch_runs/)
python scripts/batch_run_vscode.py data/cohorts/sample_small.json

# Parallel workers (faster): run 4 analyses at once
python scripts/batch_run_vscode.py data/cohorts/recent_10.json --workers 4 --fast

# Skip VirusTotal to speed up
python scripts/batch_run_vscode.py data/cohorts/sample_small.json --skip-vt

# Fast mode (skip VT and OSINT)
python scripts/batch_run_vscode.py data/cohorts/sample_small.json --fast

# Limit to first N extensions (e.g. 2 for a quick test)
python scripts/batch_run_vscode.py data/cohorts/sample_small.json --limit 2
```

**Parallel runs:** Use `--workers N` (e.g. 4–6) to run N extensions in parallel. When `--workers > 1`, analyzer stdout/stderr are suppressed so only batch progress is shown. This significantly reduces wall-clock time for large cohorts.

### Cohorts

Cohort JSON files live in `data/cohorts/`. Format:

```json
{
  "name": "sample_small",
  "description": "Optional description",
  "extension_ids": ["publisher.name1", "publisher.name2"]
}
```

Example: `data/cohorts/sample_small.json` (5 extensions for testing).

### Output

- **Reports:** `reports/vscode_<id>_analysis.json` and `reports/vscode_<id>_threat_analysis_report.html` (created by the analyzer).
- **Extraction:** `data/vscode_extensions/<id>-<version>/extension/` (created by the unpacker used inside the analyzer).
- **Manifest:** `batch_runs/batch_manifest_<cohort>_<date>.json` — lists each extension with `report_json`, `report_html`, `extraction_path` for Bablu and for the validator.

---

## List main JS (for Bablu)

- **`list_main_js.py`** — Lists main/entry JavaScript and TypeScript files for a VSCode extension (from package.json `main`/`browser`, contributes, and top-level src/out/dist). Use this to know which files Bablu should open first.

```bash
# By extraction path
python scripts/list_main_js.py --path data/vscode_extensions/dbaeumer.vscode-eslint-3.0.21/extension

# By manifest + extension ID
python scripts/list_main_js.py --from-manifest batch_runs/batch_manifest_sample_small_2026-02-21.json --id dbaeumer.vscode-eslint

# Full JSON output
python scripts/list_main_js.py --from-manifest batch_runs/... --id dbaeumer.vscode-eslint --json
```

---

## Central store writer

- **`central_store_writer.py`** — Ingests analysis report(s) into `central_store/vscode/<safe_id>.json`. **Run after the post-enhancement re-run** (not the first run) so the central store holds the final, improved analysis. Optional: use after on-demand analyze.

```bash
# Ingest one report
python scripts/central_store_writer.py --report reports/vscode_dbaeumer.vscode-eslint_analysis.json

# Ingest all reports from a batch manifest (e.g. after re-run)
python scripts/central_store_writer.py --manifest batch_runs/batch_manifest_sample_small_2026-02-21.json

# Only successful extensions
python scripts/central_store_writer.py --manifest batch_runs/... --only-success
```

---

## Cleanup after review

- **`cleanup_after_review.py`** — Deletes extracted extension directories for extensions that have a Bablu review file (`bablu_review_<extension_id>.json` in the review dir). Frees disk; reports and central store are kept.

```bash
# Default review dir: batch_runs/bablu_reviews
python scripts/cleanup_after_review.py --manifest batch_runs/batch_manifest_sample_small_2026-02-21.json

# Custom review dir
python scripts/cleanup_after_review.py --manifest batch_runs/... --review-dir batch_runs/bablu_reviews

# Preview only
python scripts/cleanup_after_review.py --manifest batch_runs/... --dry-run
```

Create `batch_runs/bablu_reviews/` and place `bablu_review_<extension_id>.json` (or `bablu_review_<safe_id>.json`) there after each review so cleanup can find them.

**Automated first pass (Bablu review run):**

- **`bablu_review_run.py`** — For each extension in the manifest: loads the report, gets main JS list, filters code findings to main JS / dist/out/src, verifies each finding against source (evidence at cited line), and writes `batch_runs/bablu_reviews/bablu_review_<id>.json` with verdicts (TP/FP/NEEDS_REVIEW). Add corrections, gaps, and risk_score_feedback manually or in a second pass.

```bash
# Review all successful extensions in manifest
python scripts/bablu_review_run.py --manifest batch_runs/batch_manifest_recent_10_2026-02-22.json

# Single extension
python scripts/bablu_review_run.py --manifest batch_runs/... --id ms-python.isort
```

After the run, **cohort summary** files are written to the same directory:
- `review_summary_<cohort>_<date>.json` — totals and per-extension counts (TP/FP/NEEDS_REVIEW, risk).
- `review_summary_<cohort>_<date>.md` — same in Markdown table form.

Each per-extension review JSON now includes `metadata_findings`, `supply_chain_findings`, and `package_json_deep_findings` for full Bablu review. Verification uses FP rules from `docs/DETECTION_GAPS_LOG.md` (e.g. method-call eval, hex-only base64, allowlisted domains).

---

## Workflow (end-to-end)

1. **Batch run (first pass)**  
   `python scripts/batch_run_vscode.py data/cohorts/sample_small.json`  
   → Reports in `reports/`, extraction in `data/vscode_extensions/`, manifest in `batch_runs/`.

2. **Bablu reviews main JS**  
   Use manifest `extraction_path` and `python scripts/list_main_js.py --from-manifest <manifest> --id <id>` to get main JS files. Compare report vs code; record corrections, gaps, and risk feedback in `batch_runs/bablu_reviews/bablu_review_<id>.json`.

3. **Enhancements**  
   Dev updates scanner from Bablu’s review and `docs/DETECTION_GAPS_LOG.md`.

4. **Re-run analyzer**  
   Run the same cohort again with the updated scanner: `python scripts/batch_run_vscode.py data/cohorts/sample_small.json` (same or new manifest).

5. **Write central store**  
   `python scripts/central_store_writer.py --manifest batch_runs/batch_manifest_<cohort>_<date>.json --only-success`  
   → Final reports in `central_store/vscode/<safe_id>.json`.

6. **Cleanup (optional)**  
   After Bablu has reviewed and you no longer need extracted source:  
   `python scripts/cleanup_after_review.py --manifest batch_runs/...`  
   → Deletes extraction dirs for extensions that have a review file; keeps reports and central store.

Plan: `docs/VSCODE_MARKETPLACE_VALIDATION_AND_HIGH_FIDELITY_PLAN.md`. Bablu workflow: `docs/BABLU_MAIN_JS_REVIEW_AND_CENTRAL_STORE.md`.
