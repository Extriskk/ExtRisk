# VSCode Marketplace Validation & High-Fidelity Plan

**Branch:** All implementation for this plan is done in `feature/marketplace-validation-api` so the existing analyzer flow on `main` is not broken. See [BRANCH_MARKETPLACE_VALIDATION_API.md](BRANCH_MARKETPLACE_VALIDATION_API.md).

**Goal:** Build a baseline of false positives and true positives, automate validation and enhancement, and close gaps so the analyzer becomes high-fidelity. Bablu reviews reports against locally read extension files and drives corrections and risk-score adjustments. Once enhanced, reports are stored in a **central JSON store** and exposed via an **API** for use as a plugin in any product or as a commercial API offering.

---

## 1. Marketplace scale

- **VSCode Marketplace (as of mid-2024):** ~**60,000 extensions**, ~45,000 publishers, ~1,800 verified publishers.
- **Testing “all” extensions** once is feasible only with automation and sampling; full 60K sweep is a long-term target, not a first step.

---

## 2. What is automated vs manual

| Step | Automated? | Notes |
|------|------------|--------|
| Cohort selection (ID lists) | **Semi:** script can fetch/candidate; final lists can be manual. | One-time or per-cohort. |
| **Batch analyze** | **Yes.** Runner loops over cohort, runs analyzer, writes reports + manifest. | Fully automated. |
| **Report validation (TP/FP)** | **Yes.** report_validator reads reports + extension files, outputs baseline JSON. | Runs after batch; needs extraction paths. |
| **Central store write** | **Yes.** After each analysis (and after re-run), upsert report to central store. | Integrated in batch runner or separate job. |
| **API** | **Yes.** Serves data from central store; optional POST /analyze enqueues jobs. | No human in the loop. |
| **Bablu review** | **No.** Human compares report vs local extension files, records mistakes/gaps/risk feedback. | Required for quality; cannot automate. |
| **Enhancement (rules, scoring)** | **Semi.** Dev implements changes from baseline/gap list; re-run and re-validate are automated. | Decision from Bablu; implementation by dev. |
| **Cleanup (delete extension files)** | **Yes.** After review (and validation) is done for an extension, a script deletes its extracted directory to free disk. | See §4.1 below. |

So: **batch run → validation → central store → API** are automated; **Bablu review** and **rule/scoring changes** are manual; **cleanup** runs automatically after review (or on a schedule).

---

## 3. High-level execution plan

| Phase | What | Who / How |
|-------|------|-----------|
| **A. Cohort selection** | Define prioritized extension sets (by installs, verified, random) for batch runs | Script + manual list |
| **B. Batch analyze** | Run analyzer on each cohort; persist JSON + HTML + extracted extension paths | Automated (script) |
| **C. Automated validation** | Run report_validator on last N (or by cohort); get TP/FP/NEEDS_REVIEW per finding | Automated |
| **D. Bablu review** | For each extension: read extracted files locally, compare with report, mark mistakes and gaps | Bablu (manual) |
| **E. Baseline + gap list** | Aggregate TP/FP from validator + Bablu; list detection gaps and scoring issues | Doc + JSON |
| **F. Enhance** | Fix detection rules, risk model, and report logic from baseline and gap list | Dev |
| **G. Iterate** | Re-run cohort, re-validate, compare before/after; expand cohort over time | Automated + Bablu |

---

## 4. Cohort strategy (what to test)

Do **not** try to run 60K extensions in one go. Use stratified cohorts:

1. **High-install cohort**  
   - Top N by install count (e.g. 500–1000).  
   - Goal: most impact; many will be legitimate (good for FP calibration).

2. **Verified publisher sample**  
   - Random sample of extensions from verified publishers (e.g. 200–500).  
   - Goal: expected lower risk; good for FP baseline.

3. **Unverified / low-install**  
   - Random sample of unverified or low-install (e.g. 200–500).  
   - Goal: higher likelihood of suspicious/malicious; good for TP and FN discovery.

4. **Known-bad / CVE list**  
   - Extensions with known CVEs or from threat reports (e.g. Live Server, others).  
   - Goal: ensure we detect and score them correctly (TP baseline).

5. **Bablu “problem set”**  
   - Extensions where Bablu has already found report errors or missing detections.  
   - Goal: close specific gaps and tune scoring.

**Suggested initial total:** ~1,500–2,500 extensions across cohorts. Scale up once the pipeline and review process are stable.

---

## 5. Automation: batch run + extraction

- **Batch runner (to add or script):**
  - Input: list of extension IDs (e.g. `publisher.name`) or a cohort label.
  - For each: `python src/analyzer.py <id> --vscode` (or `--vscode --local <path>` if using unpacked dirs).
  - Save: JSON report, HTML report, and **path to the extracted extension directory** (e.g. under `src/data/extensions/` or a dedicated `batch_runs/<cohort>/<id>/`).
- **Critical:** Persist the **mapping “extension_id → path to extracted files”** (e.g. `batch_runs/<cohort>/manifest.json` or a small DB) so Bablu can open the same folder when reviewing.

Example manifest format:

```json
{
  "cohort": "high_install_500",
  "run_date": "2025-02-21",
  "extensions": [
    {
      "id": "vscode.extension-id",
      "path": "C:/.../batch_runs/high_install_500/vscode.extension-id",
      "report_json": "reports/vscode_..._analysis.json",
      "report_html": "reports/vscode_..._threat_analysis_report.html"
    }
  ]
}
```

### 5.1 Storage and cleanup: delete extension files after review

- **Problem:** Extracted extension directories (full source trees) can be large; keeping 60K of them locally is not feasible.
- **Policy:** Keep extracted files **only until review (and validation) is done** for that extension. After that, **delete the extension directory** and keep only:
  - The **report JSON and HTML** (already under `reports/` or copied into central store).
  - The **central store record** (the report JSON stored for the API).
  - The **batch manifest** with extension_id and **report paths** (no longer extraction path, or mark path as `deleted`).
- **Automation:**
  - **Option A:** Cleanup script that runs after Bablu marks an extension as “reviewed” (e.g. when a `bablu_review_<id>.json` exists or a “reviewed” flag is set in the manifest). Script deletes the directory at `path` for that extension.
  - **Option B:** Scheduled job: delete extraction dirs for all extensions in the manifest that are older than N days (e.g. 14) so Bablu has time to review; or delete only when “reviewed” flag is set.
  - **Option C:** Batch runner writes reports and central store, then **immediately** deletes the extraction dir after each extension (saves space but Bablu cannot review source unless we re-download later). Not recommended if Bablu needs to review; use Option A or B.
- **Recommendation:** Use **Option A**: once Bablu’s review file is submitted for an extension, a cleanup job (or the same script that aggregates reviews) deletes that extension’s extracted directory. Validator can run **before** cleanup (while files still exist); Bablu reviews; then cleanup runs (per extension or in a batch of “reviewed” extensions).
- **Result:** Only reports (and central store) persist; local disk stays bounded. Re-analysis of an extension re-downloads/re-extracts when needed.

---

## 6. Automated validation (report_validator)

- **Existing:** `report_validator.py` loads last N analyzed extensions, loads their reports, and for each finding checks the **actual extension source** (file + line) to classify **TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW**.
- **Usage:**  
  `python report_validator.py --count 50` or `python report_validator.py --id publisher.name`
- **Enhancement for this plan:**
  - Support **cohort-based** validation: e.g. `--cohort high_install_500` so it validates all extensions in that cohort using the same path mapping as the batch run.
  - Output a **per-extension summary** (counts of TP/FP/NEEDS_REVIEW) and an **aggregate baseline file** (e.g. `validation_baseline_<cohort>_<date>.json`) with:
    - Extension ID, report path, extraction path.
    - Per-finding: category, verdict (TP/FP/NEEDS_REVIEW), file, line, reason.
  - This file is the **automated baseline** that Bablu can use to see where the tool is wrong before doing deep review.

---

## 7. Bablu review workflow: main JS files → enhancements → re-run → central store

- **Input for Bablu:**
  - HTML/JSON report for extension X.
  - **Local path to the same extension’s extracted files** (from batch manifest).
- **Process:**
  1. Open the extension folder locally (the same files the analyzer used).
  2. For each finding in the report, go to the cited file/line and decide:
     - **Correct:** Finding is accurate and meaningful (TP, or acceptable severity).
     - **Wrong:** Finding is wrong or misleading (FP, or wrong category/severity).
     - **Missing:** Code shows a real issue the tool did **not** report (gap / false negative).
  3. Record:
     - **Mistakes:** Finding ID/category + correction (e.g. “FP: library code”, “Severity should be LOW”).
     - **Gaps:** Description of what the tool missed (pattern, file, line) so we can add or adjust detection.
     - **Risk score:** Whether the overall risk score/level for this extension was too high or too low and why (e.g. “vuln-only extension should be at least MEDIUM”, “too many FP so score inflated”).

- **Output (to feed enhancement):**
  - **Per-extension review file** (e.g. `bablu_review_<extension_id>.json` or a shared sheet) with:
    - List of corrections (finding → correct verdict/severity).
    - List of gaps (missing detection + location).
    - Risk score feedback (expected vs actual; suggested rule change).
  - Optional: Bablu adds short comments in the report or in a separate “Bablu notes” section for the most important cases.

**Main JS focus and central store timing:** Bablu reviews the **main JS files** of the unpacked extension (entry points from package.json / contributes). After Bablu review, we do **scanner adjustments/enhancements**, then **re-run the analyzer** on the same extensions; the **final** result (from the re-run) is stored in the **central JSON** store. So: review main JS → enhancements → re-run → store final in central file. See [BABLU_MAIN_JS_REVIEW_AND_CENTRAL_STORE.md](BABLU_MAIN_JS_REVIEW_AND_CENTRAL_STORE.md) for the full sequence.

---

## 8. Baseline: false positives and true positives

- **Automated baseline:** From `report_validator` (TP/FP/NEEDS_REVIEW per finding, per extension).
- **Human baseline:** From Bablu’s reviews (corrected verdicts, gaps, risk-score adjustments).
- **Single baseline file (or DB):**
  - For each extension: extension_id, cohort, report paths, extraction path.
  - For each finding: category, automated_verdict, bablu_verdict (if reviewed), bablu_notes.
  - For each extension: risk_score_reported, risk_score_bablu_suggested, gap_summary.
- **Metrics to track over time:**
  - Precision: TP / (TP + FP) per category and overall.
  - Recall: TP / (TP + FN) where FN = gaps Bablu found.
  - Risk score alignment: how often Bablu agrees with risk level (or delta).

---

## 9. Risk scoring and model changes

- Current behavior (see `vscode_analyzer.py`): Supply chain (e.g. vuln deps, Retire) can contribute up to 5/10; metadata/code/behavior/infra contribute the rest; vulnerable deps can set a MEDIUM floor.
- **Based on Bablu’s review we may need to:**
  - Change weights (e.g. activation events, contributes, code patterns).
  - Add a **stricter floor** when certain high/critical dependency or bundled-JS vulns exist (so “vuln-only” extensions don’t show LOW).
  - Cap or reduce contribution of categories that often produce FP (e.g. certain storage or DOM patterns).
- **Process:**
  1. Collect Bablu’s risk-score feedback in the baseline (expected vs actual, per extension).
  2. Identify recurring themes (e.g. “vuln-only → always at least MEDIUM”, “obfuscation without exfil → cap at HIGH”).
  3. Propose concrete rule/weight changes in the risk model and document them (e.g. in this doc or `docs/RISK_SCORING_MODEL.md`).
  4. Implement, re-run the same cohort, and compare scores before/after; iterate with Bablu.

---

## 10. Closing detection gaps (Bablu → detection library)

- **Gaps** = issues Bablu finds in the code that the tool did **not** report (false negatives).
- **Flow:**
  1. Bablu records each gap with: extension ID, file, line (or snippet), and a short description of the pattern or behavior.
  2. We maintain a **gap log** (e.g. `docs/DETECTION_GAPS_LOG.md` or `data/gaps_from_bablu.json`) with:
     - Pattern/behavior description.
     - Example file/line or snippet.
     - Status: open / in progress / closed (with rule ID or PR).
  3. For each “open” gap we:
     - Decide if it’s in scope (e.g. new pattern in detection_rules.json or vscode_analyzer patterns).
     - Add or adjust the detection rule; add tests if possible (e.g. fixture extension that triggers the pattern).
     - Mark gap as closed and note the rule/finding name.
  4. Re-run the extension that had the gap and confirm the new finding appears and is classified correctly (TP).

**Note for Bablu:** When you review an extension’s local files and compare with the report, please explicitly list **gaps**: any suspicious or malicious pattern you see in the code that the tool did **not** flag. Those gap entries are the input we use to extend and fix the detection library so the analyzer catches them in future runs.

---

## 11. Central report store and API (product / commercial use)

Once each extension’s report is enhanced (and optionally Bablu-reviewed), store it in a **central store** and expose it via an **API** so any product can consume it (plugin, IDE, marketplace, internal tools) and the API can be offered as a commercial product.

### 11.1 Central JSON store

- **What:** A single, queryable store of **final** (post-enhancement) analysis reports per extension.
- **When to write:** After an extension is analyzed (and optionally after Bablu review / re-run), **upsert** that extension’s report into the central store.
- **Schema (per record):**
  - `extension_id` (e.g. `publisher.name`), `platform` (`vscode` / `chrome` / `edge`), `version_analyzed`.
  - `analyzed_at`, `enhancement_version` (or `report_schema_version`).
  - Full analysis payload: risk_score, risk_level, findings (by layer), supply_chain, virustotal_results, etc. (same structure as current JSON report, or a normalized subset).
  - Optional: `bablu_reviewed_at`, `validation_verdict` (e.g. TP/FP summary), `source` (batch cohort / on-demand).
- **Storage options:**
  - **File-based:** One JSON file per extension under a known layout (e.g. `central_store/vscode/publisher/name.json`) or a single large JSON array/NDJSON file with an index by extension_id. Simple to start; use for MVP.
  - **Database:** SQLite or PostgreSQL with a `reports` table (extension_id, platform, version_analyzed, json_payload, timestamps). Better for API querying, filtering, and scaling. Migrate when API usage grows.

### 11.2 API design (for plugin and product integration)

- **Purpose:** Let any product (IDE, marketplace, security dashboard, CI) look up extension risk and findings by ID; support “plug-in” integration and future commercial offering.
- **Suggested endpoints (REST):**
  - `GET /api/v1/report/{platform}/{extension_id}` — Return the latest stored report for that extension (JSON). Optional query: `?version=1.2.3` for a specific analyzed version.
  - `GET /api/v1/report/{platform}/{extension_id}/summary` — Lightweight summary (risk_score, risk_level, finding counts) for list views or badges.
  - `GET /api/v1/reports` — List/browse (optional: filter by platform, risk_level, cohort). Pagination (e.g. `?limit=50&offset=0`).
  - `POST /api/v1/analyze` (optional) — Trigger on-demand analysis for an extension (async job); return job_id. Poll `GET /api/v1/job/{job_id}` for completion; then fetch report. Useful for “analyze and then serve from store.”
- **Auth (for commercial / controlled use):**
  - API key in header (e.g. `Authorization: Bearer <key>` or `X-API-Key: <key>`). Different keys for different customers or tiers.
  - Optional: rate limits per key (e.g. 100 req/min for free tier, higher for paid).
- **Plugin use case:** A product (e.g. IDE, marketplace UI) calls `GET /report/{platform}/{extension_id}` or `/summary` and displays risk badge, link to full report, or blocks installation based on policy. The API is the “plugin” contract.

### 11.3 Integration with the enhancement pipeline

- After **batch analyze** or **on-demand analyze**: write or update the extension’s record in the central store.
- After **Bablu review** and any **re-run**: update the same record (e.g. add `bablu_reviewed_at`, optional overrides or corrected findings if you store them).
- The API **only reads** from the central store; it does not run the analyzer itself (unless you expose `POST /analyze` and then store the result).

Add to the plan:
- Implement **central store writer** (script or service) that, after the **post-enhancement re-run** (and optionally after on-demand analyze), upserts the **final** report into the central store. Do not write the first-run report to the central store; only the result after Bablu review and scanner enhancements.
- Implement **API service** (e.g. FastAPI/Flask) that reads from the central store and exposes the endpoints above; add API key auth and rate limiting for commercial readiness.

---

## 12. Suggested file layout

```
docs/
  VSCODE_MARKETPLACE_VALIDATION_AND_HIGH_FIDELITY_PLAN.md   # this file
  DETECTION_GAPS_LOG.md                                     # open/closed gaps from Bablu
  RISK_SCORING_MODEL.md                                     # current + proposed rules (optional)

data/ or batch_runs/
  cohorts/
    high_install_500.json                                   # list of extension IDs
    verified_sample_200.json
    unverified_low_install_200.json
  batch_manifest_<cohort>_<date>.json                      # id → report paths, extraction path
  validation_baseline_<cohort>_<date>.json                  # validator TP/FP/NEEDS_REVIEW
  bablu_reviews/                                            # per-extension review files
  gaps_from_bablu.json                                      # structured gap list (optional)

central_store/                                              # post-enhancement report store (API backend)
  vscode/
    publisher/
      name.json                                             # one JSON per extension (or DB later)
  index.json                                                # optional: extension_id → path or cursor

api/                                                        # API service (e.g. FastAPI)
  main.py                                                   # endpoints, auth, rate limits
  requirements-api.txt
```

---

## 13. Step-by-step execution with time estimates

Rough estimates assume one developer plus Bablu for review; adjust if team size or scope changes.

| Step | Task | Rough time |
|------|------|-------------|
| **1** | Define cohorts: high-install, verified sample, unverified/low-install, known-bad, Bablu problem set. Produce cohort JSON files (extension ID lists). | **1–2 days** |
| **2** | Implement batch runner: loop over cohort, run analyzer per extension, persist JSON/HTML and extraction path; output batch manifest (extension_id → report paths → extraction path). | **3–5 days** |
| **3** | Run batch on first cohort (e.g. 200–500 extensions); fix runner/analyzer issues; confirm central output layout. | **2–3 days** (mostly compute + 1 day fix) |
| **4** | Extend report_validator: cohort-based validation, output validation_baseline JSON (TP/FP/NEEDS_REVIEW per finding). | **2–3 days** |
| **5** | Document Bablu workflow: how to get extraction path per report, how to submit corrections + gaps + risk feedback (template or form). | **0.5–1 day** |
| **6** | Bablu reviews first batch (e.g. 50–100 extensions): compare report vs local files, record mistakes, gaps, risk feedback. | **1–2 weeks** (depends on Bablu’s bandwidth) |
| **7** | Create baseline aggregate: merge validator output + Bablu reviews; create DETECTION_GAPS_LOG and risk-feedback summary. | **1–2 days** |
| **8** | Enhance detection and scoring: fix rules from baseline, implement risk-model changes (weights/floors), add tests for closed gaps. | **1–2 weeks** |
| **9** | Re-run same cohort; re-validate; compare metrics (precision/recall, score alignment). Iterate with Bablu on borderline cases. | **3–5 days** |
| **10** | Define central store schema and layout (file-based MVP: one JSON per extension under central_store/). | **0.5–1 day** |
| **11** | Implement central store writer: after each analysis (and optionally after Bablu review/re-run), upsert report into central_store. Integrate with batch runner and (optional) manual “ingest report” script. | **2–3 days** |
| **12** | Implement API service: FastAPI/Flask, GET /report/{platform}/{extension_id}, GET /report/.../summary, GET /reports (list) with pagination; read from central store. | **3–5 days** |
| **13** | Add API auth (API key) and rate limiting; document API for plugin/product integration. | **1–2 days** |
| **14** | Optional: POST /analyze for on-demand analysis, job queue, then store result and expose via GET /report. | **3–5 days** |
| **15** | Implement cleanup: script to delete extracted extension directories after Bablu review (or after N days). Frees local disk; keep only reports + central store. | **1–2 days** |
| **16** | Scale cohort (e.g. 1,500–2,500 extensions); repeat batch → validate → Bablu sample → cleanup → enhance → re-run. Ongoing: add new extensions to central store and expose via API. | **Ongoing (weeks/months)** |

**Rough total to “first usable pipeline + API”:**  
- **Without** on-demand analyze: **~4–6 weeks** (steps 1–13).  
- **With** cleanup + on-demand analyze and polish: **~6–8 weeks** (steps 1–15, 16 ongoing).

**Time to build API vs populate with "all" extensions:**
- **API build (code only):** Steps 10–13 → **~1–1.5 weeks** for a working API reading from central store.
- **API with initial cohort (1.5–2.5K):** Batch + store write. At ~2–5 min/extension, **~3–10 days** compute (parallelizable). **End-to-end API + first cohort: ~5–7 weeks.**
- **API with full 60K extensions:** At 2 min/extension single-threaded ≈ **83 days**; with ~10 workers at 1 min/extension ≈ **4–5 days** wall-clock. **Populating all 60K: ~1 week to ~3 months** depending on parallelism. Build API first; populate in cohorts; scale to 60K when pipeline and cleanup are stable.

---

## 14. Summary checklist

- [ ] Define cohorts (high-install, verified sample, unverified/low-install, known-bad, Bablu problem set).
- [ ] Implement or script batch run that records extension_id → report paths → extraction path.
- [ ] Extend report_validator to support cohort-based validation and output baseline JSON.
- [ ] Document for Bablu: how to get the extraction path for each report and how to submit corrections + gaps + risk feedback.
- [ ] Create DETECTION_GAPS_LOG (or equivalent) and process to close gaps (rule + test + re-run).
- [ ] Collect risk-score feedback from Bablu and iterate on risk scoring model.
- [ ] Re-run cohorts after changes and track precision/recall and score alignment over time.
- [ ] Define central store schema; implement writer so each (enhanced) report is stored in a central JSON store.
- [ ] Build API (GET report/summary/list) reading from central store; add API key auth and rate limiting for product/plugin and commercial use.
- [ ] Optional: on-demand analyze endpoint (POST /analyze) and job completion → store → serve via API.
- [ ] Automate cleanup: delete extracted extension files after Bablu review (or after N days) to limit local storage; keep only reports and central store.
- [ ] Optional: orchestrate with n8n (schedule batch → validate → central store → notify; cleanup; API calls). See §15.

This plan keeps the human (Bablu) in the loop for quality while automating batch analysis, validation, and cleanup; reports are stored in a central store and served via API for plugin or commercial use. n8n can orchestrate these automated steps (see §15).

---

## 15. Automating the workflow with n8n

Yes — you can use **n8n** to orchestrate the validation and enrichment pipeline. n8n can trigger scripts, call your API, run on a schedule, and chain steps so the workflow runs end-to-end with minimal manual runs.

### What n8n can do in this pipeline

| Step | How in n8n | Notes |
|------|------------|--------|
| **Run batch analyze** | **Execute Command** node: run `python scripts/batch_run_vscode.py data/cohorts/<cohort>.json --skip-vt` (or with `--limit`). Use the repo path as working directory. | Long-running; consider **Schedule** trigger (e.g. nightly) or **Webhook** to start on demand. |
| **Run report_validator** | **Execute Command** node: `python src/report_validator.py --cohort <cohort>` (once cohort support exists) or `--count 50`. Run after batch completes. | Chain after batch in the same workflow or a separate “validation” workflow. |
| **Write to central store** | Either (a) **Execute Command** for a “central store writer” script that reads `batch_runs/` manifest and upserts reports, or (b) **HTTP Request** to your API’s `POST /ingest` if you add one. | Fits after batch (and optionally after Bablu review). |
| **Cleanup (delete extension dirs)** | **Execute Command** node: run the cleanup script (e.g. `python scripts/cleanup_after_review.py --cohort X` or `--manifest batch_runs/...`). | Run on a schedule (e.g. weekly) or after “review complete” webhook. |
| **Call the API** | **HTTP Request** node: GET report/summary/list with API key in headers. Use for dashboards, other tools, or to check that the store is populated. | Read-only; no script needed. |
| **On-demand analyze** | **Webhook** trigger → **HTTP Request** to your API `POST /analyze` with `extension_id` → poll or webhook callback for completion → **HTTP Request** GET report. | When API supports async analyze. |
| **Notify / handoff to Bablu** | After batch: **Slack/Email/Discord** node with manifest path and “review these extensions” message. Or **Google Sheets** with extension IDs and report links for Bablu to mark reviewed. | Human-in-the-loop; Bablu uses manifest to open local paths. |

### Example n8n workflow (high level)

1. **Trigger:** Schedule (e.g. “Every Monday 2am”) or Webhook (e.g. “Run cohort X”).
2. **Execute Command:** Run batch runner for a cohort; capture stdout/stderr (and exit code) for logging.
3. **IF** batch succeeded (exit code 0): **Execute Command** run report_validator for that cohort.
4. **Execute Command** (or HTTP): Run central store writer so new/updated reports are in the store.
5. **Optional:** Send notification (Slack/email) with “Batch done; manifest at …” and link to batch_runs manifest for Bablu.
6. **Separate workflow (or same, on another schedule):** Run cleanup script for “reviewed” extensions to free disk.

### Requirements for n8n

- **Worker with access to the repo:** The machine (or container) where n8n runs must have the repo cloned, `pip install -r requirements.txt`, `npm install`, and (if used) config e.g. VirusTotal API key. So either run n8n on the same host as the repo or mount the repo into the n8n runner.
- **Execute Command node:** Needs permission to run shell commands and the correct working directory (repo root). Use **Execute Command** with command e.g. `python scripts/batch_run_vscode.py data/cohorts/sample_small.json` and **cwd** = repo path.
- **API (optional but useful):** Once the API exists, use **HTTP Request** for reads and (if you add it) for triggering analyze or ingest; no need to shell out for those.

### Summary

Use n8n to **schedule or trigger** the batch runner and validator, **chain** them (batch → validate → central store write), **run cleanup** on a schedule or after review, and **call the API** for reads or on-demand analyze. Bablu review stays manual; n8n handles the automated steps and handoff (e.g. “batch done, please review these IDs”).

---

## Note for Bablu

When you review reports against the **locally extracted extension files**:

1. **Compare report ↔ code**  
   For each finding, open the cited file/line and decide: correct (TP), wrong (FP), or wrong severity/category. Record corrections so we can fix the detection logic and reduce FPs.

2. **Find gaps (false negatives)**  
   Look for **suspicious or malicious patterns in the code that the tool did not report**. Document each gap (extension ID, file, line/snippet, and what pattern or behavior is missing). These gaps drive updates to the detection library (rules, patterns, correlations) so we close them in future runs.

3. **Risk score feedback**  
   Note when the overall risk score/level feels too high or too low (e.g. “vuln-only should be at least MEDIUM”, “too many FP inflating score”). Your feedback will be used to adjust the risk scoring model and weights.

Your review is the main input for making the tool high-fidelity: fixing mistakes, adding missing detections, and calibrating risk scores.
