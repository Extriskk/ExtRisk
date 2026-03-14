# Bablu: main JS review → enhancements → re-run → central store

This doc spells out the workflow: Bablu reviews the **main JS files** of unpacked extensions; we apply adjustments/enhancements to the scanner; we **re-run the analyzer**; then we store the **final** result in the central JSON file.

---

## 1. What Bablu reviews: main JS files of the unpacked extension

- **Scope:** The extension’s **main/entry JavaScript (and TypeScript) files** — the code that actually runs as the extension. Not the full tree (e.g. not every file under `node_modules`).
- **How “main” is identified** (for the batch manifest or a small script that lists files for Bablu):
  - **package.json `main`** — e.g. `"main": "./out/extension.js"` (primary entry).
  - **package.json `browser`** — if present (web extension).
  - **Entry points from `contributes`** — e.g. commands, debuggers, or views that reference a script path.
  - **Top-level extension code** — `.js` / `.ts` / `.mjs` in the extension root or in `src/`, `out/`, `dist/` **excluding** `node_modules` and obvious vendor dirs.

**Input for Bablu:**

- HTML/JSON report for the extension (first run, before enhancements).
- Local path to the unpacked extension (from batch manifest).
- List of main JS files for that extension (from package.json + heuristic above), so Bablu can open those files first and compare with the report.

**Process:**

1. Open the unpacked extension folder and the **main JS files** listed for that extension.
2. For each finding in the report that references those files (or any file Bablu chooses to check), go to the cited file/line and decide: **Correct** (TP), **Wrong** (FP or wrong severity), or **Missing** (gap / false negative in main JS).
3. Record mistakes, gaps, and risk-score feedback in e.g. `bablu_review_<extension_id>.json`.

---

## 2. Sequence: review → enhancements → re-run → store final in central JSON

1. **Batch run (first pass)**  
   Run the analyzer on the cohort. Extensions are unpacked; reports (JSON + HTML) are generated; batch manifest records `extension_id` → report paths → extraction path.

2. **Bablu reviews main JS files**  
   Using the manifest, Bablu opens each extension’s unpacked dir and the **main JS files**, compares with the report, and submits review files (corrections, gaps, risk feedback).

3. **Adjustments / enhancements**  
   Dev updates the scanner (detection rules, risk model, false-positive logic) from Bablu’s review and the gap list.

4. **Re-run the analyzer**  
   Run the analyzer again on the same extensions (or cohort) with the updated scanner. This produces the **post-enhancement** report set.

5. **Store final result in central JSON**  
   Write the **final** analysis result (from the re-run) into the central store (one JSON per extension). The API and other products use this as the authoritative record. Optionally tag the record with e.g. `bablu_reviewed: true` or `enhancement_run: true`.

So the **central store is populated only after enhancements and re-run** — it holds the final, improved analysis, not the pre-enhancement first run. The first-run reports stay in `reports/` and in the batch manifest for comparison and for Bablu’s review.

---

## 3. Reference

- Main plan: [VSCODE_MARKETPLACE_VALIDATION_AND_HIGH_FIDELITY_PLAN.md](VSCODE_MARKETPLACE_VALIDATION_AND_HIGH_FIDELITY_PLAN.md) (§7 Bablu review workflow).
