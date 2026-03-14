# Branch: feature/marketplace-validation-api

This branch is used for the **marketplace validation pipeline, central store, API, and cleanup** work. The existing analyzer flow on `main` is **not changed** here; new automation only *calls* the current analyzer.

**Keeping this branch private:** GitHub does not support per-branch visibility. To keep this work private, either (1) **do not push** this branch (keep it local only), or (2) set the **repository** to private (Settings → General → Danger zone → Change repository visibility). Pushing to a private repo keeps all branches private.

## What lives on this branch

- **Batch runner** — runs the analyzer on cohorts, writes manifest (extension_id → report paths → extraction path).
- **Central store** — schema and writer to persist reports (post-enhancement) for API consumption.
- **API service** — REST API (GET report/summary/list, auth, rate limits) reading from central store.
- **Cleanup** — script to delete extracted extension directories after Bablu review to limit local storage.
- **Cohort lists** and batch manifest layout under `data/` or `batch_runs/`.

## What stays on main

- `src/analyzer.py` — existing CLI (Chrome / Edge / VSCode single-extension analysis).
- `src/vscode_analyzer.py`, report generation, VirusTotal, etc. — unchanged; invoked by the batch runner as-is.

## Merging later

When the new pipeline is stable and tested, merge `feature/marketplace-validation-api` into `main`. Until then, use this branch for all marketplace-validation and API work so the existing flow does not break.

## Plan reference

Full plan: [VSCODE_MARKETPLACE_VALIDATION_AND_HIGH_FIDELITY_PLAN.md](VSCODE_MARKETPLACE_VALIDATION_AND_HIGH_FIDELITY_PLAN.md).
