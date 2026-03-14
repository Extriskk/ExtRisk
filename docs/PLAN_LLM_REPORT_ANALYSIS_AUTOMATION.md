# Plan: Automate LLM Analysis of Report API Output (Free, 2k Extensions/Month)

**Goal:** Periodically run a job that (1) reads reports from the Report API (or DB), (2) sends a summary to a free LLM for analysis, (3) stores the AI analysis in a separate DB and exposes it to users.

**Constraints:** Fully free automation; total target 2,000 extensions per month; no hard time limit (throughput can be slow).

---

## 1. Context from Brain.md

- **Report API (Brain §4):** Reports are stored in `ScanResult.report_json` / `report_html`. Served by:
  - `GET /api/v1/reports/{job_id}` and `.../html`, `.../full`
  - `GET /api/v1/reports/by-extension/{extension_id}` and `.../html`, `.../full`
- **Source of reports:** Either from the API (existing scans) or from batch runs (e.g. `scripts/batch_run_vscode.py`) that produce reports on disk, then imported via `scripts/import_reports_to_db.py`.
- **Existing LLM usage:** `src/ollama_analyzer.py` already uses **Ollama** (local, free) to produce a short security assessment from manifest + code excerpts + a one-line findings summary. It uses a bounded context (~32k chars) and a fixed prompt. No API key or cost.
- **Batch/scripts (Brain §6):** Cohort-driven batch runs, Bablu review, central store. A “periodic job” fits here: a script that iterates over extensions (from cohort or from “extensions that have a report but no LLM analysis”), calls the Report API or DB, then LLM, then writes to the new store.

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Report API / DB (existing)                                              │
│  • ScanResult.report_json, report_html per extension                     │
│  • GET by extension_id or job_id                                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Periodic job (new script, e.g. scripts/llm_report_analysis_job.py)      │
│  1. List extensions to process (cohort file OR “report exists, no AI”)   │
│  2. For each: fetch report (API or DB), build prompt-sized summary      │
│  3. Call free LLM (Ollama preferred; optional: free cloud API)           │
│  4. Write result to “AI analysis” store                                  │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  AI analysis DB (new)                                                    │
│  • One row per extension (or per report version):                        │
│    extension_id, source_report_id, model_used, analysis_text, created_at│
│  • Served to users via new API route or same API (e.g. GET .../ai)      │
└─────────────────────────────────────────────────────────────────────────┘
```

- **No execution:** This doc is planning only; no code or commands are run.

---

## 3. Free LLM Options (Prioritized)

| Option | Cost | Rate limit | Best for |
|--------|------|------------|----------|
| **Ollama (local)** | Free | Your CPU/GPU only | 2k/month at your own pace; no account, no quotas. |
| **OpenAI free tier** | Free (with caps) | Low RPM/TPM (e.g. 3–20 RPM); check platform | If you want cloud and can stay under limits. |
| **Groq free tier** | Free | Generous free tier | Fast inference; good if you add a second provider. |
| **Google AI Studio / Gemini free** | Free (with caps) | Per-day limits | Alternative cloud option. |

**Recommendation for “whole automation free” and “don’t care about time”:** Use **Ollama** as the primary engine. It’s already in the repo (`src/ollama_analyzer.py`), runs locally, and has no rate limits beyond your machine. Optional: add a small adapter for one free cloud API (e.g. Groq or OpenAI free tier) as a fallback or for testing.

---

## 4. Report Size and Prompt Design

- Full report JSON from the API can be **very large** (e.g. 1–3 MB+ per extension). Most free APIs have context windows of ~4k–128k tokens; sending the full report is not feasible.
- **Approach:** Build a **fixed-size summary** for the LLM (similar in spirit to `_findings_summary` in `ollama_analyzer.py`):
  - From report JSON: `extension_id`, `name`, `version`, `risk_score`, `risk_level`, `threat_classification`, BLUF/summary if present, and a **truncated list of findings** (e.g. top 20–30 by severity, with category and short description).
  - Optional: 1–2 paragraphs of key findings text from the HTML report (e.g. “Key findings” section only).
  - Cap total prompt size (e.g. 8k–16k characters for Ollama; 4k for strict free APIs) so every extension fits and you stay within free tiers.
- The prompt can ask the LLM to: (1) summarize risk in plain language, (2) highlight the most important concerns, (3) give 2–4 concrete recommendations. Output format: plain text or a small JSON (e.g. `{ "summary", "main_risks", "recommendations" }`) for easier storage and display.

---

## 5. New “AI Analysis” Store

- **Option A (simplest):** Same DB as the API; new table e.g. `llm_analysis`:
  - `id`, `extension_id`, `scan_result_id` (FK to `ScanResult`, nullable), `model_used`, `prompt_version`, `analysis_text` (or JSON), `created_at`.
  - One row per “run” so you can re-run and keep history if desired.
- **Option B:** Separate DB (e.g. SQLite `ai_analysis.db`) so the main API stays unchanged and you can back up or migrate the AI store independently.
- **Serving to users:** New endpoint(s), e.g.:
  - `GET /api/v1/reports/by-extension/{extension_id}/ai` → latest AI analysis for that extension.
  - `GET /api/v1/ai-analysis/{extension_id}` → same, or list of analyses with timestamps.
- Stored content: **analysis_text** (and optionally structured JSON) so the UI can show “AI summary” next to the raw report.

---

## 6. Periodic Job Design

- **Trigger:** Cron (Linux/macOS) or Task Scheduler (Windows) or a simple loop script that runs “N times per day” (e.g. every 6 hours, process 50–100 extensions per run). No paid queue needed.
- **Input list:** Either:
  - A **cohort file** (e.g. `data/cohorts/llm_analysis_2k.json`) with 2k extension IDs, or
  - Query **DB**: “extensions that have at least one `ScanResult` but no row in `llm_analysis`” (or no row for the latest scan). This keeps the job “catch-up” style: process any extension that has a report but not yet an AI analysis.
- **Idempotency:** Skip or update: if “one analysis per extension” is enough, skip when a row exists; if you want “one per report version”, use `scan_result_id` and allow multiple rows per extension.
- **Error handling:** If LLM call fails (timeout, rate limit, crash), log and continue; optionally write a row with `analysis_text = NULL` and `error_message` so you can retry later.
- **No execution:** This is design only; implementation is a separate step.

---

## 7. Time Estimate: 2,000 Extensions in One Month

- **Target:** 2,000 extensions / 30 days ≈ **67 extensions/day**.
- **Ollama (local):** Assume 1–3 minutes per extension (build summary + LLM call + DB write).  
  - 67 × 2 min ≈ **134 minutes/day** (~2.2 hours).  
  - 67 × 3 min ≈ **201 minutes/day** (~3.4 hours).  
  - So: **about 2–3.5 hours of compute per day** over 30 days, or run overnight in a single long batch (e.g. 67 × 3 min ≈ 3.35 hours per run).
- **Free cloud API:** If the free tier allows e.g. 20 RPM, then 67 requests/day is trivial (under 4 minutes of API time); the bottleneck is your script and any rate limits. So **wall-clock time can be well under 1 hour/day** if you stay within limits and token caps.

**Summary:** With Ollama, **2k extensions in a month is feasible at ~2–3.5 hours of compute per day** (or equivalent in overnight batches). With a free cloud API, **time can be under an hour per day** depending on rate limits and context size.

---

## 8. Implementation Checklist (When You Build It)

- [ ] **DB:** Add table `llm_analysis` (or new DB + schema). Migration or create script.
- [ ] **Report summary builder:** Function that, given full report JSON (or API summary), produces a prompt-sized string (e.g. 4k–16k chars) with extension_id, name, risk, main findings.
- [ ] **LLM client:** Reuse/extend `ollama_analyzer` for Ollama; optional thin adapter for one free cloud API (e.g. Groq/OpenAI free) with same prompt interface.
- [ ] **Job script:** `scripts/llm_report_analysis_job.py`: read cohort or “extensions with report, no AI”; for each, fetch report (API or DB), build summary, call LLM, write to `llm_analysis`.
- [ ] **API:** New route(s) to return latest (or list of) AI analysis by `extension_id`; optionally include in report by-extension response.
- [ ] **Scheduling:** Cron or Task Scheduler to run the job at desired frequency (e.g. every 6 h or once per day).
- [ ] **Docs:** Update Brain.md §4 (API) and §6 (scripts) and AI_CONTEXT.md with “LLM report analysis job” and “AI analysis store”.

---

## 9. Summary

| Item | Suggestion |
|------|------------|
| **Source** | Report API (by extension_id) or direct DB read of `ScanResult.report_json`. |
| **LLM** | **Ollama** (free, no rate limit; already in repo). Optional: one free cloud API. |
| **Input to LLM** | Truncated summary from report (risk, BLUF, top findings), not full JSON. |
| **New store** | Table `llm_analysis` (or separate DB) keyed by extension_id (+ optional scan_result_id). |
| **User-facing** | New API endpoint(s) to get “AI analysis” for an extension (e.g. `/reports/by-extension/{id}/ai`). |
| **Automation** | Cron/Task Scheduler; run script that processes “report exists, no AI” or a cohort of 2k. |
| **Time for 2k/month** | **~2–3.5 hours compute per day** with Ollama; less with free cloud if within limits. |

This keeps the whole pipeline **free** and meets the **2k extensions in a month** target with slow-but-steady automation.

---

## 10. Cost: All Chrome Web Store Extensions in 1 Month

If the goal is to run LLM analysis for **every extension in the Chrome Web Store** and finish in **one month**, the scale and cost look like this.

### Scale

- **Chrome Web Store size:** ~**150,000–160,000** extensions (2024–2025 estimates; themes excluded).
- **Throughput needed:** 160,000 / 30 days ≈ **5,333 extensions/day** (or ~3.7 per minute if spread 24/7).

### Token assumptions (per extension)

- **Input to LLM:** Truncated report summary ≈ 1,500 tokens (~6k chars).
- **Output:** Short assessment (2–4 paragraphs) ≈ 500 tokens.
- **Total per extension:** ~2,000 tokens (in + out).

---

### Option A: Ollama (local) — $0 API cost

- **API cost:** **$0** (no cloud LLM).
- **Time:** At ~2 min per extension: 160,000 × 2 min = **320,000 minutes** ≈ **5,333 hours** of compute.
- **In one month (720 hours):** You’d need **5,333 / 720 ≈ 7.4** workers running 24/7 (e.g. 8 machines or 8 parallel processes on a big machine).
- **“Cost”:**  
  - **Electricity (rough):** 8 × 200 W × 720 h ≈ 1,150 kWh. At ~$0.12–0.15/kWh → **~$140–175** for the month.  
  - **Cloud VMs (if you don’t have 8 machines):** 8 small VMs × 720 h × ~$0.01–0.02/h → **~$60–120** for the month (varies by provider and region).
- **Summary:** **~$140–175 electricity** (own hardware) or **~$60–120** (cloud VMs); **no LLM API cost**. You must run ~8 workers in parallel to finish in 1 month.

---

### Option B: OpenAI API (GPT-4o mini) — paid tier

- **Pricing (typical):** Input $0.15 / 1M tokens, output $0.60 / 1M tokens.
- **Input:** 160,000 × 1,500 = 240M tokens → 240 × $0.15 = **$36**.  
- **Output:** 160,000 × 500 = 80M tokens → 80 × $0.60 = **$48**.  
- **Total LLM cost:** **~$84** for 160k extensions.
- **Rate limits:** Free tier is too low for 5,333 requests/day. You need a **paid** account with sufficient RPM/TPM (paid tier is usually enough).
- **Summary:** **~$84** in API fees; no extra hardware if you run the job from one machine. Total **~$84** (plus any infra you already use).

---

### Option C: Groq free tier — not enough for “all in 1 month”

- **Free tier (e.g. llama-3.1-8b):** ~30 RPM, **14.4k RPD**, **500k TPD**.
- **Tokens per day:** 500k / 2,000 ≈ **250 extensions/day** → **7,500 extensions/month**.
- So free Groq can do **at most ~7.5k extensions in a month**, not 160k. For “all in 1 month” you’d need a **paid** Groq plan (check current pricing).

---

### Comparison (all 160k in 1 month)

| Option              | LLM API cost | Other cost (electricity or VMs) | Notes                                      |
|---------------------|--------------|----------------------------------|--------------------------------------------|
| **Ollama (local)**  | **$0**       | ~$140–175 (electricity) or ~$60–120 (VMs) | Need ~8 workers 24/7 for 30 days.         |
| **OpenAI GPT-4o mini** | **~$84**  | ~$0 (single machine)            | Paid tier for rate limits.                 |
| **Groq free**       | $0           | N/A                              | Cap ~7.5k/month; cannot do 160k in 1 month.|

**Bottom line for “all Chrome Store in 1 month”:**  
- **Cheapest in dollars:** **OpenAI GPT-4o mini** at **~$84** (API only), assuming you have one machine and a paid account.  
- **Cheapest with $0 API:** **Ollama** with your own hardware: **~$140–175** electricity for ~8 machines running 24/7, or **~$60–120** if you use 8 small cloud VMs instead (no LLM API fee).

---

### INR conversion (approximate; 1 USD ≈ ₹87, Feb 2025)

| Item | USD | INR (approx) |
|------|-----|--------------|
| OpenAI API (160k extensions) | ~$84 | **~₹7,300** |
| Ollama – electricity (8 machines, 1 month) | ~$140–175 | **~₹12,200–15,200** |
| Ollama – cloud VMs (8 × 720 h) | ~$60–120 | **~₹5,200–10,400** |

---

### Which OpenAI subscription do you need?

- **No separate “subscription”:** OpenAI API is **pay-as-you-go**. You add a payment method (card) and are billed for usage. There is no monthly subscription fee; you only pay for tokens used.
- **Rate limits:** For 160k extensions in 30 days you need **~5,333 requests/day** → on average **~3.7 RPM** and **~7,400 TPM**. That’s low.
- **Tier:** After you add a payment method you’re usually on **Tier 1** (or higher as usage grows). Tier 1 limits for GPT-4o mini are typically **much higher** than 4 RPM (often 500+ RPM, 200k+ TPM). So **Tier 1 (pay-as-you-go with payment method added) is enough**; you don’t need a special “Plus” or “Team” subscription for the API.
- **Where to check:** Your exact limits: [platform.openai.com/settings/organization/limits](https://platform.openai.com/settings/organization/limits) and [Rate limits docs](https://platform.openai.com/docs/guides/rate-limits).

**Summary:** Add a payment method on [platform.openai.com](https://platform.openai.com), use GPT-4o mini via API; expect **~$84 (~₹7,300)** for 160k extensions. No “ChatGPT Plus” or “Team” plan required for API access.
