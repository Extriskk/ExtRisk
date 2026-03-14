# Testing Report Storage and Report API

Step-by-step guide to verify report storage in the DB and the Report API (by `job_id` and by `extension_id`).

---

## Prerequisites

- **Python venv** with project dependencies: `pip install -r requirements.txt`
- **PostgreSQL** running with DB created (default: `ext_intel`; user `ext_intel` / pass `ext_intel` per `api/config.py`, or set `DATABASE_URL`)
- **Optional:** Redis (only needed for async jobs on non-Windows; on Windows the API runs scans synchronously)

---

## 1. Run migrations

From repo root:

```powershell
cd c:\Users\user2\Documents\GitHub\chrome-extension-security-analyzer
alembic upgrade head
```

You should see migrations 001 and 002 applied (or “already at head”).

---

## 2. Start the API

```powershell
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

- **Auth:** If `API_KEYS` is not set, the API runs in dev mode (no key required). Otherwise set header: `X-API-Key: your-key`.
- **Docs:** Open http://localhost:8000/docs for Swagger UI.

---

## 3. Import existing reports into the DB (one-time)

If you already have report files in `reports/`:

```powershell
# Dry run (no DB writes)
python scripts/import_reports_to_db.py --dry-run

# Actual import
python scripts/import_reports_to_db.py
```

Optional: `--reports-dir path\to\reports` to use another directory.

After import, those reports are available via the Report API by **extension_id** and by **job_id** (if you later trigger a scan that reuses the same extension).

---

## 4. Trigger a new scan (POST /analyze)

This creates a job, runs the scan (synchronously on Windows), and stores the report content in the DB.

**PowerShell (no API key in dev):**

```powershell
$body = @{ extension_id = "vscode.vscode-theme-seti"; browser = "vscode" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/analyze" -Method POST -Body $body -ContentType "application/json"
```

**With API key:**

```powershell
$headers = @{ "X-API-Key" = "your-api-key" }
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/analyze" -Method POST -Body $body -ContentType "application/json" -Headers $headers
```

**cURL (no key):**

```bash
curl -X POST "http://localhost:8000/api/v1/analyze" -H "Content-Type: application/json" -d "{\"extension_id\":\"vscode.vscode-theme-seti\",\"browser\":\"vscode\"}"
```

**Example response:**

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "complete",
  "message": "..."
}
```

Save `job_id` for the next step.

---

## 5. Fetch report by job_id

Use the `job_id` from the POST response. Replace `JOB_ID` and add `X-API-Key` if required.

- **Summary (JSON):**  
  `GET /api/v1/reports/{job_id}`

- **Full HTML report:**  
  `GET /api/v1/reports/{job_id}/html`

- **Full JSON report:**  
  `GET /api/v1/reports/{job_id}/full`

**PowerShell:**

```powershell
$jobId = "YOUR_JOB_ID_HERE"
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/reports/$jobId" -Headers @{ "X-API-Key" = "your-key" }  # or omit in dev
Invoke-WebRequest -Uri "http://localhost:8000/api/v1/reports/$jobId/html" -Headers @{ "X-API-Key" = "your-key" } -OutFile report.html
```

Reports are served from DB first (`report_json` / `report_html`); if missing, the API falls back to file paths.

---

## 6. Fetch report by extension_id

Use the same `extension_id` you sent to POST /analyze (e.g. `vscode.vscode-theme-seti`). The API returns the **latest** stored report for that extension.

- **Summary:**  
  `GET /api/v1/reports/by-extension/{extension_id}`

- **HTML:**  
  `GET /api/v1/reports/by-extension/{extension_id}/html`

- **Full JSON:**  
  `GET /api/v1/reports/by-extension/{extension_id}/full`

**PowerShell:**

```powershell
$extId = "vscode.vscode-theme-seti"
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/reports/by-extension/$([uri]::EscapeDataString($extId))"
Invoke-WebRequest -Uri "http://localhost:8000/api/v1/reports/by-extension/$([uri]::EscapeDataString($extId))/html" -OutFile report_by_ext.html
```

**cURL:**

```bash
curl "http://localhost:8000/api/v1/reports/by-extension/vscode.vscode-theme-seti"
curl "http://localhost:8000/api/v1/reports/by-extension/vscode.vscode-theme-seti/html" -o report.html
```

---

## 7. Quick checklist

| Step | Action | Expected |
|------|--------|----------|
| 1 | `alembic upgrade head` | Migrations applied (or “already at head”). |
| 2 | Start API, open `/health` | `{"status":"ok"}`. |
| 3 | `import_reports_to_db.py` (optional) | Existing reports imported; no errors. |
| 4 | POST `/api/v1/analyze` with `extension_id` + `browser` | `job_id` and `status` (e.g. `complete`). |
| 5 | GET `/api/v1/reports/{job_id}` and `.../html`, `.../full` | Summary JSON, HTML body, full JSON. |
| 6 | GET `/api/v1/reports/by-extension/{extension_id}` and `.../html`, `.../full` | Same content as latest report for that extension. |

---

## Troubleshooting

- **404 on report:** Ensure the scan completed (`status: complete`) and that you’re using the correct `job_id` or `extension_id`. After import, use the extension_id that matches the report filenames (e.g. `vscode_vscode.vscode-theme-seti` from `reports/vscode_vscode.vscode-theme-seti_analysis.json` → extension_id may be stored as `vscode.vscode-theme-seti`; check import script output or DB).
- **401/403:** Set `X-API-Key` to a value in `API_KEYS`, or leave `API_KEYS` unset for dev mode.
- **DB connection:** Set `DATABASE_URL` if PostgreSQL is not on `localhost:5432` with user `ext_intel`.
- **“Analysis in progress” / 202:** On Windows, the sync path should complete in the same request; if you see 202, a previous run may have left a job in `queued`/`running`. Check `ScanJob` table or trigger a new scan with a different extension.

For API architecture and report storage design, see **Brain.md** section 4.
