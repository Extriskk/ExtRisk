# Start the API with SQLite (no PostgreSQL required).
# Use this when you only need the API UI / docs and don't have PostgreSQL running.
#
# Usage: .\scripts\run_api_sqlite.ps1
# Then open: http://127.0.0.1:8000/docs

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
$env:DATABASE_URL = "sqlite:///./api_local.db"
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
