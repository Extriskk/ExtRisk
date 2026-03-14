# Commit DB, reports, batch/central/cohorts so clone/deploy has same state.
# Run from repo root. Ensure no other git process is running (close IDE git, etc.).

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root

# Remove stale lock if any
Remove-Item ".git\index.lock" -Force -ErrorAction SilentlyContinue

git add .gitignore api_local.db package.json package-lock.json
git add reports/
git add batch_runs/
git add central_store/
git add data/cohorts/
git add ai-context/
git add .cursor/rules/
git add .cursor/skills/
git status

Write-Host "`nIf status looks good, run: git commit -m `"Track DB, reports, batch_runs, central_store, cohorts, ai-context, cursor rules/skills for deploy parity`""
Write-Host "Then: git push origin main"
