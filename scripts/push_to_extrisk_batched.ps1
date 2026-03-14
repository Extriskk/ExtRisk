# Push chrome-extension-security-analyzer content to ExtRisk in batches to avoid HTTP 408 timeout.
# Run from repo root. Requires: Git, network. ExtRisk must exist on GitHub (empty or not).
# Optimized: small batches first, then reports, then DB. No LFS, no history rewrite.

$ErrorActionPreference = "Stop"
$Source = "C:\Users\user2\Documents\GitHub\chrome-extension-security-analyzer"
$Dest   = "C:\Users\user2\Documents\GitHub\ExtRisk-push"
$ExtRiskRepo = "https://github.com/debarshi17/ExtRisk.git"

Set-Location $Source

# Ensure 5GB buffer for large pushes
git config http.postBuffer 5368709120
git config http.version HTTP/1.1

# Clone or refresh ExtRisk-push
if (-not (Test-Path $Dest)) {
    Write-Host "[1/4] Cloning ExtRisk to $Dest ..."
    git clone $ExtRiskRepo $Dest
} else {
    Write-Host "[1/4] ExtRisk-push exists; pulling..."
    Set-Location $Dest
    git fetch origin
    git checkout main -f 2>$null; if (-not $?) { git checkout -b main }
    git reset --hard origin/main 2>$null
    Set-Location $Source
}

# Clear dest working tree (keep .git)
Write-Host "[2/4] Clearing destination working tree..."
Set-Location $Dest
Get-ChildItem -Force | Where-Object { $_.Name -ne ".git" } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Set-Location $Source

# Batch 1: Everything except reports/ and api_local.db (code, config, docs, cursor, ai-context, batch_runs, central_store, data/cohorts)
Write-Host "[3/4] Batch 1: Copying code, config, docs, ai-context, cursor, batch_runs, central_store, data/cohorts..."
robocopy $Source $Dest /E /XD .git node_modules reports /XF api_local.db /NFL /NDL /NJH /NJS /NC /NS /NP | Out-Null
# Robocopy exit 0-7 = success; 8+ = partial
if ($LASTEXITCODE -ge 8) { Write-Warning "Robocopy Batch 1 exit: $LASTEXITCODE" }

Set-Location $Dest
git add -A
git status -s | Select-Object -First 20
$n = (git status -s | Measure-Object -Line).Lines
if ($n -gt 0) {
    git commit -m "Batch 1: code, config, docs, ai-context, cursor, batch_runs, central_store, data/cohorts"
    Write-Host "Pushing Batch 1..."
    git push origin main
}
Set-Location $Source

# Batch 2: reports/
Write-Host "[3/4] Batch 2: Copying reports/..."
if (Test-Path "$Source\reports") {
    New-Item -ItemType Directory -Path "$Dest\reports" -Force | Out-Null
    robocopy "$Source\reports" "$Dest\reports" /E /NFL /NDL /NJH /NJS /NC /NS /NP | Out-Null
    Set-Location $Dest
    git add -A
    $n = (git status -s | Measure-Object -Line).Lines
    if ($n -gt 0) {
        git commit -m "Batch 2: reports"
        Write-Host "Pushing Batch 2..."
        git push origin main
    }
    Set-Location $Source
}

# Batch 3: api_local.db
Write-Host "[3/4] Batch 3: Copying api_local.db..."
if (Test-Path "$Source\api_local.db") {
    Copy-Item "$Source\api_local.db" "$Dest\api_local.db" -Force
    Set-Location $Dest
    git add api_local.db
    git status -s
    git commit -m "Batch 3: api_local.db"
    Write-Host "Pushing Batch 3..."
    git push origin main
    Set-Location $Source
}

Write-Host "[4/4] Done. ExtRisk repo: https://github.com/debarshi17/ExtRisk"
