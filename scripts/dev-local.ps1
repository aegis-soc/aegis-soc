#Requires -Version 5.1
<#
.SYNOPSIS
    AegisSoc local launcher WITHOUT Docker (SQLite + eager task mode).

.DESCRIPTION
    Starts the FastAPI backend (uvicorn) and the Vue dev server (vite), so you can
    see the real UI on a machine where Docker is not available or too heavy.

    This mode is for LOCAL FUNCTIONAL DEMO ONLY:
      - database        : SQLite (file: backend/_local.db)
      - task execution  : synchronous, in-process (TASK_EAGER=true)
      - redis / celery  : NOT used
      - webhook secret  : -WebhookSecret (default: local-dev-secret)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\dev-local.ps1
    powershell -ExecutionPolicy Bypass -File scripts\dev-local.ps1 -FrontendPort 5273

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\dev-local.ps1 -Stop
#>
param(
    [int]$BackendPort = 8000,
    [int]$FrontendPort = 5173,
    [string]$WebhookSecret = "local-dev-secret",
    [switch]$Stop
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # 去掉 Invoke-WebRequest 的进度条刷屏
$root = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $root "backend"
$frontendDir = Join-Path $root "frontend"
$python = Join-Path $backendDir ".venv\Scripts\python.exe"
$pidFile = Join-Path $PSScriptRoot ".dev-local.pids"

function Stop-Local {
    if (-not (Test-Path $pidFile)) { Write-Host "No PID file found, nothing to stop." -ForegroundColor Yellow; return }
    Get-Content $pidFile | ForEach-Object {
        $procId = $_.Trim()
        if (-not $procId) { return }
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($p) {
            Write-Host ("Stopping {0} (PID {1})" -f $p.ProcessName, $procId) -ForegroundColor Yellow
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    Write-Host "Stopped." -ForegroundColor Green
}

if ($Stop) { Stop-Local; exit 0 }

if (-not (Test-Path $python)) {
    Write-Host "Backend venv not found: $python" -ForegroundColor Red
    Write-Host "Create it first:" -ForegroundColor Yellow
    Write-Host "  cd backend; python -m venv .venv; .venv\Scripts\python.exe -m pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path (Join-Path $frontendDir "node_modules"))) {
    Write-Host "Frontend dependencies missing: run 'npm install' in frontend/" -ForegroundColor Red
    exit 1
}

# --- backend env (local demo mode) ---
$env:DATABASE_URL = "sqlite:///./_local.db"
$env:TASK_EAGER = "true"
$env:GRAYLOG_WEBHOOK_SECRET = $WebhookSecret
$env:REDIS_URL = "redis://127.0.0.1:6399/0"
$env:CELERY_BROKER_URL = "redis://127.0.0.1:6399/1"
$env:CELERY_RESULT_BACKEND = "redis://127.0.0.1:6399/2"

Write-Host "Starting backend  (SQLite, eager mode) ..." -ForegroundColor Cyan
$api = Start-Process -FilePath $python `
    -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "$BackendPort", "--log-level", "warning" `
    -WorkingDirectory $backendDir -PassThru -WindowStyle Hidden

Write-Host "Starting frontend (vite dev server) ..." -ForegroundColor Cyan
$fe = Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/c", "npx vite --host 127.0.0.1 --port $FrontendPort --strictPort" `
    -WorkingDirectory $frontendDir -PassThru -WindowStyle Hidden

"$($api.Id)`n$($fe.Id)" | Set-Content -Path $pidFile -Encoding ascii

# --- wait for backend health ---
$healthUrl = "http://127.0.0.1:$BackendPort/api/healthz"
$ready = $false
for ($i = 1; $i -le 40; $i++) {
    Start-Sleep -Milliseconds 750
    try {
        $r = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 3
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
}

Write-Host ""
if ($ready) {
    Write-Host "Backend  ready : $healthUrl" -ForegroundColor Green
} else {
    Write-Host "Backend  NOT ready after 30s, check console output." -ForegroundColor Red
}

# --- wait for frontend (vite first start needs to pre-bundle deps) ---
$uiUrl = "http://127.0.0.1:$FrontendPort/"
$uiReady = $false
for ($i = 1; $i -le 40; $i++) {
    Start-Sleep -Milliseconds 750
    try {
        $r = Invoke-WebRequest -Uri $uiUrl -UseBasicParsing -TimeoutSec 3
        if ($r.StatusCode -eq 200) { $uiReady = $true; break }
    } catch { }
}
if ($uiReady) {
    Write-Host ("Frontend ready : {0}" -f $uiUrl) -ForegroundColor Green
} else {
    Write-Host "Frontend NOT ready after 30s (first run may still be pre-bundling, retry in a moment)." -ForegroundColor Yellow
}
Write-Host ("API docs      : http://127.0.0.1:{0}/api/docs" -f $BackendPort) -ForegroundColor Green
Write-Host ("Webhook secret: {0}" -f $WebhookSecret) -ForegroundColor DarkGray
Write-Host ""
Write-Host "Login with the bootstrap admin account, then change the password when prompted." -ForegroundColor Yellow
Write-Host "Stop with:  powershell -ExecutionPolicy Bypass -File scripts\dev-local.ps1 -Stop" -ForegroundColor DarkGray
