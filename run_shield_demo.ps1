param(
    [string]$PolicyBackend = "opa",
    [string]$ShadowBackend = "yaml"
)

# =====================================================================
# RUNTIME SHIELD & DVLA INTEGRATED DEMO LAUNCHER FOR WINDOWS (POWERSHELL)
# =====================================================================

Write-Host "======================================================" -ForegroundColor Blue
Write-Host "🛡️  Runtime Shield & DVLA Bot Integration Demo Launcher 🛡️" -ForegroundColor Blue
Write-Host "======================================================" -ForegroundColor Blue

# Change directory to script root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($ScriptDir) { Set-Location $ScriptDir }

# Resolve repository root and paths
$repoRoot = $PSScriptRoot
$opaPath = Join-Path $repoRoot "opa.exe"
$regoPath = Join-Path $repoRoot "rules\runtime_shield.rego"
$bundlePath = Join-Path $repoRoot "rules\runtime_shield_bundle.tar.gz"
$providerEntry = Join-Path $repoRoot "dist\index.js"

Write-Host "🧹 Cleaning up old processes and logs for a fresh start..." -ForegroundColor Yellow

# Kill lingering demo processes selectively instead of all python.exe instances
Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%bridge.py%'" -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%streamlit%'" -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# Remove old database files and logs
Remove-Item -Path "telemetry.db*" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "bridge_demo.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "damn-vulnerable-llm-agent/streamlit_demo.log" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Build the Keycloak/filesystem MCP providers if the compiled entry point is missing.
if (-not (Test-Path $providerEntry)) {
    if (-not (Test-Path (Join-Path $repoRoot "node_modules"))) {
        Write-Host "Installing Node.js dependencies for the MCP providers..." -ForegroundColor Yellow
        npm ci
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to install MCP provider dependencies."
            exit 1
        }
    }

    Write-Host "Building MCP providers..." -ForegroundColor Yellow
    npm run build
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $providerEntry)) {
        Write-Error "MCP provider build failed; dist\index.js was not created."
        exit 1
    }
}

# ---------------------------------------------------------------------
# 1. Start Runtime Shield Bridge & Live Dashboard
# ---------------------------------------------------------------------
# Start OPA policy engine
$OpaLog = "opa_demo.log"
Write-Host "🚀 Starting OPA policy engine..." -ForegroundColor Green
if (Test-Path $opaPath) {
    $OpaErrorLog = "opa_demo_error.log"
    $OpaProcess = Start-Process -FilePath $opaPath -ArgumentList "run -s -b $bundlePath --addr :8182" -RedirectStandardOutput $OpaLog -RedirectStandardError $OpaErrorLog -WindowStyle Hidden -PassThru
} else {
    Write-Host "opa.exe not found; starting OPA with Docker Compose..." -ForegroundColor Yellow
    docker compose up -d opa
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to start the OPA service with Docker Compose."
        exit 1
    }
}

Write-Host "Waiting for the OPA policy API to become ready..."
$OpaReady = $false
$OpaWait = [System.Diagnostics.Stopwatch]::StartNew()
while (-not $OpaReady -and $OpaWait.Elapsed.TotalSeconds -lt 90) {
    try {
        $OpaResponse = Invoke-WebRequest -Uri "http://127.0.0.1:8182/health" -UseBasicParsing -TimeoutSec 3
        $OpaReady = $OpaResponse.StatusCode -eq 200
    } catch [System.Net.WebException] {
        Start-Sleep -Seconds 2
    } catch {
        Write-Error "OPA readiness check failed: $_"
        exit 1
    }
}

if (-not $OpaReady) {
    Write-Error "OPA did not become ready within 90 seconds. Check $OpaLog and the OPA container logs."
    exit 1
}
Write-Host "✅ OPA policy API is ready." -ForegroundColor Green

Write-Host "🚀 Starting Runtime Shield Bridge & Live Dashboard (Backend: $PolicyBackend, Shadow: $ShadowBackend)..." -ForegroundColor Green
$RootVenvActivate = Join-Path $PSScriptRoot "venv\Scripts\Activate.ps1"
$BridgeArgs = "--policy-backend $PolicyBackend --shadow-backend $ShadowBackend"
$BridgeLog = "bridge_demo.log"

if (Test-Path $RootVenvActivate) {
    Write-Host "DEBUG: Detected venv at $RootVenvActivate" -ForegroundColor Cyan
    $BridgeProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c venv\Scripts\activate.bat && python bridge.py $BridgeArgs > $BridgeLog 2>&1" -WindowStyle Hidden -PassThru
} else {
    Write-Host "⚠️ Global Virtual Environment 'venv' not found. Trying global python..." -ForegroundColor Red
    $BridgeProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c python bridge.py $BridgeArgs > $BridgeLog 2>&1" -WindowStyle Hidden -PassThru
}
Write-Host "✅ Bridge process launched. Logging to $BridgeLog." -ForegroundColor Green
Write-Host "Waiting for the Shield Proxy API to become ready..."
$ProxyReady = $false
$ProxyWait = [System.Diagnostics.Stopwatch]::StartNew()
while (-not $ProxyReady -and $ProxyWait.Elapsed.TotalSeconds -lt 180) {
    try {
        $ProxyResponse = Invoke-WebRequest -Uri "http://127.0.0.1:5001/v1/models" -UseBasicParsing -TimeoutSec 3
        $ProxyReady = $ProxyResponse.StatusCode -eq 200
    } catch [System.Net.WebException] {
        Start-Sleep -Seconds 2
    } catch {
        Write-Error "Shield Proxy readiness check failed: $_"
        exit 1
    }
}

if (-not $ProxyReady) {
    Write-Error "Shield Proxy did not become ready within 180 seconds. Check $BridgeLog."
    exit 1
}

Write-Host "✅ Shield Proxy API is ready." -ForegroundColor Green

# ---------------------------------------------------------------------
# 2. Start Damn Vulnerable LLM Agent (DVLA) Streamlit app
# ---------------------------------------------------------------------
Write-Host "🚀 Starting Damn Vulnerable LLM Agent (DVLA) Streamlit app..." -ForegroundColor Green
$AgentDir = Join-Path $PSScriptRoot "damn-vulnerable-llm-agent"
$AgentVenvActivate = Join-Path $AgentDir "venv\Scripts\Activate.ps1"
$StreamlitLog = "streamlit_demo.log"
if (Test-Path $AgentVenvActivate) {
    Write-Host "DEBUG: Detected agent venv at $AgentVenvActivate" -ForegroundColor Cyan
    $StreamlitProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c cd $AgentDir && venv\Scripts\activate.bat && streamlit run main.py --server.port 8501 --server.headless true > $StreamlitLog 2>&1" -WindowStyle Hidden -PassThru
} else {
    Write-Host "⚠️ Agent Virtual Environment 'venv' not found. Using global streamlit..." -ForegroundColor Red
    $StreamlitProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c cd $AgentDir && streamlit run main.py --server.port 8501 --server.headless true > $StreamlitLog 2>&1" -WindowStyle Hidden -PassThru
}
Write-Host "✅ Streamlit chatbot launched. Logging to $StreamlitLog." -ForegroundColor Green

# ---------------------------------------------------------------------
# 3. Open Browser Tabs
# ---------------------------------------------------------------------
Write-Host "🌐 Opening browser interfaces..." -ForegroundColor Blue
Start-Sleep -Seconds 2
Start-Process "http://localhost:9090"
Start-Process "http://localhost:8501"

Write-Host "======================================================" -ForegroundColor Yellow
Write-Host "🎉 Demo is running live!" -ForegroundColor Yellow
Write-Host "   - Shield Live Dashboard: http://localhost:9090" -ForegroundColor Yellow
Write-Host "   - Secured Banking Bot:   http://localhost:8501" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop both servers." -ForegroundColor Yellow
Write-Host "======================================================" -ForegroundColor Yellow

# Keep the script alive until user interrupt
try {
    # Keep the script running to wait for Ctrl+C
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host "`n🛑 Shutting down servers gracefully..." -ForegroundColor Yellow
    if ($BridgeProcess) {
        Stop-Process -Id $BridgeProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($StreamlitProcess) {
        Stop-Process -Id $StreamlitProcess.Id -Force -ErrorAction SilentlyContinue
    }
    # Ensure no orphaned demo processes remain
    Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%bridge.py%'" -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%streamlit%'" -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Write-Host "✨ Shutdown complete. Have a secure day!" -ForegroundColor Green
}
