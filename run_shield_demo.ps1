# =====================================================================
# RUNTIME SHIELD & DVLA INTEGRATED DEMO LAUNCHER FOR WINDOWS (POWERSHELL)
# =====================================================================

Write-Host "======================================================" -ForegroundColor Blue
Write-Host "🛡️  Runtime Shield & DVLA Bot Integration Demo Launcher 🛡️" -ForegroundColor Blue
Write-Host "======================================================" -ForegroundColor Blue

# Change directory to script root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($ScriptDir) { Set-Location $ScriptDir }

Write-Host "🧹 Cleaning up old processes and logs for a fresh start..." -ForegroundColor Yellow

# Kill any ghost python or streamlit processes from previous runs using taskkill (more reliable on Windows)
taskkill /f /im python.exe 2>$null
taskkill /f /im streamlit.exe 2>$null
Get-Process -Name "python" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process -Name "streamlit" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Remove old database files and logs
Remove-Item -Path "telemetry.db*" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "bridge_demo.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "damn-vulnerable-llm-agent/streamlit_demo.log" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 1. Start Runtime Shield Bridge
Write-Host "🚀 Starting Runtime Shield Bridge & Live Dashboard..." -ForegroundColor Green
$RootVenvActivate = Join-Path $PSScriptRoot "venv\Scripts\Activate.ps1"

# Create a job or start process in background
$BridgeLog = "bridge_demo.log"
if (Test-Path $RootVenvActivate) {
    # Run within the virtual environment and detach using cmd.exe to avoid powershell redirection issues
    $BridgeProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c venv\Scripts\activate.bat && python bridge.py > bridge_demo.log 2>&1" -WindowStyle Hidden -PassThru
} else {
    Write-Host "⚠️ Global Virtual Environment 'venv' not found. Trying global python..." -ForegroundColor Red
    $BridgeProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c python bridge.py > bridge_demo.log 2>&1" -WindowStyle Hidden -PassThru
}

Write-Host "✅ Bridge process launched. Logging to bridge_demo.log." -ForegroundColor Green
Write-Host "Waiting for proxy to start on port 5001..."
Start-Sleep -Seconds 4

# 2. Start Damn Vulnerable LLM Agent Chatbot
Write-Host "🚀 Starting Damn Vulnerable LLM Agent (DVLA) Streamlit app..." -ForegroundColor Green
$AgentDir = Join-Path $PSScriptRoot "damn-vulnerable-llm-agent"
$AgentVenvActivate = Join-Path $AgentDir "venv\Scripts\Activate.ps1"

if (Test-Path $AgentVenvActivate) {
    # Run within the virtual environment and detach using cmd.exe
    $StreamlitProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c cd damn-vulnerable-llm-agent && venv\Scripts\activate.bat && streamlit run main.py --server.port 8501 --server.headless true > streamlit_demo.log 2>&1" -WindowStyle Hidden -PassThru
} else {
    Write-Host "⚠️ Chatbot Local Virtual Environment 'venv' not found in subfolder! Trying global streamlit..." -ForegroundColor Red
    $StreamlitProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c cd damn-vulnerable-llm-agent && streamlit run main.py --server.port 8501 --server.headless true > streamlit_demo.log 2>&1" -WindowStyle Hidden -PassThru
}

Write-Host "✅ Streamlit chatbot launched." -ForegroundColor Green

# 3. Open Browser Tabs
Write-Host "🌐 Opening browser interfaces..." -ForegroundColor Blue
Start-Sleep -Seconds 2

Start-Process "http://localhost:9090"
Start-Process "http://localhost:8501"

Write-Host "======================================================" -ForegroundColor Yellow
Write-Host "🎉 Demo is running live!"
Write-Host "   - Shield Live Dashboard: http://localhost:9090"
Write-Host "   - Secured Banking Bot:   http://localhost:8501"
Write-Host "Press Ctrl+C to stop both servers."
Write-Host "======================================================" -ForegroundColor Yellow

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
    # To be extra safe and ensure no orphaned python/streamlit processes are left:
    taskkill /f /im python.exe 2>$null
    taskkill /f /im streamlit.exe 2>$null
    Write-Host "✨ Shutdown complete. Have a secure day!" -ForegroundColor Green
}
