Write-Host "======================================================" -ForegroundColor Blue
Write-Host "🛡️  Runtime Shield & DVLA Bot Integration Demo Launcher 🛡️" -ForegroundColor Blue
Write-Host "======================================================" -ForegroundColor Blue

# Resolve script directory robustly
$scriptDir = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrEmpty($scriptDir)) {
    if (Test-Path ".\Runtime-shield-for-agentic-systems\run_shield_demo.ps1") {
        $scriptDir = Resolve-Path ".\Runtime-shield-for-agentic-systems"
    } else {
        $scriptDir = Get-Location
    }
}

# Ensure NVIDIA_NIM_API_KEY is populated from NVIDIA_API_KEY if present
if ($env:NVIDIA_API_KEY -and -not $env:NVIDIA_NIM_API_KEY) {
    $env:NVIDIA_NIM_API_KEY = $env:NVIDIA_API_KEY
}

# Clean up existing processes
Write-Host "🧹 Cleaning up old processes and logs for a fresh start..." -ForegroundColor Yellow
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "bridge.py" -or $_.CommandLine -match "streamlit run main.py" -or $_.CommandLine -match "streamlit run" } | Invoke-CimMethod -MethodName Terminate | Out-Null

# Remove old telemetry database
Remove-Item -Path (Join-Path $scriptDir "telemetry.db*") -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

Write-Host "🚀 Starting Runtime Shield Bridge & Live Dashboard..." -ForegroundColor Green

# Start Bridge in background with absolute path
$bridgePy = Join-Path $scriptDir "bridge.py"
$bridgeJob = Start-Process -FilePath "python" -ArgumentList "`"$bridgePy`"" -WorkingDirectory $scriptDir -NoNewWindow -RedirectStandardOutput (Join-Path $scriptDir "bridge_demo_out.log") -RedirectStandardError (Join-Path $scriptDir "bridge_demo_err.log") -PassThru
Write-Host "✅ Bridge process launched (PID: $($bridgeJob.Id)). Logging to bridge_demo_err.log." -ForegroundColor Green

Write-Host "Waiting for proxy to start on port 5001..."
Start-Sleep -Seconds 15

Write-Host "🚀 Starting Damn Vulnerable LLM Agent (DVLA) Streamlit app..." -ForegroundColor Green
$dvlaDir = Join-Path -Path $scriptDir -ChildPath "damn-vulnerable-llm-agent"
if (Test-Path $dvlaDir) {
    $streamlitJob = Start-Process -FilePath "python" -ArgumentList "-u -m streamlit run main.py --server.port 8501 --browser.gatherUsageStats false" -WorkingDirectory $dvlaDir -NoNewWindow -RedirectStandardOutput (Join-Path $scriptDir "streamlit_out.log") -RedirectStandardError (Join-Path $scriptDir "streamlit_err.log") -PassThru
    Write-Host "✅ Streamlit chatbot launched (PID: $($streamlitJob.Id)). Logging to streamlit_err.log." -ForegroundColor Green
} else {
    Write-Host "⚠️ Chatbot directory 'damn-vulnerable-llm-agent' not found at '$dvlaDir'!" -ForegroundColor Red
}

Write-Host "🌐 Opening browser interfaces..." -ForegroundColor Blue
Start-Sleep -Seconds 2

Start-Process "http://localhost:9090"
Start-Process "http://localhost:8501"

Write-Host "======================================================" -ForegroundColor Yellow
Write-Host "🎉 Demo is running live! Close this PowerShell window or press Ctrl+C to stop."
Write-Host "======================================================" -ForegroundColor Yellow

try {
    # Keep the script running
    while ($true) {
        Start-Sleep -Seconds 1
    }
} finally {
    Write-Host "🛑 Shutting down servers gracefully..." -ForegroundColor Yellow
    if ($bridgeJob -and (Get-Process -Id $bridgeJob.Id -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $bridgeJob.Id -Force
    }
    if ($streamlitJob -and (Get-Process -Id $streamlitJob.Id -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $streamlitJob.Id -Force
    }
    Write-Host "✨ Shutdown complete. Have a secure day!" -ForegroundColor Green
}
