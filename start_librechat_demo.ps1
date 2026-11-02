$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Write-Error "Docker CLI was not found. Install Docker Desktop, then rerun this script."
    exit 1
}

function Invoke-Docker {
    param(
        [string[]]$DockerArguments,
        [switch]$Quiet
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        if ($Quiet) {
            & $docker.Source @DockerArguments *> $null
        } else {
            & $docker.Source @DockerArguments | Out-Host
        }
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

$desktopPaths = @(
    (Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Docker\Docker\Docker Desktop.exe")
)

if ((Invoke-Docker -DockerArguments @("info") -Quiet) -ne 0) {
    $desktopPath = $desktopPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $desktopPath) {
        Write-Error "Docker Desktop was not found. Install/start Docker Desktop, then rerun this script."
        exit 1
    }

    Write-Host "Starting Docker Desktop..." -ForegroundColor Cyan
    Start-Process -FilePath $desktopPath

    $dockerReady = $false
    $timeout = [Diagnostics.Stopwatch]::StartNew()
    while (-not $dockerReady -and $timeout.Elapsed.TotalSeconds -lt 180) {
        Start-Sleep -Seconds 3
        $dockerReady = (Invoke-Docker -DockerArguments @("info") -Quiet) -eq 0
    }

    if (-not $dockerReady) {
        Write-Error "Docker Engine did not start within 3 minutes. Open Docker Desktop, select the Linux engine, and rerun this script."
        exit 1
    }
}

if ((Invoke-Docker -DockerArguments @("network", "inspect", "dokploy-network") -Quiet) -ne 0) {
    Write-Host "Creating the Compose network..." -ForegroundColor Cyan
    if ((Invoke-Docker -DockerArguments @("network", "create", "dokploy-network")) -ne 0) {
        Write-Error "Could not create the dokploy-network Docker network."
        exit 1
    }
}

$svidPath = Join-Path $PSScriptRoot "spire\certs\llm-agent.crt"
if (-not (Test-Path $svidPath)) {
    Write-Error "LibreChat's SPIFFE certificate was not found at $svidPath."
    exit 1
}

$svidPem = Get-Content -Path $svidPath -Raw
if ($svidPem -notmatch "-----BEGIN CERTIFICATE-----" -or $svidPem -notmatch "-----END CERTIFICATE-----") {
    Write-Error "LibreChat's SPIFFE certificate is not a valid PEM file: $svidPath."
    exit 1
}

$configTemplatePath = Join-Path $PSScriptRoot "librechat.yaml"
$runtimeConfigPath = Join-Path $PSScriptRoot "librechat.runtime.yaml"
$configTemplate = [System.IO.File]::ReadAllText($configTemplatePath)
$certPlaceholder = '${SPIFFE_LLM_CERT}'
if (-not $configTemplate.Contains($certPlaceholder)) {
    Write-Error "LibreChat config is missing the SPIFFE certificate placeholder: $certPlaceholder."
    exit 1
}

$encodedCert = [uri]::EscapeDataString($svidPem.Trim())
$runtimeConfig = $configTemplate.Replace($certPlaceholder, $encodedCert)
[System.IO.File]::WriteAllText($runtimeConfigPath, $runtimeConfig, [System.Text.UTF8Encoding]::new($false))

$stagingContainers = @(
    "runtime-shield-workshop-gateway-next",
    "runtime-shield-filesystem-provider",
    "chatbot_mcp"
)
$stagingReady = $true
foreach ($containerName in $stagingContainers) {
    if ((Invoke-Docker -DockerArguments @("inspect", $containerName) -Quiet) -ne 0) {
        $stagingReady = $false
        break
    }
}

function Get-ContainerProviderToken {
    param([string]$ContainerName)

    $inspection = & $docker.Source inspect $ContainerName 2>$null
    if ($LASTEXITCODE -ne 0) {
        return ""
    }
    $container = ($inspection | ConvertFrom-Json)[0]
    $entries = @($container.Config.Env | Where-Object { $_ -like "RUNTIME_SHIELD_FS_PROVIDER_TOKEN=*" })
    if ($entries.Count -ne 1) {
        return ""
    }
    return $entries[0].Substring("RUNTIME_SHIELD_FS_PROVIDER_TOKEN=".Length)
}

$envFilePath = Join-Path $PSScriptRoot ".env"
$envFileContent = if (Test-Path $envFilePath) {
    [System.IO.File]::ReadAllText($envFilePath)
} else {
    ""
}
$envFileLines = if (Test-Path $envFilePath) {
    [System.IO.File]::ReadAllLines($envFilePath)
} else {
    @()
}
$tokenEntries = @(
    $envFileLines | Where-Object {
        $_.StartsWith("RUNTIME_SHIELD_FS_PROVIDER_TOKEN=")
    }
)
if ($tokenEntries.Count -gt 1) {
    Write-Error "The .env file contains duplicate RUNTIME_SHIELD_FS_PROVIDER_TOKEN entries. Keep exactly one and rerun."
    exit 1
}

$storedProviderToken = if ($tokenEntries.Count -eq 1) {
    $tokenEntries[0].Substring("RUNTIME_SHIELD_FS_PROVIDER_TOKEN=".Length)
} else {
    ""
}
$providerToken = $env:RUNTIME_SHIELD_FS_PROVIDER_TOKEN
if ($storedProviderToken -and $providerToken -and $storedProviderToken -cne $providerToken) {
    Write-Error "RUNTIME_SHIELD_FS_PROVIDER_TOKEN differs between the process environment and .env. Keep one value and rerun."
    exit 1
}
if (-not $providerToken) {
    $providerToken = $storedProviderToken
}
if ($stagingReady) {
    $gatewayProviderToken = Get-ContainerProviderToken "runtime-shield-workshop-gateway-next"
    $filesystemProviderToken = Get-ContainerProviderToken "runtime-shield-filesystem-provider"
    if (
        -not $gatewayProviderToken -or
        -not $filesystemProviderToken -or
        $gatewayProviderToken -cne $filesystemProviderToken
    ) {
        Write-Error "The running staging gateway and provider do not expose one matching shared token. Do not restart them; resolve their configuration first."
        exit 1
    }
    if ($providerToken -and $providerToken -cne $gatewayProviderToken) {
        Write-Error "The token in .env or the process environment does not match the running staging gateway/provider. Preserve the running containers and reconcile the local token before rerunning."
        exit 1
    }
    if (-not $providerToken) {
        $providerToken = $gatewayProviderToken
    }
}
if (-not $providerToken) {
    $randomBytes = New-Object byte[] 32
    $randomGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $randomGenerator.GetBytes($randomBytes)
        $providerToken = [Convert]::ToBase64String($randomBytes)
        $providerToken = $providerToken.TrimEnd("=").Replace("+", "-").Replace("/", "_")
    } finally {
        $randomGenerator.Dispose()
    }
}
if ($providerToken -notmatch "^[A-Za-z0-9_-]{32,}$") {
    Write-Error "RUNTIME_SHIELD_FS_PROVIDER_TOKEN must be at least 32 URL-safe characters."
    exit 1
}
if (-not $storedProviderToken) {
    $separator = if (
        $envFileContent.Length -gt 0 -and
        -not $envFileContent.EndsWith("`n") -and
        -not $envFileContent.EndsWith("`r")
    ) {
        [Environment]::NewLine
    } else {
        ""
    }
    [System.IO.File]::AppendAllText(
        $envFilePath,
        $separator + "RUNTIME_SHIELD_FS_PROVIDER_TOKEN=$providerToken" + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-Host "Saved the private filesystem-provider token in the Git-ignored .env file." -ForegroundColor Cyan
}
$env:RUNTIME_SHIELD_FS_PROVIDER_TOKEN = $providerToken

$chatbotUrl = "http://localhost:3080"
$dashboardUrl = "http://localhost:9090"

if ($stagingReady) {
    $runtimeConfig = $runtimeConfig.Replace("http://gateway:5001", "http://gateway-workshop-next:5001")
    [System.IO.File]::WriteAllText($runtimeConfigPath, $runtimeConfig, [System.Text.UTF8Encoding]::new($false))

    foreach ($containerName in @(
        "runtime-shield-filesystem-provider",
        "runtime-shield-workshop-gateway-next"
    )) {
        $containerStatus = (& $docker.Source inspect --format "{{.State.Status}}" $containerName 2>$null)
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Could not inspect staging container $containerName."
            exit 1
        }
        if ($containerStatus.Trim() -ne "running") {
            if ((Invoke-Docker -DockerArguments @("start", $containerName)) -ne 0) {
                Write-Error "Could not start staging container $containerName."
                exit 1
            }
        }
    }

    $chatbotStatus = (& $docker.Source inspect --format "{{.State.Status}}" chatbot_mcp 2>$null)
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Could not inspect the existing LibreChat container."
        exit 1
    }
    if ($chatbotStatus.Trim() -eq "running") {
        $chatbotAction = "restart"
    } else {
        $chatbotAction = "start"
    }
    if ((Invoke-Docker -DockerArguments @($chatbotAction, "chatbot_mcp")) -ne 0) {
        Write-Error "Could not $chatbotAction the existing LibreChat container."
        exit 1
    }
    $dashboardUrl = "http://localhost:9091"
    Write-Host "Using the existing isolated workshop gateway and provider; existing gateway containers and Docker data were left untouched." -ForegroundColor Cyan
} else {
    Write-Host "Building and starting Runtime Shield, LibreChat, and the dashboard..." -ForegroundColor Cyan
    if ((Invoke-Docker -DockerArguments @("compose", "-f", "docker-compose.yml", "-f", "docker-compose.librechat-demo.yml", "up", "--build", "-d")) -ne 0) {
        Write-Error "Docker Compose could not start the stack. Review the error above, fix it, and rerun this script."
        exit 1
    }

    if ((Invoke-Docker -DockerArguments @("compose", "-f", "docker-compose.yml", "-f", "docker-compose.librechat-demo.yml", "ps")) -ne 0) {
        Write-Error "Docker Compose could not list the running services."
        exit 1
    }
}
Write-Host ""
Write-Host "LibreChat: $chatbotUrl" -ForegroundColor Green
Write-Host "Dashboard: $dashboardUrl" -ForegroundColor Green
if ($stagingReady) {
    Write-Host "The existing gateway/provider and Docker data were preserved." -ForegroundColor Yellow
} else {
    Write-Host "Stop the stack with: docker compose down" -ForegroundColor Yellow
}

Start-Process $chatbotUrl
Start-Process $dashboardUrl
