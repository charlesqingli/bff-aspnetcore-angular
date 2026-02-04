# Run UI (ng serve --ssl), server (dotnet run), then open browser to server port.
# Run from project root: .\run.ps1

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$UiPath = Join-Path $ProjectRoot "ui"
$ServerPath = Join-Path $ProjectRoot "server"
$ServerUrl = "https://localhost:5001"

# Start Angular dev server in a new window
Write-Host "Starting UI (ng serve --ssl)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$UiPath'; ng serve --ssl"

# Wait for UI to be serving index.html (try HTTPS first, then HTTP)
$UiPort = 4201
$UiUrlHttps = "https://localhost:$UiPort"
$UiUrlHttp = "http://localhost:$UiPort"
$IndexPath = "/index.html"
$MaxWaitSeconds = 60
$Elapsed = 0
Write-Host "Waiting for UI (GET index.html) at $UiUrlHttps or $UiUrlHttp (max ${MaxWaitSeconds}s)..." -ForegroundColor Cyan
# Load index.html over HTTPS like browser "continue anyway" (self-signed cert): use TLS 1.2 and accept any cert for this check only
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$prevCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
try {
    while ($Elapsed -lt $MaxWaitSeconds) {
        $ready = $false
        $usedUrl = $null
        try {
            $uri = "$UiUrlHttps$IndexPath"
            $params = @{ Uri = $uri; UseBasicParsing = $true; TimeoutSec = 2 }
            if ($PSVersionTable.PSVersion.Major -ge 6) { $params['SkipCertificateCheck'] = $true }
            Invoke-WebRequest @params | Out-Null
            $ready = $true
            $usedUrl = $UiUrlHttps
        } catch {
            try {
                Invoke-WebRequest -Uri "$UiUrlHttp$IndexPath" -UseBasicParsing -TimeoutSec 2 | Out-Null
                $ready = $true
                $usedUrl = $UiUrlHttp
            } catch { }
        }
        if ($ready) {
            Write-Host "UI is ready at $usedUrl (index.html)." -ForegroundColor Green
            break
        }
        Start-Sleep -Seconds 2
        $Elapsed += 2
    }
} finally {
    [Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCallback
}
if ($Elapsed -ge $MaxWaitSeconds) {
    Write-Error "UI did not start within ${MaxWaitSeconds}s. Aborting."
    exit 1
}

# Start BFF server in a new window
Write-Host "Starting server (dotnet run)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ServerPath'; dotnet run"

# Wait for BFF server to be listening before opening browser
$BffMaxWaitSeconds = 60
$BffElapsed = 0
Write-Host "Waiting for BFF server at $ServerUrl (max ${BffMaxWaitSeconds}s)..." -ForegroundColor Cyan
$prevBffCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
try {
    while ($BffElapsed -lt $BffMaxWaitSeconds) {
        try {
            $params = @{ Uri = $ServerUrl; UseBasicParsing = $true; TimeoutSec = 2 }
            if ($PSVersionTable.PSVersion.Major -ge 6) { $params['SkipCertificateCheck'] = $true }
            Invoke-WebRequest @params | Out-Null
            Write-Host "BFF server is ready at $ServerUrl." -ForegroundColor Green
            break
        } catch { }
        Start-Sleep -Seconds 2
        $BffElapsed += 2
    }
} finally {
    [Net.ServicePointManager]::ServerCertificateValidationCallback = $prevBffCallback
}
if ($BffElapsed -ge $BffMaxWaitSeconds) {
    Write-Warning "BFF server did not start within ${BffMaxWaitSeconds}s. Not opening browser."
    exit 1
}

# Open browser to BFF
Write-Host "Opening $ServerUrl in browser..." -ForegroundColor Green
Start-Process $ServerUrl

Write-Host "Done. Close the UI and Server windows when finished." -ForegroundColor Yellow
