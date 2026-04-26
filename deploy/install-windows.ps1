# CloakDNS Windows Service installer.
# Usage (from elevated PowerShell):
#   .\install-windows.ps1              # install and start
#   .\install-windows.ps1 -Uninstall   # stop and remove

param(
    [switch]$Uninstall,
    [string]$BinaryPath = (Join-Path $PSScriptRoot "..\build-msvc\cloakdns.exe"),
    [string]$ConfigDir  = "$env:ProgramData\CloakDNS"
)

$ServiceName = "CloakDNS"

if ($Uninstall) {
    Write-Host "Stopping and removing $ServiceName..."
    & sc.exe stop   $ServiceName 2>$null
    & sc.exe delete $ServiceName
    exit 0
}

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found at $BinaryPath. Build first (build-msvc.bat) or pass -BinaryPath."
    exit 1
}

if (-not (Test-Path $ConfigDir)) {
    Write-Host "Creating config dir $ConfigDir"
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

$LogDir = Join-Path $ConfigDir "logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$ConfigPath = Join-Path $ConfigDir "cloakdns.toml"
if (-not (Test-Path $ConfigPath)) {
    $SampleConfig = Join-Path $PSScriptRoot "..\cloakdns.toml"
    if (Test-Path $SampleConfig) {
        Write-Host "Seeding default config from $SampleConfig"
        Copy-Item $SampleConfig $ConfigPath
    } else {
        Write-Warning "No sample config found. Create $ConfigPath before starting the service."
    }
}

# Lock down the config + log directory: only Administrators and the
# virtual service account get access. Removes inherited Users / Authenticated
# Users entries that would otherwise let any local user read the query log.
Write-Host "Hardening ACLs on $ConfigDir"
$Account = "NT SERVICE\$ServiceName"
& icacls.exe $ConfigDir /inheritance:r /grant:r `
    "$Account:(OI)(CI)M" `
    "Administrators:(OI)(CI)F" `
    "SYSTEM:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warning "icacls returned $LASTEXITCODE on $ConfigDir; continuing anyway."
}

# Resolve to absolute path for sc.exe.
$AbsBinary = (Resolve-Path $BinaryPath).Path

Write-Host "Installing $ServiceName..."
# Virtual service account (NT SERVICE\<ServiceName>) gets SIDs automatically.
# No login password; the service runs with minimal rights.
& sc.exe create $ServiceName `
    binPath= "`"$AbsBinary`" `"$ConfigPath`"" `
    start= auto `
    DisplayName= "CloakDNS tracker-blocking DNS" `
    obj= "NT SERVICE\$ServiceName"

& sc.exe description $ServiceName "DNS-level tracker blocker with CNAME uncloaking."
& sc.exe failure     $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000

Write-Host "Starting $ServiceName..."
& sc.exe start $ServiceName
