# tools/capture_chrome_dns.ps1
#
# Self-elevating DNS-capture helper. Run with:
#
#   powershell -ExecutionPolicy Bypass -File tools\capture_chrome_dns.ps1
#
# (no need to start an elevated shell first -- the script will UAC-prompt
# itself if needed, then re-run as Administrator).
#
# What it does:
#   1. Reads current Wi-Fi DNS, saves to .\dns-restore.json.
#   2. Switches Wi-Fi DNS to 127.0.0.1 (cloakdns must already be
#      bound to 127.0.0.1:53 -- see cloakdns-capture.toml).
#   3. Sleeps until you Ctrl+C, all the while your real Chrome
#      (and every other app on this machine) sends DNS to cloakdns.
#   4. Restores the saved DNS in a finally block -- even if you
#      Ctrl+C, the script crashes, or the window closes.
#
# Recovery: if the script dies before restoring (Task Manager kill,
# BSOD, etc.), run with:
#
#   powershell -ExecutionPolicy Bypass -File tools\capture_chrome_dns.ps1 -Restore
#
# That reads dns-restore.json and puts your DNS back without touching
# anything else.

param(
    [string]$InterfaceAlias = "Wi-Fi",
    [int]$Duration          = 0,        # seconds; 0 = until Ctrl+C
    [switch]$Restore                    # restore-only mode
)

$ErrorActionPreference = "Stop"

Write-Host "=== capture_chrome_dns.ps1 starting ===" -ForegroundColor Cyan
Write-Host ("PID:           {0}" -f $PID)
Write-Host ("WorkingDir:    {0}" -f (Get-Location).Path)
Write-Host ("ScriptDir:     {0}" -f $PSScriptRoot)
$argSummary = ($PSBoundParameters.GetEnumerator() |
               ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " "
Write-Host ("Args:          {0}" -f $argSummary)

# --- Self-elevate if not already admin ---
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Not running as Administrator. Re-launching elevated..." `
        -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Path
    $argList = @(
        "-NoProfile", "-NoExit", "-ExecutionPolicy", "Bypass",
        "-File", "`"$scriptPath`"",
        "-InterfaceAlias", "`"$InterfaceAlias`""
    )
    if ($Duration -gt 0) {
        $argList += @("-Duration", "$Duration")
    }
    if ($Restore) {
        $argList += "-Restore"
    }
    Start-Process -FilePath "powershell.exe" `
                  -ArgumentList $argList `
                  -Verb RunAs `
                  -WorkingDirectory (Get-Location).Path
    exit
}

$RestorePath = Join-Path $PSScriptRoot "..\dns-restore.json"
$RestorePath = [System.IO.Path]::GetFullPath($RestorePath)

# --- Restore-only mode ---
if ($Restore) {
    if (-not (Test-Path $RestorePath)) {
        Write-Host "No restore file at $RestorePath -- nothing to do." `
            -ForegroundColor Yellow
        exit 1
    }
    $saved = Get-Content $RestorePath -Raw | ConvertFrom-Json
    Write-Host ("Restoring {0} -> {1}" -f $saved.InterfaceAlias,
        ($saved.ServerAddresses -join ", ")) -ForegroundColor Yellow
    if ($saved.ServerAddresses -and $saved.ServerAddresses.Count -gt 0) {
        Set-DnsClientServerAddress -InterfaceAlias $saved.InterfaceAlias `
                                    -ServerAddresses $saved.ServerAddresses
    } else {
        Set-DnsClientServerAddress -InterfaceAlias $saved.InterfaceAlias `
                                    -ResetServerAddresses
    }
    ipconfig /flushdns | Out-Null
    Write-Host "Restored." -ForegroundColor Green
    Remove-Item $RestorePath -Force
    Read-Host "Press Enter to close"
    exit 0
}

# --- Verify cloakdns is listening on 127.0.0.1:53 before we switch.
# Using netstat (fast, no CIM/WMI) instead of Get-NetUDPEndpoint
# because the latter hangs on heavily-loaded systems. ---
Write-Host "Checking 127.0.0.1:53 ..." -ForegroundColor DarkGray
$netstatOut = & netstat.exe -ano -p UDP 2>$null
$bound = $netstatOut | Where-Object { $_ -match '127\.0\.0\.1:53\s' }
if (-not $bound) {
    Write-Host "Nothing listening on 127.0.0.1:53." -ForegroundColor Red
    Write-Host "Start the capture cloakdns first via your normal shell." -ForegroundColor Yellow
    Read-Host "Press Enter to close"
    exit 2
}
Write-Host "  cloakdns OK on 127.0.0.1:53" -ForegroundColor Green

# --- Save current DNS state to disk BEFORE we touch anything ---
$current = Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias `
                                       -AddressFamily IPv4
$state = [ordered]@{
    InterfaceAlias  = $InterfaceAlias
    ServerAddresses = @($current.ServerAddresses)
    SavedAt         = (Get-Date).ToString("o")
}
$state | ConvertTo-Json | Set-Content -Path $RestorePath -Encoding utf8
Write-Host "Saved restore state to $RestorePath" -ForegroundColor DarkGray
Write-Host ("  Original DNS: {0}" -f ($state.ServerAddresses -join ", "))

# --- Active block: set DNS, wait, restore. Single try/finally so the
#     restore path runs even if Set-DnsClientServerAddress half-succeeds. ---
$switched = $false
try {
    Write-Host "Switching $InterfaceAlias DNS -> 127.0.0.1 ..." `
        -ForegroundColor Yellow
    Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias `
                                -ServerAddresses ("127.0.0.1")
    $switched = $true
    ipconfig /flushdns | Out-Null
    Write-Host "Active. Every DNS query from this machine now goes through cloakdns." `
        -ForegroundColor Green
    Write-Host "Logged to: chrome-capture.jsonl" -ForegroundColor DarkGray
    Write-Host ""
    if ($Duration -gt 0) {
        Write-Host ("Will auto-restore after {0} seconds. Ctrl+C to stop early." -f $Duration) `
            -ForegroundColor Yellow
        Start-Sleep -Seconds $Duration
    } else {
        Write-Host "Press Ctrl+C to stop and restore DNS." -ForegroundColor Yellow
        while ($true) { Start-Sleep -Seconds 1 }
    }
}
finally {
    if ($switched) {
        Write-Host ""
        Write-Host "Restoring $InterfaceAlias DNS ..." -ForegroundColor Yellow
        try {
            if ($state.ServerAddresses -and $state.ServerAddresses.Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias `
                                            -ServerAddresses $state.ServerAddresses
            } else {
                Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias `
                                            -ResetServerAddresses
            }
            ipconfig /flushdns | Out-Null
            Write-Host ("Restored: {0}" -f ($state.ServerAddresses -join ", ")) `
                -ForegroundColor Green
            Remove-Item $RestorePath -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "RESTORE FAILED. Run with the -Restore switch to retry." -ForegroundColor Red
            throw
        }
    }
}
