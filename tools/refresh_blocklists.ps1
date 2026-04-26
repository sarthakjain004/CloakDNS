# tools/refresh_blocklists.ps1 - fetch, parse, merge upstream blocklists.
#
# Convenience wrapper around tools/update_blocklists.py. Writes
# blocklists/merged.txt from the sources in tools/blocklist_sources.toml.
#
# Pass extra arguments through, e.g. --no-conditional to force refetch:
#   .\tools\refresh_blocklists.ps1 --no-conditional
#
# After this finishes, send Ctrl+Break to a running cloakdns console
# to trigger SIGBREAK hot-reload (M11). Or just restart the server.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $PSCommandPath
$RepoRoot  = Split-Path -Parent $ScriptDir
Push-Location $RepoRoot
try {
    & py -3 tools/update_blocklists.py `
        --sources tools/blocklist_sources.toml `
        --out blocklists/merged.txt @args
} finally {
    Pop-Location
}
