#!/usr/bin/env bash
# tools/refresh_blocklists.sh — fetch, parse, merge upstream blocklists.
#
# Convenience wrapper around tools/update_blocklists.py. Writes
# blocklists/merged.txt from the sources defined in
# tools/blocklist_sources.toml. Pass --no-conditional to force a full
# refetch ignoring etag/Last-Modified caches.
#
# After this completes, send SIGHUP to a running cloakdns to reload the
# blocklist without restarting the server. On Linux:
#
#   pkill -HUP cloakdns
#
# On Windows (PowerShell):
#
#   Stop-Process -Id <pid> -Force; .\build-msvc\cloakdns.exe ...
#
# (Windows uses SIGBREAK for hot reload; the convenience signal is
# Ctrl+Break in a console attached to the cloakdns process.)
set -euo pipefail
cd "$(dirname "$0")/.."

PY=${PY:-python3}
exec "$PY" tools/update_blocklists.py \
    --sources tools/blocklist_sources.toml \
    --out blocklists/merged.txt "$@"
