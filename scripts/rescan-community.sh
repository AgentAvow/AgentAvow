#!/usr/bin/env bash
# Re-score all CommunityScan rows (live user scans, all surfaces) with the current
# scorer; Browse picks the new rows up within a minute. Small one-off (~hundreds of
# rows). Run on the host.
set -uo pipefail
cd "$(dirname "$0")/.."
PY="./.venv/bin/python3"; [ -x "$PY" ] || PY="python3"
GITHUB_TOKEN="$(grep -E '^GITHUB_TOKEN=' .env.secrets 2>/dev/null | cut -d= -f2- | sed 's/^["'\'']//; s/["'\'']$//')"
export GITHUB_TOKEN
echo "[$(date -u +%FT%TZ)] rescan-community: start"
"$PY" scripts/launch_scans/rescore_community.py
# No catalog refresh call: community rows live in the DB and every backend worker
# re-reads them within COMMUNITY_ROWS_TTL_SECONDS (60s).
echo "[$(date -u +%FT%TZ)] rescan-community: done"
