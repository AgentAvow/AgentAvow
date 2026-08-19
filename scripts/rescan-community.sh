#!/usr/bin/env bash
# Re-score all CommunityScan rows (live user scans, all surfaces) with the current
# scorer, then refresh Browse. Small one-off (~hundreds of rows). Run on the host.
set -uo pipefail
cd "$(dirname "$0")/.."
PY="./.venv/bin/python3"; [ -x "$PY" ] || PY="python3"
GITHUB_TOKEN="$(grep -E '^GITHUB_TOKEN=' .env.secrets 2>/dev/null | cut -d= -f2- | sed 's/^["'\'']//; s/["'\'']$//')"
export GITHUB_TOKEN
echo "[$(date -u +%FT%TZ)] rescan-community: start"
"$PY" scripts/launch_scans/rescore_community.py
curl -fsS -X POST "https://agentavow.com/api/v1/public/scan-catalog/refresh" --max-time 30 \
  && echo "[$(date -u +%FT%TZ)] catalog refreshed" || echo "refresh failed"
echo "[$(date -u +%FT%TZ)] rescan-community: done"
