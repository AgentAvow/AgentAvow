#!/usr/bin/env bash
# Weekly re-scan: re-runs the four launch-scan datasets (x402 / MCP /
# npm / PyPI) and invalidates the /scans catalog in-memory cache.
#
# Press story: "we publish the trail, not a frozen PDF" — only works
# if the trail keeps growing. This script is the cadence anchor.
#
# Crontab (EC2): every Sunday at 02:00 UTC
#   0 2 * * 0 cd /home/ec2-user/agentgraph && bash scripts/weekly_rescan.sh >> data/launch-scans/weekly.log 2>&1
#
# Manual run:
#   bash scripts/weekly_rescan.sh
#
# Each scan respects rate limits and pacing per the script's own
# config. The MCP scan is the slowest (~30-60 min); x402 next (~20
# min). npm + PyPI under 5 min each. Total ~60-90 min.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

LOG_TS() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf '[%s] %s\n' "$(LOG_TS)" "$*"; }

log "weekly_rescan: start"

# RE-SCORE existing corpus entries in place — non-destructive. The old flow re-ran the
# discover+scan launch scripts, which (a) default to dry-run without --run and (b) via
# their progress skip-set could OVERWRITE a results file with a shrunken subset. This
# instead re-scans the coordinates already in the corpus and updates scores in place,
# never dropping a row. Uses the project venv (system python3 on the host lacks deps).
# Bounded + resumable per run; a larger --limit here since this is the weekly full-ish pass.
PY="./.venv/bin/python3"
[ -x "$PY" ] || PY="python3"
# GITHUB_TOKEN from .env.secrets (do NOT `source .env` — it breaks pydantic cors parse).
GITHUB_TOKEN="$(grep -E '^GITHUB_TOKEN=' .env.secrets 2>/dev/null | cut -d= -f2- | sed 's/^["'\'']//; s/["'\'']$//')"
export GITHUB_TOKEN
log "re-scoring corpus (venv=$PY, token=$([ -n "$GITHUB_TOKEN" ] && echo yes || echo no))"
if "$PY" scripts/launch_scans/rescore_corpus.py --limit 400; then
  log "rescore OK"
else
  log "rescore FAILED (exit $?)"
fi

# Invalidate the /scans catalog cache. Backend runs in Docker, so localhost:8000 is not
# reachable from the host — go through nginx on the public URL instead.
log "refreshing catalog cache"
curl -fsS -X POST "https://agentavow.com/api/v1/public/scan-catalog/refresh" \
  -H "Content-Type: application/json" --max-time 30 \
  || log "catalog refresh failed (cache will rebuild on next request)"

log "weekly_rescan: done"
