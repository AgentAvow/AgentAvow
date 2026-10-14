#!/usr/bin/env bash
# Full corpus re-scan grind. Loops rescore_corpus.py (all its surfaces: mcp/npm/pypi/
# openclaw) in chunks, re-fetching + re-scoring each row with the CURRENT scorer.
# RESUMABLE: each surface persists a cursor (.rescore-cursor-<surface>.json), so a
# re-launch continues where it left off; a chunk that dies just loses that chunk.
# Browse reloads after every chunk (workers watch the results files), so the catalog
# de-saturates progressively.
#
# Runs for ~2-3 days at ~400 scans/hr (GitHub-API-budget-limited). Safe to re-run.
#   CHUNKS=40 CHUNK=800 nohup ./scripts/grind-rescan.sh > ~/grind.log 2>&1 &
set -uo pipefail
cd "$(dirname "$0")/.."
PY="./.venv/bin/python3"; [ -x "$PY" ] || PY="python3"
GITHUB_TOKEN="$(grep -E '^GITHUB_TOKEN=' .env.secrets 2>/dev/null | cut -d= -f2- | sed 's/^["'\'']//; s/["'\'']$//')"
export GITHUB_TOKEN
CHUNKS="${CHUNKS:-40}"
CHUNK="${CHUNK:-800}"
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

echo "[$(ts)] grind: start ($CHUNKS chunks x $CHUNK rows; token=$([ -n "$GITHUB_TOKEN" ] && echo yes || echo no))"
for i in $(seq 1 "$CHUNKS"); do
  echo "[$(ts)] --- chunk $i/$CHUNKS ---"
  "$PY" scripts/launch_scans/rescore_corpus.py --limit "$CHUNK" 2>&1 | tail -3 || echo "[$(ts)] chunk $i rescore failed (continuing)"
  # No catalog refresh call: backend workers reload Browse when a results file changes.
  sleep 90   # brief breather so the GitHub API budget replenishes between chunks
done
echo "[$(ts)] grind: done ($CHUNKS chunks)"
