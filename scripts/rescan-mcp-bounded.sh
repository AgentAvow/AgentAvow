#!/usr/bin/env bash
# Bounded MCP re-scan — re-fetches + re-analyzes the top N MCP corpus rows with the
# CURRENT scorer (post the 2026-08-19 critical-consistency fix); Browse reloads by itself.
# Re-scan (not recalc) is required: stored rows kept only score summaries, not the
# per-finding paths the new shipped/non-shipped logic needs. Safe + non-destructive:
# rescore_corpus.py updates scores IN PLACE and never drops a row.
#
#   LIMIT=300 ./scripts/rescan-mcp-bounded.sh
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"
LIMIT="${LIMIT:-300}"
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf '[%s] %s\n' "$(ts)" "$*"; }

PY="./.venv/bin/python3"
[ -x "$PY" ] || PY="python3"
GITHUB_TOKEN="$(grep -E '^GITHUB_TOKEN=' .env.secrets 2>/dev/null | cut -d= -f2- | sed 's/^["'\'']//; s/["'\'']$//')"
export GITHUB_TOKEN

log "rescan-mcp: start (limit=$LIMIT, venv=$PY, token=$([ -n "$GITHUB_TOKEN" ] && echo yes || echo no))"
if "$PY" scripts/launch_scans/rescore_corpus.py --surface mcp --limit "$LIMIT"; then
  log "rescore OK"
else
  log "rescore FAILED (exit $?)"
fi
# No catalog refresh call: backend workers reload Browse when the results file changes.
log "catalog: backend workers reload the rewritten results file within ~2 min"
log "rescan-mcp: done"
