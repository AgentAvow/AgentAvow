#!/usr/bin/env bash
# Catalog growth: weekly discovery of new tools, daily version refresh (src/catalog_growth).
#
# Starts ONE one-off container of the backend image per job, outside the web backend
# (a deploy that recreates the backend does not kill it; it does not share the
# backend's memory), at low priority: cpu-shares 128, nice 19, a hard memory limit and
# --max-rss-mb under it so the job stops with a message instead of an OOM kill. Same
# pattern as the x402 live run (docs: memory reference_prod_batch_jobs).
# The container gets the running backend's environment and network, so it reaches
# Postgres and Redis exactly as the backend does.
#
# What a run does is decided by CATALOG_DISCOVERY / CATALOG_REFRESH (off | dry-run | on;
# default off) from .env.production, or from this shell's environment, which wins:
#   CATALOG_DISCOVERY=dry-run bash scripts/catalog_growth.sh discover
#
# Crontab (EC2), once the owner turns a job on:
#   20 3 * * 1  cd ~/agentgraph && bash scripts/catalog_growth.sh discover >> data/catalog-growth/cron.log 2>&1
#   50 4 * * *  cd ~/agentgraph && bash scripts/catalog_growth.sh refresh  >> data/catalog-growth/cron.log 2>&1
#
# Read a run:   docker logs --tail 60 catalog-growth-<job>
# Work list:    data/catalog-growth/plan-<job>-<mode>.json   (counts at the top)
# Queue/status: bash scripts/catalog_growth.sh status
set -euo pipefail
JOB="${1:-}"
case "$JOB" in discover|refresh|status) ;; *) echo "usage: $0 discover|refresh|status [--max-scans N]"; exit 2;; esac
shift || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
MEM="${CATALOG_GROWTH_MEMORY:-1g}"
MAX_RSS_MB="${CATALOG_GROWTH_MAX_RSS_MB:-800}"
NAME="catalog-growth-$JOB"
IMAGE="agentavow-backend:latest"
mkdir -p data/catalog-growth

BACKEND="$(docker ps --filter 'label=com.docker.compose.service=backend' --format '{{.Names}}' | head -1)"
if [ -z "$BACKEND" ]; then echo "catalog_growth: backend container not running; not starting"; exit 1; fi
if docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
  echo "catalog_growth: $NAME is still running; not starting another"; exit 0
fi
docker rm "$NAME" >/dev/null 2>&1 || true

NET="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$BACKEND" | awk '{print $1}')"
ENVFILE="$(mktemp "$HOME/.catalog-growth-env.XXXXXX")"
chmod 600 "$ENVFILE"
trap 'rm -f "$ENVFILE"' EXIT
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$BACKEND" | grep -v '^$' > "$ENVFILE"
OVERRIDES=()
for v in CATALOG_DISCOVERY CATALOG_REFRESH CATALOG_GROWTH_MAX_SCANS_PER_RUN CATALOG_GROWTH_TOP_N; do
  if [ -n "${!v:-}" ]; then OVERRIDES+=(-e "$v=${!v}"); fi
done

ARGS=("$JOB")
[ "$JOB" = "status" ] || ARGS+=(--max-rss-mb "$MAX_RSS_MB")
docker run -d --name "$NAME" \
  --network "$NET" --env-file "$ENVFILE" ${OVERRIDES[@]+"${OVERRIDES[@]}"} \
  --cpu-shares 128 --memory "$MEM" --memory-swap "$MEM" \
  --user "$(id -u):$(id -g)" \
  -v "$ROOT/data/catalog-growth:/app/data/catalog-growth" \
  -v "$ROOT/data/launch-scans:/app/data/launch-scans" \
  --entrypoint nice "$IMAGE" -n 19 python -u -m src.catalog_growth "${ARGS[@]}" "$@" >/dev/null
echo "catalog_growth: started $NAME ($(date -u +%FT%TZ)); follow with: docker logs -f $NAME"
if [ "$JOB" = "status" ]; then docker wait "$NAME" >/dev/null; docker logs "$NAME"; docker rm "$NAME" >/dev/null; fi
