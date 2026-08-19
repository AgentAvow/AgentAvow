#!/usr/bin/env bash
# Weekly Docker cleanup for the prod host. Deploys build a fresh backend image each
# time; the old ones pile up and eventually fill the 30G root volume (this bit us
# 2026-08-19 at 100%). This reclaims images + build cache + stopped containers.
#
# SAFE: never touches named VOLUMES (postgres/redis data) or RUNNING containers.
# Install as a weekly cron (see scripts/install-prune-cron.sh) and/or called from
# deploy-prod.sh after a successful deploy.
set -uo pipefail

echo "=== docker prune $(date -u +%FT%TZ) ==="
df -h / | awk 'NR==2 {print "before: " $5 " used, " $4 " free"}'

docker image prune -af   >/dev/null 2>&1 || true   # dangling + unreferenced images
docker builder prune -af >/dev/null 2>&1 || true   # build cache
docker container prune -f >/dev/null 2>&1 || true  # stopped containers only

df -h / | awk 'NR==2 {print "after:  " $5 " used, " $4 " free"}'
