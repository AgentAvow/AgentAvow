#!/usr/bin/env bash
# Sign the served /.well-known/agent-card.json on the prod host (A2A 1.0 §8.4).
#
# The committed web/public copy is unsigned: signing needs the production P-256
# catalog key (CATALOG_SIGNING_KEY_P256 in .env.secrets), which only the host has.
# This script signs a temporary copy inside the backend image with that key (kid
# catalog-es256-v1, jku https://agentavow.com/.well-known/jwks.json, the JWKS that
# already publishes the key), verifies it against the LIVE JWKS, and installs the
# result into web/dist so nginx serves it. It never touches the git working tree and
# never prints the key.
#
# Run after every frontend build, because `npm run build` copies the unsigned
# web/public card back into web/dist. scripts/deploy-prod.sh does this (warn-only:
# an unsigned card still serves, and the A2A check reads "not signed" as an info
# note). By hand on the host:  ./scripts/refresh_agent_card.sh
set -euo pipefail
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
cd "$(dirname "$0")/.."
REPO="$PWD"
set -a; . ./.env.production; . ./.env.secrets; set +a

WORK="$(mktemp -d /tmp/agent-card-sign.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/public/.well-known"
cp web/public/.well-known/agent-card.json "$WORK/public/.well-known/agent-card.json"
chmod -R a+rwX "$WORK"

DC="sudo -E docker-compose -f docker-compose.prod.yml"
RUN="$DC run --rm --no-deps -T --user root -v $WORK/public:/app/web/public -v $REPO/scripts:/app/scripts backend"

$RUN python3 scripts/agent_card_wellknown.py sign --prod
$RUN python3 scripts/agent_card_wellknown.py verify --resolve

OUT="$WORK/public/.well-known/agent-card.json"
sudo chown "$(id -u):$(id -g)" "$OUT"
DEST="web/dist/.well-known/agent-card.json"
mkdir -p "$(dirname "$DEST")"
install -m 644 "$OUT" "$DEST.tmp" && mv -f "$DEST.tmp" "$DEST"
echo "signed $DEST at $(date -u +%FT%TZ)"
