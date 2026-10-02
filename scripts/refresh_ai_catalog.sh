#!/usr/bin/env bash
# Refresh and re-sign the served /.well-known/ai-catalog.json on the prod host.
#
# The catalog inlines a live AgentAvow self-scan attestation that expires 24h
# after it was issued, and the trust manifest itself expires 30 days after
# signing. This script rebuilds the catalog with a fresh self-scan, signs it with
# the production ES256 catalog key (CATALOG_SIGNING_KEY_P256 in .env.secrets),
# verifies it strictly against the live DID document, and installs the result
# into web/dist so nginx serves it. It never touches the git working tree: the
# committed web/public copy stays a dated snapshot, so deploys keep working.
#
# Cron (host, daily, UTC):  15 1 * * * /home/ec2-user/agentgraph/scripts/refresh_ai_catalog.sh >> /home/ec2-user/ai-catalog-refresh.log 2>&1
set -euo pipefail
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
cd "$(dirname "$0")/.."
REPO="$PWD"
set -a; . ./.env.production; . ./.env.secrets; set +a

WORK="$(mktemp -d /tmp/ai-catalog-refresh.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/public/.well-known"
cp web/public/.well-known/ai-catalog.json "$WORK/public/.well-known/ai-catalog.json"
chmod -R a+rwX "$WORK"

DC="sudo -E docker-compose -f docker-compose.prod.yml"
RUN="$DC run --rm --no-deps -T --user root -v $WORK/public:/app/web/public -v $REPO/scripts:/app/scripts -v $REPO/docs:/app/docs backend"

$RUN python3 scripts/ai_catalog_wellknown.py build --self-scan
$RUN python3 scripts/ai_catalog_wellknown.py sign --prod
$RUN python3 scripts/ai_catalog_wellknown.py verify --resolve

OUT="$WORK/public/.well-known/ai-catalog.json"
sudo chown "$(id -u):$(id -g)" "$OUT"
python3 - "$OUT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
b = d["extensions"]["com.agentavow.catalogBuild"]
assert b["status"] == "signed", b
print("signed by", b["signerKid"], "manifest expires", d["entries"][0]["trustManifest"].get("expiresAt"))
PY
DEST="web/dist/.well-known/ai-catalog.json"
mkdir -p "$(dirname "$DEST")"
install -m 644 "$OUT" "$DEST.tmp" && mv -f "$DEST.tmp" "$DEST"
echo "refreshed $DEST at $(date -u +%FT%TZ)"
