#!/usr/bin/env bash
# Behavioral sandbox runner — Phase 0 prototype.
# Runs a command in an image inside a gVisor-isolated container whose ONLY network path is
# a logging egress proxy, then reports observed egress + exit status as JSON.
#
#   ./behavioral_run.sh <image> '<command>'  [timeout_secs]
#
# Requires a dedicated Linux host with Docker + gVisor (runsc). NEVER run on the prod box.
# See README.md. Phase 1 replaces proxy-env egress with a transparent iptables redirect and
# adds filesystem/process capture + automatic artifact materialization.
set -uo pipefail

IMAGE="${1:?usage: behavioral_run.sh <image> <command> [timeout]}"
CMD="${2:?usage: behavioral_run.sh <image> <command> [timeout]}"
TIMEOUT="${3:-45}"

# Use gVisor if installed; otherwise warn (plain runc is NOT a safe boundary for malware).
RUNTIME="runsc"
if ! docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q runsc; then
  echo "WARN: runsc (gVisor) runtime not found — falling back to default runtime, which is" >&2
  echo "      NOT a safe boundary for untrusted code. Install gVisor before real use." >&2
  RUNTIME="runc"
fi

RUN_ID="beh_$(date +%s)_$$"
NET="${RUN_ID}_net"
PROXY="${RUN_ID}_proxy"
TARGET="${RUN_ID}_target"
PROXY_LOG="$(mktemp)"

cleanup() {
  docker rm -f "$TARGET" "$PROXY" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -f "$PROXY_LOG" "$PROXY_CONF" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Private network — internal so the target has no route out except via the proxy.
docker network create --internal "$NET" >/dev/null

# 2. Logging egress proxy (tinyproxy) — the only path out. LogLevel Connect logs each host.
PROXY_CONF="$(mktemp)"
cat > "$PROXY_CONF" <<'CONF'
Port 8888
Listen 0.0.0.0
Timeout 30
LogLevel Connect
Allow 0.0.0.0/0
CONF
# NOTE: give the PROXY (only) real internet by also attaching it to the default bridge.
docker run -d --name "$PROXY" --network "$NET" \
  -v "$PROXY_CONF:/etc/tinyproxy/tinyproxy.conf:ro" \
  kalaksi/tinyproxy >/dev/null 2>&1 \
  || { echo '{"error":"proxy_start_failed"}'; exit 1; }
docker network connect bridge "$PROXY" >/dev/null 2>&1 || true

# 3. Run the target — gVisor, read-only, no mounts, capped, egress only via the proxy,
#    hard wall-clock kill. All outbound HTTP(S) is forced through the logging proxy.
docker run --rm --name "$TARGET" \
  --runtime="$RUNTIME" \
  --network "$NET" \
  --read-only --tmpfs /tmp --tmpfs /run \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 512m --cpus 1 --pids-limit 256 \
  -e "HTTP_PROXY=http://${PROXY}:8888" -e "HTTPS_PROXY=http://${PROXY}:8888" \
  -e "http_proxy=http://${PROXY}:8888" -e "https_proxy=http://${PROXY}:8888" \
  "$IMAGE" sh -c "$CMD" >/dev/null 2>&1 &
TARGET_PID=$!

TIMED_OUT=false
if ! ( sleep "$TIMEOUT" && kill -0 "$TARGET_PID" 2>/dev/null && docker kill "$TARGET" >/dev/null 2>&1 ) &
then :; fi
wait "$TARGET_PID"; EXIT_CODE=$?
# if the watchdog killed it, docker returns 137
[ "$EXIT_CODE" = "137" ] && TIMED_OUT=true

# 4. Observed egress — the distinct hosts the proxy saw the target CONNECT to.
docker logs "$PROXY" 2>&1 > "$PROXY_LOG" || true
HOSTS_JSON=$(grep -oiE 'Connect(ing)? to [^ :]+' "$PROXY_LOG" 2>/dev/null \
  | awk '{print $NF}' | sort -u \
  | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]')

python3 - "$IMAGE" "$EXIT_CODE" "$TIMED_OUT" "$HOSTS_JSON" <<'PY'
import sys, json
image, exit_code, timed_out, hosts = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "true", sys.argv[4]
print(json.dumps({
    "image": image,
    "exit_code": exit_code,
    "timed_out": timed_out,
    "egress_hosts": json.loads(hosts),
    "schema": "behavioral-v0-prototype",
    "note": "proxy-env egress capture; Phase 1 uses a transparent redirect + fs/proc capture",
}, indent=2))
PY
