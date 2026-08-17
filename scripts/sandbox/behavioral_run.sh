#!/usr/bin/env bash
# Behavioral sandbox runner — Phase 1.
# Runs a command in an image inside a gVisor-isolated container and PASSIVELY records the
# hosts it contacts (DNS query names + TLS SNI, captured inside the container's network
# namespace so it CANNOT be bypassed by ignoring HTTP_PROXY) plus the files it writes
# (container diff). Emits a JSON BehavioralResult on stdout.
#
#   ./behavioral_run.sh <image> '<command>' [timeout_secs]
#
# Requires a DEDICATED Linux host with Docker + gVisor (runsc) + tcpdump, run as root.
# NEVER run on the prod box (signing keys + memory-tight). See README.md.
#
# NOTE: written for a gVisor host; validate end-to-end there before wiring into the scan
# pipeline. The Python orchestrator (src/scanner/behavioral/) fails OPEN if this is absent.
set -uo pipefail

IMAGE="${1:?usage: behavioral_run.sh <image> <command> [timeout]}"
CMD="${2:?usage: behavioral_run.sh <image> <command> [timeout]}"
TIMEOUT="${3:-45}"

RUNTIME="runsc"
docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q runsc || {
  echo '{"error":"gvisor_runtime_missing"}'; exit 0; }

RUN_ID="beh_$(date +%s)_$$"
NAME="${RUN_ID}"
PCAP="$(mktemp /tmp/${RUN_ID}.XXXX.pcap)"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -f "$PCAP" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# 1. Start the target: gVisor, read-only root, no host mounts, dropped caps, capped, and a
#    real network (we observe passively rather than proxy, so nothing to bypass).
docker run -d --name "$NAME" \
  --runtime="$RUNTIME" \
  --read-only --tmpfs /tmp:exec --tmpfs /run \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 512m --cpus 1 --pids-limit 256 \
  "$IMAGE" sh -c "$CMD" >/dev/null 2>&1 \
  || { echo '{"error":"container_start_failed"}'; exit 0; }

# 2. Capture DNS + TLS SNI inside the container's network namespace for the run's duration.
CPID="$(docker inspect -f '{{.State.Pid}}' "$NAME" 2>/dev/null)"
if [ -n "${CPID:-$CPID}" ] && [ "$CPID" != "0" ]; then
  nsenter -t "$CPID" -n timeout "$TIMEOUT" \
    tcpdump -l -nn -w "$PCAP" '(udp port 53) or (tcp port 443)' >/dev/null 2>&1 &
  TCPDUMP_PID=$!
fi

# 3. Wait for the target, bounded by the wall-clock timeout.
TIMED_OUT=false
if timeout "$TIMEOUT" docker wait "$NAME" >/tmp/${RUN_ID}.exit 2>/dev/null; then
  EXIT_CODE="$(cat /tmp/${RUN_ID}.exit 2>/dev/null || echo -1)"
else
  TIMED_OUT=true; EXIT_CODE=124; docker kill "$NAME" >/dev/null 2>&1 || true
fi
kill "${TCPDUMP_PID:-}" >/dev/null 2>&1 || true
wait "${TCPDUMP_PID:-}" 2>/dev/null || true
rm -f /tmp/${RUN_ID}.exit >/dev/null 2>&1 || true

# 4. Extract egress hostnames — DNS query names + TLS SNI — and files the container wrote.
HOSTS_JSON="$(
  { tcpdump -nn -r "$PCAP" 2>/dev/null | grep -oiE 'A\? [a-z0-9._-]+' | awk '{print $2}' | sed 's/\.$//'
    tcpdump -nn -A -r "$PCAP" 2>/dev/null | grep -oiE 'server_name.{0,60}' | grep -oiE '[a-z0-9.-]+\.[a-z]{2,}' ; } \
  | tr 'A-Z' 'a-z' | sort -u \
  | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]'
)"
FS_JSON="$(docker diff "$NAME" 2>/dev/null | grep -E '^[AC] ' \
  | grep -vE ' /(tmp|run|proc|sys|dev)(/|$)' | awk '{print $2}' | head -100 \
  | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]')"

python3 - "$IMAGE" "$EXIT_CODE" "$TIMED_OUT" "$HOSTS_JSON" "$FS_JSON" <<'PY'
import sys, json
image, exit_code, timed_out, hosts, fs = sys.argv[1:6]

def _arr(s):
    # The shell capture can carry a doubled/blank fallback (e.g. "[]\n[]"); take the
    # first line that parses as a JSON array, else empty. Keeps the runner robust.
    for line in (s or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            v = json.loads(line)
            if isinstance(v, list):
                return v
        except Exception:
            continue
    return []

print(json.dumps({
    "image": image,
    "exit_code": int(exit_code) if str(exit_code).lstrip("-").isdigit() else None,
    "timed_out": timed_out == "true",
    "egress_hosts": _arr(hosts),
    "fs_writes": _arr(fs),
    "schema": "behavioral-v1",
}))
PY
