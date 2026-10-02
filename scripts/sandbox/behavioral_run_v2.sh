#!/usr/bin/env bash
# Behavioral sandbox runner — v2 (exec | mcp | image modes).
#
# Runs a target inside a gVisor-isolated container and PASSIVELY records the hosts it
# contacts (DNS query names + TLS SNI + plaintext HTTP Host headers, captured on the host
# side of the docker bridge so the target CANNOT bypass it), the files it writes (container
# diff), whether a credential canary leaked over DNS / plaintext HTTP, and — in mcp mode —
# the MCP exerciser's transcript. Emits ONE JSON object on stdout.
#
#   behavioral_run_v2.sh [options] <image> '<command>' [timeout_secs]        # exec / mcp
#   behavioral_run_v2.sh --mode image [options] <image> [''] [timeout_secs]  # image
#
# Drop-in for v1: `behavioral_run_v2.sh <image> '<cmd>' [timeout]` behaves exactly like
# behavioral_run.sh (mode exec) plus the additional fields below.
#
# Options (all optional, must come BEFORE the positionals):
#   --mode exec|mcp|image   exec (default) and mcp run `sh -c '<command>'` in <image>;
#                           image runs <image> with its OWN ENTRYPOINT/CMD (no sh -c) and
#                           removes the image afterwards when this run pulled it.
#   --files-b64 <b64>       base64 of a JSON object {filename: base64(content)}; the files
#                           are materialized into /work inside the container BEFORE the
#                           command runs (exec/mcp only). The decoded bytes may also be a
#                           gzip stream of that JSON (magic 1f 8b) to keep the SSM command
#                           small. Filenames must be plain (no '/'). Ignored in image mode.
#                           The sandbox host never needs files from the app host.
#   --canary <value>        credential canary; its first 16 chars are searched in DNS query
#                           names and plaintext HTTP (port 80) payloads → canary_exfil.
#   --timeout <secs>        same as the 3rd positional.
#   --memory-mb <MB>        container memory cap (default 512 — unchanged for v1-style calls;
#                           the app passes scanner_behavioral_memory_mb, default 1024).
#   --pids <N>              container pids cap (default 256; the app passes
#                           scanner_behavioral_pids, default 512). exit_code 137 = the
#                           container was SIGKILLed by one of these caps.
#
# Output JSON (schema "behavioral-v2"; every v1 field is kept):
#   {
#     "schema": "behavioral-v2",
#     "image": "<image>",
#     "mode": "exec" | "mcp" | "image",
#     "exit_code": int | null,           # container exit code (124 on wall-clock kill)
#     "timed_out": bool,
#     "egress_hosts": [str],             # DNS names + TLS SNI + HTTP Host, lower-cased, unique
#     "fs_writes": [str],                # added/changed paths outside the tmpfs mounts (≤100)
#     "canary_exfil": [{"via": "dns"|"http", "host": str}],   # [] when no canary / clean
#     "exercise": {...} | null,          # the exerciser's transcript, slimmed (no input
#                                        # schemas, capped strings); if the whole result
#                                        # exceeds 20,000 chars it is emitted instead as
#                                        # {"schema": "behavioral-v2", "gz": "<base64 gzip of the JSON>"}
#                                        # (text between AGENTAVOW_TRANSCRIPT_BEGIN/END on
#                                        # the container's stdout), null when absent
#     "image_pulled": bool,              # image mode: this run pulled (and removed) the image
#     "files_materialized": [str]        # names written into /work from --files-b64
#   }
#   or, on a runner-level failure (no container ran):
#   {"error": "gvisor_runtime_missing" | "container_start_failed" | "image_pull_failed"
#             | "bad_files_payload"}
#
# Requires a DEDICATED Linux host with Docker + gVisor (runsc) + tcpdump + python3, run as
# root. NEVER run on the prod box (signing keys + memory-tight). See README.md.
set -uo pipefail

MODE="exec"
FILES_B64=""
CANARY=""
TIMEOUT_OPT=""
MEMORY_MB="512"
PIDS="256"
while [ $# -gt 0 ]; do
  case "$1" in
    --memory-mb) MEMORY_MB="${2:-512}"; shift 2 ;;
    --memory-mb=*) MEMORY_MB="${1#--memory-mb=}"; shift ;;
    --pids) PIDS="${2:-256}"; shift 2 ;;
    --pids=*) PIDS="${1#--pids=}"; shift ;;
    --mode) MODE="${2:-exec}"; shift 2 ;;
    --mode=*) MODE="${1#--mode=}"; shift ;;
    --files-b64) FILES_B64="${2:-}"; shift 2 ;;
    --files-b64=*) FILES_B64="${1#--files-b64=}"; shift ;;
    --canary) CANARY="${2:-}"; shift 2 ;;
    --canary=*) CANARY="${1#--canary=}"; shift ;;
    --timeout) TIMEOUT_OPT="${2:-}"; shift 2 ;;
    --timeout=*) TIMEOUT_OPT="${1#--timeout=}"; shift ;;
    --) shift; break ;;
    -*) echo "{\"error\":\"unknown_option\"}"; exit 0 ;;
    *) break ;;
  esac
done

USAGE="usage: behavioral_run_v2.sh [--mode exec|mcp|image] [--files-b64 B64] [--canary V] [--memory-mb MB] [--pids N] <image> <command> [timeout]"
IMAGE="${1:?$USAGE}"
if [ "$MODE" = "image" ]; then
  CMD="${2:-}"
else
  CMD="${2:?$USAGE}"
fi
TIMEOUT="${TIMEOUT_OPT:-${3:-45}}"
case "$MODE" in exec|mcp|image) ;; *) echo '{"error":"bad_mode"}'; exit 0 ;; esac
case "$TIMEOUT" in ''|*[!0-9]*) TIMEOUT=45 ;; esac
case "$MEMORY_MB" in ''|*[!0-9]*|0) MEMORY_MB=512 ;; esac
case "$PIDS" in ''|*[!0-9]*|0) PIDS=256 ;; esac
[ "$MEMORY_MB" -gt 4096 ] && MEMORY_MB=4096   # the sandbox box itself is small
[ "$PIDS" -gt 4096 ] && PIDS=4096

RUNTIME="runsc"
docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q runsc || {
  echo '{"error":"gvisor_runtime_missing"}'; exit 0; }

RUN_ID="beh_$(date +%s)_$$"
NAME="${RUN_ID}"
PCAP="$(mktemp /tmp/${RUN_ID}.XXXX.pcap)"
LOGS="$(mktemp /tmp/${RUN_ID}.XXXX.log)"
DNS_TXT="$(mktemp /tmp/${RUN_ID}.XXXX.dns)"
HTTP_TXT="$(mktemp /tmp/${RUN_ID}.XXXX.http)"
IMAGE_PULLED=false
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  [ -n "${NET:-}" ] && docker network rm "$NET" >/dev/null 2>&1 || true
  rm -f "$PCAP" "$LOGS" "$DNS_TXT" "$HTTP_TXT" /tmp/${RUN_ID}.exit >/dev/null 2>&1 || true
  if [ "$IMAGE_PULLED" = true ]; then docker rmi -f "$IMAGE" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

# 0. Materialize shipped files (exec/mcp): the payload is decoded HERE, on the sandbox host,
#    into a prefix of shell commands that writes each file into /work (a tmpfs) before the
#    target command runs. No host mount, no pre-placed files, nothing the target can read
#    outside its own container.
FILES_JSON='[]'
if [ -n "$FILES_B64" ] && [ "$MODE" != "image" ]; then
  # Line 1: JSON list of names; line 2: the materialization prefix (single line).
  PAYLOAD="$(python3 - "$FILES_B64" <<'PY'
import base64, gzip, json, re, shlex, sys
raw = base64.b64decode(sys.argv[1])
if raw[:2] == b"\x1f\x8b":
    raw = gzip.decompress(raw)
obj = json.loads(raw.decode("utf-8"))
if not isinstance(obj, dict) or not obj:
    raise SystemExit(2)
parts, names = [], []
for name, b64 in obj.items():
    name = str(name)
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}", name):
        raise SystemExit(2)
    base64.b64decode(str(b64), validate=True)  # validate: the container decodes it blind
    parts.append("printf %s " + shlex.quote(str(b64)) + " | base64 -d > /work/" + name)
    names.append(name)
print(json.dumps(names))
print(" && ".join(parts) + " && ")
PY
)" || { echo '{"error":"bad_files_payload"}'; exit 0; }
  FILES_JSON="$(printf '%s\n' "$PAYLOAD" | sed -n 1p)"
  PREFIX="$(printf '%s\n' "$PAYLOAD" | sed -n 2p)"
  CMD="${PREFIX}${CMD}"
fi

# Image mode: pull the TARGET image ourselves so we know whether to remove it afterwards.
if [ "$MODE" = "image" ]; then
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    timeout 300 docker pull -q "$IMAGE" >/dev/null 2>&1 || { echo '{"error":"image_pull_failed"}'; exit 0; }
    IMAGE_PULLED=true
  fi
fi

# 1. Start capturing DNS + TLS + plaintext HTTP on the HOST side of a docker bridge that is
#    PRIVATE TO THIS RUN, before the target runs. gVisor uses a user-space netstack, so a
#    capture inside the container's netns sees nothing — we capture where the packets cross
#    the host kernel. A per-run network keeps concurrent runs' egress apart (two runs on the
#    shared docker0 bridge saw each other's DNS; found 2026-10-02).
NET="agv-${RUN_ID}"
if docker network create --driver bridge "$NET" >/dev/null 2>&1; then
  BRIDGE="br-$(docker network inspect -f '{{.Id}}' "$NET" | cut -c1-12)"
else
  NET=""
  BRIDGE="$(docker network inspect bridge -f '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null)"
  [ -z "$BRIDGE" ] && BRIDGE=docker0
fi
timeout "$TIMEOUT" tcpdump -l -nn -i "$BRIDGE" -w "$PCAP" \
  '(udp port 53) or (tcp port 443) or (tcp port 80)' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 0.3  # let tcpdump attach before the target does any egress

# 2. Start the target: gVisor, read-only root, writable tmpfs /tmp + /run + /work (cwd),
#    no host mounts, dropped caps, capped, and a real network (observed passively).
DOCKER_OPTS=(
  -d --name "$NAME" --runtime="$RUNTIME"
  --read-only --tmpfs /tmp:exec --tmpfs /run --tmpfs /work:exec
  --workdir /work
  --cap-drop ALL --security-opt no-new-privileges
  --memory "${MEMORY_MB}m" --cpus 1 --pids-limit "$PIDS"
)
[ -n "$NET" ] && DOCKER_OPTS+=(--network "$NET")
if [ "$MODE" = "image" ]; then
  # The image's own ENTRYPOINT/CMD — what a user would get from `docker run <image>`.
  docker run "${DOCKER_OPTS[@]}" "$IMAGE" >/dev/null 2>&1 \
    || { echo '{"error":"container_start_failed"}'; exit 0; }
else
  docker run "${DOCKER_OPTS[@]}" "$IMAGE" sh -c "$CMD" >/dev/null 2>&1 \
    || { echo '{"error":"container_start_failed"}'; exit 0; }
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

# 4. Observations: the container's stdout (for the exerciser transcript; stderr dropped),
#    egress hostnames (DNS + SNI + HTTP Host), files written, and the canary search.
docker logs "$NAME" 2>/dev/null | head -c 4000000 > "$LOGS" || true
HOSTS_JSON="$(
  { tcpdump -nn -r "$PCAP" 'udp port 53' 2>/dev/null | grep -oiE 'A\? [a-z0-9._-]+' | awk '{print $2}' | sed 's/\.$//'
    tcpdump -nn -A -r "$PCAP" 'tcp port 443' 2>/dev/null | grep -oiE 'server_name.{0,60}' | grep -oiE '[a-z0-9.-]+\.[a-z]{2,}'
    tcpdump -nn -A -r "$PCAP" 'tcp port 80' 2>/dev/null | grep -oiE '^Host: [a-z0-9._-]+' | awk '{print $2}' ; } \
  | tr 'A-Z' 'a-z' | sort -u \
  | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]'
)"
FS_JSON="$(docker diff "$NAME" 2>/dev/null | grep -E '^[AC] ' \
  | grep -vE ' /(tmp|run|proc|sys|dev)(/|$)' | awk '{print $2}' | head -100 \
  | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]')"
tcpdump -nn -r "$PCAP" 'udp port 53' 2>/dev/null | grep -oiE 'A\? [a-z0-9._-]+' | awk '{print $2}' | head -2000 > "$DNS_TXT" || true
tcpdump -nn -A -r "$PCAP" 'tcp port 80' 2>/dev/null | head -c 2000000 > "$HTTP_TXT" || true

python3 - "$IMAGE" "$MODE" "$EXIT_CODE" "$TIMED_OUT" "$HOSTS_JSON" "$FS_JSON" "$CANARY" "$LOGS" \
  "$IMAGE_PULLED" "$FILES_JSON" "$DNS_TXT" "$HTTP_TXT" <<'PY'
import sys, json, re
(image, mode, exit_code, timed_out, hosts, fs, canary, logs_path, image_pulled, files_json,
 dns_path, http_path) = sys.argv[1:13]

def _read(path, limit):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except Exception:
        return ""

dns_txt, http_txt = _read(dns_path, 200000), _read(http_path, 2000000)

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

BEGIN, END = "AGENTAVOW_TRANSCRIPT_BEGIN", "AGENTAVOW_TRANSCRIPT_END"
exercise = None
try:
    with open(logs_path, "rb") as fh:
        out = fh.read().decode("utf-8", "replace")
    i = out.find(BEGIN)
    j = out.find(END, i + len(BEGIN)) if i >= 0 else -1
    if i >= 0 and j >= 0:
        doc = json.loads(out[i + len(BEGIN):j].strip())
        exercise = doc if isinstance(doc, dict) else None
except Exception:
    exercise = None

canary_exfil = []
needle = (canary or "").strip()[:16].lower()
if len(needle) >= 8:
    seen = set()
    for q in (dns_txt or "").splitlines():
        q = q.strip().rstrip(".").lower()
        if needle in q and ("dns", q) not in seen:
            seen.add(("dns", q)); canary_exfil.append({"via": "dns", "host": q})
    # tcpdump -A: one packet per block starting with a timestamp line; the Host header
    # (if any) names the server, else the destination IP from the header line.
    blocks = re.split(r"(?m)^(?=\d\d:\d\d:\d\d\.\d+ )", http_txt or "")
    for b in blocks:
        if needle not in b.lower():
            continue
        m = re.search(r"(?im)^Host:\s*([A-Za-z0-9._:-]+)", b)
        host = m.group(1).lower() if m else ""
        if not host:
            m = re.search(r"> (\d+\.\d+\.\d+\.\d+)\.80[: ]", b)
            host = m.group(1) if m else "unknown"
        if ("http", host) not in seen:
            seen.add(("http", host)); canary_exfil.append({"via": "http", "host": host})

# The result travels back through SSM, whose stdout is capped at 24,000 characters.
# Slim the transcript (the graders never read input schemas or long descriptions) and,
# if it is still large, wrap it as gzip+base64 (the runner unwraps "gz").
def _slim(ex):
    if not isinstance(ex, dict):
        return ex
    for t in ex.get("tools") or []:
        if isinstance(t, dict):
            t.pop("input_schema", None)
            if isinstance(t.get("description"), str):
                t["description"] = t["description"][:200]
    for c in ex.get("calls") or []:
        if isinstance(c, dict):
            if isinstance(c.get("result_sample"), str):
                c["result_sample"] = c["result_sample"][:120]
            a = c.get("args")
            if isinstance(a, dict):
                c["args"] = {k: (v[:80] if isinstance(v, str) else v) for k, v in list(a.items())[:16]}
    return ex

result = {
    "image": image,
    "mode": mode,
    "exit_code": int(exit_code) if str(exit_code).lstrip("-").isdigit() else None,
    "timed_out": timed_out == "true",
    "egress_hosts": _arr(hosts),
    "fs_writes": _arr(fs),
    "canary_exfil": canary_exfil[:32],
    "exercise": _slim(exercise),
    "image_pulled": image_pulled == "true",
    "files_materialized": _arr(files_json),
    "schema": "behavioral-v2",
}
text = json.dumps(result, separators=(",", ":"))
if len(text) > 20000:
    import base64, gzip
    text = json.dumps({"schema": "behavioral-v2",
                       "gz": base64.b64encode(gzip.compress(text.encode("utf-8"), 9)).decode("ascii")})
print(text)
PY
