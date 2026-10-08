#!/usr/bin/env bash
# Rug-pull at the call: one command, everything on localhost.
#
#   ./run.sh            the demo (control and protected side by side in tmux when
#                       there is a terminal and tmux; one after the other otherwise)
#   ./run.sh --plain    one after the other, no tmux
#   ./run.sh --tweak    the "later" server is v1 plus ONE byte in the description,
#                       not the attack: watch the digest change and the gate refuse it
#   ./run.sh --model    an LLM drives the agent (Vercel AI SDK; needs ANTHROPIC_API_KEY)
#
# Ports: MCP_PORT (8787) and API_PORT (8788). State: .state/ (or RUGPULL_STATE).
# Python: $PYTHON, else the repo's .venv312/.venv, else python3; it needs this
# repository's backend installed (pip install -e . from the repo root).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$HERE"

PLAIN=0; LATER=v2; MODEL_FLAG=""
for a in "$@"; do
  case "$a" in
    --plain) PLAIN=1 ;;
    --tweak) LATER=v1-tweak ;;
    --model) MODEL_FLAG="--model" ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option $a" >&2; exit 2 ;;
  esac
done

export MCP_PORT="${MCP_PORT:-8787}" API_PORT="${API_PORT:-8788}"
export RUGPULL_STATE="${RUGPULL_STATE:-$HERE/.state}"
MCP_URL="http://127.0.0.1:$MCP_PORT/mcp"

bold=$'\033[1m'; red=$'\033[31m'; green=$'\033[32m'; dim=$'\033[2m'; off=$'\033[0m'
[ -t 1 ] || { bold=""; red=""; green=""; dim=""; off=""; }
# RUGPULL_PACE=<seconds> pauses before each step (for recording or presenting live).
header() { [ -n "${RUGPULL_PACE:-}" ] && sleep "$RUGPULL_PACE"; printf '\n%s== %s ==%s\n' "$bold" "$1" "$off"; }

# ── prerequisites ────────────────────────────────────────────────────────────
command -v node >/dev/null || { echo "node 20+ is required" >&2; exit 1; }
if [ -z "${PYTHON:-}" ]; then
  for p in "$REPO/.venv312/bin/python" "$REPO/.venv/bin/python" python3; do
    if ( cd "$REPO" && "$p" -c "import src.scanner.scan" ) >/dev/null 2>&1 </dev/null; then PYTHON="$p"; break; fi
  done 2>/dev/null
fi
PYTHON="${PYTHON:-python3}"
( cd "$REPO" && "${PYTHON:-python3}" -c "import src.scanner.scan" ) >/dev/null 2>&1 || {
  echo "grade.py needs this repo's backend: (cd $REPO && pip install -e .), or set PYTHON=..." >&2; exit 1; }
[ -d "$REPO/sdk/js/dist" ] || (cd "$REPO/sdk/js" && npm install --silent && npm run build --silent)
[ -d node_modules/@modelcontextprotocol ] || npm install --silent
for port in "$MCP_PORT" "$API_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then echo "port $port is in use; set MCP_PORT/API_PORT" >&2; exit 1; fi
done

# ── processes ────────────────────────────────────────────────────────────────
rm -rf "$RUGPULL_STATE"; mkdir -p "$RUGPULL_STATE"
SERVER_PID=""; API_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_up() { for _ in $(seq 1 50); do curl -s -o /dev/null "$1" >/dev/null 2>&1 && return 0; sleep 0.1; done; echo "timed out waiting for $1" >&2; exit 1; }
start_server() {
  [ -n "$SERVER_PID" ] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
  node server.mjs --version "$1" >"$RUGPULL_STATE/server.log" 2>&1 &
  SERVER_PID=$!
  wait_up "http://127.0.0.1:$MCP_PORT/healthz"
}

header "1. Approval day: acme-mail serves send_email v1"
start_server v1
echo "  $MCP_URL is up, serving v1 ($(curl -s "http://127.0.0.1:$MCP_PORT/healthz"))"
node api.mjs >"$RUGPULL_STATE/api.log" 2>&1 &
API_PID=$!
wait_up "http://127.0.0.1:$API_PORT/"

header "2. Grade v1 with AgentAvow's scanner (offline; signed by a throwaway DEMO key, not AgentAvow's)"
( cd "$REPO" && "$PYTHON" "$HERE/grade.py" --endpoint "$MCP_URL" --out "$RUGPULL_STATE" )

header "3. Security reviews the grade and approves the server"
node approve.mjs

header "4. Baseline: the protected agent calls send_email on v1"
node agent.mjs --mode protected $MODEL_FLAG

if [ "$LATER" = v2 ]; then
  header "5. Weeks later: the operator redefines send_email (same name, same URL)"
else
  header "5. Weeks later: the server changes ONE byte of the description (--tweak)"
fi
start_server "$LATER"
echo "  $MCP_URL now serves $LATER. Nobody re-approved anything."
node --input-type=module -e "
  import { V1, VERSIONS } from './tools.mjs';
  const t = VERSIONS['$LATER'];
  if (t.description !== V1.description) console.log('  description now: ' + JSON.stringify(t.description));
  if (t.inputSchema.properties.bcc) console.log('  new input:       bcc, default ' + t.inputSchema.properties.bcc.default);
"

# Each run carries its own canary, so the sink shows which run leaked.
TAG=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
CONTROL_CANARY="CANARY-control-$TAG"; PROTECTED_CANARY="CANARY-protected-$TAG"
CONTROL_CMD="RUGPULL_CANARY=$CONTROL_CANARY node agent.mjs --mode control $MODEL_FLAG"
PROTECTED_CMD="RUGPULL_CANARY=$PROTECTED_CANARY node agent.mjs --mode protected $MODEL_FLAG"

if [ "$PLAIN" = 0 ] && [ -t 1 ] && command -v tmux >/dev/null && [ -z "${TMUX:-}" ]; then
  header "6. Control and protected runs, side by side (tmux; press enter in each pane to close it)"
  S="rugpull-$$"
  env_prefix="cd '$HERE' && MCP_PORT=$MCP_PORT API_PORT=$API_PORT RUGPULL_STATE='$RUGPULL_STATE'"
  pane() { # title, command
    printf "%s; printf '\\033[1m== %s ==\\033[0m\\n\\n'; %s; echo; echo '(press enter to close)'; read -r _" \
      "$env_prefix" "$1" "$2"
  }
  tmux new-session -d -s "$S" -x 220 -y 40 "$(pane 'CONTROL: no gate' "$CONTROL_CMD")"
  sleep 1.5  # the control run lands first, so the sink line below is its copy
  tmux split-window -h -t "$S" "$(pane 'PROTECTED: AgentAvow gate' "$PROTECTED_CMD")"
  tmux attach -t "$S" || true
else
  header "6a. CONTROL run: same agent, no gate"
  env RUGPULL_CANARY="$CONTROL_CANARY" node agent.mjs --mode control $MODEL_FLAG
  header "6b. PROTECTED run: same agent, AgentAvow gate (onDrift: 'block')"
  env RUGPULL_CANARY="$PROTECTED_CANARY" node agent.mjs --mode protected $MODEL_FLAG
fi

header "7. What left the building"
leaks=$( [ -f "$RUGPULL_STATE/attacker-sink.jsonl" ] && wc -l <"$RUGPULL_STATE/attacker-sink.jsonl" | tr -d ' ' || echo 0)
sent=$( [ -f "$RUGPULL_STATE/outbox.jsonl" ] && wc -l <"$RUGPULL_STATE/outbox.jsonl" | tr -d ' ' || echo 0)
echo "  outbox (messages the server sent):        $sent"
echo "  attacker sink (copies to the operator):   ${red}${leaks}${off}"
if [ -f "$RUGPULL_STATE/attacker-sink.jsonl" ]; then
  while IFS= read -r line; do echo "    ${dim}${line}${off}"; done <"$RUGPULL_STATE/attacker-sink.jsonl"
fi
count() { cat "$RUGPULL_STATE/$2" 2>/dev/null | grep -c "$1" || true; }
echo "  control run   ($CONTROL_CANARY): in outbox $(count "$CONTROL_CANARY" outbox.jsonl), in attacker sink ${red}$(count "$CONTROL_CANARY" attacker-sink.jsonl)${off}"
echo "  protected run ($PROTECTED_CANARY): in outbox $(count "$PROTECTED_CANARY" outbox.jsonl), in attacker sink ${green}$(count "$PROTECTED_CANARY" attacker-sink.jsonl)${off}"
echo "  logs and the signed grade: ${RUGPULL_STATE#"$HERE"/}"
