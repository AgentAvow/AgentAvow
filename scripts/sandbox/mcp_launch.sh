#!/bin/sh
# In-container launcher for the MCP exerciser (shipped per run via --files-b64, POSIX sh).
#
#   sh /work/mcp_launch.sh <npm|pypi> <package> [--canary-value V] -- <exerciser command...>
#
# Discovers up to 3 candidate server commands for an installed package — npm: the
# package.json `bin` entries (then `main`); pypi: console_scripts entry points (then
# `python -m <import_name>`) — and runs `<exerciser command...> -- <candidate>` for each in
# turn, stopping at the first whose transcript reports launch.ok. It then prints THAT
# transcript (the exerciser's full stdout) so the sandbox runner forwards it as `exercise`.
# With no candidate at all, it prints a minimal transcript saying so, so the grader can
# tell "could not find an entrypoint" from "the server crashed".
#
# Key-gated servers. When the FIRST (bare) candidate fails and its launch.error names a
# credential ("A Brave API key is required via --brave-api-key, BRAVE_API_KEY …", "set the
# SUPABASE_ACCESS_TOKEN environment variable"), the launcher retries that candidate:
#   1. once with every UPPERCASE_NAME in the error that looks like a credential exported
#      as the canary value AND appended to the exerciser's --canary-env list (so the
#      transcript's canary.env_names records them and an echo/exfil is attributed);
#   2. once per `--something-token` / `--something-key` flag in the error (at most 2),
#      as `<candidate> --flag <canary>`.
# The canary value comes from `--canary-value V` (placed BEFORE `--`; runner.py passes the
# same value the exerciser gets after `--`). Without it, a fixed placeholder is used so
# the server still starts (no exfil attribution for that value in that case).
# Hard cap: 4 exerciser launches per run, whatever the mix of candidates and retries.
#
# Decision (documented): candidate iteration + credential retries live HERE, not in the
# exerciser, so the exerciser keeps its single `-- <server cmd>` contract.
# Tests run this script outside the sandbox with MCP_LAUNCH_WORK=<tmp dir>.
set -u

KIND="${1:?usage: mcp_launch.sh <npm|pypi> <package> [--canary-value V] -- <exerciser...>}"
PKG="${2:?usage: mcp_launch.sh <npm|pypi> <package> [--canary-value V] -- <exerciser...>}"
shift 2
CANARY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --canary-value) CANARY="${2:-}"; shift 2 ;;
    --canary-value=*) CANARY="${1#--canary-value=}"; shift ;;
    --) shift; break ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || { echo "mcp_launch: missing exerciser command" >&2; exit 2; }
[ -n "$CANARY" ] || CANARY="agentavow-canary-launcher0"
WORK="${MCP_LAUNCH_WORK:-/work}"
MAX_LAUNCHES=4

CANDS="$WORK/.candidates"
: > "$CANDS"
if [ "$KIND" = "npm" ]; then
  node -e '
const fs=require("fs"),path=require("path");const pkg=process.argv[1];
let p;try{p=JSON.parse(fs.readFileSync(path.join("node_modules",pkg,"package.json"),"utf8"))}catch(e){process.exit(0)}
let b=p.bin;if(typeof b==="string")b={[p.name||pkg]:b};
const out=[];for(const k of Object.keys(b||{}))out.push(path.resolve("node_modules",pkg,String(b[k])));
if(!out.length&&p.main)out.push(path.resolve("node_modules",pkg,String(p.main)));
// Many servers take one positional path (filesystem, git, sqlite…): try bare, then "/work".
const cands=[];for(const o of out.slice(0,2)){cands.push("node "+o);cands.push("node "+o+" /work");}
for(const c of cands.slice(0,3))console.log(c);
' "$PKG" > "$CANDS" 2>/dev/null || true
else
  python3 -c '
import sys, importlib.metadata as m
pkg = sys.argv[1]
try:
    eps = list(m.distribution(pkg).entry_points)
except Exception:
    eps = []
names = [e.name for e in eps if getattr(e, "group", "") == "console_scripts"]
# Many servers take one positional path (git, sqlite, filesystem…): try bare, then /work.
cands = []
for n in names[:2]:
    cands += [n, n + " /work"]
if not names:
    cands.append("python3 -m " + pkg.split("[")[0].replace("-", "_"))
for c in cands[:3]:
    print(c)
' "$PKG" > "$CANDS" 2>/dev/null || true
fi

if [ ! -s "$CANDS" ]; then
  echo "AGENTAVOW_TRANSCRIPT_BEGIN"
  printf '{"version":1,"launch":{"command":[],"ok":false,"error":"no_entrypoint_found"},"tools":[],"calls":[],"error":"no_entrypoint_found"}\n'
  echo "AGENTAVOW_TRANSCRIPT_END"
  exit 0
fi

# transcript_field FILE FIELD → prints "ok" when launch.ok is true (FIELD=ok), or the
# launch.error text (FIELD=error); empty when the file holds no parseable transcript.
transcript_field() {
  if [ "$KIND" = "npm" ]; then
    node -e '
const t=require("fs").readFileSync(process.argv[1],"utf8"),f=process.argv[2];
const B="AGENTAVOW_TRANSCRIPT_BEGIN",E="AGENTAVOW_TRANSCRIPT_END";
const i=t.indexOf(B),j=t.indexOf(E,i+B.length);if(i<0||j<0)process.exit(0);
let d;try{d=JSON.parse(t.slice(i+B.length,j))}catch(e){process.exit(0)}
const l=(d&&d.launch)||{};
if(f==="ok"){if(l.ok)process.stdout.write("ok")}else if(typeof l.error==="string")process.stdout.write(l.error.slice(0,2000));
' "$1" "$2" 2>/dev/null
  else
    python3 -c '
import json, sys
t = open(sys.argv[1], encoding="utf-8", errors="replace").read()
B, E = "AGENTAVOW_TRANSCRIPT_BEGIN", "AGENTAVOW_TRANSCRIPT_END"
i = t.find(B); j = t.find(E, i + len(B)) if i >= 0 else -1
if i < 0 or j < 0:
    sys.exit(0)
try:
    d = json.loads(t[i + len(B):j])
except Exception:
    sys.exit(0)
launch = d.get("launch") or {}
if sys.argv[2] == "ok":
    if launch.get("ok"):
        sys.stdout.write("ok")
elif isinstance(launch.get("error"), str):
    sys.stdout.write(launch["error"][:2000])
' "$1" "$2" 2>/dev/null
  fi
}

ok_transcript() {  # $1 = file; exit 0 when it holds a transcript with launch.ok == true
  [ "$(transcript_field "$1" ok)" = "ok" ]
}

# The exerciser's own --canary-env list (so a retry can EXTEND it rather than replace it:
# the exerciser takes the last occurrence of a flag).
EXISTING_ENV=""
prev=""
for a in "$@"; do
  [ "$prev" = "--canary-env" ] && EXISTING_ENV="$a"
  prev="$a"
done

N=0
FIRST=""

while IFS= read -r CAND; do
  [ -n "$CAND" ] || continue
  [ "$N" -lt "$MAX_LAUNCHES" ] || break
  N=$((N + 1))
  OUT="$WORK/.exercise.$N"
  # shellcheck disable=SC2086 — the candidate is a space-separated command, split on purpose
  "$@" -- $CAND > "$OUT" 2>/dev/null || true
  [ -n "$FIRST" ] || FIRST="$OUT"
  if ok_transcript "$OUT"; then
    cat "$OUT"
    exit 0
  fi

  if [ "$N" -eq 1 ]; then
    # ── credential retries on the bare candidate ──────────────────────────────
    ERR="$(transcript_field "$OUT" error)"
    if printf '%s' "$ERR" | grep -qiE 'api[ _-]?key|token|secret|credential|password|access[-_ ]token|env(ironment)? variable' \
       || printf '%s' "$ERR" | grep -qE '(^|[^A-Za-z])PAT([^A-Za-z]|$)'; then
      NAMES="$(printf '%s' "$ERR" | grep -oE '[A-Z][A-Z0-9_]{3,}' \
        | grep -E 'KEY|TOKEN|SECRET|AUTH|CREDENTIAL|PASSWORD|PASSWD|(^|_)(API|PAT|ACCESS)(_|$)' \
        | grep -vxE 'PATH|HOME|USER|SHELL|PWD|TERM|LANG|NODE_OPTIONS|NODE_PATH|PYTHONPATH' \
        | grep -vE '_(REGION|ENDPOINT|URL|URI|HOST|HOSTNAME|PORT|BASE|DOMAIN|PATH|DIR|FILE|MODEL|VERSION|ENV|LEVEL|MODE|NAME|ID|TIMEOUT|PROFILE|BUCKET|ZONE)$' \
        | sort -u | head -8 | tr '\n' ',' | sed 's/,$//')"
      if [ -n "$NAMES" ] && [ "$N" -lt "$MAX_LAUNCHES" ]; then
        OLDIFS="$IFS"; IFS=','
        for name in $NAMES; do export "$name=$CANARY"; done
        IFS="$OLDIFS"
        MERGED="$NAMES"
        [ -n "$EXISTING_ENV" ] && MERGED="$EXISTING_ENV,$NAMES"
        N=$((N + 1))
        OUT="$WORK/.exercise.$N"
        # shellcheck disable=SC2086
        "$@" --canary-env "$MERGED" -- $CAND > "$OUT" 2>/dev/null || true
        if ok_transcript "$OUT"; then
          cat "$OUT"
          exit 0
        fi
      fi
      FLAGS="$(printf '%s' "$ERR" | grep -oE -- '--[a-z][a-z-]*(token|key)' | sort -u | head -2)"
      for flag in $FLAGS; do
        [ "$N" -lt "$MAX_LAUNCHES" ] || break
        N=$((N + 1))
        OUT="$WORK/.exercise.$N"
        # shellcheck disable=SC2086
        "$@" -- $CAND "$flag" "$CANARY" > "$OUT" 2>/dev/null || true
        if ok_transcript "$OUT"; then
          cat "$OUT"
          exit 0
        fi
      done
    fi
  fi
done < "$CANDS"

# Nothing initialized: report the FIRST (bare) candidate's failure — that is the real
# reason (missing API key, needs a URL…), not the fallback variant's usage error.
[ -n "$FIRST" ] && cat "$FIRST"
exit 0
