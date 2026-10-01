#!/bin/sh
# In-container launcher for the MCP exerciser (shipped per run via --files-b64, POSIX sh).
#
#   sh /work/mcp_launch.sh <npm|pypi> <package> -- <exerciser command...>
#
# Discovers up to 3 candidate server commands for an installed package — npm: the
# package.json `bin` entries (then `main`); pypi: console_scripts entry points (then
# `python -m <import_name>`) — and runs `<exerciser command...> -- <candidate>` for each in
# turn, stopping at the first whose transcript reports launch.ok. It then prints THAT
# transcript (the exerciser's full stdout) so the sandbox runner forwards it as `exercise`.
# With no candidate at all, it prints a minimal transcript saying so, so the grader can
# tell "could not find an entrypoint" from "the server crashed".
#
# Decision (documented): candidate iteration lives HERE, not in the exerciser, so the
# exerciser keeps its single `-- <server cmd>` contract.
set -u

KIND="${1:?usage: mcp_launch.sh <npm|pypi> <package> -- <exerciser...>}"
PKG="${2:?usage: mcp_launch.sh <npm|pypi> <package> -- <exerciser...>}"
shift 2
[ "${1:-}" = "--" ] && shift
[ $# -gt 0 ] || { echo "mcp_launch: missing exerciser command" >&2; exit 2; }

CANDS=/work/.candidates
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

ok_transcript() {  # $1 = file; exit 0 when it holds a transcript with launch.ok == true
  if [ "$KIND" = "npm" ]; then
    node -e '
const t=require("fs").readFileSync(process.argv[1],"utf8");
const B="AGENTAVOW_TRANSCRIPT_BEGIN",E="AGENTAVOW_TRANSCRIPT_END";
const i=t.indexOf(B),j=t.indexOf(E,i+B.length);if(i<0||j<0)process.exit(1);
try{const d=JSON.parse(t.slice(i+B.length,j));process.exit(d.launch&&d.launch.ok?0:1)}catch(e){process.exit(1)}
' "$1" 2>/dev/null
  else
    python3 -c '
import json, sys
t = open(sys.argv[1], encoding="utf-8", errors="replace").read()
B, E = "AGENTAVOW_TRANSCRIPT_BEGIN", "AGENTAVOW_TRANSCRIPT_END"
i = t.find(B); j = t.find(E, i + len(B)) if i >= 0 else -1
if i < 0 or j < 0:
    sys.exit(1)
try:
    d = json.loads(t[i + len(B):j])
except Exception:
    sys.exit(1)
sys.exit(0 if (d.get("launch") or {}).get("ok") else 1)
' "$1" 2>/dev/null
  fi
}

N=0
FIRST=""
while IFS= read -r CAND; do
  [ -n "$CAND" ] || continue
  N=$((N + 1))
  OUT="/work/.exercise.$N"
  # shellcheck disable=SC2086 — the candidate is a space-separated command, split on purpose
  "$@" -- $CAND > "$OUT" 2>/dev/null || true
  [ -n "$FIRST" ] || FIRST="$OUT"
  if ok_transcript "$OUT"; then
    cat "$OUT"
    exit 0
  fi
  [ "$N" -ge 3 ] && break
done < "$CANDS"

# Nothing initialized: report the FIRST (bare) candidate's failure — that is the real
# reason (missing API key, needs a URL…), not the fallback variant's usage error.
[ -n "$FIRST" ] && cat "$FIRST"
exit 0
