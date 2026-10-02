#!/bin/sh
# In-container exerciser for an OpenClaw / Agent Skill (shipped per run via --files-b64,
# POSIX sh + the image's python3; nothing else is assumed).
#
#   sh /work/skill_exercise.sh [--timeout S] [--per-script-timeout S] [--max-scripts N]
#       [--canary-value V] [--canary-env A,B] [--root DIR] [--mounts /tmp,/work]
#
# The sandbox plan clones the skill's repo to /work/skill, cd's into it and runs this
# script. It then exercises everything the skill would run on a user's machine, each
# with its own timeout, every secret-named env var the static scan found exported with
# the canary value, and prints ONE transcript between AGENTAVOW_TRANSCRIPT_BEGIN /
# AGENTAVOW_TRANSCRIPT_END on stdout in the SAME shape as the MCP exerciser
# (src/scanner/behavioral/transcript.py), so parse_transcript and the graders work
# unchanged. Always exits 0 and always prints a transcript.
#
# What runs (in this order, nothing outside --root is ever executed):
#   1. lifecycle hooks — every hook `command` in hooks.json / plugin.json ("hooks"
#      object, Claude Code shape: {Event: [{matcher, hooks: [{type, command}]}]}), run
#      with `sh -c` from the skill root with CLAUDE_PLUGIN_ROOT / CLAUDE_PROJECT_DIR set
#      and a small hook payload on stdin (hooks read JSON there);
#   2. MCP servers — every `mcpServers` entry in .mcp.json / plugin.json: launched over
#      stdio, sent `initialize`, killed after --mcp-timeout (10 s) whatever it answered;
#   3. bundled scripts — every *.sh / *.bash / *.py / *.js / *.mjs / *.cjs, plus any
#      shebang'd file under a scripts/ or bin/ directory, run with NO arguments by its
#      interpreter (sh/bash, python3, node) — never executed directly, so a `#!/bin/bash`
#      shebang needs no /bin/bash and no exec bit. A script a hook or server entry
#      already names is not run twice. .git, node_modules, __pycache__, venvs are skipped; at most
#      --max-scripts scripts run.
#
# Transcript (version 1 — field meanings for a skill):
#   launch.command    the clone that put the skill here (origin URL + root) when git can
#                     tell us, else ["sh", "skill_exercise.sh", <root>]
#   launch.ok         at least one hook / server / script actually started
#   launch.error      "no_entrypoint_found" when the skill ships nothing runnable (error is
#                     set to the same value), else the first spawn failure
#   server_info       {"name": SKILL.md frontmatter name, "version": short commit sha}
#   protocol_version  "skill-v1"
#   tools[]           every entrypoint found: name = relative script path, or
#                     "<manifest>:<Event>" for a hook, "<manifest>:<server>" for an MCP
#                     server; description = "<kind>: <command>";
#                     annotations = {"kind": "hook" | "mcp" | "script"}
#   calls[]           one per entrypoint run: tool = the name above;
#                     args = {"kind", "command"}; ok = it started and finished (or, for an
#                     MCP server, answered initialize) within its timeout;
#                     is_error = non-zero exit; error = "exited <n>" | "call_timeout" |
#                     "spawn_failed: …" | "missing_binary: <interp> not found" |
#                     "initialize_timeout" | "server_exited"; duration_ms;
#                     fs_writes = NEW paths under --mounts after that call (≤50);
#                     result_sample = first 300 chars of its output
#   canary            {"env_names": the --canary-env names exported for every run,
#                      "seen_in_result": those names when the canary VALUE showed up in
#                      any entrypoint's output}
#   timed_out         the --timeout wall clock stopped the run before every entrypoint ran
#   error             null | "no_entrypoint_found" | "exerciser_crash"
#
# Tests run this script outside the sandbox with --root <fixture dir> --mounts <tmp dir>.
set -u

TIMEOUT=120
PER_SCRIPT=20
MCP_TIMEOUT=10
MAX_SCRIPTS=25
CANARY=""
CANARY_ENV=""
ROOT="${SKILL_EXERCISE_ROOT:-/work/skill}"
MOUNTS="/tmp,/work"
while [ $# -gt 0 ]; do
  case "$1" in
    --timeout) TIMEOUT="${2:-120}"; shift 2 ;;
    --per-script-timeout|--per-call-timeout) PER_SCRIPT="${2:-20}"; shift 2 ;;
    --mcp-timeout) MCP_TIMEOUT="${2:-10}"; shift 2 ;;
    --max-scripts|--max-tools) MAX_SCRIPTS="${2:-25}"; shift 2 ;;
    --canary-value) CANARY="${2:-}"; shift 2 ;;
    --canary-env) CANARY_ENV="${2:-}"; shift 2 ;;
    --root) ROOT="${2:-$ROOT}"; shift 2 ;;
    --mounts) MOUNTS="${2:-$MOUNTS}"; shift 2 ;;
    --readme) shift 2 ;;        # accepted for exerciser-arg compatibility; unused
    --) shift; break ;;
    *) shift ;;                 # unknown flag: ignore (never fail the run over an option)
  esac
done
case "$TIMEOUT" in ''|*[!0-9]*) TIMEOUT=120 ;; esac
case "$PER_SCRIPT" in ''|*[!0-9]*) PER_SCRIPT=20 ;; esac
case "$MCP_TIMEOUT" in ''|*[!0-9]*) MCP_TIMEOUT=10 ;; esac
case "$MAX_SCRIPTS" in ''|*[!0-9]*) MAX_SCRIPTS=25 ;; esac
[ -n "$CANARY" ] || CANARY="agentavow-canary-skill0000"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/skex.XXXXXX" 2>/dev/null || echo /tmp/skex.$$)"
mkdir -p "$TMP"
START="$(date +%s)"
export PYTHONDONTWRITEBYTECODE=1
export CLAUDE_PLUGIN_ROOT="$ROOT" CLAUDE_PROJECT_DIR="$ROOT"

# Canary: every secret-named env var the static scan found gets the same value, so a
# DNS query / HTTP body carrying it is attributable credential exfiltration.
OLDIFS="$IFS"; IFS=','
for name in $CANARY_ENV; do
  case "$name" in
    [A-Za-z_]*) case "$name" in *[!A-Za-z0-9_]*) ;; *) export "$name=$CANARY" ;; esac ;;
  esac
done
IFS="$OLDIFS"

cat > "$TMP/helper.py" <<'PY'
import json, os, re, subprocess, sys, threading, time
sys.dont_write_bytecode = True

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
MANIFESTS = ("hooks.json", "plugin.json", ".mcp.json")
EXT_INTERP = {".sh": "sh", ".bash": "bash", ".py": "python3",
              ".js": "node", ".mjs": "node", ".cjs": "node"}
MAX_SCRIPT_BYTES = 2_000_000
SAMPLE = 300
OUT_CAP = 262_144


def _sub(s, root):
    for var in ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PROJECT_DIR"):
        s = s.replace("${" + var + "}", root).replace("$" + var, root)
    return s


def _frontmatter_name(root):
    best = None
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            if fn.lower() == "skill.md":
                p = os.path.join(dp, fn)
                depth = p.count(os.sep)
                if best is None or depth < best[0]:
                    best = (depth, p)
    if not best:
        return ""
    try:
        with open(best[1], "rb") as fh:
            text = fh.read(8192).decode("utf-8", "replace")
    except OSError:
        return ""
    m = re.match(r"^﻿?---\s*\n(.*?)\n---", text, re.S)
    if not m:
        return ""
    for line in m.group(1).splitlines():
        kv = re.match(r"^name\s*:\s*(.+)$", line.strip(), re.I)
        if kv:
            return kv.group(1).strip().strip("'\"")[:120]
    return ""


def _git(root, *args):
    try:
        out = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True,
                             timeout=5)
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:
        return ""


def discover(root, max_scripts, tmp):
    root = os.path.realpath(root)

    def inside(p):
        rp = os.path.realpath(p)
        return rp == root or rp.startswith(root + os.sep)

    def rel(p):
        return os.path.relpath(p, root).replace(os.sep, "/")

    files = []
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS
                        and not os.path.islink(os.path.join(dp, d)))
        for fn in sorted(fns):
            p = os.path.join(dp, fn)
            if os.path.islink(p) or not inside(p):
                continue
            files.append(p)

    entries, names = [], {}

    def add(kind, name, command, argv=None, shell=None, env=None, stdin=None, missing=None):
        n = names.get(name, 0) + 1
        names[name] = n
        entries.append({
            "kind": kind, "name": name if n == 1 else f"{name}#{n}",
            "command": command[:300], "argv": argv, "shell": shell, "env": env or {},
            "stdin": stdin, "missing": missing,
        })

    named_cmds = []  # every hook / server command: a script one names is not run twice

    def hooks_of(obj, src):
        h = obj.get("hooks") if isinstance(obj, dict) and isinstance(obj.get("hooks"), dict) \
            else obj
        if not isinstance(h, dict):
            return
        for event, groups in h.items():
            if not isinstance(groups, list):
                continue
            for g in groups:
                items = g.get("hooks") if isinstance(g, dict) and isinstance(g.get("hooks"),
                                                                            list) else [g]
                for it in items:
                    cmd = it.get("command") if isinstance(it, dict) else None
                    if isinstance(cmd, str) and cmd.strip():
                        cmd = _sub(cmd.strip(), root)
                        named_cmds.append(cmd)
                        payload = json.dumps({"session_id": "agentavow-sandbox",
                                              "hook_event_name": str(event), "cwd": root,
                                              "transcript_path": "/tmp/transcript.jsonl"})
                        add("hook", f"{src}:{event}", cmd, shell=cmd, stdin=payload)

    def servers_of(obj, src):
        servers = obj.get("mcpServers") if isinstance(obj, dict) else None
        if not isinstance(servers, dict):
            return
        for sname, spec in servers.items():
            if not (isinstance(spec, dict) and isinstance(spec.get("command"), str)):
                continue
            args = [_sub(str(a), root) for a in (spec.get("args") or [])
                    if isinstance(a, (str, int, float))]
            env = {str(k): _sub(str(v), root) for k, v in (spec.get("env") or {}).items()} \
                if isinstance(spec.get("env"), dict) else {}
            argv = [_sub(spec["command"], root), *args]
            named_cmds.append(" ".join(argv))
            add("mcp", f"{src}:{sname}", " ".join(argv), argv=argv, env=env)

    for p in files:
        base = os.path.basename(p).lower()
        if base not in MANIFESTS:
            continue
        try:
            with open(p, "rb") as fh:
                obj = json.loads(fh.read(1_000_000).decode("utf-8", "replace"))
        except Exception:
            continue
        if base in ("hooks.json", "plugin.json"):
            hooks_of(obj, rel(p))
        if base in (".mcp.json", "plugin.json"):
            servers_of(obj, rel(p))

    def interp_of(p, r):
        try:
            if os.path.getsize(p) > MAX_SCRIPT_BYTES:
                return None
            with open(p, "rb") as fh:
                head = fh.read(512)
        except OSError:
            return None
        if b"\0" in head:
            return None
        first = head.split(b"\n", 1)[0].decode("utf-8", "replace")
        shebang = first[2:].strip().lower() if first.startswith("#!") else ""
        ext = os.path.splitext(p)[1].lower()
        if ext in EXT_INTERP:
            it = EXT_INTERP[ext]
            return "bash" if (it == "sh" and "bash" in shebang) else it
        parts = r.split("/")[:-1]
        if shebang and ("scripts" in parts or "bin" in parts):
            if "python" in shebang:
                return "python3"
            if "node" in shebang:
                return "node"
            if "bash" in shebang:
                return "bash"
            if shebang.endswith("sh") or " sh" in shebang:
                return "sh"
        return None

    from shutil import which
    n_scripts = 0
    for p in files:
        r = rel(p)
        it = interp_of(p, r)
        if not it:
            continue
        if any(r in c or os.path.basename(r) in c for c in named_cmds):
            continue  # a hook or server entry already runs it
        if n_scripts >= max_scripts:
            break
        n_scripts += 1
        missing = None if which(it) else f"missing_binary: {it} not found"
        add("script", r, f"{it} {r}", argv=[it, p], missing=missing)

    origin = _git(root, "config", "--get", "remote.origin.url")
    meta = {
        "name": _frontmatter_name(root), "version": _git(root, "rev-parse", "--short", "HEAD"),
        "launch_command": (["git", "clone", "--depth", "1", origin, root] if origin
                           else ["sh", "skill_exercise.sh", root]),
        "root": root,
    }
    with open(os.path.join(tmp, "meta.json"), "w") as fh:
        json.dump(meta, fh)
    with open(os.path.join(tmp, "entries.jsonl"), "w") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")
    print(len(entries))


def _kill(proc):
    try:
        os.killpg(proc.pid, 9)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_proc(entry, timeout, env, root):
    if entry.get("missing"):
        return {"ok": False, "is_error": False, "error": entry["missing"], "exit": None,
                "out": "", "spawned": False}
    argv = entry["argv"] or ["sh", "-c", entry["shell"]]
    stdin = (entry.get("stdin") or "").encode("utf-8")
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(argv, cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env, start_new_session=True)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "is_error": False, "exit": None, "out": "", "spawned": False,
                "error": f"spawn_failed: {e.__class__.__name__}: {str(e)[:120]}"}
    try:
        out, _ = proc.communicate(input=stdin, timeout=timeout)
        code = proc.returncode
        err = None if code == 0 else f"exited {code}"
        ok = True
    except subprocess.TimeoutExpired:
        _kill(proc)
        try:
            out, _ = proc.communicate(timeout=3)
        except Exception:
            out = b""
        code, err, ok = proc.returncode, "call_timeout", False
    return {"ok": ok, "is_error": bool(ok and code != 0), "error": err, "exit": code,
            "out": (out or b"")[:OUT_CAP].decode("utf-8", "replace"), "spawned": True,
            "ms": int((time.monotonic() - t0) * 1000)}


def run_mcp(entry, timeout, env, root):
    argv = entry["argv"]
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(argv, cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, start_new_session=True,
                                bufsize=0)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "is_error": False, "exit": None, "out": "", "spawned": False,
                "error": f"spawn_failed: {e.__class__.__name__}: {str(e)[:120]}"}
    got, lines = {}, []

    def pump():
        for raw in proc.stdout:
            line = raw.decode("utf-8", "replace").strip()
            lines.append(line[:SAMPLE])
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if isinstance(msg, dict) and msg.get("id") == 1 and "result" in msg:
                got["result"] = msg["result"]
                return

    th = threading.Thread(target=pump, daemon=True)
    th.start()
    req = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
           "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                      "clientInfo": {"name": "agentavow-skill-exerciser", "version": "1.0"}}}
    try:
        proc.stdin.write((json.dumps(req) + "\n").encode("utf-8"))
        proc.stdin.flush()
    except Exception:
        pass
    th.join(timeout)
    exited = proc.poll() is not None
    _kill(proc)
    try:
        _, err_b = proc.communicate(timeout=3)
    except Exception:
        err_b = b""
    ms = int((time.monotonic() - t0) * 1000)
    if "result" in got:
        info = got["result"].get("serverInfo") if isinstance(got["result"], dict) else None
        sample = json.dumps(info)[:SAMPLE] if isinstance(info, dict) else "initialized"
        return {"ok": True, "is_error": False, "error": None, "exit": 0, "out": sample,
                "spawned": True, "ms": ms}
    tail = (err_b or b"")[-200:].decode("utf-8", "replace").strip()
    err = "server_exited" if exited else "initialize_timeout"
    return {"ok": False, "is_error": False, "exit": proc.returncode, "spawned": True,
            "error": err + (f": {tail}" if tail else ""), "ms": ms,
            "out": "\n".join(lines)[:OUT_CAP]}


def run(tmp, idx, timeout, mcp_timeout, canary):
    with open(os.path.join(tmp, "entries.jsonl")) as fh:
        entries = [json.loads(line) for line in fh if line.strip()]
    with open(os.path.join(tmp, "meta.json")) as fh:
        root = json.load(fh)["root"]
    entry = entries[idx]
    env = dict(os.environ)
    env.update({k: v for k, v in (entry.get("env") or {}).items() if isinstance(v, str)})
    env.setdefault("HOME", "/work")
    if entry["kind"] == "mcp":
        res = run_mcp(entry, mcp_timeout, env, root)
    else:
        res = run_proc(entry, timeout, env, root)
    res["canary_seen"] = bool(canary) and len(canary) >= 8 and canary in (res.get("out") or "")
    res["sample"] = (res.get("out") or "")[:SAMPLE]
    res.pop("out", None)
    with open(os.path.join(tmp, f"r.{idx}"), "w") as fh:
        json.dump(res, fh)


def emit(tmp, canary_env, timed_out):
    try:
        with open(os.path.join(tmp, "meta.json")) as fh:
            meta = json.load(fh)
    except Exception:
        meta = {}
    try:
        with open(os.path.join(tmp, "entries.jsonl")) as fh:
            entries = [json.loads(line) for line in fh if line.strip()]
    except Exception:
        entries = None
    names = [n for n in (canary_env or "").split(",") if n.strip()]
    doc = {
        "version": 1,
        "launch": {"command": meta.get("launch_command") or ["sh", "skill_exercise.sh"],
                   "ok": False, "error": None, "startup_ms": 0},
        "server_info": {"name": meta.get("name") or "", "version": meta.get("version") or ""},
        "protocol_version": "skill-v1",
        "tools": [], "calls": [],
        "canary": {"env_names": names, "seen_in_result": []},
        "timed_out": bool(timed_out),
        "error": None,
    }
    if entries is None:
        doc["error"] = "exerciser_crash"
    else:
        for e in entries:
            doc["tools"].append({"name": e["name"], "description": f"{e['kind']}: {e['command']}",
                                 "annotations": {"kind": e["kind"]}, "input_schema": None})
        spawned = 0
        first_err = None
        for i, e in enumerate(entries):
            try:
                with open(os.path.join(tmp, f"r.{i}")) as fh:
                    r = json.load(fh)
            except Exception:
                continue  # not reached before the wall clock
            try:
                with open(os.path.join(tmp, f"w.{i}")) as fh:
                    writes = [ln.rstrip("\n") for ln in fh if ln.strip()][:50]
            except Exception:
                writes = []
            if r.get("spawned"):
                spawned += 1
            elif first_err is None:
                first_err = r.get("error")
            if r.get("canary_seen"):
                doc["canary"]["seen_in_result"] = list(names)
            doc["calls"].append({
                "tool": e["name"], "args": {"kind": e["kind"], "command": e["command"][:200]},
                "ok": bool(r.get("ok")), "is_error": bool(r.get("is_error")),
                "error": r.get("error"), "duration_ms": int(r.get("ms") or 0),
                "fs_writes": writes, "result_sample": r.get("sample") or "",
            })
        if not entries:
            doc["launch"]["error"] = doc["error"] = "no_entrypoint_found"
        elif spawned:
            doc["launch"]["ok"] = True
        else:
            doc["launch"]["error"] = first_err or "spawn_failed"
    print("AGENTAVOW_TRANSCRIPT_BEGIN")
    print(json.dumps(doc, separators=(",", ":")))
    print("AGENTAVOW_TRANSCRIPT_END")
    sys.stdout.flush()


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "discover":
        discover(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    elif cmd == "run":
        run(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5]), sys.argv[6])
    elif cmd == "emit":
        emit(sys.argv[2], sys.argv[3], sys.argv[4] == "1")
PY

DONE=0
finish() {
  [ "$DONE" = 1 ] && return
  DONE=1
  TO=0; [ -f "$TMP/timed_out" ] && TO=1
  python3 "$TMP/helper.py" emit "$TMP" "$CANARY_ENV" "$TO" 2>/dev/null || {
    # python itself failed: a last-resort transcript so the run still fails open
    printf 'AGENTAVOW_TRANSCRIPT_BEGIN\n{"version":1,"launch":{"command":["sh","skill_exercise.sh"],"ok":false,"error":"exerciser_crash","startup_ms":0},"tools":[],"calls":[],"canary":{"env_names":[],"seen_in_result":[]},"timed_out":false,"error":"exerciser_crash"}\nAGENTAVOW_TRANSCRIPT_END\n'
  }
  rm -rf "$TMP" >/dev/null 2>&1 || true
}
trap finish EXIT

# Snapshot of the writable mounts (our own scratch dir excluded), for the per-call diff.
snap() {
  OLDIFS="$IFS"; IFS=','
  for m in $MOUNTS; do find "$m" -xdev 2>/dev/null; done | grep -v "^$TMP" | head -n 50000 | sort > "$1"
  IFS="$OLDIFS"
}

if [ ! -d "$ROOT" ]; then
  # nothing to exercise: the clone never happened — emit the empty transcript
  : > "$TMP/entries.jsonl"
  printf '{"root":"%s","launch_command":["sh","skill_exercise.sh","%s"]}' "$ROOT" "$ROOT" > "$TMP/meta.json"
  exit 0
fi

COUNT="$(python3 "$TMP/helper.py" discover "$ROOT" "$MAX_SCRIPTS" "$TMP" 2>/dev/null)" || COUNT=0
case "$COUNT" in ''|*[!0-9]*) COUNT=0 ;; esac

i=0
while [ "$i" -lt "$COUNT" ]; do
  NOW="$(date +%s)"
  if [ $((NOW - START)) -ge "$TIMEOUT" ]; then
    : > "$TMP/timed_out"
    break
  fi
  snap "$TMP/before"
  python3 "$TMP/helper.py" run "$TMP" "$i" "$PER_SCRIPT" "$MCP_TIMEOUT" "$CANARY" 2>/dev/null \
    || printf '{"ok":false,"is_error":false,"error":"spawn_failed: helper","exit":null,"spawned":false,"sample":""}' > "$TMP/r.$i"
  snap "$TMP/after"
  comm -13 "$TMP/before" "$TMP/after" | head -n 50 > "$TMP/w.$i"
  i=$((i + 1))
done
exit 0
