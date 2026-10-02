#!/usr/bin/env python3
"""Behavioral-tier eval: does the sandbox + exerciser + graders raise what they must and
nothing they must not?

Three modes (combine freely):
  --fixtures    run tests/fixtures/behavioral/* through the REAL exerciser and graders on
                this machine (no sandbox) and check scripts/sandbox/eval/corpus.json
                expectations. Deterministic; also run by tests/test_behavioral_eval.py.
  --sandbox     ship the same fixtures INTO the real gVisor sandbox (v2 runner, --files-b64)
                and check the same expectations end to end. Needs the sandbox settings
                (SSM/SSH/local) and SCANNER_BEHAVIORAL_SANDBOX_RUNNER_V2.
  --known-good  run every corpus "known_good" package through run_behavioral with the MCP
                plan and list every finding: each one is a false positive until a human
                says otherwise. Slow (~1–2 min per package, serial sandbox).

  --out PATH    also write the full JSON report.  Exit code 1 when any expectation fails.

Measure, don't chase: the numbers go in docs/internal/metrics-log.md next to the others.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import gzip
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from src.scanner.behavioral.graders import grade, grade_summary  # noqa: E402
from src.scanner.behavioral.runner import BehavioralResult, _classify_egress  # noqa: E402
from src.scanner.behavioral.transcript import (  # noqa: E402
    CANARY_PREFIX,
    extract_transcript_json,
    parse_transcript,
)

SANDBOX_DIR = ROOT / "scripts" / "sandbox"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "behavioral"
SKILL_FIXTURE_DIR = FIXTURE_DIR / "skills"  # one directory per fixture skill
CORPUS = pathlib.Path(__file__).with_name("corpus.json")
PY = sys.executable


def load_corpus() -> dict:
    return json.loads(CORPUS.read_text())


# ---------------------------------------------------------------------------
# expectations
# ---------------------------------------------------------------------------

def check_expectations(entry: dict, result: BehavioralResult) -> list[str]:
    """Human-readable failures for one fixture, [] when every expectation holds."""
    rules = {f.rule for f in grade(result)}
    tr = result.transcript
    fails: list[str] = []
    for r in entry.get("must_raise", []):
        if r not in rules:
            fails.append(f"expected rule {r!r} not raised (raised: {sorted(rules) or 'none'})")
    for r in entry.get("must_not_raise", []):
        if r in rules:
            fails.append(f"rule {r!r} raised but must not")
    exp = entry.get("expect") or {}
    if "launch_ok" in exp and (tr is None or tr.launch_ok != exp["launch_ok"]):
        fails.append(f"launch_ok expected {exp['launch_ok']}, got "
                     f"{None if tr is None else tr.launch_ok} ({tr and tr.launch_error})")
    if "min_calls" in exp and (tr is None or len(tr.calls) < exp["min_calls"]):
        fails.append(f"expected ≥{exp['min_calls']} calls, got {0 if tr is None else len(tr.calls)}")
    for needle in exp.get("call_errors_include", []):
        errs = [c.error or "" for c in (tr.calls if tr else [])]
        if not any(needle in e for e in errs):
            fails.append(f"no call error containing {needle!r} (errors: {errs})")
    return fails


# ---------------------------------------------------------------------------
# --fixtures: local exerciser + graders, no sandbox
# ---------------------------------------------------------------------------

def run_fixture_local(entry: dict, *, per_call: float = 2.0, timeout: float = 20.0) -> BehavioralResult:
    fixture = FIXTURE_DIR / entry["file"]
    canary = CANARY_PREFIX + "evalfixture0"
    with tempfile.TemporaryDirectory(prefix="agentavow-eval-") as mount:
        env = dict(os.environ, AGENTAVOW_FIXTURE_TMP=mount, AGENTAVOW_FIXTURE_SLEEP="6")
        cmd = [PY, str(SANDBOX_DIR / "mcp_exercise.py"), "--timeout", str(timeout),
               "--per-call-timeout", str(per_call), "--mounts", mount,
               "--canary-value", canary]
        if entry.get("env_names"):
            cmd += ["--canary-env", ",".join(entry["env_names"])]
        cmd += ["--", PY, str(fixture)]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env,
                              timeout=timeout + 20)
    tr = parse_transcript(extract_transcript_json(proc.stdout))
    fs = sorted({p for c in tr.calls for p in c.fs_writes})
    return BehavioralResult(ran=True, surface="fixture", coordinate=entry["file"], plan="pypi-mcp",
                            fs_writes=fs, transcript=tr)


def run_skill_fixture_local(entry: dict, *, per_script: float = 5.0, timeout: float = 30.0,
                            ) -> BehavioralResult:
    """A fixture SKILL through the real in-container exerciser (skill_exercise.sh) on this
    machine: hooks + scripts run against a temp mount, no sandbox and no network
    (AGENTAVOW_FIXTURE_NET=0). Egress cannot be observed here, so an entry's
    ``simulated_egress`` stands in for what the sandbox's capture would report."""
    skill_dir = SKILL_FIXTURE_DIR / entry["dir"]
    canary = CANARY_PREFIX + "evalfixture0"
    with tempfile.TemporaryDirectory(prefix="agentavow-eval-skill-") as mount:
        env = dict(os.environ, AGENTAVOW_FIXTURE_TMP=mount, AGENTAVOW_FIXTURE_NET="0")
        cmd = ["sh", str(SANDBOX_DIR / "skill_exercise.sh"), "--timeout", str(int(timeout)),
               "--per-script-timeout", str(int(per_script)), "--root", str(skill_dir),
               "--mounts", mount, "--canary-value", canary]
        if entry.get("env_names"):
            cmd += ["--canary-env", ",".join(entry["env_names"])]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env,
                              timeout=timeout + 20)
    tr = parse_transcript(extract_transcript_json(proc.stdout))
    fs = sorted({p for c in tr.calls for p in c.fs_writes})
    hosts = [str(h) for h in entry.get("simulated_egress") or []]
    return BehavioralResult(ran=True, surface="fixture", coordinate=entry["dir"], plan="skill",
                            fs_writes=fs, transcript=tr, egress_hosts=hosts,
                            unexpected_egress=_classify_egress(hosts, set()))


# ---------------------------------------------------------------------------
# --sandbox: same fixtures through the real v2 runner
# ---------------------------------------------------------------------------

def _payload(files: dict[str, bytes]) -> str:
    enc = {k: base64.b64encode(v).decode() for k, v in files.items()}
    raw = json.dumps(enc, separators=(",", ":")).encode()
    return base64.b64encode(gzip.compress(raw)).decode()


async def run_fixture_sandbox(entry: dict, *, timeout: int = 60) -> BehavioralResult:
    from src.scanner.behavioral.runner import _execute
    fixture = FIXTURE_DIR / entry["file"]
    canary = CANARY_PREFIX + os.urandom(6).hex()
    files = {
        "mcp_exercise.py": (SANDBOX_DIR / "mcp_exercise.py").read_bytes(),
        "synthetic_args.py": (ROOT / "src" / "scanner" / "behavioral"
                              / "synthetic_args.py").read_bytes(),
        "_mcp_stdio.py": (FIXTURE_DIR / "_mcp_stdio.py").read_bytes(),
        entry["file"]: fixture.read_bytes(),
    }
    ex = ["python3", "/work/mcp_exercise.py", "--timeout", str(timeout - 10),
          "--per-call-timeout", "5", "--canary-value", canary]
    if entry.get("env_names"):
        ex += ["--canary-env", ",".join(entry["env_names"])]
    ex += ["--", "python3", f"/work/{entry['file']}"]
    command = "AGENTAVOW_FIXTURE_SLEEP=8 " + " ".join(ex)
    args = ["--mode", "mcp", "--files-b64", _payload(files), "--canary", canary,
            "--timeout", str(timeout), "python:3.12-alpine", command]
    stdout, err = await _execute(args, timeout, v2=True)
    if err or not stdout:
        return BehavioralResult(ran=False, surface="fixture", coordinate=entry["file"],
                                plan="pypi-mcp", error=err or "no_output")
    try:
        data = json.loads(stdout[stdout.index("{"):stdout.rindex("}") + 1])
    except Exception as e:  # noqa: BLE001
        return BehavioralResult(ran=False, surface="fixture", coordinate=entry["file"],
                                plan="pypi-mcp", error=f"unparseable_runner_output: {e}")
    hosts = [h for h in data.get("egress_hosts") or [] if isinstance(h, str)]
    tr = parse_transcript(data.get("exercise"))
    return BehavioralResult(
        ran=True, surface="fixture", coordinate=entry["file"], plan="pypi-mcp",
        timed_out=bool(data.get("timed_out")), exit_code=data.get("exit_code"),
        egress_hosts=hosts, unexpected_egress=_classify_egress(hosts, set()),
        fs_writes=[p for p in data.get("fs_writes") or [] if isinstance(p, str)],
        transcript=tr, canary_exfil=[c for c in data.get("canary_exfil") or []
                                     if isinstance(c, dict)],
    )


async def run_skill_fixture_sandbox(entry: dict, *, timeout: int = 90) -> BehavioralResult:
    """A fixture skill INTO the real sandbox: the skill's tree travels as one tar.gz in
    the --files-b64 payload (the runner only materializes flat filenames), is unpacked to
    /work/skill, and the shipped exerciser runs it exactly as the skill plan would —
    minus the clone, so the egress capture sees only what the skill itself does."""
    import io
    import tarfile

    from src.scanner.behavioral.runner import _execute
    skill_dir = SKILL_FIXTURE_DIR / entry["dir"]
    canary = CANARY_PREFIX + os.urandom(6).hex()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(skill_dir, arcname=".")
    files = {"skill_exercise.sh": (SANDBOX_DIR / "skill_exercise.sh").read_bytes(),
             "skill.tgz": buf.getvalue()}
    ex = ["sh", "/work/skill_exercise.sh", "--timeout", str(timeout - 20),
          "--per-script-timeout", "10", "--canary-value", canary]
    if entry.get("env_names"):
        ex += ["--canary-env", ",".join(entry["env_names"])]
    command = ("mkdir -p /work/skill && tar -xzf /work/skill.tgz -C /work/skill && "
               "cd /work/skill && " + " ".join(ex))
    args = ["--mode", "exec", "--files-b64", _payload(files), "--canary", canary,
            "--timeout", str(timeout), "python:3.12-alpine", command]
    stdout, err = await _execute(args, timeout, v2=True)
    if err or not stdout:
        return BehavioralResult(ran=False, surface="fixture", coordinate=entry["dir"],
                                plan="skill", error=err or "no_output")
    try:
        data = json.loads(stdout[stdout.index("{"):stdout.rindex("}") + 1])
    except Exception as e:  # noqa: BLE001
        return BehavioralResult(ran=False, surface="fixture", coordinate=entry["dir"],
                                plan="skill", error=f"unparseable_runner_output: {e}")
    hosts = [h for h in data.get("egress_hosts") or [] if isinstance(h, str)]
    return BehavioralResult(
        ran=True, surface="fixture", coordinate=entry["dir"], plan="skill",
        timed_out=bool(data.get("timed_out")), exit_code=data.get("exit_code"),
        egress_hosts=hosts, unexpected_egress=_classify_egress(hosts, set()),
        fs_writes=[p for p in data.get("fs_writes") or [] if isinstance(p, str)],
        transcript=parse_transcript(data.get("exercise")),
        canary_exfil=[c for c in data.get("canary_exfil") or [] if isinstance(c, dict)],
    )


def run_fixture_entry_local(entry: dict) -> BehavioralResult:
    return (run_skill_fixture_local(entry) if "dir" in entry else run_fixture_local(entry))


async def run_fixture_entry_sandbox(entry: dict) -> BehavioralResult:
    return await (run_skill_fixture_sandbox(entry) if "dir" in entry
                  else run_fixture_sandbox(entry))


# ---------------------------------------------------------------------------
# --known-good: real packages, every finding is a suspected false positive
# ---------------------------------------------------------------------------

async def run_known_good(pkg: dict) -> dict:
    """One corpus package (MCP plan) or, for a ``known_good_skills`` entry
    ({"repo": "owner/repo"}), one skill through the skill plan."""
    from src.scanner.behavioral.runner import run_behavioral
    started = time.monotonic()
    if "repo" in pkg:
        pkg = dict(pkg, surface="skill", name=pkg["repo"])
        res = await run_behavioral("skill", pkg["name"], plan="skill")
    else:
        res = await run_behavioral(pkg["surface"], pkg["name"], plan=f"{pkg['surface']}-mcp")
    findings = grade(res)
    tr = res.transcript
    return {
        "surface": pkg["surface"], "name": pkg["name"], "ran": res.ran, "error": res.error,
        "plan": res.plan, "seconds": round(time.monotonic() - started, 1),
        "egress_hosts": res.egress_hosts, "unexpected_egress": res.unexpected_egress,
        "vendor_egress": res.vendor_egress, "notes": res.notes,
        "launch_error": tr.launch_error if tr else None,
        "launch_command": tr.launch_command if tr else [],
        "exercise_error": tr.error if tr else None,
        "exit_code": res.exit_code,
        "expect_rules": pkg.get("expect_rules", []),
        "false_positives": [f.rule for f in findings if f.rule not in pkg.get("expect_rules", [])],
        "summary": grade_summary(res),
        "findings": [{"rule": f.rule, "severity": f.severity, "name": f.name}
                     for f in findings],
    }


# ---------------------------------------------------------------------------

def _report_fixtures(rows: list[dict]) -> bool:
    ok = True
    print(f"{'fixture':32} {'label':20} {'result':8} detail")
    for r in rows:
        status = "PASS" if not r["failures"] else "FAIL"
        ok &= status == "PASS"
        detail = "; ".join(r["failures"]) if r["failures"] else ", ".join(r["rules"]) or "clean"
        print(f"{r['file']:32} {r['label']:20} {status:8} {detail}")
    return ok


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fixtures", action="store_true")
    ap.add_argument("--sandbox", action="store_true")
    ap.add_argument("--known-good", action="store_true")
    ap.add_argument("--only", help="substring filter on fixture file / package name")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    if not (a.fixtures or a.sandbox or a.known_good):
        ap.error("pick at least one of --fixtures / --sandbox / --known-good")
    corpus = load_corpus()
    report: dict = {"ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    ok = True

    def _rows(mode: str, runner) -> list[dict]:
        rows = []
        for entry in corpus["fixtures"] + corpus.get("skill_fixtures", []):
            name = entry.get("file") or entry["dir"]
            if a.only and a.only not in name:
                continue
            res = runner(entry)
            rows.append({"file": name, "label": entry["label"],
                         "rules": sorted({f.rule for f in grade(res)}),
                         "failures": check_expectations(entry, res) if res.ran
                         else [f"did not run: {res.error}"],
                         "summary": grade_summary(res)})
        print(f"\n== {mode} ==")
        return rows

    if a.fixtures:
        report["fixtures_local"] = _rows("fixtures (local exerciser + graders)",
                                         run_fixture_entry_local)
        ok &= _report_fixtures(report["fixtures_local"])
    if a.sandbox:
        report["fixtures_sandbox"] = _rows(
            "fixtures (real sandbox, v2 runner)",
            lambda e: asyncio.run(run_fixture_entry_sandbox(e)))
        ok &= _report_fixtures(report["fixtures_sandbox"])
    if a.known_good:
        rows = []
        print("\n== known-good packages (every finding = suspected false positive) ==")
        for pkg in corpus["known_good"] + [
                dict(e, surface="skill", name=e["repo"])
                for e in corpus.get("known_good_skills", [])]:
            if a.only and a.only not in pkg["name"]:
                continue
            row = asyncio.run(run_known_good(pkg))
            rows.append(row)
            fl = ", ".join(f"{f['rule']}({f['severity']})" for f in row["findings"]) or "clean"
            state = "ran" if row["ran"] else f"did not run: {row['error']}"
            s = row["summary"]
            extra = (f"tools={s.get('tools_listed')} called={s.get('tools_called')} "
                     f"egress={row['egress_hosts']} unexpected={row['unexpected_egress']} "
                     f"vendor={row['vendor_egress']}")
            if not s.get("launch_ok"):
                extra += (f" exit_code={row['exit_code']} launch_error={row['launch_error']!r} "
                          f"cmd={row['launch_command']}")
            if row["expect_rules"]:
                extra += f" expected={row['expect_rules']}"
            print(f"{pkg['surface']}:{pkg['name']:48} {row['seconds']:6}s {state:32} {fl}\n"
                  f"    {extra}")
        report["known_good"] = rows
        n_ran = sum(1 for r in rows if r["ran"])
        n_exercised = sum(1 for r in rows if r["summary"].get("launch_ok"))
        n_fp = sum(1 for r in rows if r["false_positives"])
        n_expected = sum(1 for r in rows if r["findings"] and not r["false_positives"])
        print(f"\nknown-good: {n_ran}/{len(rows)} ran, {n_exercised} servers started and were "
              f"exercised, {n_fp} with FALSE-POSITIVE findings, {n_expected} with expected findings")
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(report, indent=2))
        print(f"\nreport → {a.out}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
