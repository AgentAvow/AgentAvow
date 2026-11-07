"""Intake record for the tool-manifest-digest v1 vectors, under intake criteria v2.1.

The criteria are the W3C Agent Conformance and Benchmarking Community Group's
"intake criteria for a submitted conformance result", v2.1 as consolidated for
the editor (public-agent-conformance, October 2026). The record shape is the one
the intake reader ``agent_evidence_vectors.w3cintake`` reads, at
probityai/agent-evidence-vectors commit 7e501506 (the commit the criteria's
CHECK lines pin). Nothing in this directory is hand-edited: this script writes
every file in it except this script and the README.

    python3 intake.py anchor  --intake-reader AEV --probity P --heldfast H --python PY
    python3 intake.py write   --intake-reader AEV --probity P --heldfast H --python PY \
                              --anchor-commit COMMIT
    python3 intake.py check   (same arguments as write; the commit is read from the record)
    python3 intake.py anchor-check [--commit COMMIT]

``anchor`` writes MANIFEST.json and DIGESTS.txt, which are committed first; the
commit that carries them is the anchor. ``write`` writes RECORD.json, the native
output, and the run logs under runs/, naming that commit. ``check`` rebuilds every
one of those files in memory, from the pinned inputs and fresh runs of every
checker, and refuses on any byte that differs, naming each differing file and
the JSON path of each differing field. It compares whole files, never chosen
fields, so an edit anywhere in the record is a refusal. ``anchor-check`` is the
anchor's own verification command (criterion 7, CHECK line C2).

What the record claims about, and why (criterion 2, "admitted population"):

The population is the 76 checks ``node verify.mjs`` makes over the one pinned
vector file, identified by the check identities the v0.1 reports in ../w3c-v01
already use. That is the only per-case output the checker prints: one ``ok`` or
``FAIL`` line per check, so each member's native line is one printed line,
carried as printed. A coarser member (one of the seven cases) would need several
printed lines folded into one verdict, which is a transform of the native
output. The ids are declared from the vector file before the checker runs, never
read back from its output. Every check reads the same input file, so every
member pins that file: a byte change there is refused for every member, and the
pin cannot say which item inside the file moved.

The intake reader reads one native format, ``corpus-result-json-v1``.
``verify.mjs`` prints text, so this script re-encodes its stdout line by line
into that shape (``native/verify-mjs.cases.json``) and keeps the stdout bytes
beside it (``native/verify-mjs.stdout``). The re-encoding is total and lossless:
the stdout is rendered back from it and must be byte-identical, or nothing is
written. The intake reader checks the carried lines against the re-encoding; the
re-encoding against the stdout is checked here, not by the intake reader.

Python 3.9 or newer, standard library only, for this script. The C1 and C3 parts
import the intake reader from ``--intake-reader`` and run the two outside readers
through ../compat with ``--python`` (3.13+ with cryptography and rfc8785 at the
versions Probity's requirements file pins).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
PKG = "docs/standards/tool-manifest-digest-vectors-v1"
OUT = PKG + "/w3c-intake"
MEMBER = PKG + "/tool-manifest-digest-v1-vectors.json"
MANIFEST = OUT + "/MANIFEST.json"
ANCHOR_LIST = OUT + "/DIGESTS.txt"
RECORD = OUT + "/RECORD.json"
NATIVE_STDOUT = OUT + "/native/verify-mjs.stdout"
NATIVE_CASES = OUT + "/native/verify-mjs.cases.json"
HELPER = OUT + "/intake.py"
RUN_C1 = OUT + "/runs/c1.txt"
RUN_CONTROLS = OUT + "/runs/controls.txt"
RUN_SWEEP = OUT + "/runs/sweep.txt"
CHECKER_SOURCE = [PKG + "/verify.mjs", PKG + "/time.mjs"]
CHECKER_ARGV = ["node", "verify.mjs"]
REPOSITORY = "https://github.com/AgentAvow/AgentAvow"
SUITE = "tool-manifest-digest-v1"
LISTS = "https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/"

#: The intake reader the CHECK lines name, pinned by commit and by the module's bytes.
INTAKE_READER = {
    "repository": "https://github.com/probityai/agent-evidence-vectors",
    "commit": "7e501506c35ddfe5da64bb5885d668f505f7d6d3",
    "module": "packaging/agent_evidence_vectors/w3cintake.py",
    "sha256": "3d7733e02ef2e38e5a3204d3188f2312876b6b615195bbb93b23ce122c5c1a11",
}
#: The two readers written from the specification, pinned by commit and by the
#: bytes of the files the glue imports (sha256-listing-v1 over those paths).
PROBITY = {
    "repository": "https://github.com/probityai/agent-evidence-vectors",
    "commit": "d759fb4db68a7fefcc91c2d3ad2a585471d6a53a",
    "files": [
        "interop/agentavow-live-mcp/definition_pin.py",
        "interop/agentavow-signed-map-v1/map_reader.py",
        "interop/agentavow-signed-map-v1/selection.json",
        "interop/agentavow-signed-map-v1/source-lock.json",
        "packaging/run_vectors.py",
    ],
    "key-file": "interop/agentavow-signed-map-v1/selection.json",
}
HELDFAST = {
    "repository": "https://github.com/rufat325/heldfast",
    "commit": "ca5a872264b486907ed5479247e5150c5122d33d",
    "files": ["src/heldfast"],
}
#: Nicolas Rocchia's run, posted as 2026Oct/0101: emit.py at fbbbd4a with
#: --runner-wrote none, which runs all three readers over the vector file.
NONAUTHOR_COMMIT = "fbbbd4ac71bcdf5353957629d5a9320c49af204d"
NONAUTHOR_FILES = [
    MEMBER, PKG + "/verify.mjs", PKG + "/time.mjs", PKG + "/compat/probity_compat.py",
    PKG + "/compat/heldfast_compat.py", PKG + "/compat/probity-pin.json",
    PKG + "/compat/heldfast-pin.json",
]

ROEL = ("no observed effect for this mutation, under this checker and context; an unchanged "
        "result does not alone establish non-consumption (2026Oct/0127)")
SCOPE_LIMITS = [
    "whole-attack-surface",
    "implementation-ranking",
    "threats-outside-corpus",
    "action-occurred-or-authority",
]
#: verify.mjs's property lines and the v0.1 check identities ../w3c-v01 gives them.
PROPERTIES = {
    "positive case relies": "property/positive-case-relies",
    "a tool the scan never saw does not bind, and its digest is not evaluated":
        "property/unknown-tool-does-not-bind",
    "a changed definition for a known tool does not bind":
        "property/changed-definition-does-not-bind",
    "a grade for one server cannot be re-attached to another":
        "property/wrong-subject-does-not-bind",
    "a signed verdict does not verify forever": "property/expiry-applies",
    "canonical form is not authenticity: tampered payload is canonical yet unsigned":
        "property/canonical-is-not-authentic",
    "a gate time inside the window by a sub-millisecond remainder is fresh and relies":
        "property/boundary-fresh-relies",
    "the pinned set carries boundary-fresh": "property/pinned-set-carries-boundary-fresh",
    "every negative fails exactly one axis": "property/negatives-fail-one-axis",
}
OK, FAIL = "  ok    ", "  FAIL  "
#: Fields of a glue report that echo the input rather than answer about it: the input
#: file's own sha256 and name, and whether that sha256 equals Probity's lock.
ECHO_FIELDS = ("fixture_sha256", "fixture_matches_probity_lock", "vectors_file")
INDENT = "        "


class Refused(SystemExit):
    """Nothing is written: a run or a comparison did not hold."""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def listing(entries: list[tuple[str, str]]) -> str:
    """sha256-listing-v1: SHA-256 over ``<sha256>  <path>\\n`` lines sorted by path."""
    return sha("".join(f"{d}  {p}\n" for p, d in sorted(entries)).encode("utf-8"))


def tree_listing(root: Path, paths: list[str]) -> str:
    entries: list[tuple[str, str]] = []
    for rel in paths:
        full = root / rel
        files = sorted(p for p in full.rglob("*") if p.is_file()) if full.is_dir() else [full]
        for f in files:
            if "__pycache__" in f.parts:
                continue
            entries.append((f.relative_to(root).as_posix(), sha(f.read_bytes())))
    return listing(entries)


def render(value: Any) -> bytes:
    """How every JSON file here is written: sorted keys, two-space indent, final newline."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def vector_bytes(doc: Any) -> bytes:
    """The vector file's own serialization (JSON.stringify with two spaces, final newline)."""
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


# --------------------------------------------------------------------------
# Running things. A run keeps stdout, stderr and the exit code; the complete
# native result of a check is all three.
# --------------------------------------------------------------------------


class Run:
    def __init__(self, argv: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
        proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, env=env)
        self.argv, self.stdout, self.stderr, self.code = argv, proc.stdout, proc.stderr, \
            proc.returncode

    def result(self) -> dict[str, Any]:
        # stderr is recorded as empty or not: a crash's stack trace carries the
        # scratch path, which differs on every run.
        return {"sha256": sha(self.stdout), "exit-code": self.code,
                "stderr": "empty" if not self.stderr else "non-empty"}

    def same(self, other: Run) -> bool:
        return (self.stdout, self.stderr, self.code) == (other.stdout, other.stderr, other.code)


def child_env(**extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(extra)
    return env


def native_run(pkg_dir: Path, args: list[str] | None = None, **env: str) -> Run:
    return Run(CHECKER_ARGV + (args or []), pkg_dir, child_env(**env))


class Readers:
    """The pinned outside readers and the interpreter that runs them."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.python = args.python
        self.probity = Path(args.probity).resolve()
        self.heldfast = Path(args.heldfast).resolve()
        aev = Path(args.intake_reader).resolve()
        module = aev / INTAKE_READER["module"]
        if sha(module.read_bytes()) != INTAKE_READER["sha256"]:
            raise Refused(f"{module} is not the pinned intake reader")
        self.aev = aev
        self.probity_listing = tree_listing(self.probity, PROBITY["files"])
        self.heldfast_listing = tree_listing(self.heldfast, HELDFAST["files"])
        spec = importlib.util.spec_from_file_location("w3cintake_pinned", module)
        assert spec is not None and spec.loader is not None
        self.w3cintake = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.w3cintake)

    def glue(self, which: str, pkg_dir: Path, vectors: str, scratch: Path) -> dict[str, Any]:
        """One run of an outside reader through ../compat. The result is the glue's
        exit code and its report without the provenance block, which names the
        checkout's git HEAD as the glue finds it (environment, not result)."""
        out = scratch / f"{which}-glue.json"
        if out.exists():
            out.unlink()
        script, flag, root, block = {
            "probity": ("compat/probity_compat.py", "--probity", self.probity, "probity"),
            "heldfast": ("compat/heldfast_compat.py", "--heldfast", self.heldfast, "heldfast"),
        }[which]
        run = Run([self.python, script, flag, str(root), "--vectors", vectors, "--out", str(out)],
                  pkg_dir, child_env())
        report = json.loads(out.read_bytes()) if out.exists() else None
        if isinstance(report, dict):
            report.pop(block, None)
        body = render(report) if report is not None else b""
        verdicts = None
        if isinstance(report, dict):
            verdicts = {k: v for k, v in report.items() if k not in ECHO_FIELDS}
        return {"report-sha256": sha(body), "exit-code": run.code,
                "stderr": "empty" if not run.stderr else "non-empty", "_report": report,
                "_verdicts": verdicts}


def public(result: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in result.items() if not k.startswith("_")}


def effects(base: dict[str, Any], got: dict[str, Any]) -> dict[str, str]:
    """Two comparisons of an outside reader's run with its baseline: the complete result
    (report, exit code, stderr state) and the answers alone (the report without the
    fields that echo the input's own digest and name)."""
    complete = (got["_report"], got["exit-code"], got["stderr"]) == (
        base["_report"], base["exit-code"], base["stderr"])
    answers = (got["_verdicts"], got["exit-code"]) == (base["_verdicts"], base["exit-code"])
    word = {True: "no observed effect", False: "changed"}
    return {"complete-result": word[complete], "answers": word[answers]}


# --------------------------------------------------------------------------
# The population, declared from the vector file before anything runs.
# --------------------------------------------------------------------------


def declared_ids(doc: dict[str, Any]) -> list[str]:
    ids = [f"definition-digest/{k}" for k in doc["attestation"]["toolDigests"]]
    ids += ["definition-count", "unsigned-map-equals-signed", "key-encoding-count"]
    ids += [f"key-encoding/{i:02d}" for i in range(len(doc["key_encoding"]))]
    for vec in doc["vectors"]:
        ids += [f"case/{vec['name']}/{axis}" for axis in vec["expect"]]
    names = {v["name"] for v in doc["vectors"]}
    for label, cid in PROPERTIES.items():
        if cid == "property/pinned-set-carries-boundary-fresh":
            continue  # printed only when the pinned set lacks that case
        if cid == "property/boundary-fresh-relies" and "boundary-fresh" not in names:
            continue
        ids.append(cid)
    return ids


# --------------------------------------------------------------------------
# The native output: verify.mjs's stdout, parsed totally, re-encoded per line.
# --------------------------------------------------------------------------


def parse_native(stdout: bytes, doc: dict[str, Any]) -> dict[str, Any]:
    """Every stdout line is a header, a section title, a blank, a check line, the
    want/got pair under a FAIL, or the final summary. Anything else refuses."""
    text = stdout.decode("utf-8")
    if not text.endswith("\n"):
        raise Refused("verify.mjs stdout does not end with a newline")
    lines = text[:-1].split("\n")
    header, rest = lines[:4], lines[4:]
    if len(header) < 4 or header[3] != "":
        raise Refused("verify.mjs stdout has no three-line header")
    pairs = doc["key_encoding"]
    section, pair_index = "", 0
    members: list[dict[str, Any]] = []
    i = 0
    summary = None
    while i < len(rest):
        raw = rest[i]
        if raw == "":
            i += 1
            continue
        if raw.startswith(OK) or raw.startswith(FAIL):
            ok = raw.startswith(OK)
            label = raw[len(OK):] if ok else raw[len(FAIL):]
            findings: list[str] = []
            if not ok:
                if i + 2 >= len(rest) or not rest[i + 1].startswith(INDENT + "want ") or \
                        not rest[i + 2].startswith(INDENT + "got  "):
                    raise Refused(f"FAIL line without its want/got pair: {raw!r}")
                findings = [rest[i + 1][len(INDENT):], rest[i + 2][len(INDENT):]]
            if section.startswith("per-tool digests"):
                if label.startswith("tool:"):
                    cid = f"definition-digest/{label}"
                elif label == "served tool count equals signed tool count":
                    cid = "definition-count"
                elif label == "unsigned toolDigests map equals the signed scan.toolDigests":
                    cid = "unsigned-map-equals-signed"
                else:
                    raise Refused(f"unknown definition line {label!r}")
            elif section == "key encoding":
                if label == "key_encoding pair count":
                    cid = "key-encoding-count"
                else:
                    if pair_index >= len(pairs) or not label.endswith(
                            " -> " + pairs[pair_index]["key"]):
                        raise Refused(f"key line out of order: {label!r}")
                    cid = f"key-encoding/{pair_index:02d}"
                    pair_index += 1
            elif section == "vectors":
                name, sep, axis = label.partition(": ")
                if not sep:
                    raise Refused(f"unknown case line {label!r}")
                cid = f"case/{name}/{axis}"
            elif section == "properties under test":
                if label not in PROPERTIES:
                    raise Refused(f"unknown property line {label!r}")
                cid = PROPERTIES[label]
            else:
                raise Refused(f"check line outside a known section: {raw!r}")
            members.append({"id": cid, "kind": "ok" if ok else "FAIL", "findings": findings,
                            "line": raw})
            i += 3 if not ok else 1
            continue
        if i == len(rest) - 1 and (raw == "all checks passed" or raw.endswith(" failure(s)")):
            summary = raw
            i += 1
            continue
        if raw.startswith(" "):
            raise Refused(f"unparsed indented line {raw!r}")
        section = raw
        i += 1
    if summary is None:
        raise Refused("verify.mjs printed no summary line")
    parsed = {"header": header[:3], "members": members, "summary": summary}
    if render_native(parsed, rest) != stdout:
        raise Refused("the re-encoding does not render back to the stdout bytes")
    return parsed


def render_native(parsed: dict[str, Any], rest: list[str]) -> bytes:
    """The stdout rebuilt from the parse: header, then every non-check line kept in
    place, every check line and its want/got pair from the member it became."""
    out = list(parsed["header"]) + [""]
    queue = list(parsed["members"])
    i = 0
    while i < len(rest):
        raw = rest[i]
        if raw.startswith(OK) or raw.startswith(FAIL):
            m = queue.pop(0)
            out.append(m["line"])
            out += [INDENT + f for f in m["findings"]]
            i += 1 + len(m["findings"])
            continue
        out.append(raw)
        i += 1
    return ("\n".join(out) + "\n").encode("utf-8")


def cases_bytes(parsed: dict[str, Any], stdout: bytes) -> bytes:
    doc = {
        "members": parsed["members"],
        "re-encoding-of": {"path": NATIVE_STDOUT, "sha256": sha(stdout),
                           "command": " ".join(CHECKER_ARGV), "cwd": PKG},
        "rule": "one member per printed ok/FAIL line, in printed order: kind is the printed "
                "token, findings are the want/got lines under a FAIL without their indent, "
                "line is the printed line; header, section titles, blanks and the summary "
                "stay in the stdout file only",
    }
    return (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n").encode("utf-8")


def failures_printed(summary: str) -> int:
    if summary == "all checks passed":
        return 0
    return int(summary.split(" ", 1)[0])


# --------------------------------------------------------------------------
# Pins: the member file, the artifacts, the manifest, the anchor list.
# --------------------------------------------------------------------------


def tracked() -> list[str]:
    listed = subprocess.run(["git", "ls-files", "-z", PKG + "/"], cwd=str(REPO),
                            capture_output=True, check=True)
    return sorted(p for p in listed.stdout.decode("utf-8").split("\0") if p)


def artifact_paths() -> list[str]:
    """Every tracked file of the package that is neither the member file, the checker's
    source, nor this submission's own directory."""
    skip = {MEMBER, *CHECKER_SOURCE}
    return [p for p in tracked() if p not in skip and not p.startswith(OUT + "/")]


def corpus_digest(root: Path, paths: list[str]) -> str:
    """The anchor's routine: sha256-listing-v1 over the member file and every artifact."""
    return listing([(p, sha((root / p).read_bytes())) for p in [MEMBER] + paths])


def manifest_doc(root: Path, paths: list[str], ids: list[str] | None = None) -> dict[str, Any]:
    doc = json.loads((root / MEMBER).read_bytes())
    return {
        "format": "agentavow/tool-manifest-digest-v1-intake-manifest/v1",
        "suite": SUITE,
        "closed": True,
        "package": PKG,
        "member-file": {"path": MEMBER, "sha256": sha((root / MEMBER).read_bytes())},
        "ids": ids if ids is not None else declared_ids(doc),
        "ids-rule": "declared from the vector file before the checker runs: one "
                    "definition-digest/<key> per signed toolDigests key, definition-count, "
                    "unsigned-map-equals-signed, key-encoding-count, key-encoding/NN per "
                    "key_encoding pair, case/<name>/<axis> per expected axis of each vector, "
                    "and the property checks verify.mjs states for this set",
        "artifacts": [{"path": p, "sha256": sha((root / p).read_bytes())} for p in paths],
        "corpusDigestRule": "sha256-listing-v1 (SHA-256 over '<sha256>  <path>\\n' lines "
                            "sorted by path, paths relative to the repository root) over the "
                            "member file and every artifact; corpus_digest in " + HELPER,
        "corpusDigest": corpus_digest(root, paths),
    }


def anchor_list_bytes(digest: str) -> bytes:
    return (f"# {SUITE} intake anchor: the corpus digest and the manifest that declares it\n"
            f"{digest}  {MANIFEST}\n").encode()


# --------------------------------------------------------------------------
# The scratch copy C3 runs in.
# --------------------------------------------------------------------------


class Farm:
    """The package copied out under a scratch root with the repository's layout."""

    def __init__(self, generated: dict[str, bytes]) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="tmd-intake-"))
        shutil.copytree(REPO / PKG, self.root / PKG,
                        ignore=shutil.ignore_patterns("__pycache__"))
        for rel, body in generated.items():
            self.write(rel, body)
        self.pkg = self.root / PKG

    def read(self, rel: str) -> bytes:
        return (self.root / rel).read_bytes()

    def write(self, rel: str, body: bytes) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)

    def remove(self, rel: str) -> None:
        (self.root / rel).unlink()

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def swapped_bytes(rel: str) -> bytes:
    return f"replaced by the swap-and-re-pin consumption test: {rel}\n".encode()


def repin(farm: Farm, rel: str, old: bytes, new: bytes, files: list[str],
          artifacts: list[str]) -> tuple[list[str], str]:
    """Move every pin over ``rel``: its sha256 wherever another file of the package
    writes it, then the pins over each file so changed, until nothing moves; then the
    corpus digest in the manifest and the anchor list."""
    changed: list[str] = []
    queue = [(rel, old, new)]
    while queue:
        source, before, after = queue.pop(0)
        for other in files:
            if other == source or other == rel:
                continue
            body = farm.read(other)
            moved = body.replace(sha(before).encode(), sha(after).encode())
            if moved != body:
                farm.write(other, moved)
                if other not in changed:
                    changed.append(other)
                queue.append((other, body, moved))
    manifest = json.loads(farm.read(MANIFEST))
    recomputed = corpus_digest(farm.root, artifacts)
    if recomputed == manifest["corpusDigest"]:
        return sorted(changed), "unchanged"
    for target in (MANIFEST, ANCHOR_LIST):
        farm.write(target, farm.read(target).replace(manifest["corpusDigest"].encode(),
                                                     recomputed.encode()))
        if target not in changed:
            changed.append(target)
    return sorted(changed), "recomputed"


# --------------------------------------------------------------------------
# The build.
# --------------------------------------------------------------------------


def git_show(commit: str, rel: str) -> bytes | None:
    proc = subprocess.run(["git", "show", f"{commit}:{rel}"], cwd=str(REPO), capture_output=True)
    return proc.stdout if proc.returncode == 0 else None


def build_anchor() -> dict[str, bytes]:
    paths = artifact_paths()
    manifest = manifest_doc(REPO, paths)
    return {MANIFEST: render(manifest), ANCHOR_LIST: anchor_list_bytes(manifest["corpusDigest"])}


def node_version() -> str:
    return Run(["node", "--version"], REPO).stdout.decode().strip()


def build_record(readers: Readers, commit: str, anchor_files: dict[str, bytes],
                 scratch: Path) -> tuple[dict[str, Any], dict[str, bytes], dict[str, Any]]:
    """The record, the native files, and the measurements the logs are written from."""
    pkg_dir = REPO / PKG
    member_raw = (REPO / MEMBER).read_bytes()
    doc = json.loads(member_raw)
    manifest = json.loads(anchor_files[MANIFEST])
    for rel, body in anchor_files.items():
        if (REPO / rel).read_bytes() != body:
            raise Refused(f"{rel} on disk is not what the anchor stage writes now")
    paths = [a["path"] for a in manifest["artifacts"]]

    runs = [native_run(pkg_dir), native_run(pkg_dir),
            native_run(pkg_dir, TZ="Pacific/Kiritimati", LANG="C", LC_ALL="C")]
    first = runs[0]
    if first.stderr:
        raise Refused(f"verify.mjs wrote to stderr: {first.stderr[:200]!r}")
    parsed = parse_native(first.stdout, doc)
    stdout, cases = first.stdout, cases_bytes(parsed, first.stdout)
    natives = {NATIVE_STDOUT: stdout, NATIVE_CASES: cases}
    members = parsed["members"]
    ids = manifest["ids"]

    checks = [{"check": m["id"], "state": "pass" if m["kind"] == "ok" else "fail",
               "native": {"verdict": m["kind"], "reasons": m["findings"]}} for m in members]
    recount_fail = sum(1 for m in members if m["kind"] == "FAIL")
    printed_fail = failures_printed(parsed["summary"])
    agrees = printed_fail == recount_fail and ((first.code == 0) == (recount_fail == 0))
    if not agrees:
        raise Refused(f"the printed aggregate says {printed_fail} failure(s) and the per-check "
                      f"lines recount {recount_fail}, exit code {first.code}")
    counts: dict[str, int] = {}
    for m in members:
        counts[m["kind"]] = counts.get(m["kind"], 0) + 1
    refusals = [{"check": c["check"], "rule": "verify.mjs's check for this id fails when the "
                 "value it computes is not the value the vector file states; the want/got "
                 "pair under the FAIL line carries both",
                 "inputs": [f"member:{c['check']}", f"check:{c['check']}"]}
                for c in checks if c["state"] == "fail"]
    member_pin = {"path": MEMBER, "sha256": sha(member_raw)}
    members_field = [{"id": i, "files": [dict(member_pin)]} for i in ids]

    farm = Farm({**anchor_files, **natives})
    try:
        c3 = consumption(readers, farm, paths, scratch, first)
        fields = member_field_mutations(readers, farm, doc, scratch)
        faults = fault_runs(pkg_dir, doc)
        spec_runs = {w: readers.glue(w, pkg_dir, "tool-manifest-digest-v1-vectors.json", scratch)
                     for w in ("probity", "heldfast")}
    finally:
        farm.close()

    artifacts = []
    for rel in paths:
        ev = c3["artifacts"][rel]
        artifacts.append({"path": rel, "sha256": sha((REPO / rel).read_bytes()),
                          "serialization": "bytes", "consumed": ev["state"],
                          "evidence": ev["evidence"]})
    anchor = {
        "kind": "digest-list-line",
        "reference": {"uri": f"{REPOSITORY}/blob/{commit}/{ANCHOR_LIST}", "path": ANCHOR_LIST},
        "git-commit": commit,
        "manifest": MANIFEST,
        "sha256": manifest["corpusDigest"],
        "serialization": "corpus-routine",
        "routine": f"corpus_digest in {HELPER}",
        "routine-file": HELPER,
        "verdicts": {"availability-failure": "inconclusive", "integrity-failure": "fail"},
        "verification": {
            "commands": [
                f"git cat-file -e {commit}^{{commit}}",
                f"git show {commit}:{ANCHOR_LIST} | grep -Fx -- "
                f"'{manifest['corpusDigest']}  {MANIFEST}'",
            ],
            "availability-failure": "the commit does not resolve in a clone of "
                                    f"{REPOSITORY} (git cat-file exits non-zero)",
            "integrity-failure": "the commit resolves and its DIGESTS.txt carries no line "
                                 "binding this digest to this manifest",
            "what-binds": "a git commit identifier (SHA-1 object id), which binds content, "
                          "not a signer; no signature is offered. Who published the commit "
                          "rests on the repository and on the list message that names it",
            "same-as": "python3 intake.py anchor-check",
        },
    }
    record_doc: dict[str, Any] = {
        "format": "public-agent-conformance/intake-record/v2",
        "suite": SUITE,
        "criteria": "intake criteria v2.1 as consolidated for the editor in October 2026; "
                    "record shape of agent_evidence_vectors.w3cintake at "
                    f"{INTAKE_READER['commit']}",
        "boundary": {"root": PKG, "complete": True, "member-locations": [
            {"dir": "", "suffix": "tool-manifest-digest-v1-vectors.json", "recursive": False}],
            "note": "the package's members all live in the one vector file; a member added "
                    "inside it is returned by the checker as a check outside the manifest "
                    "(W3C-I-007), and a file added beside it is outside the claim"},
        "manifest": {"closed": True, "path": MANIFEST, "sha256": sha(anchor_files[MANIFEST]),
                     "ids": ids},
        "members": members_field,
        "pin-serialization": "bytes",
        "corpus-digest": {"serialization": "sha256-listing-v1", "sha256": listing(
            [(MEMBER, member_pin["sha256"])] * len(ids)
            + [(a["path"], a["sha256"]) for a in artifacts]
            + [(MANIFEST, sha(anchor_files[MANIFEST]))])},
        "selector": {"language": "id-glob", "expression": "*", "require": "at-least-one",
                     "selected": ids, "matched": len(ids)},
        "checks": checks,
        "aggregate": {"line": parsed["summary"], "total": len(members), "counts": counts},
        "aggregate-agreement": {
            "printed-line": parsed["summary"],
            "printed-failures": printed_fail,
            "printed-total": None,
            "recount": {"total": len(members), "failures": recount_fail,
                        "passes": len(members) - recount_fail},
            "exit-code": first.code,
            "agrees": agrees,
            "rule": "the printed line states a failure count (all checks passed means 0) and "
                    "no total; it is compared with the FAIL lines recounted from the per-check "
                    "lines, and the exit code with whether any FAIL line exists. A "
                    "disagreement is a refusal and nothing is written",
        },
        "exit-code": first.code,
        "exit-rule": "zero-iff-every-check-passes",
        "state": "pass" if recount_fail == 0 else "fail",
        "refusal-verdicts": ["FAIL"],
        "refusals": refusals,
        "native": {"format": "corpus-result-json-v1", "cases": "native-cases", "summary": None,
                   "process-status": {"exit-code": first.code},
                   "re-encoding": "verify.mjs prints text; native-cases is its stdout "
                                  "re-encoded one printed line per member and checked to "
                                  "render back to the stdout bytes exactly. The intake reader "
                                  "checks the carried lines against native-cases; the stdout "
                                  "against native-cases is checked by intake.py check"},
        "observations": [
            {"id": "native-stdout", "carry": "referenced", "reference": {
                "path": NATIVE_STDOUT, "sha256": sha(stdout), "serialization": "bytes"}},
            {"id": "native-cases", "carry": "referenced", "reference": {
                "path": NATIVE_CASES, "sha256": sha(cases), "serialization": "bytes"}},
            {"id": "stderr", "carry": "carried", "carried": ""},
            {"id": "exit-code", "carry": "carried", "carried": str(first.code)},
        ],
        "artifacts": artifacts,
        "member-consumption": c3["member"],
        "member-field-mutations": fields,
        "anchor": anchor,
        "checker": {
            "name": "verify.mjs (AgentAvow native verifier)",
            "revision": {"kind": "source-listing", "paths": CHECKER_SOURCE,
                         "serialization": "sha256-listing-v1",
                         "sha256": listing([(p, sha((REPO / p).read_bytes()))
                                            for p in CHECKER_SOURCE])},
            "commands": [f"cd {PKG} && node verify.mjs"],
            "runtime": {"name": "node", "version": node_version().lstrip("v")},
            "dependencies": [],
            "dependencies-note": "verify.mjs imports node:crypto, node:fs and ./time.mjs only",
            "helpers": [{"uri": f"{REPOSITORY}/blob/{commit}/{HELPER}", "path": HELPER,
                         "sha256": sha((REPO / HELPER).read_bytes()), "serialization": "bytes",
                         "role": "re-encodes the checker's stdout into native-cases, and "
                                 "writes this record; not acquired over the network"}],
            "helper-runtime": {"name": "cpython", "version": platform.python_version()},
            "relationship": "same-implementation",
            "shared-verification-code": CHECKER_SOURCE,
        },
        "specification-readers": spec_readers(readers, spec_runs),
        "non-author-runs": nonauthor_runs(),
        "canonicalization": {"encoding": "jcs-sha256",
                             "instance": "the attestation payload under test is RFC 8785 "
                                         "bytes; the record offers no digest over a JSON value"},
        "byte-identity": {"pins": len(ids), "serialization": "bytes",
                          "note": "one pin per member, each over the one vector file"},
        "replay-stability": {
            "state": "stable" if len({sha(r.stdout) for r in runs}) == 1
            and all(r.same(first) for r in runs) else "varies",
            "ordering": "emission-order",
            "seed": None,
            "seed-note": "verify.mjs iterates arrays and sorted keys; no hash seed reaches its "
                         "output. The re-encoding writes members in printed order",
            "cause": None,
            "runs": [{"process": "run-1", "sha256": sha(runs[0].stdout)},
                     {"process": "run-2", "sha256": sha(runs[1].stdout)},
                     {"process": "run-3 (TZ=Pacific/Kiritimati, LANG=C, LC_ALL=C)",
                      "sha256": sha(runs[2].stdout)}],
            "scope": "three processes on one machine and one Node version; not measured "
                     "across runtimes at the stdout level",
        },
        "exposure": "visible",
        "exposure-note": "the expected answers are in the vector file and were visible to "
                         "every implementer and every runner",
        "faults": faults,
        "relaxed-controls": [],
        "relaxed-controls-note": "no check of this suite has been run relaxed; there is no "
                                 "relaxed result to pair with a baseline",
        "scope": {
            "establishes": [
                f"verify.mjs, at the source listing named here and run as `node verify.mjs` "
                f"under the Node version named here, returns the {len(ids)} declared checks "
                f"over the pinned vector file, each equal to the value the file states for it",
                "the two readers written from the specification, at their pinned commits and "
                "through AgentAvow's glue, agree with the vector file on every check each "
                "makes, on the same bytes (see specification-readers)",
                "each of the three injected faults fails exactly its target check (faults)",
            ],
            "leaves-open": [
                "anything about AgentAvow's safety grades, trust scores or answers; the "
                "vectors pin one attestation for one server and test byte agreement only",
                "runtime behaviour of the pinned server or of any tool",
                "who published the anchor: it is a git commit, which binds content and "
                "names no signer",
                "whether any reader reaches these results without the expected answers "
                "visible: they were visible to all",
                "replay across Node versions or platforms at the stdout level",
                "for an artifact recorded unconsumed: " + ROEL,
                "the readers written from the specification have been run against these "
                "bytes only through AgentAvow's glue, by the vector author and by one "
                "operator who wrote none of it",
            ],
            "does-not-claim": list(SCOPE_LIMITS),
        },
    }
    measurements = {"runs": runs, "parsed": parsed, "spec_runs": spec_runs, "c3": c3}
    return record_doc, natives, measurements


def consumption(readers: Readers, farm: Farm, artifacts: list[str], scratch: Path,
                first: Run) -> dict[str, Any]:
    """The swap-and-re-pin test of 2026Oct/0091 for every artifact, under the record's
    checker and under each outside reader's glue."""
    files = [p for p in tracked() if not p.startswith(OUT + "/")] + [MANIFEST, ANCHOR_LIST]
    base = native_run(farm.pkg)
    if not base.same(first):
        raise Refused("verify.mjs prints other output in the scratch copy than in the "
                      "repository, so a swap there proves nothing")
    vec = "tool-manifest-digest-v1-vectors.json"
    other_base = {w: readers.glue(w, farm.pkg, vec, scratch) for w in ("probity", "heldfast")}
    out: dict[str, Any] = {"artifacts": {}}
    snapshot = {p: farm.read(p) for p in files}
    for rel in artifacts + [MEMBER]:
        old, new = farm.read(rel), swapped_bytes(rel)
        farm.write(rel, new)
        changed, digest_state = repin(farm, rel, old, new, files, artifacts)
        after = native_run(farm.pkg)
        others = {}
        for w in ("probity", "heldfast"):
            got = readers.glue(w, farm.pkg, vec, scratch)
            others[{"probity": "probity-map-reader", "heldfast": "heldfast-profiles"}[w]] = {
                "baseline": public(other_base[w]), "swapped": public(got),
                **effects(other_base[w], got)}
        for p in [rel] + changed:
            farm.write(p, snapshot[p])
        native_changed = not after.same(base)
        if native_changed != ((sha(after.stdout), after.code) != (sha(base.stdout), base.code)):
            raise Refused(f"{rel}: the swap changed stderr only, which the record's native "
                          "result shape cannot carry")
        evidence = {
            "test": "swap-and-re-pin",
            "swapped-in": sha(new),
            "pins-moved": changed,
            "corpus-digest": digest_state,
            "baseline": base.result(),
            "swapped": after.result(),
            "reading": "changed: the swap changes the complete native result of this "
                       "checker" if native_changed else ROEL,
            "other-readers": others,
        }
        entry = {"state": "consumed" if native_changed else "unconsumed", "evidence": evidence}
        if rel == MEMBER:
            out["member"] = {"path": rel, **entry}
        else:
            out["artifacts"][rel] = entry
    return out


RFC8032_TEST1_PUBLIC = "11qYAYKxCrfVS_7TyWQHOg7hcvPaoiMlrwIaaPcHURo"


def _set(doc: Any, pointer: list[Any], value: Any) -> None:
    for key in pointer[:-1]:
        doc = doc[key]
    doc[pointer[-1]] = value


MEMBER_FIELD_MUTATIONS: list[dict[str, Any]] = [
    {"id": "issuer-key", "pointer": ["issuer", "jwk", "x"], "to": RFC8032_TEST1_PUBLIC,
     "why": "the verification key: replaced by the RFC 8032 test 1 public key (no private "
            "key of ours is involved)"},
    {"id": "issuer-id", "pointer": ["issuer", "id"], "to": "did:web:example.invalid",
     "why": "the issuer identifier the file names"},
    {"id": "jwks-url", "pointer": ["issuer", "jwks_url"],
     "to": "https://example.invalid/.well-known/jwks.json", "why": "where the key is published"},
    {"id": "unsigned-map-entry", "pointer": ["attestation", "toolDigests",
                                             "tool:ask_wiki_question"],
     "to": "sha256:" + "0" * 64, "why": "the unsigned convenience copy of one signed digest"},
    {"id": "payload-sha256", "pointer": ["attestation", "payload_sha256"], "to": "0" * 64,
     "why": "the file's stated digest of the signed payload"},
    {"id": "claim-ceiling", "pointer": ["claim_ceiling"], "to": "edited",
     "why": "prose: the claim ceiling"},
    {"id": "case-note", "pointer": ["vectors", 0, "note"], "to": "edited",
     "why": "prose: a case's note"},
]


def member_field_mutations(readers: Readers, farm: Farm, doc: dict[str, Any],
                           scratch: Path) -> dict[str, Any]:
    """One field of the vector file changed at a time, the file re-pinned (verify.mjs
    checks no pin, so the swap alone decides), each reader re-run. Then the one key
    input that lives outside the file: Probity's selected key."""
    vec = "tool-manifest-digest-v1-vectors.json"
    original = farm.read(MEMBER)
    if vector_bytes(doc) != original:
        raise Refused("the vector file is not in its own serialization; field swaps would "
                      "change formatting too")
    base = native_run(farm.pkg)
    other_base = {w: readers.glue(w, farm.pkg, vec, scratch) for w in ("probity", "heldfast")}
    rows = []
    for m in MEMBER_FIELD_MUTATIONS:
        mutated = copy.deepcopy(doc)
        _set(mutated, m["pointer"], m["to"])
        farm.write(MEMBER, vector_bytes(mutated))
        after = native_run(farm.pkg)
        row = {"id": m["id"], "field": "/" + "/".join(str(p) for p in m["pointer"]),
               "what": m["why"], "native": "changed" if not after.same(base)
               else "no observed effect"}
        for w, name in (("probity", "probity-map-reader"), ("heldfast", "heldfast-profiles")):
            row[name] = effects(other_base[w], readers.glue(w, farm.pkg, vec, scratch))
        rows.append(row)
    farm.write(MEMBER, original)
    # Probity selects its key from its own selection.json, not from the file.
    selection = readers.probity / PROBITY["key-file"]
    saved = selection.read_bytes()
    try:
        chosen = json.loads(saved)
        chosen["jwk"]["x"] = RFC8032_TEST1_PUBLIC
        selection.write_bytes(render(chosen))
        got = readers.glue("probity", farm.pkg, vec, scratch)
    finally:
        selection.write_bytes(saved)
    probity_key = {
        "id": "probity-selected-key", "field": PROBITY["key-file"] + " /jwk/x",
        "what": "the key Probity's reader verifies under, in its own checkout, replaced by the "
                "RFC 8032 test 1 public key",
        "native": "not read", "heldfast-profiles": "not read",
        "probity-map-reader": effects(other_base["probity"], got)}
    return {"rows": rows + [probity_key], "reading": "'no observed effect': " + ROEL
            + ". 'changed': that reader's result differs from its baseline. For the outside "
            "readers, complete-result includes the glue's echo of the input file's own sha256, "
            "so any byte change to the vector file changes it; answers leaves that echo out"}


def fault_runs(pkg_dir: Path, doc: dict[str, Any]) -> list[dict[str, Any]]:
    """The three controls of ../w3c-v01, each built to fail one check, run through the
    record's checker as injected faults with results of their own."""
    controls = json.loads((REPO / PKG / "w3c-v01/records/controls.json").read_bytes())
    seen: dict[str, dict[str, Any]] = {}
    for c in controls:
        cid = c["fixture_id"].split("/")[0]
        seen.setdefault(cid, c)
    out = []
    base = parse_native(native_run(pkg_dir).stdout, doc)
    base_fail = {m["id"] for m in base["members"] if m["kind"] == "FAIL"}
    for cid, c in sorted(seen.items()):
        rel = "w3c-v01/records/" + c["input"]["ref"]
        body = (pkg_dir / rel).read_bytes()
        run = native_run(pkg_dir, [rel])
        parsed = parse_native(run.stdout, json.loads(body))
        failed = sorted(m["id"] for m in parsed["members"] if m["kind"] == "FAIL")
        target = c["target_check"]["check_id"]
        out.append({
            "id": cid,
            "injected": c["derived_from"]["change"],
            "input": {"path": PKG + "/" + rel, "sha256": sha(body)},
            "command": f"cd {PKG} && node verify.mjs {rel}",
            "target-check": target,
            "result": {"state": "fail" if failed == [target] and not base_fail else "void",
                       "exit-code": run.code, "stdout-sha256": sha(run.stdout),
                       "failed-checks": failed,
                       "detected": failed == [target]},
        })
    return out


def spec_readers(readers: Readers, runs: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """What each outside reader returned on the pinned file, counted as the v0.1 reports
    in ../w3c-v01 count it: Probity 3 digests, the count, the payload digest, 13 keys and
    the seven expected axes of each case (its own issuer_binds axis is not compared);
    heldfast 3 digests and 13 keys."""
    p, h = runs["probity"]["_report"], runs["heldfast"]["_report"]
    doc = json.loads((REPO / MEMBER).read_bytes())
    expect = {v["name"]: v["expect"] for v in doc["vectors"]}
    p_total = (len(p["key_pairs"]) + len(p["definitions"]) + 2
               + sum(len(expect[r["name"]]) for r in p["results"]))
    p_agree = (sum(k["matches"] for k in p["key_pairs"])
               + sum(d["matches"] for d in p["definitions"])
               + int(p["definition_count_matches"]) + int(p["payload_digest_matches"])
               + sum(1 for r in p["results"] for a, w in expect[r["name"]].items()
                     if r["axes"].get(a) == w))
    h_total = len(h["key_pairs"]) + len(h["definitions"])
    h_agree = (sum(k["matches"] for k in h["key_pairs"])
               + sum(d["matches"] for d in h["definitions"]))
    return [
        {
            "reader": f"{PROBITY['repository']}/tree/{PROBITY['commit']}/"
                      "interop/agentavow-signed-map-v1 (map_reader.py)",
            "author": "Sankalp Gilda, Probity",
            "relationship": "written-from-specification",
            "basis": "its README at the pinned commit: it reads the producer's version-1 "
                     "profile, and the native verifier is never imported or executed",
            "revision": {"kind": "git-commit", "value": PROBITY["commit"]},
            "reader-files": {"paths": PROBITY["files"], "serialization": "sha256-listing-v1",
                             "sha256": readers.probity_listing},
            "key-source": {"path": PROBITY["key-file"], "sha256": sha(
                (readers.probity / PROBITY["key-file"]).read_bytes()), "serialization": "bytes",
                "note": "the reader verifies under this key, not the key in the vector file"},
            "glue": {"path": PKG + "/compat/probity_compat.py", "sha256": sha(
                (REPO / PKG / "compat/probity_compat.py").read_bytes()), "serialization": "bytes",
                "note": "AgentAvow's glue: calls the reader's functions and writes their "
                        "answers; no encoding, hashing or verification of its own"},
            "this-run": {"operator": "the vector author (AgentAvow), with the answers visible",
                         "checks": p_total, "agree": p_agree,
                         "glue-exit-code": runs["probity"]["exit-code"]},
            "author-run": "the reader's author ran it on the vector file at producer commit "
                          "36426cf, whose bytes differ from the pinned file (the boundary-fresh "
                          "case was added after); Probity's own driver refuses the current file "
                          "for that reason",
        },
        {
            "reader": f"{HELDFAST['repository']}/blob/{HELDFAST['commit']}/"
                      "src/heldfast/profiles.py",
            "author": "rufat325, heldfast",
            "relationship": "written-from-specification",
            "basis": "heldfast's statement on stacklok/toolhive#6734 and its TRANSPARENCY.md: "
                     "its own implementation of the published rules, with none of our files "
                     "copied",
            "revision": {"kind": "git-commit", "value": HELDFAST["commit"]},
            "reader-files": {"paths": HELDFAST["files"], "serialization": "sha256-listing-v1",
                             "sha256": readers.heldfast_listing},
            "glue": {"path": PKG + "/compat/heldfast_compat.py", "sha256": sha(
                (REPO / PKG / "compat/heldfast_compat.py").read_bytes()),
                "serialization": "bytes",
                "note": "AgentAvow's glue: calls agentavow_v1_digest and agentavow_v1_key"},
            "claims": "the three served-definition digests and the thirteen key pairs only",
            "this-run": {"operator": "the vector author (AgentAvow), with the answers visible",
                         "checks": h_total, "agree": h_agree,
                         "glue-exit-code": runs["heldfast"]["exit-code"]},
        },
    ]


def nonauthor_runs() -> list[dict[str, Any]]:
    covers = all(git_show(NONAUTHOR_COMMIT, p) == (REPO / p).read_bytes()
                 for p in NONAUTHOR_FILES)
    common = {
        "operator": "Nicolas Rocchia (wrote none of the vectors, the readers or the glue)",
        "date": "2026-10-14",
        "list-message": LISTS + "0101.html",
        "producer-commit": NONAUTHOR_COMMIT,
        "command": "python emit.py --runner <name> --runner-wrote none --out records "
                   "(in w3c-v01)",
        "environment": "Linux x86_64, Python 3.13.7, cryptography 50.0.2, rfc8785 0.1.4, "
                       "Node v22.22.2",
        "files-compared": NONAUTHOR_FILES,
        "covers-these-bytes": covers,
        "output": "v0.1 reports, eleven of thirteen files byte-identical to the committed "
                  "ones; run.json and SHA256SUMS differ by design. Not this record's native "
                  "output: the run predates it",
        "answers-visible": True,
    }
    return [
        {**common, "reader": "verify.mjs", "relationship": "same-implementation",
         "shared-verification-code": CHECKER_SOURCE, "result": "76/76",
         "label": "a reproduction in O8's sense: our implementation, another operator"},
        {**common, "reader": f"Probity map_reader at {PROBITY['commit']}",
         "relationship": "written-from-specification", "shared-verification-code": [],
         "result": "67/67",
         "label": "a reader written from the specification, run by someone who wrote neither "
                  "it nor the vectors, through AgentAvow's glue"},
        {**common, "reader": f"heldfast profiles.py at {HELDFAST['commit']}",
         "relationship": "written-from-specification", "shared-verification-code": [],
         "result": "16/16",
         "label": "a reader written from the specification, run by someone who wrote neither "
                  "it nor the vectors, through AgentAvow's glue"},
    ]


def refused_by(readers: Readers, record_doc: dict[str, Any],
               generated: dict[str, bytes]) -> None:
    """For each artifact recorded unconsumed, the grounds the intake reader raises when it
    is swapped with its pin left in place."""
    for item in record_doc["artifacts"]:
        if item["consumed"] == "unconsumed":
            item["evidence"]["refused-by"] = ["W3C-I-002"]
    farm = Farm(generated)
    try:
        before = readers.w3cintake.rejections(record_doc, str(farm.root))
        if before:
            raise Refused(f"the intake reader refuses the record before any swap: {before}")
        for item in record_doc["artifacts"]:
            if item["consumed"] != "unconsumed":
                continue
            old = farm.read(item["path"])
            farm.write(item["path"], swapped_bytes(item["path"]))
            found = readers.w3cintake.rejections(record_doc, str(farm.root))
            farm.write(item["path"], old)
            if not found:
                raise Refused(f"{item['path']} swapped with its pin in place is refused under "
                              "no ground")
            item["evidence"]["refused-by"] = found
    finally:
        farm.close()


# --------------------------------------------------------------------------
# C1, controls, sweep: the logs under runs/.
# --------------------------------------------------------------------------


def c1_log(readers: Readers, generated: dict[str, bytes]) -> bytes:
    farm = Farm(generated)
    try:
        env = child_env(PYTHONPATH=str(readers.aev / "packaging"), PYTHONHASHSEED="0")
        cmd = [readers.python, "-m", "agent_evidence_vectors.w3cintake", RECORD, "--root", "."]
        run = Run(cmd, farm.root, env)
        judge = Run([readers.python, "-m", "agent_evidence_vectors.w3cintake", "--judge",
                     "vectors-w3c-intake"], readers.aev, env)
    finally:
        farm.close()
    shown = (f"PYTHONPATH=aev/packaging PYTHONHASHSEED=0 python3 -m "
             f"agent_evidence_vectors.w3cintake {RECORD} --root .")
    judge_lines = judge.stdout.decode().splitlines()
    return "\n".join([
        f"intake reader: {INTAKE_READER['repository']} at {INTAKE_READER['commit']}",
        f"module sha256: {INTAKE_READER['sha256']}",
        "",
        "C1, from the repository root:",
        f"$ {shown}",
        run.stdout.decode().rstrip("\n"),
        f"exit {run.code}",
        f"stdout sha256 {sha(run.stdout)}",
        "",
        "criterion 13, the same reader on its own corpus, from its checkout:",
        "$ python3 -m agent_evidence_vectors.w3cintake --judge vectors-w3c-intake",
        *judge_lines[:4],
        judge_lines[-1] if judge_lines else "",
        f"exit {judge.code}",
        f"stdout sha256 {sha(judge.stdout)}",
    ]).encode() + b"\n"


def record_bytes(doc: dict[str, Any]) -> bytes:
    return render(doc)


def controls_log(readers: Readers, record_doc: dict[str, Any], generated: dict[str, bytes],
                 commit: str) -> bytes:
    """Mutations of the record and of the tree, each read by the intake reader (C1, in
    process) and, for the anchor, by the anchor's own check (C2)."""
    w = readers.w3cintake
    lines = ["Controls. Each row: what changed, then the intake reader's grounds "
             "(C1 with the root), and for the anchor rows the anchor check (C2).", ""]

    def on_record(label: str, mutate: Callable[[dict[str, Any]], None]) -> None:
        doc = copy.deepcopy(record_doc)
        mutate(doc)
        farm = Farm(generated)
        try:
            found = w.rejections(doc, str(farm.root))
        finally:
            farm.close()
        verdict = "refused under " + ", ".join(found) if found else "admitted"
        lines.append(f"- record: {label}: {verdict}")

    def on_tree(label: str, change: Callable[[Farm], None], c2: bool = False,
                doc: dict[str, Any] | None = None) -> None:
        farm = Farm(generated)
        try:
            change(farm)
            used = doc if doc is not None else record_doc
            found = w.rejections(used, str(farm.root))
            extra = ""
            if c2:
                body = git_show(commit, ANCHOR_LIST)
                want = f"{used['anchor']['sha256']}  {used['anchor']['manifest']}"
                ok = body is not None and want in body.decode().split("\n")
                extra = f"; C2 against {commit[:12]}: {'exit 0' if ok else 'exit 1'}"
        finally:
            farm.close()
        lines.append(f"- tree: {label}: "
                     f"{'refused under ' + ', '.join(found) if found else 'admitted'}{extra}")

    on_record("criterion 3, selector expression matches nothing ('nothing*')",
              lambda d: d["selector"].update(expression="nothing*", selected=[], matched=0))
    on_record("criterion 3, exactly one member required, '*' matches 76",
              lambda d: d["selector"].update(require="exactly-one"))
    on_record("criterion 3, selector.matched changed to 0 (Roel's second case, 0129)",
              lambda d: d["selector"].update(matched=0))
    on_record("criterion 1, one member pin changed to 64 zeroes (Roel's first case, 0129)",
              lambda d: d["members"][0]["files"][0].update(sha256="0" * 64))
    on_record("criterion 4, aggregate total changed to 77",
              lambda d: d["aggregate"].update(total=77))
    on_record("criterion 4, exit code carried as 1",
              lambda d: d.update({"exit-code": 1}))
    on_record("criterion 4, aggregate-agreement.agrees changed to false (a field the intake "
              "reader does not read)",
              lambda d: d["aggregate-agreement"].update(agrees=False))
    on_record("criterion 5, one carried verdict changed from ok to FAIL",
              lambda d: d["checks"][0]["native"].update(verdict="FAIL"))
    on_record("criterion 6, an unconsumed artifact declared consumed",
              lambda d: next(a for a in d["artifacts"] if a["consumed"] == "unconsumed")
              .update(consumed="consumed"))
    on_record("criterion 8, specification-readers removed",
              lambda d: d.pop("specification-readers"))
    on_record("criterion 10, one replay digest changed, state left stable",
              lambda d: d["replay-stability"]["runs"][1].update(sha256="0" * 64))
    on_record("criterion 12, one limit removed from does-not-claim",
              lambda d: d["scope"]["does-not-claim"].pop())
    lines.append("")

    def drop_case(name: str) -> Callable[[dict[str, Any]], None]:
        return lambda d: d.__setitem__("vectors", [v for v in d["vectors"] if v["name"] != name])

    def add_copy(d: dict[str, Any]) -> None:
        extra = copy.deepcopy(d["vectors"][0])
        extra["name"] = "tool-match-copy"
        d["vectors"].append(extra)

    def dup_case(d: dict[str, Any]) -> None:
        d["vectors"].append(copy.deepcopy(d["vectors"][0]))

    for label, mutate in (
        ("criterion 2 (i), the boundary-fresh case removed from the vector file", drop_case(
            "boundary-fresh")),
        ("criterion 2 (ii), the tool-match case duplicated in the vector file", dup_case),
        ("criterion 2 (iii), an eighth case added inside the vector file", add_copy),
    ):
        lines.append(population_control(readers, record_doc, generated, label, mutate))
    lines.append("")

    on_tree("criterion 1, the vector file's bytes moved, pins left (a key changed)",
            lambda f: f.write(MEMBER, f.read(MEMBER).replace(b"JwovTLVbpgk85zlMNruTiLzp85dAuc",
                                                             b"JwovTLVbpgk85zlMNruTiLzp85dAuX")))
    on_tree("criterion 2, a file named like the vector file added beside it "
            "(extra-tool-manifest-digest-v1-vectors.json)",
            lambda f: f.write(PKG + "/extra-tool-manifest-digest-v1-vectors.json",
                              f.read(MEMBER)))
    on_tree("criterion 2, the same file added inside the declared location's directory under "
            "another name (copy.json)", lambda f: f.write(PKG + "/copy.json", f.read(MEMBER)))
    on_tree("criterion 5, the native stdout file edited (one ok token changed)",
            lambda f: f.write(NATIVE_STDOUT, f.read(NATIVE_STDOUT).replace(b"  ok    ",
                                                                           b"  oK    ", 1)))
    on_tree("criterion 5, the re-encoded native cases edited (one finding added)",
            lambda f: f.write(NATIVE_CASES, f.read(NATIVE_CASES).replace(
                b'"findings":[]', b'"findings":["x"]', 1)))
    on_tree("criterion 7, DIGESTS.txt removed", lambda f: f.remove(ANCHOR_LIST), c2=True)
    on_tree("criterion 7, the DIGESTS.txt line's digest changed",
            lambda f: f.write(ANCHOR_LIST, f.read(ANCHOR_LIST).replace(
                record_doc["anchor"]["sha256"].encode(), b"0" * 64)), c2=True)
    rewritten, tree_change = consistent_rewrite(record_doc, generated)
    on_tree("criterion 7, consistent rewrite: one key byte in the vector file, then every pin "
            "moved (record, manifest, corpus digest, DIGESTS.txt line); the record still names "
            "the anchor commit", tree_change, c2=True, doc=rewritten)
    on_tree("criterion 8, the helper (intake.py) edited",
            lambda f: f.write(HELPER, f.read(HELPER) + b"\n"))
    on_tree("criterion 8, the checker source (time.mjs) edited",
            lambda f: f.write(PKG + "/time.mjs", f.read(PKG + "/time.mjs") + b"\n"))
    return ("\n".join(lines) + "\n").encode()


def consistent_rewrite(record_doc: dict[str, Any], generated: dict[str, bytes]
                       ) -> tuple[dict[str, Any], Callable[[Farm], None]]:
    old = (REPO / MEMBER).read_bytes()
    new = old.replace(b"JwovTLVbpgk85zlMNruTiLzp85dAuc", b"JwovTLVbpgk85zlMNruTiLzp85dAuX")
    manifest = json.loads(generated[MANIFEST])
    manifest["member-file"]["sha256"] = sha(new)
    entries = [(MEMBER, sha(new))] + [(a["path"], a["sha256"]) for a in manifest["artifacts"]]
    manifest["corpusDigest"] = listing(entries)
    manifest_bytes = render(manifest)
    doc = copy.deepcopy(record_doc)
    for m in doc["members"]:
        m["files"][0]["sha256"] = sha(new)
    doc["manifest"]["sha256"] = sha(manifest_bytes)
    doc["anchor"]["sha256"] = manifest["corpusDigest"]
    doc["corpus-digest"]["sha256"] = listing(
        [(MEMBER, sha(new))] * len(doc["members"])
        + [(a["path"], a["sha256"]) for a in doc["artifacts"]] + [(MANIFEST, sha(manifest_bytes))])

    def change(farm: Farm) -> None:
        farm.write(MEMBER, new)
        farm.write(MANIFEST, manifest_bytes)
        farm.write(ANCHOR_LIST, anchor_list_bytes(manifest["corpusDigest"]))
    return doc, change


def population_control(readers: Readers, record_doc: dict[str, Any],
                       generated: dict[str, bytes], label: str,
                       mutate: Callable[[dict[str, Any]], None]) -> str:
    """The vector file changed, the checker re-run, every pin moved to the new bytes; the
    manifest keeps the population declared before the change."""
    doc = json.loads((REPO / MEMBER).read_bytes())
    mutate(doc)
    new = vector_bytes(doc)
    farm = Farm(generated)
    try:
        farm.write(MEMBER, new)
        run = native_run(farm.pkg)
        try:
            parsed = parse_native(run.stdout, doc)
        except Refused as exc:
            return f"- population: {label}: the checker's output does not parse ({exc})"
        stdout, cases = run.stdout, cases_bytes(parsed, run.stdout)
        farm.write(NATIVE_STDOUT, stdout)
        farm.write(NATIVE_CASES, cases)
        rec = copy.deepcopy(record_doc)
        rec["checks"] = [{"check": m["id"], "state": "pass" if m["kind"] == "ok" else "fail",
                          "native": {"verdict": m["kind"], "reasons": m["findings"]}}
                         for m in parsed["members"]]
        counts: dict[str, int] = {}
        for m in parsed["members"]:
            counts[m["kind"]] = counts.get(m["kind"], 0) + 1
        nfail = counts.get("FAIL", 0)
        rec["aggregate"] = {"line": parsed["summary"], "total": len(parsed["members"]),
                            "counts": counts}
        rec["exit-code"] = run.code
        rec["native"]["process-status"]["exit-code"] = run.code
        rec["state"] = "pass" if nfail == 0 else "fail"
        rec["refusals"] = [{"check": c["check"], "rule": "as in the record",
                            "inputs": [f"check:{c['check']}"]}
                           for c in rec["checks"] if c["state"] == "fail"]
        for o in rec["observations"]:
            if o["id"] == "native-stdout":
                o["reference"]["sha256"] = sha(stdout)
            if o["id"] == "native-cases":
                o["reference"]["sha256"] = sha(cases)
            if o["id"] == "exit-code":
                o["carried"] = str(run.code)
        manifest = json.loads(generated[MANIFEST])
        manifest["member-file"]["sha256"] = sha(new)
        manifest["corpusDigest"] = listing(
            [(MEMBER, sha(new))] + [(a["path"], a["sha256"]) for a in manifest["artifacts"]])
        mbytes = render(manifest)
        farm.write(MANIFEST, mbytes)
        farm.write(ANCHOR_LIST, anchor_list_bytes(manifest["corpusDigest"]))
        for m in rec["members"]:
            m["files"][0]["sha256"] = sha(new)
        rec["manifest"]["sha256"] = sha(mbytes)
        rec["anchor"]["sha256"] = manifest["corpusDigest"]
        rec["corpus-digest"]["sha256"] = listing(
            [(MEMBER, sha(new))] * len(rec["members"])
            + [(a["path"], a["sha256"]) for a in rec["artifacts"]] + [(MANIFEST, sha(mbytes))])
        found = readers.w3cintake.rejections(rec, str(farm.root))
    finally:
        farm.close()
    return (f"- population: {label}, checker re-run (exit {run.code}, "
            f"{len(parsed['members'])} check lines), pins moved, manifest ids as declared: "
            f"{'refused under ' + ', '.join(found) if found else 'admitted'}")


def sweep_log(readers: Readers, record_doc: dict[str, Any], fresh: bytes,
              generated: dict[str, bytes]) -> bytes:
    """Every single-field edit of RECORD.json: does ``check`` refuse it, and does the
    intake reader (C1 with the root)? The first is byte equality with a fresh build; the
    second is what the intake reader reads."""
    edits: list[tuple[str, Any]] = []

    def walk(value: Any, path: list[Any]) -> None:
        if isinstance(value, dict):
            edits.append(("insert " + _ptr(path), (path, "insert")))
            for k in value:
                edits.append(("delete " + _ptr(path + [k]), (path + [k], "delete")))
                walk(value[k], path + [k])
        elif isinstance(value, list):
            for i, v in enumerate(value):
                edits.append(("delete " + _ptr(path + [i]), (path + [i], "delete")))
                walk(v, path + [i])
        else:
            edits.append(("edit " + _ptr(path), (path, "edit")))

    walk(record_doc, [])
    farm = Farm(generated)
    check_refused = c1_refused = 0
    c1_admitted: list[str] = []
    try:
        for label, (path, op) in edits:
            doc = copy.deepcopy(record_doc)
            _apply(doc, path, op)
            if render(doc) != fresh:
                check_refused += 1
            if readers.w3cintake.rejections(doc, str(farm.root)):
                c1_refused += 1
            else:
                c1_admitted.append(label)
    finally:
        farm.close()
    by_top: dict[str, int] = {}
    for label in c1_admitted:
        op, _, where = label.partition(" ")
        top = where.split("/")[1] if where.count("/") >= 1 and where != "/" else "(root)"
        key = f"{top}, {op}"
        by_top[key] = by_top.get(key, 0) + 1
    lines = [
        f"single-field edits of RECORD.json: {len(edits)} (every leaf edited, every key and "
        "list element deleted, a key inserted into every object)",
        f"refused by intake.py check (byte equality with a fresh build): {check_refused}",
        f"refused by the intake reader, C1 with the root: {c1_refused}",
        f"admitted by the intake reader: {len(c1_admitted)}, by top-level field and edit:",
        *[f"  {k}: {v}" for k, v in sorted(by_top.items())],
    ]
    return ("\n".join(lines) + "\n").encode()


def _ptr(path: list[Any]) -> str:
    return "/" + "/".join(str(p) for p in path)


def _apply(doc: Any, path: list[Any], op: str) -> None:
    if op == "insert":
        target = doc
        for p in path:
            target = target[p]
        target["sweep-inserted"] = True
        return
    parent = doc
    for p in path[:-1]:
        parent = parent[p]
    key = path[-1]
    if op == "delete":
        del parent[key]
        return
    value = parent[key]
    if isinstance(value, bool):
        parent[key] = not value
    elif isinstance(value, int):
        parent[key] = value + 1
    elif isinstance(value, str):
        parent[key] = value + "x"
    else:
        parent[key] = "x"


# --------------------------------------------------------------------------
# Command line.
# --------------------------------------------------------------------------


def build_all(args: argparse.Namespace, commit: str) -> dict[str, bytes]:
    readers = Readers(args)
    anchor_files = build_anchor()
    scratch = Path(tempfile.mkdtemp(prefix="tmd-intake-glue-"))
    try:
        record_doc, natives, _ = build_record(readers, commit, anchor_files, scratch)
        generated = {**anchor_files, **natives}
        refused_by(readers, record_doc, {**generated, HELPER: (REPO / HELPER).read_bytes()})
        record = record_bytes(record_doc)
        generated[RECORD] = record
        generated[RUN_C1] = c1_log(readers, generated)
        generated[RUN_CONTROLS] = controls_log(readers, record_doc, generated, commit)
        generated[RUN_SWEEP] = sweep_log(readers, record_doc, record, generated)
        return generated
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def json_diff(a: Any, b: Any, path: str = "") -> list[str]:
    if type(a) is not type(b):
        return [path or "/"]
    if isinstance(a, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}/{k}")
            else:
                out += json_diff(a[k], b[k], f"{path}/{k}")
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            return [path + " (length)"]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += json_diff(x, y, f"{path}/{i}")
        return out
    return [] if a == b else [path or "/"]


def compare(fresh: dict[str, bytes]) -> list[str]:
    problems = []
    for rel, body in sorted(fresh.items()):
        path = REPO / rel
        if not path.is_file():
            problems.append(f"{rel}: missing")
            continue
        disk = path.read_bytes()
        if disk == body:
            continue
        where = ""
        if rel.endswith(".json"):
            try:
                where = ", fields " + ", ".join(json_diff(json.loads(body),
                                                          json.loads(disk))[:20])
            except ValueError:
                where = ", not JSON"
        problems.append(f"{rel}: differs from a fresh build{where}")
    known = set(fresh) | {HELPER, OUT + "/README.md"}
    for p in sorted((REPO / OUT).rglob("*")):
        rel = p.relative_to(REPO).as_posix()
        if p.is_file() and "__pycache__" not in p.parts and rel not in known:
            problems.append(f"{rel}: a file this script does not write")
    return problems


def anchor_check(commit: str) -> int:
    record = json.loads((REPO / RECORD).read_bytes())
    want = f"{record['anchor']['sha256']}  {record['anchor']['manifest']}"
    exists = subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=str(REPO),
                            capture_output=True).returncode == 0
    if not exists:
        print(f"availability-failure: commit {commit} does not resolve here; fetch "
              f"{REPOSITORY} and retry (verdict: inconclusive)")
        return 2
    body = git_show(commit, ANCHOR_LIST)
    if body is None or want not in body.decode().split("\n"):
        print(f"integrity-failure: {ANCHOR_LIST} at {commit} carries no line '{want}' "
              "(verdict: fail)")
        return 1
    print(f"anchor verified: {ANCHOR_LIST} at {commit} carries '{want}'")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("action", choices=["anchor", "write", "check", "anchor-check"])
    parser.add_argument("--intake-reader", help="probityai/agent-evidence-vectors at 7e501506")
    parser.add_argument("--probity", help="probityai/agent-evidence-vectors at d759fb4")
    parser.add_argument("--heldfast", help="rufat325/heldfast at ca5a872")
    parser.add_argument("--python", default=sys.executable,
                        help="3.13+ with cryptography and rfc8785, for the outside readers")
    parser.add_argument("--anchor-commit", help="the commit that carries DIGESTS.txt")
    args = parser.parse_args()

    if args.action == "anchor-check":
        commit = args.anchor_commit or json.loads((REPO / RECORD).read_bytes())["anchor"][
            "git-commit"]
        return anchor_check(commit)
    if args.action == "anchor":
        for rel, body in build_anchor().items():
            (REPO / rel).parent.mkdir(parents=True, exist_ok=True)
            (REPO / rel).write_bytes(body)
            print(f"wrote {rel}")
        return 0
    for need in ("intake_reader", "probity", "heldfast"):
        if getattr(args, need) is None:
            parser.error(f"{args.action} needs --{need.replace('_', '-')}")
    if args.action == "write":
        if not args.anchor_commit:
            parser.error("write needs --anchor-commit")
        if git_show(args.anchor_commit, ANCHOR_LIST) != (REPO / ANCHOR_LIST).read_bytes():
            raise Refused(f"{ANCHOR_LIST} at {args.anchor_commit} is not the file on disk")
        fresh = build_all(args, args.anchor_commit)
        for rel, body in fresh.items():
            (REPO / rel).parent.mkdir(parents=True, exist_ok=True)
            (REPO / rel).write_bytes(body)
            print(f"wrote {rel}")
        return 0
    commit = args.anchor_commit or json.loads((REPO / RECORD).read_bytes())["anchor"][
        "git-commit"]
    fresh = build_all(args, commit)
    problems = compare(fresh)
    status = anchor_check(commit)
    if status != 0:
        problems.append("the anchor does not verify")
    for p in problems:
        print(f"REFUSE {p}")
    if problems:
        return 1
    print(f"check: {len(fresh)} files byte-identical to a fresh build; anchor verified")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    raise SystemExit(main())
