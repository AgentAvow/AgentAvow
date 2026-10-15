"""Emit v0.1 reports for runs of the tool-manifest-digest v1 vectors.

The reporting format is v0.1 of the W3C Agent Conformance and Benchmarking
Community Group (public-agent-conformance, 2026Sep/0087). This script runs each
implementation we can re-run from pinned sources over the v1 vector file, and
writes one v0.1 report per implementation: one producer per implementation, one
per-check record per check that implementation makes, the checker revision and
configuration it ran under, and a control built to fail run under the same
checker and configuration (section 5.4).

    python3 emit.py --runner "<name>" --runner-wrote vectors,native --out records

Implementations:

- native: ``verify.mjs`` in the parent directory, run with Node.
- probity: Probity's ``map_reader`` at the commit in ``compat/probity-pin.json``,
  driven by ``compat/probity_compat.py`` (needs Python 3.13+ with the pinned
  ``cryptography`` and ``rfc8785``; pass that interpreter as ``--python``).
- heldfast: heldfast's ``profiles.py`` at the commit in
  ``compat/heldfast-pin.json``, driven by ``compat/heldfast_compat.py``
  (stdlib only).

Checkouts of the two pinned repositories are cloned into ``--work`` when they are
not there yet; that clone is the only network access. Every run after that is
offline. The script refuses to write anything if a checkout is not at its pinned
commit or has local changes, if a reader refuses an input, or if a control does
not fail exactly the one check it was built to fail.

Determinism: every output is a function of the inputs, the pinned checkouts,
``--runner`` and ``--runner-wrote``, and the interpreter and library versions.
No clock is read. ``--runner``, ``--runner-wrote`` and the environment (Node,
Python and library versions, operating system) are written to ``run.json`` and
nowhere else, so changing any of them changes ``run.json`` and ``SHA256SUMS``
and no report.

Python 3.9+ for this script, standard library only.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
V1_DIR = HERE.parent
COMPAT = V1_DIR / "compat"
VECTORS = V1_DIR / "tool-manifest-digest-v1-vectors.json"
REPO_PATH = "docs/standards/tool-manifest-digest-vectors-v1"

FORMAT = "public-agent-conformance/report/v0.1"
SPEC = "https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0087.html"
REFERENCE_READER = {
    "repository": "probityai/agent-evidence-vectors",
    "tag": "v0.18.1",
    "commit": "33d545104ff2f8c124cff465c96c013eeb809156",
    "module": "packaging/agent_evidence_vectors/w3creport.py",
}
SCOPE = (
    "byte agreement between this implementation's output and the expected values in the "
    "pinned v1 vector file, on those pinned inputs only. It says nothing about AgentAvow's "
    "safety grades, trust scores or answers, and nothing about any tool other than the one "
    "pinned server's three served definitions."
)
SAFE_INTEGER = 2**53

# --------------------------------------------------------------------------
# RFC 8785 (JCS) under the jcs-sha256 numeric profile: integers of magnitude
# below 2^53 only, no floats. Strings escape only the quotation mark, the
# backslash and U+0000 to U+001F, which is what json.dumps does with
# ensure_ascii=False; member names sort by UTF-16 code units.
# --------------------------------------------------------------------------


def jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) >= SAFE_INTEGER:
            raise ValueError(f"integer outside the jcs-sha256 profile: {value}")
        return str(value)
    if isinstance(value, float):
        raise ValueError(f"float has no jcs-sha256 form: {value!r}")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(jcs(k) + ":" + jcs(value[k]) for k in keys) + "}"
    raise ValueError(f"no JSON form for {type(value).__name__}")


def jcs_bytes(value: Any) -> bytes:
    return jcs(value).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def flat_root(checks: list[dict[str, Any]]) -> str:
    """The flat check-set root: SHA-256 over the concatenated raw SHA-256 of each leaf."""
    return sha(b"".join(hashlib.sha256(jcs_bytes(c)).digest() for c in checks))


def file_bytes(value: Any) -> bytes:
    """How every JSON output is written: sorted keys, two-space indent, UTF-8, final newline."""
    jcs(value)  # refuses floats and unsafe integers before anything is written
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


# --------------------------------------------------------------------------
# Pinned checkouts.
# --------------------------------------------------------------------------


def git(args: list[str], cwd: Path) -> str:
    out = subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)
    return out.stdout.strip()


def checkout(pin: dict[str, Any], path: Path | None, work: Path, name: str) -> Path:
    if path is None:
        path = work / name
        if not (path / ".git").is_dir():
            work.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "-q", f"https://github.com/{pin['repository']}", str(path)],
                check=True,
            )
        if git(["rev-parse", "HEAD"], path) != pin["commit"]:
            subprocess.run(["git", "fetch", "-q", "origin", pin["commit"]], cwd=str(path))
            subprocess.run(["git", "checkout", "-q", pin["commit"]], cwd=str(path), check=True)
    head = git(["rev-parse", "HEAD"], path)
    if head != pin["commit"]:
        sys.exit(f"{name} checkout {path} is at {head}, pinned commit is {pin['commit']}")
    if git(["status", "--porcelain", "--untracked-files=no"], path):
        sys.exit(f"{name} checkout {path} has local changes to tracked files")
    return path


# --------------------------------------------------------------------------
# Controls: inputs built to fail one declared check each. Each is the vector
# file with one stated change, and is written beside the reports.
# --------------------------------------------------------------------------


def _by_name(items: list[dict[str, Any]], name: str) -> int:
    for i, item in enumerate(items):
        if item.get("name") == name:
            return i
    raise KeyError(name)


def _control_key(doc: dict[str, Any]) -> tuple[str, Any, Any]:
    i = 1
    before = doc["key_encoding"][i]["key"]
    after = "tool:" + doc["key_encoding"][i]["name"]
    doc["key_encoding"][i]["key"] = after
    return f"/key_encoding/{i}/key", before, after


def _control_definition(doc: dict[str, Any]) -> tuple[str, Any, Any]:
    i = _by_name(doc["observed_tools"], "ask_wiki_question")
    before = doc["observed_tools"][i]["description"]
    after = before + " This sentence was added after the grade."
    doc["observed_tools"][i]["description"] = after
    return f"/observed_tools/{i}/description", before, after


def _control_case(doc: dict[str, Any]) -> tuple[str, Any, Any]:
    i = _by_name(doc["vectors"], "tool-drift")
    before = doc["vectors"][i]["expect"]["tool_digest_binds"]
    doc["vectors"][i]["expect"]["tool_digest_binds"] = True
    return f"/vectors/{i}/expect/tool_digest_binds", before, True


CONTROLS: list[dict[str, Any]] = [
    {
        "id": "control-key-encoding-01",
        "mutate": _control_key,
        "witness": "key-encoding/01",
        "why_must_fail": (
            "the expected key for the name a=b is written with = left literal, and the key "
            "rule percent-encodes = as %3D, so a correct encoder disagrees with it"
        ),
    },
    {
        "id": "control-definition-ask_wiki_question",
        "mutate": _control_definition,
        "witness": "definition-digest/tool:ask_wiki_question",
        "why_must_fail": (
            "the served definition of ask_wiki_question has a sentence appended to its "
            "description, so its digest no longer equals the signed one"
        ),
    },
    {
        "id": "control-case-tool-drift",
        "mutate": _control_case,
        "witness": "case/tool-drift/tool_digest_binds",
        "why_must_fail": (
            "the tool-drift case expects tool_digest_binds true, but the definition the gate "
            "names differs from the signed one, so a correct reader computes false"
        ),
    },
]


def build_controls(fixture: dict[str, Any]) -> dict[str, dict[str, Any]]:
    built = {}
    for control in CONTROLS:
        doc = copy.deepcopy(fixture)
        pointer, before, after = control["mutate"](doc)
        data = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        built[control["id"]] = {
            "bytes": data,
            "path": f"controls/{control['id']}.json",
            "change": {"field": pointer, "from": before, "to": after},
        }
    return built


# --------------------------------------------------------------------------
# Readers. Each returns {check id: (passed, annotations)} in a fixed order.
# A check passes when the implementation's output equals the expected value
# the vector file states for it.
# --------------------------------------------------------------------------

Results = dict  # check id -> {"pass": bool, "annotations": dict}

NATIVE_PROPERTIES = {
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
    "every negative fails exactly one axis": "property/negatives-fail-one-axis",
}
LINE = re.compile(r"^  (ok|FAIL)\s+(.*)$")


def run_native(vectors: Path, fixture: dict[str, Any], node: str, scratch: Path) -> Results:
    proc = subprocess.run(
        [node, str(V1_DIR / "verify.mjs"), str(vectors)], capture_output=True, text=True
    )
    if proc.returncode not in (0, 1) or proc.stderr.strip():
        sys.exit(f"verify.mjs did not run to completion on {vectors.name}:\n{proc.stderr}")
    signed = fixture["attestation"]["toolDigests"]
    pairs = fixture["key_encoding"]
    expect = {v["name"]: v["expect"] for v in fixture["vectors"]}
    section = ""
    pair_index = 0
    results: Results = {}
    for raw in proc.stdout.splitlines():
        if raw and not raw.startswith(" "):
            section = raw
            continue
        m = LINE.match(raw)
        if not m:
            continue
        ok, label = m.group(1) == "ok", m.group(2)
        if section.startswith("per-tool digests"):
            if label.startswith("tool:"):
                cid, note = f"definition-digest/{label}", {"expected": signed.get(label)}
            elif label == "served tool count equals signed tool count":
                cid, note = "definition-count", {"expected": len(signed)}
            elif label == "unsigned toolDigests map equals the signed scan.toolDigests":
                cid, note = "unsigned-map-equals-signed", {"expected": True}
            else:
                sys.exit(f"verify.mjs printed a check this emitter does not know: {label!r}")
        elif section == "key encoding":
            if label == "key_encoding pair count":
                cid, note = "key-encoding-count", {"expected": 13}
            else:
                pair = pairs[pair_index]
                if not label.endswith(" -> " + pair["key"]):
                    sys.exit(f"verify.mjs key line out of order: {label!r}")
                cid = f"key-encoding/{pair_index:02d}"
                note = {"name": pair["name"], "expected": pair["key"]}
                pair_index += 1
        elif section == "vectors":
            name, _, axis = label.partition(": ")
            cid, note = f"case/{name}/{axis}", {"expected": expect[name][axis]}
        elif section == "properties under test":
            if label not in NATIVE_PROPERTIES:
                sys.exit(f"verify.mjs printed a property this emitter does not know: {label!r}")
            cid, note = NATIVE_PROPERTIES[label], {"expected": True}
        else:
            sys.exit(f"verify.mjs printed a check outside a known section: {raw!r}")
        if cid in results:
            sys.exit(f"verify.mjs printed {cid} twice")
        if ok:
            note["observed"] = note["expected"]
        note["reader-line"] = raw.strip()
        results[cid] = {"pass": ok, "annotations": note}
    if pair_index != len(pairs):
        sys.exit(f"verify.mjs printed {pair_index} key pairs, the file has {len(pairs)}")
    return results


def _python_glue(script: str, flag: str, checkout_dir: Path, vectors: Path, python: str,
                 scratch: Path) -> dict[str, Any]:
    out = scratch / f"{script}-{vectors.stem}.json"
    proc = subprocess.run(
        [python, str(COMPAT / script), flag, str(checkout_dir), "--vectors", str(vectors),
         "--out", str(out)],
        capture_output=True, text=True,
    )
    if not out.exists():
        sys.exit(f"{script} wrote no report for {vectors.name}:\n{proc.stdout}{proc.stderr}")
    report = json.loads(out.read_text(encoding="utf-8"))
    if "refusal" in report:
        sys.exit(f"{script} refused {vectors.name}: {report['refusal']}")
    return report


def run_probity(vectors: Path, fixture: dict[str, Any], python: str, checkout_dir: Path,
                scratch: Path) -> Results:
    report = _python_glue("probity_compat.py", "--probity", checkout_dir, vectors, python, scratch)
    results: Results = {}
    for d in report["definitions"]:
        results[f"definition-digest/{d['key']}"] = {
            "pass": d["matches"], "annotations": {"expected": d["signed"], "observed": d["probity"]}
        }
    results["definition-count"] = {
        "pass": report["definition_count_matches"],
        "annotations": {"expected": len(fixture["attestation"]["toolDigests"]),
                        "observed": len(report["definitions"])},
    }
    results["payload-digest"] = {
        "pass": report["payload_digest_matches"],
        "annotations": {"expected": fixture["attestation"]["payload_sha256"],
                        "observed": report["payload_sha256"]},
    }
    for i, k in enumerate(report["key_pairs"]):
        results[f"key-encoding/{i:02d}"] = {
            "pass": k["matches"],
            "annotations": {"name": k["name"], "expected": k["key"], "observed": k["probity"]},
        }
    expect = {v["name"]: v["expect"] for v in fixture["vectors"]}
    for r in report["results"]:
        for axis, want in expect[r["name"]].items():
            got = r["axes"].get(axis)
            results[f"case/{r['name']}/{axis}"] = {
                "pass": got == want, "annotations": {"expected": want, "observed": got}
            }
    return results


def run_heldfast(vectors: Path, fixture: dict[str, Any], python: str, checkout_dir: Path,
                 scratch: Path) -> Results:
    report = _python_glue("heldfast_compat.py", "--heldfast", checkout_dir, vectors, python,
                          scratch)
    results: Results = {}
    for d in report["definitions"]:
        results[f"definition-digest/{d['key']}"] = {
            "pass": d["matches"],
            "annotations": {"expected": d["signed"], "observed": d["heldfast"]},
        }
    for i, k in enumerate(report["key_pairs"]):
        results[f"key-encoding/{i:02d}"] = {
            "pass": k["matches"],
            "annotations": {"name": k["name"], "expected": k["key"], "observed": k["heldfast"]},
        }
    return results


# --------------------------------------------------------------------------
# What each implementation is, and what each one says it establishes.
# --------------------------------------------------------------------------


def implementations(probity_pin: dict[str, Any], heldfast_pin: dict[str, Any],
                    fixture: dict[str, Any]) -> list[dict[str, Any]]:
    probity_url = (
        f"https://github.com/{probity_pin['repository']}/tree/{probity_pin['commit']}/"
        f"{probity_pin['reader_dir']}"
    )
    heldfast_url = (
        f"https://github.com/{heldfast_pin['repository']}/blob/{heldfast_pin['commit']}/"
        f"{heldfast_pin['module']}"
    )
    return [
        {
            "id": "native-verify-mjs",
            "name": "verify.mjs (AgentAvow native verifier)",
            "author": "AgentAvow",
            "relationship": "same implementation as the vector producer",
            "wrote_key": "native",
            "checker": (
                f"AgentAvow/AgentAvow {REPO_PATH}/verify.mjs@sha256:"
                f"{sha((V1_DIR / 'verify.mjs').read_bytes())}, time.mjs@sha256:"
                f"{sha((V1_DIR / 'time.mjs').read_bytes())}"
            ),
            "files": ["verify.mjs", "time.mjs"],
            "claim_ceiling": {
                "stated_by": "AgentAvow, in the vector file's claim_ceiling field",
                "text": fixture["claim_ceiling"],
            },
            "controls": [c["id"] for c in CONTROLS],
        },
        {
            "id": "probity-map-reader",
            "name": "Probity signed-map reader (map_reader.py)",
            "author": "Probity (probityai)",
            "relationship": "implementation written from the specification",
            "wrote_key": "probity",
            "checker": (
                f"{probity_pin['repository']}@{probity_pin['commit']}/"
                f"{probity_pin['reader_dir']}/map_reader.py"
            ),
            "source": probity_url,
            "files": ["compat/probity_compat.py", "compat/probity-pin.json"],
            "key_source": "Probity's selection.json at the pinned commit, not the key in the "
                          "vector file",
            "claim_ceiling": {
                "stated_by": "Probity, in the reader README at the pinned commit",
                "source": probity_url + "/README.md",
                "text": (
                    "The emitted pin is a static-definition input, not invocation "
                    "authorization, a runtime result or independent custody. The 64-bit "
                    "suffix does not prove injectivity of truncated keys. This remains a "
                    "candidate consumer extraction policy, not AgentAvow or APS adoption."
                ),
            },
            "controls": [c["id"] for c in CONTROLS],
        },
        {
            "id": "heldfast-profiles",
            "name": "heldfast agentavow.mcp-tool-definition.v1 profile (profiles.py)",
            "author": "heldfast (rufat325)",
            "relationship": "implementation written from the specification",
            "wrote_key": "heldfast",
            "checker": (
                f"{heldfast_pin['repository']}@{heldfast_pin['commit']}/{heldfast_pin['module']}"
            ),
            "source": heldfast_url,
            "files": ["compat/heldfast_compat.py", "compat/heldfast-pin.json"],
            "claim_ceiling": {
                "stated_by": "heldfast, in the profiles.py docstring at the pinned commit",
                "source": heldfast_url,
                "text": (
                    "heldfast reproduces the digests and key encoding. It makes no claim "
                    "about anything AgentAvow does with them."
                ),
            },
            "scope_note": "heldfast's claim covers the three served-definition digests and the "
                          "thirteen key pairs only; no other check is asked of it.",
            "controls": ["control-key-encoding-01", "control-definition-ask_wiki_question"],
        },
    ]


NOT_EMITTED = [
    {
        "implementation": "APS-side consumer (agent-passport-system 7.2.0 primitives, "
                          "examples/interop/agentavow)",
        "author": "APS (aeoess)",
        "status": "not emitted",
        "reason": (
            "No v1 run of this consumer has been reported. Its reported run is of the v0 "
            "vectors, and the v1 README lists it as awaiting a v1 report. There is no v1 "
            "result to record, and running its v0 example against the v1 file would not be "
            "its v1 run."
        ),
        "source": "https://github.com/aeoess/agent-passport-system/tree/"
                  "fd47f34cc36fce060d092fe1216aff3f89fb8d88/examples/interop/agentavow",
    },
]


# --------------------------------------------------------------------------
# The report.
# --------------------------------------------------------------------------


def make_report(impl: dict[str, Any], main: Results, control_runs: dict[str, Results],
                config_ref: str, domain: dict[str, Any], vectors_sha: str,
                controls: dict[str, dict[str, Any]]) -> dict[str, Any]:
    fixed = {"checker": impl["checker"], "constraint-set": config_ref}
    checks: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    witnesses: list[str] = []
    by_witness = {c["witness"]: c for c in CONTROLS if c["id"] in impl["controls"]}
    for cid, result in main.items():
        record: dict[str, Any] = {
            "check": cid,
            "state": "pass" if result["pass"] else "fail",
            "annotations": result["annotations"],
        }
        control = by_witness.get(cid)
        if control is not None:
            ctl = controls[control["id"]]
            eid = f"e-{control['id']}"
            vectors_ref = f"{REPO_PATH}/tool-manifest-digest-v1-vectors.json"
            control_verdict = "pass" if control_runs[control["id"]][cid]["pass"] else "fail"
            evidence.append({
                "id": eid,
                "changed": "input artifact",
                "fixed": dict(fixed, domain=domain["id"]),
                "compared": ["verdict"],
                "moved": ["verdict"],
                "delta": {"changes": [ctl["change"]]},
                "observations": [
                    {"carried": {"verdict": record["state"], "rules": [],
                                 "input": {"ref": vectors_ref, "sha256": vectors_sha}}},
                    {"carried": {"verdict": control_verdict, "rules": [],
                                 "input": {"ref": ctl["path"], "sha256": sha(ctl["bytes"])}}},
                ],
            })
            record["other-verdict"] = {"value": "demonstrated", "ref": eid}
            record["discrimination"] = {"value": "demonstrated", "ref": eid}
            witnesses.append(cid)
        checks.append(record)
    n_pass = sum(1 for c in checks if c["state"] == "pass")
    n_fail = len(checks) - n_pass
    rollup = {
        "declared": len(checks), "exercised": len(checks),
        "pass": n_pass, "fail": n_fail, "inconclusive": 0, "not-exercised": 0, "void": 0,
        "carried": 2 * len(evidence), "referenced": 0,
        "negative-capable": {
            "kind": "control-failed",
            "control": {
                "checks": witnesses,
                "state": "fail",
                "fixed": dict(fixed),
                "fixtures": [f"{c}/{impl['id']}" for c in impl["controls"]],
            },
        },
        "completeness": {
            "accounting": {"population": len(checks), "claim": "satisfied"},
            "execution": {"population": len(checks), "claim": "satisfied"},
            "evidence": {"population": n_pass + n_fail, "claim": "not-satisfied"},
            "no-void": {"population": len(checks), "claim": "satisfied"},
        },
    }
    return {
        "format": FORMAT,
        "spec": SPEC,
        "producer": {
            "implementation": impl["name"],
            "author": impl["author"],
            "relationship-to-vectors": impl["relationship"],
            **({"source": impl["source"]} if "source" in impl else {}),
        },
        "scope": SCOPE,
        "claim-ceiling": impl["claim_ceiling"],
        **({"scope-note": impl["scope_note"]} if "scope_note" in impl else {}),
        "fixed": fixed,
        "domain": domain,
        "checks": checks,
        "evidence": evidence,
        "roll-up": rollup,
        "check-set": {
            "sha256": flat_root(checks),
            "leaf-count": len(checks),
            "tree-shape": "flat",
            "digest-encoding": "jcs-sha256",
        },
    }


def runner_label(impl: dict[str, Any], wrote: set[str]) -> str:
    if "vectors" in wrote:
        who = "run by the vector author"
    elif impl["wrote_key"] in wrote:
        who = "run by the implementation author"
    else:
        return f"{impl['relationship']}, run by a party that wrote neither the vectors nor " \
               "the implementation (an independent run)"
    return f"{impl['relationship']}, {who}"


def tool_version(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def environment(node: str, python: str) -> dict[str, Any]:
    probe = (
        "import json, platform, importlib.metadata as m\n"
        "v = {}\n"
        "for p in ('cryptography', 'rfc8785'):\n"
        "    try: v[p] = m.version(p)\n"
        "    except m.PackageNotFoundError: v[p] = 'not installed'\n"
        "print(json.dumps({'python': platform.python_version(), 'packages': v}))\n"
    )
    reader = tool_version([python, "-c", probe])
    try:
        reader_env = json.loads(reader)
    except ValueError:
        reader_env = {"python": "unknown", "packages": {}}
    return {
        "node": tool_version([node, "--version"]),
        "reader-python": reader_env["python"],
        "reader-packages": reader_env["packages"],
        "emitter-python": platform.python_version(),
        "os": f"{platform.system()} {platform.release()} {platform.machine()}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--runner", required=True,
                        help="who runs this; written to run.json and nowhere else")
    parser.add_argument("--runner-wrote", required=True,
                        help="comma list of what the runner authored: vectors, native, probity, "
                             "heldfast, or none; decides the run label in run.json")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    parser.add_argument("--work", type=Path,
                        default=Path(tempfile.gettempdir()) / "tmd-v1-w3c-v01-work",
                        help="where pinned checkouts are cloned and readers write scratch output")
    parser.add_argument("--probity", type=Path, help="existing checkout at the Probity pin")
    parser.add_argument("--heldfast", type=Path, help="existing checkout at the heldfast pin")
    parser.add_argument("--python", default=sys.executable,
                        help="interpreter for the Python readers (3.13+ with Probity's pins)")
    parser.add_argument("--node", default="node", help="Node 18+ for verify.mjs")
    args = parser.parse_args()

    wrote = {w.strip() for w in args.runner_wrote.split(",") if w.strip()}
    allowed = {"vectors", "native", "probity", "heldfast", "none"}
    if not wrote or not wrote <= allowed or ("none" in wrote and len(wrote) > 1):
        sys.exit(f"--runner-wrote takes a comma list from {sorted(allowed)}")
    wrote.discard("none")

    probity_pin = json.loads((COMPAT / "probity-pin.json").read_text(encoding="utf-8"))
    heldfast_pin = json.loads((COMPAT / "heldfast-pin.json").read_text(encoding="utf-8"))
    probity_dir = checkout(probity_pin, args.probity, args.work, "probity")
    heldfast_dir = checkout(heldfast_pin, args.heldfast, args.work, "heldfast")

    vectors_raw = VECTORS.read_bytes()
    vectors_sha = sha(vectors_raw)
    fixture = json.loads(vectors_raw.decode("utf-8"))
    controls = build_controls(fixture)
    domain = {
        "id": f"d-tmd-v1-{vectors_sha[:16]}",
        "description": (
            f"the tool-manifest-digest v1 vector file ({REPO_PATH}/"
            f"tool-manifest-digest-v1-vectors.json, sha256 {vectors_sha}), and the control "
            "inputs derived from it by the single changes listed in controls.json"
        ),
    }

    scratch = args.work / "scratch"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    for ctl in controls.values():
        p = scratch / ctl["path"]
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(ctl["bytes"])

    runners: dict[str, Callable[[Path, dict[str, Any]], Results]] = {
        "native-verify-mjs": lambda v, f: run_native(v, f, args.node, scratch),
        "probity-map-reader": lambda v, f: run_probity(v, f, args.python, probity_dir, scratch),
        "heldfast-profiles": lambda v, f: run_heldfast(v, f, args.python, heldfast_dir, scratch),
    }

    files: dict[str, bytes] = {}
    for cid, ctl in controls.items():
        files[ctl["path"]] = ctl["bytes"]
    fixtures_out: list[dict[str, Any]] = []
    impls = implementations(probity_pin, heldfast_pin, fixture)
    run_labels = {}
    summary = []
    for impl in impls:
        config = {
            "implementation": impl["name"],
            "checker": impl["checker"],
            "inputs": {
                "vectors": {"path": f"{REPO_PATH}/tool-manifest-digest-v1-vectors.json",
                            "sha256": vectors_sha},
            },
            "driver-files": {
                f"{REPO_PATH}/{name}": sha((V1_DIR / name).read_bytes())
                for name in [*impl["files"], "w3c-v01/emit.py"]
            },
            "controls": impl["controls"],
            "check-ids": (
                "definition-digest/<key>, definition-count, key-encoding/NN (index into the "
                "file's key_encoding), case/<vector>/<axis>, plus the implementation's own "
                "checks (native: unsigned-map-equals-signed, key-encoding-count, property/*; "
                "probity: payload-digest)"
            ),
            "pass-rule": "a check passes when the implementation's output equals the value the "
                         "vector file states for it; otherwise it fails",
        }
        if "key_source" in impl:
            config["key-source"] = impl["key_source"]
        config_bytes = file_bytes(config)
        config_path = f"configs/{impl['id']}.json"
        files[config_path] = config_bytes
        config_ref = f"{config_path}@sha256:{sha(config_bytes)}"

        main_results = runners[impl["id"]](VECTORS, fixture)
        control_runs: dict[str, Results] = {}
        for control in CONTROLS:
            if control["id"] not in impl["controls"]:
                continue
            ctl = controls[control["id"]]
            mutated = json.loads(ctl["bytes"].decode("utf-8"))
            got = runners[impl["id"]](scratch / ctl["path"], mutated)
            if set(got) != set(main_results):
                sys.exit(f"{impl['id']} ran a different check set on {control['id']}")
            flipped = sorted(c for c in got if got[c]["pass"] != main_results[c]["pass"])
            if flipped != [control["witness"]] or got[control["witness"]]["pass"]:
                sys.exit(f"{impl['id']}: {control['id']} flipped {flipped}, built to flip only "
                         f"{control['witness']} to fail; nothing written")
            if not main_results[control["witness"]]["pass"]:
                sys.exit(f"{impl['id']}: {control['witness']} does not pass on the pinned "
                         "vectors, so the control shows no change; nothing written")
            control_runs[control["id"]] = got
            fixtures_out.append({
                "fixture_id": f"{control['id']}/{impl['id']}",
                "target_check": {"check_id": control["witness"],
                                 "checker_revision": impl["checker"],
                                 "config_digest": sha(config_bytes)},
                "input": {"ref": ctl["path"], "sha256": sha(ctl["bytes"])},
                "derived_from": {
                    "ref": f"{REPO_PATH}/tool-manifest-digest-v1-vectors.json",
                    "sha256": vectors_sha,
                    "change": "{}: {} -> {}".format(
                        ctl["change"]["field"],
                        json.dumps(ctl["change"]["from"], ensure_ascii=False),
                        json.dumps(ctl["change"]["to"], ensure_ascii=False),
                    ),
                },
                "expected": {"state": "fail", "rule": control["witness"]},
                "why_must_fail": control["why_must_fail"],
                "observed": {"state": "fail", "flipped": flipped,
                             "unchanged_count": len(got) - len(flipped)},
                "provenance": {"author": "AgentAvow", "source": f"{REPO_PATH}/w3c-v01/emit.py",
                               "license": "Apache-2.0"},
            })

        report = make_report(impl, main_results, control_runs, config_ref, domain, vectors_sha,
                             controls)
        files[f"reports/{impl['id']}.json"] = file_bytes(report)
        run_labels[impl["id"]] = runner_label(impl, wrote)
        r = report["roll-up"]
        summary.append(f"{impl['id']}: {r['declared']} checks, {r['pass']} pass, {r['fail']} fail; "
                       f"controls {len(control_runs)}/{len(impl['controls'])} failed as built")

    files["controls.json"] = file_bytes(fixtures_out)
    files["not-emitted.json"] = file_bytes(NOT_EMITTED)
    files["run.json"] = file_bytes({
        "runner": args.runner,
        "runner-wrote": sorted(wrote) or ["none"],
        "run-labels": run_labels,
        "environment": environment(args.node, args.python),
        "command": "python3 emit.py --runner <runner> --runner-wrote <list> --out <dir> "
                   "--python <python3.13+>",
        "note": "the only file that carries the runner and the environment; no clock is read",
    })
    sums = "".join(f"{sha(files[p])}  {p}\n" for p in sorted(files)).encode("utf-8")
    files["SHA256SUMS"] = sums

    out = args.out
    if out.exists():
        stray = [p for p in out.rglob("*") if p.is_file()
                 and p.relative_to(out).as_posix() not in files]
        if stray:
            sys.exit(f"{out} holds files this script does not emit: "
                     f"{[p.relative_to(out).as_posix() for p in stray][:5]}")
    for rel, data in files.items():
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for line in summary:
        print(line)
    print(f"wrote {len(files)} files to {out}")
    print(f"sha256 of SHA256SUMS: {sha(sums)}")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    raise SystemExit(main())
