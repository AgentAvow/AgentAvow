"""Offline checks on the intake record for the tool-manifest-digest v1 vectors.

The record lives in docs/standards/tool-manifest-digest-vectors-v1/w3c-intake and
is written by intake.py beside it. ``intake.py check`` is the full verification
(it re-runs the outside readers and needs their pinned checkouts); these tests need
no network and no checkout. They check that every pin in the committed record
matches the bytes on disk, that the manifest and anchor list are what the anchor
stage writes now, and that a fresh run of the native verifier re-encodes to the
committed native files and per-check lines.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PKG = ROOT / "docs" / "standards" / "tool-manifest-digest-vectors-v1"
INTAKE = PKG / "w3c-intake"


def _load_intake():
    spec = importlib.util.spec_from_file_location("tmd_v1_w3c_intake", INTAKE / "intake.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


intake = _load_intake()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record() -> dict:
    return json.loads((INTAKE / "RECORD.json").read_bytes())


def _disk(rel: str) -> bytes:
    return (ROOT / rel).read_bytes()


def test_every_pin_in_the_record_matches_the_bytes_on_disk():
    record = _record()
    for member in record["members"]:
        for pin in member["files"]:
            assert _sha(_disk(pin["path"])) == pin["sha256"], pin["path"]
    assert _sha(_disk(record["manifest"]["path"])) == record["manifest"]["sha256"]
    for item in record["artifacts"]:
        assert _sha(_disk(item["path"])) == item["sha256"], item["path"]
    for obs in record["observations"]:
        if obs["carry"] == "referenced":
            ref = obs["reference"]
            assert _sha(_disk(ref["path"])) == ref["sha256"], ref["path"]
    revision = record["checker"]["revision"]
    assert intake.listing([(p, _sha(_disk(p))) for p in revision["paths"]]) == revision["sha256"]
    for helper in record["checker"]["helpers"]:
        assert _sha(_disk(helper["path"])) == helper["sha256"]


def test_corpus_digest_recomputes_from_the_record():
    record = _record()
    entries = [(f["path"], f["sha256"]) for m in record["members"] for f in m["files"]]
    entries += [(a["path"], a["sha256"]) for a in record["artifacts"]]
    entries.append((record["manifest"]["path"], record["manifest"]["sha256"]))
    assert intake.listing(entries) == record["corpus-digest"]["sha256"]


def test_manifest_and_anchor_list_are_what_the_anchor_stage_writes():
    if shutil.which("git") is None:
        pytest.skip("git is needed to list the package's tracked files")
    fresh = intake.build_anchor()
    for rel, body in fresh.items():
        assert _disk(rel) == body, rel
    manifest = json.loads(fresh[intake.MANIFEST])
    record = _record()
    assert record["anchor"]["sha256"] == manifest["corpusDigest"]
    assert record["manifest"]["ids"] == manifest["ids"]
    assert f"{manifest['corpusDigest']}  {intake.MANIFEST}" in fresh[intake.ANCHOR_LIST].decode()


def test_population_is_declared_from_the_vector_file_and_matches_the_v01_report():
    doc = json.loads(_disk(intake.MEMBER))
    ids = intake.declared_ids(doc)
    assert ids == _record()["manifest"]["ids"]
    assert len(ids) == len(set(ids)) == 76
    report = json.loads((PKG / "w3c-v01/records/reports/native-verify-mjs.json").read_bytes())
    assert {c["check"] for c in report["checks"]} == set(ids)


def test_a_fresh_native_run_re_encodes_to_the_committed_files():
    if shutil.which("node") is None:
        pytest.skip("node is not installed")
    run = intake.native_run(PKG)
    assert run.code == 0 and run.stderr == b""
    assert run.stdout == _disk(intake.NATIVE_STDOUT)
    doc = json.loads(_disk(intake.MEMBER))
    parsed = intake.parse_native(run.stdout, doc)
    assert intake.cases_bytes(parsed, run.stdout) == _disk(intake.NATIVE_CASES)
    carried = [(c["check"], c["native"]["verdict"], c["native"]["reasons"])
               for c in _record()["checks"]]
    assert carried == [(m["id"], m["kind"], m["findings"]) for m in parsed["members"]]


def test_the_parser_refuses_output_it_cannot_account_for():
    doc = json.loads(_disk(intake.MEMBER))
    stdout = _disk(intake.NATIVE_STDOUT)
    for bad in (
        stdout.replace(b"  ok    tool:ask_wiki_question", b"  ok    tool:unknown_line", 1)
        .replace(b"per-tool digests", b"some other section", 1),
        stdout.replace(b"all checks passed\n", b""),
        stdout + b"  stray indented line\n",
    ):
        with pytest.raises(SystemExit):
            intake.parse_native(bad, doc)


def test_a_fail_line_is_carried_with_its_want_and_got():
    doc = json.loads(_disk(intake.MEMBER))
    stdout = _disk(intake.NATIVE_STDOUT).replace(
        b"  ok    \"a=b\" -> tool:a%3Db\n",
        b"  FAIL  \"a=b\" -> tool:a%3Db\n        want tool:a%3Db\n        got  tool:a=b\n",
    ).replace(b"all checks passed\n", b"1 failure(s)\n")
    parsed = intake.parse_native(stdout, doc)
    failed = [m for m in parsed["members"] if m["kind"] == "FAIL"]
    assert [(m["id"], m["findings"]) for m in failed] == [
        ("key-encoding/01", ["want tool:a%3Db", "got  tool:a=b"])]
    assert intake.failures_printed(parsed["summary"]) == 1
