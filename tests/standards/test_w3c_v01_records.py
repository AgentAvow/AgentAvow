"""Checks on the committed v0.1 records for the tool-manifest-digest v1 vectors.

The records live in docs/standards/tool-manifest-digest-vectors-v1/w3c-v01/records
and are written by emit.py beside them. These tests need no network and no pinned
checkout: they check the committed bytes against themselves and against the
current inputs, so a change to the vectors, the verifier, the drivers or the
emitter that is not followed by a fresh emission fails here.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
V1 = ROOT / "docs" / "standards" / "tool-manifest-digest-vectors-v1"
W3C = V1 / "w3c-v01"
RECORDS = W3C / "records"
REPO_PATH = "docs/standards/tool-manifest-digest-vectors-v1"


def _load_emit():
    spec = importlib.util.spec_from_file_location("tmd_v1_w3c_emit", W3C / "emit.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


emit = _load_emit()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reports() -> dict[str, dict]:
    return {
        p.stem: json.loads(p.read_text(encoding="utf-8"))
        for p in sorted((RECORDS / "reports").glob("*.json"))
    }


def test_sha256sums_cover_every_file_and_match():
    lines = (RECORDS / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    listed = {}
    for line in lines:
        digest, _, rel = line.partition("  ")
        listed[rel] = digest
    on_disk = {
        p.relative_to(RECORDS).as_posix()
        for p in RECORDS.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS"
    }
    assert set(listed) == on_disk
    assert list(listed) == sorted(listed)
    for rel, digest in listed.items():
        assert _sha((RECORDS / rel).read_bytes()) == digest, rel


def test_one_report_per_reemittable_implementation():
    assert set(_reports()) == {"native-verify-mjs", "probity-map-reader", "heldfast-profiles"}


@pytest.mark.parametrize("name", ["native-verify-mjs", "probity-map-reader", "heldfast-profiles"])
def test_report_roll_up_and_check_set_recompute(name):
    report = _reports()[name]
    checks = report["checks"]
    assert report["format"] == "public-agent-conformance/report/v0.1"
    binding = report["check-set"]
    assert binding["tree-shape"] == "flat"
    assert binding["digest-encoding"] == "jcs-sha256"
    assert binding["leaf-count"] == len(checks)
    assert binding["sha256"] == emit.flat_root(checks)
    rollup = report["roll-up"]
    states = [c["state"] for c in checks]
    assert rollup["declared"] == len(checks)
    for state in ("pass", "fail", "inconclusive", "not-exercised", "void"):
        assert rollup[state] == states.count(state)
    assert rollup["carried"] == 2 * len(report["evidence"])
    assert rollup["referenced"] == 0
    control = rollup["negative-capable"]["control"]
    assert rollup["negative-capable"]["kind"] == "control-failed"
    assert control["state"] == "fail"
    assert control["fixed"] == report["fixed"]
    ids = {c["check"] for c in checks}
    assert control["checks"] and set(control["checks"]) <= ids
    assert len(ids) == len(checks)


def test_heldfast_is_asked_only_what_it_claims():
    checks = [c["check"] for c in _reports()["heldfast-profiles"]["checks"]]
    assert sum(c.startswith("definition-digest/") for c in checks) == 3
    assert sum(c.startswith("key-encoding/") for c in checks) == 13
    assert len(checks) == 16


def test_runner_and_environment_live_only_in_run_json():
    run = json.loads((RECORDS / "run.json").read_text(encoding="utf-8"))
    runner = run["runner"]
    for p in RECORDS.rglob("*"):
        if p.is_file() and p.name not in ("run.json", "SHA256SUMS"):
            text = p.read_text(encoding="utf-8")
            assert runner not in text, p
            assert run["environment"]["node"] not in text, p


def test_records_are_not_stale():
    vectors = (V1 / "tool-manifest-digest-v1-vectors.json").read_bytes()
    for config_path in sorted((RECORDS / "configs").glob("*.json")):
        config = json.loads(config_path.read_text(encoding="utf-8"))
        assert config["inputs"]["vectors"]["sha256"] == _sha(vectors)
        for rel, digest in config["driver-files"].items():
            local = ROOT / rel
            assert _sha(local.read_bytes()) == digest, f"{rel} changed; re-run emit.py"
    for name, report in _reports().items():
        config_rel, _, digest = report["fixed"]["constraint-set"].partition("@sha256:")
        assert _sha((RECORDS / config_rel).read_bytes()) == digest, name


def test_control_inputs_are_the_stated_single_changes():
    fixture = json.loads((V1 / "tool-manifest-digest-v1-vectors.json").read_text(encoding="utf-8"))
    built = emit.build_controls(fixture)
    for ctl in built.values():
        assert (RECORDS / ctl["path"]).read_bytes() == ctl["bytes"]
    fixtures = json.loads((RECORDS / "controls.json").read_text(encoding="utf-8"))
    for record in fixtures:
        assert record["expected"]["state"] == "fail"
        assert record["observed"]["state"] == "fail"
        assert record["observed"]["flipped"] == [record["target_check"]["check_id"]]
        assert _sha((RECORDS / record["input"]["ref"]).read_bytes()) == record["input"]["sha256"]


def test_aps_consumer_is_recorded_as_not_emitted():
    entries = json.loads((RECORDS / "not-emitted.json").read_text(encoding="utf-8"))
    aps = [e for e in entries if e["implementation"].startswith("APS-side consumer")]
    assert len(aps) == 1 and aps[0]["status"] == "not emitted"


def test_jcs_profile():
    # Member names sort by UTF-16 code units: U+1F600 (lead surrogate D83D) before U+FB33.
    assert emit.jcs({"דּ": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"דּ":1}'
    # U+007F and non-ASCII are written as themselves; controls use short or \u00xx forms.
    assert emit.jcs("\x7fé\t\x01") == '"\x7fé\\t\\u0001"'
    assert emit.jcs([True, False, None, 0, -(2**53 - 1)]) == "[true,false,null,0,-9007199254740991]"
    with pytest.raises(ValueError):
        emit.jcs(2**53)
    with pytest.raises(ValueError):
        emit.jcs(0.5)
