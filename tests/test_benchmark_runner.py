"""Pure helpers of the benchmark runner (scripts/benchmark/run.py); no dataset needed."""
from __future__ import annotations

import io
import tarfile
import zipfile

from scripts.benchmark.fetch import git_blob_sha
from scripts.benchmark.run import (
    _c_name_version,
    _ensure_skill_md,
    _strip_prefix,
    _targz,
    _zip_members,
    breakdown,
)


def test_c_name_version():
    assert _c_name_version("npm/malicious_intent/@tallyui@components/1.0.3/x.zip") == (
        "@tallyui/components", "1.0.3")
    assert _c_name_version("pypi/malicious_intent/0wneg/0.9.0/x.zip") == ("0wneg", "0.9.0")
    # Some samples have no version folder.
    assert _c_name_version("pypi/malicious_intent/2828/2022-11-16-2828.zip") == ("2828", "0")


def test_strip_prefix():
    files = {"tmp/a/x/SKILL.md": b"1", "tmp/a/x/scripts/run.sh": b"2"}
    assert _strip_prefix(files) == {"SKILL.md": b"1", "scripts/run.sh": b"2"}
    assert _strip_prefix({"SKILL.md": b"1", "a/b": b"2"}) == {"SKILL.md": b"1", "a/b": b"2"}
    assert _strip_prefix({}) == {}


def test_ensure_skill_md():
    files = {"skill.md": b"x", "run.py": b"y"}
    assert _ensure_skill_md(files) == (files, None)
    got, note = _ensure_skill_md({"prompt.txt": b"text"})
    assert got == {"SKILL.md": b"text"} and note
    files = {"a.md": b"", "b.md": b""}
    assert _ensure_skill_md(files) == (files, None)


def test_targz_round_trip():
    raw = _targz({"package/package.json": b"{}", "package/index.js": b"x"})
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        assert sorted(tf.getnames()) == ["package/index.js", "package/package.json"]


def test_zip_members_reads_in_memory_and_skips_dirs():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("pkg/", b"")
        zf.writestr("pkg/SKILL.md", b"hello")
    assert _zip_members(buf.getvalue()) == {"pkg/SKILL.md": b"hello"}


def test_git_blob_sha():
    # `git hash-object` of "hello\n".
    assert git_blob_sha(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_breakdown_by_list_field():
    rows = [{"truth": "malicious", "outcome": "review", "categories": ["a", "b"]},
            {"truth": "malicious", "outcome": "safe", "categories": ["a"]}]
    got = breakdown(rows, "categories")
    assert got["a"]["malicious"]["checked"] == 2
    assert got["b"]["malicious"]["checked"] == 1


def test_apply_osv():
    from scripts.benchmark.osv import apply_osv

    row = {"outcome": "safe"}
    assert apply_osv(row, True)["outcome_osv"] == "do_not_connect"
    assert apply_osv(row, False)["outcome_osv"] == "safe"
    assert apply_osv(row, None) == {"outcome": "safe", "osv": "unknown", "outcome_osv": "safe"}
    # A not-checked item stays not checked unless OSV itself names the version.
    assert apply_osv({"outcome": "not_checked"}, False)["outcome_osv"] == "not_checked"
