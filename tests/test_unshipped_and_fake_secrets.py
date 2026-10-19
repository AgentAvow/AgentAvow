"""DNC false-alarm sample 2026-10-19: the ``shipped`` tag and the blocking rule agree;
a PEM marker with no base64 body and a fake key in a test fixture are not credentials;
the weekly report dedupes PyPI spellings and names the finding that decided."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts.dnc_weekly_report import (
    dedupe_rows,
    parse_prev_keys,
    pick_top,
    remote_script,
    render_report,
    row_key,
)
from src.scanner.scan import (
    _NONSHIPPED_FINDING_WEIGHT,
    Finding,
    _finding_grade_weight,
    _finding_is_blocking,
    _scan_content,
    finding_is_shipped,
)
from src.scanner.service import stored_scan_decision_input
from src.scanner.verdict import decide, finding_decides


def _finding(path, severity="critical", **kw):
    return Finding(category=kw.pop("category", "dynamic_remote_load"),
                   name=kw.pop("name", "curl/wget piped to shell"), severity=severity,
                   file_path=path, line_number=1, snippet="", **kw)


# ── 1. shipped tag == blocking location rule ──────────────────────────────────────

@pytest.mark.parametrize("path", [
    "scripts/create-slack-app.sh",          # CorellisOrg/Corellis
    "skills/ix/scripts/bootstrap.sh",       # ix-infrastructure/Ix: a skill's scripts/
    "tooling/run.py", "sandbox/server.py", "playground/app.ts", "demo_server.py",
    "website/build.js", "release/sign.py",
])
def test_author_controlled_paths_are_shipped_and_block(path):
    """A path an author can move the entry point into is shipped: the page no longer
    says "not shipped" for a critical that blocks."""
    f = _finding(path)
    assert finding_is_shipped(f) is True
    assert _finding_is_blocking(f) is True
    # Score weight is unchanged by this fix (still the broad discount where it was).


@pytest.mark.parametrize("path", [
    "tests/test_x.py", "src/foo.test.ts", "pkg/foo_test.go", "docs/install.md",
    "examples/run.py", "benchmarks/b.py", "fixtures/k.py", ".github/scripts/ci.sh",
    "infra/release-runner/bootstrap.sh", "scripts/release.sh", "install.sh",
])
def test_non_runtime_paths_are_not_shipped_and_never_block(path):
    f = _finding(path)
    assert finding_is_shipped(f) is False
    assert _finding_is_blocking(f) is False


def test_tag_and_blocking_agree_on_flags():
    not_installed = _finding("pkg/run.py", installed=False)
    assert not finding_is_shipped(not_installed) and not _finding_is_blocking(not_installed)
    inline_test = _finding("src/lib.rs", test_code=True)
    assert not finding_is_shipped(inline_test) and not _finding_is_blocking(inline_test)
    payload = _finding("tests/helpers.py", payload=True)
    assert finding_is_shipped(payload) and _finding_is_blocking(payload)


def test_weight_discount_unchanged_for_scripts():
    """Only the tag moved: a scripts/ finding still weighs at the non-shipped fraction,
    so no score changes."""
    assert _finding_grade_weight(_finding("scripts/x.sh")) == _NONSHIPPED_FINDING_WEIGHT
    assert _finding_grade_weight(_finding("src/x.py")) == 1.0


def test_unshipped_item_never_decides_even_without_headline_counts():
    item = {"category": "dynamic_remote_load", "name": "curl/wget piped to shell",
            "severity": "critical", "file_path": "ci/build.sh", "shipped": False,
            "kind": "defect", "installed": True}
    assert not finding_decides(item)
    d = decide({"trust_score": 70, "findings": {"items": [item]},
                "metadata": {"files_scanned": 50}})
    assert d.decision == "safe"


def test_stored_rows_retag_old_scripts_tag():
    """A stored row written under the old tag (scripts/ said not-shipped) is read with
    today's rule, so the badge and the report agree."""
    row = {"trust_score": 40, "findings": [
        {"category": "dynamic_remote_load", "name": "curl/wget piped to shell",
         "severity": "critical", "file_path": "scripts/setup.sh", "shipped": False},
        {"category": "secret", "name": "Private Key block", "severity": "critical",
         "file_path": "tests/k.py", "shipped": False},
    ]}
    data = stored_scan_decision_input(row)
    tags = {i["file_path"]: i["shipped"] for i in data["findings"]["items"]}
    assert tags == {"scripts/setup.sh": True, "tests/k.py": False}
    assert decide(data).decision == "do_not_connect"
    # A stored test_code False on a runtime path (inline Rust test) is not flipped.
    row = {"trust_score": 80, "findings": [
        {"category": "secret", "name": "Private Key block", "severity": "critical",
         "file_path": "src/lib.rs", "shipped": False}]}
    data = stored_scan_decision_input(row)
    assert data["findings"]["items"][0]["shipped"] is False
    assert decide(data).decision != "do_not_connect"


def test_stored_row_without_tag_uses_installed():
    row = {"trust_score": 80, "findings": [
        {"category": "x", "name": "y", "severity": "critical", "file_path": "pkg/a.py",
         "installed": False}]}
    item = stored_scan_decision_input(row)["findings"]["items"][0]
    assert item["shipped"] is False


# ── 2a. PEM marker with no base64 body ────────────────────────────────────────────

def _secrets(content, path):
    findings, _, _ = _scan_content(content, path)
    return [(f.name, f.severity, f.kind) for f in findings if f.category == "secret"]


_BODY = ("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzmc7SPaB07+gK",
         "p/VETtmayzNASEaaGIEKO5eOrlrKfIMdmSyB38Ia4dCyxb8WKAROeBtaev8AXfKh",
         "Y3RhbXBsZTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0")


def test_i18n_placeholder_with_long_camelcase_keys_is_not_a_key():
    """t8y2/dbx: a UI placeholder string; >= 40-char camelCase i18n keys around it are
    identifiers, not base64 body lines."""
    keys = "\n".join(f'  elasticsearchConnectivityCheckPath{w}Placeholder: "x",'
                     for w in ("One", "Two", "Three", "Four", "Five"))
    src = ('export default {\n  pemPlaceholder: "-----BEGIN PRIVATE KEY-----",\n'
           + keys + "\n  elasticsearchConnectivityCheckPathPlaceholderDescription\n}\n")
    assert _secrets(src, "apps/desktop/src/i18n/locales/es.ts") == [
        ("Private Key block marker (no key body)", "info", "capability")]


def test_bare_identifier_lines_do_not_count_as_body():
    src = ("MARKER = '-----BEGIN PRIVATE KEY-----'\n"
           "someVeryLongIdentifierNameThatIsReallyQuiteLongIndeed\n"
           "anotherVeryLongIdentifierNameThatIsReallyQuiteLongToo\n"
           "yetAnotherVeryLongIdentifierNameThatIsReallyQuiteLong\n")
    assert _secrets(src, "src/k.py")[0][0] == "Private Key block marker (no key body)"


@pytest.mark.parametrize("src", [
    'KEY = """-----BEGIN PRIVATE KEY-----\n' + "\n".join(_BODY)
    + '\n-----END PRIVATE KEY-----"""\n',
    'const k = "-----BEGIN PRIVATE KEY-----\\n' + "\\n".join(_BODY)
    + '\\n-----END PRIVATE KEY-----\\n";\n',
    "const k = [\n  '-----BEGIN RSA PRIVATE KEY-----',\n"
    + "".join(f"  '{b}',\n" for b in _BODY) + "  '-----END RSA PRIVATE KEY-----',\n].join('\\n')\n",
    'k = ("-----BEGIN PRIVATE KEY-----\\n"\n' + "".join(f'     "{b}\\n"\n' for b in _BODY)
    + '     "-----END PRIVATE KEY-----")\n',
    "key: |\n  -----BEGIN OPENSSH PRIVATE KEY-----\n" + "".join(f"  {b}\n" for b in _BODY)
    + "  -----END OPENSSH PRIVATE KEY-----\n",
    'K="-----BEGIN PRIVATE KEY----- ' + " ".join(_BODY) + ' -----END PRIVATE KEY-----"\n',
])
def test_real_key_shapes_still_critical(src):
    assert ("Private Key block", "critical", "defect") in _secrets(src, "src/keys.py")


# ── 2b. fake keys in test fixtures ────────────────────────────────────────────────

_DIFY = "sk-ant-api11-IamNotARealKeyJustForMockTestKawaiiiiiiiiiiiiiiiiiiii"
_REAL_LOOKING = "sk-ant-api03-q8Zr2LxW9vKp4TnB7yHc1MdF6gJs3RaE0uXo5WiQ"


def test_dify_pytest_ini_fake_key_is_ignored():
    src = f"[pytest]\nenv =\n    ANTHROPIC_API_KEY={_DIFY}\n"
    assert _secrets(src, "api/pytest.ini") == []


@pytest.mark.parametrize("path", [
    "api/pytest.ini", "tox.ini", "setup.cfg", "tests/conftest.py", "conftest.py",
    "tests/unit/test_client.py", "src/client.test.ts", "fixtures/env.py",
    ".env.test", "jest.config.js",
])
def test_fake_marker_in_test_files_ignored(path):
    for val in ("sk-ant-FAKEKEY0123456789abcdefghijklmnopqrstuvwxyz",
                "sk-ant-dummy_0123456789abcdefghijklmnopqrstuvwxyzAB",
                "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"):
        assert _secrets(f"KEY = '{val}'\n", path) == [], (path, val)


def test_real_looking_key_in_test_file_still_fires():
    hits = _secrets(f"[pytest]\nenv =\n    ANTHROPIC_API_KEY={_REAL_LOOKING}\n",
                    "api/pytest.ini")
    assert hits == [("Anthropic API Key", "critical", "defect")]
    assert _secrets(f"KEY = '{_REAL_LOOKING}'\n", "tests/test_x.py")


def test_fake_marker_outside_test_files_still_fires():
    """``Mock`` / ``Test`` inside a value in runtime code is not evidence it is fake."""
    hits = _secrets(f"KEY = '{_DIFY}'\n", "src/config.py")
    assert hits == [("Anthropic API Key", "critical", "defect")]


# ── 3. weekly report ──────────────────────────────────────────────────────────────

def _row(full, scanned, surface="pypi", **kw):
    name = full.split(":", 1)[-1]
    return {"surface": surface, "full_name": full, "name": name, "version": "1",
            "score": 10, "reason": "r", "scanned_at": scanned, "top": None, **kw}


def test_pypi_names_are_pep503_normalized_and_deduped():
    rows = [_row("pypi:huggingface_hub", "2026-10-10T00:00:00+00:00", version="0.1"),
            _row("pypi:huggingface-hub", "2026-10-18T00:00:00+00:00", version="0.2"),
            _row("pypi:HuggingFace._Hub", "2026-10-01T00:00:00+00:00"),
            _row("npm:left_pad", "2026-10-01T00:00:00+00:00", surface="npm"),
            _row("npm:left-pad", "2026-10-01T00:00:00+00:00", surface="npm")]
    assert row_key(rows[0]) == row_key(rows[1]) == "pypi:pypi:huggingface-hub"
    out = dedupe_rows(rows)
    pypi = [r for r in out if r["surface"] == "pypi"]
    assert len(pypi) == 1 and pypi[0]["version"] == "0.2"
    assert pypi[0]["name"] == "huggingface-hub"
    assert len([r for r in out if r["surface"] == "npm"]) == 2  # npm names untouched


def test_prev_keys_normalized_so_old_spelling_is_not_new_or_gone():
    prev = parse_prev_keys('<!-- dnc-keys: {"pypi:pypi:huggingface_hub": "0.1", '
                           '"pypi:pypi:huggingface-hub": null} -->')
    assert prev == {"pypi:pypi:huggingface-hub": "0.1"}
    rows = dedupe_rows([_row("pypi:huggingface-hub", "2026-10-18T00:00:00+00:00",
                             version="0.1")])
    text = render_report(rows, prev, "2026-10-19", "t", "2026-10-12.md")
    assert "No longer Do not connect" not in text
    assert "(1, 0 new)" in text


def _item(sev, name, **kw):
    return {"category": kw.pop("category", "code_safety"), "name": name, "severity": sev,
            "file_path": kw.pop("file_path", "src/a.py"), "line_number": 1,
            "shipped": kw.pop("shipped", True), "kind": kw.pop("kind", "defect"),
            "installed": kw.pop("installed", True), **kw}


def test_pick_top_prefers_highest_severity_decider():
    items = [_item("high", "H"), _item("critical", "C"), _item("medium", "M")]
    assert pick_top(items, finding_decides)["name"] == "C"


def test_pick_top_falls_back_by_severity_not_first_item():
    """C0ntr0lledCha0s: the only critical was tagged not-shipped in a cached result, so
    no item 'decides'; the fallback names the critical, not items[0] (a medium)."""
    items = [_item("medium", "Unpinned npx/uvx package"),
             _item("critical", "curl/wget piped to shell", shipped=False),
             _item("critical", "Vulnerable dependency", category="dependency"),
             _item("high", "cap", kind="capability")]
    assert pick_top(items, finding_decides)["name"] == "curl/wget piped to shell"
    assert pick_top([], finding_decides) is None


def test_remote_script_carries_pick_top():
    script = remote_script()
    assert script.startswith("def pick_top(")
    compile(script, "<remote>", "exec")
    ns: dict = {}
    exec(script.split("\nimport asyncio")[0], ns)  # the helper alone runs standalone
    assert ns["pick_top"]([_item("low", "L")], lambda i: False)["name"] == "L"


def test_simple_namespace_shape_tolerated():
    assert finding_is_shipped(SimpleNamespace(file_path="src/a.py"))
