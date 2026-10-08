"""The OpenAI (ChatGPT / Codex) plugin package must stay submittable.

scripts/build_openai_plugin.py encodes OpenAI's documented submission limits. These
tests keep the committed package inside them and check that the validator really does
catch the mistakes that get an upload rejected.
"""
from __future__ import annotations

import json
import shutil
import zipfile

import pytest

from scripts.build_openai_plugin import PACKAGE, build, compare, validate


@pytest.fixture
def package(tmp_path):
    """A scratch copy of the real package that a test can break."""
    dest = tmp_path / "openai-plugin"
    shutil.copytree(PACKAGE, dest)
    return dest


def _edit_manifest(package, mutate):
    path = package / "plugin.json"
    manifest = json.loads(path.read_text())
    mutate(manifest)
    path.write_text(json.dumps(manifest))


def _iface(manifest):
    return manifest["extensions"]["com.openai"]["interface"]


def test_committed_package_is_valid():
    assert validate() == []


def test_package_points_at_the_production_mcp_server():
    servers = json.loads((PACKAGE / "mcp.json").read_text())["mcpServers"]
    assert [s["url"] for s in servers.values()] == ["https://agentavow.com/mcp"]


def test_skill_only_names_tools_the_server_exposes():
    from src.bridges.mcp_streamable import _TOOLS

    text = (PACKAGE / "skills" / "scan-before-connect" / "SKILL.md").read_text()
    for tool in ("scan_repo", "scan_package", "scan_mcp_server"):
        assert f"`{tool}`" in text
    assert {"scan_repo", "scan_package", "scan_mcp_server"} <= {t.name for t in _TOOLS}


def test_zip_has_the_manifest_at_the_root_and_nothing_extra(package, tmp_path):
    (package / "README.md").write_text("not part of the upload")
    out = build(package, tmp_path / "dist")
    names = set(zipfile.ZipFile(out).namelist())
    assert {"plugin.json", "mcp.json", "assets/logo.png",
            "skills/scan-before-connect/SKILL.md",
            "skills/scan-before-connect/agents/openai.yaml"} == names


@pytest.mark.parametrize("mutate,expect", [
    (lambda m: _iface(m).update(shortDescription="x" * 31), "shortDescription"),
    (lambda m: _iface(m).update(displayName="two\nlines"), "displayName"),
    (lambda m: _iface(m).update(category="Trust"), "category"),
    (lambda m: _iface(m).update(capabilities=["x" * 121]), "capabilities"),
    (lambda m: _iface(m).update(privacyPolicyURL="http://agentavow.com/p"), "privacyPolicyURL"),
    (lambda m: _iface(m).update(defaultPrompt=["a", "b", "c", "d"]), "defaultPrompt"),
    (lambda m: _iface(m).update(defaultPrompt=["Scan  chalk", "scan chalk"]), "unique"),
    (lambda m: _iface(m).update(defaultPrompt=["@AgentAvow scan chalk"]), "@mention"),
    (lambda m: _iface(m).update(logo="assets/logo.png"), "interface.logo"),
    (lambda m: _iface(m).update(logo="./assets/missing.png"), "interface.logo"),
    (lambda m: _iface(m).update(screenshots=["./assets/logo.png"]), "screenshots"),
    (lambda m: m.update(version="1.1"), "version"),
    (lambda m: m.update(name="Agent Avow"), "name"),
    (lambda m: m["extensions"]["com.openai"].update(hooks="./hooks/hooks.json"), "hooks"),
    (lambda m: m["extensions"]["com.openai"].update(
        review={"test_credentials": "x"}), "test_credentials"),
    (lambda m: m["extensions"]["com.openai"].update(
        review={"test_cases": {"positive": [], "negative": []}}), "5 positive"),
    (lambda m: m["extensions"]["com.openai"].update(
        onboardingSkill="./skills/nope/SKILL.md"), "onboardingSkill"),
])
def test_validator_catches_submission_blockers(package, mutate, expect):
    _edit_manifest(package, mutate)
    assert any(expect in e for e in validate(package)), validate(package)


def test_validator_catches_a_broken_skill(package):
    skill = package / "skills" / "scan-before-connect" / "SKILL.md"
    skill.write_text("no front matter here")
    assert any("front matter" in e for e in validate(package))
    skill.write_text("---\nname: scan-before-connect\ndescription: d\n---\nAsk Claude to scan.")
    assert any("provider-neutral" in e for e in validate(package))


def test_validator_catches_a_skill_identity_that_is_too_long(package):
    _edit_manifest(package, lambda m: m.update(name="a" * 60))
    assert any("longer than 64" in e for e in validate(package))


def test_validator_requires_exactly_one_https_mcp_server(package):
    (package / "mcp.json").write_text(json.dumps({
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {"agentavow": {"type": "http", "url": "http://agentavow.com/mcp"}},
    }))
    errors = validate(package)
    assert any("streamable-http" in e for e in errors)
    assert any("https" in e for e in errors)


def _release_zip(tmp_path, manifest, mcp):
    path = tmp_path / "release.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(".codex-plugin/plugin.json", json.dumps(manifest))
        zf.writestr(".mcp.json", json.dumps(mcp))
    return path


def test_compare_flags_what_an_update_must_not_change(tmp_path):
    ours = json.loads((PACKAGE / "plugin.json").read_text())
    release = _release_zip(
        tmp_path,
        {"name": "some-other-name", "version": ours["version"],
         "interface": {"displayName": "AgentAvow", "category": "Security"}},
        {"mcpServers": {"AgentAvow": {"url": "https://agentavow.com/mcp"}}},
    )
    diffs = compare(release)
    assert sum(d.startswith("MUST FIX") for d in diffs) == 3  # name, version, server name
    assert any(d.startswith("listing category") for d in diffs)


def test_compare_is_quiet_about_must_fix_when_identity_matches(tmp_path):
    ours = json.loads((PACKAGE / "plugin.json").read_text())
    release = _release_zip(
        tmp_path,
        {"name": ours["name"], "version": "1.0.1", "interface": _iface(ours)},
        {"mcpServers": {"agentavow": {"url": "https://agentavow.com/mcp"}}},
    )
    assert not [d for d in compare(release) if d.startswith("MUST FIX")]
