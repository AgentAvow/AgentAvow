#!/usr/bin/env python3
"""Validate and zip the OpenAI (ChatGPT / Codex) plugin package.

The package lives in integrations/openai-plugin/ in the portable Agent Plugins layout:
root plugin.json, mcp.json, skills/, assets/. OpenAI's portal takes it as a ZIP. The
checks here are the documented submission limits, so a mistake shows up locally instead
of after an upload (https://developers.openai.com/plugins/deploy/submission-errors).

Usage:
    python3 scripts/build_openai_plugin.py                 # validate, write dist/*.zip
    python3 scripts/build_openai_plugin.py --check         # validate only
    python3 scripts/build_openai_plugin.py --compare release.zip
        # diff the package against the release ZIP downloaded from the portal; the
        # package name and the MCP server entry must match it on an update
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "integrations" / "openai-plugin"
DIST = ROOT / "dist"

# Only these ship. Anything else in the folder (a README, notes) stays out of the ZIP.
_SHIPPED = ("plugin.json", "mcp.json", "skills", "assets")

_PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
_MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
_CATEGORIES = {
    "Productivity", "Creativity", "Developer Tools", "Business & Operations",
    "Data & Analytics", "Communication", "Education & Research", "Security", "Finance",
    "Healthcare", "Travel", "Entertainment", "Other",
}
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_URL_FIELDS = ("websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL")
_MAX_IMAGE_BYTES = 5 * 1024 * 1024


def _one_line(s: object, limit: int) -> bool:
    return isinstance(s, str) and bool(s.strip()) and "\n" not in s and len(s) <= limit


def _frontmatter(text: str) -> tuple[dict[str, str], str] | None:
    """Parse a SKILL.md header of plain `key: value` lines. None when it has no header."""
    if not text.startswith("---\n"):
        return None
    head, sep, body = text[4:].partition("\n---\n")
    if not sep:
        return None
    fields = {}
    for line in head.splitlines():
        key, colon, value = line.partition(":")
        if colon:
            fields[key.strip()] = value.strip().strip("\"'")
    return fields, body


def _image_size(path: Path) -> tuple[int, int]:
    from PIL import Image

    with Image.open(path) as im:
        return im.size


def _asset(package: Path, field: str, value: object, errors: list[str]) -> Path | None:
    if not isinstance(value, str) or not value.startswith("./"):
        errors.append(f"{field}: must be a path starting with './'")
        return None
    path = (package / value).resolve()
    if package.resolve() not in path.parents or not path.is_file():
        errors.append(f"{field}: {value} is not a file inside the package")
        return None
    if path.stat().st_size > _MAX_IMAGE_BYTES:
        errors.append(f"{field}: {value} is larger than 5 MiB")
    return path


def _check_interface(package: Path, iface: dict, errors: list[str]) -> None:
    for field, limit in (("displayName", 30), ("shortDescription", 30), ("developerName", 80)):
        if not _one_line(iface.get(field), limit):
            errors.append(f"interface.{field}: required, one line, at most {limit} characters")
    long_desc = iface.get("longDescription")
    if not isinstance(long_desc, str) or not long_desc.strip() or len(long_desc) > 4000:
        errors.append("interface.longDescription: required, at most 4000 characters")
    if iface.get("category") not in _CATEGORIES:
        errors.append(f"interface.category: must be one of {sorted(_CATEGORIES)}")
    caps = iface.get("capabilities", [])
    if len(caps) > 20 or not all(_one_line(c, 120) for c in caps):
        errors.append("interface.capabilities: at most 20, each one line of at most 120 chars")
    for field in _URL_FIELDS:
        url = iface.get(field)
        if not isinstance(url, str) or not url.startswith("https://") or len(url) > 1024:
            errors.append(f"interface.{field}: required https URL (a remote MCP plugin)")

    prompts = iface.get("defaultPrompt", [])
    prompts = [prompts] if isinstance(prompts, str) else prompts
    if len(prompts) > 3 or not all(_one_line(p, 128) for p in prompts):
        errors.append("interface.defaultPrompt: at most 3, each one line of at most 128 chars")
    if any("@" in p for p in prompts if isinstance(p, str)):
        errors.append("interface.defaultPrompt: must not contain an @mention")
    if len({" ".join(p.split()).casefold() for p in prompts if isinstance(p, str)}) != len(prompts):
        errors.append("interface.defaultPrompt: prompts must be unique")

    for field in ("logo", "composerIcon"):
        path = _asset(package, f"interface.{field}", iface.get(field), errors)
        if path:
            width, height = _image_size(path)
            if width != height or width < 48:
                errors.append(f"interface.{field}: must be square and at least 48x48")

    shots = iface.get("screenshots", [])
    if shots and len(shots) != len(prompts):
        errors.append("interface.screenshots: provide one screenshot per starter prompt")
    for i, shot in enumerate(shots):
        path = _asset(package, f"interface.screenshots[{i}]", shot, errors)
        if path:
            width, height = _image_size(path)
            if width != 706 or not 400 <= height <= 860:
                errors.append(f"interface.screenshots[{i}]: must be 706 wide, 400-860 tall")


def _check_review(openai: dict, errors: list[str]) -> None:
    review = openai.get("review") or {}
    for banned in ("test_credentials", "reviewer_instructions"):
        if banned in review:
            errors.append(f"review.{banned}: not allowed in the ZIP; enter it in the portal")
    cases = review.get("test_cases")
    if not cases:
        return  # omitted: the portal keeps the cases already saved there
    positive, negative = cases.get("positive", []), cases.get("negative", [])
    if len(positive) != 5 or len(negative) != 3:
        errors.append("review.test_cases: exactly 5 positive and 3 negative cases")
    for case in positive:
        if not all(case.get(k) for k in
                   ("description", "prompt", "tools_triggered", "expected_behavior")):
            errors.append("review.test_cases.positive: each case needs description, prompt, "
                          "tools_triggered, expected_behavior")
    for case in negative:
        if not all(case.get(k) for k in ("description", "prompt")):
            errors.append("review.test_cases.negative: each case needs description and prompt")


def _check_mcp(package: Path, errors: list[str]) -> None:
    try:
        mcp = json.loads((package / "mcp.json").read_text())
    except (OSError, ValueError) as e:
        errors.append(f"mcp.json: {e}")
        return
    if mcp.get("$schema") != _MCP_SCHEMA:
        errors.append(f"mcp.json: $schema must be {_MCP_SCHEMA}")
    servers = mcp.get("mcpServers")
    if not isinstance(servers, dict) or len(servers) != 1:
        errors.append("mcp.json: exactly one server (only one can be connected per plugin)")
        return
    (name, server), = servers.items()
    if not name.strip() or not isinstance(server, dict):
        errors.append("mcp.json: the server needs a name and a declaration object")
        return
    if server.get("type") != "streamable-http":
        errors.append("mcp.json: the portable format needs type 'streamable-http'")
    if not str(server.get("url", "")).startswith("https://"):
        errors.append("mcp.json: url must be https")


def _check_skills(package: Path, plugin_name: str, errors: list[str]) -> set[str]:
    names: set[str] = set()
    skills = package / "skills"
    if not skills.is_dir():
        return names
    for nested in skills.glob("*/*/**/SKILL.md"):
        errors.append(f"{nested.relative_to(package)}: a skill must sit directly under skills/")
    for skill_dir in sorted(p for p in skills.iterdir() if p.is_dir()):
        rel = skill_dir.relative_to(package)
        if skill_dir.name.startswith("."):
            errors.append(f"{rel}: skill directory names must not start with '.'")
        manifest = skill_dir / "SKILL.md"
        parsed = _frontmatter(manifest.read_text()) if manifest.is_file() else None
        if parsed is None:
            errors.append(f"{rel}/SKILL.md: missing, or no '---' front matter")
            continue
        fields, body = parsed
        name, description = fields.get("name", ""), fields.get("description", "")
        if not name or not description or len(description) > 1024:
            errors.append(f"{rel}/SKILL.md: needs name and a description of at most 1024 chars")
        if not body.strip():
            errors.append(f"{rel}/SKILL.md: instructions must not be empty")
        if name in names:
            errors.append(f"{rel}/SKILL.md: skill name '{name}' is used twice")
        names.add(name)
        if len(f"{plugin_name}:{name}") > 64:
            errors.append(f"{rel}/SKILL.md: '{plugin_name}:{name}' is longer than 64 characters")
        # OpenAI asks for provider-neutral skill text ("the model", not a product name).
        if re.search(r"\bclaude\b", manifest.read_text(), re.IGNORECASE):
            errors.append(f"{rel}/SKILL.md: mentions Claude; use provider-neutral wording")
        agent = skill_dir / "agents" / "openai.yaml"
        if agent.is_file():
            text = agent.read_text()
            for key in ("display_name", "short_description"):
                if not re.search(rf"^interface:\n(?:  .*\n)*?  {key}: *\S", text, re.MULTILINE):
                    errors.append(f"{rel}/agents/openai.yaml: interface.{key} is required")
    return names


def validate(package: Path = PACKAGE) -> list[str]:
    """Return every submission-rule violation in the package; empty when it is ready."""
    errors: list[str] = []
    try:
        manifest = json.loads((package / "plugin.json").read_text())
    except (OSError, ValueError) as e:
        return [f"plugin.json: {e}"]

    if manifest.get("$schema") != _PLUGIN_SCHEMA:
        errors.append(f"plugin.json: $schema must be {_PLUGIN_SCHEMA}")
    name = manifest.get("name")
    if not isinstance(name, str) or not _NAME.match(name) or len(name) > 64:
        errors.append("name: letters, digits, '_' and '-', starting with a letter or digit; max 64")
    version = manifest.get("version")
    if not isinstance(version, str) or not _SEMVER.match(version) or len(version) > 64:
        errors.append("version: must be a semantic version such as 1.1.0")

    openai = (manifest.get("extensions") or {}).get("com.openai") or {}
    for unsupported in ("hooks", "apps"):
        if unsupported in openai:
            errors.append(f"extensions.com.openai.{unsupported}: a ZIP with {unsupported} "
                          "cannot be submitted")
    for unsupported in ("hooks", ".app.json"):
        if (package / unsupported).exists():
            errors.append(f"{unsupported}: a ZIP with this cannot be submitted")

    _check_interface(package, openai.get("interface") or {}, errors)
    _check_review(openai, errors)
    _check_mcp(package, errors)
    skill_names = _check_skills(package, str(name), errors)

    onboarding = openai.get("onboardingSkill")
    if onboarding is not None:
        match = re.fullmatch(r"\./skills/([^/]+)/SKILL\.md", str(onboarding))
        if not match or not (package / onboarding).is_file():
            errors.append("onboardingSkill: must point at an included ./skills/<name>/SKILL.md")
    if not skill_names and not (package / "mcp.json").is_file():
        errors.append("package: needs at least one skill or an MCP server")
    return errors


def build(package: Path = PACKAGE, dist: Path = DIST) -> Path:
    """Write the ZIP with plugin.json at the archive root and return its path."""
    version = json.loads((package / "plugin.json").read_text())["version"]
    dist.mkdir(parents=True, exist_ok=True)
    out = dist / f"agentavow-openai-plugin-{version}.zip"
    files = []
    for entry in _SHIPPED:
        path = package / entry
        files += [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            if path.name != ".DS_Store":
                zf.write(path, path.relative_to(package).as_posix())
    return out


def _release_manifest(release_zip: Path) -> tuple[dict, dict]:
    """(plugin manifest, mcp config) from a portal release ZIP, whichever layout it uses."""
    with zipfile.ZipFile(release_zip) as zf:
        # Shortest path first, so a root file wins over one nested in a skill folder.
        names = sorted(zf.namelist(), key=len)

        def load(filename: str) -> dict:
            for n in names:
                if n == filename or n.endswith("/" + filename):
                    return json.loads(zf.read(n))
            return {}

        manifest = load(".codex-plugin/plugin.json") or load("plugin.json")
        return manifest, load(".mcp.json") or load("mcp.json")


def compare(release_zip: Path, package: Path = PACKAGE) -> list[str]:
    """Differences that matter on an update: package name, MCP server, listing text."""
    ours = json.loads((package / "plugin.json").read_text())
    ours_mcp = json.loads((package / "mcp.json").read_text()).get("mcpServers", {})
    theirs, theirs_mcp = _release_manifest(release_zip)
    theirs_mcp = theirs_mcp.get("mcpServers", {})
    diffs = []
    if theirs.get("name") != ours.get("name"):
        diffs.append(f"MUST FIX name: release has {theirs.get('name')!r}, package has "
                     f"{ours.get('name')!r} (an update must keep the existing name)")
    if theirs.get("version") == ours.get("version"):
        diffs.append(f"MUST FIX version: still {ours.get('version')!r}; an update needs a new one")
    their_urls = {k: v.get("url") for k, v in theirs_mcp.items()}
    our_urls = {k: v.get("url") for k, v in ours_mcp.items()}
    if their_urls != our_urls:
        diffs.append(f"MUST FIX mcp server: release has {their_urls}, package has {our_urls} "
                     "(keep the release's server name and URL)")
    ours_iface = ours["extensions"]["com.openai"].get("interface", {})
    theirs_iface = (theirs.get("interface")
                    or (theirs.get("extensions") or {}).get("com.openai", {}).get("interface")
                    or {})
    for key in sorted(set(ours_iface) | set(theirs_iface)):
        if ours_iface.get(key) != theirs_iface.get(key):
            diffs.append(f"listing {key}: release {theirs_iface.get(key)!r} -> "
                         f"package {ours_iface.get(key)!r}")
    return diffs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="validate only, write nothing")
    parser.add_argument("--compare", type=Path, metavar="RELEASE_ZIP",
                        help="diff the package against the portal's release ZIP")
    args = parser.parse_args()

    errors = validate()
    for e in errors:
        print(f"ERROR {e}")
    if errors:
        return 1
    if args.compare:
        diffs = compare(args.compare)
        print("\n".join(diffs) if diffs else "No differences from the release ZIP.")
        return 1 if any(d.startswith("MUST FIX") for d in diffs) else 0
    if args.check:
        print("OpenAI plugin package is valid.")
        return 0
    print(f"Wrote {build().relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
