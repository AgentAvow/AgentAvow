"""Lockfile / manifest parsers → a flat, ecosystem-tagged dependency set.

Phase 1 of the scoring roadmap (§2.B). The scanner's old ``dependency`` check
was a ~20-package regex list (``scan._VULN_DEPS``). To query a *real* vuln DB
(OSV) we first need the actual resolved dependency set — every pinned version
across the transitive tree — which lives in the repo's lockfiles.

This module is **pure and dependency-light**: it parses the lockfile text that
the existing GitHub fetch already returns and emits a de-duplicated list of
``Dep(ecosystem, name, version)``. It never touches the network. OSV ecosystem
names are used verbatim (``npm`` / ``PyPI`` / ``crates.io`` / ``Go``) so the
output can be POSTed to ``api.osv.dev/v1/querybatch`` without remapping.

Parsers are defensive: any malformed/oversized/unknown file yields ``[]`` rather
than raising, so a broken lockfile can never break a scan (fail-open).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# OSV ecosystem identifiers (https://ossf.github.io/osv-schema/#affectedpackage-field)
ECO_NPM = "npm"
ECO_PYPI = "PyPI"
ECO_CRATES = "crates.io"
ECO_GO = "Go"

# Lockfiles we know how to parse, keyed by lowercased basename.
LOCKFILE_NAMES = frozenset({
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "poetry.lock",
    "pipfile.lock",
    "cargo.lock",
    "go.sum",
})

# Guardrail: never spend unbounded time on a pathological lockfile.
_MAX_DEPS = 4000


@dataclass(frozen=True)
class Dep:
    """One resolved dependency, ready for an OSV querybatch entry.

    ``dev`` marks a development-only dependency (npm ``dev:true`` / Pipfile
    ``develop``). Dev deps are NOT installed by consumers of the published
    package, so their vulns must not lower the trust grade — the supply-chain
    pass filters them out. ``compare=False`` keeps (ecosystem, name, version)
    dedup unaffected by the flag.
    """

    ecosystem: str
    name: str
    version: str
    dev: bool = field(default=False, compare=False)
    # ``direct`` marks a manifest-declared (top-level) dependency vs a transitive one
    # pulled in by another dep. Defaults True everywhere it can't be determined, so
    # unknowns keep FULL grade weight — the fail-safe side (never under-count a CVE).
    direct: bool = field(default=True, compare=False)

    def as_osv_query(self) -> dict:
        return {
            "package": {"ecosystem": self.ecosystem, "name": self.name},
            "version": self.version,
        }


# --- individual parsers -------------------------------------------------------

_SEMVERISH = re.compile(r"^\d")  # a resolved version starts with a digit


def _clean_version(raw: str) -> str:
    v = raw.strip().strip('"').strip("'")
    # Strip common operators/leading markers ("==1.2.3", "v1.2.3", "^1.2.3").
    v = v.lstrip("=~^><! v")
    return v.strip()


def parse_package_lock(text: str) -> list[Dep]:
    """npm ``package-lock.json`` (v1 ``dependencies`` and v2/v3 ``packages``)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    out: list[Dep] = []

    # v2/v3: "packages" keyed by "node_modules/<name>" (nested paths keep the
    # trailing package after the last node_modules/ segment).
    packages = data.get("packages") if isinstance(data, dict) else None
    if isinstance(packages, dict):
        # The root ("") entry lists the manifest's declared deps — those are DIRECT.
        # If it's absent we can't tell, so we fall back to full weight (all direct).
        root = packages.get("") if isinstance(packages.get(""), dict) else {}
        root_direct = set(root.get("dependencies") or {}) | set(root.get("peerDependencies") or {})
        have_root = bool(root_direct)
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue  # "" is the root project
            ver = meta.get("version")
            if not isinstance(ver, str):
                continue
            name = path.split("node_modules/")[-1]
            if name:
                # npm marks devDependencies (and their dev-only transitives) with
                # `dev: true`; `devOptional` is dev-or-optional. Either → dev.
                is_dev = bool(meta.get("dev") or meta.get("devOptional"))
                # A NESTED node_modules path is never hoisted → definitely transitive.
                # A top-level entry is direct iff the manifest declared it (else, when
                # we have no root info, default direct = full weight).
                nested = path.count("node_modules/") > 1
                is_direct = False if nested else (name in root_direct if have_root else True)
                out.append(Dep(ECO_NPM, name, _clean_version(ver), dev=is_dev, direct=is_direct))

    # v1: recursive "dependencies" tree — depth 0 is direct, anything deeper transitive.
    def _walk(node: dict, depth: int = 0) -> None:
        deps = node.get("dependencies")
        if not isinstance(deps, dict):
            return
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            if isinstance(ver, str) and isinstance(name, str):
                out.append(Dep(
                    ECO_NPM, name, _clean_version(ver),
                    dev=bool(meta.get("dev")), direct=(depth == 0),
                ))
            _walk(meta, depth + 1)

    if isinstance(data, dict) and not packages:
        _walk(data)
    return out


def parse_yarn_lock(text: str) -> list[Dep]:
    """Yarn v1 ``yarn.lock`` (custom flat format)."""
    out: list[Dep] = []
    current_names: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            # Header line: `"a@^1", b@~2:` — one or more specs, then a colon.
            header = line.rstrip(":").strip()
            names: list[str] = []
            for spec in header.split(","):
                spec = spec.strip().strip('"')
                if not spec:
                    continue
                # Strip the version range: split on the LAST '@' (scope keeps its
                # leading '@'): "@scope/pkg@^1.0" -> "@scope/pkg".
                at = spec.rfind("@")
                names.append(spec[:at] if at > 0 else spec)
            current_names = [n for n in names if n]
        else:
            m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
            if m and current_names:
                ver = _clean_version(m.group(1))
                for name in current_names:
                    out.append(Dep(ECO_NPM, name, ver))
                current_names = []
    return out


def parse_pnpm_lock(text: str) -> list[Dep]:
    """pnpm ``pnpm-lock.yaml`` — keys like ``/name/1.2.3`` or ``/name@1.2.3``.

    Dev-only deps (a ``dev: true`` sub-field, pnpm v5/6/8) are marked so the
    supply-chain pass can exclude them, matching the npm/Pipfile behaviour. (pnpm v9
    moves dev-ness into the ``importers`` section — not yet parsed; those deps stay
    prod-classified, which is the safe/conservative default.)
    """
    from dataclasses import replace

    out: list[Dep] = []
    in_packages = False
    cur = -1  # index in `out` of the package whose sub-fields we're reading
    for line in text.splitlines():
        if re.match(r"^packages:\s*$", line):
            in_packages = True
            continue
        if in_packages and line and not line[0].isspace():
            break  # left the packages: block
        if not in_packages:
            continue
        # A ``dev: true`` sub-field marks the current package dev-only. Sub-fields
        # have a value after the colon, so they never match the key regex below.
        if cur >= 0 and re.match(r"\s+dev:\s*true\s*$", line):
            out[cur] = replace(out[cur], dev=True)
            continue
        m = re.match(r"\s+(['\"]?)(/?[^:'\"]+)\1:\s*$", line)
        if not m:
            continue
        key = m.group(2).strip()
        if not key or key == "/":
            continue
        key = key.lstrip("/")
        # Drop peer-dep suffixes first — "react@18.0.0(react-dom@18.0.0)" — so the
        # nested '@' inside the parenthetical can't be mistaken for the version sep.
        key = key.split("(")[0]
        # v9 form: name@version (name may be @scope/pkg).
        if "@" in key and "/" not in key.split("@")[-1]:
            at = key.rfind("@")
            name, ver = key[:at], key[at + 1:]
        else:
            # v5/6 form: name/version or @scope/name/version, version last segment.
            parts = key.rsplit("/", 1)
            if len(parts) != 2:
                # A sub-block header (dependencies:/optionalDependencies:) — keep the
                # current package so its later ``dev: true`` still attaches.
                continue
            name, ver = parts
        name, ver = name.strip(), _clean_version(ver)
        if name and ver and _SEMVERISH.match(ver):
            out.append(Dep(ECO_NPM, name, ver))
            cur = len(out) - 1
    return out


def parse_requirements_txt(text: str) -> list[Dep]:
    """``requirements.txt`` — only exact ``==`` pins yield an OSV-queryable version."""
    out: list[Dep] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!-]+)", line)
        if m:
            out.append(Dep(ECO_PYPI, m.group(1), _clean_version(m.group(2))))
    return out


def _parse_toml_packages(text: str, ecosystem: str) -> list[Dep]:
    """Shared ``[[package]]`` block parser for poetry.lock / Cargo.lock.

    Line-based (no tomllib on Python 3.9) — scans for ``[[package]]`` blocks and
    pulls the ``name``/``version`` string keys from each.
    """
    out: list[Dep] = []
    name: str | None = None
    version: str | None = None
    in_pkg = False
    for line in text.splitlines():
        s = line.strip()
        if s == "[[package]]":
            if name and version:
                out.append(Dep(ecosystem, name, _clean_version(version)))
            name, version, in_pkg = None, None, True
            continue
        if s.startswith("[") and s != "[[package]]":
            # Any other table ends the current package block.
            if in_pkg and name and version:
                out.append(Dep(ecosystem, name, _clean_version(version)))
                name = version = None
            in_pkg = False
            continue
        if not in_pkg:
            continue
        m = re.match(r'name\s*=\s*"([^"]+)"', s)
        if m:
            name = m.group(1)
            continue
        m = re.match(r'version\s*=\s*"([^"]+)"', s)
        if m:
            version = m.group(1)
    if in_pkg and name and version:
        out.append(Dep(ecosystem, name, _clean_version(version)))
    return out


def parse_poetry_lock(text: str) -> list[Dep]:
    return _parse_toml_packages(text, ECO_PYPI)


def parse_cargo_lock(text: str) -> list[Dep]:
    return _parse_toml_packages(text, ECO_CRATES)


def parse_pipfile_lock(text: str) -> list[Dep]:
    """``Pipfile.lock`` — JSON with ``default``/``develop`` maps of name→{version}."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    out: list[Dep] = []
    if not isinstance(data, dict):
        return out
    for section in ("default", "develop"):
        is_dev = section == "develop"
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, meta in block.items():
            if not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            if isinstance(ver, str) and ver.startswith("=="):
                out.append(Dep(ECO_PYPI, name, _clean_version(ver), dev=is_dev))
    return out


def parse_go_sum(text: str) -> list[Dep]:
    """``go.sum`` — ``module version[/go.mod] hash`` lines, de-duped by module@ver."""
    out: list[Dep] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module, ver = parts[0], parts[1]
        ver = ver.split("/go.mod")[0]
        ver = _clean_version(ver)
        if not ver or not _SEMVERISH.match(ver):
            continue
        key = (module, ver)
        if key in seen:
            continue
        seen.add(key)
        out.append(Dep(ECO_GO, module, ver))
    return out


_DISPATCH = {
    "package-lock.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "requirements.txt": parse_requirements_txt,
    "poetry.lock": parse_poetry_lock,
    "pipfile.lock": parse_pipfile_lock,
    "cargo.lock": parse_cargo_lock,
    "go.sum": parse_go_sum,
}


def parse_lockfile(filename: str, text: str) -> list[Dep]:
    """Parse one lockfile by basename. Returns ``[]`` for unknown/broken files."""
    if not text:
        return []
    parser = _DISPATCH.get(Path(filename).name.lower())
    if not parser:
        return []
    try:
        return parser(text)
    except Exception:  # never let a malformed lockfile break a scan
        return []


def parse_all(files: dict[str, str]) -> list[Dep]:
    """Parse a ``{path: content}`` map into one de-duplicated Dep list.

    De-duped on ``(ecosystem, name, version)`` and capped at ``_MAX_DEPS`` so a
    giant monorepo lockfile can't blow up the downstream OSV batch.
    """
    seen: set[tuple[str, str, str]] = set()
    out: list[Dep] = []
    for path, content in files.items():
        for dep in parse_lockfile(path, content):
            if not dep.name or not dep.version:
                continue
            key = (dep.ecosystem, dep.name, dep.version)
            if key in seen:
                continue
            seen.add(key)
            out.append(dep)
            if len(out) >= _MAX_DEPS:
                return out
    return out
