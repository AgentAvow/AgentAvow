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
            if "node_modules/" not in path:
                continue  # a workspace member ("src/everything") is the project, not a dep
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


def _pnpm_v9_dev_only_names(text: str) -> set[str]:
    """pnpm v9 dev-only DIRECT dep names, from the ``importers:`` section.

    v9 dropped the inline ``dev: true`` marker from ``packages:`` and derives
    dev-ness from ``importers:`` — each importer (workspace root or member) carries
    separate ``dependencies`` / ``devDependencies`` (and ``optionalDependencies``)
    maps. We treat ``optionalDependencies`` as PRODUCTION (matches the package-lock
    ``devOptional`` handling — optional runtime deps still ship to consumers).

    Returns names present under some importer's ``devDependencies`` and under NO
    importer's production map. Per the module's fail-safe philosophy, a name in ANY
    production map is never returned, so a real prod CVE is never hidden.

    SAFE first increment: only DIRECT importer deps are considered. A devDependency
    that is *transitively* pulled in by a production dep is still returned here; full
    prod-reachability across the ``packages`` graph is a FOLLOW-UP. This stays safe
    because callers apply the result only to DIRECT deps (a transitive package whose
    name isn't a direct importer key is never in this set), so transitives keep full
    production weight.
    """
    prod: set[str] = set()
    dev: set[str] = set()
    in_importers = False
    section: str | None = None  # "prod" or "dev" — the group we're collecting under
    section_indent = -1
    for line in text.splitlines():
        if re.match(r"^importers:\s*$", line):
            in_importers = True
            continue
        if not in_importers:
            continue
        if line and not line[0].isspace():
            break  # left the importers: block (e.g. reached packages:)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        m = re.match(r"(dependencies|devDependencies|optionalDependencies):\s*$", stripped)
        if m:
            section = "dev" if m.group(1) == "devDependencies" else "prod"
            section_indent = indent
            continue
        # A dep name sits exactly one indent level under its group header, ends ":".
        if section is not None and indent == section_indent + 2:
            dm = re.match(r"(['\"]?)([^:'\"]+)\1:\s*$", stripped)
            if dm:
                name = dm.group(2).strip()
                if name:
                    (dev if section == "dev" else prod).add(name)
                continue
        # A line at/above the group-header indent (new importer, new section header
        # handled above) ends the current group; deeper lines are the dep's fields.
        if indent <= section_indent:
            section = None
    return dev - prod


_PNPM_KEY_RE = re.compile(r"^\s*(['\"]?)(.+?)\1:\s*(.*)$")


def _pnpm_nv(key: str) -> str | None:
    """``name@version`` from a v9 snapshot key or a dependency reference, peer
    suffix dropped (``next@15.5.25(react@19.0.0)`` -> ``next@15.5.25``)."""
    key = key.strip().strip("'\"").lstrip("/").split("(")[0]
    if "@" not in key[1:]:
        return None
    at = key.rfind("@")
    name, ver = key[:at], key[at + 1:]
    return f"{name}@{_clean_version(ver)}" if name and ver else None


def pnpm_v9_importers(text: str) -> dict[str, dict[str, set[str]]]:
    """``{importer path: {"prod": {name@ver}, "dev": {name@ver}, "links": {path}}}``
    from a v9 ``importers:`` block (``optionalDependencies`` count as prod). A prod
    ``link:`` to another workspace member is recorded in ``links`` as that member's
    importer path; ``file:`` deps are skipped. Empty on any other shape."""
    import posixpath
    out: dict[str, dict[str, set[str]]] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines) and not re.match(r"^importers:\s*$", lines[i]):
        i += 1
    cur: str | None = None
    group: str | None = None
    dep: str | None = None
    for line in lines[i + 1:]:
        if line and not line[0].isspace():
            break
        if not line.strip():
            continue
        ind = len(line) - len(line.lstrip())
        m = _PNPM_KEY_RE.match(line)
        if not m:
            continue
        key, val = m.group(2).strip(), m.group(3).strip()
        if ind == 2:
            cur, group, dep = key, None, None
            out.setdefault(cur, {"prod": set(), "dev": set(), "links": set()})
        elif ind == 4 and cur is not None:
            group = ("dev" if key == "devDependencies" else
                     "prod" if key in ("dependencies", "optionalDependencies") else None)
            dep = None
        elif ind == 6 and group:
            dep = key
        elif ind == 8 and group and dep and key == "version":
            v = val.strip("'\"")
            if v.startswith("link:"):
                if group == "prod":
                    tgt = posixpath.normpath(posixpath.join(
                        "" if cur == "." else cur, v[len("link:"):]))
                    out[cur]["links"].add("." if tgt in ("", ".") else tgt)
                continue
            if v.startswith("file:"):
                continue  # a local tarball/dir: not a registry package
            # npm alias: the version names the real package (`types-react@19.0.0`)
            nv = _pnpm_nv(v) if "@" in v.split("(")[0][1:] else _pnpm_nv(f"{dep}@{v}")
            if nv:
                out[cur][group].add(nv)
    return out


def pnpm_v9_edges(text: str) -> dict[str, set[str]]:
    """``{name@ver: {name@ver of each dependency}}`` from the v9 ``snapshots:``
    block (dependencies + optionalDependencies)."""
    edges: dict[str, set[str]] = {}
    in_snap = False
    cur: str | None = None
    in_deps = False
    for line in text.splitlines():
        if re.match(r"^snapshots:\s*$", line):
            in_snap = True
            continue
        if not in_snap:
            continue
        if line and not line[0].isspace():
            break
        if not line.strip():
            continue
        ind = len(line) - len(line.lstrip())
        m = _PNPM_KEY_RE.match(line)
        if not m:
            continue
        key, val = m.group(2).strip(), m.group(3).strip()
        if ind == 2:
            cur = _pnpm_nv(key)
            in_deps = False
            if cur:
                edges.setdefault(cur, set())
        elif ind == 4:
            in_deps = key in ("dependencies", "optionalDependencies")
        elif ind == 6 and in_deps and cur and val:
            v = val.strip("'\"")
            if v.startswith(("link:", "file:")):
                continue
            nv = _pnpm_nv(v) if "@" in v.split("(")[0][1:] else _pnpm_nv(f"{key}@{v}")
            if nv:
                edges[cur].add(nv)
    return edges


def _reach(roots: set[str], edges: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(edges.get(n, ()))
    return seen


def pnpm_v9_unshipped(text: str, private_importers: set[str]) -> set[str] | None:
    """``name@ver`` NOT reachable from any shipped importer's production deps, or
    None when the lockfile cannot be read that way (then nothing changes).

    Shipped importers are the public ones (``private_importers`` excluded); when every
    importer is private (an app, not a library), all of them count as shipped, since
    their deps are what its users run. Reachability follows ``snapshots``
    (dependencies + optionalDependencies), so the transitive deps of dev tools are
    unshipped too (the follow-up ``_pnpm_v9_dev_only_names`` documents).

    Fail-safe: None when there is no importer or no snapshot graph, or when a
    shipped importer's direct prod dep is missing from the graph (an unreadable
    shape must never hide a production vulnerability)."""
    imps = pnpm_v9_importers(text)
    edges = pnpm_v9_edges(text)
    if not imps or not edges:
        return None
    shipped_imps = {k for k in imps if k not in private_importers} or set(imps)
    # A member a shipped member links to as a prod dep ships with it, private or not.
    todo = list(shipped_imps)
    while todo:
        for tgt in imps.get(todo.pop(), {}).get("links", ()):
            if tgt in imps and tgt not in shipped_imps:
                shipped_imps.add(tgt)
                todo.append(tgt)
    roots = set().union(*(imps[k]["prod"] for k in shipped_imps))
    if any(r not in edges for r in roots):
        return None
    return set(edges) - _reach(roots, edges)


def _npm_packages(text: str) -> dict | None:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    pk = data.get("packages") if isinstance(data, dict) else None
    return pk if isinstance(pk, dict) else None


def npm_workspace_members(text: str) -> list[str]:
    """Workspace members of an npm v2/v3 lockfile: the root (``""``) and every
    ``packages`` key outside node_modules (``src/everything``). Empty for a plain
    (non-workspace) project or a v1 lockfile."""
    pk = _npm_packages(text)
    if not pk:
        return []
    members = [k for k in pk if isinstance(k, str) and "node_modules/" not in k]
    return members if len(members) >= 2 else []


def _npm_parent(path: str) -> str | None:
    """The directory whose node_modules a package at ``path`` falls back to."""
    if not path:
        return None
    i = path.rfind("node_modules/")
    if i > 0:
        return path[:i - 1]
    if i == 0:
        return ""
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _npm_resolve(pk: dict, frm: str, name: str) -> str | None:
    """Node's lookup: ``<dir>/node_modules/<name>`` from ``frm`` up to the root; a
    workspace link resolves to the member it points at."""
    base: str | None = frm
    while base is not None:
        cand = (base + "/" if base else "") + "node_modules/" + name
        meta = pk.get(cand)
        if isinstance(meta, dict):
            if meta.get("link") and isinstance(meta.get("resolved"), str):
                tgt = meta["resolved"]
                return tgt if tgt in pk else None
            return cand
        base = _npm_parent(base)
    return None


def npm_workspace_unshipped(text: str, private_members: set[str]) -> set[str] | None:
    """``name@ver`` an npm workspace installs that no shipped member reaches through
    its production deps, or None when that can't be read (then nothing changes).

    The npm twin of ``pnpm_v9_unshipped``. npm's own ``dev`` flags are computed over
    the whole workspace, so what only a private member uses (a docs site, examples)
    still reads as production. Shipped members are the public ones; when every member
    is private (an app), all ship. A member a shipped member depends on ships too.
    Only used when some member is known private.

    Fail-safe: None when it isn't a workspace lockfile, or a shipped member's own prod
    dep can't be resolved."""
    pk = _npm_packages(text)
    members = npm_workspace_members(text)
    if not pk or not members:
        return None

    def prod_names(meta: dict) -> list[tuple[str, bool]]:
        out = []
        for fld, required in (("dependencies", True), ("optionalDependencies", False),
                              ("peerDependencies", False)):
            deps = meta.get(fld)
            if isinstance(deps, dict):
                out += [(n, required) for n in deps if isinstance(n, str)]
        return out

    shipped = {m for m in members if m not in private_members} or set(members)
    seen: set[str] = set()
    stack: list[str] = []
    for m in shipped:
        for n, required in prod_names(pk.get(m) or {}):
            tgt = _npm_resolve(pk, m, n)
            if tgt is None:
                if required:
                    return None
                continue
            stack.append(tgt)
    stack += list(shipped)
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        meta = pk.get(node)
        if not isinstance(meta, dict):
            continue
        for n, _ in prod_names(meta):
            tgt = _npm_resolve(pk, node, n)
            if tgt is not None and tgt not in seen:
                stack.append(tgt)

    def key(path: str, meta: dict) -> str | None:
        ver = meta.get("version")
        name = path.split("node_modules/")[-1]
        if "node_modules/" not in path or not isinstance(ver, str) or not name:
            return None
        return f"{name}@{_clean_version(ver)}"

    shipped_keys = {k for p in seen if isinstance(pk.get(p), dict)
                    for k in [key(p, pk[p])] if k}
    all_keys = {k for p, meta in pk.items() if isinstance(meta, dict)
                for k in [key(p, meta)] if k}
    return all_keys - shipped_keys


def pnpm_private_only(text: str, private_importers: set[str]) -> set[str]:
    """``name@ver`` pulled in ONLY by private workspace members: reachable from a
    private importer's production deps and NOT from any public importer's
    production deps. Empty unless the lockfile is a workspace with at least one
    public importer (a single private app's deps are exactly what its users run)."""
    imps = pnpm_v9_importers(text)
    if len(imps) < 2 or not private_importers:
        return set()
    public = [k for k in imps if k not in private_importers]
    private = [k for k in imps if k in private_importers]
    if not public or not private:
        return set()
    edges = pnpm_v9_edges(text)
    shipped = _reach(set().union(*(imps[k]["prod"] for k in public)), edges)
    unshipped = _reach(set().union(*(imps[k]["prod"] for k in private)), edges)
    return unshipped - shipped


def parse_pnpm_lock(text: str) -> list[Dep]:
    """pnpm ``pnpm-lock.yaml`` — keys like ``/name/1.2.3`` or ``/name@1.2.3``.

    Dev-only deps are marked so the supply-chain pass can exclude them, matching the
    npm/Pipfile behaviour:

    - **v5/6/8:** a per-package ``dev: true`` sub-field under ``packages:``.
    - **v9:** the inline marker is gone; dev-ness is derived from the ``importers:``
      section (see ``_pnpm_v9_dev_only_names``). A DIRECT dep is marked dev-only iff
      it is in some importer's ``devDependencies`` and in NO importer's production
      map. When uncertain, deps stay production (full grade weight).
    """
    from dataclasses import replace

    # v9 detection: presence of a top-level ``importers:`` block (v5/6/8 have none).
    v9_dev_only = (
        _pnpm_v9_dev_only_names(text) if re.search(r"^importers:\s*$", text, re.M) else set()
    )

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
    # v9: apply importer-derived dev-only marking. Only DIRECT names absent from every
    # production map are flagged (transitive prod-reachability is a follow-up), so a
    # real prod CVE is never mis-marked dev.
    if v9_dev_only:
        out = [replace(d, dev=True) if (d.name in v9_dev_only and not d.dev) else d for d in out]
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


def yaml_documents(text: str) -> list[str]:
    """The YAML documents in a file, split on ``---`` lines. pnpm 10 can write a small
    first document (config dependencies) before the lockfile proper: reading only the
    first document graded 15 of vercel/ai's 4,054 packages (2026-11-11)."""
    docs, cur = [], []
    for line in text.splitlines():
        if line.rstrip() == "---":
            if any(x.strip() for x in cur):
                docs.append("\n".join(cur))
            cur = []
            continue
        cur.append(line)
    if any(x.strip() for x in cur):
        docs.append("\n".join(cur))
    return docs or [text]


def parse_all(files: dict[str, str],
              private_importers: dict[str, set[str]] | None = None) -> list[Dep]:
    """Parse a ``{path: content}`` map into one de-duplicated Dep list.

    De-duped on ``(ecosystem, name, version)`` and capped at ``_MAX_DEPS`` so a
    giant monorepo lockfile can't blow up the downstream OSV batch.

    pnpm v9 lockfiles: a package not reachable from a shipped importer's production
    deps is marked dev (``pnpm_v9_unshipped``): dev tools' transitive deps, and what
    only ``private_importers`` (per lockfile path: members whose package.json is
    ``"private": true``) pull in, e.g. colinhacks/zod's private docs site
    (2026-11-11). npm v2/v3 workspace lockfiles get the same treatment when some member
    is known private (``npm_workspace_unshipped``). When one lockfile ships a package
    another marks dev, the shipped (production) entry wins.
    """
    from dataclasses import replace
    private_importers = private_importers or {}
    seen: dict[tuple[str, str, str], int] = {}
    out: list[Dep] = []
    units: list[tuple[str, str]] = []
    for path, content in files.items():
        if path.lower().endswith("pnpm-lock.yaml"):
            units += [(path, doc) for doc in yaml_documents(content)]
        else:
            units.append((path, content))
    for path, content in units:
        unshipped: set[str] = set()
        if path.lower().endswith("pnpm-lock.yaml") and re.search(
                r"^snapshots:\s*$", content, re.M):
            try:
                unshipped = pnpm_v9_unshipped(content, private_importers.get(path) or set()) \
                    or set()
            except Exception:  # noqa: BLE001 — fail safe: deps keep production weight
                unshipped = set()
        elif path.lower().endswith("package-lock.json") and private_importers.get(path):
            try:
                unshipped = npm_workspace_unshipped(content, private_importers[path]) or set()
            except Exception:  # noqa: BLE001 — fail safe: deps keep production weight
                unshipped = set()
        for dep in parse_lockfile(path, content):
            if not dep.name or not dep.version:
                continue
            if unshipped and not dep.dev and f"{dep.name}@{dep.version}" in unshipped:
                dep = replace(dep, dev=True)
            key = (dep.ecosystem, dep.name, dep.version)
            if key in seen:
                prev = seen[key]
                if out[prev].dev and not dep.dev:
                    out[prev] = dep
                continue
            seen[key] = len(out)
            out.append(dep)
            if len(out) >= _MAX_DEPS:
                return out
    return out
    return out
