"""Phase 2 — fetch + unpack the PUBLISHED artifact (npm tarball / PyPI sdist+wheel).

The scanner grades the GitHub *repo* today, but an agent installs the *published
package*, which can differ from the source ("clean repo, poisoned tarball" —
event-stream, ctx, ua-parser-js, xz-utils). This module resolves and downloads the
real artifact FROM THE REGISTRY ONLY, verifies size/host guards, computes the exact
artifact ``sha256`` digest, and unpacks it to an in-memory file map — **statically,
never executing anything**.

Hard rules (why this file is security-critical — it downloads untrusted bytes):
  * **Registry-host allowlist + SSRF guard.** Every URL is validated through
    ``src.ssrf`` AND its host must be on :data:`_ALLOWED_HOSTS`. Redirects are
    NOT followed (a 3xx to an arbitrary host is rejected).
  * **Size cap + zip-bomb / zip-slip guard.** Downloads abort past
    :data:`MAX_DOWNLOAD_BYTES`; unpacking aborts past :data:`MAX_UNPACKED_BYTES`
    or :data:`MAX_FILE_COUNT`; per-member size is capped; path-traversal
    (``..`` / absolute) and non-regular members (symlink/hardlink/dev) are rejected.
  * **No execution.** We only read bytes. setup.py / install hooks are inspected
    statically (AST) by :mod:`src.scanner.artifact_scan`, never run.
  * **Fail-closed on abuse, fail-open to the caller.** Guard violations raise
    :class:`ArtifactFetchError`; the orchestrator turns any error into a repo-only
    fallback so a scan is never broken.
"""
from __future__ import annotations

import hashlib
import io
import logging
import tarfile
import zipfile
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from src.ssrf import validate_url_https

logger = logging.getLogger(__name__)

# --- Registry endpoints (metadata) -------------------------------------------
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_JSON = "https://pypi.org/pypi/{name}/json"
PYPI_VERSION_JSON = "https://pypi.org/pypi/{name}/{version}/json"
CRATES_META = "https://crates.io/api/v1/crates/{name}"
# Direct CDN URL — bypasses the crates.io 302 to static.crates.io (which _download
# refuses, since it disallows redirects as an SSRF guard).
CRATES_DL = "https://static.crates.io/crates/{name}/{name}-{version}.crate"

# --- Host allowlist. A resolved download URL MUST match one of these hosts, in
# addition to passing the generic SSRF guard. This is the anti-SSRF backbone:
# a packument whose ``dist.tarball`` points at an attacker host is rejected. -----
_ALLOWED_HOSTS = frozenset({
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
})

# --- Size / zip-bomb guards ---------------------------------------------------
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024      # 50MB compressed download ceiling
MAX_UNPACKED_BYTES = 50 * 1024 * 1024      # 50MB total unpacked ceiling
MAX_FILE_COUNT = 5_000                     # reject artifacts with too many members
MAX_MEMBER_BYTES = 8 * 1024 * 1024         # per-file unpacked cap
_METADATA_MAX_BYTES = 8 * 1024 * 1024      # packument / pypi json ceiling
_HTTP_TIMEOUT = 20.0
_DOWNLOAD_TIMEOUT = 40.0

# Redirect status codes we refuse to follow (would leave the allowlisted host).
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class ArtifactFetchError(Exception):
    """Raised on any resolve/download/guard failure. Caller falls open."""


@dataclass
class ArtifactFile:
    """One unpacked file from the published artifact (static — never executed)."""

    path: str                      # normalized relative path (wrapper prefix stripped)
    size: int                      # unpacked byte size
    sha256: str                    # hex sha256 of the raw bytes (drift/added anchor)
    text: str | None = None        # decoded utf-8 text if textual, else None (binary)
    text_sha256: str | None = None  # sha256 of the decoded-text utf-8 (drift-modified)
    is_binary: bool = False


@dataclass
class ArtifactFetchResult:
    """Resolved + unpacked published artifact."""

    ecosystem: str                 # "npm" | "pypi"
    name: str
    version: str
    kind: str                      # "tarball" | "sdist" | "wheel"
    ok: bool = False
    digest: str | None = None      # "sha256:<hex>" of the downloaded artifact bytes
    download_url: str | None = None
    files: dict[str, ArtifactFile] = field(default_factory=dict)
    unpacked_size: int = 0
    file_count: int = 0
    packaged_manifest: dict | None = None  # parsed package.json (npm), None otherwise
    error: str | None = None


# ---------------------------------------------------------------------------
# URL validation (SSRF + host allowlist)
# ---------------------------------------------------------------------------

def _validate_registry_url(url: str) -> str:
    """Assert a URL is https, passes the SSRF guard, AND is an allowlisted host."""
    validate_url_https(url, field_name="artifact_url")  # scheme + private-IP + rebind
    host = (urlparse(url).hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        raise ArtifactFetchError(f"host not on registry allowlist: {host!r}")
    return url


# ---------------------------------------------------------------------------
# HTTP (streaming download with a hard size cap, no redirects)
# ---------------------------------------------------------------------------

async def _get_json(url: str, client: httpx.AsyncClient) -> dict:
    _validate_registry_url(url)
    resp = await client.get(url, timeout=_HTTP_TIMEOUT, follow_redirects=False)
    if resp.status_code in _REDIRECT_CODES:
        raise ArtifactFetchError(f"unexpected redirect from registry: {url}")
    if resp.status_code == 404:
        raise ArtifactFetchError(f"not found: {url}")
    if resp.status_code != 200:
        raise ArtifactFetchError(f"registry status {resp.status_code} for {url}")
    if len(resp.content) > _METADATA_MAX_BYTES:
        raise ArtifactFetchError("registry metadata exceeds size cap")
    try:
        return resp.json()
    except ValueError as exc:
        raise ArtifactFetchError(f"invalid JSON from {url}") from exc


async def _download(url: str, client: httpx.AsyncClient) -> bytes:
    """Stream-download an artifact with a hard byte cap and no redirect following."""
    _validate_registry_url(url)
    buf = bytearray()
    async with client.stream(
        "GET", url, timeout=_DOWNLOAD_TIMEOUT, follow_redirects=False,
    ) as resp:
        if resp.status_code in _REDIRECT_CODES:
            # A redirect could point off the allowlisted host — refuse it.
            raise ArtifactFetchError(f"redirect while downloading artifact: {url}")
        if resp.status_code != 200:
            raise ArtifactFetchError(f"download status {resp.status_code} for {url}")
        clen = resp.headers.get("content-length")
        if clen:
            try:
                if int(clen) > MAX_DOWNLOAD_BYTES:
                    raise ArtifactFetchError("artifact Content-Length exceeds cap")
            except ValueError:
                pass
        async for chunk in resp.aiter_bytes():
            buf.extend(chunk)
            if len(buf) > MAX_DOWNLOAD_BYTES:
                raise ArtifactFetchError("artifact download exceeded size cap")
    if not buf:
        raise ArtifactFetchError("empty artifact download")
    return bytes(buf)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Safe unpacking (tar.gz for npm/sdist, zip for wheel) with zip-bomb/slip guards
# ---------------------------------------------------------------------------

def _is_unsafe_member_name(name: str) -> bool:
    """Reject absolute paths and ``..`` traversal (zip-slip)."""
    if not name or name.startswith("/") or name.startswith("\\"):
        return True
    # Windows drive / UNC
    if len(name) >= 2 and name[1] == ":":
        return True
    parts = name.replace("\\", "/").split("/")
    return any(p == ".." for p in parts)


def _classify_bytes(raw: bytes) -> tuple[str | None, bool]:
    """Return ``(text_or_None, is_binary)``. A NUL byte or undecodable utf-8 = binary."""
    if b"\x00" in raw:
        return None, True
    try:
        return raw.decode("utf-8"), False
    except UnicodeDecodeError:
        return None, True


def _make_file(path: str, raw: bytes) -> ArtifactFile:
    text, is_binary = _classify_bytes(raw)
    text_sha = (
        hashlib.sha256(text.encode("utf-8")).hexdigest() if text is not None else None
    )
    return ArtifactFile(
        path=path,
        size=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        text=text,
        text_sha256=text_sha,
        is_binary=is_binary,
    )


def _strip_common_prefix(raw_files: dict[str, bytes]) -> dict[str, bytes]:
    """Strip a single shared top-level directory (npm ``package/``, sdist
    ``<name>-<ver>/``) so artifact paths line up with repo-relative paths."""
    if not raw_files:
        return raw_files
    tops = {p.split("/", 1)[0] for p in raw_files if "/" in p}
    roots_at_top = [p for p in raw_files if "/" not in p]
    # Only strip when EVERY member shares one top dir (no files at the archive root).
    if len(tops) == 1 and not roots_at_top:
        prefix = next(iter(tops)) + "/"
        return {p[len(prefix):]: b for p, b in raw_files.items() if p != prefix.rstrip("/")}
    return raw_files


def _unpack_tar_gz(raw: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    total = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ArtifactFetchError(f"not a valid gzip tar: {exc}") from exc
    with tf:
        for member in tf:
            if len(out) >= MAX_FILE_COUNT:
                raise ArtifactFetchError("artifact exceeds file-count cap (zip bomb?)")
            if not member.isfile():
                # Skip dirs, and REFUSE symlinks/hardlinks/devices outright.
                continue
            if _is_unsafe_member_name(member.name):
                raise ArtifactFetchError(f"unsafe member path: {member.name!r}")
            if member.size > MAX_MEMBER_BYTES:
                raise ArtifactFetchError(f"member exceeds per-file cap: {member.name}")
            total += member.size
            if total > MAX_UNPACKED_BYTES:
                raise ArtifactFetchError("artifact exceeds unpacked-size cap (zip bomb?)")
            try:
                fobj = tf.extractfile(member)
                data = fobj.read(MAX_MEMBER_BYTES + 1) if fobj else b""
            except (tarfile.TarError, OSError):
                continue
            if len(data) > MAX_MEMBER_BYTES:
                raise ArtifactFetchError(f"member exceeds per-file cap: {member.name}")
            out[member.name] = data
    return out


def _unpack_zip(raw: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    total = 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArtifactFetchError(f"not a valid zip/wheel: {exc}") from exc
    with zf:
        for info in zf.infolist():
            if len(out) >= MAX_FILE_COUNT:
                raise ArtifactFetchError("artifact exceeds file-count cap (zip bomb?)")
            name = info.filename
            if name.endswith("/"):
                continue  # directory entry
            if _is_unsafe_member_name(name):
                raise ArtifactFetchError(f"unsafe member path: {name!r}")
            if info.file_size > MAX_MEMBER_BYTES:
                raise ArtifactFetchError(f"member exceeds per-file cap: {name}")
            total += info.file_size
            if total > MAX_UNPACKED_BYTES:
                raise ArtifactFetchError("artifact exceeds unpacked-size cap (zip bomb?)")
            try:
                data = zf.read(name)
            except (zipfile.BadZipFile, OSError):
                continue
            if len(data) > MAX_MEMBER_BYTES:
                raise ArtifactFetchError(f"member exceeds per-file cap: {name}")
            out[name] = data
    return out


def _build_file_map(raw_files: dict[str, bytes]) -> dict[str, ArtifactFile]:
    stripped = _strip_common_prefix(raw_files)
    return {path: _make_file(path, data) for path, data in stripped.items()}


# ---------------------------------------------------------------------------
# npm resolve + fetch
# ---------------------------------------------------------------------------

async def fetch_npm_artifact(
    name: str, version: str | None = None, *, client: httpx.AsyncClient | None = None,
) -> ArtifactFetchResult:
    """Resolve + download + unpack an npm package tarball from the registry.

    ``version=None`` resolves ``dist-tags.latest``. Raises
    :class:`ArtifactFetchError` on any guard/network failure (caller falls open).
    """
    owns = client is None
    if owns:
        client = httpx.AsyncClient(headers={"User-Agent": "AgentAvow-ArtifactScanner"})
    try:
        packument = await _get_json(f"{NPM_REGISTRY}/{name}", client)
        if version is None:
            version = (packument.get("dist-tags") or {}).get("latest")
            if not version:
                raise ArtifactFetchError(f"no latest dist-tag for npm:{name}")
        vdata = (packument.get("versions") or {}).get(version)
        if not isinstance(vdata, dict):
            raise ArtifactFetchError(f"npm version not found: {name}@{version}")
        dist = vdata.get("dist") or {}
        tarball = dist.get("tarball")
        if not tarball:
            raise ArtifactFetchError(f"no dist.tarball for {name}@{version}")

        raw = await _download(tarball, client)
        files = _build_file_map(_unpack_tar_gz(raw))

        # The PACKAGED package.json (what actually ships) — install hooks live here.
        packaged_manifest = None
        pkg_json = files.get("package.json")
        if pkg_json and pkg_json.text:
            import json
            try:
                packaged_manifest = json.loads(pkg_json.text)
            except ValueError:
                packaged_manifest = None

        return ArtifactFetchResult(
            ecosystem="npm",
            name=name,
            version=version,
            kind="tarball",
            ok=True,
            digest=_digest(raw),
            download_url=tarball,
            files=files,
            unpacked_size=sum(f.size for f in files.values()),
            file_count=len(files),
            packaged_manifest=packaged_manifest,
        )
    finally:
        if owns:
            await client.aclose()


# ---------------------------------------------------------------------------
# PyPI resolve + fetch
# ---------------------------------------------------------------------------

def _pick_pypi_url(urls: list[dict]) -> tuple[str, str] | None:
    """Prefer the sdist (has setup.py / build backend); fall back to a wheel.

    Returns ``(url, kind)`` where kind is ``"sdist"`` or ``"wheel"``.
    """
    sdist = None
    wheel = None
    for u in urls or []:
        if not isinstance(u, dict):
            continue
        pt = u.get("packagetype")
        url = u.get("url")
        if not url:
            continue
        if pt == "sdist" and sdist is None:
            sdist = url
        elif pt == "bdist_wheel" and wheel is None:
            wheel = url
    if sdist:
        return sdist, "sdist"
    if wheel:
        return wheel, "wheel"
    return None


async def fetch_pypi_artifact(
    name: str, version: str | None = None, *, client: httpx.AsyncClient | None = None,
) -> ArtifactFetchResult:
    """Resolve + download + unpack a PyPI sdist (preferred) or wheel from the registry."""
    owns = client is None
    if owns:
        client = httpx.AsyncClient(headers={"User-Agent": "AgentAvow-ArtifactScanner"})
    try:
        if version:
            meta = await _get_json(
                PYPI_VERSION_JSON.format(name=name, version=version), client,
            )
        else:
            meta = await _get_json(PYPI_JSON.format(name=name), client)
            version = (meta.get("info") or {}).get("version")
            if not version:
                raise ArtifactFetchError(f"no version for pypi:{name}")
        picked = _pick_pypi_url(meta.get("urls") or [])
        if not picked:
            raise ArtifactFetchError(f"no downloadable sdist/wheel for {name}=={version}")
        url, kind = picked

        raw = await _download(url, client)
        if kind == "wheel" or url.endswith(".zip") or url.endswith(".whl"):
            raw_files = _unpack_zip(raw)
        else:
            raw_files = _unpack_tar_gz(raw)  # sdist .tar.gz
        files = _build_file_map(raw_files)

        return ArtifactFetchResult(
            ecosystem="pypi",
            name=name,
            version=version,
            kind=kind,
            ok=True,
            digest=_digest(raw),
            download_url=url,
            files=files,
            unpacked_size=sum(f.size for f in files.values()),
            file_count=len(files),
        )
    finally:
        if owns:
            await client.aclose()


async def fetch_crates_artifact(
    name: str, version: str | None = None, *, client: httpx.AsyncClient | None = None,
) -> ArtifactFetchResult:
    """Resolve + download + unpack a crates.io ``.crate`` (a gzipped tar) by coordinate.
    crates.io asks for a descriptive User-Agent with contact info in its crawl policy."""
    owns = client is None
    if owns:
        client = httpx.AsyncClient(headers={
            "User-Agent": "AgentAvow-ArtifactScanner (safety scanning; kenne@agentavow.com)",
        })
    try:
        meta = await _get_json(CRATES_META.format(name=name), client)
        crate = meta.get("crate") or {}
        if not version:
            version = (
                crate.get("max_stable_version")
                or crate.get("max_version")
                or crate.get("newest_version")
            )
            if not version:
                versions = meta.get("versions") or []
                version = versions[0].get("num") if versions else None
            if not version:
                raise ArtifactFetchError(f"no version for crates:{name}")
        url = CRATES_DL.format(name=name, version=version)
        raw = await _download(url, client)
        files = _build_file_map(_unpack_tar_gz(raw))  # a .crate is a gzipped tar
        return ArtifactFetchResult(
            ecosystem="crates",
            name=name,
            version=version,
            kind="crate",
            ok=True,
            digest=_digest(raw),
            download_url=url,
            files=files,
            unpacked_size=sum(f.size for f in files.values()),
            file_count=len(files),
        )
    finally:
        if owns:
            await client.aclose()
