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
import json
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
# --- Hugging Face model repo (git-backed, but graded like a package by coordinate).
# Metadata + a recursive file tree (path/size/type), and small text files served
# directly by the hub (NOT via the LFS CDN, which large binary weights redirect to —
# and which _download refuses). We never download the weight blobs; their FORMAT is
# the signal (pickle-backed formats execute arbitrary code on load).
HF_META = "https://huggingface.co/api/models/{name}"
HF_TREE = "https://huggingface.co/api/models/{name}/tree/main?recursive=true"
HF_RESOLVE = "https://huggingface.co/{name}/resolve/main/{path}"
# --- Container images. Graded at CONFIG level (not a full layer scan): the OCI
# image config carries the highest-density security signal without pulling layers —
# runs-as-root, secrets baked into ENV/labels, stale base, exposed ports. The token
# dance is anonymous pull scope; the config blob is content-addressed so we verify
# its digest even when the registry redirects it to a CDN.
DOCKER_REGISTRY = "https://registry-1.docker.io"
DOCKER_AUTH = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
GHCR_REGISTRY = "https://ghcr.io"
GHCR_AUTH = "https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}:pull"
_OCI_MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
# Bounded full-layer scan: pull the image's (gzip) layers up to a total cap, extract
# the filesystem, and run the 12-category engine over it — baked file secrets,
# world-readable keys, install/entry scripts. NOT a config-only grade. Skips zstd
# layers (can't gunzip) and any single layer over the per-layer cap; newest layers
# (the app's own, most interesting) are pulled first.
_DOCKER_MAX_LAYER_TOTAL = 45 * 1024 * 1024   # total compressed bytes pulled across layers
_DOCKER_MAX_ONE_LAYER = 30 * 1024 * 1024     # skip any single layer bigger than this
_DOCKER_MAX_LAYER_FILES = 800                # cap extracted files scanned

# --- Host allowlist. A resolved download URL MUST match one of these hosts, in
# addition to passing the generic SSRF guard. This is the anti-SSRF backbone:
# a packument whose ``dist.tarball`` points at an attacker host is rejected. -----
_ALLOWED_HOSTS = frozenset({
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "huggingface.co",
    "registry-1.docker.io",
    "auth.docker.io",
    "ghcr.io",
})

# Hugging Face weight-file formats. Pickle-backed formats deserialize arbitrary
# Python on load (``torch.load`` / ``pickle.load``) — the model IS executable code.
# ``.safetensors`` (and friends) are pure tensor containers with no code path.
_HF_UNSAFE_WEIGHT_EXT = frozenset({
    ".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".h5", ".joblib", ".npy", ".npz",
})
_HF_SAFE_WEIGHT_EXT = frozenset({
    ".safetensors", ".gguf", ".onnx", ".tflite", ".mlmodel",
})
# Text files worth downloading for the 12-category engine (model card, configs,
# custom modeling code). Weight blobs are never fetched.
_HF_TEXT_EXT = frozenset({
    ".md", ".txt", ".py", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini",
    ".gitattributes", ".sh", ".jinja", ".template",
})
_HF_MAX_TEXT_FILES = 40
_HF_MAX_TEXT_BYTES = 512 * 1024

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
    # git blob SHA-1 of the raw bytes (== GitHub's tree entry `sha`). Lets drift
    # compare the artifact against a repo TREE at a release tag with no content fetch.
    git_blob_sha: str = ""


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
    description: str | None = None          # one-line "what it is" from registry metadata
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


async def _get_json_list(url: str, client: httpx.AsyncClient) -> list:
    """Like :func:`_get_json` but for endpoints returning a JSON array (HF tree)."""
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
        data = resp.json()
    except ValueError as exc:
        raise ArtifactFetchError(f"invalid JSON from {url}") from exc
    return data if isinstance(data, list) else []


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
        # git blob SHA-1: sha1("blob <len>\0" + bytes) — matches GitHub's tree `sha`.
        git_blob_sha=hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\x00" + raw
        ).hexdigest(),
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
            description=(packaged_manifest or {}).get("description"),
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
            description=(meta.get("info") or {}).get("summary"),
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
            description=crate.get("description"),
        )
    finally:
        if owns:
            await client.aclose()


# HF ``/resolve/`` 307-redirects even small git files to an on-host cache path, and
# LFS blobs to the HF CDN. We follow redirects for HF text files ONLY, re-validating
# every hop's host against this set (SSRF stays closed — an off-HF Location is refused).
_HF_DOWNLOAD_HOSTS = frozenset({
    "huggingface.co", "cdn-lfs.huggingface.co", "cdn-lfs-us-1.huggingface.co",
    "cdn-lfs-eu-1.huggingface.co",
})


async def _download_hf_text(url: str, client: httpx.AsyncClient) -> bytes | None:
    """Best-effort download of one small HF text file, following redirects but only
    to HF hosts (each hop re-validated). Returns None on any failure (skipped)."""
    try:
        cur = url
        for _hop in range(4):
            validate_url_https(cur, field_name="hf_file_url")
            host = (urlparse(cur).hostname or "").lower()
            if host not in _HF_DOWNLOAD_HOSTS:
                return None
            resp = await client.get(cur, timeout=_HTTP_TIMEOUT, follow_redirects=False)
            if resp.status_code in _REDIRECT_CODES:
                loc = resp.headers.get("location")
                if not loc:
                    return None
                cur = str(httpx.URL(cur).join(loc))  # resolves relative → absolute
                continue
            if resp.status_code != 200:
                return None
            if len(resp.content) > _HF_MAX_TEXT_BYTES:
                return None
            return resp.content
        return None
    except (httpx.HTTPError, ValueError):
        return None


async def fetch_huggingface_artifact(
    name: str, version: str | None = None, *, client: httpx.AsyncClient | None = None,
) -> ArtifactFetchResult:
    """Resolve + statically fetch a Hugging Face **model repo** by ``org/model``.

    Unlike npm/PyPI/crates there is no single downloadable tarball — the repo is
    git+LFS-backed. We pull the recursive file tree, download only the small text
    files (model card, configs, custom ``modeling_*.py`` code) for the 12-category
    engine, and record the FORMAT of every weight file without downloading it: a
    model shipping pickle-backed weights (``.bin``/``.pt``/``.ckpt``…) executes
    arbitrary code on load, which is the load-time analogue of an install hook.

    ``packaged_manifest['hf']`` carries the metadata + weight-format census the
    HF-specific detector consumes. Fail-open: raises ``ArtifactFetchError`` on a
    hard failure; per-file download failures are tolerated (skipped)."""
    owns = client is None
    if owns:
        client = httpx.AsyncClient(headers={
            "User-Agent": "AgentAvow-ArtifactScanner (safety scanning; kenne@agentavow.com)",
        })
    try:
        meta = await _get_json(HF_META.format(name=name), client)
        try:
            tree = await _get_json_list(HF_TREE.format(name=name), client)
        except ArtifactFetchError:
            tree = []

        safe_weights: list[str] = []
        unsafe_weights: list[str] = []
        custom_code: list[str] = []
        text_targets: list[tuple[str, int]] = []
        for entry in tree:
            if not isinstance(entry, dict) or entry.get("type") != "file":
                continue
            path = str(entry.get("path") or "")
            if not path or _is_unsafe_member_name(path):
                continue
            size = int(entry.get("size") or 0)
            ext = ("." + path.rsplit(".", 1)[1].lower()) if "." in path else ""
            if ext in _HF_UNSAFE_WEIGHT_EXT:
                unsafe_weights.append(path)
            elif ext in _HF_SAFE_WEIGHT_EXT:
                safe_weights.append(path)
            if ext == ".py":
                custom_code.append(path)
            if ext in _HF_TEXT_EXT and size <= _HF_MAX_TEXT_BYTES:
                text_targets.append((path, size))

        # Deterministic order (drift-stable), configs/code first, capped.
        text_targets.sort(key=lambda t: (t[0].count("/"), t[0]))
        files: dict[str, ArtifactFile] = {}
        total = 0
        for path, _size in text_targets[:_HF_MAX_TEXT_FILES]:
            raw = await _download_hf_text(
                HF_RESOLVE.format(name=name, path=path), client,
            )
            if raw is None:
                continue
            total += len(raw)
            if total > MAX_UNPACKED_BYTES:
                break
            files[path] = _make_file(path, raw)

        sha = meta.get("sha")
        # HF's `sha` is a 40-hex git commit id (sha1), not a content sha256. Derive a
        # deterministic, offline-recomputable content digest over the file census +
        # every weight-file PATH (their format is the graded signal) so the coverage
        # block gets a stable artifact anchor.
        manifest_lines = [f"{p}:{files[p].sha256}" for p in sorted(files)]
        manifest_lines += [f"weight:{p}" for p in sorted(safe_weights + unsafe_weights)]
        if sha:
            manifest_lines.append(f"commit:{sha}")
        digest = _digest("\n".join(manifest_lines).encode())
        return ArtifactFetchResult(
            ecosystem="huggingface",
            name=name,
            version=version or sha or "main",
            kind="model",
            ok=True,
            digest=digest,
            download_url=f"https://huggingface.co/{name}",
            files=files,
            unpacked_size=sum(f.size for f in files.values()),
            file_count=len(safe_weights) + len(unsafe_weights) + len(files),
            packaged_manifest={"hf": {
                "downloads": meta.get("downloads", 0),
                "likes": meta.get("likes", 0),
                "pipeline_tag": meta.get("pipeline_tag"),
                "library_name": meta.get("library_name"),
                "tags": (meta.get("tags") or [])[:20],
                "sha": sha,
                "gated": meta.get("gated", False),
                "last_modified": meta.get("lastModified"),
                "safe_weights": safe_weights[:50],
                "unsafe_weights": unsafe_weights[:50],
                "custom_code": custom_code[:50],
            }},
            description=_hf_description(
                meta.get("pipeline_tag"), meta.get("library_name"),
            ),
        )
    finally:
        if owns:
            await client.aclose()


def _first_label(labels: dict, *keys: str) -> str | None:
    """First non-empty value among ``keys`` in an OCI image's label map."""
    for k in keys:
        v = labels.get(k)
        if v and isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _hf_description(pipeline_tag: str | None, library: str | None) -> str | None:
    """A short 'what it is' for a HF model from its pipeline tag + library."""
    if not pipeline_tag and not library:
        return None
    tag = (pipeline_tag or "").replace("-", " ").strip()
    lib = (library or "").strip()
    if tag and lib:
        return f"{tag.capitalize()} model ({lib})"
    if tag:
        return f"{tag.capitalize()} model"
    return f"Model ({lib})"


def parse_docker_coordinate(name: str, tag: str | None) -> tuple[str, str, str, str]:
    """(registry_host, repo, tag, display) from a user image coordinate.

    Docker Hub official ``nginx`` → repo ``library/nginx``; ``bitnami/redis`` stays;
    ``ghcr.io/owner/app`` routes to GHCR. An embedded ``:tag`` in ``name`` wins over
    the ``tag`` arg; default ``latest``."""
    name = name.strip().strip("/")
    if ":" in name.rsplit("/", 1)[-1]:  # tag embedded in the last path segment
        name, _, embedded = name.rpartition(":")
        tag = embedded or tag
    tag = (tag or "latest").strip()
    if name.startswith("ghcr.io/"):
        repo = name[len("ghcr.io/"):]
        return GHCR_REGISTRY, repo, tag, f"ghcr.io/{repo}"
    repo = name if "/" in name else f"library/{name}"
    display = repo[len("library/"):] if repo.startswith("library/") else repo
    return DOCKER_REGISTRY, repo, tag, display


async def _docker_token(auth_tmpl: str, repo: str, client: httpx.AsyncClient) -> str | None:
    url = auth_tmpl.format(repo=repo)
    validate_url_https(url, field_name="docker_auth")
    resp = await client.get(url, timeout=_HTTP_TIMEOUT, follow_redirects=False)
    if resp.status_code != 200:
        return None
    return (resp.json() or {}).get("token")


async def _docker_get(
    url: str, client: httpx.AsyncClient, *, token: str | None, accept: str | None = None,
    verify_digest: str | None = None, max_bytes: int = _METADATA_MAX_BYTES,
) -> bytes | None:
    """GET a registry URL following redirects to public https hosts only. When
    ``verify_digest`` is set, the returned bytes must hash to it (content-addressed
    blobs), which is what makes following a CDN redirect safe."""
    cur = url
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if accept:
        headers["Accept"] = accept
    for _hop in range(5):
        validate_url_https(cur, field_name="docker_url")  # https + private-IP/rebind guard
        # Auth header is only sent to the registry host, never to a redirected CDN.
        send = dict(headers)
        if urlparse(cur).hostname not in _ALLOWED_HOSTS:
            send.pop("Authorization", None)
        # STREAM with a hard incremental cap — never materialize an attacker-sized
        # manifest/config blob in memory before checking its length (OOM DoS guard).
        async with client.stream(
            "GET", cur, headers=send, timeout=_DOWNLOAD_TIMEOUT, follow_redirects=False,
        ) as resp:
            if resp.status_code in _REDIRECT_CODES:
                loc = resp.headers.get("location")
                if not loc:
                    return None
                cur = str(httpx.URL(cur).join(loc))
                continue
            if resp.status_code != 200:
                return None
            clen = resp.headers.get("content-length")
            if clen and clen.isdigit() and int(clen) > max_bytes:
                return None  # reject on the advertised size before reading a byte
            buf = bytearray()
            async for chunk in resp.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    return None  # runaway / lying Content-Length → bail mid-stream
            raw = bytes(buf)
        if verify_digest:
            algo, _, hexd = verify_digest.partition(":")
            if algo == "sha256" and hashlib.sha256(raw).hexdigest() != hexd:
                return None
        return raw
    return None


def _pick_platform_manifest(index: dict) -> str | None:
    """From a manifest list / OCI index, pick linux/amd64 (fallback: first non-attestation)."""
    manifests = index.get("manifests") or []
    for m in manifests:
        plat = m.get("platform") or {}
        if plat.get("os") == "linux" and plat.get("architecture") == "amd64":
            return m.get("digest")
    for m in manifests:
        plat = m.get("platform") or {}
        if plat.get("os") not in (None, "unknown"):
            return m.get("digest")
    return manifests[0].get("digest") if manifests else None


async def fetch_docker_artifact(
    name: str, version: str | None = None, *, client: httpx.AsyncClient | None = None,
) -> ArtifactFetchResult:
    """Resolve a container image and fetch its **OCI config** (not its layers).

    The config JSON is where the highest-density security signal lives without a
    layer pull: ``User`` (runs-as-root), ``Env``/``Labels`` (baked secrets),
    ``ExposedPorts``, ``Entrypoint``, and ``created`` (staleness). The config blob
    is content-addressed, so its digest is a perfect offline-recompute anchor.

    Fail-open: raises ``ArtifactFetchError`` on a hard failure."""
    owns = client is None
    if owns:
        client = httpx.AsyncClient(headers={
            "User-Agent": "AgentAvow-ArtifactScanner (safety scanning; kenne@agentavow.com)",
        })
    try:
        registry, repo, tag, display = parse_docker_coordinate(name, version)
        auth = GHCR_AUTH if registry == GHCR_REGISTRY else DOCKER_AUTH
        token = await _docker_token(auth, repo, client)

        man_url = f"{registry}/v2/{repo}/manifests/{tag}"
        man_raw = await _docker_get(man_url, client, token=token, accept=_OCI_MANIFEST_ACCEPT)
        if man_raw is None:
            raise ArtifactFetchError(f"image not found or unauthorized: {display}:{tag}")
        try:
            manifest = json.loads(man_raw)
        except ValueError as exc:
            raise ArtifactFetchError(f"invalid manifest for {display}:{tag}") from exc

        # Multi-arch index → resolve the linux/amd64 child manifest.
        if manifest.get("manifests"):
            child = _pick_platform_manifest(manifest)
            if not child:
                raise ArtifactFetchError(f"no platform manifest for {display}:{tag}")
            man_raw = await _docker_get(
                f"{registry}/v2/{repo}/manifests/{child}", client,
                token=token, accept=_OCI_MANIFEST_ACCEPT, verify_digest=child,
            )
            if man_raw is None:
                raise ArtifactFetchError(f"platform manifest fetch failed: {display}:{tag}")
            manifest = json.loads(man_raw)

        cfg_digest = ((manifest.get("config") or {}).get("digest"))
        if not cfg_digest:
            raise ArtifactFetchError(f"manifest has no config digest: {display}:{tag}")
        cfg_raw = await _docker_get(
            f"{registry}/v2/{repo}/blobs/{cfg_digest}", client,
            token=token, verify_digest=cfg_digest,
        )
        if cfg_raw is None:
            raise ArtifactFetchError(f"config blob fetch failed: {display}:{tag}")
        config = json.loads(cfg_raw)

        layers = manifest.get("layers") or []
        layer_count = len(layers)

        # Bounded full-layer scan: pull + extract the actual filesystem so the engine
        # sees baked secrets/keys and install/entry scripts a config grade can't. Newest
        # layers first (the app's own). Fail-soft: a bad layer is skipped, never fatal.
        files: dict[str, ArtifactFile] = {}
        pulled = 0
        layers_scanned = 0
        for layer in reversed(layers):
            if pulled >= _DOCKER_MAX_LAYER_TOTAL or len(files) >= _DOCKER_MAX_LAYER_FILES:
                break
            if not isinstance(layer, dict):
                continue
            mt = str(layer.get("mediaType") or "")
            dig = layer.get("digest")
            sz = int(layer.get("size") or 0)
            if "gzip" not in mt or not dig or sz > _DOCKER_MAX_ONE_LAYER:
                continue  # skip zstd / oversized / malformed
            raw = await _docker_get(
                f"{registry}/v2/{repo}/blobs/{dig}", client,
                token=token, verify_digest=dig, max_bytes=_DOCKER_MAX_ONE_LAYER,
            )
            if raw is None:
                continue
            pulled += len(raw)
            try:
                for path, af in _build_file_map(_unpack_tar_gz(raw)).items():
                    # A layer's whiteout markers (deleted files) aren't a real surface.
                    if path.rsplit("/", 1)[-1].startswith(".wh."):
                        continue
                    files.setdefault(path, af)
                    if len(files) >= _DOCKER_MAX_LAYER_FILES:
                        break
                layers_scanned += 1
            except ArtifactFetchError:
                continue

        return ArtifactFetchResult(
            ecosystem="docker",
            name=display,
            version=tag,
            kind="image",
            ok=True,
            files=files,
            unpacked_size=sum(f.size for f in files.values()),
            digest=cfg_digest if cfg_digest.startswith("sha256:") else None,
            download_url=(
                f"https://hub.docker.com/r/{repo}" if registry == DOCKER_REGISTRY
                and not repo.startswith("library/")
                else f"https://hub.docker.com/_/{display}" if registry == DOCKER_REGISTRY
                else f"https://{repo}"
            ),
            file_count=len(files) or layer_count,
            packaged_manifest={"docker": {
                "registry": "ghcr" if registry == GHCR_REGISTRY else "dockerhub",
                "repo": repo,
                "tag": tag,
                "config": config.get("config") or {},
                "created": config.get("created"),
                "os": config.get("os"),
                "architecture": config.get("architecture"),
                "layer_count": layer_count,
                "layers_scanned": layers_scanned,
                "history_len": len(config.get("history") or []),
            }},
            description=_first_label(
                (config.get("config") or {}).get("Labels") or {},
                "org.opencontainers.image.description",
                "org.label-schema.description",
                "org.opencontainers.image.title",
            ),
        )
    finally:
        if owns:
            await client.aclose()
