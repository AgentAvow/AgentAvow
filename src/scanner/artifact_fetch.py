"""Phase 2 — fetch + unpack the PUBLISHED artifact (npm tarball / PyPI wheel or sdist).

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
    :data:`MAX_DOWNLOAD_BYTES` and spool to an anonymous temp file, not memory.
    Unpacking is BOUNDED, not all-or-nothing: past the soft budget
    (:data:`MAX_UNPACKED_BYTES` kept, :data:`MAX_FILE_COUNT` members) and for any
    member over :data:`MAX_MEMBER_BYTES`, low-priority members (binaries, media,
    test data) are skipped or evicted so code and manifests are still read, and every
    skip is recorded in ``ArtifactFetchResult.skipped`` (the scan then reports partial
    coverage). It aborts only on a real bomb: an implausible compression ratio, more
    than :data:`HARD_UNPACKED_BYTES` walked or :data:`HARD_ENTRY_COUNT` entries.
    Path-traversal (``..`` / absolute) and non-regular members
    (symlink/hardlink/dev) are rejected.
  * **No execution.** We only read bytes. setup.py / install hooks are inspected
    statically (AST) by :mod:`src.scanner.artifact_scan`, never run.
  * **Fail-closed on abuse, fail-open to the caller.** Guard violations raise
    :class:`ArtifactFetchError`; the orchestrator turns any error into a repo-only
    fallback so a scan is never broken.
"""
from __future__ import annotations

import asyncio
import hashlib
import heapq
import io
import json
import logging
import re
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import IO
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
# --- Container images. The OCI image config carries runs-as-root, secrets baked into
# ENV/labels, stale base and exposed ports; ``src.scanner.docker_layers`` then pulls the
# layers (bounded) for the app's own files and the installed-package inventory. The token
# dance is anonymous pull scope; every blob is content-addressed, so its digest is
# verified even when the registry redirects it to a CDN.
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
# Two kinds of limit. The SOFT budget (bytes kept in memory, members kept) never fails a
# scan: past it, low-priority members (binaries, data, media, tests/docs) are skipped, or
# evicted to make room for code and manifests, and every skip is recorded so the scan
# reports partial coverage honestly. The HARD guards fail the fetch: they only trip on
# an archive that really looks like a bomb (an absurd compression ratio, or more
# decompressed bytes / entries than any real package ships).
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024      # 50MB compressed download ceiling
MAX_UNPACKED_BYTES = 50 * 1024 * 1024      # soft: bytes of member content kept in memory
MAX_FILE_COUNT = 5_000                     # soft: members kept
MAX_MEMBER_BYTES = 8 * 1024 * 1024         # members larger than this are skipped, unread
HARD_UNPACKED_BYTES = 1024 * 1024 * 1024   # hard: total declared size walked (1GB)
HARD_ENTRY_COUNT = 100_000                 # hard: archive entries walked
# Compression-ratio bomb test. Per member (zip, where the compressed size is known) and
# over the whole archive (tar.gz, where it is not); only above a size floor, so a tiny
# file of zeros is not a bomb. Deflate tops out near 1032:1; real code is ~3-20:1.
MAX_MEMBER_RATIO = 250
MAX_ARCHIVE_RATIO = 100
_RATIO_MEMBER_FLOOR = 1024 * 1024          # members under 1MB are never ratio-checked
_RATIO_ARCHIVE_FLOOR = 256 * 1024 * 1024   # archive ratio is checked past 256MB walked
_SPOOL_BYTES = 4 * 1024 * 1024             # downloads past this spool to a temp file
_METADATA_MAX_BYTES = 8 * 1024 * 1024      # packument / pypi json ceiling
# PyPI's project document lists every file of every release (grpcio: ~9MB) and has no
# small "latest" variant, so it gets its own ceiling; versioned documents stay at 8MB.
_PYPI_PROJECT_MAX_BYTES = 32 * 1024 * 1024
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
    # The maintainer's own end-of-life signal: npm `deprecated` on the resolved version,
    # PyPI `yanked` (+ reason) or the 'Development Status :: 7 - Inactive' classifier.
    deprecation: str | None = None
    published_at: str | None = None  # ISO date the resolved version was published
    # The INSTALLED surface, when it differs from the scanned tree: for a PyPI sdist
    # this is the wheel's file list (what `pip install` actually puts on disk). None =
    # unknown (sdist-only package, wheel fetch failed) → everything counts as installed.
    # An npm tarball IS the installed tree, so it stays None there.
    installed_paths: set[str] | None = None
    # Container images only: the layer walk's package inventory, distro, layer summary
    # and the tag's top-level manifest digest (what signatures are made over). Read by
    # ``src.scanner.docker_image`` for the CVE check and cosign provenance.
    image: dict | None = None
    # Members the bounded unpack did not keep (too large, or past the soft budget). Not
    # None means the archive was NOT read whole; ``skipped.scannable`` counts the ones
    # the static engine would have read, which is what makes the scan ``sampled``.
    skipped: SkipReport | None = None
    error: str | None = None


@dataclass
class SkipReport:
    """What a bounded unpack left out, for the honest-coverage disclosure."""

    count: int = 0                  # members not kept
    bytes: int = 0                  # their declared (uncompressed) size
    scannable: int = 0              # of those, files the static engine would have read
    # Source members dropped as too large for the engine's own 500 KB read cap. Not a
    # sampling loss (the engine would skip them anyway) but never read: disclosed as a
    # coverage gap so a payload padded past the cap can't vanish into a clean result.
    oversized_scannable: int = 0
    reasons: dict[str, int] = field(default_factory=dict)   # reason -> count
    examples: list[dict] = field(default_factory=list)      # first few, for display

    _MAX_EXAMPLES = 20

    def add(self, path: str, size: int, reason: str, scannable: bool) -> None:
        self.count += 1
        self.bytes += max(0, int(size))
        if scannable:
            self.scannable += 1
        self.reasons[reason] = self.reasons.get(reason, 0) + 1
        if len(self.examples) < self._MAX_EXAMPLES:
            self.examples.append({"path": path, "size": int(size), "reason": reason})

    def strip_prefix(self, prefix: str) -> None:
        if not prefix:
            return
        for ex in self.examples:
            if ex["path"].startswith(prefix):
                ex["path"] = ex["path"][len(prefix):]

    def summary(self) -> dict:
        out = {
            "count": self.count,
            "bytes": self.bytes,
            "scannable": self.scannable,
            "reasons": dict(sorted(self.reasons.items())),
            "examples": list(self.examples),
        }
        if self.oversized_scannable:
            out["oversized_scannable"] = self.oversized_scannable
        return out


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

async def _get_json(
    url: str, client: httpx.AsyncClient, max_bytes: int | None = None,
) -> dict:
    _validate_registry_url(url)
    resp = await client.get(url, timeout=_HTTP_TIMEOUT, follow_redirects=False)
    if resp.status_code in _REDIRECT_CODES:
        raise ArtifactFetchError(f"unexpected redirect from registry: {url}")
    if resp.status_code == 404:
        raise ArtifactFetchError(f"not found: {url}")
    if resp.status_code != 200:
        raise ArtifactFetchError(f"registry status {resp.status_code} for {url}")
    if len(resp.content) > (max_bytes or _METADATA_MAX_BYTES):
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


async def _download_spooled(url: str, client: httpx.AsyncClient) -> IO[bytes]:
    """Stream-download an artifact with a hard byte cap and no redirect following,
    into a temp file that stays in memory up to :data:`_SPOOL_BYTES` and spills to an
    anonymous on-disk file past it (deleted on close; the OS reclaims it even if the
    process dies). The caller owns the returned file and must close it; it is
    rewound to offset 0."""
    _validate_registry_url(url)
    out = tempfile.SpooledTemporaryFile(max_size=_SPOOL_BYTES)  # noqa: SIM115 — returned
    try:
        size = 0
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
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES:
                    raise ArtifactFetchError("artifact download exceeded size cap")
                out.write(chunk)
        if not size:
            raise ArtifactFetchError("empty artifact download")
        out.seek(0)
        return out
    except BaseException:
        out.close()
        raise


async def _download(url: str, client: httpx.AsyncClient) -> bytes:
    """:func:`_download_spooled`, read into memory (small artifacts and tests)."""
    with await _download_spooled(url, client) as fh:
        return fh.read()


def _digest(raw: bytes | IO[bytes]) -> str:
    """``sha256:<hex>`` of the artifact bytes; a file is hashed in chunks from offset 0
    and rewound afterwards."""
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return "sha256:" + hashlib.sha256(raw).hexdigest()
    h = hashlib.sha256()
    raw.seek(0)
    for chunk in iter(lambda: raw.read(1024 * 1024), b""):
        h.update(chunk)
    raw.seek(0)
    return "sha256:" + h.hexdigest()


def _archive_size(raw: bytes | IO[bytes]) -> int:
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return len(raw)
    pos = raw.tell()
    raw.seek(0, io.SEEK_END)
    size = raw.tell()
    raw.seek(pos)
    return size


def _as_fileobj(raw: bytes | IO[bytes]) -> IO[bytes]:
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return io.BytesIO(raw)
    raw.seek(0)
    return raw


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


def _common_prefix(names) -> str:
    """The single shared top-level directory (npm ``package/``, sdist
    ``<name>-<ver>/``) with its trailing slash, or ``""`` when members do not all
    share one (or any member sits at the archive root)."""
    tops: set[str] = set()
    for p in names:
        if "/" not in p:
            return ""
        tops.add(p.split("/", 1)[0])
        if len(tops) > 1:
            return ""
    return (next(iter(tops)) + "/") if tops else ""


def _strip_common_prefix(raw_files: dict[str, bytes]) -> dict[str, bytes]:
    """Strip a single shared top-level directory (npm ``package/``, sdist
    ``<name>-<ver>/``) so artifact paths line up with repo-relative paths."""
    if not raw_files:
        return raw_files
    prefix = _common_prefix(raw_files)
    if prefix:
        return {p[len(prefix):]: b for p, b in raw_files.items() if p != prefix.rstrip("/")}
    return raw_files


# --- Member priority for the bounded unpack ------------------------------------------
# Lower tier = kept first. When the soft budget is full, a member only displaces members
# of a strictly worse tier (largest first), so code and manifests always win over test
# data, binaries and media, whatever order the archive lists them in.
TIER_MANIFEST = 0   # install surface + metadata: package.json, setup.py, pyproject, README
TIER_CODE = 1       # executable source the static engine reads
TIER_TEXT = 2       # other text: data formats, tests, docs, examples
TIER_BULK = 3       # binaries, native libraries, media, fonts, archives, test data blobs

_MANIFEST_NAMES = frozenset({
    "package.json", "setup.py", "setup.cfg", "pyproject.toml", "requirements.txt",
    "pipfile", "cargo.toml", "build.rs", "binding.gyp", "manifest.in", "pkg-info",
    "metadata", "entry_points.txt", "top_level.txt", "wheel", "record",
    "npm-shrinkwrap.json", ".agentavow.yml", ".agentavow.yaml", "mcp.json",
    "server.json", "smithery.yaml", "skill.md",
})
_MANIFEST_PREFIXES = ("readme", "license", "licence", "copying", "notice")
# Never read by the static engine (it only reads text source). Native code, compiled
# objects, media, fonts, archives and data blobs.
_BULK_EXTS = frozenset({
    ".so", ".dylib", ".pyd", ".dll", ".node", ".wasm", ".a", ".lib", ".o", ".obj",
    ".exe", ".bin", ".dat", ".pyc", ".pyo", ".class", ".jar", ".whl", ".egg",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".tif", ".tiff", ".mpo",
    ".psd", ".icns", ".heic", ".avif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".afm", ".pfb",
    ".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".zst", ".7z", ".lz4",
    ".mp3", ".mp4", ".wav", ".ogg", ".flac", ".avi", ".mov", ".webm",
    ".pdf", ".npy", ".npz", ".pkl", ".pickle", ".h5", ".hdf5", ".parquet", ".feather",
    ".arrow", ".db", ".sqlite", ".sqlite3", ".mat", ".nc", ".fits", ".fit", ".mo",
    ".onnx", ".pt", ".pth", ".safetensors", ".tflite", ".pb", ".ckpt",
})
# Scanner-read formats that are data rather than code: kept after code, before bulk.
_DATA_TEXT_EXTS = frozenset({
    ".json", ".yaml", ".yml", ".toml", ".xml", ".html", ".htm", ".svg", ".ipynb",
    ".cfg", ".ini", ".conf", ".env",
})


def _scan_helpers():
    """The repo scanner's path predicates (lazy: ``scan`` imports this module)."""
    from src.scanner.patterns import SKIP_EXTENSIONS
    from src.scanner.scan import (
        _MAX_FILE_SIZE,
        _is_git_config_file,
        _is_git_hook_file,
        _is_source_file,
        _is_test_or_doc_file,
    )
    return (SKIP_EXTENSIONS, _MAX_FILE_SIZE, _is_git_config_file, _is_git_hook_file,
            _is_source_file, _is_test_or_doc_file)


def _member_class(name: str) -> tuple[int, bool]:
    """``(tier, scannable)`` for an archive member path. ``scannable`` = the static
    engine would read this file (a manifest, or non-test/doc source) — the files whose
    absence makes a scan partial. Conservative: it may count a file the engine would
    still skip for another reason, never the reverse."""
    (skip_exts, _max, is_git_config, is_git_hook, is_source,
     is_test_or_doc) = _scan_helpers()
    p = PurePosixPath(name.replace("\\", "/"))
    base = p.name.lower()
    ext = p.suffix.lower()
    if (base in _MANIFEST_NAMES or base.endswith(".pth")
            or base.startswith(_MANIFEST_PREFIXES)
            or is_git_config(name) or is_git_hook(name)):
        return TIER_MANIFEST, True
    if ext in _BULK_EXTS:
        return TIER_BULK, False
    test_or_doc = is_test_or_doc(name)
    source = is_source(name) and ext not in skip_exts and ".min." not in base
    if source and not test_or_doc:
        return (TIER_TEXT if ext in _DATA_TEXT_EXTS else TIER_CODE), True
    if test_or_doc and not source:
        return TIER_BULK, False  # test fixtures / doc assets: the first thing to drop
    return TIER_TEXT, False


class _BoundedMembers:
    """Members kept under the soft budget, with priority eviction and the hard bomb
    guards. Peak memory is about ``MAX_UNPACKED_BYTES`` plus one member."""

    def __init__(self, archive_size: int, report: SkipReport) -> None:
        self.archive_size = max(1, archive_size)
        self.report = report
        self.kept: dict[str, bytes] = {}
        self.meta: dict[str, tuple[int, bool]] = {}      # name -> (tier, scannable)
        self.kept_bytes = 0
        self.tier_bytes = [0, 0, 0, 0]
        self.tier_count = [0, 0, 0, 0]
        self.heaps: list[list[tuple[int, str]]] = [[], [], [], []]  # (-size, name)
        self.walked_bytes = 0
        self.entries = 0

    # -- hard guards (raise) -----------------------------------------------------
    def walk(self, name: str, size: int, compressed: int | None = None) -> None:
        """Account one archive entry before anything is read. Raises on a bomb."""
        self.entries += 1
        if self.entries > HARD_ENTRY_COUNT:
            raise ArtifactFetchError(
                f"archive has more than {HARD_ENTRY_COUNT:,} entries (zip bomb?)")
        size = max(0, int(size))
        self.walked_bytes += size
        if self.walked_bytes > HARD_UNPACKED_BYTES:
            raise ArtifactFetchError("archive decompresses past the hard ceiling (zip bomb?)")
        if (compressed is not None and size >= _RATIO_MEMBER_FLOOR
                and size > MAX_MEMBER_RATIO * max(1, compressed)):
            raise ArtifactFetchError(
                f"member compression ratio is implausible (zip bomb?): {name}")
        if (self.walked_bytes >= _RATIO_ARCHIVE_FLOOR
                and self.walked_bytes > MAX_ARCHIVE_RATIO * self.archive_size):
            raise ArtifactFetchError("archive compression ratio is implausible (zip bomb?)")

    # -- soft budget (skip / evict, never raise) -----------------------------------
    def admit(self, name: str, size: int) -> bool:
        """Decide BEFORE reading whether a member can be kept, evicting worse-tier
        members to make room. A refused member is recorded as skipped."""
        tier, scannable = _member_class(name)
        if size > MAX_MEMBER_BYTES:
            # The engine skips text past its own (much smaller) file cap, so an oversize
            # file is not a coverage loss for scanning; it is still disclosed.
            self.report.add(name, size, "too large", scannable and size <= _scan_helpers()[1])
            if scannable and size > _scan_helpers()[1]:
                self.report.oversized_scannable += 1
            return False
        over_bytes = self.kept_bytes + size - MAX_UNPACKED_BYTES
        over_count = len(self.kept) + 1 - MAX_FILE_COUNT
        if over_bytes > 0 or over_count > 0:
            worse_bytes = sum(self.tier_bytes[t] for t in range(tier + 1, 4))
            worse_count = sum(self.tier_count[t] for t in range(tier + 1, 4))
            if worse_bytes < over_bytes or worse_count < over_count:
                self.report.add(name, size, "over budget", scannable)
                return False
            for t in range(3, tier, -1):          # worst tier first, largest first
                heap = self.heaps[t]
                while heap and (over_bytes > 0 or over_count > 0):
                    _neg, victim = heapq.heappop(heap)
                    freed = self._evict(victim, t)
                    if freed is not None:
                        over_bytes -= freed
                        over_count -= 1
        self.meta[name] = (tier, scannable)
        return True

    def keep(self, name: str, data: bytes) -> None:
        tier, _scannable = self.meta[name]
        if name in self.kept:  # duplicate member name: last one wins, like extraction
            old = len(self.kept[name])
            self.kept_bytes -= old
            self.tier_bytes[tier] -= old
            self.tier_count[tier] -= 1
        self.kept[name] = data
        self.kept_bytes += len(data)
        self.tier_bytes[tier] += len(data)
        self.tier_count[tier] += 1
        heapq.heappush(self.heaps[tier], (-len(data), name))

    def drop(self, name: str, size: int) -> None:
        """An admitted member that could not be read after all (recorded)."""
        _tier, scannable = self.meta.pop(name, (TIER_TEXT, False))
        if name not in self.kept:
            self.report.add(name, size, "unreadable", scannable)

    def _evict(self, name: str, tier: int) -> int | None:
        """Evict a kept member; returns the bytes freed (None if it was already gone,
        e.g. a stale heap entry left by a duplicate member name)."""
        data = self.kept.pop(name, None)
        if data is None:
            return None
        _t, scannable = self.meta.pop(name, (tier, False))
        self.kept_bytes -= len(data)
        self.tier_bytes[tier] -= len(data)
        self.tier_count[tier] -= 1
        self.report.add(name, len(data), "over budget", scannable)
        return len(data)


def _unpack_tar_gz(raw: bytes | IO[bytes], report: SkipReport | None = None,
                   ) -> dict[str, bytes]:
    """Unpack a gzipped tar, bounded. Members past the soft budget are skipped (into
    ``report``); only a bomb, a path-traversal or a malformed archive raises."""
    report = report if report is not None else SkipReport()
    try:
        tf = tarfile.open(fileobj=_as_fileobj(raw), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ArtifactFetchError(f"not a valid gzip tar: {exc}") from exc
    box = _BoundedMembers(_archive_size(raw), report)
    with tf:
        while True:
            try:
                member = tf.next()
            except (tarfile.TarError, OSError, EOFError) as exc:
                raise ArtifactFetchError(f"corrupt tar archive: {exc}") from exc
            if member is None:
                break
            box.walk(member.name, member.size if member.isfile() else 0)
            if not member.isfile():
                # Skip dirs, and REFUSE symlinks/hardlinks/devices outright.
                continue
            if _is_unsafe_member_name(member.name):
                raise ArtifactFetchError(f"unsafe member path: {member.name!r}")
            if not box.admit(member.name, member.size):
                continue
            try:
                fobj = tf.extractfile(member)
                data = fobj.read(MAX_MEMBER_BYTES + 1) if fobj else b""
            except (tarfile.TarError, OSError):
                box.drop(member.name, member.size)
                continue
            if len(data) > member.size:
                raise ArtifactFetchError(f"member larger than its header: {member.name}")
            box.keep(member.name, data)
    return box.kept


def _unpack_zip(raw: bytes | IO[bytes], report: SkipReport | None = None,
                ) -> dict[str, bytes]:
    """Unpack a zip / wheel, bounded. The central directory gives every member's sizes
    up front, so the bomb checks run before any byte is inflated and members are read in
    priority order (manifests and code first)."""
    report = report if report is not None else SkipReport()
    try:
        zf = zipfile.ZipFile(_as_fileobj(raw))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArtifactFetchError(f"not a valid zip/wheel: {exc}") from exc
    box = _BoundedMembers(_archive_size(raw), report)
    with zf:
        infos = []
        for info in zf.infolist():
            name = info.filename
            is_dir = name.endswith("/")
            box.walk(name, 0 if is_dir else info.file_size,
                     None if is_dir else info.compress_size)
            if is_dir:
                continue  # directory entry
            if _is_unsafe_member_name(name):
                raise ArtifactFetchError(f"unsafe member path: {name!r}")
            infos.append(info)
        # Read in priority order so the budget goes to what the engine reads; ties keep
        # archive order (stable sort), so the result is deterministic.
        infos.sort(key=lambda i: _member_class(i.filename)[0])
        for info in infos:
            name = info.filename
            if not box.admit(name, info.file_size):
                continue
            try:
                with zf.open(info) as fh:
                    data = fh.read(MAX_MEMBER_BYTES + 1)
            except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
                box.drop(name, info.file_size)
                continue
            if len(data) > info.file_size:
                raise ArtifactFetchError(f"member larger than its header: {name}")
            box.keep(name, data)
    return box.kept


def _build_file_map(raw_files: dict[str, bytes],
                    report: SkipReport | None = None) -> dict[str, ArtifactFile]:
    """Turn unpacked members into :class:`ArtifactFile` s (prefix stripped). Consumes
    ``raw_files`` as it goes, so the raw bytes and the decoded text are never both held
    for the whole tree. ``report`` (skipped members) gets the same prefix stripped."""
    names = list(raw_files)
    if report is not None and report.examples:
        names += [ex["path"] for ex in report.examples]
    prefix = _common_prefix(names) if raw_files else ""
    if report is not None:
        report.strip_prefix(prefix)
    out: dict[str, ArtifactFile] = {}
    for path in list(raw_files):
        data = raw_files.pop(path)
        if prefix and path == prefix.rstrip("/"):
            continue
        rel = path[len(prefix):] if prefix else path
        out[rel] = _make_file(rel, data)
    return out


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
        packument: dict = {}
        vdata: dict | None = None
        try:
            packument = await _get_json(f"{NPM_REGISTRY}/{name}", client)
        except ArtifactFetchError as exc:
            # A giant packument (typescript, vite: every version ever published) trips
            # the metadata size cap. The per-version document is small — fall back to
            # it; only the `time` map (published_at) is lost.
            if "size cap" not in str(exc):
                raise
            vdata = await _get_json(f"{NPM_REGISTRY}/{name}/{version or 'latest'}", client)
            version = str(vdata.get("version") or version or "")
            if not version:
                raise ArtifactFetchError(f"no version for npm:{name}") from exc
        if vdata is None:
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

        published_at = str((packument.get("time") or {}).get(version) or "")[:10] or None
        with await _download_spooled(tarball, client) as raw:
            # Unpack + hash is CPU-bound: off the event loop.
            return await asyncio.to_thread(
                npm_result_from_tarball, name, version, raw, tarball_url=tarball,
                vdata=vdata, published_at=published_at,
            )
    finally:
        if owns:
            await client.aclose()


def npm_result_from_tarball(
    name: str, version: str, raw: bytes | IO[bytes], *, tarball_url: str | None = None,
    vdata: dict | None = None, published_at: str | None = None,
) -> ArtifactFetchResult:
    """Unpack a downloaded npm tarball into the result ``fetch_npm_artifact`` returns.
    Pure (no network): the static corpus runner builds the identical result from cached
    bytes, so the gate scans exactly what production scans."""
    report = SkipReport()
    files = _build_file_map(_unpack_tar_gz(raw, report), report)

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
        download_url=tarball_url,
        files=files,
        **_size_fields(files, report),
        packaged_manifest=packaged_manifest,
        description=(packaged_manifest or {}).get("description"),
        deprecation=_npm_deprecation(vdata or {}),
        published_at=published_at,
    )


def _size_fields(files: dict[str, ArtifactFile], report: SkipReport) -> dict:
    """``unpacked_size`` / ``file_count`` describe the WHOLE artifact (kept + skipped
    members), and ``skipped`` is set only when something was left out."""
    return {
        "unpacked_size": sum(f.size for f in files.values()) + report.bytes,
        "file_count": len(files) + report.count,
        "skipped": report if report.count else None,
    }


# ---------------------------------------------------------------------------
# PyPI resolve + fetch
# ---------------------------------------------------------------------------

def _pick_pypi_url(urls: list[dict]) -> tuple[str, str] | None:
    """The file a PyPI scan reads: a WHEEL when one fits the download cap (what ``pip
    install`` actually puts on disk, and far smaller unpacked than the sdist of a big
    package like numpy or botocore), else the sdist.

    Wheel order: the pure-Python ``*-none-any`` wheel (platform independent), else the
    smallest platform wheel (the Python sources are the same in every platform build;
    the native parts differ and are never read). Ties break on the URL, so the pick is
    deterministic. Returns ``(url, kind)`` where kind is ``"wheel"`` or ``"sdist"``.
    """
    sdist, wheel = _pypi_sdist_and_wheel(urls)
    if wheel:
        return wheel, "wheel"
    if sdist:
        return sdist, "sdist"
    # Every file is over the cap: try the smallest wheel anyway (the download cap then
    # reports the real reason), else nothing.
    over = _wheel_candidates(urls, fits_only=False)
    return (over[0][2], "wheel") if over else None


def _pypi_size(u: dict) -> int:
    try:
        return int(u.get("size") or 0)
    except (TypeError, ValueError):
        return 0


def _wheel_candidates(urls: list[dict], *, fits_only: bool = True,
                      ) -> list[tuple[int, int, str]]:
    """``(not_pure, size, url)`` for every wheel, best first. ``fits_only`` drops wheels
    whose listed size is over :data:`MAX_DOWNLOAD_BYTES` (an unknown size counts as
    fitting; the download cap still applies)."""
    out = []
    for u in urls or []:
        if not isinstance(u, dict) or u.get("packagetype") != "bdist_wheel":
            continue
        url = u.get("url")
        if not url or u.get("yanked"):
            continue
        size = _pypi_size(u)
        if fits_only and size > MAX_DOWNLOAD_BYTES:
            continue
        filename = str(u.get("filename") or url.rsplit("/", 1)[-1])
        pure = filename.endswith("-none-any.whl")
        out.append((0 if pure else 1, size, url))
    out.sort()
    return out


def _pypi_sdist_and_wheel(urls: list[dict]) -> tuple[str | None, str | None]:
    """``(sdist_url, wheel_url)`` from a PyPI release's ``urls`` list. The wheel is the
    best one under the download cap (see :func:`_pick_pypi_url`); the sdist is the first
    one listed that fits (or the first one at all)."""
    sdist = None
    sdist_any = None
    for u in urls or []:
        if not isinstance(u, dict) or u.get("packagetype") != "sdist" or not u.get("url"):
            continue
        if sdist_any is None:
            sdist_any = u["url"]
        if sdist is None and _pypi_size(u) <= MAX_DOWNLOAD_BYTES:
            sdist = u["url"]
    wheels = _wheel_candidates(urls)
    return (sdist or sdist_any), (wheels[0][2] if wheels else None)


_WHEEL_META_DIR_RE = re.compile(r"^[^/]+\.(?:dist-info|data)/")


def _wheel_installed_paths(namelist: list[str]) -> set[str]:
    """Normalize a wheel's member list to the paths a consumer ends up with: metadata
    (``*.dist-info/``) is dropped; ``*.data/<kind>/`` prefixes are stripped (scripts /
    headers / data land outside the package dir)."""
    out: set[str] = set()
    for name in namelist:
        if not name or name.endswith("/"):
            continue
        if ".dist-info/" in name:
            continue
        m = re.match(r"^[^/]+\.data/[^/]+/(.+)$", name)
        out.add(m.group(1) if m else name)
    return out


def is_installed_path(path: str, installed: set[str] | None) -> bool:
    """Is an sdist file part of the installed (wheel) tree? ``installed`` None = unknown
    → True (conservative). Handles the ``src/`` / ``lib/`` layouts, where the sdist
    nests the package one level deeper than the wheel."""
    if installed is None:
        return True
    if path in installed:
        return True
    for prefix in ("src/", "lib/", "python/"):
        if path.startswith(prefix) and path[len(prefix):] in installed:
            return True
    return False


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
            meta = await _get_json(
                PYPI_JSON.format(name=name), client, max_bytes=_PYPI_PROJECT_MAX_BYTES,
            )
            version = (meta.get("info") or {}).get("version")
            if not version:
                raise ArtifactFetchError(f"no version for pypi:{name}")
        picked = _pick_pypi_url(meta.get("urls") or [])
        if not picked:
            raise ArtifactFetchError(f"no downloadable sdist/wheel for {name}=={version}")
        url, kind = picked

        with await _download_spooled(url, client) as raw:
            installed_paths = await _sdist_installed_paths(name, version, kind, meta, client)
            # Unpack + hash is CPU-bound: off the event loop.
            return await asyncio.to_thread(
                pypi_result_from_archive, name, version, kind, url, raw,
                installed_paths=installed_paths, meta=meta,
            )
    finally:
        if owns:
            await client.aclose()


async def _sdist_installed_paths(
    name: str, version: str, kind: str, meta: dict, client: httpx.AsyncClient,
) -> set[str] | None:

    """Installed surface (precision pass #1): when we scan the sdist but the consumer
    installs a wheel, read the wheel's member list (central directory only — nothing is
    unpacked or executed) so findings in files pip never puts on disk (scripts/, bench/,
    Makefile, _cffi_src/) are informational. Since wheels are scanned first this only
    runs when no wheel fits the cap, so it usually finds none. Fail-open: any error
    leaves None → everything counts as installed."""
    if kind != "sdist":
        return None
    _sd, wheel_url = _pypi_sdist_and_wheel(meta.get("urls") or [])
    if not wheel_url:
        return None
    try:
        with await _download_spooled(wheel_url, client) as wraw:
            return wheel_installed_paths_from_bytes(wraw)
    except (ArtifactFetchError, zipfile.BadZipFile, OSError, httpx.HTTPError) as exc:
        logger.info("wheel namelist unavailable for %s==%s: %s", name, version, exc)
        return None


def wheel_installed_paths_from_bytes(wheel_raw: bytes | IO[bytes]) -> set[str]:
    """The installed-path set from a wheel's central directory (nothing is unpacked).
    Raises ``zipfile.BadZipFile`` / ``OSError`` on a bad archive."""
    with zipfile.ZipFile(_as_fileobj(wheel_raw)) as zf:
        return _wheel_installed_paths(zf.namelist())


def pypi_result_from_archive(
    name: str, version: str, kind: str, url: str, raw: bytes | IO[bytes], *,
    installed_paths: set[str] | None, meta: dict | None = None,
) -> ArtifactFetchResult:
    """Unpack a downloaded sdist/wheel into the result ``fetch_pypi_artifact`` returns.
    Pure (no network): the static corpus runner builds the identical result from cached
    bytes."""
    meta = meta or {}
    report = SkipReport()
    if kind == "wheel" or url.endswith(".zip") or url.endswith(".whl"):
        raw_files = _unpack_zip(raw, report)
    else:
        raw_files = _unpack_tar_gz(raw, report)  # sdist .tar.gz
    files = _build_file_map(raw_files, report)
    return ArtifactFetchResult(
        ecosystem="pypi",
        name=name,
        version=version,
        kind=kind,
        ok=True,
        digest=_digest(raw),
        download_url=url,
        files=files,
        **_size_fields(files, report),
        description=(meta.get("info") or {}).get("summary"),
        # The source repo the project declares (project_urls / home_page): what a
        # PEP 740 Trusted Publisher identity is compared against for Certified.
        packaged_manifest=_pypi_declared_manifest(meta),
        deprecation=_pypi_deprecation(meta),
        published_at=_pypi_published(meta, url),
        installed_paths=installed_paths,
    )


def _pypi_declared_manifest(meta: dict) -> dict | None:
    from src.scanner.provenance import declared_repo_from_pypi_meta
    repo = declared_repo_from_pypi_meta(meta)
    return {"declared_repository": repo} if repo else None


def _pypi_published(meta: dict, url: str) -> str | None:
    for u in (meta or {}).get("urls") or []:
        if u.get("url") == url and u.get("upload_time"):
            return str(u["upload_time"])[:10]
    return None


def _npm_deprecation(vdata: dict) -> str | None:
    """npm marks a version deprecated with a string message (or, rarely, ``true``)."""
    dep = (vdata or {}).get("deprecated")
    if dep is True:
        return "deprecated by its maintainer"
    if isinstance(dep, str) and dep.strip():
        return dep.strip()[:300]
    return None


def _pypi_deprecation(meta: dict) -> str | None:
    """PyPI has no 'deprecated' flag: a yanked release, or the maintainer's own
    'Development Status :: 7 - Inactive' classifier, is the equivalent signal."""
    info = (meta or {}).get("info") or {}
    if info.get("yanked"):
        reason = str(info.get("yanked_reason") or "").strip()
        return f"release yanked: {reason[:280]}" if reason else "release yanked by its maintainer"
    classifiers = info.get("classifiers") or []
    if any(str(c).strip() == "Development Status :: 7 - Inactive" for c in classifiers):
        return "marked inactive by its maintainer (Development Status :: 7 - Inactive)"
    return None


def _unpack_crate(raw: IO[bytes], report: SkipReport) -> tuple[str, dict[str, ArtifactFile]]:
    return _digest(raw), _build_file_map(_unpack_tar_gz(raw, report), report)


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
        report = SkipReport()
        with await _download_spooled(url, client) as raw:
            # a .crate is a gzipped tar; unpack + hash off the event loop
            digest, files = await asyncio.to_thread(_unpack_crate, raw, report)
        vrow = next((v for v in (meta.get("versions") or [])
                     if isinstance(v, dict) and v.get("num") == version), {})
        return ArtifactFetchResult(
            ecosystem="crates",
            published_at=str(vrow.get("created_at") or "")[:10] or None,
            packaged_manifest={
                "repository": crate.get("repository") or None,
                "homepage": crate.get("homepage") or None,
                "license": vrow.get("license") or None,
            },
            name=name,
            version=version,
            kind="crate",
            ok=True,
            digest=digest,
            download_url=url,
            files=files,
            **_size_fields(files, report),
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

        # ``.bin`` is ambiguous (PyTorch pickle vs OpenVINO raw tensors): classify
        # each by its first bytes so raw weights aren't flagged as executable.
        from src.scanner.hf_facts import PICKLE, ZIP_PICKLE, classify_weights, license_from_meta
        all_paths = {str(e.get("path") or "") for e in tree if isinstance(e, dict)}
        formats = await classify_weights(name, unsafe_weights, all_paths, client)
        raw_weights = [p for p in unsafe_weights
                       if formats.get(p) not in (None, PICKLE, ZIP_PICKLE)]
        unsafe_weights = [p for p in unsafe_weights if p not in raw_weights]

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
        manifest_lines += [f"weight:{p}" for p in sorted(safe_weights + unsafe_weights
                                                           + raw_weights)]
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
                "raw_weights": raw_weights[:50],
                "custom_code": custom_code[:50],
                "license": license_from_meta(meta),
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
    """Resolve a container image, fetch its **OCI config**, and walk its **layers**.

    The config JSON carries ``User`` (runs-as-root), ``Env``/``Labels`` (baked secrets),
    ``ExposedPorts``, ``Entrypoint`` and ``created`` (staleness). The layer walk
    (:func:`src.scanner.docker_layers.scan_image_layers`, bounded) adds the app's own
    files for the static engine and the installed-package inventory for the CVE check.
    When the layers are over budget the result keeps the config grade and says so
    (``image.layers.depth`` = ``partial`` / ``config``). The config blob is
    content-addressed, so its digest is the offline-recompute anchor.

    Fail-open: raises ``ArtifactFetchError`` on a hard failure."""
    from src.scanner.docker_layers import scan_image_layers

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
        # The tag's top-level manifest (often a multi-arch index): signatures and
        # `image@sha256:` pins refer to this digest.
        index_digest = "sha256:" + hashlib.sha256(man_raw).hexdigest()
        try:
            manifest = json.loads(man_raw)
        except ValueError as exc:
            raise ArtifactFetchError(f"invalid manifest for {display}:{tag}") from exc
        has_build_attestation = any(
            ((m.get("annotations") or {}).get("vnd.docker.reference.type")
             == "attestation-manifest")
            for m in (manifest.get("manifests") or []) if isinstance(m, dict)
        )

        # Multi-arch index → resolve the linux/amd64 child manifest.
        platform_digest = index_digest
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
            platform_digest = child

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

        layers = [ly for ly in (manifest.get("layers") or []) if isinstance(ly, dict)]
        layer_count = len(layers)
        walked = await scan_image_layers(
            registry, repo, layers, token=token, client=client,
            allowed_hosts=_ALLOWED_HOSTS,
        )
        files = walked.files
        layers_scanned = walked.layers_scanned
        labels = (config.get("config") or {}).get("Labels") or {}
        image_info = {
            "registry": "ghcr" if registry == GHCR_REGISTRY else "dockerhub",
            "repo": repo,
            "tag": tag,
            "index_digest": index_digest,
            "platform_digest": platform_digest,
            "has_build_attestation": has_build_attestation,
            "source_label": _first_label(
                labels, "org.opencontainers.image.source", "org.label-schema.vcs-url",
            ),
            "os_release": walked.os_release,
            "packages": walked.packages,
            "layers": walked.summary(),
        }

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
                "scan_depth": walked.depth,
                "history_len": len(config.get("history") or []),
            }},
            image=image_info,
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
