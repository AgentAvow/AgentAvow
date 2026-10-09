"""Container image layer scan — pull an image's filesystem layers and read them as data.

``fetch_docker_artifact`` resolves the image manifest and config; this module pulls the
layers themselves, verifies each against its content digest, and walks the tar stream to
collect two things:

* **The app's own files** — text files outside the base-OS and third-party trees
  (``/app``, ``/srv``, ``/opt``, entrypoint scripts, ``/etc`` config …), which the
  12-category static engine then grades like any other artifact.
* **The installed package inventory** — OS packages from ``var/lib/dpkg/status`` (Debian,
  Ubuntu, distroless ``status.d``) or ``lib/apk/db/installed`` (Alpine), plus Python
  ``*.dist-info`` and npm ``node_modules/*/package.json`` — for the OSV CVE check in
  :mod:`src.scanner.docker_image`.

Nothing in an image is ever executed, installed or written outside a private temp file.

Bounded by design (prod is one EC2 box; a scan runs inside the web worker):
  * each layer is streamed to a temp file (memory stays flat) with a per-layer and a
    total compressed-byte cap, and verified against its sha256 digest before it is read;
  * the decompressed bytes walked are capped per image (a gzip bomb stops at the cap);
  * a wall-clock budget covers the whole layer phase, checked between layers and
    between tar members;
  * the CPU-bound tar walk runs in a worker thread, never on the event loop.
When a budget runs out the scan keeps what it read and says so: ``depth`` becomes
``partial`` (some layers read) or ``config`` (none), with a plain-English ``reason``.

Layers are walked newest first, so the app's own layers are read before the base OS and
an upper layer's file shadows the same path below it. Whiteouts (``.wh.<name>`` and the
opaque ``.wh..wh..opq``) hide lower-layer paths exactly as the container runtime would.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import posixpath
import re
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from src.ssrf import validate_url_https

logger = logging.getLogger(__name__)

# --- Budgets ---------------------------------------------------------------------------
MAX_LAYER_COMPRESSED = 160 * 1024 * 1024      # one layer's download (streamed to disk)
MAX_TOTAL_COMPRESSED = 400 * 1024 * 1024      # all layers' downloads
MAX_TOTAL_WALKED = 1536 * 1024 * 1024         # decompressed tar bytes walked (bomb guard)
# The whole image scan must finish inside the router's scan timeout (60 s on the badge
# path): layers 35 s + CVE check 12 s + signatures 8 s + manifest/config leaves headroom.
LAYER_TIME_BUDGET = 35.0                      # seconds for the whole layer phase
MAX_APP_FILES = 800                           # app files handed to the static engine
MAX_APP_FILE_BYTES = 512 * 1024               # largest single app file read
MAX_APP_BYTES = 48 * 1024 * 1024              # all app-file candidates held in memory
MAX_DB_BYTES = 16 * 1024 * 1024               # a package database (dpkg status, apk)
MAX_MANIFEST_BYTES = 256 * 1024               # an npm package.json
MAX_PACKAGES = 4000                           # inventory entries kept
_DOWNLOAD_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_CHUNK = 1024 * 1024

_GZIP_TYPES = ("tar+gzip", "tar.gzip", "rootfs.diff.tar.gzip")
_PLAIN_TYPES = ("image.layer.v1.tar", "rootfs.diff.tar")
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

# Base-OS and third-party trees: their files are the distro's or a dependency's, not the
# image author's. Their packages are inventoried (CVE check) instead of graded as code.
_SKIP_PREFIXES = (
    "proc/", "sys/", "dev/", "boot/", "run/", "tmp/", "mnt/", "media/", "srv/tmp/",
    "var/lib/", "var/cache/", "var/log/", "var/tmp/", "var/spool/", "var/mail/",
    "var/backups/", "usr/share/", "usr/lib/", "usr/lib32/", "usr/lib64/", "usr/libx32/",
    "lib/", "lib32/", "lib64/", "libx32/", "usr/include/", "usr/libexec/", "usr/games/",
    "bin/", "sbin/", "usr/bin/", "usr/sbin/", "usr/local/include/", "usr/local/lib/",
    "usr/local/share/", "usr/local/go/", "usr/local/cargo/", "usr/local/rustup/",
    "usr/local/libexec/", "usr/src/linux", "nix/store/", "opt/conda/pkgs/",
    "opt/yarn-", "opt/java/", "opt/venv/lib/",
    "root/.cache/", "root/.npm/", "root/.cargo/", "root/.rustup/", "root/.local/lib/",
    "etc/ssl/certs/", "etc/ca-certificates/", "etc/alternatives/", "etc/apt/",
    "etc/dpkg/", "etc/pam.d/", "etc/security/", "etc/selinux/", "etc/systemd/",
    "etc/init.d/", "etc/rc", "etc/cron", "etc/logrotate.d/", "etc/X11/", "etc/fonts/",
    "etc/ld.so", "etc/apk/", "etc/update-motd.d/", "etc/skel/", "etc/terminfo/",
)
_SKIP_SEGMENTS = (
    "/node_modules/", "/site-packages/", "/dist-packages/", "/__pycache__/", "/.git/",
    "/vendor/bundle/", "/.cache/", "/gems/",
)
_BINARY_EXT = frozenset({
    ".so", ".a", ".o", ".dylib", ".dll", ".exe", ".bin", ".pyc", ".pyo", ".class",
    ".jar", ".war", ".whl", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".zip", ".7z", ".png",
    ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".woff", ".woff2", ".ttf", ".otf",
    ".mo", ".db", ".sqlite", ".wasm", ".node", ".deb", ".rpm", ".apk",
})
_OS_RELEASE = ("etc/os-release", "usr/lib/os-release")
_DPKG_STATUS = "var/lib/dpkg/status"
_DPKG_STATUS_D = "var/lib/dpkg/status.d/"
_APK_INSTALLED = "lib/apk/db/installed"
_DIST_INFO_RE = re.compile(
    r"(?:^|/)(?:site|dist)-packages/([A-Za-z0-9_.]+?)-([^/-]+)\.dist-info/METADATA$",
)
_NPM_MANIFEST_RE = re.compile(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/@][^/]*)/package\.json$")


@dataclass
class ImagePackage:
    """One installed package, ready for an OSV query. ``kind`` is ``os`` (dpkg / apk)
    or ``lang`` (PyPI / npm). ``source`` is the distro source package OSV indexes by."""

    ecosystem: str          # dpkg | apk | PyPI | npm (the OSV ecosystem is set later)
    name: str
    version: str
    kind: str = "os"
    source: str | None = None
    source_version: str | None = None


@dataclass
class LayerScan:
    """What the layer walk read, and how far it got."""

    files: dict = field(default_factory=dict)          # path -> ArtifactFile (app files)
    packages: list[ImagePackage] = field(default_factory=list)
    os_release: dict = field(default_factory=dict)     # ID, VERSION_ID, VERSION …
    layers_total: int = 0
    layers_scanned: int = 0
    skipped: list[dict] = field(default_factory=list)  # [{digest, reason}]
    bytes_pulled: int = 0
    bytes_walked: int = 0
    seconds: float = 0.0
    depth: str = "config"       # full | partial | config
    reason: str | None = None   # why the walk stopped short (plain English)

    def summary(self) -> dict:
        reasons: dict[str, int] = {}
        for s in self.skipped:
            reasons[s["reason"]] = reasons.get(s["reason"], 0) + 1
        return {
            "depth": self.depth,
            "layers_total": self.layers_total,
            "layers_scanned": self.layers_scanned,
            "layers_skipped": [{"reason": r, "count": n} for r, n in reasons.items()],
            "app_files": len(self.files),
            "packages": len(self.packages),
            "bytes_pulled": self.bytes_pulled,
            "bytes_walked": self.bytes_walked,
            "seconds": round(self.seconds, 1),
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------------------
# Pure parsers (unit-tested directly)
# ---------------------------------------------------------------------------------------
def parse_os_release(text: str) -> dict:
    """``KEY=value`` lines of ``/etc/os-release`` → dict (quotes stripped)."""
    out: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def parse_dpkg_status(text: str) -> list[ImagePackage]:
    """Installed packages from a dpkg ``status`` file (or one distroless ``status.d``
    stanza). Only ``install ok installed`` entries count; ``Source:`` (optionally with its
    own version in parentheses) names the source package OSV indexes Debian by."""
    out: list[ImagePackage] = []
    for stanza in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        last = None
        for line in stanza.splitlines():
            if line[:1] in (" ", "\t") and last:
                continue  # continuation line (Description etc.)
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            last = key.strip()
            fields[last] = val.strip()
        name, version = fields.get("Package"), fields.get("Version")
        status = fields.get("Status", "install ok installed")
        if not name or not version or not status.endswith("installed") \
                or "not-installed" in status or "config-files" in status:
            continue
        src, src_ver = None, None
        if fields.get("Source"):
            m = re.match(r"^(\S+)(?:\s+\(([^)]+)\))?", fields["Source"])
            if m:
                src, src_ver = m.group(1), m.group(2)
        out.append(ImagePackage("dpkg", name, version, "os", src or name, src_ver or version))
    return out


def parse_apk_installed(text: str) -> list[ImagePackage]:
    """Installed packages from Alpine's ``lib/apk/db/installed`` (``P:`` name, ``V:``
    version, ``o:`` origin — the source package OSV indexes Alpine by)."""
    out: list[ImagePackage] = []
    for stanza in re.split(r"\n\s*\n", text):
        f: dict[str, str] = {}
        for line in stanza.splitlines():
            if len(line) > 2 and line[1] == ":":
                f.setdefault(line[0], line[2:].strip())
        if f.get("P") and f.get("V"):
            out.append(ImagePackage("apk", f["P"], f["V"], "os", f.get("o") or f["P"], f["V"]))
    return out


def package_from_path(path: str) -> ImagePackage | None:
    """A Python distribution recognised from its ``*.dist-info/METADATA`` path alone
    (the directory name carries the normalized name and version)."""
    m = _DIST_INFO_RE.search(path)
    if not m:
        return None
    return ImagePackage("PyPI", m.group(1).replace("_", "-"), m.group(2), "lang")


def parse_npm_manifest(raw: bytes) -> ImagePackage | None:
    """``name`` + ``version`` of an installed npm package's ``package.json``."""
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    name, version = doc.get("name"), doc.get("version")
    if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
        return None
    return ImagePackage("npm", name, version, "lang")


def normalize_member(name: str) -> str | None:
    """A tar member name as an image path (``./etc/x`` → ``etc/x``), or None when it is
    unsafe (``..`` traversal) or empty. Paths are only ever used as labels — nothing is
    written to disk — but a traversal name is still refused rather than reinterpreted."""
    n = name.replace("\\", "/")
    while n.startswith("./"):
        n = n[2:]
    n = n.lstrip("/")
    if not n or n == ".":
        return None
    norm = posixpath.normpath(n)
    if norm.startswith("..") or "/../" in f"/{norm}/":
        return None
    return norm


def app_file_priority(path: str) -> int | None:
    """Whether an image path is the image author's own file worth grading, and how early:
    0 = app trees, 1 = root-level and entrypoint scripts, 2 = ``/etc`` config.
    None = base-OS / third-party / binary — skipped (its packages are inventoried)."""
    lp = path.lower()
    ext = posixpath.splitext(lp)[1]
    if ext in _BINARY_EXT:
        return None
    if any(lp.startswith(p) for p in _SKIP_PREFIXES):
        return None
    if any(seg in f"/{lp}" for seg in _SKIP_SEGMENTS):
        return None
    base = posixpath.basename(lp)
    if lp.startswith("usr/local/bin/") or lp.startswith("usr/local/sbin/"):
        # Interpreter wrappers pip/npm drop here are third-party; keep the image's own
        # shell entrypoints only.
        return 1 if (ext == ".sh" or base.startswith("docker-entrypoint")) else None
    if lp.startswith("etc/"):
        return 2
    if "/" not in lp or base.startswith("docker-entrypoint") or lp.startswith(
            "docker-entrypoint"):
        return 1
    return 0


def osv_ecosystem(os_release: dict) -> str | None:
    """The OSV ecosystem id for the image's distro: ``Debian:12``, ``Ubuntu:22.04:LTS``,
    ``Alpine:v3.20``. None when the distro isn't one OSV indexes (or is unknown)."""
    did = (os_release.get("ID") or "").lower()
    ver = os_release.get("VERSION_ID") or ""
    if did == "debian" and ver:
        return f"Debian:{ver.split('.')[0]}"
    if did == "ubuntu" and ver:
        lts = "LTS" in (os_release.get("VERSION") or "")
        return f"Ubuntu:{ver}:LTS" if lts else f"Ubuntu:{ver}"
    if did == "alpine" and ver:
        parts = ver.split(".")
        return f"Alpine:v{parts[0]}.{parts[1]}" if len(parts) >= 2 else None
    return None


def os_label(os_release: dict) -> str | None:
    """``Debian 12``-style label for the page (PRETTY_NAME trimmed), or None."""
    pretty = os_release.get("PRETTY_NAME")
    if pretty:
        return re.sub(r"\s*\(.*\)\s*$", "", pretty).strip() or pretty
    did, ver = os_release.get("ID"), os_release.get("VERSION_ID")
    return f"{did} {ver}".strip() if did else None


# ---------------------------------------------------------------------------------------
# The tar walk (runs in a worker thread)
# ---------------------------------------------------------------------------------------
@dataclass
class _WalkState:
    """Shared across layers, newest first. ``hidden`` / ``opaque`` collect whiteouts from
    the layers above; ``seen`` is every path an upper layer already provided."""

    deadline: float
    walked: int = 0
    seen: set = field(default_factory=set)
    hidden: set = field(default_factory=set)
    opaque: set = field(default_factory=set)
    candidates: list = field(default_factory=list)    # (priority, order, path, bytes)
    candidate_bytes: int = 0
    os_release: dict = field(default_factory=dict)
    dpkg: list = field(default_factory=list)
    dpkg_seen: bool = False
    apk: list = field(default_factory=list)
    apk_seen: bool = False
    lang: dict = field(default_factory=dict)          # (eco, name) -> ImagePackage
    stopped: str | None = None


def _visible(path: str, st: _WalkState) -> bool:
    if path in st.seen or path in st.hidden:
        return False
    parts = path.split("/")
    for i in range(1, len(parts)):
        anc = "/".join(parts[:i])
        if anc in st.hidden or anc in st.opaque:
            return False
    return True


def _read(tf: tarfile.TarFile, member: tarfile.TarInfo, cap: int) -> bytes | None:
    if member.size > cap:
        return None
    try:
        fobj = tf.extractfile(member)
        data = fobj.read(cap + 1) if fobj else b""
    except (tarfile.TarError, OSError):
        return None
    return data if len(data) <= cap else None


def walk_layer(path: str, gzipped: bool, st: _WalkState) -> str | None:
    """Walk one verified layer tar (on disk) and fold it into ``st``. Returns None when
    the layer was read to the end, or a short reason when a budget stopped it."""
    new_hidden: set = set()
    new_opaque: set = set()
    layer_seen: set = set()
    order = len(st.candidates)
    try:
        with open(path, "rb") as fh, tarfile.open(
            fileobj=fh, mode="r|gz" if gzipped else "r|",
        ) as tf:
            for member in tf:
                st.walked += max(member.size, 0)
                if st.walked > MAX_TOTAL_WALKED:
                    return "decompressed-size budget reached"
                if time.monotonic() > st.deadline:
                    return "time budget reached"
                p = normalize_member(member.name)
                if not p:
                    continue
                base = posixpath.basename(p)
                if base.startswith(".wh."):
                    parent = posixpath.dirname(p)
                    if base == ".wh..wh..opq":
                        new_opaque.add(parent)
                    else:
                        new_hidden.add(posixpath.join(parent, base[4:]) if parent
                                       else base[4:])
                    continue
                if not member.isfile() or not _visible(p, st):
                    continue
                layer_seen.add(p)

                if p in _OS_RELEASE and not st.os_release:
                    raw = _read(tf, member, 64 * 1024)
                    if raw:
                        st.os_release = parse_os_release(raw.decode("utf-8", "replace"))
                    continue
                if p == _DPKG_STATUS and not st.dpkg_seen:
                    raw = _read(tf, member, MAX_DB_BYTES)
                    if raw is not None:
                        st.dpkg_seen = True
                        st.dpkg.extend(parse_dpkg_status(raw.decode("utf-8", "replace")))
                    continue
                if p.startswith(_DPKG_STATUS_D) and not p.endswith(".md5sums"):
                    raw = _read(tf, member, 1024 * 1024)
                    if raw is not None:
                        st.dpkg.extend(parse_dpkg_status(raw.decode("utf-8", "replace")))
                    continue
                if p == _APK_INSTALLED and not st.apk_seen:
                    raw = _read(tf, member, MAX_DB_BYTES)
                    if raw is not None:
                        st.apk_seen = True
                        st.apk.extend(parse_apk_installed(raw.decode("utf-8", "replace")))
                    continue
                pkg = package_from_path(p)
                if pkg is not None:
                    st.lang.setdefault(("PyPI", pkg.name.lower()), pkg)
                    continue
                if _NPM_MANIFEST_RE.search(p):
                    raw = _read(tf, member, MAX_MANIFEST_BYTES)
                    npm = parse_npm_manifest(raw) if raw else None
                    if npm is not None:
                        st.lang.setdefault(("npm", f"{npm.name}@{npm.version}"), npm)
                    continue

                prio = app_file_priority(p)
                if prio is None or member.size > MAX_APP_FILE_BYTES:
                    continue
                if st.candidate_bytes + member.size > MAX_APP_BYTES:
                    continue
                raw = _read(tf, member, MAX_APP_FILE_BYTES)
                if raw is None or b"\x00" in raw[:8192]:
                    continue  # unreadable or binary
                st.candidates.append((prio, order, p, raw))
                st.candidate_bytes += len(raw)
                order += 1
    except (tarfile.TarError, OSError, EOFError) as exc:
        logger.debug("layer walk stopped: %s", exc)
        return "unreadable layer"
    finally:
        # This layer's files shadow lower layers; its whiteouts hide lower paths.
        st.seen |= layer_seen
        st.hidden |= new_hidden
        st.opaque |= new_opaque
    return None


def _finish(st: _WalkState, scan: LayerScan) -> None:
    """Pick the app files (priority, then layer order) and assemble the inventory."""
    from src.scanner.artifact_fetch import _make_file

    for prio, _order, p, raw in sorted(st.candidates, key=lambda c: (c[0], c[1])):
        if len(scan.files) >= MAX_APP_FILES:
            break
        scan.files[p] = _make_file(p, raw)
    os_pkgs = st.dpkg or st.apk
    seen: set = set()
    for pkg in list(os_pkgs) + list(st.lang.values()):
        key = (pkg.ecosystem, pkg.name, pkg.version)
        if key in seen:
            continue
        seen.add(key)
        scan.packages.append(pkg)
        if len(scan.packages) >= MAX_PACKAGES:
            break
    scan.os_release = st.os_release


# ---------------------------------------------------------------------------------------
# Download (async) + orchestration
# ---------------------------------------------------------------------------------------
async def _download_blob(
    url: str, client: httpx.AsyncClient, *, token: str | None, digest: str,
    max_bytes: int, dest, allowed_hosts: frozenset,
) -> int | None:
    """Stream a registry blob into ``dest`` (an open binary file), following redirects to
    public https hosts only (SSRF guard on every hop; the registry token is never sent to
    a CDN). The bytes must hash to ``digest``. Returns the byte count, or None."""
    algo, _, want = digest.partition(":")
    if algo != "sha256" or not want:
        return None
    cur = url
    for _hop in range(5):
        validate_url_https(cur, field_name="docker_layer_url")
        headers = {}
        if token and urlparse(cur).hostname in allowed_hosts:
            headers["Authorization"] = f"Bearer {token}"
        async with client.stream("GET", cur, headers=headers, timeout=_DOWNLOAD_TIMEOUT,
                                 follow_redirects=False) as resp:
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
                return None
            h = hashlib.sha256()
            n = 0
            dest.seek(0)
            dest.truncate()
            async for chunk in resp.aiter_bytes(_CHUNK):
                n += len(chunk)
                if n > max_bytes:
                    return None
                h.update(chunk)
                dest.write(chunk)
            dest.flush()
        return n if h.hexdigest() == want else None
    return None


def _layer_kind(media_type: str) -> str | None:
    mt = (media_type or "").lower()
    if "zstd" in mt:
        return None
    if any(t in mt for t in _GZIP_TYPES) or mt.endswith("gzip"):
        return "gzip"
    if any(mt.endswith(t) for t in _PLAIN_TYPES):
        return "tar"
    return None


async def scan_image_layers(
    registry: str, repo: str, layers: list, *, token: str | None,
    client: httpx.AsyncClient, allowed_hosts: frozenset,
    time_budget: float = LAYER_TIME_BUDGET,
) -> LayerScan:
    """Pull and walk ``layers`` (manifest order: base first). Never raises: any failure
    leaves the result at the depth it reached, with a reason."""
    scan = LayerScan(layers_total=len(layers))
    started = time.monotonic()
    st = _WalkState(deadline=started + time_budget)
    stop_reason: str | None = None
    tmp = tempfile.NamedTemporaryFile(prefix="agentavow-layer-", delete=False)
    try:
        for layer in reversed(layers):
            dig = layer.get("digest") if isinstance(layer, dict) else None
            if stop_reason:
                scan.skipped.append({"digest": dig, "reason": stop_reason})
                continue
            if not isinstance(layer, dict) or not dig:
                scan.skipped.append({"digest": dig, "reason": "malformed layer entry"})
                continue
            kind = _layer_kind(str(layer.get("mediaType") or ""))
            size = int(layer.get("size") or 0)
            if kind is None:
                scan.skipped.append({"digest": dig, "reason": "unsupported compression"})
                continue
            if size > MAX_LAYER_COMPRESSED:
                scan.skipped.append({"digest": dig, "reason": "layer too large"})
                continue
            if scan.bytes_pulled + size > MAX_TOTAL_COMPRESSED:
                stop_reason = "image too large"
                scan.skipped.append({"digest": dig, "reason": stop_reason})
                continue
            if time.monotonic() > st.deadline:
                stop_reason = "time budget reached"
                scan.skipped.append({"digest": dig, "reason": stop_reason})
                continue
            try:
                n = await asyncio.wait_for(
                    _download_blob(
                        f"{registry}/v2/{repo}/blobs/{dig}", client, token=token,
                        digest=dig, max_bytes=MAX_LAYER_COMPRESSED, dest=tmp,
                        allowed_hosts=allowed_hosts,
                    ),
                    timeout=max(1.0, st.deadline - time.monotonic()),
                )
            except asyncio.TimeoutError:
                stop_reason = "time budget reached"
                scan.skipped.append({"digest": dig, "reason": stop_reason})
                continue
            except Exception as exc:  # noqa: BLE001 — one bad layer never fails the scan
                logger.debug("layer download failed %s: %s", dig, exc)
                n = None
            if n is None:
                scan.skipped.append({"digest": dig, "reason": "download failed or digest mismatch"})
                continue
            scan.bytes_pulled += n
            stopped = await asyncio.to_thread(walk_layer, tmp.name, kind == "gzip", st)
            if stopped == "unreadable layer":
                scan.skipped.append({"digest": dig, "reason": stopped})
                continue
            scan.layers_scanned += 1
            if stopped:
                # Partly read: what it yielded counts, the layers below are skipped.
                stop_reason = stopped
    finally:
        try:
            tmp.close()
            os.unlink(tmp.name)
        except OSError:
            pass
        _finish(st, scan)
        scan.bytes_walked = st.walked
        scan.seconds = time.monotonic() - started

    if scan.layers_scanned == 0:
        scan.depth = "config"
    elif scan.layers_scanned == scan.layers_total and not stop_reason:
        scan.depth = "full"
    else:
        scan.depth = "partial"
    if stop_reason:
        scan.reason = stop_reason
    elif scan.skipped:
        scan.reason = scan.skipped[0]["reason"]
    return scan
