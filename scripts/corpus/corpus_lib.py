"""Shared helpers for the static known-good corpus (manifest builder + runner).

Downloaded archives are UNTRUSTED DATA: they are fetched into a cache directory,
verified against the pinned sha256, and only ever read as bytes by the same pure
unpack/scan functions production uses. Nothing in an archive is executed, imported,
or installed. Run the scripts with ``python -I`` (isolated mode) so neither the
current directory nor the cache can shadow a module.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO_ROOT / "tests" / "corpus" / "static"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
EXPECTED_PATH = CORPUS_DIR / "expected.json"
SUBSET_PATH = CORPUS_DIR / "subset.json"

USER_AGENT = "AgentAvow-StaticCorpus/1 (+https://agentavow.com)"


def ensure_repo_on_path() -> None:
    """`python -I` drops the script dir from sys.path; put the repo root back
    explicitly (never the cache dir or the cwd)."""
    root = str(REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def default_cache_dir() -> Path:
    env = os.environ.get("AGENTAVOW_CORPUS_CACHE")
    if env:
        return Path(env)
    return Path.home() / ".cache" / "agentavow-static-corpus"


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    return json.loads(path.read_text())


def cache_path(cache_dir: Path, sha256: str) -> Path:
    """Archives are stored by content hash, so the cache is shareable across pins and
    a corrupted/partial file can never be mistaken for the pinned one."""
    return cache_dir / sha256[:2] / sha256


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_cached(cache_dir: Path, sha256: str) -> bytes | None:
    p = cache_path(cache_dir, sha256)
    if not p.is_file():
        return None
    raw = p.read_bytes()
    if sha256_bytes(raw) != sha256:
        p.unlink(missing_ok=True)  # corrupted: refetch
        return None
    return raw


def write_cached(cache_dir: Path, raw: bytes) -> str:
    digest = sha256_bytes(raw)
    p = cache_path(cache_dir, digest)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".part")
    tmp.write_bytes(raw)
    tmp.replace(p)
    return digest


def http_get(url: str, *, max_bytes: int, client=None, retries: int = 4) -> bytes:
    """GET with the production registry allowlist + SSRF guard, no redirects, a hard
    size cap, and exponential backoff on transient errors (be gentle with registries)."""
    ensure_repo_on_path()
    import httpx

    from src.scanner.artifact_fetch import _validate_registry_url

    _validate_registry_url(url)
    owns = client is None
    if owns:
        client = httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=60)
    try:
        delay = 2.0
        for attempt in range(retries + 1):
            try:
                buf = bytearray()
                with client.stream("GET", url, follow_redirects=False) as resp:
                    if resp.status_code in (429, 500, 502, 503, 504):
                        raise httpx.TransportError(f"status {resp.status_code}")
                    if resp.status_code != 200:
                        raise RuntimeError(f"HTTP {resp.status_code} for {url}")
                    for chunk in resp.iter_bytes():
                        buf.extend(chunk)
                        if len(buf) > max_bytes:
                            raise RuntimeError(f"exceeds {max_bytes} bytes: {url}")
                return bytes(buf)
            except httpx.TransportError:
                if attempt == retries:
                    raise
                time.sleep(delay)
                delay *= 2
        raise RuntimeError("unreachable")
    finally:
        if owns:
            client.close()


def ensure_cached(cache_dir: Path, url: str, sha256: str | None, *, max_bytes: int,
                  client=None) -> tuple[bytes, str]:
    """Return ``(raw, sha256)`` for ``url``, from the cache when the pinned hash is
    present, else downloaded (and verified against the pin when one is given)."""
    if sha256:
        raw = read_cached(cache_dir, sha256)
        if raw is not None:
            return raw, sha256
    raw = http_get(url, max_bytes=max_bytes, client=client)
    digest = sha256_bytes(raw)
    if sha256 and digest != sha256:
        raise RuntimeError(f"sha256 mismatch for {url}: pinned {sha256}, got {digest}")
    write_cached(cache_dir, raw)
    return raw, digest
