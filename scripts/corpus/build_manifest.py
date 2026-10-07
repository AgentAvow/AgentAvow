"""Build / re-pin the static known-good corpus manifest (tests/corpus/static/manifest.json).

Sources (both public and reproducible; the exact snapshot is recorded in the manifest):

* PyPI: hugovk/top-pypi-packages, 30-day list
  (https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json), first N rows
  by ``download_count``.
* npm: ``npm-high-impact`` (wooorm) ``lib/top-download.js`` from a PINNED package version
  — the npm packages ordered by weekly downloads, generated from the npm downloads API.
  The module is read as text and parsed with a regex; it is never executed.

Plus the pinned extras: ``pypi/mcp`` (official MCP Python SDK), the 20-package sample of
the precision-pass scope report, and the sandbox eval's ``known_good`` MCP packages.

Each package is pinned to the version current at build time, with the archive that
production would scan (``_pick_pypi_url``: sdist preferred; npm: the tarball) and, for
PyPI, the wheel whose member list decides the installed surface (``_pypi_sdist_and_wheel``),
each with its sha256. Packages that are yanked, carry an OSV ``MAL-`` advisory, have no
downloadable files, or whose archive exceeds the production download cap are excluded
(listed under ``excluded`` with the reason) and the next package backfills.

``expect`` / ``expect_reason`` written by a human are carried over on a re-pin.

Usage (network; downloads into the cache, never executes):
    python -I scripts/corpus/build_manifest.py --cache <dir> [--n 200]
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402

from scripts.corpus.corpus_lib import (  # noqa: E402
    MANIFEST_PATH,
    USER_AGENT,
    default_cache_dir,
    ensure_cached,
)
from src.scanner.artifact_fetch import (  # noqa: E402
    MAX_DOWNLOAD_BYTES,
    _pick_pypi_url,
    _pypi_deprecation,
    _pypi_sdist_and_wheel,
)

PYPI_TOP_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json"
NPM_HIGH_IMPACT_VERSION = "1.13.0"
NPM_HIGH_IMPACT_TARBALL = (
    f"https://registry.npmjs.org/npm-high-impact/-/npm-high-impact-{NPM_HIGH_IMPACT_VERSION}.tgz"
)

# The precision-pass scope report's 20-package live sample (§1).
SCOPE_SAMPLE = [
    ("pypi", "psutil"), ("pypi", "google-auth"), ("pypi", "fastapi"), ("pypi", "pytest"),
    ("pypi", "pydantic"), ("pypi", "cryptography"), ("pypi", "paramiko"),
    ("pypi", "requests"), ("pypi", "httpx"), ("pypi", "boto3"),
    ("npm", "task-master-ai"), ("npm", "typescript"), ("npm", "vite"),
    ("npm", "@modelcontextprotocol/sdk"), ("npm", "puppeteer"), ("npm", "express"),
    ("npm", "lodash"), ("npm", "axios"), ("npm", "chalk"), ("npm", "commander"),
]
REQUIRED_EXTRAS = [("pypi", "mcp")]
SANDBOX_CORPUS = Path(__file__).resolve().parents[2] / "scripts/sandbox/eval/corpus.json"


def _client() -> httpx.Client:
    return httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=60, follow_redirects=False)


def pypi_top(client: httpx.Client) -> tuple[list[str], str]:
    r = client.get(PYPI_TOP_URL)
    r.raise_for_status()
    d = r.json()
    rows = sorted(d["rows"], key=lambda x: -int(x["download_count"]))
    return [x["project"] for x in rows], str(d.get("last_update"))


def npm_top(client: httpx.Client) -> list[str]:
    r = client.get(NPM_HIGH_IMPACT_TARBALL)
    r.raise_for_status()
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tf:
        member = tf.getmember("package/lib/top-download.js")
        text = tf.extractfile(member).read().decode("utf-8")  # type: ignore[union-attr]
    body = text[text.index("[") : text.rindex("]")]
    return re.findall(r"'([^']+)'", body)


def resolve_pypi(client: httpx.Client, name: str) -> dict:
    r = client.get(f"https://pypi.org/pypi/{quote(name)}/json")
    if r.status_code != 200:
        return {"excluded": f"PyPI metadata HTTP {r.status_code}"}
    meta = r.json()
    info = meta.get("info") or {}
    version = info.get("version")
    urls = meta.get("urls") or []
    if info.get("yanked"):
        return {"excluded": "latest release yanked"}
    picked = _pick_pypi_url(urls)
    if not picked:
        return {"excluded": "no downloadable sdist/wheel"}
    url, kind = picked
    by_url = {u.get("url"): u for u in urls if isinstance(u, dict)}
    a = by_url[url]
    if int(a.get("size") or 0) > MAX_DOWNLOAD_BYTES:
        return {"excluded": f"{kind} exceeds the production download cap "
                            f"({a.get('size')} bytes)"}
    entry: dict = {
        "ecosystem": "pypi", "name": info.get("name") or name, "version": version,
        "archive": {"kind": kind, "url": url, "sha256": a["digests"]["sha256"],
                    "size": a.get("size")},
        "wheel": None,
    }
    if kind == "sdist":
        _sd, wheel_url = _pypi_sdist_and_wheel(urls)
        if wheel_url:
            w = by_url[wheel_url]
            entry["wheel"] = {"url": wheel_url, "sha256": w["digests"]["sha256"],
                              "size": w.get("size")}
    dep = _pypi_deprecation(meta)
    if dep:
        entry["deprecation"] = dep
    return entry


def resolve_npm(client: httpx.Client, name: str) -> dict:
    enc = name.replace("/", "%2F")
    r = client.get(f"https://registry.npmjs.org/{enc}/latest")
    if r.status_code != 200:
        return {"excluded": f"npm metadata HTTP {r.status_code}"}
    v = r.json()
    dist = v.get("dist") or {}
    if not dist.get("tarball"):
        return {"excluded": "no dist.tarball"}
    if int(dist.get("unpackedSize") or 0) > 0 and int(dist["unpackedSize"]) > 50 * 1024 * 1024:
        return {"excluded": f"unpacked size {dist['unpackedSize']} exceeds the production cap"}
    entry: dict = {
        "ecosystem": "npm", "name": name, "version": v.get("version"),
        "archive": {"kind": "tarball", "url": dist["tarball"], "sha256": None,
                    "integrity": dist.get("integrity")},
        "wheel": None,
    }
    dep = v.get("deprecated")
    if dep:
        entry["deprecation"] = (dep.strip()[:300] if isinstance(dep, str)
                                else "deprecated by its maintainer")
    return entry


def osv_malicious(client: httpx.Client, entries: list[dict]) -> dict[str, list[str]]:
    """``{id: [MAL-…]}`` for pinned versions with a malicious-package advisory."""
    out: dict[str, list[str]] = {}
    for i in range(0, len(entries), 500):
        chunk = entries[i : i + 500]
        q = {"queries": [{"package": {"name": e["name"],
                                      "ecosystem": "PyPI" if e["ecosystem"] == "pypi" else "npm"},
                          "version": e["version"]} for e in chunk]}
        r = client.post("https://api.osv.dev/v1/querybatch", json=q)
        r.raise_for_status()
        for e, res in zip(chunk, r.json().get("results") or []):
            mal = [v["id"] for v in (res.get("vulns") or []) if v["id"].startswith("MAL-")]
            if mal:
                out[f"{e['ecosystem']}/{e['name']}"] = mal
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--n", type=int, default=200, help="packages per ecosystem")
    ap.add_argument("--cache", type=Path, default=default_cache_dir())
    ap.add_argument("--out", type=Path, default=MANIFEST_PATH)
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    old: dict[str, dict] = {}
    if args.out.exists():
        for e in json.loads(args.out.read_text()).get("packages") or []:
            old[e["id"]] = e

    client = _client()
    pypi_names, pypi_snapshot = pypi_top(client)
    npm_names = npm_top(client)

    extras: list[tuple[str, str, str]] = [(e, n, "required") for e, n in REQUIRED_EXTRAS]
    extras += [(e, n, "scope-sample") for e, n in SCOPE_SAMPLE]
    try:
        sb = json.loads(SANDBOX_CORPUS.read_text())
        extras += [(k["surface"], k["name"], "sandbox-known-good")
                   for k in sb.get("known_good") or [] if k.get("surface") in ("npm", "pypi")]
    except (OSError, ValueError, KeyError):
        pass

    def resolve(eco: str, name: str) -> dict:
        with _client() as c:
            return resolve_pypi(c, name) if eco == "pypi" else resolve_npm(c, name)

    packages: list[dict] = []
    excluded: list[dict] = []
    seen: set[str] = set()

    def take(eco: str, names: list[str], source: str, limit: int | None) -> None:
        kept = 0
        idx = 0
        while idx < len(names) and (limit is None or kept < limit):
            want = (limit - kept) if limit is not None else len(names)
            batch = []
            while idx < len(names) and len(batch) < want:
                pid = f"{eco}/{names[idx].lower() if eco == 'pypi' else names[idx]}"
                if pid not in seen:
                    batch.append((idx, names[idx]))
                    seen.add(pid)
                idx += 1
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                results = list(ex.map(lambda t: resolve(eco, t[1]), batch))
            for (rank, name), res in zip(batch, results):
                pid = f"{eco}/{name.lower() if eco == 'pypi' else name}"
                if "excluded" in res:
                    excluded.append({"id": pid, "source": f"{source}#{rank + 1}",
                                     "reason": res["excluded"]})
                    continue
                res["id"] = pid
                res["source"] = f"{source}#{rank + 1}" if limit is not None else source
                packages.append(res)
                kept += 1
            print(f"  {source}: {kept} kept, {len(excluded)} excluded so far", file=sys.stderr)

    take("pypi", pypi_names, "top-pypi-30d", args.n)
    take("npm", npm_names, "npm-high-impact-top-download", args.n)
    for eco, name, src in extras:
        pid = f"{eco}/{name.lower() if eco == 'pypi' else name}"
        if pid in seen:
            for p in packages:
                if p["id"] == pid:
                    p.setdefault("also", []).append(src)
            continue
        take(eco, [name], src, None)

    # Malicious-package advisories on the pinned versions: exclude (no backfill needed
    # for extras; top-N lists would be re-run if this ever fires).
    mal = osv_malicious(client, packages)
    for pid, ids in mal.items():
        excluded.append({"id": pid, "reason": f"OSV malicious advisory {', '.join(ids)}"})
    packages = [p for p in packages if p["id"] not in mal]

    # Download every archive (+ wheel) into the cache; record npm sha256 (the registry
    # publishes sha512/sha1 only).
    def fetch(p: dict) -> dict:
        try:
            with _client() as c:
                _raw, digest = ensure_cached(args.cache, p["archive"]["url"],
                                             p["archive"].get("sha256"),
                                             max_bytes=MAX_DOWNLOAD_BYTES, client=c)
                p["archive"]["sha256"] = digest
                p["archive"]["size"] = len(_raw)
                w = p.get("wheel")
                if w and int(w.get("size") or 0) <= MAX_DOWNLOAD_BYTES:
                    ensure_cached(args.cache, w["url"], w["sha256"],
                                  max_bytes=MAX_DOWNLOAD_BYTES, client=c)
        except Exception as exc:  # noqa: BLE001 — record and exclude
            p["_fetch_error"] = str(exc)[:200]
        return p

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        packages = list(ex.map(fetch, packages))
    for p in [p for p in packages if p.get("_fetch_error")]:
        excluded.append({"id": p["id"], "reason": f"download failed: {p['_fetch_error']}"})
    packages = [p for p in packages if not p.get("_fetch_error")]

    for p in packages:
        prev = old.get(p["id"])
        if prev:
            for k in ("expect", "expect_reason", "subset"):
                if k in prev:
                    p[k] = prev[k]
        p["archive"].pop("integrity", None)
    out = {
        "_doc": (
            "Static known-good corpus (precision PR 2). Top PyPI + npm packages by "
            "downloads, pinned to one version with the archive production scans and "
            "(PyPI) the wheel whose member list is the installed surface. Archives are "
            "downloaded into a cache, verified by sha256, and NEVER executed or "
            "installed. Default expectation: no package is 'do_not_connect'. `expect` "
            "(safe|review) is recorded only after a human read the reason. Rebuild with "
            "scripts/corpus/build_manifest.py; run with scripts/corpus/run_static_corpus.py."
        ),
        "built": date.today().isoformat(),
        "sources": {
            "pypi": {"url": PYPI_TOP_URL, "snapshot": pypi_snapshot,
                     "rule": f"first {args.n} by 30-day download_count"},
            "npm": {"package": f"npm-high-impact@{NPM_HIGH_IMPACT_VERSION}",
                    "file": "lib/top-download.js", "url": NPM_HIGH_IMPACT_TARBALL,
                    "rule": f"first {args.n} (ordered by weekly downloads)"},
            "extras": "pypi/mcp; precision-scope §1 sample; "
                      "scripts/sandbox/eval/corpus.json known_good",
        },
        "excluded": excluded,
        "packages": packages,
    }
    return _write(args.out, out, packages)


def _write(path: Path, out: dict, packages: list[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1, sort_keys=False) + "\n")
    print(f"wrote {path}: {len(packages)} packages, {len(out['excluded'])} excluded",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
