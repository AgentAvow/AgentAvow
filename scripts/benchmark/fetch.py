"""Fetch the benchmark answer keys (sets A-D) into the data directory, outside the repo.

Download only. Archives are unpacked with tarfile's ``data`` filter (no links, devices
or paths outside the target), zips are never unpacked to disk, and nothing fetched is
installed, imported, built or run. Run with ``python -I`` so nothing in the cwd or the
data directory can shadow a module:

    python -I scripts/benchmark/fetch.py A          # repo tarball, skill packages, HF rows
    python -I scripts/benchmark/fetch.py B          # Cisco evals tarball
    python -I scripts/benchmark/fetch.py C          # sample index (no samples)
    python -I scripts/benchmark/fetch.py C --samples 20   # + the first 20 per hash order
    python -I scripts/benchmark/fetch.py D [--download 20]  # benign manifest (+ archives)

A GitHub token in ``GITHUB_TOKEN`` lifts the API rate limit for the C index.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tarfile
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.benchmark.sources import SOURCES, set_dir  # noqa: E402

UA = "AgentAvow-Benchmark/1 (+https://agentavow.com)"
C_STRATA = ("npm/malicious_intent", "npm/compromised_lib", "pypi/malicious_intent",
            "pypi/compromised_lib", "ai-skills/malicious_intent")


# ---------------------------------------------------------------------------
# HTTP (plain GETs to GitHub / Hugging Face / the registries; bounded)
# ---------------------------------------------------------------------------

def _get(url: str, *, max_bytes: int = 200 * 1024 * 1024, headers: dict | None = None,
         retries: int = 4) -> bytes:
    import httpx

    h = {"User-Agent": UA, **(headers or {})}
    delay = 2.0
    for attempt in range(retries + 1):
        try:
            buf = bytearray()
            with httpx.stream("GET", url, headers=h, timeout=120,
                              follow_redirects=True) as resp:
                if resp.status_code in (429, 500, 502, 503, 504):
                    raise httpx.TransportError(f"status {resp.status_code}")
                if resp.status_code != 200:
                    raise RuntimeError(f"HTTP {resp.status_code} for {url}")
                for chunk in resp.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        raise RuntimeError(f"over {max_bytes} bytes: {url}")
            return bytes(buf)
        except httpx.TransportError:
            if attempt == retries:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 120)
    raise RuntimeError("unreachable")


def _gh_json(path: str) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    return json.loads(_get(f"https://api.github.com/{path}", headers=headers))


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob_sha(raw: bytes) -> str:
    """Git's object id for a file's bytes, to check a sample against the pinned tree."""
    return hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()  # noqa: S324


def _codeload(repo: str, commit: str, dest: Path, pinned_sha256: str | None) -> Path:
    out = dest / "src.tar.gz"
    if not out.is_file():
        raw = _get(f"https://codeload.github.com/{repo}/tar.gz/{commit}")
        out.write_bytes(raw)
    got = _sha256(out.read_bytes())
    if pinned_sha256 and got != pinned_sha256:
        raise RuntimeError(f"{out}: sha256 {got} != pinned {pinned_sha256}")
    return out


def _extract(tar_path: Path, dest: Path) -> None:
    """Unpack with the ``data`` filter: regular files and dirs only, nothing outside
    ``dest``, no permissions carried over."""
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, mode="r:*") as tf:
        tf.extractall(dest, filter="data")


def repo_dir(set_id: str) -> Path:
    """The single top-level directory of an unpacked codeload tarball."""
    x = set_dir(set_id) / "x"
    dirs = [p for p in x.iterdir() if p.is_dir()] if x.is_dir() else []
    if len(dirs) != 1:
        raise RuntimeError(f"expected one unpacked repo under {x}, found {len(dirs)}")
    return dirs[0]


# ---------------------------------------------------------------------------
# Set A: MaliciousSkillBench
# ---------------------------------------------------------------------------

def fetch_a() -> None:
    src = SOURCES["A"]
    d = set_dir("A")
    d.mkdir(parents=True, exist_ok=True)
    tgz = _codeload(src["repo"], src["commit"], d, src["tarball_sha256"])
    if not (d / "x").is_dir():
        _extract(tgz, d / "x")
    root = repo_dir("A")
    pk = root / "packages"
    sums = {}
    for line in (pk / "SHA256SUMS.txt").read_text().splitlines():
        if line.strip():
            h, name = line.split(None, 1)
            sums[name.strip()] = h
    for arc in sorted(pk.glob("SRC*.tar.gz")):
        if _sha256(arc.read_bytes()) != sums.get(arc.name):
            raise RuntimeError(f"{arc.name}: does not match SHA256SUMS.txt")
        target = d / "pkgs" / arc.name.split("_")[0]
        if not target.is_dir():
            _extract(arc, target)
    _fetch_a_rows(d / "hf_rows.jsonl")
    print(f"A: ok at {root}")


def _fetch_a_rows(out: Path) -> None:
    """Every row of the HF ``primary`` config (label + skill text) as JSONL, through
    the datasets-server rows API (no parquet reader needed). The API serves the
    current revision, so we check it is still the pinned one first."""
    src = SOURCES["A"]
    if out.is_file():
        return
    info = json.loads(_get(f"https://huggingface.co/api/datasets/{src['hf_dataset']}"))
    if info.get("sha") != src["hf_revision"]:
        raise RuntimeError(f"HF revision moved: {info.get('sha')} != {src['hf_revision']}")
    ds = urllib.parse.quote(src["hf_dataset"], safe="")
    rows, offset, total = [], 0, None
    while total is None or offset < total:
        time.sleep(2)  # the rows API rate-limits; be gentle
        page = json.loads(_get(
            "https://datasets-server.huggingface.co/rows?dataset="
            f"{ds}&config=primary&split=train&offset={offset}&length=100", retries=8))
        total = page["num_rows_total"]
        got = [r["row"] for r in page["rows"]]
        if not got:
            break
        rows.extend(got)
        offset += len(got)
    if len(rows) != total:
        raise RuntimeError(f"HF rows: got {len(rows)} of {total}")
    tmp = out.with_suffix(".part")
    with tmp.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    tmp.replace(out)


# ---------------------------------------------------------------------------
# Set B: Cisco skill-scanner evals
# ---------------------------------------------------------------------------

def fetch_b() -> None:
    src = SOURCES["B"]
    d = set_dir("B")
    d.mkdir(parents=True, exist_ok=True)
    tgz = _codeload(src["repo"], src["commit"], d, src["tarball_sha256"])
    if not (d / "x").is_dir():
        _extract(tgz, d / "x")
    print(f"B: ok at {repo_dir('B')}")


# ---------------------------------------------------------------------------
# Set C: DataDog malicious packages (index + per-sample download)
# ---------------------------------------------------------------------------

def _tree(repo: str, sha: str, recursive: bool = False) -> dict:
    q = "?recursive=1" if recursive else ""
    t = _gh_json(f"repos/{repo}/" + "git" + f"/trees/{sha}{q}")
    if t.get("truncated"):
        raise RuntimeError(f"tree {sha} truncated; list a smaller subtree")
    return t


def _child(tree: dict, name: str) -> str:
    for e in tree["tree"]:
        if e["path"] == name and e["type"] == "tree":
            return e["sha"]
    raise KeyError(name)


def fetch_c_index() -> Path:
    """``C/index.json``: every sample zip at the pinned commit (path, git blob id,
    size, stratum), listed from the git tree without downloading any sample."""
    src = SOURCES["C"]
    d = set_dir("C")
    d.mkdir(parents=True, exist_ok=True)
    out = d / "index.json"
    if out.is_file():
        return out
    repo = src["repo"]
    root = _tree(repo, src["commit"])
    samples = _tree(repo, _child(root, "samples"))
    items = []
    for stratum in C_STRATA:
        eco, kind = stratum.split("/")
        eco_t = _tree(repo, _child(samples, eco))
        sub = _tree(repo, _child(eco_t, kind), recursive=True)
        for e in sub["tree"]:
            if e["type"] == "blob" and e["path"].endswith(".zip"):
                items.append({"stratum": stratum, "path": f"{eco}/{kind}/{e['path']}",
                              "blob": e["sha"], "size": e["size"]})
        # The ecosystem manifest (names only), used to keep D disjoint from C.
        for e in eco_t["tree"]:
            if e["path"] == "manifest.json" and not (d / f"manifest-{eco}.json").is_file():
                raw = _get(_raw_url(f"{eco}/manifest.json"))
                if git_blob_sha(raw) != e["sha"]:
                    raise RuntimeError(f"{eco}/manifest.json: blob id mismatch")
                (d / f"manifest-{eco}.json").write_bytes(raw)
    out.write_text(json.dumps({"commit": src["commit"], "items": items}, indent=0))
    return out


def _raw_url(sample_path: str) -> str:
    src = SOURCES["C"]
    return (f"https://raw.githubusercontent.com/{src['repo']}/{src['commit']}/samples/"
            + urllib.parse.quote(sample_path, safe="/"))


MIN_FREE_BYTES = 5 * 1024**3  # stop fetching before the disk drops under 5 GB free


def check_disk(path: Path, need: int = 0) -> None:
    """Stop (SystemExit) if writing ``need`` more bytes would leave under 5 GB free."""
    import shutil

    path.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(path).free
    if free - need < MIN_FREE_BYTES:
        raise SystemExit(f"disk guard: {free / 1024**3:.1f} GB free; stopping before "
                         f"it drops under {MIN_FREE_BYTES / 1024**3:.0f} GB")


def c_cache_path(blob: str) -> Path:
    return set_dir("C") / "cache" / f"{blob}.zip"


def fetch_c_sample(item: dict, max_bytes: int) -> str:
    """Download one sample zip (still encrypted) into the cache, checked against its
    git blob id. Returns ``ok`` / ``cached`` / ``too_large``."""
    p = c_cache_path(item["blob"])
    if p.is_file():
        return "cached"
    if int(item["size"]) > max_bytes:
        return "too_large"
    check_disk(p.parent, int(item["size"]))
    raw = _get(_raw_url(item["path"]), max_bytes=max_bytes)
    if git_blob_sha(raw) != item["blob"]:
        raise RuntimeError(f"{item['path']}: blob id mismatch")
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".part")
    tmp.write_bytes(raw)
    tmp.replace(p)
    return "ok"


# ---------------------------------------------------------------------------
# Set D: benign packages (manifest in the static-corpus format)
# ---------------------------------------------------------------------------

def _ranking(key: str) -> list[str]:
    r = SOURCES["D"][key]
    raw = _get(f"https://raw.githubusercontent.com/{r['repo']}/{r['commit']}/{r['path']}")
    if key == "pypi_ranking":
        d = json.loads(raw)
        rows = sorted(d["rows"], key=lambda x: -int(x["download_count"]))
        return [x["project"] for x in rows]
    text = raw.decode("utf-8")
    return re.findall(r"'([^']+)'", text[text.index("["): text.rindex("]")])


def _c_names(eco: str) -> set[str]:
    p = set_dir("C") / f"manifest-{eco}.json"
    if not p.is_file():
        raise RuntimeError("fetch the C index first (it brings the C name lists)")
    return set(json.loads(p.read_text()))


def fetch_d(download: int | None) -> None:
    from scripts.benchmark.sampling import benign_sample
    from scripts.corpus.build_manifest import _client, resolve_npm, resolve_pypi
    from scripts.corpus.corpus_lib import MANIFEST_PATH, ensure_cached
    from src.scanner.artifact_fetch import MAX_DOWNLOAD_BYTES

    d = set_dir("D")
    d.mkdir(parents=True, exist_ok=True)
    out = d / "manifest.json"
    if out.is_file():
        man = json.loads(out.read_text())
    else:
        static = json.loads(MANIFEST_PATH.read_text())["packages"]
        man = {"built": time.strftime("%Y-%m-%d"), "packages": [], "excluded": []}
        client = _client()
        for eco, key in (("pypi", "pypi_ranking"), ("npm", "npm_ranking")):
            ranked = _ranking(key)
            exclude = {e["name"] for e in static if e["ecosystem"] == eco} | _c_names(eco)
            for name in benign_sample(eco, ranked, exclude=exclude):
                e = resolve_pypi(client, name) if eco == "pypi" else resolve_npm(client, name)
                if "excluded" in e:
                    man["excluded"].append({"id": f"{eco}/{name}", "why": e["excluded"]})
                    continue
                e["id"] = f"{eco}/{name}"
                man["packages"].append(e)
        out.write_text(json.dumps(man, indent=1))
    if download:
        from scripts.benchmark.split import hash_order
        by_id = {e["id"]: e for e in man["packages"]}
        cache = d / "cache"
        for i in hash_order("D", by_id)[:download]:
            e = by_id[i]
            check_disk(cache, int(e["archive"].get("size") or 0))
            try:
                _raw, digest = ensure_cached(cache, e["archive"]["url"],
                                             e["archive"].get("sha256"),
                                             max_bytes=MAX_DOWNLOAD_BYTES)
                e["archive"]["sha256"] = digest
                if e.get("wheel"):
                    ensure_cached(cache, e["wheel"]["url"], e["wheel"]["sha256"],
                                  max_bytes=MAX_DOWNLOAD_BYTES)
            except Exception as exc:  # noqa: BLE001 — the runner counts it as not checked
                print(f"{i}: download failed: {exc}")
        out.write_text(json.dumps(man, indent=1))
    print(f"D: {len(man['packages'])} packages, {len(man['excluded'])} excluded -> {out}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("set", choices=["A", "B", "C", "D"])
    ap.add_argument("--samples", type=int, default=0,
                    help="C: also download the first N samples per hash order")
    ap.add_argument("--download", type=int, default=0,
                    help="D: also download the first N archives per hash order")
    args = ap.parse_args(argv)
    if args.set == "A":
        fetch_a()
    elif args.set == "B":
        fetch_b()
    elif args.set == "C":
        idx = json.loads(fetch_c_index().read_text())
        print(f"C: {len(idx['items'])} samples indexed")
        if args.samples:
            from scripts.benchmark.sampling import C_QUOTAS, quota_sample
            from src.scanner.artifact_fetch import MAX_DOWNLOAD_BYTES
            by_path = {it["path"]: it for it in idx["items"]}
            strata: dict[str, list[str]] = {}
            for it in idx["items"]:
                strata.setdefault(it["stratum"], []).append(it["path"])
            for p in quota_sample("C", strata, C_QUOTAS)[: args.samples]:
                try:
                    print(p, fetch_c_sample(by_path[p], MAX_DOWNLOAD_BYTES), flush=True)
                except Exception as exc:  # noqa: BLE001 — counted as not checked later
                    print(p, f"failed: {exc}", flush=True)
    else:
        fetch_d(args.download or None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
