"""Accuracy benchmark runner: scan sets A-D with the local static engine and count.

Static only, on this machine, through the same scanner code production runs:

* skills (A, B, C ai-skills): ``src.scanner.scan.scan_skill``, with its two GitHub
  reads (the repo tree and each file) answered from the local item instead of the
  network. Every other step (which files are read, the 39-file cap, coverage gaps,
  scoring) is production's own code.
* packages (C npm / PyPI, D): ``npm_result_from_tarball`` / ``pypi_result_from_archive``
  then ``apply_artifact_scan`` and the scoring tail, as the static corpus gate does.
  Networked signals (OSV advisories, build provenance) are not applied.

The answer is ``src.scanner.verdict.decide()`` over the dict the public API builds.

Safety: the samples are real malware. Items are read as bytes only; nothing is
installed, imported, built or run. Workers refuse every network connection. Run with
``python -I`` and under ``nice``:

    nice -n 19 python -I scripts/benchmark/run.py --set A --limit 20 [--split heldout]
        [--workers 1] [--out DIR]

``--limit N`` takes the first N items in the fixed hash order (a smoke run).
Results go to ``<data root>/results/<run id>/`` (JSONL rows + summary.json), never into
the repo.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import io
import json
import os
import subprocess
import sys
import tarfile
import time
import zipfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scripts.benchmark.labels import outcome_for, summarize, truth_for  # noqa: E402
from scripts.benchmark.sampling import C_QUOTAS, quota_sample  # noqa: E402
from scripts.benchmark.sources import SOURCES, data_root, set_dir  # noqa: E402
from scripts.benchmark.split import hash_order, in_split, split_of  # noqa: E402

ZIP_PASSWORD = SOURCES["C"]["zip_password"].encode()
# Members over this are skipped unread by production's unpack anyway, so they are not
# decrypted here (ZipCrypto in Python is slow).
_MAX_MEMBER = 8 * 1024 * 1024
BATCH = 200  # items per worker pool before the workers are replaced


# ---------------------------------------------------------------------------
# Item lists (pure reads of the fetched metadata)
# ---------------------------------------------------------------------------

def _item(set_id: str, item_id: str, group: str, raw_label: str, surface: str,
          stratum: str, **extra) -> dict:
    return {"set": set_id, "id": item_id, "group": group, "raw_label": raw_label,
            "truth": truth_for(set_id, raw_label), "surface": surface,
            "stratum": stratum, "split": split_of(set_id, group), **extra}


def load_items(set_id: str) -> list[dict]:
    """Every item of a set (for C: the quota sample), in the fixed hash order (for C:
    the round-robin of each stratum's hash order)."""
    if set_id == "A":
        return _items_a()
    if set_id == "B":
        return _items_b()
    if set_id == "C":
        return _items_c()
    if set_id == "D":
        return _items_d()
    raise ValueError(set_id)


def _items_a() -> list[dict]:
    from scripts.benchmark.fetch import repo_dir

    root = repo_dir("A")
    pk = {r["benchmark_id"]: r for r in
          csv.DictReader((root / "packages" / "package_manifest.csv").open())}
    items = []
    for r in csv.DictReader((root / "metadata" / "benchmark_manifest.csv").open()):
        bid = r["benchmark_id"]
        group = r["structural_family_id"] or bid
        p = pk.get(bid)
        src = {"kind": "package", "archive": p["package_archive"].split("_")[0],
               "rel": p["package_relative_path"]} if p else {"kind": "text"}
        items.append(_item("A", bid, group, r["label"], "skill", f"A/{r['source_id']}",
                           source=src, attack=r["attack_categories"]))
    order = {i: n for n, i in enumerate(hash_order("A", [it["id"] for it in items]))}
    return sorted(items, key=lambda it: order[it["id"]])


def _items_b() -> list[dict]:
    from scripts.benchmark.fetch import repo_dir

    base = repo_dir("B") / "evals" / "skills"
    items = []
    for exp in base.glob("*/*/_expected.json"):
        d = json.loads(exp.read_text())
        case = exp.parent.relative_to(base).as_posix()
        items.append(_item("B", case, case, d["package_label"], "skill", f"B/{case.split('/')[0]}",
                           expected_verdict=d.get("expected_verdict")))
    order = {i: n for n, i in enumerate(hash_order("B", [it["id"] for it in items]))}
    return sorted(items, key=lambda it: order[it["id"]])


def _c_name_version(path: str) -> tuple[str, str]:
    """``npm/malicious_intent/@scope@name/1.0.0/x.zip`` -> (``@scope/name``, ``1.0.0``)."""
    parts = path.split("/")
    name = parts[2]
    if name.startswith("@") and "@" in name[1:]:
        scope, rest = name[1:].split("@", 1)
        name = f"@{scope}/{rest}"
    version = parts[3] if len(parts) > 4 else "0"
    return name, version


def _items_c() -> list[dict]:
    idx = json.loads((set_dir("C") / "index.json").read_text())
    by_path = {it["path"]: it for it in idx["items"]}
    strata: dict[str, list[str]] = {}
    for it in idx["items"]:
        strata.setdefault(it["stratum"], []).append(it["path"])
    items = []
    for path in quota_sample("C", strata, C_QUOTAS):
        it = by_path[path]
        eco, kind = it["stratum"].split("/")
        if eco == "ai-skills":
            name, version, surface = path.split("/")[2], "", "skill"
        else:
            (name, version), surface = _c_name_version(path), "package"
        items.append(_item("C", path, f"{eco}/{name}", kind, surface, it["stratum"],
                           blob=it["blob"], size=it["size"], ecosystem=eco,
                           name=name, version=version))
    return items


def _items_d() -> list[dict]:
    man = json.loads((set_dir("D") / "manifest.json").read_text())
    by_id = {e["id"]: e for e in man["packages"]}
    # Names the manifest left out (over the 50 MB download cap) stay in as not checked.
    for x in man.get("excluded") or []:
        by_id.setdefault(x["id"], {"ecosystem": x["id"].split("/")[0], "excluded": x["why"]})
    return [_item("D", i, i, "benign", "package", f"D/{by_id[i]['ecosystem']}", entry=by_id[i])
            for i in hash_order("D", by_id)]


# ---------------------------------------------------------------------------
# Worker side: network guard, then scan one item
# ---------------------------------------------------------------------------

def _no_network() -> None:
    """Refuse every outbound connection in this process: the run is static only."""
    import socket

    def refuse(*_a, **_k):
        raise OSError("benchmark runner: network access is disabled")

    socket.socket.connect = refuse  # type: ignore[method-assign]
    socket.socket.connect_ex = refuse  # type: ignore[method-assign]
    socket.create_connection = refuse  # type: ignore[assignment]
    socket.getaddrinfo = refuse  # type: ignore[assignment]


def _worker_init() -> None:
    os.environ.setdefault("DEBUG", "true")
    _no_network()


_LOCAL_FILES: dict[str, bytes] = {}


def _install_local_github() -> None:
    """Answer ``scan_skill``'s GitHub reads from ``_LOCAL_FILES``."""
    import src.github_auth as gh
    from src.scanner import scan

    async def tree(owner, repo, token=None, meta_out=None):
        items = [{"path": p, "type": "blob", "size": len(b)} for p, b in _LOCAL_FILES.items()]
        over = meta_out.setdefault("oversized", []) if meta_out is not None else None
        return scan._tree_blobs(items, over), False, True, "local"

    async def content(owner, repo, path, token=None, ref=None):
        raw = _LOCAL_FILES.get(path)
        return None if raw is None else raw.decode("utf-8", errors="replace")

    async def no_token():
        return None

    scan._fetch_repo_tree = tree
    scan._fetch_file_content = content
    gh.get_github_token = no_token


def _strip_prefix(files: dict[str, bytes]) -> dict[str, bytes]:
    """Drop the directory every path shares (an archive's wrapper folder)."""
    if not files:
        return files
    parts = [p.split("/") for p in files]
    common = []
    for segs in zip(*[p[:-1] for p in parts]):
        if len(set(segs)) != 1:
            break
        common.append(segs[0])
    n = len("/".join(common)) + 1 if common else 0
    return {p[n:]: b for p, b in files.items()}


def _zip_members(raw: bytes) -> dict[str, bytes]:
    """Every regular member of a (possibly encrypted) zip, read in memory only."""
    out: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for info in zf.infolist():
            if info.is_dir() or info.file_size > _MAX_MEMBER:
                continue
            pwd = ZIP_PASSWORD if info.flag_bits & 1 else None
            out[info.filename] = zf.read(info, pwd=pwd)
    return out


def _dir_files(root: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink() and p.stat().st_size <= _MAX_MEMBER:
            out[p.relative_to(root).as_posix()] = p.read_bytes()
    return out


def _skill_files(item: dict) -> dict[str, bytes]:
    s = item["set"]
    if s == "A":
        src = item["source"]
        if src["kind"] == "text":
            return {"SKILL.md": item["text"].encode("utf-8")}
        root = set_dir("A") / "pkgs" / src["archive"] / src["rel"]
        if root.is_file():
            return {"SKILL.md": root.read_bytes()}
        return _dir_files(root)
    if s == "B":
        from scripts.benchmark.fetch import repo_dir
        files = _dir_files(repo_dir("B") / "evals" / "skills" / item["id"])
        files.pop("_expected.json", None)  # the answer key is never scanned
        return files
    from scripts.benchmark.fetch import c_cache_path
    return _strip_prefix(_zip_members(c_cache_path(item["blob"]).read_bytes()))


def _ensure_skill_md(files: dict[str, bytes]) -> tuple[dict[str, bytes], str | None]:
    """A one-file item with no SKILL.md is the skill text itself (the datasets' native
    single-file form): name it SKILL.md. Otherwise leave it, and say why it can't run."""
    if any(p.lower().endswith("skill.md") for p in files):
        return files, None
    if len(files) == 1:
        return {"SKILL.md": next(iter(files.values()))}, "single file read as SKILL.md"
    return files, None


def _scan_skill_item(item: dict):
    from src.scanner import scan

    files, note = _ensure_skill_md(_skill_files(item))
    _LOCAL_FILES.clear()
    _LOCAL_FILES.update(files)
    _install_local_github()
    result = asyncio.run(scan.scan_skill("benchmark", item["set"] + "-item"))
    return result, note


def _package_from_c(item: dict):
    """The DataDog zip holds the UNPACKED package (npm: ``<name>/package/...`` beside a
    ``package_info-*.json`` of DataDog's; PyPI: the unpacked sdist). Rebuild the archive
    a registry would serve, in memory, and hand it to production's unpack."""
    from scripts.benchmark.fetch import c_cache_path
    from src.scanner.artifact_fetch import npm_result_from_tarball, pypi_result_from_archive

    members = _zip_members(c_cache_path(item["blob"]).read_bytes())
    eco, name, version = item["ecosystem"], item["name"], item["version"]
    if eco == "npm":
        roots = sorted((p[: -len("package.json")] for p in members
                        if p.endswith("package/package.json")), key=len)
        root = roots[0] if roots else None
        if root is None:
            members = _strip_prefix({p: b for p, b in members.items()
                                     if not p.rsplit("/", 1)[-1].startswith("package_info-")})
            root = ""
        files = {p[len(root):]: b for p, b in members.items() if p.startswith(root)}
        raw = _targz({f"package/{p}": b for p, b in files.items()})
        return npm_result_from_tarball(name, version, raw)
    marks = ("setup.py", "pyproject.toml", "PKG-INFO", "setup.cfg")
    roots = sorted({p.rsplit("/", 1)[0] + "/" if "/" in p else "" for p in members
                    if p.rsplit("/", 1)[-1] in marks}, key=len)
    if roots:
        files = {p[len(roots[0]):]: b for p, b in members.items() if p.startswith(roots[0])}
    else:
        files = _strip_prefix(members)
    raw = _targz({f"{name}-{version}/{p}": b for p, b in files.items()})
    return pypi_result_from_archive(name, version, "sdist", f"{name}-{version}.tar.gz", raw,
                                    installed_paths=None)


def _targz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=1) as tf:
        for path in sorted(files):
            data = files[path]
            ti = tarfile.TarInfo(path)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _score_package(eco: str, name: str, fetched):
    from src.scanner.scan import (
        ScanResult,
        _calculate_category_scores,
        _calculate_trust_score,
        _certified_status,
        apply_artifact_scan,
    )

    result = ScanResult(repo=f"{eco}:{name}", stars=0, description="", framework="")
    apply_artifact_scan(result, eco, fetched)
    result.trust_score = _calculate_trust_score(result)
    result.category_scores = _calculate_category_scores(result)
    result.certified = _certified_status(result)
    return result


def scan_item(item: dict) -> dict:
    """Scan one item; never raises. The row carries the answer, or not_checked + why."""
    from scripts.corpus.run_static_corpus import real_decide
    from src.scanner.artifact_fetch import ArtifactFetchError
    from src.scanner.scan import _finding_is_blocking

    t0 = time.monotonic()
    row = {k: item[k] for k in ("set", "id", "group", "raw_label", "truth", "surface",
                                "stratum", "split")}
    note = None
    try:
        if item["surface"] == "skill":
            result, note = _scan_skill_item(item)
        elif item["set"] == "C":
            from src.scanner.artifact_fetch import MAX_DOWNLOAD_BYTES
            if int(item["size"]) > MAX_DOWNLOAD_BYTES:
                raise ArtifactFetchError("over the 50 MB download cap")
            result = _score_package(item["ecosystem"], item["name"], _package_from_c(item))
        else:
            from scripts.corpus.run_static_corpus import scan_entry
            if item["entry"].get("excluded"):
                raise ArtifactFetchError(item["entry"]["excluded"])
            r = scan_entry(item["entry"], str(set_dir("D") / "cache"), True)
            row.update(answer=r.get("label") if r.get("label") in
                       ("safe", "review", "do_not_connect") else None,
                       reason=r.get("reason") or r.get("error") or r.get("label"),
                       score=r.get("score"), files_scanned=r.get("files_scanned"),
                       top=[{"sev": f["sev"], "name": f["name"]}
                            for f in r.get("_findings", [])[:5]])
            row["outcome"] = outcome_for(row["answer"])
            row["secs"] = round(time.monotonic() - t0, 2)
            return row
        if getattr(result, "error", None):
            raise ArtifactFetchError(str(result.error))
        d = real_decide(result)
        blocking = [f for f in result.findings if _finding_is_blocking(f)]
        row.update(
            answer=d.label, reason=d.reason, score=result.trust_score,
            files_scanned=result.files_scanned,
            coverage_gaps=getattr(result, "coverage_gaps", None) or {},
            categories=sorted({f.category for f in blocking
                               if f.severity in ("critical", "high")}),
            top=[{"sev": f.severity, "cat": f.category, "name": f.name,
                  "path": f.file_path, "line": f.line_number}
                 for f in sorted(blocking, key=lambda f: ("critical", "high", "medium",
                                                          "low", "info").index(f.severity)
                                 if f.severity in ("critical", "high", "medium", "low",
                                                   "info") else 9)[:5]],
        )
    except Exception as exc:  # noqa: BLE001 — a failure is "not checked", never Safe
        row.update(answer=None, reason=f"not checked: {type(exc).__name__}: {str(exc)[:200]}")
    if note:
        row["note"] = note
    row["outcome"] = outcome_for(row.get("answer"))
    row["secs"] = round(time.monotonic() - t0, 2)
    return row


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def _attach_text(items: list[dict]) -> None:
    """A's benign rows have no package: their skill text comes from the HF rows."""
    need = {it["id"] for it in items if it["set"] == "A" and it["source"]["kind"] == "text"}
    if not need:
        return
    text = {}
    with (set_dir("A") / "hf_rows.jsonl").open() as fh:
        for line in fh:
            r = json.loads(line)
            if r["benchmark_id"] in need:
                text[r["benchmark_id"]] = r.get("skill_text") or r.get("public_skill_text")
    for it in items:
        if it["id"] in need:
            it["text"] = text.get(it["id"]) or ""


def _scanner_commit() -> str:
    try:
        return subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _ensure_c_samples(items: list[dict]) -> None:
    """Say how many C samples are missing; they are scanned as not checked."""
    from scripts.benchmark.fetch import c_cache_path
    missing = [it["id"] for it in items if it["set"] == "C"
               and not c_cache_path(it["blob"]).is_file()
               and int(it["size"]) <= 50 * 1024 * 1024]
    if missing:
        print(f"warning: {len(missing)} C samples not downloaded (fetch.py C --samples N); "
              f"they count as not checked, e.g. {missing[0]}", flush=True)


def breakdown(rows: list[dict], key: str) -> dict:
    groups: dict[str, list[dict]] = {}
    for r in rows:
        vals = r.get(key)
        for v in (vals if isinstance(vals, list) else [vals]):
            groups.setdefault(str(v), []).append(r)
    return {k: summarize(v) for k, v in sorted(groups.items())}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--set", action="append", choices=["A", "B", "C", "D"], required=True)
    ap.add_argument("--split", default="all", choices=["all", "tune", "heldout"])
    ap.add_argument("--limit", type=int, default=0, help="first N items per set (smoke)")
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    if args.workers > 2:
        raise SystemExit("keep --workers at 1 or 2 (16 GB machine)")

    items: list[dict] = []
    for s in args.set:
        got = [it for it in load_items(s) if in_split(s, it["group"], args.split)]
        items.extend(got[: args.limit] if args.limit else got)
    _attach_text(items)
    _ensure_c_samples(items)

    run_id = time.strftime("%Y%m%d-%H%M%S")
    out = args.out or data_root() / "results" / run_id
    out.mkdir(parents=True, exist_ok=True)
    # Resume: rows already written for this output dir are kept, not rescanned.
    rows_path = out / "rows.jsonl"
    rows: list[dict] = []
    if rows_path.is_file():
        rows = [json.loads(line) for line in rows_path.open() if line.strip()]
    done = {(r["set"], r["id"]) for r in rows}
    todo = [it for it in items if (it["set"], it["id"]) not in done]
    n = len(rows)
    with rows_path.open("a") as fh:
        # A fresh pool per batch bounds worker memory growth. (max_tasks_per_child
        # hangs on this Python, so workers are recycled this way instead.)
        for start in range(0, len(todo), BATCH):
            batch = todo[start:start + BATCH]
            with ProcessPoolExecutor(max_workers=args.workers,
                                     initializer=_worker_init) as pool:
                for row in pool.map(scan_item, batch, chunksize=1):
                    n += 1
                    rows.append(row)
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
                    fh.flush()
                    print(f"[{n}/{len(items)}] {row['set']} {row['id'][:60]} "
                          f"{row['truth']} -> {row['outcome']} ({row['secs']}s)", flush=True)

    summary = {
        "run_id": run_id, "scanner_commit": _scanner_commit(), "split": args.split,
        "limit": args.limit or None,
        "datasets": {s: {k: v for k, v in SOURCES[s].items() if k != "zip_password"}
                     for s in args.set},
        "overall": summarize(rows),
        "by_set": breakdown(rows, "set"),
        "by_surface": breakdown(rows, "surface"),
        "by_stratum": breakdown(rows, "stratum"),
        "by_category": breakdown([r for r in rows if r.get("categories")], "categories"),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True))
    print(json.dumps({"out": str(out), "overall": summary["overall"],
                      "by_set": summary["by_set"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
