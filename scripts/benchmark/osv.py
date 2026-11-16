"""Second count for package items: static answer plus the OSV known-malware lookup.

A production package scan also asks OSV (api.osv.dev, the public OpenSSF data, not
AgentAvow) for the package's OWN ``MAL-`` / malware-class (CWE-506) advisories, and a
version those list reads Do not connect (``incident_history.current_version_affected``
-> ``verdict.decide()``). The scan workers have no network, so this is a separate step
over a finished run: it queries OSV once per package name (cached on disk), applies
production's own reducer (``summarize_incidents``), and writes a second set of numbers
next to the static ones. Non-malware advisories are not applied.

Read the result with care: DataDog reports feed the OpenSSF malicious-packages list, so
for set C this mostly measures whether a sample was already reported, not detection.

    python -I scripts/benchmark/osv.py <results dir>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.benchmark.labels import summarize  # noqa: E402
from scripts.benchmark.sources import data_root  # noqa: E402

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_ECO = {"npm": "npm", "pypi": "PyPI"}


def _coords(items: list[dict]) -> dict[str, tuple[str, str, str]]:
    """``{item id: (ecosystem, name, version)}`` for the package items."""
    out = {}
    for it in items:
        if it["surface"] != "package":
            continue
        if it["set"] == "C":
            out[it["id"]] = (it["ecosystem"], it["name"], it["version"])
        elif it["set"] == "D" and not it["entry"].get("excluded"):
            e = it["entry"]
            out[it["id"]] = (e["ecosystem"], e["name"], e["version"])
    return out


def _vulns(eco: str, name: str, cache: Path) -> list[dict] | None:
    import httpx

    key = hashlib.sha256(f"{eco}/{name}".encode()).hexdigest()
    p = cache / f"{key}.json"
    if p.is_file():
        return json.loads(p.read_text())
    for attempt in range(4):
        try:
            r = httpx.post(OSV_QUERY_URL, timeout=30,
                           json={"package": {"name": name, "ecosystem": _OSV_ECO[eco]}})
            if r.status_code == 200:
                vulns = [v for v in (r.json().get("vulns") or []) if isinstance(v, dict)]
                cache.mkdir(parents=True, exist_ok=True)
                p.write_text(json.dumps(vulns))
                time.sleep(0.2)
                return vulns
        except httpx.HTTPError:
            pass
        time.sleep(2 * (attempt + 1))
    return None


def apply_osv(row: dict, affected: bool | None) -> dict:
    """The row with ``outcome_osv``: Do not connect when OSV lists this version as
    malware, else the static outcome. ``osv`` records what the lookup said."""
    out = dict(row)
    out["osv"] = {True: "affected", False: "clean", None: "unknown"}[affected]
    out["outcome_osv"] = "do_not_connect" if affected else row["outcome"]
    return out


def main(argv: list[str] | None = None) -> int:
    from scripts.benchmark.run import breakdown, load_items
    from src.scanner.incident_history import summarize_incidents

    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("results", type=Path)
    args = ap.parse_args(argv)

    rows = [json.loads(line) for line in (args.results / "rows.jsonl").open()]
    sets = sorted({r["set"] for r in rows})
    items = [it for s in sets for it in load_items(s)]
    coords = _coords(items)
    cache = data_root() / "osv-cache"
    out_rows = []
    for r in rows:
        c = coords.get(r["id"])
        affected = None
        if c is not None:
            eco, name, version = c
            vulns = _vulns(eco, name, cache)
            if vulns is not None:
                affected = bool(summarize_incidents(vulns, version, _OSV_ECO[eco], name)
                                ["current_version_affected"])
        out_rows.append(apply_osv(r, affected) if c is not None else
                        {**r, "osv": "n/a", "outcome_osv": r["outcome"]})
    with (args.results / "rows_osv.jsonl").open("w") as fh:
        for r in out_rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    swapped = [{**r, "outcome": r["outcome_osv"]} for r in out_rows]
    summary = {
        "note": "static answer, plus Do not connect where OSV lists the version as malware",
        "osv_lookups": {k: sum(1 for r in out_rows if r["osv"] == k)
                        for k in ("affected", "clean", "unknown", "n/a")},
        "overall": summarize(swapped),
        "by_set": breakdown(swapped, "set"),
        "by_stratum": breakdown(swapped, "stratum"),
    }
    (args.results / "summary_osv.json").write_text(json.dumps(summary, indent=1,
                                                              sort_keys=True))
    print(json.dumps({"osv_lookups": summary["osv_lookups"],
                      "by_set": summary["by_set"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
