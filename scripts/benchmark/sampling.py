"""Sampling rules for the accuracy benchmark, fixed before the first full run.

**Benign sample (set D).** Household-name packages, picked by a rule anyone can re-run:

1. Ranking lists, pinned in ``sources.py``: PyPI by downloads over 30 days
   (hugovk/top-pypi-packages) and npm by downloads (wooorm/npm-high-impact,
   ``topDownload``).
2. Pool: the top ``POOL_PER_ECOSYSTEM`` (1,000) names of each list.
3. Drop every name in the static known-good corpus (``tests/corpus/static``): the
   scanner's precision work was tuned on those, so they would flatter the
   false-positive rate. Drop every name the malicious set C lists in the same
   ecosystem, so an item is never both benign and malicious.
4. Order the rest by the fixed hash (``split.hash_order``) and take the first
   ``BENIGN_PER_ECOSYSTEM`` (300) of each ecosystem.
5. Each name is scanned at its latest version on the day the manifest is built
   (``fetch.py D``); the manifest pins the version, URL and sha256 it got.

Popular MCP servers are not in this rule yet: there is no public, pinned download
ranking for them. Benign skills come from sets A (2,235) and B (4).

**Malicious packages (set C).** The DataDog set is ~29.5k samples and ~27 GB, more than
we can hold. Per stratum, items are ordered by the fixed hash and the first
``C_QUOTAS[stratum]`` taken (``None`` = all of them); strata are then interleaved
round-robin, so a smoke run's first N items cover every stratum. Archives over the production
download cap (50 MB) are counted as not checked, as production would.

**Smoke runs** take the first N items of the same hash order.
"""
from __future__ import annotations

from collections.abc import Iterable

from scripts.benchmark.split import hash_order

POOL_PER_ECOSYSTEM = 1000
BENIGN_PER_ECOSYSTEM = 300

C_QUOTAS: dict[str, int | None] = {
    "npm/malicious_intent": 1000,
    "npm/compromised_lib": 300,
    "pypi/malicious_intent": 1000,
    "pypi/compromised_lib": None,
    "ai-skills/malicious_intent": None,
}


def normalize_name(ecosystem: str, name: str) -> str:
    """Registry-equivalent spelling: PyPI names per PEP 503, npm names lowercased."""
    n = name.strip().lower()
    if ecosystem == "pypi":
        import re
        n = re.sub(r"[-_.]+", "-", n)
    return n


def benign_sample(
    ecosystem: str,
    ranked: Iterable[str],
    *,
    exclude: Iterable[str] = (),
    pool: int = POOL_PER_ECOSYSTEM,
    take: int = BENIGN_PER_ECOSYSTEM,
) -> list[str]:
    """Apply the benign rule to one ranking list (most-downloaded first). Returns the
    chosen names in hash order. Duplicate names keep their best rank."""
    seen: set[str] = set()
    top: list[str] = []
    for raw in ranked:
        n = normalize_name(ecosystem, raw)
        if not n or n in seen:
            continue
        seen.add(n)
        top.append(n)
        if len(top) >= pool:
            break
    banned = {normalize_name(ecosystem, x) for x in exclude}
    kept = [n for n in top if n not in banned]
    ordered = hash_order("D", [f"{ecosystem}/{n}" for n in kept])
    return [i.split("/", 1)[1] for i in ordered[:take]]


def quota_sample(set_id: str, ids_by_stratum: dict[str, list[str]],
                 quotas: dict[str, int | None]) -> list[str]:
    """Per stratum, the first ``quotas[stratum]`` ids in hash order (all when None),
    interleaved round-robin across strata (in stratum-name order), so the first N of
    the result are a balanced smoke sample. A stratum missing from ``quotas`` is left
    out entirely."""
    lists: list[list[str]] = []
    for stratum in sorted(ids_by_stratum):
        if stratum not in quotas:
            continue
        ordered = hash_order(set_id, ids_by_stratum[stratum])
        q = quotas[stratum]
        lists.append(ordered if q is None else ordered[:q])
    out: list[str] = []
    for i in range(max((len(x) for x in lists), default=0)):
        out.extend(x[i] for x in lists if i < len(x))
    return out
