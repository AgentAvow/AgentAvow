"""Fixed-hash held-out split and hash-order sampling for the accuracy benchmark.

The rule against teaching to the test (design section 2): before any scanner change is
made off a benchmark miss, 30% of sets A-D is set aside by a fixed hash. Fixes may be
tuned on the other 70%; the report states the held-out numbers first.

The rule, written down in advance:

* key   = ``"agentavow-benchmark-2026q4|" + set + "|" + group``
* h     = the first 8 bytes of ``sha256(key)`` read as a big-endian integer
* held out when ``h / 2**64 < 0.30``

``group`` keeps near-duplicates on one side of the line, so a fix tuned on one copy
cannot be scored on its twin:

* A (MaliciousSkillBench): the dataset's ``structural_family_id`` (its own grouping of
  near-identical malicious skills); benign rows have none, so their ``benchmark_id``.
* B (Cisco evals): the case directory (``category/case``).
* C (DataDog): the ecosystem plus package name, so every version of one package falls
  on the same side.
* D (benign packages): the ecosystem plus package name.

Nothing here depends on the order items are listed in, on the run, or on the machine.
"""
from __future__ import annotations

import hashlib

SALT = "agentavow-benchmark-2026q4"
HELDOUT_FRACTION = 0.30
SPLITS = ("all", "tune", "heldout")


def _unit(key: str) -> float:
    """A stable number in [0, 1) for ``key``."""
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def split_unit(set_id: str, group: str) -> float:
    return _unit(f"{SALT}|{set_id}|{group}")


def is_heldout(set_id: str, group: str) -> bool:
    return split_unit(set_id, group) < HELDOUT_FRACTION


def split_of(set_id: str, group: str) -> str:
    return "heldout" if is_heldout(set_id, group) else "tune"


def sample_key(set_id: str, item_id: str) -> str:
    """Sort key for hash-order sampling: take the first N items in this order. A
    different salt from the split, so a sample is not biased toward either side."""
    return hashlib.sha256(f"{SALT}|sample|{set_id}|{item_id}".encode()).hexdigest()


def hash_order(set_id: str, ids) -> list[str]:
    """``ids`` sorted by :func:`sample_key` (ties cannot happen for distinct ids)."""
    return sorted(ids, key=lambda i: sample_key(set_id, i))


def in_split(set_id: str, group: str, split: str) -> bool:
    if split == "all":
        return True
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}")
    return split_of(set_id, group) == split
