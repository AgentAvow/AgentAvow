"""Benchmark held-out split and sampling rules (scripts/benchmark/split.py, sampling.py)."""
from __future__ import annotations

import hashlib
import random

import pytest

from scripts.benchmark.sampling import benign_sample, normalize_name, quota_sample
from scripts.benchmark.split import (
    HELDOUT_FRACTION,
    SALT,
    hash_order,
    in_split,
    is_heldout,
    split_of,
    split_unit,
)


def test_rule_is_the_written_one():
    # The published rule, recomputed by hand: sha256 of the key, first 8 bytes.
    key = f"{SALT}|A|FAMILY_0439"
    h = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big") / 2**64
    assert split_unit("A", "FAMILY_0439") == h
    assert is_heldout("A", "FAMILY_0439") is (h < 0.30)
    assert SALT == "agentavow-benchmark-2026q4"
    assert HELDOUT_FRACTION == 0.30


def test_split_is_stable_and_order_free():
    groups = [f"npm/pkg-{i}" for i in range(500)]
    first = {g: split_of("C", g) for g in groups}
    shuffled = groups[:]
    random.Random(7).shuffle(shuffled)
    assert {g: split_of("C", g) for g in shuffled} == first


def test_split_fraction_near_thirty_percent():
    n = 20_000
    held = sum(is_heldout("A", f"FAMILY_{i:05d}") for i in range(n))
    assert abs(held / n - 0.30) < 0.015


def test_split_depends_on_set():
    groups = [f"g{i}" for i in range(400)]
    a = [is_heldout("A", g) for g in groups]
    c = [is_heldout("C", g) for g in groups]
    assert a != c


def test_in_split():
    g = "pypi/requests"
    side = split_of("D", g)
    other = "tune" if side == "heldout" else "heldout"
    assert in_split("D", g, "all")
    assert in_split("D", g, side)
    assert not in_split("D", g, other)
    with pytest.raises(ValueError):
        in_split("D", g, "train")


def test_hash_order_is_deterministic_and_independent_of_input_order():
    ids = [f"x{i}" for i in range(100)]
    assert hash_order("B", ids) == hash_order("B", list(reversed(ids)))
    assert sorted(hash_order("B", ids)) == sorted(ids)


def test_normalize_name():
    assert normalize_name("pypi", "Typing_Extensions") == "typing-extensions"
    assert normalize_name("pypi", "zope.interface") == "zope-interface"
    assert normalize_name("npm", "@Types/Node") == "@types/node"


def test_benign_sample_rule():
    ranked = [f"pkg{i}" for i in range(50)] + ["PKG1"]  # a duplicate spelling
    got = benign_sample("npm", ranked, exclude={"pkg0", "pkg1"}, pool=20, take=5)
    assert len(got) == 5
    assert not {"pkg0", "pkg1"} & set(got)
    # Only the top-20 pool is eligible.
    assert all(int(n[3:]) < 20 for n in got)
    # The same rule gives the same picks every time, in hash order.
    assert got == benign_sample("npm", ranked, exclude={"pkg1", "pkg0"}, pool=20, take=5)
    pool = [n for n in (f"pkg{i}" for i in range(20)) if n not in {"pkg0", "pkg1"}]
    assert got == [i.split("/", 1)[1] for i in hash_order("D", [f"npm/{n}" for n in pool])][:5]


def test_quota_sample_round_robin_and_quotas():
    strata = {"a/x": [f"a{i}" for i in range(10)], "b/y": [f"b{i}" for i in range(3)],
              "c/z": [f"c{i}" for i in range(4)]}
    got = quota_sample("C", strata, {"a/x": 5, "b/y": None})
    assert len(got) == 8  # 5 from a/x, all 3 from b/y, c/z left out
    assert not any(i.startswith("c") for i in got)
    # Round-robin: the first two items come from different strata.
    assert {got[0][0], got[1][0]} == {"a", "b"}
    assert [i for i in got if i.startswith("a")] == hash_order("C", strata["a/x"])[:5]
