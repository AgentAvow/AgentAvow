"""Label mapping and metrics for the accuracy benchmark.

Two mappings, both written down before any run:

1. **Dataset label -> truth.** Each dataset's own label becomes one of
   ``malicious`` / ``benign`` / ``contextual``. The labels are the dataset authors';
   where we disagree we list the item and keep their label in the numbers.

   * A, MaliciousSkillBench: ``label`` 1 -> malicious, 0 -> benign.
   * B, Cisco evals: ``package_label`` malicious -> malicious, benign -> benign,
     contextual_risk -> contextual. Contextual cases (risky but not malicious, e.g. a
     missing license or an unpinned dependency) are reported on their own line and
     left out of both the recall and the false-positive figures.
   * C, DataDog: both ``malicious_intent`` and ``compromised_lib`` -> malicious (a
     compromised_lib sample is the compromised version itself).
   * D, benign sample: benign.

2. **Our answer -> outcome.** The three answers from ``src.scanner.verdict.decide()``:

   * ``do_not_connect`` -> flagged at Do not connect
   * ``review``         -> flagged at Review
   * ``safe``           -> not flagged (a miss on a malicious item)
   * no answer (fetch / unpack / scan error, nothing readable) -> **not checked**,
     counted on its own line and never quietly counted as Safe.

Metrics (design section 3), each with a 95% Wilson interval and its n. The
denominator is the items we checked; not-checked items are reported beside it.

* malicious: flag rate at Do not connect, flag rate at Review or worse (the
  headline), miss rate (reads Safe).
* benign: false Do-not-connect rate, Review rate, and the false-positive rate at
  Review or worse.
"""
from __future__ import annotations

import math
from collections import Counter

TRUTHS = ("malicious", "benign", "contextual")
ANSWERS = ("safe", "review", "do_not_connect")
NOT_CHECKED = "not_checked"

_A_LABELS = {"1": "malicious", "0": "benign"}
_B_LABELS = {"malicious": "malicious", "benign": "benign", "contextual_risk": "contextual"}
_C_KINDS = {"malicious_intent": "malicious", "compromised_lib": "malicious"}


def truth_for(set_id: str, raw_label: object) -> str:
    """Map a dataset's own label to ``malicious`` / ``benign`` / ``contextual``.
    Raises ``ValueError`` on a label the mapping does not know, so a dataset that
    changes its labels fails loudly instead of being miscounted."""
    raw = str(raw_label).strip()
    table = {"A": _A_LABELS, "B": _B_LABELS, "C": _C_KINDS}.get(set_id)
    if set_id == "D":
        if raw != "benign":
            raise ValueError(f"set D holds benign items only, got {raw!r}")
        return "benign"
    if table is None:
        raise ValueError(f"unknown set {set_id!r}")
    if raw not in table:
        raise ValueError(f"set {set_id}: unknown label {raw!r}")
    return table[raw]


def outcome_for(answer: str | None) -> str:
    """Our answer as an outcome: one of ANSWERS, or NOT_CHECKED when there is none."""
    if answer in ANSWERS:
        return answer
    return NOT_CHECKED


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """95% Wilson score interval for k successes out of n (``(0, 0)`` when n is 0)."""
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _rate(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else None, "ci95": [lo, hi]}


def summarize(rows: list[dict]) -> dict:
    """Metrics over result rows (each has ``truth`` and ``outcome``), per truth class."""
    by_truth: dict[str, Counter] = {t: Counter() for t in TRUTHS}
    for r in rows:
        by_truth[r["truth"]][r["outcome"]] += 1
    out: dict = {}
    m = by_truth["malicious"]
    n = m["safe"] + m["review"] + m["do_not_connect"]
    out["malicious"] = {
        "checked": n,
        "not_checked": m[NOT_CHECKED],
        "flag_do_not_connect": _rate(m["do_not_connect"], n),
        "flag_review_or_worse": _rate(m["do_not_connect"] + m["review"], n),
        "miss_safe": _rate(m["safe"], n),
    }
    b = by_truth["benign"]
    n = b["safe"] + b["review"] + b["do_not_connect"]
    out["benign"] = {
        "checked": n,
        "not_checked": b[NOT_CHECKED],
        "false_do_not_connect": _rate(b["do_not_connect"], n),
        "review": _rate(b["review"], n),
        "fpr_review_or_worse": _rate(b["do_not_connect"] + b["review"], n),
    }
    c = by_truth["contextual"]
    out["contextual"] = {k: c[k] for k in (*ANSWERS, NOT_CHECKED)}
    return out
