"""The web registry (web/src/components/trust/scanCategories.ts) mirrors the canonical
detection categories in src/scanner/categories.py: the same 14 ids in the same order, and
every raw finding key mapped to the same detection category."""
from __future__ import annotations

import re
from pathlib import Path

from src.scanner.categories import DETECTION_CATEGORIES, FINDING_CATEGORY_MAP

_TS = Path(__file__).resolve().parents[1] / "web/src/components/trust/scanCategories.ts"


def _source() -> str:
    return _TS.read_text(encoding="utf-8")


def test_ts_detection_ids_match_canonical_order():
    block = _source().split("export const DETECTION_CATEGORIES", 1)[1].split("\n]\n", 1)[0]
    ids = re.findall(r"\{ id: '([a-z_]+)'", block)
    assert ids == [c.id for c in DETECTION_CATEGORIES]
    assert len(ids) == 14


def test_ts_static_flags_match():
    block = _source().split("export const DETECTION_CATEGORIES", 1)[1].split("\n]\n", 1)[0]
    flags = dict(re.findall(r"\{ id: '([a-z_]+)', name: '[^']*', static: (true|false)", block))
    assert flags == {c.id: ("true" if c.static else "false") for c in DETECTION_CATEGORIES}


def test_ts_raw_keys_roll_up_like_backend():
    block = _source().split("export const SCAN_CATEGORIES", 1)[1].split("\n}\n", 1)[0]
    pairs = dict(re.findall(r"key: '([a-z_]+)',.*?detection: '([a-z_]+)',", block, re.S))
    assert pairs == FINDING_CATEGORY_MAP
