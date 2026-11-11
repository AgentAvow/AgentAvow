"""Real monorepo lockfiles (tests/fixtures/repo_lockfiles, fetched 2026-11-11) pin what
lockfiles.parse_all grades as production dependencies. The static corpora are package
artifacts with no lockfiles, so this is where repo-scan dependency counts are pinned.

- pnpm workspaces: only what a shipped member reaches counts (zod 1,205 -> 0; astro's
  runtime deps stay shipped);
- a multi-document pnpm lockfile is read whole (vercel/ai: 15 -> 780);
- npm workspaces and yarn: unchanged (no-op)."""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from src.scanner import lockfiles as lf

FX = Path(__file__).resolve().parent / "fixtures" / "repo_lockfiles"
MANIFEST = json.loads((FX / "manifest.json").read_text())["repos"]


@pytest.mark.parametrize("r", MANIFEST, ids=[r["repo"] for r in MANIFEST])
def test_repo_production_dependencies(r):
    text = gzip.open(FX / r["fixture"], "rt").read()
    priv = set(r["private_importers"])
    deps = lf.parse_all({r["lockfile"]: text}, {r["lockfile"]: priv} if priv else None)
    prod = [d for d in deps if not d.dev]
    assert len(prod) == r["prod_after"]
    names = {d.name for d in prod}
    for n in r["must_ship"]:
        assert n in names, n
    for n in r["must_not_ship"]:
        assert n not in names, n


@pytest.mark.parametrize("r", [r for r in MANIFEST if r["lockfile"] != "pnpm-lock.yaml"],
                         ids=lambda r: r["repo"])
def test_npm_and_yarn_are_unchanged(r):
    assert r["prod_after"] == r["prod_before"]


def test_counts_only_go_down_except_the_multi_document_fix():
    for r in MANIFEST:
        if r["repo"] == "vercel/ai":
            # read whole now: more real dependencies are graded, never fewer
            assert r["prod_after"] > r["prod_before"]
        else:
            assert r["prod_after"] <= r["prod_before"], r["repo"]
