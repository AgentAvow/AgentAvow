"""What the catalog already lists, keyed exactly as Browse keys it.

Browse lists one row per tool page (commit 544d1d81): ``scan_catalog_router.page_key``
of the row's page path, GitHub owner/repo case-folded, package names and MCP endpoints
as they are. This module builds that key set from the launch corpus files (x402 left
out: it is not a discovery source) and from community_scans (a light column read, not
the catalog's per-row mark lookup), so "new" here means "Browse has no page for it".
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PEP503 = re.compile(r"[-_.]+")


def pypi_loose(name: str) -> str:
    """PEP 503 normal form: PyPI treats Foo_Bar and foo-bar as one project."""
    return _PEP503.sub("-", (name or "").strip()).lower()


@dataclass(slots=True)
class Entry:
    """One catalog page, the facts the refresh job needs about it."""

    key: str
    surface: str               # catalog surface of the listed row
    name: str
    full_name: str | None
    endpoint_url: str | None
    target: tuple[str, str, str] | None   # (surface, owner, repo) its live scan uses
    adoption: int = 0
    last_scanned_at: datetime | None = None
    decision: str | None = None
    live: bool = False         # a community_scans row lists it (else launch corpus)


@dataclass
class CatalogIndex:
    entries: dict[str, Entry] = field(default_factory=dict)
    pypi_names: set[str] = field(default_factory=set)
    # Launch MCP registry rows skipped for no readable code and with no page: their
    # registry names (the skipped-with-URL pass looks up a remote endpoint for them).
    skipped_mcp_names: set[str] = field(default_factory=set)
    # MCP registry name -> page key of its launch row (refresh: registry updated_since).
    mcp_registry_keys: dict[str, str] = field(default_factory=dict)

    def has(self, key: str | None, *, surface: str | None = None, name: str = "") -> bool:
        if key is None:
            return False
        if key in self.entries:
            return True
        return surface == "pypi" and pypi_loose(name) in self.pypi_names

    def add(self, e: Entry) -> None:
        cur = self.entries.get(e.key)
        # A live row takes the launch row's place (scan_catalog_router._supersede); it
        # keeps the corpus row's adoption when it has none of its own yet.
        if cur is None or (e.live and not cur.live):
            if cur is not None and not e.adoption:
                e.adoption = cur.adoption
            self.entries[e.key] = e
        if e.target and e.target[0] == "pypi":
            self.pypi_names.add(pypi_loose(e.target[2]))


def row_key_and_target(surface: str, name: str, full_name: str | None = None,
                       endpoint_url: str | None = None
                       ) -> tuple[str | None, tuple[str, str, str] | None]:
    """(page key, live-scan target) for a would-be catalog row, using the catalog's own
    functions so a discovered tool and its future Browse row can never key differently."""
    from src.api.scan_catalog_router import CatalogRow, _rescan_target, page_key

    row = CatalogRow(surface=surface, name=name, full_name=full_name,
                     endpoint_url=endpoint_url)
    return page_key(row), _rescan_target(row)


def _corpus_rows(data_dir: Path | None = None) -> list[Any]:
    from src.api import scan_catalog_router as scr

    base = data_dir or scr._DATA_DIR
    rows: list[Any] = []
    for surface, fname, key in scr._CATALOG_SOURCES:
        if surface == "x402":
            continue
        rows += scr._load_surface(surface, base / fname, results_key=key)
    scr._apply_mcp_endpoints(rows, scr.load_mcp_endpoints(base / scr._MCP_ENDPOINTS_FILE))
    return scr._dedupe_static(rows)


def add_corpus(index: CatalogIndex, rows: list[Any]) -> None:
    from src.api.scan_catalog_router import _rescan_target, page_key

    for r in rows:
        k = page_key(r)
        if k is None:
            if r.surface == "mcp" and r.skipped and r.name:
                index.skipped_mcp_names.add(r.name)
            continue
        if r.surface == "mcp" and r.name and not r.name.lower().startswith("http"):
            index.mcp_registry_keys[r.name] = k
        if r.skipped:
            # A skipped row has a page only via the endpoint overlay; it is listed.
            index.add(Entry(key=k, surface=r.surface, name=r.name, full_name=r.full_name,
                            endpoint_url=r.endpoint_url, target=None))
            continue
        index.add(Entry(
            key=k, surface=r.surface, name=r.name, full_name=r.full_name,
            endpoint_url=r.endpoint_url, target=_rescan_target(r),
            adoption=int(r.adoption_count or 0), last_scanned_at=r.last_scanned_at,
            decision=r.decision, live=False,
        ))


def add_community(index: CatalogIndex, rows: list[tuple]) -> None:
    """``rows``: (surface, owner, repo, full_name, adoption_count, last_scanned_at,
    decision) tuples from community_scans."""
    from src.api.scan_catalog_router import _path_key, community_row_coords, page_path_for

    for surface, owner, repo, full_name, adoption, when, decision in rows:
        surf, name, _repo_url, endpoint = community_row_coords(surface, repo, full_name)
        k = _path_key(page_path_for(surf, name, full_name, endpoint))
        if k is None:
            continue
        index.add(Entry(
            key=k, surface=surf, name=name, full_name=full_name, endpoint_url=endpoint,
            target=(surf, owner, repo), adoption=int(adoption or 0),
            last_scanned_at=when, decision=decision, live=True,
        ))


async def community_rows(db: Any, limit: int = 50_000) -> list[tuple]:
    from sqlalchemy import select

    from src.models import CommunityScan

    res = await db.execute(
        select(CommunityScan.surface, CommunityScan.owner, CommunityScan.repo,
               CommunityScan.full_name, CommunityScan.adoption_count,
               CommunityScan.last_scanned_at, CommunityScan.decision)
        .order_by(CommunityScan.last_scanned_at.desc()).limit(limit))
    return [tuple(r) for r in res.all()]


async def build_index(db: Any, data_dir: Path | None = None) -> CatalogIndex:
    """The catalog's pages: launch corpus (blocking file read, in a thread) + live rows.
    Raises when the community read fails: with no live rows every tool would look new."""
    import asyncio

    index = CatalogIndex()
    rows = await asyncio.to_thread(_corpus_rows, data_dir)
    add_corpus(index, rows)
    del rows
    add_community(index, await community_rows(db))
    return index
