"""Catalog growth: find new tools and re-scan tools whose version moved.

Two jobs, each behind its own off | dry-run | on switch (default off):

* ``discover`` (weekly, CATALOG_DISCOVERY): lists the MCP Registry, npm (MCP and agent
  packages), PyPI (same), OpenClaw skills (GitHub search + ClawHub) and Smithery, keeps
  the entries whose catalog page does not exist yet (the catalog's own one-row-per-page
  key, ``scan_catalog_router.page_key``), and queues them for a scan. The same run takes
  launch-corpus rows skipped for "no readable code" that have a remote MCP endpoint and
  queues the live tool-definition scan for them.
* ``refresh`` (daily, CATALOG_REFRESH): for the top catalog tools by adoption (daily) and
  the rest (weekly, one seventh a day), compares the registry's latest version or the
  repo's default-branch HEAD with what was scanned, and queues only the changed ones.

Both run as a one-off container of the backend image (``python -m src.catalog_growth``,
see scripts/catalog_growth.sh), never inside a web worker. Scans go through the same
path as the catalog re-scan loop (``scheduler._rescan_catalog_row``) into
community_scans, which Browse already reads. Nothing here touches the sitemap or
IndexNow: a Do-not-connect answer from these jobs is written to a human review list and
is never pushed to search (owner decision 2026-11-11, B11).
"""
