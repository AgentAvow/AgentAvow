# Catalog skill rows that open an error page (2026-11)

The round-2 verdict audit found three kinds of odd row in the Do-not-connect list. This
page records what a visitor saw, why it happened, and what changed.

## What a visitor saw (public site, checked 2026-11-15)

- `GET /api/v1/public/scan-catalog` lists, for example, `kwalus/Canopy` as an
  **Agent skill**, Do not connect, `page_path: /check/skill/kwalus/Canopy`,
  `scan_source: launch`.
- `GET /api/v1/public/scan/skill/kwalus/Canopy` answers 404
  `No SKILL.md found — this repo isn't a recognizable Agent Skill.` The skill page then
  renders "Not a recognizable Agent Skill". So Browse said Do not connect and the page
  it opened said "not a skill". The same holds for the other 10 audited rows:
  zhaoxinyi02/ClawPanel, riba2534/happyclaw, robsannaa/openclaw-mission-control,
  openclaw/openclaw-ansible, pjasicek/OpenClaw, milady-ai/milady, byJoey/openclawctl,
  itq5/OpenClaw-Admin, MemTensor/MemOS-Cloud-OpenClaw-Plugin, bgdnvk/clanker.
- `LycheeMem/LycheeMem` is still listed as an Agent skill, Do not connect, 1,096 stars.
  GitHub's repo API answers 404, and the skill page said "couldn't find a SKILL.md",
  which is the wrong reason.

## Root causes

1. **The launch skill corpus never required a SKILL.md.** `openclaw-results.json` came
   from `scripts/scan_openclaw_batch.py`: GitHub searches (`topic:openclaw`,
   `"openclaw skill"`, `org:openclaw`, `"openclaw in:name"`) graded with `scan_repo`, the
   repo scanner. Any repo that matched a search became an "Agent skill" row with a
   `/check/skill/…` page. Control panels, CLIs and Ansible roles that mention OpenClaw
   got in this way, and so did `pjasicek/OpenClaw` (a C++ Captain Claw remake) through
   the `in:name` query. The verdicts are repo-scanner verdicts, which is why the repo
   endpoint agrees with them.
2. **A failed re-scan is silent.** The catalog re-scan loop
   (`scheduler._rescan_stale_corpus_rows` → `_rescan_catalog_row`) runs `scan_skill` for
   every corpus skill row. On an error it returns False and writes nothing; the
   coordinate goes into the in-memory `_supersede_failed` set. The launch row therefore
   kept its old verdict and its skill page path forever, whether the repo had no
   SKILL.md or no longer existed.
3. **Weekly discovery is not affected.** `src/catalog_growth` uses the same GitHub
   searches, but it scans candidates with `scan_skill`, and a failed scan writes no row.
   So new rows already need a SKILL.md; only the launch corpus is wrong.

## What changed

- `src/api/catalog_skill_rows.py` keeps an overlay, `data/launch-scans/skill-rows.json`
  (the same pattern as `mcp-endpoints.json`). When the re-scan loop's skill scan of a
  **launch-corpus skill row** fails:
  - with `No SKILL.md found` (the tree was read), the row is recorded `no_skill_md`. The
    catalog then lists it as a plain GitHub repo row (`/check/<owner>/<repo>`), keeping
    its repo-scanner verdict. The repo page renders, and the live repo scan takes it over
    as usual. A later successful skill scan clears the entry.
  - with `Repository not found or unreadable`, the loop asks GitHub's repo API once more.
    Only a 404 or 451 records `repo_gone`, and the row leaves the catalog. A rate limit,
    a 403 or an outage never delists anything.
- The overlay file is part of the catalog's source signature, so the catalog reloads
  when the loop writes it.
- The skill page's error state says "Repository unavailable" for a deleted repo, and for
  a repo with no SKILL.md it links to the repo's own scan.

Not changed here: the scanner itself (`src/scanner/scan.py`, `skill_scan.py`; open PRs
touch them), and live community rows whose repo later disappears (a separate staleness:
they are re-scanned through other loops).

## One-off cleanup (optional, not run)

The loop fixes each row as it reaches it. To fix the audited rows now, on the API host:

```bash
python3 scripts/catalog_skill_rows_cleanup.py --audit-rows          # dry run
python3 scripts/catalog_skill_rows_cleanup.py --audit-rows --apply  # write the overlay
```

`--all` checks every corpus skill row (about 500 repos, two GitHub calls each, one
second apart). The script is read-only against GitHub and touches no database.
Undo: delete the entries (or the whole file) from `data/launch-scans/skill-rows.json`.

## Note for later

`pjasicek/OpenClaw` stays in the catalog as a GitHub repo row with its repo verdict
(`travis.sh` pipes Coverity's CI script to bash; audit class N4, a scanner false
positive tracked separately).
