## What changed and why

<!-- One or two plain sentences, written for the person affected. Link the issue: "Part of #123" or "Fixes #123". -->

## Checks

- [ ] `make check` passes (lint, AST verify, doc parity, web typecheck)
- [ ] Tests I ran locally, against my own test database (not dev, staging or prod):
- [ ] Python table changed? Its TypeScript twin changed in this PR too: `src/scanner/verdict.py` ↔ `web/src/components/trust/gradeSystem.ts`, `src/scanner/categories.py` ↔ `web/src/components/trust/scanCategories.ts`
- [ ] `src/scanner/` changed? I checked for new false negatives as well as false positives (corpus or fixture test; `make corpus` if detection moved)
- [ ] AGENTS.md still matches what this PR changed (commands, paths, house rules)

<!-- Tick or delete boxes that don't apply. If this touches the hosted /mcp tool list, the public API, the badge routes or /.well-known, say so here: those changes must be additive. -->
