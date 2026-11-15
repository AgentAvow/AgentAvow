# src/scanner/static

The static scan of code, manifests and packages, moving here out of
`src/scanner/scan.py` one block at a time. The plan, its steps and its layer order
are in issue #415.

## What lives here

Nothing yet. Each split step adds one module (or one small folder with its own
AGENTS.md) and lists it here, one line per module.

## Rules while the split is in progress

- **Move, don't edit.** A step cuts a block out of `scan.py` and pastes it here
  unchanged. The only new lines are the module's imports, the re-export lines in
  `scan.py`, and the folder docs. Fixes and new rules go in their own PRs, never in
  a move step.
- **`scan.py` keeps its names.** Every name it exposes today stays importable from
  `src.scanner.scan` through an explicit re-export. Callers and tests don't change in
  a move step.
- **Imports point down.** A module here never imports `src.scanner.scan`. It imports
  only lower layers and the sibling scanner modules `scan.py` already uses. Keep
  function-local imports exactly as they were; they break import cycles.
- **Module-level state moves with its readers.** A cache or table goes in the same
  step as every function that reads it.
- **Network I/O lives in one place.** Only the fetch layer talks to GitHub.
- **Size.** Aim for modules well under 800 lines.

## How a step proves it changed nothing

Every move step must pass all four:

1. `python3 scripts/dev/check_moved.py origin/main .` reports OK: every function,
   class and constant from `scan.py` exists exactly once with an identical syntax
   tree, and nothing new was added.
2. `tests/test_scan_surface.py`: `src.scanner.scan` still exposes every name in
   `tests/fixtures/scan_surface.txt`.
3. `tests/test_scan_patch_targets.py`: no test patch on `src.scanner.scan` has gone
   silent. If it fails, point the named tests at the module that now defines the
   name, in the same step.
4. The full test suite gives the same pass and skip counts as the base commit, and
   the static corpus shows no change against `expected.json`.

Import-layer contracts for this package follow the repo's import-linter setup
(#411) and will be added here when that lands.
