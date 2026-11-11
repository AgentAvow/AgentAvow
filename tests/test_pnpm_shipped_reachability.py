"""pnpm v9: only what a shipped workspace member reaches at runtime counts as a
production dependency (colinhacks/zod, 2026-11-11: next@15 came from the private
@zod/docs site, and dev tools' transitive deps were graded as shipped).

Every rule has the twin that keeps a real production dependency at full weight."""
from __future__ import annotations

from src.scanner import lockfiles as lf

LOCK = """lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    devDependencies:
      vitest:
        specifier: ^4.0.0
        version: 4.1.5(@types/node@22.0.0)

  packages/lib:
    dependencies:
      left-pad:
        specifier: ^1.3.0
        version: 1.3.0
      '@ws/helpers':
        specifier: workspace:*
        version: link:../helpers

  packages/helpers:
    dependencies:
      ms:
        specifier: ^2.1.3
        version: 2.1.3

  packages/docs:
    dependencies:
      next:
        specifier: ^15.5.0
        version: 15.5.25(react@19.0.0)
      '@types/react':
        specifier: npm:types-react@19.0.0-alpha.3
        version: types-react@19.0.0-alpha.3
      fixture:
        specifier: file:fixtures/fixture
        version: file:fixtures/fixture

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-a}

  ms@2.1.3:
    resolution: {integrity: sha512-b}

  vitest@4.1.5:
    resolution: {integrity: sha512-c}

  '@vitest/mocker@4.1.5':
    resolution: {integrity: sha512-d}

  tinypool@1.0.0:
    resolution: {integrity: sha512-e}

  next@15.5.25:
    resolution: {integrity: sha512-f}

  form-data@4.0.2:
    resolution: {integrity: sha512-g}

  react@19.0.0:
    resolution: {integrity: sha512-h}

  types-react@19.0.0-alpha.3:
    resolution: {integrity: sha512-i}

snapshots:

  left-pad@1.3.0: {}

  ms@2.1.3: {}

  vitest@4.1.5(@types/node@22.0.0):
    dependencies:
      '@vitest/mocker': 4.1.5
      tinypool: 1.0.0

  '@vitest/mocker@4.1.5': {}

  tinypool@1.0.0: {}

  next@15.5.25(react@19.0.0):
    dependencies:
      form-data: 4.0.2
      react: 19.0.0

  form-data@4.0.2: {}

  react@19.0.0: {}

  types-react@19.0.0-alpha.3: {}
"""

PRIVATE = {".", "packages/docs", "packages/helpers"}


def _prod(lock=LOCK, priv=None):
    pv = {"pnpm-lock.yaml": priv} if priv is not None else None
    return {f"{d.name}@{d.version}" for d in lf.parse_all({"pnpm-lock.yaml": lock}, pv)
            if not d.dev}


def test_importers_links_aliases_and_files():
    imps = lf.pnpm_v9_importers(LOCK)
    assert imps["packages/lib"]["links"] == {"packages/helpers"}
    assert "types-react@19.0.0-alpha.3" in imps["packages/docs"]["prod"]
    assert not any("fixture" in x for x in imps["packages/docs"]["prod"])


def test_private_docs_and_dev_transitives_are_not_shipped():
    prod = _prod(priv=PRIVATE)
    # the published library and what it reaches (its private helper is linked in)
    assert prod == {"left-pad@1.3.0", "ms@2.1.3"}


def test_a_private_member_linked_by_a_shipped_one_ships():
    # packages/helpers is private, but packages/lib (public) depends on it
    assert "ms@2.1.3" in _prod(priv=PRIVATE)


def test_without_private_info_every_member_ships():
    prod = _prod()
    assert {"next@15.5.25", "form-data@4.0.2", "left-pad@1.3.0", "ms@2.1.3"} <= prod
    # dev tools' transitives are still not shipped
    assert "@vitest/mocker@4.1.5" not in prod and "tinypool@1.0.0" not in prod


def test_all_private_app_keeps_its_runtime_deps():
    # An app repo (every member private): its deps are what its users run.
    prod = _prod(priv={".", "packages/lib", "packages/helpers", "packages/docs"})
    assert {"next@15.5.25", "form-data@4.0.2", "left-pad@1.3.0"} <= prod


def test_unreadable_graph_changes_nothing():
    # A shipped root missing from snapshots: fail safe, everything keeps prod weight.
    broken = LOCK.replace("  left-pad@1.3.0: {}\n", "")
    assert lf.pnpm_v9_unshipped(broken, PRIVATE) is None
    assert "next@15.5.25" in _prod(broken, PRIVATE)


def test_no_snapshots_block_changes_nothing():
    v8 = LOCK.split("\nsnapshots:\n")[0]
    assert lf.pnpm_v9_unshipped(v8, PRIVATE) is None


def test_shipped_wins_across_lockfiles():
    other = """lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      next:
        specifier: ^15.5.0
        version: 15.5.25(react@19.0.0)

packages:

  next@15.5.25:
    resolution: {integrity: sha512-f}

  react@19.0.0:
    resolution: {integrity: sha512-h}

snapshots:

  next@15.5.25(react@19.0.0):
    dependencies:
      react: 19.0.0

  react@19.0.0: {}
"""
    deps = lf.parse_all({"a/pnpm-lock.yaml": LOCK, "b/pnpm-lock.yaml": other},
                       {"a/pnpm-lock.yaml": PRIVATE})
    nxt = [d for d in deps if d.name == "next"]
    assert len(nxt) == 1 and nxt[0].dev is False
