"""Guard for the scan.py split (#415): ``src.scanner.scan`` keeps every name it exposes.

Callers in ``src/``, ``scripts/`` and ``tests/`` import from ``src.scanner.scan``. While
code moves into ``src/scanner/static/``, ``scan.py`` re-exports what it moved, so none of
those imports change. This test compares the names ``scan`` exposes today with the
snapshot in ``tests/fixtures/scan_surface.txt`` and fails if any are gone. Imported
modules (``re``, ``json``, ``httpx`` …) are not part of the surface.

Adding names is fine. To record new names, regenerate the snapshot:

    python3 -c "from tests.test_scan_surface import write_snapshot; write_snapshot()"
"""

from __future__ import annotations

import types
from pathlib import Path

SNAPSHOT = Path(__file__).resolve().parent / "fixtures" / "scan_surface.txt"


def current_surface() -> set[str]:
    from src.scanner import scan

    return {
        name
        for name in dir(scan)
        if not name.startswith("__") and not isinstance(getattr(scan, name), types.ModuleType)
    }


def snapshot() -> set[str]:
    lines = SNAPSHOT.read_text(encoding="utf-8").splitlines()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


def write_snapshot() -> None:
    header = "# Names src.scanner.scan exposes (tests/test_scan_surface.py). May only grow.\n"
    SNAPSHOT.write_text(header + "\n".join(sorted(current_surface())) + "\n", encoding="utf-8")


def missing_names(expected: set[str], actual: set[str]) -> list[str]:
    return sorted(expected - actual)


def test_snapshot_is_not_empty():
    assert len(snapshot()) > 300


def test_scan_surface_does_not_shrink():
    missing = missing_names(snapshot(), current_surface())
    assert not missing, (
        f"src.scanner.scan no longer exposes {len(missing)} name(s): {missing[:20]}. "
        "Re-export them from scan.py (from src.scanner.static.<module> import <name>)."
    )


def test_guard_fires_on_planted_violation():
    """Self-check: dropping one exported name is reported."""
    expected = snapshot()
    dropped = sorted(expected)[0]
    assert missing_names(expected, expected - {dropped}) == [dropped]
