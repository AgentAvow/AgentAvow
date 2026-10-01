"""Fixture: reads stdin forever and never answers anything (a hung server)."""
from __future__ import annotations

import sys

if __name__ == "__main__":
    sys.stderr.write("warming up (forever)\n")
    sys.stderr.flush()
    for _ in sys.stdin:
        pass
