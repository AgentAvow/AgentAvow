"""A critical ``secret`` finding alone caps at Review (verdict.SECRET_CATEGORY), so the
category must stay limited to hardcoded credential values. This pins every place that
emits it: a new emitter (say, a credential-read or credential-send rule) fails here and
has to be reviewed against the cap instead of silently inheriting it."""
from __future__ import annotations

import re
from pathlib import Path

from src.scanner.patterns import SECRET_PATTERNS

SRC = Path(__file__).resolve().parent.parent / "src"
# Finding(category="secret", …) and _capability("secret", …) call sites, per file.
_EMIT_RE = re.compile(r"""category\s*=\s*["']secret["']|_capability\(\s*["']secret["']""")
KNOWN = {
    "scanner/scan.py": 2,           # SECRET_PATTERNS hits + the PEM marker (info capability)
    "scanner/artifact_scan.py": 1,  # docker image ENV / label (high)
    "scanner/skill_scan.py": 1,     # "Uses your … API key" (capability, excluded from the cap)
    "scanner/behavioral/graders.py": 1,     # canary echoed in a tool result (medium)
    "scanner/behavioral/live_probe.py": 1,  # secret-like tool result (medium)
}


def test_secret_category_emitters_are_pinned():
    found = {}
    for path in SRC.rglob("*.py"):
        n = len(_EMIT_RE.findall(path.read_text(encoding="utf-8")))
        if n:
            found[str(path.relative_to(SRC))] = n
    assert found == KNOWN, (
        "A new emitter of category 'secret' must be a hardcoded credential VALUE only "
        "(a secret alone caps at Review). Credential reads / sends are 'exfiltration'.")


def test_secret_patterns_only_match_literal_credential_values():
    # every rule in SECRET_PATTERNS names a credential format, not a behaviour
    for name, _pat, _sev in SECRET_PATTERNS:
        assert not re.search(r"read|send|exfil|upload|post|leak", name, re.I), name
