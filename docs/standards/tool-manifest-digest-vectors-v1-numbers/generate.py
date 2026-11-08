"""Build tool-manifest-digest-v1-numbers-vectors.json with the issuer's own derivation.

    python3 docs/standards/tool-manifest-digest-vectors-v1-numbers/generate.py

Run from the repository root with the backend's environment (it imports
``src.scanner.mcp_scan`` and ``rfc8785``). Each definition is written below as raw JSON
text, because the cases are about how number literals are read: ``json.loads`` keeps
``9007199254740993`` as an exact integer, and the issuer reads it as the double
``JSON.parse`` gives. The expected digest and canonical preimage are what the issuer
(``tool_definition_digest``, the function whose output is signed into the attestation)
computes from that text. Running it again produces byte-identical output.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

import rfc8785  # noqa: E402

from src.scanner.mcp_scan import (  # noqa: E402
    _TOOL_DIGEST_FIELDS,
    MCP_TOOL_DIGEST_PROFILE,
    _as_ijson,
    tool_definition_digest,
)

OUT = Path(__file__).with_name("tool-manifest-digest-v1-numbers-vectors.json")


def _definition(schema: str) -> str:
    return ('{"name":"set_limit","description":"Set a numeric limit.",'
            '"inputSchema":{"type":"object","properties":{"value":' + schema + '},'
            '"required":["value"]}}')


CASES = [
    ("fraction",
     "Fractions in inputSchema. Each is written as the shortest decimal that reads back "
     "to the same double.",
     _definition('{"type":"number","minimum":-273.15,"multipleOf":0.1}')),
    ("integer-2^53",
     "An integer at 2^53, one past Number.MAX_SAFE_INTEGER. A double holds it exactly.",
     _definition('{"type":"integer","maximum":9007199254740992}')),
    ("integer-2^53+1",
     "An integer at 2^53 + 1. No double holds it: JSON.parse reads it as 2^53, and the "
     "issuer does the same. So its digest equals the integer-2^53 case's.",
     _definition('{"type":"integer","maximum":9007199254740993}')),
    ("large-exponent",
     "A large exponent (1e300), and 1e21, the first integer ECMAScript prints in "
     "exponent form.",
     _definition('{"type":"number","maximum":1e300,"exclusiveMinimum":1e21}')),
    ("negative-zero",
     "-0 written as an integer and as a fraction. Both canonicalize to 0.",
     _definition('{"type":"number","minimum":-0,"default":-0.0}')),
]
SAME_DIGEST = [["integer-2^53", "integer-2^53+1"]]


def build() -> dict:
    cases = []
    for name, note, text in CASES:
        tool = json.loads(text)
        body = {f: tool[f] for f in _TOOL_DIGEST_FIELDS if tool.get(f) is not None}
        preimage = rfc8785.dumps({"profile": MCP_TOOL_DIGEST_PROFILE, "tool": _as_ijson(body)})
        digest = tool_definition_digest(tool)
        if digest != "sha256:" + hashlib.sha256(preimage).hexdigest():
            raise SystemExit(f"{name}: the issuer's digest is not over the portable preimage")
        cases.append({"name": name, "note": note, "definition_json": text,
                      "preimage": preimage.decode("utf-8"), "digest": digest})
    by_name = {c["name"]: c["digest"] for c in cases}
    for group in SAME_DIGEST:
        if len({by_name[n] for n in group}) != 1:
            raise SystemExit(f"expected equal digests: {group}")
    return {
        "suite": "tool-manifest-digest-v1-numbers",
        "profile": MCP_TOOL_DIGEST_PROFILE,
        "status": "additive to tool-manifest-digest-v1; v1's vector file is unchanged",
        "rule": ("Every JSON number is read as an IEEE 754 double, as ECMAScript JSON.parse "
                 "reads it, and printed as ECMAScript Number::toString prints it (RFC 8785 "
                 "section 3.2.2.3). Fractions are digestible. An integer beyond 2^53 is "
                 "hashed at its double value. -0 prints as 0."),
        "derivation": ("digest = 'sha256:' + hex(sha256(preimage)); preimage = JCS({profile, "
                       "tool}) with tool restricted to name, title, description, inputSchema, "
                       "outputSchema, annotations; parse definition_json with JSON.parse or "
                       "equivalent"),
        "produced_by": ("src/scanner/mcp_scan.py tool_definition_digest (the issuer), via "
                        "generate.py"),
        "same_digest": SAME_DIGEST,
        "cases": cases,
    }


if __name__ == "__main__":
    OUT.write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
