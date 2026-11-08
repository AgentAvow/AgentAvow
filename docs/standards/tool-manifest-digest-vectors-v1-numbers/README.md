# Tool-manifest-digest vectors (v1-numbers): how numbers are read

A separate packet for the per-tool digest in
[v1](../tool-manifest-digest-vectors-v1/) (`agentavow.mcp-tool-definition.v1`). v1's three
served definitions hold no number other than small integers, so v1 never tests how a
number in a tool definition is canonicalized. This packet does. It is a new folder so that
the v1 packet and the run records made against it stay exactly as they are.

    node verify.mjs

Zero dependencies, Node 18+. Nothing is fetched. Exits non-zero on any failure.

## The rule

Every JSON number in a served definition is read as an IEEE 754 double, as ECMAScript
`JSON.parse` reads it, and printed in the preimage as ECMAScript `Number::toString` prints
it (RFC 8785 section 3.2.2.3). So:

- a fraction is digestible (`0.1` prints as `0.1`, `-273.15` as `-273.15`);
- an integer beyond 2^53 is hashed at its double value (`9007199254740993` reads as
  `9007199254740992`, so the two give one digest);
- a large magnitude prints in exponent form (`1e300` as `1e+300`; `1e21` is the first
  integer printed that way);
- `-0` prints as `0`.

The derivation is otherwise v1's: `"sha256:" + hex(sha256(JCS({ "profile":
"agentavow.mcp-tool-definition.v1", "tool": tool })))` over `name, title, description,
inputSchema, outputSchema, annotations`, a missing or null field omitted, `_meta` never
hashed.

## The five cases

Each case carries the served definition as raw JSON text (`definition_json`), because the
cases are about how number literals are read; a parser that keeps exact integers must
read them as doubles first. Each also carries the canonical `preimage` and the `digest`.

1. **fraction**: `"minimum": -273.15, "multipleOf": 0.1`.
2. **integer-2^53**: `"maximum": 9007199254740992`.
3. **integer-2^53+1**: `"maximum": 9007199254740993`. Same digest as case 2.
4. **large-exponent**: `"maximum": 1e300, "exclusiveMinimum": 1e21`.
5. **negative-zero**: `"minimum": -0, "default": -0.0`.

`verify.mjs` parses each `definition_json` with `JSON.parse`, recomputes the preimage
and digest with v1's `jcs` and `toolDigest` (copied unchanged) and checks both, then
checks that cases 2 and 3 share one digest.

## Provenance

The expected values were computed by the issuer: `generate.py` (run from the repository
root with the backend's environment) reads each definition with `json.loads` and calls
`src/scanner/mcp_scan.py` `tool_definition_digest`, the function whose output is signed
into the attestation's `scan.toolDigests`. Running it again produces byte-identical
output. These are unsigned derivation vectors: there is no attestation in this packet,
only the per-tool digest the issuer would sign for each definition.

The repository test `tests/test_tool_digest_number_vectors.py` checks that the issuer, the
Python gate (`src/bridges/tool_gate.py`), the Claude Code plugin gate and this verifier
agree on all five, and that the npm gate's canonicalizer does when it is installed.

## Outside the profile

NaN and Infinity have no JSON or JCS form. `JSON.parse` never produces them except for a
literal too large for a double (`1e400`). The issuer digests such a definition under a
distinct label (`agentavow.mcp-tool-definition.v1.noncanonical`) that no portable digest
can equal, so no vector here covers it.

## Licence

This directory (the vector file, `generate.py`, `verify.mjs` and this README) is licensed
under Apache-2.0; see [`LICENSE`](./LICENSE) here.
