# Tool-manifest-digest vectors (v1-noncanonical): definitions JCS cannot carry

A separate packet for the per-tool digest in
[v1](../tool-manifest-digest-vectors-v1/) (`agentavow.mcp-tool-definition.v1`). It covers
the definitions RFC 8785 cannot canonicalize once parsed, and the issuer's fallback digest
for them. It is a new folder so that v1, v1-annotations, v1-numbers and the run records
made against them stay exactly as they are.

    node verify.mjs

Zero dependencies, Node 18+. Nothing is fetched. Exits non-zero on any failure.

## When the fallback applies

`JSON.parse` and Python's `json.loads` both accept two things JCS cannot print:

- a lone surrogate, from an escape such as `"\ud800"` with no partner;
- a number literal too large for a double (`1e400`), which reads as Infinity.

For such a definition the issuer does not fail. It digests a different preimage under a
distinct label:

```
LABEL    = "agentavow.mcp-tool-definition.v1.noncanonical"
TEXT     = Python json.dumps(tool, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
           over the same restricted definition as v1 (name, title, description,
           inputSchema, outputSchema, annotations; missing or null omitted)
preimage = LABEL + "\n" + TEXT, as UTF-8 with each lone surrogate written as its own
           three-byte form (Python "surrogatepass", also called WTF-8)
digest   = "sha256:" + hex(sha256(preimage))
```

Keys sort by code point, not UTF-16 unit. Strings escape `"`, `\`, `\n`, `\r`, `\t`, `\b`,
`\f` and other controls as `\u00XX`. Everything else is literal. Numbers print as Python
does: an integer literal as its digits, any other number as Python's `repr` of the double
(`0.1`, `1e-05`, `1e+16`), and Infinity as `Infinity`. The digest is stable, and any change
to the definition changes it, so drift detection works. It is not portable: it can never
equal a v1 digest, and a reader that does not have the literal number forms cannot always
rebuild it. A reader that cannot rebuild it should treat the tool as unbound, not as
matching.

## The 2026-11 change

Until November 2026 the issuer encoded `TEXT` as strict UTF-8. A lone surrogate made that
fail, and the definition fell through to the constant
`sha256(LABEL_BASE + ".unhashable")`, which is the same for every such definition. A server
could then change a tool with a lone surrogate in it without changing its signed digest.
The issuer now passes lone surrogates through. That changes the signed digest of those
tools, and only those. `.unhashable` remains only for a body that `json.dumps` itself
refuses, which a parsed `tools/list` never produces. The gates never bind to it.

## The five cases

1. **lone-surrogate**: a lone high surrogate in the description.
2. **lone-surrogate-drift**: the same tool with the description changed. Its digest
   differs from case 1. Before the fix the two were equal.
3. **lone-surrogate-key**: a lone low surrogate as a property name.
4. **numbers-in-fallback**: a lone surrogate beside `100`, `0.1` and `1e-05`, which print
   as `100`, `0.1` and `1e-05`.
5. **overflow-literal**: `"maximum": 1e400`, printed as `Infinity`.

Each case carries the raw JSON text (`definition_json`), the expected preimage bytes as
hex (`preimage_hex`, because the bytes are not valid UTF-8) and the `digest`.

## Provenance

`generate.py`, run from the repository root with the backend's environment, computes the
expected values with the issuer's `src/scanner/mcp_scan.py` `tool_definition_digest`.
Running it again produces byte-identical output. These are unsigned derivation vectors.
`tests/test_tool_digest_noncanonical_vectors.py` checks that the issuer, the Python gate,
the Claude Code plugin gate and this verifier agree.

## Licence

This directory (the vector file, `generate.py`, `verify.mjs` and this README) is licensed
under Apache-2.0; see [`LICENSE`](./LICENSE) here.
