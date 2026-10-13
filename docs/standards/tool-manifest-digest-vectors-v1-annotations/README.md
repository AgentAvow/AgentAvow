# Tool-manifest-digest vectors (v1-annotations): an annotation-only drift

A separate pinned packet for the per-tool binding in
[v1](../tool-manifest-digest-vectors-v1/), requested on
[Agent-Authority-Conformance/aps-conformance-suite#155](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/155).
v1 hashes `annotations`, but its drift case changes only `description`, and none of its
three served definitions has annotations. So v1 never tests whether an annotation change
breaks the binding. This packet does. It is a new folder so that the v1 packet and the run
records made against it stay exactly as they are.

    node verify.mjs

Zero dependencies, Node 18+. Nothing is fetched. Exits non-zero on any failure.

## What this packet establishes, and what it does not

It establishes one thing: **an annotation change alone breaks the per-tool binding.** The
baseline is a served definition with `annotations.readOnlyHint: true`, signed by the
issuer. The drift case is that definition with `readOnlyHint` set to `false` and every
other field and annotation key byte-identical. Because `annotations` is part of the hashed
preimage, the two digests differ, so `tool_digest_binds` is false and `rely` is false.
The other five axes are unchanged.

It does not establish anything about what the hint means. `readOnlyHint` is something the
server declares about itself. The scan does not measure it, the digest does not interpret
it, and `true` is not evidence that the tool is read-only. The drift case would come out
the same if the hint went from `false` to `true`. Nothing here concerns runtime behaviour.

## The artifact

One real, pinned AgentAvow scan attestation, signed in production, for the live public MCP
server at `https://docs.mcp.cloudflare.com/mcp` (unauthenticated, two tools, server
`docs-ai-search` 0.4.13). It is a compact JWS (RFC 7515, EdDSA/Ed25519) whose payload is
the RFC 8785 canonical bytes of the verdict, signed under the same key as v1
(`kid` `agentgraph-security-v1`). Both served tools carry `annotations` with
`readOnlyHint: true`, and `search_cloudflare_documentation` also carries an `outputSchema`.

The cases use `search_cloudflare_documentation`:

| | digest |
|---|---|
| signed baseline (`readOnlyHint: true`) | `sha256:6294e99197f065f40014c8f43b0cd632affb227f790e8ec57b8c21e77937a84b` |
| drift (`readOnlyHint: false`) | `sha256:7369e8db0094c35b8034bf1b04c258cbb43303a63f9e5b53be6b35a927c2b265` |

The file carries `observed_tools`, the `tools/list` the server served at scan time,
unmodified, and `drift_definition`, the full drifted definition, so that a consumer can
compute the drift digest itself rather than trusting the one in the gate.

## The consumer input, derivation and axes

These are the same as in v1. The gate input has the same four fields (`subject_id`,
`tool_name`, `observed_tool_digest`, `evaluation_time`). The per-tool digest is
`"sha256:" + hex(sha256(JCS({ "profile": "agentavow.mcp-tool-definition.v1", "tool": tool })))`
over `name, title, description, inputSchema, outputSchema, annotations` (a missing or null
field is omitted, and `_meta` is never hashed). The key is `tool:<name>` under the v1
encoding rules. The six axes, `signature_valid`, `canonical_bytes`, `subject_binds`,
`tool_binds`, `tool_digest_binds` and `fresh`, are reported separately, and `fresh` is
compared as exact instants (`time.mjs`, copied unchanged from v1). `rely` is true only
when all six are `true`. See the [v1 README](../tool-manifest-digest-vectors-v1/README.md)
for the full text. `generate.mjs` and `verify.mjs` reuse v1's code for the derivation and
the axes unchanged.

## The six cases

1. **annotation-match**: the positive case. The served definition, as signed. Every axis
   passes and `rely` is true.
2. **annotation-drift**: the same definition with `readOnlyHint` set to `false`, nothing
   else changed. Only `tool_digest_binds` fails, so `rely` is false.
3. **unknown-tool**: the gate authorizes `purge_cloudflare_cache`, which the scan never
   saw. `tool_binds` is false and `tool_digest_binds` is not evaluated.
4. **wrong-subject**: the same tool name and digest, presented for a different server.
5. **past-expiry**: evaluated after `expiresAt`.
6. **tampered-payload**: the score was raised after signing, the payload re-canonicalized
   and the original signature kept. The canonical bytes still check, and the signature
   does not.

The verifier asserts that each negative fails exactly one axis. There is no
`boundary-fresh` case. This attestation's timestamps have whole-millisecond precision
(`2026-10-13T16:08:39.064Z`), so a gate time cut to milliseconds is not inside the
window, and the case would test nothing. v1 keeps that control.

## What the verifier also checks

Before the vectors, it does the following:

- Recomputes the digest of every served definition in `observed_tools` and checks it
  against the signed `scan.toolDigests` (2 of 2). It also checks that the unsigned
  convenience map in the file equals the signed one.
- Checks that the signed baseline carries `readOnlyHint: true` and that the positive
  gate's digest is the digest of that baseline.
- Checks that `drift_definition` carries `readOnlyHint: false`. With the hint set back
  to `true`, it must equal the baseline byte for byte, across all fields and not only the
  hashed ones.
- Checks that the drift gate's digest is the digest of `drift_definition`.

So the packet cannot change a different field and still describe itself as an
annotation-only drift.

## Claim ceiling

`rely=true` establishes exactly this: at `evaluation_time`, the named issuer had signed a
static-analysis grade for this server, the grade covered a tool of this name, the
definition the gate was served for that tool is the one the scan graded, and signature,
subject and window all check. It establishes nothing about runtime behavior, nothing about
what the tool does when invoked, nothing about other tools on the server, and nothing
about definitions the scan did not observe.

## Derivation and provenance

`node generate.mjs` rebuilds the vector file from `source.json` (the pinned JWS, the JWK
and the served `tools/list`). Running it again produces byte-identical output. It refuses
to build in any of these cases:

- a served definition does not recompute to its signed digest
- the served and signed tool sets differ
- the payload is not JCS-canonical
- the chosen tool does not carry `readOnlyHint: true`

The attestation was fetched with one request on 2026-10-13 at 16:08:39Z from
`https://agentavow.com/api/v1/public/scan/mcp?endpoint=https%3A%2F%2Fdocs.mcp.cloudflare.com%2Fmcp&force=true`.
The response said `cached: false`. Its `issuedAt` is `2026-10-13T16:08:39.064Z` and its
`expiresAt` is 24 hours later. The `tools/list` was fetched directly from the server (MCP
Streamable HTTP: `initialize`, `notifications/initialized`, `tools/list`) at
16:08:38.515Z, just before the scan request. A second fetch just after the scan returned
an identical list. The evaluation times are pinned offsets from `issuedAt` and
`expiresAt`, so the verdicts do not depend on when the file is run. A fresh fetch gives a
fresh attestation, so the fixture is this file, not the URL.

## Run it yourself and report

The procedure is `node verify.mjs` (Node 18+, no dependencies, no network). Every check
prints `ok` or `FAIL`, and the run exits non-zero on any failure. To report a run, state:

- the commit of this directory you ran
- your Node version and OS
- the verifier output, verbatim
- whether you used your own implementation or `verify.mjs`

A run counts as independent only when the runner wrote neither these vectors nor the
implementation under test. The claim ceiling above applies to every run.

Contributions to this folder are accepted under its Apache-2.0 licence; see
`CONTRIBUTING.md` at the repository root.

## Licence

This directory (the vector file, `source.json`, `generate.mjs`, `verify.mjs`, `time.mjs`
and this README) is licensed under Apache-2.0; see [`LICENSE`](./LICENSE) here.
