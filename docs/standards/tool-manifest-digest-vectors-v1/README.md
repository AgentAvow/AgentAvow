# Tool-manifest-digest vectors (v1): one named tool

Extends [v0](../tool-manifest-digest-vectors-v0/) for the boundary on
[aeoess/agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177)
(edge E1 in [#179](https://github.com/aeoess/agent-governance-vocabulary/pull/179)).
v0 bound a gate to a whole server by its manifest digest. The first consumer run recorded
that the attestation carried no tool name, so a gate authorizing one tool had nothing to
bind to. v1 closes that: the attestation now signs one digest per served tool, keyed by
tool name, and the gate binds to the tool it is authorizing.

    node verify.mjs

Zero dependencies, Node 18+. Nothing is fetched. Exits non-zero on any failure.

## The artifact

One real, pinned AgentAvow scan attestation for the live MCP server at
`https://mcp.deepwiki.com/mcp` (a public, unauthenticated server with three tools): a
compact JWS (RFC 7515, EdDSA/Ed25519) whose payload is the RFC 8785 canonical bytes of
the verdict. Inside the signed payload: the issuer (`did:web:agentgraph.co`), the subject
`mcp:https://mcp.deepwiki.com/mcp`, `issuedAt`, `expiresAt`, the score and tier, the
findings, `scan.toolDigests` (one digest per tool, keyed `tool:<name>`), and
`scan.toolManifestDigest` folded over them.

The file also carries `observed_tools`: the `tools/list` the server served at scan time,
fetched directly from the server and unmodified. That is what makes the preimage
testable (below).

## The consumer input

A gate supplies four things about the one tool call it is about to authorize:

```jsonc
"gate": {
  "subject_id": "mcp:https://mcp.deepwiki.com/mcp",     // the server
  "tool_name": "ask_wiki_question",                      // the tool being authorized
  "observed_tool_digest": "sha256:171a53c9…",            // digest of the definition it was served
  "evaluation_time": "2026-10-01T22:28:34.085Z"          // pinned, so verdicts are reproducible
}
```

A gate computes `observed_tool_digest` itself, from the `tools/list` entry it holds,
with no call to the issuer. The derivation:

```
tool      = the served definition restricted to
            name, title, description, inputSchema, outputSchema, annotations
            (a missing or null field is omitted; _meta and unknown fields are never hashed)
preimage  = JCS({ "profile": "agentavow.mcp-tool-definition.v1", "tool": tool })
digest    = "sha256:" + hex(sha256(preimage))
key       = "tool:" + body, where body is the name with every character outside
            0x21-0x7E (space, controls and all non-ASCII), plus % and =, replaced by
            its UTF-8 bytes as %XX (uppercase hex); if that encoded body is longer
            than 128 characters it is cut to its first 96 and suffixed with "~" and
            the first 16 lowercase hex characters of sha256 over the raw UTF-8 name;
            the cut is a plain character count and may land inside a %XX triplet
```

The profile label versions the preimage: if the field set ever changes, the label changes,
and an old digest can never be mistaken for a new one.

## The six axes

A consumer reports these separately. None is derived from another.

- **signature_valid**: Ed25519 verifies under the pinned key.
- **canonical_bytes**: `jcs(JSON.parse(payload))` equals the payload bytes.
- **subject_binds**: the attestation's subject is the server the gate names.
- **tool_binds**: the scan observed a tool of the name the gate is authorizing.
- **tool_digest_binds**: the signed digest for that tool equals the digest the gate
  computed from the definition it was served. `not_evaluated` when `tool_binds` is false:
  there is no signed digest to compare, and the verifier says so rather than reporting a
  failure it did not measure.
- **fresh**: `evaluation_time` is inside `[issuedAt, expiresAt)`.

`rely` is all six. Whether a gate proceeds on `rely=true` is a separately versioned
admission policy.

## The six cases

1. **tool-match**: the positive case.
2. **unknown-tool**: the gate authorizes `delete_wiki_page`, which the scan never saw.
   `tool_binds` false, `tool_digest_binds` not evaluated.
3. **tool-drift**: the definition the gate was served has one sentence added to its
   description after the grade (the rug-pull, per tool). Only `tool_digest_binds` fails.
4. **wrong-subject**: the same tool name and digest presented for a different server.
5. **past-expiry**: evaluated after `expiresAt`.
6. **tampered-payload**: score raised after signing, payload re-canonicalized, original
   signature kept. Canonical bytes still check; the signature does not.

Each negative fails exactly one axis, and the verifier asserts that.

## What the verifier also checks

Before the vectors, it recomputes the digest of every served definition in
`observed_tools` with the derivation above and checks it against the signed
`scan.toolDigests`. All three match. So the preimage is under test across
implementations, not only the comparison: a consumer in another language that gets the
same three digests from the same three definitions has implemented the derivation
correctly.

## Key encoding

The pinned server's tool names are plain ASCII, so the six cases never exercise the
key rules. `key_encoding` in the vector file carries thirteen name-to-key pairs that
do: seven for percent-encoding (`=`, `%`, space, a tab, `é`, an emoji) and six for the
length rule (an encoded body of exactly 128 stays literal; 129 ASCII characters, 200
ASCII characters, and 50 `é` whose encoded body is 300 characters are cut and
suffixed; two names whose cut lands inside a `%XX` triplet, keeping `%` and `%C`
respectively). They are derived with the same rules and carry no signature; the
expected keys were produced by the issuer's own implementation. The verifier checks
them; an implementer who gets all thirteen has the encoder right.

## Claim ceiling

`rely=true` establishes exactly this: at `evaluation_time`, the named issuer had signed a
static-analysis grade for this server, the grade covered a tool of this name, the
definition the gate was served for that tool is the one the scan graded, and signature,
subject and window all check. It establishes nothing about runtime behavior, nothing about
what the tool does when invoked, nothing about other tools on the server, and nothing
about definitions the scan did not observe.

## Boundaries carried over from v0

- The subject is a server, not a tool; the tool binding is the separate `tool_binds` axis.
- `scan.toolManifestDigest` is a fold over the per-tool digests, not a per-tool metadata
  pin, and the v1 gate does not use it. A consumer that needs the whole-server binding
  uses v0.

## Derivation

`node generate.mjs` rebuilds the vector file from `source.json` (the pinned JWS, JWK and
the served `tools/list`). It refuses to build if any served definition does not recompute
to its signed digest. The pinned attestation was fetched once on 2026-10-01 from
`https://agentavow.com/api/v1/public/scan/mcp?endpoint=https%3A%2F%2Fmcp.deepwiki.com%2Fmcp`;
the `tools/list` was fetched from the server in the same minute. A fresh fetch yields a
fresh attestation, so the file is the fixture, not the URL.
