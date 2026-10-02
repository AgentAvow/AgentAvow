# Tool-manifest-digest vectors (v0)

Conformance vectors for the boundary proposed on
[aeoess/agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177):
**tool-safety evidence consumed by a pre-execution gate, bound by the tool-definition digest.**
Proposed consumer-input shape and expected outcomes for the boundary to refine, not a
finalized schema.

    node verify.mjs

Zero dependencies, Node 18+. Nothing is fetched. Exits non-zero on any failure.

## The artifact

One real, pinned AgentAvow scan attestation for `github/github-mcp-server`: a compact JWS
(RFC 7515, EdDSA/Ed25519) whose payload is the RFC 8785 canonical bytes of the verdict.
Inside the signed payload: the issuer (`did:web:agentgraph.co`), the subject, `issuedAt`,
`expiresAt`, the score and tier, the findings, and `scan.toolManifestDigest`, a SHA-256 folded over
the per-file digests of every tool definition the scan observed (`scan.toolDigests`).

The JWK is pinned in the vector file, matched by `kid` to the JWS header. The `jwks_url`
is there so a consumer can cross-check the pin against the live key set; it is not on the
verification path.

## The consumer input

A gate supplies three things about the action it is about to authorize:

```jsonc
"gate": {
  "subject_id": "github:github/github-mcp-server",          // the repo or server being authorized
  "observed_manifest_digest": "sha256:38027bb3…",           // digest of the definitions it sees now
  "evaluation_time": "2026-09-29T18:27:13.430Z"             // pinned, so verdicts are reproducible
}
```

That is deliberately the minimum. An APS decision, a PIC action proposal or a guardrail
provider can carry these three fields however it likes; the vectors only fix what a correct
consumer must conclude from them.

## The five axes

A consumer reports these separately. None is derived from another.

- **signature_valid**: Ed25519 verifies under the pinned key. Binds the signer to what it
  signed, and no further.
- **canonical_bytes**: `jcs(JSON.parse(payload))` equals the payload bytes. Recomputability,
  independent of authenticity.
- **subject_binds**: the attestation's subject is the repo or server the gate is authorizing.
- **digest_binds**: the definitions the scan graded are the definitions the gate observes.
- **fresh**: `evaluation_time` is inside `[issuedAt, expiresAt)`.

`rely` is all five. Whether a gate proceeds on `rely=true` is a separately versioned
admission policy, not part of this set.

## The five cases

1. **digest-match**: the positive case. Same subject, same digest, inside the window.
2. **digest-mismatch**: the definitions drifted after the grade (the rug-pull). Signature,
   subject and freshness all pass. The attestation is simply not about this definition.
3. **past-expiry**: same attestation, evaluated after `expiresAt`. A signed "safe" verdict
   must not verify forever; a grade issued before a tool was trojaned has to stop counting.
4. **wrong-subject**: a valid grade for one subject presented for another.
5. **tampered-payload**: score raised after signing, payload re-canonicalized, original
   signature kept. Canonical bytes still check. Signature does not. Canonical form is not
   authenticity.

Each negative fails exactly one axis, and the verifier asserts that, so a consumer that
collapses axes into one aggregate cannot pass this set by accident.

## Claim ceiling

`rely=true` establishes exactly this: at `evaluation_time`, the named issuer had signed a
static-analysis grade for this subject over this tool-definition digest, and signature,
subject, digest and window all check. It establishes nothing about runtime behavior,
nothing about what the tool does when invoked, and nothing about definitions the scan did
not observe. A behavioral axis is a separate artifact with its own ceiling.

## What the subject and the digest are not

Two boundaries recorded from the first consumer run (an APS-side consumer, reported on
[#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-5899072203)).
Both are limits of the artifact, not of the consumer.

- **The subject is a repo or server, not a named tool.** `subject.id` identifies what was
  scanned, and `scan.toolDigests` is keyed by definition file path. The attestation carries
  no tool name, so it cannot by itself say which tool inside the server a gate is
  authorizing. A consumer that needs that binding reports it as not evaluated.
- **The digest is not a per-tool metadata pin.** `scan.toolManifestDigest` is folded over
  the per-file digests of every definition the scan observed. It has a different preimage
  from a digest over one tool's declared metadata, and neither is evidence for the other.

## Consumers

- **APS-side consumer** (`agent-passport-system` 7.2.0 primitives), owned by APS:
  [`examples/interop/agentavow/` at `fd47f34`](https://github.com/aeoess/agent-passport-system/tree/fd47f34cc36fce060d092fe1216aff3f89fb8d88/examples/interop/agentavow).
  It reads the vector file at `4404df2c` unchanged and reports 30 of 30 expected axis
  results, each negative failing exactly its own axis. By its author's label, a second
  implementation run by the consuming project: a reproduction, not an independent
  verification record. It reports the tool-to-subject binding as not evaluated and keeps
  the manifest digest separate from an APS metadata pin, the two boundaries above.

## Derivation

`node generate.mjs` rebuilds the vector file from `source.json` (the pinned JWS and JWK).
The tampered JWS, the drifted digest and the evaluation times are derived, not transcribed.
The pinned attestation was fetched once on 2026-09-29 from
`https://agentavow.com/api/v1/public/scan/github/github-mcp-server`; a fresh fetch yields a
fresh attestation with new timestamps, so the file is the fixture, not the URL. Any current
attestation from the same endpoint can be dropped into `source.json` to regenerate the set
against a different tool.

## Licence

This directory (the vector file, `source.json`, `generate.mjs`, `verify.mjs` and this README) is licensed under
Apache-2.0; see [`LICENSE`](./LICENSE) here. The repository LICENSE grants a subdirectory with its own LICENSE file
its own terms, so these vectors can be vendored and redistributed by any implementer.
