# Consumed-artifact record (v0): one pinned fixture

A first cut at the record [aeoess/agent-governance-vocabulary#185](https://github.com/aeoess/agent-governance-vocabulary/issues/185)
asked for before any attribution formula: a signed, per-action statement of which
artifacts the action consumed, in which role, with evidence a verifier recomputes from.
The definition is in [RECORD.md](./RECORD.md). This directory is the fixture: one
positive record built from the pinned APS x PriorSeal pair, three negatives, and a
verifier that takes nothing on trust.

    node verify.mjs

Zero dependencies, Node 18+. Nothing is fetched. Exits non-zero on any failure.

## The pair

Edge E2 of the [#179 boundary map](https://github.com/aeoess/agent-governance-vocabulary/pull/179):
APS decision evidence consumed by a PriorSeal exact-call authorization.

- Producer: `aeoess/agent-passport-system` at
  [`948f99b8`](https://github.com/aeoess/agent-passport-system/commit/948f99b85343bef2c6fa677c8543965caacfc087),
  tag `fixtures/priorseal-decision-binding-v1`, manifest SHA-256
  `2bf365bc9124ecfc943d5be86c34e8e0cacd51a5929b8d0c906e633a017231f9`. The permit case.
- Consumer: `imokokok/PriorSeal` at
  [`d749d269`](https://github.com/imokokok/PriorSeal/commit/d749d2691c3e6be139de4020e7b27cdafca2c428),
  `examples/aps-priorseal-decision-binding-v1/`: the `payment-within-limit.json`
  receipt, whose principal-signed authorization carries the APS `decision_ref` as a
  context commitment, and `PAYMENT-LIMIT-REPORT.json` (SHA-256
  `d2c1bea5f0acf0afe06c944376c5a471402ab5d48bf85ca267ed9b5876336ae4`, reference time
  `2026-09-19T10:05:00Z`), which cites the digest of every APS input it loaded.

Neither project added a claim for this. The record is built from the artifacts as they
are, and the only new signature is the record's own, under a test key.

## The record

One action, the APS `action_ref` the permit receipts carry. Three claims, one per APS
permit file the adapter loaded, all in the role `decision.pre_action` (the systems map's
id for "decide permit or deny for one proposed action before it runs"). One attester,
`did:example:record-attester`, a test identity standing in for the consumer that
performed the consumption, which is who signs a real record (RECORD.md, rule 1).

```jsonc
{
  "profile": "consumed-artifact-record.v0",
  "action": { "ref": "aps-action-ref-v2:c3aacbd7..." },
  "consumed": [
    { "artifact": { "ref": ".../cases/permit/policy-decision-receipt.json", "digest": "sha256:09263d4d..." },
      "role": "decision.pre_action",
      "evidence": [
        { "ref": ".../priorseal-inputs/payment-within-limit.json", "digest": "sha256:c8dd05f4...",
          "binding": { "kind": "value_equals", "artifact_pointer": "/decision_ref",
                       "evidence_pointer": "/authorizationEvidence/authorization/intent/contextCommitments/0/digest",
                       "normalize": "hex" } },
        { "ref": ".../PAYMENT-LIMIT-REPORT.json", "digest": "sha256:d2c1bea5...",
          "binding": { "kind": "digest_cited", "evidence_pointer": "/producer/permitSourceSha256/policy-decision-receipt.json" } }
      ] },
    { "artifact": { "ref": ".../cases/permit/decision-evidence.json", ... }, "role": "decision.pre_action", "evidence": [ ... ] },
    { "artifact": { "ref": ".../cases/permit/action-intent-receipt.json", ... }, "role": "decision.pre_action", "evidence": [ ... ] }
  ],
  "attester": { "id": "did:example:record-attester", "kid": "car-v0-test-attester-1" },
  "attested_at": "2026-10-07T00:00:00Z"
}
```

Signed as a compact JWS (EdDSA, Ed25519) over the RFC 8785 canonical bytes. There is no
status field. Whether it holds is what `verify.mjs` prints.

## The checks

A verifier reports these separately. None is derived from another.

- **canonical_bytes**: the payload is its own JCS canonical form.
- **attester_signed**: the key pinned for the attester the record names (matched by
  `kid`, window covering `attested_at`) verifies the signature.
- per claim, **artifact_digest**: the pinned bytes hash to the stated digest.
- per claim, **evidence_resolves**: bytes are held for every evidence reference.
- per claim, **evidence_digest**: those bytes hash to their stated digests.
  `not_evaluated` when the evidence does not resolve.
- per claim, **evidence_binds**: every binding holds against the bytes: the APS
  `decision_ref` equals the PriorSeal context commitment (after stripping its `0x`),
  and the PriorSeal report cites the SHA-256 of each APS input. `not_evaluated` when
  the evidence does not resolve.

`holds` is all of them. Bindings are measured against the bytes, never against the
digest the record states, so a wrong digest fails one check and not two.

## The four cases

1. **consumed-and-attested**: the positive case. Every check passes.
2. **wrong-digest**: the first claim's digest has one hex digit changed. Only
   `artifact_digest` fails, on that claim.
3. **missing-evidence**: the second claim points at evidence that resolves nowhere, in
   this fixture or upstream. `evidence_resolves` fails; digest and binding are
   `not_evaluated`.
4. **attester-not-signer**: the record names the attester, but a different test key
   signed it under its own `kid`. Canonical, every claim checks, and only
   `attester_signed` fails.

Each negative fails exactly one check, and the verifier asserts that.

## What the verifier also checks

Before the vectors, it hashes the retained APS `MANIFEST.sha256` and checks it against
the manifest digest pinned on #185, checks each retained APS file against its manifest
line, and hashes the retained PriorSeal report against its pinned digest. So the fixture
is shown to be built on the bytes the thread agreed on, not on a copy that drifted. It
also checks that the decoded `record` shown in each vector is byte-for-byte the signed
payload, so a reader can read the JSON and trust it is what was signed.

## Retained bytes

`pins/` holds the exact upstream bytes the record references, so the verifier runs
offline:

- `pins/aps-948f99b8/`: `MANIFEST.sha256`, the three `cases/permit/` files, and the
  upstream `LICENSE` and `NOTICE`. Apache-2.0, copyright 2026 Tymofii Pidlisnyi, as
  `REUSE.toml` at that commit declares for `fixtures/**`. Unmodified.
- `pins/priorseal-d749d269/`: `priorseal-inputs/payment-within-limit.json`,
  `PAYMENT-LIMIT-REPORT.json`, and the upstream `LICENSE`. MIT, copyright 2026
  imokokok. Unmodified.

Both licences permit redistribution with their notices kept, which is what is done
here, and is the rule for any fixture of this record (RECORD.md, rule 7). Every `ref`
in the record is the raw URL of the file at its commit, so a reader who prefers not to
trust this copy can fetch the same bytes and compare digests.

## Keys

The two signing keys are test keys derived from public labels
(`sha256("consumed-artifact-record.v0 test key: <name>")` as the Ed25519 seed). They
are generated inside `generate.mjs`, exist nowhere else, protect nothing, and are not a
key of any project. Public halves are pinned in the vector file under `attesters`.

## Claim ceiling

`holds=true` establishes exactly this: the named attester signed a statement that each
named artifact was consumed in the named role for the named action, and every piece of
evidence the statement points to is present, hashes to its stated digest, and binds the
artifact the way the statement says. Nothing about value, importance or payment.
Nothing about whether the action ran. Nothing about whether the APS receipts or the
PriorSeal authorization are valid under their own producers' rules: that is what the
lab record in
[aps-conformance-suite#139](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/139)
is for; a record MAY cite such a record as evidence and this one does not.

## Second journey

Edge E1 (AgentAvow signed grade consumed by a pre-execution gate) is the second journey
and is meant to fit the same shape unchanged. It is not a vector here: no pinned
gate-side decision record exists yet, and the E1 consumers published so far are readers
that re-check the fixture, not gates that authorized a call on it. The vector file
carries an `e1` hook stating what that fixture would reference and what is missing.

## Derivation

`node generate.mjs` rebuilds the vector file from `source.json` and `pins/`. Every
digest is computed from the bytes; none is transcribed. The build refuses to run if the
manifest or the report does not hash to its pinned value, or if any binding in the
positive record does not hold. Two runs produce identical bytes.

## Licence

This directory (the vector file, `source.json`, `generate.mjs`, `verify.mjs`,
`RECORD.md` and this README) is licensed under Apache-2.0; see [`LICENSE`](./LICENSE)
here. The retained upstream bytes under `pins/` keep their own licences, next to them.
The repository LICENSE grants a subdirectory with its own LICENSE file its own terms, so
this record and its vectors can be vendored and redistributed by any implementer.

## Run it yourself and report

Nothing here needs permission or guidance from anyone. The inputs are pinned in this
directory, the procedure is `node verify.mjs` (Node 18+, no dependencies, no network),
and the classification rules are the ones the verifier prints: every check is `ok` or
`FAIL`, and the run exits non-zero on any failure. To report a run, state the commit of
this directory you ran, your Node version and OS, the verifier output verbatim, and
whether you wrote your own implementation of the checks or used `verify.mjs`. A run by
someone who authored neither these vectors nor the implementation under test is the
only kind that counts as independent; a run of your own reader is a separate
implementation, run by its author, and should be labelled that way. The claim ceiling
above applies to every run regardless of who performs it.

To write a second implementation: read `consumed-artifact-record-v0-vectors.json`,
take `byte_store` as your map from reference to bytes (paths relative to this
directory), take `attesters` as your key pins, and for each vector compute the checks
listed under `checks` from the JWS alone. Your results must equal each vector's
`expect`. If they do and you imported nothing from here, the record has its second
reader.
