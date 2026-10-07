# Consumed-artifact record, v0

A signed statement that one action consumed a named artifact in a named role, with
the evidence a verifier recomputes from. Proposed on
[aeoess/agent-governance-vocabulary#185](https://github.com/aeoess/agent-governance-vocabulary/issues/185)
as the record that has to exist before any attribution formula can be discussed.
Apache-2.0. The name is deliberately plain and belongs to no project: the record says
what was consumed, not what it was worth.

Status: a first cut for review under whatever process #185 settles. Nothing here is a
shared format until two implementations with no code in common agree on the fixture
in this directory.

## What the record is for

Several independent projects each produce an artifact: a signed decision, a signed
grade, a signed authorization. One action consumes some of them. The record names, for
that action, which artifacts were consumed and in what role, and points at evidence
that a reader can check without trusting the record's author. The thread's phrase is
"record first, money later": the record is the factual substrate, and whether anything
is owed on it is a separate decision that this format does not take.

## Fields

The record is a JSON object. These are all of its members. There is no status field,
no verification result, no value, weight, share, price or importance, and no statement
that the action ran. Whether the record holds is the output of a verifier, never a
field someone wrote.

| Field | Type | Meaning |
|---|---|---|
| `profile` | string, constant `consumed-artifact-record.v0` | Versions the shape. A changed field set gets a new value. |
| `action.ref` | string | What action the record is about. Opaque to the verifier, chosen by the attester; MAY be tool-scoped when the artifacts share no action id (rule 2). The fixture reuses the APS `action_ref`. |
| `consumed[]` | array, at least one | One claim per artifact: "this artifact was consumed in this role". |
| `consumed[].artifact.ref` | string | Where the artifact bytes are published, pinned to an immutable revision. Opaque to the verifier: it is the key into the verifier's byte store. |
| `consumed[].artifact.digest` | `sha256:` + 64 lowercase hex | SHA-256 over the exact bytes at `artifact.ref`. |
| `consumed[].role` | string | The job the artifact did in the action. Free string; SHOULD be the systems map's capability id where one exists (rule 3). The fixture uses `decision.pre_action`. |
| `consumed[].evidence[]` | array, at least one | References a verifier recomputes from. |
| `consumed[].evidence[].ref` | string | Where the evidence bytes are published, pinned. Opaque; key into the byte store. |
| `consumed[].evidence[].digest` | `sha256:` + 64 lowercase hex | SHA-256 over the exact evidence bytes. |
| `consumed[].evidence[].binding` | object, required | How the evidence binds the artifact. See below. |
| `attester.id` | string | Who attested: the consumer that performed the consumption (rule 1). |
| `attester.kid` | string | The key the attester signed with. The verifier resolves it from its own pins for that attester. |
| `attested_at` | RFC 3339 instant | When the attester made the statement. The attester's key pin must cover it. |

### Bindings

A binding is the part of an evidence reference that tells a verifier where in the
evidence the artifact shows up. Without it, "evidence" would mean "some bytes exist".
Two kinds in v0, both evaluated against the bytes, never against the digest the record
states:

- `value_equals`: the value at `artifact_pointer` in the artifact equals the value at
  `evidence_pointer` in the evidence, after `normalize`. The fixture uses this to show
  that the APS `decision_ref` is the context commitment inside the PriorSeal
  authorization.
- `digest_cited`: the value at `evidence_pointer` in the evidence equals SHA-256 over
  the artifact bytes. The fixture uses this to show that the PriorSeal report cites
  each APS input it loaded.

A binding is required on every evidence item; without one, `evidence_binds` cannot be
evaluated and the record does not hold. Pointers are RFC 6901 JSON pointers.
`normalize: "hex"` lowercases and strips a leading `0x` or `sha256:`; it is implied for
`digest_cited`. The pinned pair needed it:
APS carries the decision reference as bare hex and PriorSeal carries it with a `0x`
prefix. A binding over a non-JSON artifact or evidence is out of scope for v0.

## Canonicalization and signing

- The signed bytes are the RFC 8785 (JCS) canonical serialization of the record.
- The signature is a compact JWS (RFC 7515) with header `{"alg":"EdDSA","kid":...}`,
  Ed25519, over `ASCII(BASE64URL(header) || "." || BASE64URL(payload))`. The fixture
  embeds the payload. A detached form (RFC 7797 style, payload carried alongside as the
  canonical bytes) verifies identically and is acceptable; the verifier here reads the
  embedded form only.
- `header.kid` must equal `record.attester.kid`. The verifier resolves the public key
  from the attester the record names and its own pin for that attester's `kid`. The
  header is checked for agreement and nothing more; a key is never taken from the
  record or its header.
- The fixture's keys are test keys derived from public labels (`sha256(label)` as the
  Ed25519 seed). They protect nothing and no production key of any project is involved.

## How a verifier recomputes

Input: a record (JWS), a pinned evaluation time, a byte store (ref to bytes) and a key
pin table (attester id and kid to public key with a validity window). Output: one
result per check, reported separately, and `holds`. No check is derived from another.

| Check | Level | Rule |
|---|---|---|
| `canonical_bytes` | record | `jcs(JSON.parse(payload))` equals the payload bytes. |
| `attester_signed` | record | `header.alg` is `EdDSA`, `header.kid` equals `attester.kid`, a key is pinned for (`attester.id`, `kid`) with a window covering `attested_at`, and the Ed25519 signature verifies under it. |
| `claims[i].artifact_digest` | claim | SHA-256 over the stored bytes for `artifact.ref` equals `artifact.digest`. `false` when the store holds nothing for the ref. |
| `claims[i].evidence_resolves` | claim | The store holds bytes for every evidence ref of the claim. |
| `claims[i].evidence_digest` | claim | Every evidence item's bytes hash to its stated digest. `not_evaluated` when `evidence_resolves` is false. |
| `claims[i].evidence_binds` | claim | Every binding of the claim holds against the bytes. `not_evaluated` when `evidence_resolves` is false or the store holds nothing for the artifact. |
| `holds` | record | `canonical_bytes`, `attester_signed`, and every check of every claim are `true`. |

`not_evaluated` is a third value, not a failure: the verifier says it did not measure
something rather than reporting a failure it did not observe. The evaluation time is
pinned in each vector so that a result is a function of the vector alone; in v0 the
only time-sensitive input is the attester key window, and no vector in the fixture
exercises it.

`VERIFIED` does not appear anywhere in the record. It is what a reader may call
`holds=true` after running the checks, and it is theirs to say, not the record's.

## Claim ceiling

`holds=true` establishes exactly this: the named attester signed a statement that each
named artifact (by digest, over the pinned bytes) was consumed in the named role for
the named action, and each piece of evidence the statement points to is present,
hashes to its stated digest, and binds the artifact the way the statement says.

It establishes nothing about:

- the value or importance of the artifact, or of the project that produced it;
- payment, entitlement, or any share of anything;
- whether the action ran, or ran as authorized;
- whether the artifact or the evidence is valid under its own producer's rules (an APS
  receipt signature, a PriorSeal principal signature, an AgentAvow grade): those are
  separate checks with their own verifiers and their own records, and a record MAY cite
  such a record as evidence but never restates it;
- any artifact the record does not name. Absence from a record is not evidence of
  non-consumption.

Count is not value. A record is one data point that an artifact was consumed once in
one action. Any formula built on records has to decide for itself how to weigh a check
that runs once per tool against one that runs once per call, and this format takes no
position on that.

## Composition

One record has one attester: the consumer that performed the consumption. A producer
MAY attest its own, separate record under the same `action.ref`. A verifier evaluates
each record on its own, and a record never speaks for an attester other than the one it
names. The fixture's attester is a test identity standing in for the consumer side.

## Two edges, one shape

The record was shaped against #179's E2 (APS to PriorSeal, a decision-binding edge)
and is meant to fit E1 (AgentAvow to a gate, a tool-safety edge) unchanged. On E2 the
artifact is a signed decision and the evidence is the authorization that carries its
reference. On E1 the artifact is a signed grade and the evidence would be the gate's
decision record carrying the per-tool digest it relied on. The fixture file carries an
`e1` hook stating exactly what the second fixture would reference and what is missing
(a pinned gate-side record). It is not a vector and nothing verifies it.

## Relation to other proposals

- Frequency-Federation-Review PR 3 (Federation Attribution Receipt v0.1) was the input
  for the field list: artifact reference and digest, role, evidence references,
  attester. This record keeps those and drops the carried `status` and the literal
  claim-ceiling block; the ceiling lives in this document and in the verifier's output,
  not in a field a writer fills in.
- The systems map in #186/#187 proposes a role `attribution.per_action` with the
  output "attribution record". If #185 adopts a shared record format, that role's
  output would be this record, and `consumed[].role` would draw on the map's
  capability ids.

## Rules stated in v0

These were open questions in the first draft and are now rules, so that nothing is
hidden in a field default.

1. **Who signs.** The consumer that performed the consumption signs the record. A
   producer whose artifact was consumed MAY attest its own, separate record under the
   same `action.ref`. One record, one attester; a verifier evaluates each on its own.
2. **Naming the action.** `action.ref` is an opaque string chosen by the attester. When
   the consumed artifacts carry a shared action identifier, the attester SHOULD reuse
   it (the fixture reuses the APS `action_ref`). When they share none, for example a
   pre-connect tool check that runs once per tool rather than once per action, the ref
   MAY be tool-scoped, for example `mcp:<server>#<tool>`.
3. **Role.** `role` is a free string. It SHOULD be the shared systems map's capability
   id where one exists, and a locally defined id where none does, stated as such. The
   fixture keeps three claims, one per APS permit file the adapter loaded, all under
   `decision.pre_action`.
4. **Bindings.** The binding descriptor is part of the evidence reference in v0 and is
   required: an evidence item without a binding leaves `evidence_binds` unevaluable
   and the record does not hold.
5. **Producer-rule validity.** Whether an artifact or its evidence is valid under its
   own producer's rules is outside the claim ceiling. A record MAY cite a lab record or
   another verification record as evidence; it is never required.
6. **Claims per record.** As many as the action consumed. The fixture keeps three.
7. **Retained bytes.** A fixture retains the referenced bytes under their upstream
   licences, with the notices those licences require kept next to them, and references
   each by the raw URL at its commit so the copy can be checked against the source.
