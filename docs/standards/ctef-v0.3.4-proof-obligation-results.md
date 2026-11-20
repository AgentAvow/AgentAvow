<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# CTEF v0.3.4 — Optional proof-obligation results profile

**Status:** Proposed optional profile; not maintainer-approved.
**Scope:** Verification-result semantics and conformance examples only.
**License:** CC BY 4.0; attribution: “CTEF, AgentAvow”.

This profile defines an optional result format for reporting what a verifier
checked about a specific proposition. It does not change the CTEF envelope,
prescribe an implementation architecture, or make a verifier result an
execution, settlement, governance, or finality authority. An implementation
may ignore this profile without changing base CTEF parsing.

The standalone synthetic vectors and zero-dependency reference verifier are in
[ctef-proof-obligation-vectors-v0/](./ctef-proof-obligation-vectors-v0/).
The standalone vector directory uses its own Apache-2.0 LICENSE. Under the
existing CTEF-LICENSE.md rule, it is outside the CC BY 4.0 specification-document
scope. This standard text is CC BY 4.0.

## 1. Result object

Each obligation result MUST use the serialization in
[result.schema.json](./ctef-proof-obligation-vectors-v0/result.schema.json)
and MUST contain exactly one object per declared obligation. The complete
expected object is pinned for each vector in expected_results; the verifier
recomputes it and reports field-level differences.

The identifiers are distinct:

- obligation_id names one verification check and its exact proposition.
- claim_id names the claim whose promotion is governed by that check.
- A vector id identifies a test case. There is no separate check_id in this
  profile; obligation_id is the check identifier.
- expected_results is test-fixture data, not a runtime verdict field.
- promotion reports eligibility for this result's claim_id; it does not
  rewrite the local verdict.

The reference verifier validates every top-level and nested object against the
closed result shape: unknown fields, missing fields, duplicate dependency or
claim identifiers, invalid commitment null semantics, and inconsistent
completion, verdict, diagnostic, terminal, or promotion combinations MUST be
rejected. Vector validation also compares every expected result object with
the independently recomputed object and reports field-level differences.

The following is an exact result object emitted by the verifier for
AUTHORIZED in case-02-authenticated-and-authorized:

```json
{
  "obligation_id": "AUTHORIZED",
  "claim_id": "claim.authorized_action",
  "proposition": "A distinct pinned synthetic governance key signed an allow decision whose checked policy permits this exact action commitment.",
  "verification_profile": {
    "id": "ctef-proof-obligation-results-v1",
    "version": "1.0.0"
  },
  "evidence_commitment": {
    "algorithm": "SHA-256",
    "canonicalization": "CTEF-JCS-subset-v1",
    "domain": "CTEF-PO-RESULTS/1/evidence/AUTHORIZED",
    "status": "committed",
    "digest": "bb68c029ee8abd88791e2e8943f5e9e1010bcf1d2fcb0e6b9f65491d4bde0f8c"
  },
  "trust_basis": {
    "assumptions": [
      "The pinned governance fixture key and the decision policy are trusted only inside this synthetic profile."
    ],
    "signer_roles": [
      "governance"
    ],
    "key_ids": [
      "ctef-test-only-governance-v1"
    ],
    "fixture_key_provenance": "Synthetic public-only conformance roots; private components and seeds are not included in the repository or required for regeneration."
  },
  "layer": "L2_governance",
  "obligation_kind": "authorization_decision",
  "completion": "completed",
  "verdict": "satisfied",
  "diagnostic_reason": "none",
  "dependencies": [
    {
      "obligation_id": "AUTHENTICATED",
      "mandatory": true
    },
    {
      "obligation_id": "ACTION_BOUND",
      "mandatory": true
    }
  ],
  "dependent_claims": [
    "claim.enforced_action",
    "claim.synthetic_finality_commitment_match"
  ],
  "terminal": false,
  "terminal_scope": "none",
  "promotion": {
    "claim_id": "claim.authorized_action",
    "status": "eligible",
    "mandatory_dependencies_satisfied": true,
    "blocked_by": [],
    "rule": "eligible iff completion is completed, verdict is satisfied, and every mandatory dependency is eligible"
  }
}
```

evidence_commitment is SHA-256 over UTF-8 canonical JSON of
{"domain": <domain>, "evidence": <exact evidence value>}. If the evidence
object is unavailable, status MUST be unavailable and digest MUST be null;
absence MUST NOT be represented by an invented digest. The input as a whole
is separately committed in each vector's input_commitment.

## 2. Layer and obligation kind

Every result MUST carry one stable layer value:

| Value | Meaning in this profile |
|---|---|
| L1_evidence | Evidence-presence, authentication, binding, enforcement-observation, outcome-record, outcome-consistency, or finality-witness proposition. |
| L2_governance | Authority or policy decision proposition. |

obligation_kind further names the domain, including authentication, binding,
authorization_decision, enforcement_observation, outcome_consistency, and
finality_witness. Layer is metadata. It is not a universal progress stage, a
trust score, a dependency, or evidence that another obligation passed.

## 3. Completion and verdict

completion and verdict are independent:

- completed means the prescribed check ran to its defined conclusion.
- incomplete means the prescribed procedure did not finish.
- not_evaluated is reserved for a check that could not be run; it is distinct
  from a completed check that found insufficient evidence.
- satisfied means the exact proposition is supported under the profile's
  stated trust basis.
- refuted means a completed check disproved that exact proposition.
- indeterminate means the proposition was neither established nor refuted.

incomplete and not_evaluated MUST use indeterminate and MUST NOT be terminal.
A completed procedure that finds no enforcement witness, finality witness, or
binding value MUST report completed plus indeterminate with the appropriate
reason code. It MUST NOT report procedural failure merely because evidence is
insufficient, and MUST NOT infer that execution did not occur.

## 4. Diagnostic vocabulary and terminality

diagnostic_reason MUST be a stable code, not free-form prose:

| Code | Required interpretation |
|---|---|
| none | Ordinary satisfied result. |
| binding_mismatch | Recomputed value differs from a present claimed binding; a completed check refutes that binding proposition. |
| binding_unresolved | The binding value is absent; completed check, indeterminate result. |
| evidence_unavailable | Evidence required for the proposition is absent; completed check, indeterminate result. |
| verification_failed | A completed cryptographic or structural verification disproves the specified artifact proposition. |
| enforcement_evidence_missing | No independent enforcement observation is available; completed, indeterminate. |
| outcome_unwitnessed | No profile-defined independent finality witness is available; completed, indeterminate. |
| procedure_unavailable | The prescribed verification procedure did not run to completion; incomplete, indeterminate. |
| policy_denied | A valid, checked decision/policy does not allow the specified action; completed, refuted. |

terminal: true means only that this completed check refuted its exact
proposition; terminal_scope MUST then be specific_proposition_only. It does not
mean an irreversible global runtime state, and it does not establish that an
underlying real-world event never occurred. A binding mismatch is terminal for
that binding obligation and blocks positive dependent claims. Invalid artifact
integrity likewise refutes only the exact integrity or authentication
proposition.

## 5. Dependencies and promotion

The profile graph is acyclic, uses only declared obligation identifiers, and
is serialized in the stable topological order implemented by profile.mjs;
every mandatory dependency MUST appear before its dependent obligation.
Direct dependencies MUST be explicit and marked mandatory: true. The
dependent_claims array names the transitive downstream claims in sorted order.
Unknown dependencies, cycles, or out-of-profile ordering are invalid.

A positive claim is eligible only when its local result is completed and
satisfied and every mandatory dependency's promotion is eligible. A refuted
mandatory obligation blocks all positive descendants along explicit edges. An
indeterminate, incomplete, or not-evaluated mandatory result cannot be promoted
to success. A blocked claim is not thereby refuted. An unrelated branch is
evaluated and promoted independently. promotion.blocked_by lists the direct
mandatory dependencies that are not eligible.

The local obligation verdict is never overwritten by dependency propagation.
An independently satisfied outcome-record result remains satisfied when
authentication is refuted, even if a downstream finality claim is blocked.

## 6. Non-equivalence and proof limits

The profile MUST preserve these distinctions:

**AUTHENTICATED != AUTHORIZED != SUPPORTED != ENFORCED != FINALIZED.**

The current vectors define no generic SUPPORTED obligation; that term is
reserved for a separately specified proposition. A valid subject signature
does not grant authority. A checked authorization decision does not prove
enforcement. An enforcement observation does not prove finality. A self-
reported outcome does not prove it was independently observed. The bounded
finality vector verifies an Ed25519 witness signature, pinned public key, result
and action bindings, and an output commitment under
synthetic-finality-witness-v1. It is synthetic fixture finality only—not
distributed consensus, chain settlement, TEE attestation, or production
finality.

## 7. Canonical bytes and cryptography

The fixture profile uses CTEF-JCS-subset-v1: parsed JSON values consisting of
null, booleans, strings without lone UTF-16 surrogates, finite safe integers,
arrays, and plain objects. Object keys sort by ECMAScript UTF-16 code-unit
order; numbers serialize with ECMAScript JSON serialization. Bytes are UTF-8.
Unsupported values are rejected. The profile does not silently fall back to
another canonicalizer.

All commitments use SHA-256 with the exact domain strings emitted in the
vectors. Signatures use Ed25519 only. The signed bytes are
UTF8("CTEF-PO-RESULTS/1\0" + kind + "\0") concatenated with
UTF8(canonicalJSON(message)), where kind is exactly authentication-v1,
authorization-v1, enforcement-v1, or finality-v1. Public keys use DER
SubjectPublicKeyInfo encoded as standard base64. Unsupported algorithms, key
encodings, or signer roles are rejected.

Each role has a separate pinned public test key. The trust-root entries state
that they are synthetic and test-only. No private fixture seed/key is checked
in or used during generation: source JSON carries the already signed test
messages and signatures. Regeneration performs no randomness, network access,
or package installation.

## 8. Vector meanings and licensing boundary

The sixteen semantic cases and expected result objects are enumerated in the
vector-folder README. All positive and negative statements are limited to the
exact fixture proposition and trust assumptions. The optional profile leaves
CTEF envelope implementation choices open.

This Markdown standard text is CC BY 4.0 with attribution “CTEF, AgentAvow”.
The code and vector artifacts carry Apache-2.0 SPDX identifiers under the
vector folder's LICENSE, under the existing CTEF-LICENSE.md exception
for directories with their own LICENSE.
