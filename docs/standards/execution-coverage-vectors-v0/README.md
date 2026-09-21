# Execution-coverage vectors (v0)

Conformance vectors for [OpenSecureAIAlliance/RFCs#6](https://github.com/OpenSecureAIAlliance/RFCs/issues/6)
— a pre-connection tool-trust attestation. **Proposed** report shape for the RFC
to refine, not a finalized schema.

    node verify.mjs

Zero dependencies, Node 18+. Exits non-zero on any failure.

## The property

Signing a coverage block binds the signer to the coverage *assertion*. It does
not establish that the checks *ran*. A consumer reports four axes separately, and
none inherits another's result:

- **signature_valid** — the report's signature verifies. Binds the signer to
  what it signed, and no further.
- **coverage_consistent** — declared coverage and aggregation are internally
  consistent; a required check is not both skipped and counted as passed.
- **digest_binds** — the report is about the definition admission observes
  (`subject_digest == observed_digest`).
- **execution_state** — `established` | `unestablished` | `unavailable`, from
  receipts or independent reproduction. Never inferred from the signature.

Whether a consumer proceeds is a separately versioned admission policy, not a
change to any of these verdicts.

## The five cases

1. **skipped-required-check** — valid signature, but a required check is declared
   skipped while the aggregate counts it passed. Caught on coverage, not
   execution: the checks that passed are evidenced.
2. **completion-without-execution-evidence** — *the control.* Signature,
   coverage, arithmetic, and digest all pass; no required check carries a receipt
   or reproduction. Execution unestablished. A coverage-only reader passes this
   false-green, which is the case the set exists to separate.
3. **digest-mismatch** — a valid, fully-evidenced report for digest A, presented
   when admission observes digest B. Every other axis passes; it is simply not
   about the artefact being admitted.
4. **reproduction-unavailable** — a required check whose inputs or dependencies
   cannot be disclosed, so it can be neither receipted nor reproduced.
   `unavailable`, a distinct state from `unestablished`.
5. **positive-continuation** — matching definitions, every required check
   evidenced by a receipt or independent reproduction, and it binds the observed
   digest. Admission is then a separate, versioned policy.

## Derivation

`signature` = Ed25519 (RFC 8032) over `jcs(report)` minus the signature field
(RFC 8785 JCS). Digests are lowercase-hex SHA-256. `node generate.mjs` rebuilds
the file — signatures and digests are derived, not transcribed.

The canonicalization these rest on is exercised independently in the
`jcs-comparison-semantics-v1` author-set (agentgraph + trail), so this set can
assume byte-stable canonical forms and focus on the coverage/execution axes.
