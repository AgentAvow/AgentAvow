<!-- SPDX-License-Identifier: Apache-2.0 -->
# CTEF proof-obligation results vectors v1

Sixteen self-contained synthetic conformance vectors for the optional CTEF
proof-obligation result profile. The normative profile is
[ctef-v0.3.4-proof-obligation-results.md](../ctef-v0.3.4-proof-obligation-results.md).
It does not change the CTEF envelope or require AgentChain, Kin, SolaraKin, or a
proprietary runtime.

Run from this directory with Node.js 18 or newer:

```sh
node generate.mjs --check
node verify.mjs
node independent_verify.mjs
node test.mjs
```

Run one self-contained vector with:

```sh
node verify.mjs --id case-09-completed-binding-mismatch
```

To run an extracted vector object by itself, save one entry from VECTORS.json
as a JSON object and use `node verify.mjs --single path/to/vector.json`.

The verifier uses only Node.js built-ins. No network or dependency installation
is involved. source.json pins the inputs, public trust roots, and synthetic
signatures. generate.mjs deterministically derives commitments and the full
expected result object for every obligation. No private key, seed, or
credential is in the repository or needed for regeneration.

## Coverage

| # | Vector | Targeted result |
|---:|---|---|
| 1 | case-01-authenticated-without-authorization | AUTHORIZED: completed + indeterminate |
| 2 | case-02-authenticated-and-authorized | Positive authorization twin |
| 3 | case-03-authorized-without-enforcement-witness | ENFORCED: completed + indeterminate |
| 4 | case-04-authorized-with-enforcement-witness | Positive enforcement twin |
| 5 | case-05-recorded-outcome-without-finality-witness | FINALITY_WITNESSED: completed + indeterminate |
| 6 | case-06-recorded-outcome-with-finality-witness | Bounded synthetic finality positive |
| 7 | case-07-tampered-authentication-material | AUTHENTICATED: completed + refuted |
| 8 | case-08-intact-authentication-control | Authentication positive control |
| 9 | case-09-completed-binding-mismatch | ACTION_BOUND: terminal specific refutation |
| 10 | case-10-matched-binding-control | Binding positive control |
| 11 | case-11-missing-binding-evidence | ACTION_BOUND: completed + indeterminate |
| 12 | case-12-authentication-procedure-unavailable | AUTHENTICATED: incomplete + indeterminate |
| 13 | case-13-rewritten-action-with-stale-authorization-binding | ENFORCED: binding mismatch |
| 14 | case-14-rebound-effective-action-control | Correctly rebound action positive control |
| 15 | case-15-independent-finality-outcome-divergence | FINALITY_WITNESSED only: specific refutation |
| 16 | case-16-refuted-authentication-isolation | Authentication branch blocked; outcome branch remains valid |

Every negative has one targeted local root result. Dependent blocked or
indeterminate promotions are propagation, not additional local failures. Local
verdicts do not say a real-world event did or did not occur.

## Reproducibility and licensing

The generator serializes UTF-8 JSON with two-space indentation and one trailing
LF. Hash inputs use CTEF-JCS-subset-v1; signatures use Ed25519 and
domain-separated UTF-8 messages. Repeated generator runs must leave
VECTORS.json byte-identical.

Vector artifacts, source, schema, generator, tests, and verifiers carry
Apache-2.0 SPDX identifiers and the vector directory’s own LICENSE.
The existing `CTEF-LICENSE.md` rule excludes standalone directories
with their own LICENSE from the CC BY 4.0 specification-document scope.
The separate normative CTEF v0.3.4 text is CC BY 4.0.

## Provenance

Contributor attribution: @Jsand-187. Project attribution: Kin / SolaraKin /
AgentChain. The conceptual distinction among authentication, authorization,
support, enforcement, and finality was discussed in A2A Discussion #1734 on
September 20, 2026; see PROVENANCE.md. No exclusive ownership, maintainer
acceptance, or copied proprietary implementation is claimed.
