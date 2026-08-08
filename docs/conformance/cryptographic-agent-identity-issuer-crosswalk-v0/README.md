# cryptographic-agent-identity — issuer/project crosswalk (dual-carry, one release)

Standalone crosswalk entry for A2A
[#1786](https://github.com/a2aproject/A2A/issues/1786) (Cryptographic Agent
Identity extension, CTEF v0.3.1-aligned).

The AgentGraph project is now **AgentAvow**. This entry carries the project name
dual for one release (`agentgraph` = previous, `agentavow` = current) so no
existing citation dangles, while making the load-bearing point explicit: **the
rename is a project-name change, not an identity migration.** The cryptographic
issuer identity, the CTEF wire format, the four `claim_type` values, the error
codes, and the JCS canonicalization do not move.

The machine data is [`crosswalk.json`](./crosswalk.json). This README is the
human-readable summary.

## What is dual-carried, and what is held

| | previous | current | wire change |
|---|---|---|---|
| project name | `agentgraph` | `agentavow` | no |
| repo | `agentgraph-co/agentgraph` | `AgentAvow/AgentAvow` | no (GitHub 301s old refs; `@69ad94d` resolves) |
| well-known host | `agentgraph.co` | `agentgraph.co` + `agentavow.com` (both serve, byte-identical) | no |
| **issuer id** | `did:web:agentgraph.co` | **`did:web:agentgraph.co` (held)** | no |
| OATR `issuer_id` | `agentgraph` | `agentgraph` (held) | no |
| `@context` ns | `https://agentgraph.co/ns/trust-evidence/v1` | unchanged | no |
| `claim_type` closed set | `identity, transport, authority, continuity` | unchanged | no |
| error codes | `INVALID_CLAIM_SCOPE`, `INVALID_COMPOSITION` | unchanged | no |
| canonicalization | RFC 8785 JCS + SHA-256 | unchanged | no |

The **project name** is the only field that carries two values. The **issuer
string is held** at `did:web:agentgraph.co` — it is not dual-carried, and it
does not rotate to `did:web:agentavow.com` as part of the rename.

## Why the issuer is held, not renamed

A string rename in a crosswalk is the wrong tool for an identity change. If
AgentAvow later re-roots the issuer to `did:web:agentavow.com`, that is a signed
**continuity-layer rotation-attestation** — the old key cross-signs the new key,
verifiable on its own terms per the `continuity` `claim_type` this extension
defines. It rides through the continuity claim, not through a project rename.
Until that signed rotation exists, the issuer stays exactly where partners
already verify against it.

## Byte-invariance (the crosswalk's bar)

The four CTEF v0.3.1 test vectors published at
`/.well-known/cte-test-vectors.json` canonicalize (RFC 8785) to these SHA-256
values at the frozen commit `agentgraph-co/agentgraph@69ad94d`. They are
reproduced byte-for-byte on **both** hosts:

| vector | canonical SHA-256 | expected |
|---|---|---|
| `envelope_vector` | `9e7b5031e46de38b5f90e895113a3f24f42a4128d8d99856a2d71e529b0f0d5c` | pass |
| `verdict_vector` | `feb42dca4214fc46207138d676ec727d7b3d0caa1eda8c0390d2d6f6fbc28913` | pass |
| `scope_violation_vector` | `e584f1cd0885dc938da5fc23ce7e528715a0086e5464c9ed0f3c1c82b364026f` | fail-closed (`INVALID_CLAIM_SCOPE`) |
| `composition_failure_vector` | `f9cd10bc4e8bf34ce3aa6a0e5df0d27989e54ff41c4333c69ae3ecfaf8de0cb5` | fail-closed (`INVALID_COMPOSITION`) |

These match the four-way byte-match state published in the interop harness
(`/.well-known/interop-harness.json`) and confirmed by independent
canonicalizers on #1786. The rename does not touch any of them.

## Run it

```
python3 verify.py
```

Zero third-party dependencies (stdlib `urllib` + `hashlib` + `json`). Requires
network access to both `agentgraph.co` and `agentavow.com`. The verifier:

1. fetches `/.well-known/cte-test-vectors.json` from both hosts,
2. asserts the two responses are byte-identical,
3. asserts each of the four vectors reproduces its pinned canonical SHA-256,
4. asserts `provider.id` / issuer is `did:web:agentgraph.co` in every vector.

## Migration path

This is the standalone-crosswalk form Kenne committed to on #1786 so nothing
blocks on the `experimental-ext-*` repo. When A2A sponsorship lands and the
`experimental-ext-cryptographic-agent-identity` repo is created, the same
crosswalk (identical values) moves into that repo alongside the AgentAvow
conformance fixtures. Values do not change on that move; only the home does.
