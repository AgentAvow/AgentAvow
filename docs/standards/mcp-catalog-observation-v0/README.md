# MCP catalog observation (v0): an example packet

The first packet for the server half of
[agentrust-io/trace-spec#443](https://github.com/agentrust-io/trace-spec/issues/443). It
follows the design matrix [dinakarjs posted there](https://github.com/agentrust-io/trace-spec/issues/443).
The catalog half is already in TRACE: `docs/rfcs/tool-catalog-observed-digest.md` and
COMP-MCP-004 to 006, merged in #456. That part shows what was served. This packet adds
how one observer got it: which endpoint it asked for, what the TLS connection that
returned the catalog proved, and every page of the list.

    node verify.mjs

Zero dependencies, Node 18+. Nothing is fetched. Exits non-zero on any failure.

## What it is, and what it is not

It is **one enrolled observer's capture claim**. AgentAvow's scanner read `tools/list`
from a live server and signed what it saw and how. It is not a server signature over
`tools/list`. A copied certificate does not become one, and neither does the scanner's
signature. A TLS-terminating proxy is the authenticated peer: its certificate identifies
no backend code or runtime. Two scans by the same observer are two observations, not
independent evidence. Whether an observer's key may make this claim is a decision the
consumer makes when it enrolls the observer, outside the packet.

**This packet is an example for review.** The capture is real: `https://mcp.deepwiki.com/mcp`,
read through the production scanner code. The production scan payload builder made the
payload. But the packet is signed with a **test observer key** derived from a fixed
label, not with the production signing key, so that the variant cases can be signed too.
Production scans carry the same block, signed as `scan.observation` under
`agentgraph-security-v1`.

## The observation block (`scan.observation`)

Profile `agentavow.mcp-catalog-observation.v0`, inside the signed scan, next to
`toolDigests` and `toolManifestDigest`:

| field | meaning |
|---|---|
| `observationId`, `capturedFrom`, `capturedUntil` | One read of the list, and its interval (RFC 3339, milliseconds, `Z`). |
| `request` | `scheme`, `host`, `port` and `path` the scanner asked for. No query string, since a query can carry a credential. |
| `redirectsFollowed` | Always `false`. The scanner follows no redirect. |
| `transport` | TLS facts of the connection that returned the catalog: `tlsVersion`, `cipher`, and `referenceIdentity`, the host the certificate was checked against (the SNI host; RFC 9525 §6). Also `certificatePathValidated`, `identityMatched`, and the SHA-256 of the leaf certificate (`leafCertificateSha256`) and of its SubjectPublicKeyInfo (`spkiSha256`). Absent when the facts were not recorded. |
| `sameConnectionFacts` | `true` when every page came back on a connection with the same identity and key facts. |
| `toolsList.pages[]` | For each page in order: the JSON-RPC `requestId`, the SHA-256 of the cursor that asked for it and of the `nextCursor` it returned, `itemCount`, the SHA-256 of the raw response body, and that page's leaf and SPKI hashes. |
| `toolsList.complete` | `true` when the read reached the last page. It is `false` if a page failed, a cursor repeated, or the page cap stopped it. |
| `toolManifestDigest` | The same value as `scan.toolManifestDigest`. It binds the observation to the signed catalog. |
| `limits` | The limits above, in the signed bytes. |

`certificatePathValidated` and `identityMatched` come from the live TLS context: with
`CERT_REQUIRED` and hostname checking, a completed handshake means both checks passed.
An SNI value and an SPKI hash alone would not establish that. The payload is the RFC 8785 (JCS)
canonical form production signs, null fields kept (`transport: null` when no TLS facts
were recorded). The verifier checks the signature over the bytes as given and never
re-canonicalizes.

## The consumer's inputs

The consumer sets these independently of the scan. In a deployment they are its own
configuration; in the packet they are `policy` (overridden per case where noted):

- `expectedEndpoint`: scheme, host, port, path.
- `trustedSpki`: the key hashes it accepts for that endpoint.
- `rotations`: rotations its own policy authorizes, from a trusted key to a new one.
- `enrolledObservers`: observer key ids it accepts capture claims from.
- `evaluationTime`.

The packet also carries the retained raw page bytes and the catalog the consumer holds.

## The seven axes

| axis | true when |
|---|---|
| `signature_valid` | The EdDSA signature verifies under the key the JWS header names. |
| `observer_enrolled` | That key is one the consumer enrolled as an observer. |
| `catalog_binds` | The consumer's catalog recomputes to the signed `toolDigests` (the #456 derivation), and the observation names the same manifest digest. |
| `exchange_binds` | The list is complete; every retained page hashes to its recorded `responseSha256`, in order; and the tools in those pages recompute to the signed digests. |
| `endpoint_binds` | The request matches the expected endpoint. There was no redirect. The verified reference identity is the expected host. Path and identity validation both passed, and the facts were the same on every page. |
| `key_trusted` | The SPKI is trusted, or reached by an authorized rotation from a trusted key. |
| `fresh` | `evaluationTime` falls inside `[issuedAt, expiresAt)`. |

`rely` is all seven true. With no `transport` facts, `endpoint_binds` and `key_trusted`
are `unavailable`. With no observation at all, those two and `exchange_binds` are
`not_evaluated`. Neither is ever reported as `false`.

## Cases

| case | what changes | fails |
|---|---|---|
| `endpoint-expected` | nothing (valid control) | — |
| `endpoint-other-name` | same catalog observed at another name with a valid certificate for it | `endpoint_binds` |
| `key-unexpected` | a key the policy does not trust (unapproved substitution) | `key_trusted` |
| `key-rotation-authorized` | the same new key, with a rotation the policy authorizes (valid control) | — |
| `exchange-copied` | catalog bytes from a different `tools/list` exchange | `exchange_binds` |
| `catalog-altered` | the consumer's catalog differs from the observed one | `catalog_binds` |
| `observer-unenrolled` | a valid signature by a self-supplied observer key | `observer_enrolled` |
| `past-expiry` | evaluated after `expiresAt` | `fresh` |
| `tampered-payload` | the observation edited after signing | `signature_valid` |
| `transport-unavailable` | no TLS facts recorded | `endpoint_binds`, `key_trusted` = `unavailable` |
| `no-observation` | a scan without the block | three axes `not_evaluated` |

Each of the seven negatives fails exactly one axis, and the verifier checks that. The
mirror name, the rotated key and the leaf hashes in the variant cases are synthetic
values, labelled as such in `make_packet.py`; the reference case is the live capture.

## Not covered yet

- **Pagination on the wire.** DeepWiki serves its three tools on one page. The scanner
  follows `nextCursor` and binds each page, which is covered by
  `tests/test_mcp_observation.py`, but this packet has no live multi-page exchange.
- **Historical TLS re-validation.** The packet records the outcome at capture time. It
  does not retain the certificate chain or its status (OCSP/CRL), so a later verifier
  cannot re-run path validation. It can only check the recorded outcome against the
  observer it enrolled.
- **TLS termination, redirects and aliases.** These are described above but have no
  case of their own.
- **A registered wire method.** The profile decision stays with the TRACE maintainers.

## Regenerate

    DEBUG=true python docs/standards/mcp-catalog-observation-v0/make_packet.py

This makes a new live capture: new observation id, times and possibly a new certificate.
`verify.mjs` holds for any regenerated packet, but its bytes and hashes will differ.

Apache-2.0 (see `LICENSE`).
