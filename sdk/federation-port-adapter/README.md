# AgentAvow adapter for federation-port/v0

An AgentAvow `tool_admission` component written against aeoess's
[federation-port](https://github.com/aeoess/federation-port) V0 contract (`spec/CONTRACT.md`, commit
92d5078). The component is `adapters/agentavow-mcp-admission/` and is documented in its own
[README](adapters/agentavow-mcp-admission/README.md). This directory mirrors federation-port's tree so
the component drops into its `adapters/` directory unchanged.

```
src/contract/types.ts      verbatim copy of federation-port's contract types (type-only import target)
src/digest.ts              section-3 digests, re-implemented from src/runtime/canonical.ts
scripts/seal.ts            writes artifact.digest into the manifest, prints the pin values
adapters/agentavow-mcp-admission/{adapter.ts, manifest.json, README.md}
test/adapter.test.ts       the adapter through the contract types with a mock ctx.fetch (offline)
test/manifest.test.ts      manifest fields, artifact and manifest digests, key pin, fixture integrity
test/harness.test.ts       the adapter through federation-port's own runtime and test harness
test/fixtures/             the pinned DeepWiki attestation (docs/standards/tool-manifest-digest-vectors-v1)
```

## Run

Node 22.18+ (type stripping). The ten harness tests need a federation-port checkout with `npm ci` done and
`FEDERATION_PORT_DIR` pointing at it; without the variable they are skipped, not failed.

**Endpoint URLs.** A server is identified by scheme, host and path. The adapter strips `user:pass@`, the query
and the fragment before it requests a scan and compares the signed subject against the URL without them, so a
token or tenant in a configured endpoint never leaves the process. A path segment that looks like a key (a
UUID, a 32+ character run, a 16+ character run with three or more digits) is withheld: the check returns
`failed` with `endpoint_path_looks_like_a_credential` and makes no request. The AgentAvow scan API applies
the same rule server-side.

```
npm install
npm run typecheck
npm test                                       # harness tests skipped
FEDERATION_PORT_DIR=/path/to/federation-port npm test
```

Or inside federation-port itself: copy `adapters/agentavow-mcp-admission/` to its `adapters/`,
`test/fixture.ts`, `test/adapter.test.ts`, `test/harness.test.ts` and `test/fixtures/` to its `test/`,
run `node scripts/seal.ts adapters/agentavow-mcp-admission` there, then `npm test` and
`npm run typecheck` as usual. Nothing under its `src/` changes.

All tests are offline: `agentavow.com` is served from the pinned fixture.
