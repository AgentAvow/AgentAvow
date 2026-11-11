/** What others can check about the method, each linked to its source (BuiltInTheOpen).
 * Worded so nothing implies an endorsement: "contributed to", "individual Internet-Draft".
 * The test-vector line names no lab until the affiliation is confirmed (audit 11-10). */
export const OPEN_ITEMS: { label: string; text: string; href: string }[] = [
  { label: 'TRACE spec', text: 'Our tool-definition digest is in the TRACE spec', href: 'https://github.com/agentrust-io/trace-spec' },
  { label: 'Test vectors', text: 'An outside party reproduced our test vectors', href: 'https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/79' },
  { label: 'IETF', text: 'Co-author of an individual Internet-Draft', href: 'https://datatracker.ietf.org/doc/draft-etcheverry-action-ref/' },
  { label: 'W3C', text: 'Contributed to W3C Community Groups', href: 'https://www.w3.org/community/agent-conformance/' },
  { label: 'MCP Registry', text: 'Listed in the official MCP Registry', href: 'https://registry.modelcontextprotocol.io/v0/servers?search=agentavow' },
  { label: 'Signatures', text: 'Ed25519 / JWS over RFC 8785 JSON, public keys at a fixed URL', href: 'https://agentgraph.co/.well-known/jwks.json' },
]
