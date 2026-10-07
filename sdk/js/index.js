// agentavow-trust (formerly @agentgraph/trust) — JS/TS peer of the Python agentavow-sdk Trust Score v2 surface.
//
// Standalone client-side verification of signed v2 trust-score envelopes
// (JCS-canonical, proof-stripped, Ed25519 over SHA-256), plus a thin async API
// client. Byte-compatible with the Python SDK and the server.

export { verifyEnvelope, envelopeDigest, isFresh, PROOF_TYPE } from './src/verify.js';
export { TrustClient, AgentGraphError } from './src/client.js';
