# open-agent-trust

> Python SDK for the Open Agent Trust Registry — verify agent identity attestations

**Status:** Beta — [feedback welcome](https://github.com/FransDevelopment/open-agent-trust-registry/issues)

## Install

```bash
pip install open-agent-trust
```

## Quick Start

```python
from open_agent_trust import OpenAgentTrustRegistry

# Load the registry (fetches manifest + revocations)
registry = await OpenAgentTrustRegistry.load(
    "https://trust-registry-mirror.example.com"
)

# Verify an agent's JWS attestation token
result = await registry.verify_token(jws_token, "https://my-api.example.com")
if result.valid:
    print(f"Verified: issuer={result.issuer.display_name}")
```

For lower-level use when you manage manifest fetching yourself:

```python
from open_agent_trust import verify_attestation

result = verify_attestation(jws_token, manifest, revocations, audience)
```

## What This Does

The Open Agent Trust Registry defines a federated trust model for AI agents. This SDK verifies JWS attestation tokens against a registry manifest, checking:

- **Signature validity** — Ed25519 verification against the issuer's published public key
- **Issuer status** — whether the issuer is active and not revoked
- **Key revocation** — whether the specific signing key has been revoked
- **Audience matching** — whether the token was issued for the expected audience
- **Expiration** — whether the attestation is still within its validity period

## Key Types

| Type | Description |
|------|-------------|
| `OpenAgentTrustRegistry` | High-level registry client with manifest loading and token verification |
| `VerificationResult` | Result of a verification: valid, issuer, claims, errors |
| `RegistryManifest` | Parsed registry manifest with issuer entries |
| `IssuerEntry` | An issuer in the registry with public keys and capabilities |
| `AttestationClaims` | Decoded claims from a JWS attestation token |
| `RevocationList` | List of revoked issuers and keys |

## Requirements

- Python 3.9+
- `cryptography>=41.0` (for Ed25519 verification)
- `httpx>=0.24.0` (for manifest fetching)

## Documentation

- [Open Agent Trust Registry spec](https://github.com/FransDevelopment/open-agent-trust-registry)
- [AgentAvow docs](https://agentavow.com/docs)

## Contributing

This package is in early development. We welcome issues, feedback, and PRs.
