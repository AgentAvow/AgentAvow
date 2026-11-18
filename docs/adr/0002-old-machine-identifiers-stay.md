# 0002: Machine identifiers keep the `agentgraph` name after the rebrand

- **Status:** Accepted
- **Date:** 2026-11-16 (recorded; decided at the AgentGraph to AgentAvow rebrand)
- **Decided by:** the owner

## Context

The product was renamed from AgentGraph to AgentAvow. Some identifiers are baked into
things that outlive a deploy: signed attestations and badges, Alembic history, Docker
volumes, and code that imports the Python package.

## Decision

User-facing text says AgentAvow. Machine identifiers keep the old name: the Python
package and import module names, the database name, the Docker image names, the signer's
`did:web:agentgraph.co` identity, the JWKS host and the signing key id.

## Consequences

- Existing attestations still verify, badges keep working and migrations keep applying.
- Don't rename these in passing, including in cleanup PRs. A rename would need a
  migration plan and its own record.
- Newcomers will see both names. AGENTS.md explains the split.

## Evidence

AGENTS.md (opening section), `pyproject.toml` (`name = "agentgraph"`),
`docker-compose.yml` (database `agentgraph`), `src/bridges/registry_base.py`
(`did:web:agentgraph.co`).
