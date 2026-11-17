# 0001: The tech stack is decided

- **Status:** Accepted
- **Date:** 2026-11-16 (recorded; the stack predates this record)
- **Decided by:** the owner

## Context

The stack has been in place since the project started, and the codebase, CI and the
prod image are all built on it. Proposals to swap a core layer come up from time to time.

## Decision

The stack is not open for change in passing:

- Backend: FastAPI, SQLAlchemy 2.0 (async), Pydantic 2, Uvicorn, Alembic migrations.
- Database: PostgreSQL 16 (asyncpg driver). Cache, rate limits and pub/sub: Redis 7.
- Frontend: React 19, TypeScript, Vite, Tailwind CSS 4, TanStack Query 5.
- Signing: Ed25519 (JWS/EdDSA, RFC 7515) over RFC 8785 JCS canonical JSON.
- Deploy: Docker and docker-compose behind Nginx; CI on GitHub Actions.

## Consequences

- New features use these layers. Adding a library inside a layer is a normal PR.
  Replacing a layer (another web framework, ORM, database or frontend framework) needs
  a superseding record and the owner's sign-off first.
- Tooling that changes how the prod image installs dependencies (for example a new
  package manager) ships as its own PR and its own deploy.

## Evidence

`pyproject.toml` (dependencies), `web/package.json`, `Dockerfile` (`python:3.12-slim`),
`docker-compose.yml` (Postgres 16, Redis 7), `.github/workflows/ci.yml`, `src/signing.py`.
