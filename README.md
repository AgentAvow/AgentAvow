# AgentAvow

> Formerly AgentGraph. The signed attestation format, JWKS, and existing badges are unchanged.

[![AgentAvow Trust](https://agentavow.com/api/v1/public/scan/AgentAvow/AgentAvow/badge)](https://agentavow.com/check/AgentAvow/AgentAvow)
[![PyPI - agentgraph-trust](https://img.shields.io/pypi/v/agentgraph-trust?label=agentgraph-trust&color=blue)](https://pypi.org/project/agentgraph-trust/)

AgentAvow gives any tool, MCP server, package, or skill an AI agent connects to a **signed, verifiable safety grade** you can recompute offline — the "is this tool safe to connect?" layer.

## MCP Server — Trust & Security for AI Agents

Check the security posture of any agent or tool directly from Claude Code:

```bash
pip install agentgraph-trust
```

See [sdk/mcp-server/](sdk/mcp-server/) for setup and full tool list.

## Key Features

- **Free, anonymous scanning** — Point AgentAvow at any GitHub repo, MCP server, npm or PyPI package, or OpenClaw skill (or a wallet address that resolves to one) and get a safety grade back. No account, no install. Results cache for 1 hour; `?force=true` re-scans.
- **Letter grade + subscores** — Every scan returns a single **A+ → F** grade and a 0–100 score, composed from per-category subscores (secret hygiene, code safety, data handling, dependencies, …) across **12 detection categories**. Each finding carries a severity and points at the exact line or manifest entry.
- **Signed, verifiable attestation** — Each result ships with a **JWS attestation** (EdDSA / Ed25519, RFC 7515) over a canonical verdict (RFC 8785 JCS). Anyone can **recompute and verify it offline** against the public JWKS at `agentgraph.co/.well-known/jwks.json` — the score is a product, the signature is the proof under it.
- **Trust tiers → recommended limits** — Each grade maps to a trust tier (`verified` → `blocked`) with a recommended execution posture (req/min, token budget, confirmation prompts) so a gateway or agent framework can act on it automatically.
- **Trust badge** — A one-line, shields.io-compatible **SVG badge** for your README that renders the repo's current signed grade and links to the full verifiable report. Served with open CORS and regenerated on every view, so it never goes stale.
- **Watch & change-alerts** — Watch a tool; AgentAvow re-scans it and alerts you when its grade drops or its **signed tool definition changes** (`tool_manifest_digest` drift) — the rug-pull you'd otherwise miss.
- **Claim repos you own** — Prove ownership of a public repo by adding a GitHub topic (no token stored), or run a **private scan** with a GitHub token you supply transiently (never persisted, never added to the public catalog).
- **Public trust catalog** — A paginated, filterable catalog of every scan (launch corpus plus community on-demand scans), browsable by surface, severity, and score.
- **MCP server & CI gating** — An MCP server (`agentgraph-trust`) exposes scanning to Claude Code and other clients, and a GitHub Action / CLI can gate merges on a minimum grade.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI, SQLAlchemy 2.0 (async), Pydantic 2.0, Uvicorn |
| **Database** | PostgreSQL 16 (asyncpg) |
| **Cache/Events** | Redis 7 (caching, rate limiting, pub/sub) |
| **Frontend** | React 19, TypeScript, Vite 7, Tailwind CSS 4, TanStack Query 5 |
| **Auth** | JWT (access + refresh tokens), API keys for agents, bcrypt |
| **Crypto/Signing** | Ed25519 (JWS/EdDSA, RFC 7515), RFC 8785 JCS canonicalization |
| **UI/Animation** | Tailwind CSS, framer-motion |
| **Infrastructure** | Docker, Docker Compose, Nginx, GitHub Actions CI |

## Quick Start

### Prerequisites

- Python 3.9+
- Node.js 20+
- PostgreSQL 16
- Redis 7
- Docker & Docker Compose (optional, for containerized setup)

### Option 1: Docker Compose (recommended)

```bash
# Clone the repo
git clone https://github.com/AgentAvow/AgentAvow.git
cd AgentAvow

# Copy environment files
cp .env.example .env
cp .env.secrets.example .env.secrets

# Edit .env and .env.secrets with your values (see Environment Variables below)

# Start everything
docker-compose up
```

This starts:
- **Backend API** at `http://localhost:8000`
- **Frontend** at `http://localhost` (port 80)
- **PostgreSQL** at `localhost:5432`
- **Redis** at `localhost:6379`

Database migrations run automatically on startup.

### Option 2: Local Development

```bash
# Clone and enter the repo
git clone https://github.com/AgentAvow/AgentAvow.git
cd AgentAvow

# Setup Python environment, install deps, start DB services
make setup

# Copy and configure environment
cp .env.example .env
cp .env.secrets.example .env.secrets
# Edit both files with your values

# Run database migrations
make migrate

# Start the backend dev server (hot reload)
make dev
```

In a separate terminal, start the frontend:

```bash
cd web
npm install
npm run dev
```

- **Backend** runs at `http://localhost:8000`
- **Frontend** runs at `http://localhost:5173` (proxies API requests to backend)

## Environment Variables

### Required (`.env`)

```bash
DATABASE_URL=postgresql+asyncpg://postgres:yourpassword@localhost:5432/agentgraph
POSTGRES_PASSWORD=yourpassword
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=change-me-to-a-random-64-char-string
```

### Optional (`.env`)

```bash
APP_NAME=AgentAvow
DEBUG=false
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
CORS_ORIGINS=["http://localhost:3000","http://localhost:80"]
RATE_LIMIT_READS_PER_MINUTE=100
RATE_LIMIT_WRITES_PER_MINUTE=20
RATE_LIMIT_AUTH_PER_MINUTE=5
```

### Secrets (`.env.secrets`)

```bash
ANTHROPIC_API_KEY=your_key_here   # Optional — LLM-assisted features (not required for scanning)
```

### Frontend (`web/.env`)

```bash
VITE_API_URL=http://localhost:8000
```

## API Overview

The public scanning API needs **no authentication**. All app endpoints use the `/api/v1` prefix; interactive docs are at `/docs` (Swagger) and `/redoc`.

### Public scan API (no auth)

| Endpoint | Path | Description |
|----------|------|-------------|
| **Scan** | `GET /public/scan/{owner}/{repo}` | Scan a repo/tool; returns grade, tier, findings, and a signed JWS attestation. `?force=true` bypasses the 1-hour cache. |
| **Badge** | `GET /public/scan/{owner}/{repo}/badge` | Shields-compatible **SVG** trust badge (open CORS), regenerated per request. |
| **Checks** | `GET /public/scan/{owner}/{repo}/checks` | Adoption signals: check count, active watchers, GitHub stars, score history. |
| **History** | `GET /public/scan/{owner}/{repo}/history` | Timeline of past scans for a repo. |
| **Wallet lookup** | `GET /public/scan/wallet/{address}` | Resolve a wallet address to its linked repo and scan it. |
| **Catalog** | `GET /public/scan-catalog` | Paginated, filterable catalog of all scans (by surface, severity, score). |
| **OG page** | `GET /check/{owner}/{repo}` | Shareable HTML report page with Open Graph meta. |

### Verification & attestations

| Endpoint | Path | Description |
|----------|------|-------------|
| **JWKS** | `GET /.well-known/jwks.json` | Public keys (EdDSA/Ed25519) for offline attestation verification. Served on `agentgraph.co`. |
| **Attestations** | `/attestations` | Issue, list, and revoke signed attestations for an entity. |
| **Security attestation** | `GET /entities/{id}/attestation/security` | Signed security-posture attestation (A2A `trust.signals[]` compatible). |
| **Composed slot** | `GET /entities/{id}/attestation/composed-slot` | `agentgraph-scan-v1-structural` slot for an APS composed-v1 envelope. |
| **Aggregate verify** | `GET /trust/aggregate/{subject_did}/verify` | Verify a signed Trust Score v2 aggregate envelope. |

### Account (authenticated)

| Endpoint | Path | Description |
|----------|------|-------------|
| **Auth** | `/auth` | Register, login, JWT tokens, email verification |
| **Claims** | `/account/claims` | Claim a public repo you own via GitHub-topic proof (no token stored) |
| **Private scan** | `POST /account/private-scan` | Scan a private repo with a transiently-supplied GitHub token (never persisted) |
| **Watches** | `/watches` | Create/list/delete tool watches for grade + signed-definition change alerts |
| **Alert webhook** | `/account/alert-webhook` | Configure (and test) the HMAC-signed webhook that receives change alerts |
| **Health** | `GET /health` | DB + Redis connectivity check |

## Project Structure

```
AgentAvow/
├── src/                     # Backend (FastAPI)
│   ├── api/                 # API router modules (public scan, badge, watches, claims, attestations)
│   ├── scanner/             # Static-analysis engine + detection patterns
│   ├── signing.py           # Ed25519 signing, JWS, JCS canonicalization
│   ├── attestation/         # CTEF envelopes, APS composed slot
│   ├── trust/               # Trust score computation, aggregate envelopes, action_ref vectors
│   ├── safety/              # Anomaly / collusion / propagation controls
│   ├── source_import/       # Fetchers (GitHub, npm, PyPI, MCP, crates, Docker, HF, …)
│   ├── jobs/                # Scheduled jobs (watch re-scan loop, population scan)
│   ├── bridges/             # Framework adapters (MCP, LangChain, CrewAI, AutoGen)
│   ├── models.py            # SQLAlchemy models
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # Settings (Pydantic)
│   ├── database.py          # Async PostgreSQL sessions
│   ├── redis_client.py      # Redis connectivity
│   ├── cache.py             # Caching layer
│   └── audit.py             # Audit logging
├── web/                     # Frontend (React + TypeScript)
│   └── src/
│       ├── pages/           # 32 page components
│       ├── components/      # Reusable UI components
│       ├── hooks/           # Custom React hooks
│       └── lib/             # Utilities and API client
├── ios/                     # iOS app (SwiftUI)
├── tests/                   # 1,319 tests across 136 files
├── migrations/              # 40 Alembic migrations
├── docker-compose.yml       # Full stack orchestration
├── Makefile                 # Development commands
└── docs/                    # PRD and architecture docs
```

## Development

### Useful Commands

```bash
make dev            # Start backend with hot reload
make test           # Run full test suite (1,319 tests)
make lint           # Lint with ruff
make lint-fix       # Auto-fix lint issues
make ast-verify     # Verify Python syntax
make migrate        # Run pending migrations
make migration      # Create a new migration
make db-start       # Start PostgreSQL + Redis (Homebrew)
make db-stop        # Stop database services
make clean          # Clean build artifacts
```

### Running Tests

```bash
# Full suite
make test

# Verbose output
.venv/bin/python3 -m pytest tests/ -v

# Single test file
.venv/bin/python3 -m pytest tests/test_auth.py -v

# With coverage
.venv/bin/python3 -m pytest tests/ --cov=src
```

### Code Standards

- **Python 3.9+** — use `from __future__ import annotations` for union types
- **Linting** — ruff (E, F, I, N, W, UP rules), 100 char line limit
- **AST verification** — all Python files must parse cleanly
- **Tests required** — all new/changed code needs unit tests

## Security

- CORS with configurable origins
- Rate limiting (read, write, auth-specific limits)
- Security headers (HSTS, X-Frame-Options, X-Content-Type-Options, etc.)
- Request ID correlation for tracing
- Content filtering with HTML sanitization
- HMAC-SHA256 webhook signing
- Bcrypt password hashing
- JWT token blacklisting on logout
- Audit trail for all sensitive actions

## Architecture

AgentAvow is a layered scan-and-attest pipeline: a scan produces evidence, the evidence is scored and canonicalized, and the verdict is signed into an attestation anyone can recompute and verify offline.

```
┌─────────────────────────────────────────────────────────┐
│  Clients — check page, trust badge, MCP server, CLI,    │
│            GitHub Action, third-party verifiers         │
├─────────────────────────────────────────────────────────┤
│  Public API — /public/scan · /badge · /checks ·         │
│               scan-catalog · watches · claims           │
├─────────────────────────────────────────────────────────┤
│  Scan & score — static analysis (12 categories),        │
│  per-category subscores, letter grade, trust tier,      │
│  tool-definition digests (drift / rug-pull detection)   │
├─────────────────────────────────────────────────────────┤
│  Attestation — Ed25519/JWS (RFC 7515) over a canonical  │
│  verdict (RFC 8785 JCS); CTEF envelopes; action_ref     │
├─────────────────────────────────────────────────────────┤
│  Verification — public JWKS (agentgraph.co/.well-known),│
│  offline byte-for-byte recompute, DID:web identity      │
└─────────────────────────────────────────────────────────┘
```

Watches close the loop: a background re-scan job compares each watched tool's new score and signed definition digest against the last, and fires an HMAC-signed webhook alert when either changes.

## License

Proprietary. All rights reserved.
