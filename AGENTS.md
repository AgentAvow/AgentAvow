# AGENTS.md

Guidance for coding agents (and people) working in this repository. Every fact here
comes from files in the repo or its merged PR history; when a file and this page
disagree, the file wins. Please fix this page in the same PR.

The product is AgentAvow. Older names still appear in code and infra (`agentgraph` is
the Python package name, the database name and the Docker image names); don't rename
them in passing.

## Layout

- `src/` FastAPI backend (`src/main.py` is the app). Scanner in `src/scanner/`, API routers in `src/api/`, trust and scoring in `src/trust/`, tool-call gate bridges in `src/bridges/`.
- `tests/` pytest suite for the backend, plugin scripts and deploy scripts (about 500 files). `tests/corpus/` holds the static and install-check corpora.
- `migrations/` Alembic migrations (`alembic.ini` at the root).
- `web/` React + TypeScript + Vite frontend, with prerendered public pages (`web/scripts/prerender.mjs`). Current site pages live under `web/src/rebrand/`.
- `plugins/agentavow-trust/` the Claude Code plugin (MIT). `.claude-plugin/marketplace.json` at the root lists it. `plugins/langchain-trust/` is the LangChain plugin.
- `integrations/` the claude-code hook scripts, plus litellm, opa (policy tested in CI) and openai-plugin.
- `sdk/` SDKs and packages: `js/` (npm gate, tested in CI), `python/`, `mcp-server/`, `bridges/`, and others. See `sdk/PUBLISHING.md`.
- `docs/standards/` open specs and conformance vectors (Apache-2.0 / CC BY 4.0; see `CONTRIBUTING.md`). Each vector folder has `generate.mjs` and `verify.mjs`.
- `docs/adr/` architecture decision records: decisions already made. Read the index before proposing to change a core layer.
- `docs/` user and operator docs (quickstart, onboarding, moderation playbook, `security-scan-false-positives.md`).
- `github-action/` the PR trust-scan Action (`trust-scan.yml` runs it on PRs). `local-scan-action/` is the local-scan Action (`agentavow-selfscan.yml`).
- `gitlab/`, `bitbucket/`, `azure-devops/` CI templates around the slim scanner image (`docker/scanner.Dockerfile`).
- `scripts/` ops, deploy, cron and data scripts. `scripts/ci/` and `scripts/corpus/` are used by workflows.
- `nginx/`, `Dockerfile`, `web/Dockerfile`, `docker-compose.yml`, `docker-compose.prod.yml` hold the deployment config.
- `demos/rugpull/` is a rug-pull demo with a CI test.

Licensing differs by folder: only the standards folders and `plugins/agentavow-trust/`
take outside contributions; `src/`, `web/`, `sdk/` and `scripts/` are all rights reserved
(`CONTRIBUTING.md`).

## Backend: lint and test (as `.github/workflows/ci.yml` does)

CI uses Python 3.12 (`requires-python >=3.11`), a `postgres:16` service (database
`agentgraph_test`) and a `redis:7` service.

**Tests wipe their database.** `tests/conftest.py` truncates every table in whatever
`DATABASE_URL` points at. Point it at a dedicated test database, never dev, staging or
prod. When two agents run at once, give each its own database (for example
`agentgraph_test_<name>`, then `alembic upgrade head` against it), because they
truncate each other's data.

```bash
pip install -e ".[prod,dev]"
ruff check src/ tests/
# AST verify: every .py under src/ and tests/ must parse (`make ast-verify`)
alembic upgrade head          # env: DATABASE_URL
pytest tests/ -v              # env: DATABASE_URL, REDIS_URL, DEBUG=true
```

- `DATABASE_URL` uses the `postgresql+asyncpg://` driver. Set `REDIS_URL` too.
- `DEBUG` must be `true` for tests. `.env` is not tracked, and without debug the settings
  refuse the default `JWT_SECRET`, so every module errors.
- The full CI run takes about 25 to 35 minutes, judging by recent runs. Run the tests
  you touched locally first, e.g. `pytest tests/test_x.py -q`.
- **`make check`** runs the fast gates in one go: ruff, AST verify, the doc-parity test
  (`tests/test_doc_parity.py`, which checks that the commands and paths on this page
  exist) and the web typecheck. It needs no database. Run it before every push. The
  full suite is still `make test`.
- The Makefile wraps these with a `.venv` (`make setup`, `make lint`, `make test`,
  `make migrate`); pass `VENV=.venv312` (or any other venv) to use a different one.
  Its `db-start` target uses Homebrew services, so it is macOS-only.
  On Linux, `docker compose up db redis` from `docker-compose.yml` gives you Postgres
  and Redis.
- New migration: `alembic revision --autogenerate -m "..."` (`make migration`).
- Changes under `src/scanner/**`, `scripts/corpus/**` and the corpus fixtures also
  trigger `static-corpus.yml`. `make corpus` runs it locally (it downloads archives
  and never executes them).

## Frontend (as ci.yml does)

Node: CI uses Node 20 for `web/`. Check the `vite` version in `web/package.json` for
its supported Node range.

```bash
cd web
npm ci
npm run lint                  # eslint; see note below
npx tsc -b
VITE_CUTOVER=true npx vite build
VITE_CUTOVER=true PRERENDER_STRICT=1 npm run prerender
```

`PRERENDER_STRICT=1` makes CI fail when a public page stops rendering (on the host
it only warns). ci.yml does not run eslint on `web/`; keep `npm run lint` clean anyway.

Other CI jobs: `sdk/js` (`npm ci && npm test`, Node 22), `demos/rugpull`, OPA policy
tests, Bitbucket/Azure template runs against the scanner image, and a non-blocking
`pip-audit` / `npm audit`. On pushes to main only, CI builds the Docker images and
publishes `ghcr.io/agentavow/scanner`.

## Workflow rails

- Work in a git worktree on a new branch, never in the primary checkout:
  `git worktree add ../AgentAvow-wt-<topic> -b <type>/<topic> origin/main`.
  One writer per worktree.
- One PR per change. Branch names follow `feat/`, `fix/`, `chore/`, `docs/`.
  `.github/pull_request_template.md` lists the checks every PR ticks.
- Never merge past failing CI or missing reviews, and never bypass branch protection.
- `ci.yml` runs on every PR, including PRs stacked on another PR's branch, and on
  pushes to main. `gh workflow run ci.yml --ref <branch>` triggers a manual run.
- Stack PRs that change `web/package.json` / `web/package-lock.json` on top of each
  other (as #371 → #373 → #374 → #375 did). Parallel lockfile changes conflict.
- Don't change global git config or system config. Pass one-off settings with
  `git -c ...`.
- Never commit secrets. `.env*.example` / `.env.production.template` show variable
  names only.

## House rules

- **Tests wipe their database.** See the warning under "Backend": a dedicated test
  database per agent, never dev, staging or prod.
- **Python tables have TypeScript twins.** Change both sides in one PR:
  `src/scanner/verdict.py` ↔ `web/src/components/trust/gradeSystem.ts`, and
  `src/scanner/categories.py` ↔ `web/src/components/trust/scanCategories.ts`.
  Main has gone red when only one side changed.
- **Pushing to `main` releases things.** The Claude Code plugin
  (`.claude-plugin/marketplace.json` → `plugins/agentavow-trust`) reaches everyone who
  has it installed, and a push touching `sdk/mcp-server/**` is mirrored to
  AgentAvow/agentavow-trust-mcp (`mirror-mcp-server.yml`), which Glama builds from.
  Everything goes through a PR.
- **The hosted `/mcp` tool list is pinned.** `_TOOLS` in `src/bridges/mcp_streamable.py`
  is guarded by `tests/fixtures/mcp_tools_list_snapshot.json`,
  `tests/fixtures/mcp_wire_2025_11_25/tools_list.json`, `EXPECTED_TOOLS_LIST_SHA256` in
  `src/jobs/mcp_health.py` and the digest in `tests/test_mcp_card_trust_adoption_c.py`.
  Any change to it also needs a manual Rescan of the published ChatGPT app by the
  owner. Schema changes are additive only; flag them in the PR description.
- **Merge only on an explicit green.** A watcher that errored or a pending job is not a
  pass.
- **No AI-attribution trailers** (`Co-Authored-By: Claude`, `Claude-Session:`,
  "Generated with …") in commits, PR text or comments.
- **Prod belongs to the owner.** No commands against the prod host or prod database.
  The owner deploys (`scripts/deploy-prod.sh`); migrations run in the container
  entrypoint (`scripts/docker-entrypoint.sh`).

## Agent work queue

GitHub labels drive which issues agents pick up:

- `agent:ready`: owner-approved for the agent queue. Only the owner applies it.
- `agent:in-progress`: claimed by an agent; other agents skip it.
- `agent:needs-owner`: the agent is stuck (plan approval, a failure or a question) and
  needs the owner.
- `agent:needs-product`: needs a product or architecture decision; agents must not act
  on it.
- `priority:1` (highest), `priority:2` (normal), `priority:3` (low).

Pick `agent:ready` issues by priority, highest first, then oldest. Add
`agent:in-progress` when you start. If a fix would widen into a product or architecture
change, add `agent:needs-product`, explain why in one comment, and stop.

## Conventions

- **PR titles are plain language**, written for the person affected:
  "Area: what changed". Examples: "Catalog growth: take turns across sources in the
  scan queue", "Slow first package scans answer 202 checking instead of a 503".
  Put the plugin version in the title when you bump it ("Plugin 0.1.40: ...").
- **Plugin version bumps** (`agentavow-trust`): the version has to match in all of
  these places, and `tests/test_agentavow_precheck.py::test_versions_agree` enforces it:
  - `plugins/agentavow-trust/.claude-plugin/plugin.json` (`version`)
  - `.claude-plugin/marketplace.json` (`plugins[0].version`)
  - `__version__` in `plugins/agentavow-trust/scripts/agentavow_{precheck,pretool_gate,pre_install}.py`

  `integrations/claude-code/agentavow_*.py` are byte-identical copies of those three
  scripts. Past bumps (#347, #356, #369) changed both copies together, so keep them in
  sync. The plugin README also quotes the version (the active-signal example).
- **Deploy gate:** `scripts/deploy-prod.sh` runs `nginx -t` on the new config in a
  throwaway container before it rebuilds or restarts anything, and stops if that
  fails. `tests/test_deploy_prod_script.py` pins this. Keep the gate.
- **Settings:** add a field to `Settings` in `src/config.py` and a line to
  `.env.example` (`tests/test_settings.py` checks every field is listed), then read
  `settings.<field>`. Don't read `os.environ` / `os.getenv` under `src/`:
  `tests/test_no_direct_env_reads.py` fails on new reads. In production
  (`ENVIRONMENT=production`, or `DEBUG=false` with it unset) the app refuses to start
  with the default `JWT_SECRET` or a localhost database or Redis. See
  `docs/adr/0001-settings-validated-at-startup.md`.
- **Scanner false positives** for users: `docs/security-scan-false-positives.md`
  covers inline `# ag-scan:ignore` and allowlist entries. Scanner precision fixes
  usually come with corpus or fixture tests.
- **Standards vectors:** `node generate.mjs` must reproduce the vector file
  byte-for-byte and `node verify.mjs` must pass (`CONTRIBUTING.md`).
- **Commits for outside contributions** use DCO sign-off (`git commit -s`).
