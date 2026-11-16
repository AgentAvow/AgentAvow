.PHONY: setup dev test lint ast-verify migrate db-start db-stop db-status clean corpus \
	check web-typecheck doc-parity

# Virtualenv the targets below run from. Override per call, e.g. `make check VENV=.venv312`.
VENV ?= .venv

# Fast gates in one command: lint, AST verify, the AGENTS.md doc-parity test and the web
# typecheck. Needs no database, Redis or network. The full suite stays `make test`.
check: lint ast-verify doc-parity web-typecheck
	@echo ""
	@echo "make check: all fast gates passed"

# Development setup
setup: db-start
	python3 -m venv .venv
	$(VENV)/bin/pip install -e ".[dev]"
	@echo ""
	@echo "Creating database if it doesn't exist..."
	createdb agentgraph 2>/dev/null || true
	@echo ""
	@echo "Setup complete. Activate venv with: source $(VENV)/bin/activate"

# Run dev server
dev:
	$(VENV)/bin/uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Run tests
test:
	$(VENV)/bin/pytest tests/ -v

# Static known-good corpus gate (top 200 PyPI + npm, pinned). Downloads archives into
# ~/.cache/agentavow-static-corpus (override: AGENTAVOW_CORPUS_CACHE); never executes them.
corpus:
	$(VENV)/bin/python3 -I scripts/corpus/run_static_corpus.py --workers 4 --fail-on-diff

# Lint
lint:
	$(VENV)/bin/ruff check src/ tests/

# Lint and fix
lint-fix:
	$(VENV)/bin/ruff check --fix src/ tests/

# AST verify all Python files under src/ and tests/ (exits non-zero if any file fails to parse)
ast-verify:
	@python3 scripts/ci/ast_verify.py src tests

# AGENTS.md doc-parity test: every make target, npm script and repo path it names must exist.
# --noconftest skips tests/conftest.py, so this needs no database.
doc-parity:
	$(VENV)/bin/python3 -m pytest --noconftest -q tests/test_doc_parity.py

# Typecheck the web app the way CI does (needs `npm ci` in web/ first)
web-typecheck:
	@test -d web/node_modules || { echo "web/node_modules missing: run 'cd web && npm ci' first"; exit 1; }
	cd web && npx tsc -b

# Run Alembic migration
migrate:
	$(VENV)/bin/alembic upgrade head

# Create new migration
migration:
	@read -p "Migration message: " msg; \
	$(VENV)/bin/alembic revision --autogenerate -m "$$msg"

# Database management (Homebrew services)
db-start:
	brew services start postgresql@16 2>/dev/null || true
	brew services start redis 2>/dev/null || true
	@echo "PostgreSQL and Redis started"

db-stop:
	brew services stop postgresql@16 2>/dev/null || true
	brew services stop redis 2>/dev/null || true
	@echo "PostgreSQL and Redis stopped"

db-status:
	@brew services list | grep -E "postgresql|redis"

# Clean build artifacts
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .coverage htmlcov
