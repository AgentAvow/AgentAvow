.PHONY: setup dev test lint ast-verify migrate db-start db-stop db-status clean corpus

# Development setup
setup: db-start
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"
	@echo ""
	@echo "Creating database if it doesn't exist..."
	createdb agentgraph 2>/dev/null || true
	@echo ""
	@echo "Setup complete. Activate venv with: source .venv/bin/activate"

# Run dev server
dev:
	.venv/bin/uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Run tests
test:
	.venv/bin/pytest tests/ -v

# Static known-good corpus gate (top 200 PyPI + npm, pinned). Downloads archives into
# ~/.cache/agentavow-static-corpus (override: AGENTAVOW_CORPUS_CACHE); never executes them.
corpus:
	.venv/bin/python3 -I scripts/corpus/run_static_corpus.py --workers 4 --fail-on-diff

# Lint
lint:
	.venv/bin/ruff check src/ tests/

# Lint and fix
lint-fix:
	.venv/bin/ruff check --fix src/ tests/

# AST verify all Python files
ast-verify:
	@find src tests -name "*.py" -exec python3 -c "import ast, sys; ast.parse(open(sys.argv[1]).read()); print('OK:', sys.argv[1])" {} \;

# Run Alembic migration
migrate:
	.venv/bin/alembic upgrade head

# Create new migration
migration:
	@read -p "Migration message: " msg; \
	.venv/bin/alembic revision --autogenerate -m "$$msg"

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
