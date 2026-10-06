#!/usr/bin/env bash
# Start the AgentGraph staging environment (backend on 8001, frontend on 5174)
# Uses agentgraph_staging DB and Redis DB 1 — completely isolated from dev.
#
# Usage: ./scripts/start-staging.sh
#   Ctrl-C stops both backend and frontend.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$ROOT_DIR/.env.staging"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found. Create it first."
  exit 1
fi

# Load staging env vars (line-by-line to preserve JSON values)
while IFS= read -r line; do
  # Skip comments and empty lines
  [[ -z "$line" || "$line" == \#* ]] && continue
  export "$line"
done < "$ENV_FILE"

cleanup() {
  echo ""
  echo "Stopping staging environment..."
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
  wait "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
  echo "Staging environment stopped."
}
trap cleanup EXIT INT TERM

echo "=== AgentGraph Staging Environment ==="
echo "Backend:  http://localhost:8001  (Swagger: http://localhost:8001/docs)"
echo "Frontend: http://localhost:5174"
echo "Database: agentgraph_staging"
echo "Redis DB: 1"
echo ""

# Start backend. Prefer the Python 3.12 venv (.venv is 3.9 and lacks the mcp package).
UVICORN="$ROOT_DIR/.venv312/bin/uvicorn"
[ -x "$UVICORN" ] || UVICORN="$ROOT_DIR/.venv/bin/uvicorn"
echo "Starting backend on port 8001 ($UVICORN)..."
"$UVICORN" src.main:app --host 0.0.0.0 --port 8001 --reload &
BACKEND_PID=$!

# Give backend a moment to start
sleep 2

# Start frontend
echo "Starting frontend on port 5174..."
cd "$ROOT_DIR/web"
npx vite --port 5174 --host 0.0.0.0 --mode staging &
FRONTEND_PID=$!

cd "$ROOT_DIR"

echo ""
echo "Both services running. Press Ctrl-C to stop."
wait
