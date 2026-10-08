#!/usr/bin/env bash
# AgentGraph Production Deployment Script
# Deploys to EC2 instance via SSH.
#
# Usage:
#   ./scripts/deploy-prod.sh                 # Full deploy (backend + frontend)
#   ./scripts/deploy-prod.sh --backend-only  # Backend only (skip frontend rebuild)
#   ./scripts/deploy-prod.sh --frontend-only # Frontend only (skip backend rebuild)
#   ./scripts/deploy-prod.sh --dry-run       # Show what would be done
#
# Flags can be combined: --frontend-only --dry-run

set -euo pipefail

# --- Configuration ---
EC2_HOST="${AG_EC2_HOST:?Set AG_EC2_HOST env var (e.g. your Elastic IP)}"
EC2_USER="ec2-user"
SSH_KEY="${AG_SSH_KEY:?Set AG_SSH_KEY env var (path to your SSH key)}"
PROJECT_DIR="agentgraph"
COMPOSE_FILE="docker-compose.prod.yml"
# Branch to deploy. Always checked out explicitly: the host can be left on a hotfix
# branch, and a bare `git pull` there would report "up to date" and rebuild the old
# code. Override with AG_DEPLOY_BRANCH to ship a hotfix branch.
DEPLOY_BRANCH="${AG_DEPLOY_BRANCH:-main}"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"

# Load prod secrets (POSTGRES_PASSWORD, REDIS_PASSWORD, JWT_SECRET, …) into the
# remote shell BEFORE invoking docker-compose so the YAML's `${VAR:?must be set}`
# interpolations resolve. `.env.production` carries the 28 prod vars; the
# auto-loaded `.env` only carries 9 (and lacks the secrets since the 2026-05-26
# cleanup that removed a stranded stash injection). `set -a` exports everything
# sourced; shell env takes precedence over `.env` so the 3 `.env`-only vars
# (NODE_ENV, TASK_MASTER_*) still come through compose's normal auto-load.
LOAD_ENV='set -a && source .env.production && set +a'

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Parse flags ---
BACKEND=true
FRONTEND=true
DRY_RUN=false

for arg in "$@"; do
  case "$arg" in
    --backend-only)  FRONTEND=false ;;
    --frontend-only) BACKEND=false ;;
    --dry-run)       DRY_RUN=true ;;
    --help|-h)
      echo "Usage: $0 [--backend-only] [--frontend-only] [--dry-run]"
      echo ""
      echo "Flags:"
      echo "  --backend-only   Skip frontend rebuild, only rebuild and restart backend"
      echo "  --frontend-only  Skip backend rebuild, only rebuild frontend and restart nginx"
      echo "  --dry-run        Print what would be done without executing"
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown flag: $arg${NC}"
      echo "Run $0 --help for usage."
      exit 1
      ;;
  esac
done

# --- Helpers ---
step=0
step() {
  step=$((step + 1))
  echo ""
  echo -e "${CYAN}${BOLD}[$step] $1${NC}"
}

ok() {
  echo -e "    ${GREEN}OK${NC} $1"
}

fail() {
  echo -e "    ${RED}FAIL${NC} $1"
  exit 1
}

warn() {
  echo -e "    ${YELLOW}WARN${NC} $1"
}

# Run a command on EC2 via SSH. Pass the command string as $1.
remote() {
  ssh $SSH_OPTS "${EC2_USER}@${EC2_HOST}" "$1"
}

# --- Pre-flight checks ---
echo -e "${BOLD}=== AgentGraph Production Deploy ===${NC}"
echo ""
echo -e "  Host:     ${EC2_USER}@${EC2_HOST}"
echo -e "  Branch:   ${DEPLOY_BRANCH}"
echo -e "  Backend:  ${BACKEND}"
echo -e "  Frontend: ${FRONTEND}"
echo -e "  Dry run:  ${DRY_RUN}"

if $DRY_RUN; then
  echo ""
  echo -e "${YELLOW}${BOLD}--- DRY RUN MODE --- No commands will be executed ---${NC}"
fi

# Verify SSH key exists
if [ ! -f "$SSH_KEY" ]; then
  fail "SSH key not found at $SSH_KEY"
fi

# --- Step 1: Test SSH connectivity ---
step "Testing SSH connectivity"
if $DRY_RUN; then
  echo "    Would run: ssh $SSH_OPTS ${EC2_USER}@${EC2_HOST} 'echo ok'"
else
  if remote "echo ok" > /dev/null 2>&1; then
    ok "Connected to ${EC2_HOST}"
  else
    fail "Cannot SSH to ${EC2_HOST}. Check key and security group."
  fi
fi

# --- Step 2: Git pull ---
step "Pulling latest code"
if $DRY_RUN; then
  echo "    Would run: cd ~/${PROJECT_DIR} && git fetch origin && git checkout ${DEPLOY_BRANCH} && git pull --ff-only origin ${DEPLOY_BRANCH}"
else
  OUTPUT=$(remote "cd ~/${PROJECT_DIR} && git fetch origin && git checkout ${DEPLOY_BRANCH} && git pull --ff-only origin ${DEPLOY_BRANCH}" 2>&1) \
    || { echo "    $OUTPUT"; fail "Could not check out ${DEPLOY_BRANCH} on the host."; }
  echo "    $OUTPUT"
  ok "On ${DEPLOY_BRANCH}: $(remote "cd ~/${PROJECT_DIR} && git log --oneline -1")"
fi

# --- Step 3: Build backend ---
if $BACKEND; then
  step "Building backend Docker image"
  # bluesky-subscriber has no build of its own: it runs the image tagged here
  # (agentavow-backend:latest), and the `up -d` in step 5 recreates it on the new image.
  if $DRY_RUN; then
    echo "    Would run: cd ~/${PROJECT_DIR} && ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} build backend"
  else
    remote "cd ~/${PROJECT_DIR} && ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} build backend" 2>&1 | while IFS= read -r line; do
      echo "    $line"
    done
    ok "Backend image built"
  fi
fi

# --- Step 4: Build frontend ---
if $FRONTEND; then
  step "Linting website copy for AI-slop (warn-only)"
  if ! $DRY_RUN; then
    remote "cd ~/${PROJECT_DIR} && python3 scripts/lint_website_copy.py 2>&1 || true" | while IFS= read -r line; do
      echo "    $line"
    done
  fi
  step "Building frontend (npm ci + npm run build)"
  if $DRY_RUN; then
    echo "    Would run: cd ~/${PROJECT_DIR}/web && npm ci && npm run build"
  else
    remote "cd ~/${PROJECT_DIR}/web && npm ci && npm run build" 2>&1 | while IFS= read -r line; do
      echo "    $line"
    done
    ok "Frontend built to web/dist/"
  fi
fi

# --- Step 5: Restart services ---
# Order matters when the backend is recreated: nginx resolves `backend` once at start
# and keeps the OLD container's IP, so it serves 502s until it is restarted. Restarting
# it before the new backend answers is not enough either (2026-10-08: a backend-only
# deploy served 502 until nginx was restarted a second time). So in EVERY mode that
# recreates the backend: up -d -> wait for the backend container itself to answer
# /health -> restart nginx -> the through-nginx health check (step 6).
step "Restarting services"
if $DRY_RUN; then
  if $BACKEND; then
    echo "    Would run: ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} up -d"
    echo "    Would poll http://localhost:8000/health INSIDE the backend container (docker-compose exec -T backend) up to 120 seconds"
    echo "    Would run: ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} restart nginx   (after the backend answers; re-resolves its new IP)"
  elif $FRONTEND; then
    echo "    Would run: ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} restart nginx"
  fi
else
  if $BACKEND; then
    remote "cd ~/${PROJECT_DIR} && ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} up -d" 2>&1 | while IFS= read -r line; do
      echo "    $line"
    done
    ok "Services started"

    # The backend container itself, not through nginx (nginx may still point at the
    # old container). Startup with migrations takes ~60 s.
    BACKEND_UP=false
    for i in $(seq 1 60); do
      if remote "cd ~/${PROJECT_DIR} && ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} exec -T backend python3 -c 'import httpx, sys; r = httpx.get(\"http://localhost:8000/health\", timeout=3); sys.exit(0 if r.json().get(\"status\") == \"ok\" else 1)'" > /dev/null 2>&1; then
        BACKEND_UP=true
        break
      fi
      echo "    Backend container attempt $i/60 — waiting 2s..."
      sleep 2
    done
    if $BACKEND_UP; then
      ok "Backend container answers /health"
    else
      fail "Backend container did not answer /health within 120 seconds. Check logs: ssh $SSH_OPTS ${EC2_USER}@${EC2_HOST} 'cd ~/${PROJECT_DIR} && docker-compose -f ${COMPOSE_FILE} logs backend --tail 50'"
    fi

    # Now nginx: re-resolve the new backend container (and pick up fresh static files
    # on a full deploy).
    remote "cd ~/${PROJECT_DIR} && ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} restart nginx" 2>&1 | while IFS= read -r line; do
      echo "    $line"
    done
    ok "Nginx restarted after the backend came up"
  elif $FRONTEND; then
    # Frontend-only: the backend was not recreated; restart nginx for the new web/dist
    remote "cd ~/${PROJECT_DIR} && ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} restart nginx" 2>&1 | while IFS= read -r line; do
      echo "    $line"
    done
    ok "Nginx restarted"
  fi
fi

# --- Step 6: Wait for backend to be healthy ---
step "Waiting for the site to be healthy (through nginx)"
if $DRY_RUN; then
  echo "    Would poll https://localhost/health (Host: agentavow.com, through nginx) up to 120 seconds"
else
  HEALTHY=false
  # Through nginx over https with the real Host, and require the body: plain
  # http://localhost answers 301 (the https redirect), which `curl -f` counts as
  # success, so the old check passed while the backend was still booting and
  # nginx was serving 502s (2026-10-08). Startup with migrations takes ~60 s.
  for i in $(seq 1 60); do
    if remote "curl -sk --max-time 3 -H 'Host: agentavow.com' https://localhost/health | grep -q '\"status\":\"ok\"'" > /dev/null 2>&1; then
      HEALTHY=true
      break
    fi
    echo "    Attempt $i/60 — waiting 2s..."
    sleep 2
  done
  if $HEALTHY; then
    ok "Backend is healthy"
  else
    fail "Backend did not become healthy within 120 seconds. Check logs: ssh $SSH_OPTS ${EC2_USER}@${EC2_HOST} 'cd ~/${PROJECT_DIR} && docker-compose -f ${COMPOSE_FILE} logs backend --tail 50'"
  fi

  # Reclaim disk from the image we just replaced (each deploy builds a fresh backend
  # image; without this they pile up and fill the 30G root — happened 2026-08-19).
  # Safe: prunes only unreferenced images/cache, never volumes or running containers.
  remote "docker image prune -af >/dev/null 2>&1 || true; docker builder prune -af >/dev/null 2>&1 || true" 2>/dev/null || true
  ok "Old images pruned"
fi

# --- Step 7: Verify login ---
step "Verifying login (inside backend container)"
if $DRY_RUN; then
  echo "    Would run: docker-compose exec backend python3 -c '...httpx login test...'"
else
  # Run the login test inside the backend container to avoid SSH quoting issues
  # with the ! character in the password. Retry up to 5 times with 2s delay
  # since the backend may still be starting after container recreation.
  LOGIN_RESULT=""
  for attempt in $(seq 1 5); do
    LOGIN_RESULT=$(remote "cd ~/${PROJECT_DIR} && ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} exec -T backend python3 -c '
import httpx, sys, time
time.sleep(1)
import os
email = os.environ.get(\"ADMIN_EMAIL\", \"kenne@agentgraph.co\")
password = os.environ.get(\"ADMIN_PASSWORD\", \"\")
if not password:
    print(\"LOGIN_SKIP: set ADMIN_EMAIL and ADMIN_PASSWORD env vars to verify login\")
    sys.exit(0)
r = httpx.post(\"http://localhost:8000/api/v1/auth/login\", json={\"email\": email, \"password\": password})
if r.status_code == 200:
    print(\"LOGIN_OK\")
else:
    print(f\"LOGIN_FAIL status={r.status_code} body={r.text[:200]}\")
    sys.exit(1)
'" 2>&1) || true
    if echo "$LOGIN_RESULT" | grep -q -e "LOGIN_OK" -e "LOGIN_SKIP"; then
      break
    fi
    echo "    Attempt $attempt/5 — retrying in 2s..."
    sleep 2
  done

  if echo "$LOGIN_RESULT" | grep -q "LOGIN_OK"; then
    ok "Login verified"
  elif echo "$LOGIN_RESULT" | grep -q "LOGIN_SKIP"; then
    # No admin credentials in the container: a real login can't be tried, which is not
    # a failure. Still prove the auth route is alive: bad credentials must get a 401.
    # (Straight to the backend, like the login test: through nginx plain http is a 301.)
    PROBE=$(remote "cd ~/${PROJECT_DIR} && ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} exec -T backend python3 -c 'import httpx; print(httpx.post(\"http://localhost:8000/api/v1/auth/login\", json={\"email\": \"deploy-probe@example.com\", \"password\": \"not-a-real-password\"}).status_code)'" 2>/dev/null | tail -1 | tr -d '[:space:]')
    PROBE="${PROBE:-000}"
    if [ "$PROBE" = "401" ]; then
      warn "Login not verified (no ADMIN_EMAIL/ADMIN_PASSWORD in the container); login endpoint answers 401 to bad credentials"
    else
      fail "Login endpoint returned $PROBE to bad credentials (expected 401). Check backend logs."
    fi
  else
    echo "    $LOGIN_RESULT"
    fail "Login verification failed. Check backend logs."
  fi
fi

# --- Step 8: Show container status ---
step "Container status"
if $DRY_RUN; then
  echo "    Would run: ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} ps"
else
  remote "cd ~/${PROJECT_DIR} && ${LOAD_ENV} && docker-compose -f ${COMPOSE_FILE} ps" 2>&1 | while IFS= read -r line; do
    echo "    $line"
  done
fi

# --- Done ---
echo ""
if $DRY_RUN; then
  echo -e "${YELLOW}${BOLD}=== Dry run complete. No changes were made. ===${NC}"
else
  echo -e "${GREEN}${BOLD}=== Deployment successful ===${NC}"
  echo ""
  echo -e "  Site:  http://${EC2_HOST}"
  echo -e "  Logs:  ssh ${SSH_OPTS} ${EC2_USER}@${EC2_HOST} 'cd ~/${PROJECT_DIR} && docker-compose -f ${COMPOSE_FILE} logs -f'"
fi
