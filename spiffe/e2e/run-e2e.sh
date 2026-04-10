#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SPIFFE E2E Test — all-in-one runner
#
#  Orchestrates the full lifecycle:
#    1. Build images
#    2. Start SPIRE Server
#    3. Bootstrap (generate join token + register workloads)
#    4. Start SPIRE Agent (attests with join token)
#    5. Run PHP E2E test suite
#    6. Report results
#    7. Tear down (optional: --keep to leave running)
#
#  Usage:
#    ./spiffe/e2e/run-e2e.sh          # run and tear down
#    ./spiffe/e2e/run-e2e.sh --keep   # run and keep environment alive
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

COMPOSE_FILE="docker-compose.spiffe.yml"
PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_DIR"

KEEP=false
[[ "${1:-}" == "--keep" ]] && KEEP=true

RED='\033[31m'
GREEN='\033[32m'
BOLD='\033[1m'
RESET='\033[0m'

log()  { echo -e "${BOLD}[e2e]${RESET} $(date +%T) $*"; }
pass() { echo -e "${GREEN}${BOLD}[PASS]${RESET} $*"; }
fail() { echo -e "${RED}${BOLD}[FAIL]${RESET} $*"; }

cleanup() {
    if [ "$KEEP" = false ]; then
        log "Tearing down..."
        docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    else
        log "Keeping environment alive (use 'docker compose -f $COMPOSE_FILE down -v' to clean up)"
    fi
}

trap cleanup EXIT

# ──────────────────────────────────────────────────────────────
#  1. Clean slate
# ──────────────────────────────────────────────────────────────
log "Cleaning previous E2E environment..."
docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
#  2. Build PHP image
# ──────────────────────────────────────────────────────────────
log "Building PHP E2E image..."
docker compose -f "$COMPOSE_FILE" build php-spiffe-e2e

# ──────────────────────────────────────────────────────────────
#  3. Start SPIRE Server
# ──────────────────────────────────────────────────────────────
log "Starting SPIRE Server..."
docker compose -f "$COMPOSE_FILE" up -d spire-server

log "Waiting for SPIRE Server to be healthy..."
timeout=60
elapsed=0
until docker compose -f "$COMPOSE_FILE" exec -T spire-server \
    /opt/spire/bin/spire-server healthcheck 2>/dev/null; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [ "$elapsed" -ge "$timeout" ]; then
        fail "SPIRE Server not healthy after ${timeout}s"
        docker compose -f "$COMPOSE_FILE" logs spire-server
        exit 1
    fi
done
log "SPIRE Server is healthy."

# ──────────────────────────────────────────────────────────────
#  4. Bootstrap: generate join token + register workloads
# ──────────────────────────────────────────────────────────────
log "Running bootstrap..."
docker compose -f "$COMPOSE_FILE" exec -T spire-server \
    /bin/sh /opt/spire/conf/e2e/bootstrap.sh

# ──────────────────────────────────────────────────────────────
#  5. Start SPIRE Agent
# ──────────────────────────────────────────────────────────────
log "Starting SPIRE Agent..."
docker compose -f "$COMPOSE_FILE" up -d spire-agent

log "Waiting for SPIRE Agent to be healthy..."
elapsed=0
until docker compose -f "$COMPOSE_FILE" exec -T spire-agent \
    /opt/spire/bin/spire-agent healthcheck 2>/dev/null; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [ "$elapsed" -ge "$timeout" ]; then
        fail "SPIRE Agent not healthy after ${timeout}s"
        docker compose -f "$COMPOSE_FILE" logs spire-agent
        exit 1
    fi
done
log "SPIRE Agent is healthy."

# ──────────────────────────────────────────────────────────────
#  6. Run PHP E2E tests
# ──────────────────────────────────────────────────────────────
log "Running PHP E2E test suite..."
echo ""

EXIT_CODE=0
docker compose -f "$COMPOSE_FILE" run --rm php-spiffe-e2e || EXIT_CODE=$?

echo ""

if [ "$EXIT_CODE" -eq 0 ]; then
    pass "All E2E tests passed!"
else
    fail "E2E tests failed (exit code: ${EXIT_CODE})"
    echo ""
    log "Dumping logs for debugging:"
    docker compose -f "$COMPOSE_FILE" logs spire-server --tail=20
    docker compose -f "$COMPOSE_FILE" logs spire-agent --tail=20
fi

exit "$EXIT_CODE"
