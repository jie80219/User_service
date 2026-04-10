#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
#  SPIFFE E2E Bootstrap — generates CA, registers workloads, waits
#  for all components to be healthy.
#
#  Run inside the spire-server container AFTER it starts.
#
#  Usage:
#    docker compose -f docker-compose.spiffe.yml exec spire-server \
#        /opt/spire/conf/e2e/bootstrap.sh
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

SPIRE_SERVER_BIN="/opt/spire/bin/spire-server"
TRUST_DOMAIN="zt.local"
MAX_WAIT=60

log() { echo "[e2e-bootstrap] $(date +%T) $*"; }

# ──────────────────────────────────────────────────────────────────
#  1. Wait for SPIRE Server to be healthy
# ──────────────────────────────────────────────────────────────────
log "Waiting for SPIRE Server healthcheck..."
elapsed=0
until ${SPIRE_SERVER_BIN} healthcheck 2>/dev/null; do
    sleep 1
    elapsed=$((elapsed + 1))
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        log "ERROR: SPIRE Server not healthy after ${MAX_WAIT}s"
        exit 1
    fi
done
log "SPIRE Server is healthy."

# ──────────────────────────────────────────────────────────────────
#  2. Generate a join token for the Agent
# ──────────────────────────────────────────────────────────────────
log "Generating agent join token..."
JOIN_TOKEN=$(${SPIRE_SERVER_BIN} token generate -spiffeID "spiffe://${TRUST_DOMAIN}/agent" -ttl 600 2>&1 | grep -oP 'Token: \K\S+' || true)

if [ -z "$JOIN_TOKEN" ]; then
    # Fallback: parse differently depending on SPIRE version
    JOIN_TOKEN=$(${SPIRE_SERVER_BIN} token generate -spiffeID "spiffe://${TRUST_DOMAIN}/agent" -ttl 600 | tail -1 | awk '{print $NF}')
fi

if [ -z "$JOIN_TOKEN" ]; then
    log "ERROR: Failed to generate join token"
    exit 1
fi

log "Join token: ${JOIN_TOKEN}"

# Write token to shared volume so the agent can read it
echo "${JOIN_TOKEN}" > /opt/spire/conf/shared/join-token

# ──────────────────────────────────────────────────────────────────
#  3. Wait for Agent to attest (it reads the join token on startup)
# ──────────────────────────────────────────────────────────────────
log "Waiting for SPIRE Agent to attest..."
elapsed=0
until ${SPIRE_SERVER_BIN} agent list 2>/dev/null | grep -q "spiffe://${TRUST_DOMAIN}"; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        log "WARNING: Agent not yet attested after ${MAX_WAIT}s — continuing anyway"
        break
    fi
done

# Get the Agent's SPIFFE ID for parent ID
AGENT_ID=$(${SPIRE_SERVER_BIN} agent list 2>/dev/null | grep -oP 'spiffe://[^\s"]+' | head -1 || echo "")
log "Attested agent: ${AGENT_ID:-none}"

# ──────────────────────────────────────────────────────────────────
#  4. Register workload entries
# ──────────────────────────────────────────────────────────────────
log "Registering workload: spiffe://${TRUST_DOMAIN}/php-gateway"
${SPIRE_SERVER_BIN} entry create \
    -parentID "spiffe://${TRUST_DOMAIN}/agent" \
    -spiffeID "spiffe://${TRUST_DOMAIN}/php-gateway" \
    -selector "unix:uid:0" \
    -ttl 3600 \
    2>&1 || true

log "Registering workload: spiffe://${TRUST_DOMAIN}/php-worker"
${SPIRE_SERVER_BIN} entry create \
    -parentID "spiffe://${TRUST_DOMAIN}/agent" \
    -spiffeID "spiffe://${TRUST_DOMAIN}/php-worker" \
    -selector "unix:uid:0" \
    -ttl 3600 \
    2>&1 || true

log "Registering workload: spiffe://${TRUST_DOMAIN}/order-service"
${SPIRE_SERVER_BIN} entry create \
    -parentID "spiffe://${TRUST_DOMAIN}/agent" \
    -spiffeID "spiffe://${TRUST_DOMAIN}/order-service" \
    -selector "unix:uid:0" \
    -ttl 3600 \
    2>&1 || true

log "Registering workload: spiffe://${TRUST_DOMAIN}/production-service"
${SPIRE_SERVER_BIN} entry create \
    -parentID "spiffe://${TRUST_DOMAIN}/agent" \
    -spiffeID "spiffe://${TRUST_DOMAIN}/production-service" \
    -selector "unix:uid:0" \
    -ttl 3600 \
    2>&1 || true

log "Registering workload: spiffe://${TRUST_DOMAIN}/user-service"
${SPIRE_SERVER_BIN} entry create \
    -parentID "spiffe://${TRUST_DOMAIN}/agent" \
    -spiffeID "spiffe://${TRUST_DOMAIN}/user-service" \
    -selector "unix:uid:0" \
    -ttl 3600 \
    2>&1 || true

log "Registering workload: spiffe://${TRUST_DOMAIN}/test-client"
${SPIRE_SERVER_BIN} entry create \
    -parentID "spiffe://${TRUST_DOMAIN}/agent" \
    -spiffeID "spiffe://${TRUST_DOMAIN}/test-client" \
    -selector "unix:uid:0" \
    -ttl 3600 \
    2>&1 || true

# ──────────────────────────────────────────────────────────────────
#  5. Show registered entries
# ──────────────────────────────────────────────────────────────────
log "Registered entries:"
${SPIRE_SERVER_BIN} entry show 2>&1 || true

# ──────────────────────────────────────────────────────────────────
#  6. Mark bootstrap complete
# ──────────────────────────────────────────────────────────────────
touch /opt/spire/conf/shared/bootstrap-done
log "Bootstrap complete."
