#!/usr/bin/env bash
set -euo pipefail

: "${SPIRE_SERVER_CONTAINER:=zt-spire-server}"
: "${TRUST_DOMAIN:=zt.local}"

# ── Resolve the agent's SPIFFE ID automatically ──────────────────
AGENT_ID=$(docker exec "${SPIRE_SERVER_CONTAINER}" \
    /opt/spire/bin/spire-server agent list 2>&1 \
    | grep -oE 'spiffe://[^ "]+' | head -1 || echo "")

if [ -z "$AGENT_ID" ]; then
    echo "ERROR: No attested agent found. Start spire-agent first."
    exit 1
fi
echo "Agent ID: $AGENT_ID"

register() {
    local spiffe_id="$1"
    local selector="$2"
    docker exec "${SPIRE_SERVER_CONTAINER}" \
        /opt/spire/bin/spire-server entry create \
        -parentID "$AGENT_ID" \
        -spiffeID "$spiffe_id" \
        -selector "$selector" \
        -x509SVIDTTL 3600 2>&1 | grep -v "AlreadyExists" || true
}

# ── Gateway & Worker (unix:uid:0 — process-level attestation) ────
register "spiffe://${TRUST_DOMAIN}/php-gateway" "unix:uid:0"
register "spiffe://${TRUST_DOMAIN}/php-worker"  "unix:uid:0"

# ── Downstream Services (unix:uid:0 — each service) ─────────────
register "spiffe://${TRUST_DOMAIN}/order-service"      "unix:uid:0"
register "spiffe://${TRUST_DOMAIN}/production-service"  "unix:uid:0"
register "spiffe://${TRUST_DOMAIN}/user-service"        "unix:uid:0"

echo ""
echo "Registered entries:"
docker exec "${SPIRE_SERVER_CONTAINER}" \
    /opt/spire/bin/spire-server entry show 2>&1 | grep "SPIFFE ID"
