#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
#  Restart user-spire-agent + user-helper (in the correct order).
#
#  Can be invoked from anywhere — the script locates the project root
#  by walking up from its own location looking for docker-compose.yml.
#
#  Usage:
#    ./restart-agent-helper.sh                  # restart both
#    ./restart-agent-helper.sh --verify         # + verify SVID delivery
#    ./restart-agent-helper.sh --clean          # force-wipe agent cache up front
#    ./restart-agent-helper.sh --clean --verify
#    ./restart-agent-helper.sh --help
#
#  Auto-recovery: if spire-agent fails to become healthy and its log shows a
#  stale trust-bundle error (typically after zt-spire-server rotated its CA),
#  the script will automatically wipe the agent cache volume and retry once.
#  Use --clean only if you want to force the wipe up front.
#
#  Environment overrides:
#    CENTRAL_SERVER   (default: zt-spire-server)
#    SPIFFE_ID        (default: spiffe://zt.local/user-service)
#    HEALTH_TIMEOUT   (default: 30   — seconds to wait for agent healthy)
#    VERIFY_TIMEOUT   (default: 30   — seconds to wait for helper SVID)
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

usage() {
    sed -n '2,25p' "$0" | sed 's/^#\s\{0,1\}//'
    exit 0
}

VERIFY=0
CLEAN=0
for arg in "$@"; do
    case "$arg" in
        --verify)     VERIFY=1 ;;
        --clean)      CLEAN=1 ;;
        -h|--help)    usage ;;
        *) echo "Unknown arg: $arg (try --help)" >&2; exit 2 ;;
    esac
done

log()  { echo "[restart] $(date +%T) $*"; }
err()  { echo "[restart] $(date +%T) ERROR: $*" >&2; }

# Regex matching agent log lines that indicate a stale trust bundle cache —
# i.e., the agent's cached bundle no longer verifies zt-spire-server's cert.
# Wiping $AGENT_VOLUME forces the agent to re-attest and fetch a fresh bundle.
STALE_BUNDLE_RE='certificate signed by unknown authority|x509svid: could not verify|transport: authentication handshake failed'

wait_agent_healthy() {
    local timeout="$1" status
    for i in $(seq 1 "$timeout"); do
        status=$(docker inspect -f '{{.State.Health.Status}}' user-spire-agent 2>/dev/null || echo "unknown")
        [ "$status" = "healthy" ] && return 0
        sleep 1
    done
    return 1
}

agent_has_stale_bundle() {
    docker logs --tail 200 user-spire-agent 2>&1 | grep -Eq "$STALE_BUNDLE_RE"
}

wipe_agent_cache() {
    log "Wiping volumes: ${AGENT_VOLUME}, ${CERTS_VOLUME}"
    docker compose stop spire-agent >/dev/null
    docker compose rm -f spire-agent user-helper >/dev/null
    # $AGENT_VOLUME is the critical one (agent trust-bundle cache); $CERTS_VOLUME
    # is often mounted by the workload container too, so we best-effort it and
    # warn rather than fail if something else holds it.
    for v in "$AGENT_VOLUME" "$CERTS_VOLUME"; do
        if ! docker volume inspect "$v" >/dev/null 2>&1; then
            log "  (volume $v not present — skipping)"
            continue
        fi
        rm_err=$(docker volume rm "$v" 2>&1 >/dev/null) && { log "  removed $v"; continue; }
        if echo "$rm_err" | grep -q "volume is in use"; then
            holders=$(docker ps --filter "volume=$v" --format '{{.Names}}' | paste -sd, -)
            log "  WARN: $v is in use by [${holders:-unknown}] — leaving intact (helper will rewrite SVID)"
        elif [ "$v" = "$AGENT_VOLUME" ]; then
            err "failed to remove critical volume $v: $rm_err"
            return 1
        else
            log "  WARN: could not remove $v: $rm_err"
        fi
    done
}

# ── Locate project root (contains docker-compose.yml) ─────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
while [ "$PROJECT_DIR" != "/" ] && [ ! -f "$PROJECT_DIR/docker-compose.yml" ]; do
    PROJECT_DIR="$(dirname "$PROJECT_DIR")"
done
if [ ! -f "$PROJECT_DIR/docker-compose.yml" ]; then
    err "docker-compose.yml not found at or above ${SCRIPT_DIR}"
    exit 1
fi
cd "$PROJECT_DIR"

# ── Derive compose project name + volume names dynamically ────────
# Ask compose itself for the effective project name (handles top-level
# `name:` in compose file, COMPOSE_PROJECT_NAME env, and the default
# normalization rules — all of which we would otherwise have to mimic).
COMPOSE_PROJECT="$(docker compose config --format json 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("name",""))' 2>/dev/null || true)"
if [ -z "$COMPOSE_PROJECT" ]; then
    err "unable to determine compose project name via 'docker compose config'"
    exit 1
fi
AGENT_VOLUME="${COMPOSE_PROJECT}_spire-agent-data"
CERTS_VOLUME="${COMPOSE_PROJECT}_user-certs"

CENTRAL_SERVER="${CENTRAL_SERVER:-zt-spire-server}"
SPIFFE_ID="${SPIFFE_ID:-spiffe://zt.local/user-service}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-30}"
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-30}"
USER_AGENT_CERT="${PROJECT_DIR}/spiffe/certs/user-agent.crt.pem"

log "Project dir:    ${PROJECT_DIR}"
log "Compose proj:   ${COMPOSE_PROJECT}"
log "Central server: ${CENTRAL_SERVER}"

# ── Pre-flight checks ─────────────────────────────────────────────
if ! docker info >/dev/null 2>&1; then
    err "docker daemon not reachable"; exit 1
fi
if ! docker ps --filter "name=^${CENTRAL_SERVER}$" --filter "status=running" \
        --format '{{.Names}}' | grep -q "^${CENTRAL_SERVER}$"; then
    err "central server container '${CENTRAL_SERVER}' is not running"
    err "start it first (the other compose project managing zt-spire-server)"
    exit 1
fi

# ── 1. Stop helper first (so it doesn't spam errors while agent is down) ──
log "Stopping user-helper..."
docker compose stop user-helper >/dev/null

# ── 2. Optional: wipe agent cache up front (--clean) ──────────────
if [ "$CLEAN" = "1" ]; then
    wipe_agent_cache || exit 1
fi

# ── 3. Restart spire-agent (wait for healthy, auto-recover stale bundle) ──
log "Restarting user-spire-agent..."
docker compose up -d --force-recreate spire-agent >/dev/null

log "Waiting for spire-agent to be healthy (timeout=${HEALTH_TIMEOUT}s)..."
if wait_agent_healthy "$HEALTH_TIMEOUT"; then
    log "spire-agent is healthy."
elif [ "$CLEAN" = "0" ] && agent_has_stale_bundle; then
    log "Detected stale trust bundle (zt-spire-server CA likely rotated) — auto-recovering..."
    wipe_agent_cache || exit 1
    log "Restarting user-spire-agent with fresh cache..."
    docker compose up -d --force-recreate spire-agent >/dev/null
    if wait_agent_healthy "$HEALTH_TIMEOUT"; then
        log "spire-agent is healthy after cache wipe."
    else
        err "spire-agent still not healthy after cache wipe."
        docker logs --tail 30 user-spire-agent || true
        exit 1
    fi
else
    err "spire-agent did not become healthy within ${HEALTH_TIMEOUT}s"
    docker logs --tail 30 user-spire-agent || true
    exit 1
fi

# ── 3.5 Ensure workload entry points at OUR agent ─────────────────
if [ ! -f "$USER_AGENT_CERT" ]; then
    err "agent cert not found: $USER_AGENT_CERT — cannot reconcile entry"
    exit 1
fi

FP=$(openssl x509 -in "$USER_AGENT_CERT" -noout -fingerprint -sha1 2>/dev/null \
    | awk -F= '{print $2}' | tr -d ':' | tr 'A-Z' 'a-z')
if [ -z "$FP" ]; then
    err "failed to compute SHA1 fingerprint of $USER_AGENT_CERT"
    exit 1
fi
OUR_AGENT_ID="spiffe://zt.local/spire/agent/x509pop/${FP}"
log "Ensuring entry ${SPIFFE_ID} → ${OUR_AGENT_ID}"

# Delete any entries with wrong parent
while read -r eid parent; do
    if [ -n "$eid" ] && [ "$parent" != "$OUR_AGENT_ID" ]; then
        log "  deleting stale entry $eid (parent=$parent)"
        docker exec "$CENTRAL_SERVER" /opt/spire/bin/spire-server entry delete \
            -entryID "$eid" >/dev/null 2>&1 || true
    fi
done < <(docker exec "$CENTRAL_SERVER" /opt/spire/bin/spire-server entry show \
            -spiffeID "$SPIFFE_ID" 2>/dev/null \
            | awk '/^Entry ID/{e=$4} /^Parent ID/{print e, $4}')

# Create if missing
if ! docker exec "$CENTRAL_SERVER" /opt/spire/bin/spire-server entry show \
        -spiffeID "$SPIFFE_ID" 2>/dev/null | grep -q "$OUR_AGENT_ID"; then
    log "  creating entry"
    docker exec "$CENTRAL_SERVER" /opt/spire/bin/spire-server entry create \
        -parentID "$OUR_AGENT_ID" -spiffeID "$SPIFFE_ID" \
        -selector "unix:uid:0" -x509SVIDTTL 3600 >/dev/null
fi

# ── 4. Start helper ───────────────────────────────────────────────
log "Starting user-helper..."
docker compose up -d --force-recreate user-helper >/dev/null

# ── 5. Optional verification ──────────────────────────────────────
if [ "$VERIFY" = "1" ]; then
    log "Verifying SVID delivery (timeout=${VERIFY_TIMEOUT}s)..."
    for i in $(seq 1 "$VERIFY_TIMEOUT"); do
        if docker logs user-helper 2>&1 | grep -q "X.509 certificates updated"; then
            log "SUCCESS: helper received SVID."
            docker logs --tail 3 user-helper
            exit 0
        fi
        sleep 1
    done
    err "SVID not delivered after ${VERIFY_TIMEOUT}s. Recent helper logs:"
    docker logs --tail 20 user-helper
    exit 1
fi

log "Done."
