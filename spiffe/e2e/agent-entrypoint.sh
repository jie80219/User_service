#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
#  SPIRE Agent entrypoint for E2E testing.
#
#  Waits for the join token to appear in the shared volume, then
#  starts the agent with that token.
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

MAX_WAIT=120

echo "[agent-entrypoint] Waiting for join token..."
elapsed=0
while [ ! -f /opt/spire/conf/shared/join-token ]; do
    sleep 1
    elapsed=$((elapsed + 1))
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        echo "[agent-entrypoint] ERROR: join token not found after ${MAX_WAIT}s"
        exit 1
    fi
done

JOIN_TOKEN=$(cat /opt/spire/conf/shared/join-token)
echo "[agent-entrypoint] Got join token, starting agent..."

exec /opt/spire/bin/spire-agent run \
    -config /opt/spire/conf/agent/agent.conf \
    -joinToken "${JOIN_TOKEN}"
