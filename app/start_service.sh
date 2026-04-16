#!/bin/bash

# ── Wait for SPIFFE certs (written by spiffe-helper) ────────────
CERTS_DIR="${SPIFFE_SHM_DIR:-/certs}"
MAX_WAIT=120
ELAPSED=0

echo "[start_service] Waiting for SPIFFE certs in ${CERTS_DIR} ..."
while [ ! -f "${CERTS_DIR}/svid_key.pem" ] || [ ! -f "${CERTS_DIR}/svid.pem" ] || [ ! -f "${CERTS_DIR}/bundle.pem" ]; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ "$ELAPSED" -ge "$MAX_WAIT" ]; then
        echo "[start_service] WARNING: Certs not found after ${MAX_WAIT}s — starting without mTLS"
        break
    fi
    echo "[start_service] Waiting... (${ELAPSED}s / ${MAX_WAIT}s)"
done

# ── Choose RoadRunner config based on cert availability ─────────
if [ -f "${CERTS_DIR}/svid_key.pem" ] && [ -f "${CERTS_DIR}/svid.pem" ] && [ -f "${CERTS_DIR}/bundle.pem" ]; then
    echo "[start_service] Certs ready — using mTLS config"
else
    echo "[start_service] Certs missing — switching to HTTP-only config"
    cp .rr-no-ssl.yaml .rr.yaml
fi

# ── Install dependencies ────────────────────────────────────────
if [ ! -d "./vendor" ]; then
    composer install
fi

if [ ! -f "./vendor/bin/rr_server" ]; then
    php spark burner:init RoadRunner
fi

# ── Start RoadRunner with retry ─────────────────────────────────
MAX_RETRIES=3
RETRY_DELAY=5
EXIT_CODE=1

for attempt in $(seq 1 "$MAX_RETRIES"); do
    echo "[start_service] Starting RoadRunner (attempt ${attempt}/${MAX_RETRIES})..."
    php spark burner:start
    EXIT_CODE=$?
    if [ "$EXIT_CODE" -eq 0 ]; then
        break
    fi
    echo "[start_service] RoadRunner exited with code ${EXIT_CODE}"
    if [ "$attempt" -lt "$MAX_RETRIES" ]; then
        echo "[start_service] Retrying in ${RETRY_DELAY}s..."
        sleep "$RETRY_DELAY"
    fi
done

exit "${EXIT_CODE}"
