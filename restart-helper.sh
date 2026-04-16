#!/usr/bin/env bash
# 一鍵恢復：spire-server 異常或重啟後，spire-agent 的 attestation 會失效，
# 連帶 user-helper 拿不到 SVID 也會卡住，需要把 agent 與 helper 一起 recreate。
set -euo pipefail

cd "$(dirname "$0")"

echo "[1/4] 強制重建 spire-agent（重新向 spire-server attest）..."
docker compose up -d --force-recreate spire-agent

echo "[2/4] 等待 spire-agent healthy..."
status="unknown"
for i in $(seq 1 30); do
    status=$(docker inspect -f '{{.State.Health.Status}}' user-spire-agent 2>/dev/null || echo "missing")
    if [ "$status" = "healthy" ]; then
        echo "  spire-agent OK"
        break
    fi
    echo "  ($i/30) 目前狀態: $status"
    sleep 2
done
if [ "$status" != "healthy" ]; then
    echo "  WARN: spire-agent 未在預期時間內 healthy，仍嘗試繼續"
fi

echo "[3/4] 移除舊的 user-helper 容器（避免卡在舊 PID namespace）..."
docker compose rm -sf user-helper

echo "[4/4] 重新建立 user-helper..."
docker compose up -d user-helper

sleep 2
echo ""
echo "===== 容器狀態 ====="
docker ps -a \
    --filter "name=user-spire-agent" \
    --filter "name=user-helper" \
    --format "table {{.Names}}\t{{.Status}}"
echo ""
echo "===== user-helper 最近 log ====="
docker logs --tail 10 user-helper
