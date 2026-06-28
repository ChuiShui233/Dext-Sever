#!/bin/sh
set -e

APP_DIR="/app"
cd "$APP_DIR"

if [ -n "$ENV_SECRET" ]; then
    echo "[entrypoint] 检测到 ENV_SECRET, 开始还原敏感文件..."
    if python3 /app/env_secret.py unpack "$APP_DIR" "$ENV_SECRET"; then
        echo "[entrypoint] 敏感文件还原完成"
        unset ENV_SECRET
    else
        echo "[entrypoint] 警告: ENV_SECRET 解包失败" >&2
        exit 1
    fi
fi

if [ ! -f "$APP_DIR/.env" ]; then
    echo "[entrypoint] 错误: 未找到 .env 文件, 请通过 ENV_SECRET 或 volume 提供" >&2
    exit 1
fi

echo "[entrypoint] 启动 Dext-Server..."
exec "$@"
