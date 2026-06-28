#!/bin/sh
set -e

APP_DIR="${1:-/app}"
cd "$APP_DIR"

if [ -n "$ENV_SECRET" ]; then
    if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
        echo "[entrypoint] 需要 python" >&2
        exit 1
    fi
    PYTHON=$(command -v python3 || command -v python)

    "$PYTHON" - "$APP_DIR" <<'PYEOF'
import base64, json, os, sys, zlib
from datetime import datetime

target_dir = sys.argv[1]
secret = os.environ.get("ENV_SECRET", "")
if not secret:
    sys.exit(0)

try:
    raw = zlib.decompress(base64.b64decode(secret))
except Exception as e:
    print(f"[unpack] decode failed: {e}")
    sys.exit(1)

if raw.startswith(b"["):
    try:
        bundle = json.loads(raw)
    except Exception as e:
        print(f"[unpack] json failed: {e}")
        sys.exit(1)
    for item in bundle:
        rel = item.get("path", "")
        content_b64 = item.get("content", "")
        if rel.startswith("/") or ".." in rel.split("/"):
            continue
        target = os.path.join(target_dir, rel)
        os.makedirs(os.path.dirname(target) or target_dir, exist_ok=True)
        if os.path.exists(target):
            bak = f"{target}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
            os.rename(target, bak)
        with open(target, "wb") as f:
            f.write(base64.b64decode(content_b64))
else:
    target = os.path.join(target_dir, ".env")
    if os.path.exists(target):
        bak = f"{target}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
        os.rename(target, bak)
    with open(target, "wb") as f:
        f.write(raw)
PYEOF

    unset ENV_SECRET
fi

if [ ! -f "$APP_DIR/.env" ]; then
    exit 1
fi

exec "$@"
