#!/bin/sh
set -e

APP_DIR="/app"
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

def safe_join(base, rel):
    if rel.startswith("/") or ".." in rel.split("/"):
        return None
    return os.path.join(base, rel)

def write_file(rel, content_b64):
    target = safe_join(target_dir, rel)
    if not target:
        print(f"[unpack] skip unsafe path: {rel}")
        return
    os.makedirs(os.path.dirname(target) or target_dir, exist_ok=True)
    if os.path.exists(target):
        bak = f"{target}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
        os.rename(target, bak)
    try:
        data = base64.b64decode(content_b64)
    except Exception as e:
        print(f"[unpack] decode content failed {rel}: {e}")
        return
    with open(target, "wb") as f:
        f.write(data)
    print(f"[unpack] restore {rel} ({len(data)} bytes)")

try:
    parsed = json.loads(raw.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError):
    parsed = None

if isinstance(parsed, dict) and "files" in parsed:
    for item in parsed["files"]:
        write_file(item.get("path", ""), item.get("content", ""))
elif isinstance(parsed, list):
    for item in parsed:
        if isinstance(item, dict):
            write_file(item.get("path", ""), item.get("content", ""))
else:
    target = os.path.join(target_dir, ".env")
    if os.path.exists(target):
        bak = f"{target}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
        os.rename(target, bak)
    with open(target, "wb") as f:
        f.write(raw)
    print(f"[unpack] restore .env ({len(raw)} bytes)")
PYEOF

    unset ENV_SECRET
fi

if [ ! -f "$APP_DIR/.env" ]; then
    exit 1
fi

exec "$@"
