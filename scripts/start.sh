#!/usr/bin/env sh
# Run migrations then start the API (Render-friendly: uses PORT from env).
set -e
cd "$(dirname "$0")/.."
if [ -n "$DATABASE_URL" ] && echo "$DATABASE_URL" | grep -q '^postgresql'; then
  echo "[start] Running migrations..."
  alembic upgrade head
fi
echo "[start] Starting uvicorn on port ${PORT:-8000}..."
exec uvicorn api.main:app --host 0.0.0.0 --port "${PORT:-8000}"
