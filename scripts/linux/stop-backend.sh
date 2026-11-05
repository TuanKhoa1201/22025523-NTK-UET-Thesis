#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="$ROOT/backend/ntk-production-v2/config/ntk_backend.env"
[[ -f "$CONFIG" ]] || { echo "Chua co cau hinh cuc bo." >&2; exit 2; }
# shellcheck disable=SC1090
source "$CONFIG"
PORT="${1:-${NTK_BACKEND_PORT:-8765}}"
CACHE="${NTK_EXT4_CACHE_DIR:-$HOME/.cache/he-thong-do-an}"
PIDFILE="$CACHE/backend-$PORT.pid"
[[ -f "$PIDFILE" ]] || { echo "Khong co PID do script quan ly. Khong tu y dung tien trinh khac."; exit 0; }
pid="$(cat "$PIDFILE")"
[[ "$pid" =~ ^[0-9]+$ ]] || { echo "Tep PID khong hop le." >&2; exit 2; }
if ! kill -0 "$pid" 2>/dev/null; then
  rm -f "$PIDFILE"
  echo "Backend khong con chay. Da don PID cu."
  exit 0
fi
argv="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
case "$argv" in
  *"ntk_web_backend_service.py"*"--serve-http"*"--port $PORT"*) ;;
  *) echo "PID khong khop backend va port mong doi. Khong dung tien trinh." >&2; exit 3 ;;
esac
kill -TERM "$pid"
for ((i=0; i<15; i++)); do
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  sleep 1
done
if kill -0 "$pid" 2>/dev/null; then
  echo "Tien trinh chua dung han. Khong tu dong kill -9." >&2
  exit 3
fi
rm -f "$PIDFILE"
echo "Da tat backend cua he thong do an (PID $pid)."
