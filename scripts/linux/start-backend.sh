#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKEND="$ROOT/backend/ntk-production-v2"
CONFIG="$BACKEND/config/ntk_backend.env"
[[ -f "$CONFIG" ]] || { echo "Thieu config/ntk_backend.env. Hay chay configure-backend.ps1." >&2; exit 2; }
# Tep config chi duoc tao tai may nguoi dung, khong nam trong Git.
# shellcheck disable=SC1090
set -a
source "$CONFIG"
set +a
: "${NTK_BASE_MODEL_PATH:?Can cau hinh model goc}"
: "${NTK_BEST_ADAPTER_PATH:?Can cau hinh adapter LoRA}"
[[ -s "$NTK_BASE_MODEL_PATH/config.json" ]] || { echo "Khong tim thay config.json cua model goc." >&2; exit 2; }
[[ -s "$NTK_BEST_ADAPTER_PATH/adapter_config.json" ]] || { echo "Khong tim thay adapter_config.json." >&2; exit 2; }
if [[ ! -s "$NTK_BEST_ADAPTER_PATH/adapter_model.safetensors" && ! -s "$NTK_BEST_ADAPTER_PATH/adapter_model.bin" ]]; then
  echo "Khong tim thay adapter weights." >&2
  exit 2
fi
if [[ -n "${NTK_DATASET_DIR:-}" ]]; then
  for name in 01_TRAIN_VNEXT_3_1_TRACK_A_TRUSTED_GOLD_PILOT.jsonl 01_TRAIN_VNEXT_3_1_TRACK_B_AUDITED_FULL.jsonl 02_DEV_VNEXT_3_1.jsonl track_b_quarantine_review_queue.jsonl; do
    [[ -s "$NTK_DATASET_DIR/$name" ]] || { echo "Thieu dataset: $name" >&2; exit 2; }
  done
else
  echo "Luu y: chua cau hinh dataset, trang Du lieu nghien cu se khong co du lieu goc."
fi
PYTHON_BIN="${PYTHON_BIN:-$HOME/.venvs/he-thong-do-an/bin/python}"
[[ -x "$PYTHON_BIN" ]] || { echo "Thieu Python venv: $PYTHON_BIN. Hay chay setup-runtime.sh." >&2; exit 2; }
command -v git >/dev/null
command -v javac >/dev/null
command -v curl >/dev/null
OPEN_BIN="${NTK_OPENGREP_BIN:-/usr/local/bin/opengrep}"
if [[ ! -x "$OPEN_BIN" ]]; then
  OPEN_BIN="$(command -v opengrep || true)"
fi
[[ -n "$OPEN_BIN" && -x "$OPEN_BIN" ]] || { echo "Chua cai OpenGrep." >&2; exit 2; }
export NTK_OPENGREP_BIN="$OPEN_BIN"
PORT="${NTK_BACKEND_PORT:-8765}"
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT >= 1 && PORT <= 65535)) || { echo "Port khong hop le." >&2; exit 2; }
export NTK_STORAGE_DIR="${NTK_STORAGE_DIR:-$HOME/.local/share/he-thong-do-an/scans}"
export NTK_EXT4_CACHE_DIR="${NTK_EXT4_CACHE_DIR:-$HOME/.cache/he-thong-do-an}"
mkdir -p "$NTK_STORAGE_DIR" "$NTK_EXT4_CACHE_DIR"
if [[ "$NTK_STORAGE_DIR" == /mnt/* ]]; then
  echo "Canh bao: nen dat storage va SQLite tren ext4 de tranh cham tai buoc luu ket qua." >&2
fi
URL="http://127.0.0.1:$PORT/api/health"
if curl --fail --silent --show-error --max-time 3 "$URL" 2>/dev/null | grep -q '"ntk-iris-local-sast-backend"'; then
  echo "Backend da hoat dong tai http://127.0.0.1:$PORT"
  exit 0
fi
PIDFILE="$NTK_EXT4_CACHE_DIR/backend-$PORT.pid"
LOGFILE="$NTK_STORAGE_DIR/backend-$PORT.log"
if [[ -f "$PIDFILE" ]]; then
  oldpid="$(cat "$PIDFILE")"
  if [[ "$oldpid" =~ ^[0-9]+$ ]] && kill -0 "$oldpid" 2>/dev/null; then
    echo "Da co tien trinh tu lan truoc. Kiem tra log: $LOGFILE" >&2
    exit 3
  fi
  rm -f "$PIDFILE"
fi
nohup "$PYTHON_BIN" -u "$BACKEND/scripts/ntk_web_backend_service.py" --serve-http --port "$PORT" >>"$LOGFILE" 2>&1 </dev/null &
pid=$!
printf '%s\n' "$pid" > "$PIDFILE"
for ((i=0; i<60; i++)); do
  if curl --fail --silent --max-time 2 "$URL" 2>/dev/null | grep -q '"ntk-iris-local-sast-backend"'; then
    echo "Backend san sang tai http://127.0.0.1:$PORT (PID $pid)"
    exit 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  sleep 1
done
echo "Backend chua san sang. Xem 30 dong log cuoi:" >&2
tail -n 30 "$LOGFILE" >&2 || true
exit 1
