#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV="${1:-$HOME/.venvs/he-thong-do-an}"
command -v python3 >/dev/null || { echo "Thieu python3." >&2; exit 2; }
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -r "$ROOT/backend/ntk-production-v2/environment/requirements.txt"
echo "Da cai dat Python tai: $VENV"
echo "Kiem tra cau hinh CUDA/GPU rieng neu su dung GPU."
