#!/usr/bin/env bash
set -euo pipefail
echo "Kiem tra cong cu trong WSL"
missing=0
for cmd in python3 git javac java curl; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "$cmd: OK"
  else
    echo "$cmd: CHUA CAI"
    missing=1
  fi
done
if command -v opengrep >/dev/null 2>&1 || [[ -x "/usr/local/bin/opengrep" ]]; then
  echo "OpenGrep: OK"
else
  echo "OpenGrep: CHUA CAI. Can cong cu OpenGrep nguon mo."
  missing=1
fi
java -version 2>&1 | head -n 1 || true
exit "$missing"
