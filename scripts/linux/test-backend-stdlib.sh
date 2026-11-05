#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$ROOT/backend/ntk-production-v2/scripts${PYTHONPATH:+:$PYTHONPATH}"
python3 -m unittest discover -s "$ROOT/backend/ntk-production-v2/tests" -p 'test_ntk_cwss_v101.py' -v
python3 -m unittest discover -s "$ROOT/backend/ntk-production-v2/tests" -p 'test_scan_aggregates.py' -v
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
javac --release 17 -d "$tmp" "$ROOT/backend/ntk-production-v2/scripts/javac_ast_bridge/NtkJavacAstExtractor.java"
echo "Kiem tra cong thuc, tong hop va bien dich Java AST: PASS"
