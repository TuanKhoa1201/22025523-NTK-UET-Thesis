#!/usr/bin/env bash
# Safe checkout only: no package installs, no model pulls and no legacy workspace changes.
set -euo pipefail
repo_url="https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis.git"
base="${NTK_V2_SERVER_ROOT:-$HOME/ntk-thesis-v2}"
mkdir -p "$base/incoming" "$base/evidence"
if [ ! -e "$base/javis/.git" ]; then
  if [ -e "$base/javis" ]; then
    echo "Refusing to overwrite existing non-Git directory: $base/javis" >&2
    exit 1
  fi
  git clone --branch thesis-v2/opengrep-qwen "$repo_url" "$base/javis"
fi
cd "$base/javis"
branch="$(git branch --show-current)"
if [ "$branch" != "v2/javis-benchmark" ]; then
  if git show-ref --verify --quiet refs/heads/v2/javis-benchmark; then
    git switch v2/javis-benchmark
  else
    git switch -c v2/javis-benchmark
  fi
fi
printf 'SERVER REPO: %s\nBRANCH: %s\nEVIDENCE: %s\n' "$PWD" "$(git branch --show-current)" "$base/evidence"
git status --short
