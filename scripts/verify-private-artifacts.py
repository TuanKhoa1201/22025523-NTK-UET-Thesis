#!/usr/bin/env python3
"""Verify offline private dataset checksums without printing their contents."""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path

FILES = {
    "01_TRAIN_VNEXT_3_1_TRACK_A_TRUSTED_GOLD_PILOT.jsonl": (275, "d179fa063b6a0bb0a8e5080aa0391564a71d22e4a816aa33ecff5fe9a6a423eb"),
    "01_TRAIN_VNEXT_3_1_TRACK_B_AUDITED_FULL.jsonl": (781, "2bb70c53ee12cc9e677895488479a58ef1ffbfd4b25d9d5055d6db5d7df8899f"),
    "02_DEV_VNEXT_3_1.jsonl": (166, "dfafd66d66957cf83b0f105ef0c98c63db62ff41456a822ea59f02a53801622d"),
    "track_b_quarantine_review_queue.jsonl": (137, "f6ec8d347d60ea70259dc5d8e446c33ba9b4eb3c280066b6d6a806d909bc3005"),
}
ADAPTER_SHA256 = "176b9b32ada029ba38a561b0937ccb75cb18c720979dbb58824fdcc112d2ce84"

def checksum(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def verify_dataset(root: Path) -> bool:
    ok = True
    for name, (rows, expected_sha) in FILES.items():
        path = root / name
        if not path.is_file():
            print(f"MISSING {name}")
            ok = False
            continue
        sha = checksum(path)
        with path.open("rb") as f:
            count = sum(bool(line.strip()) for line in f)
        good = sha == expected_sha and count == rows
        print(f"{'PASS' if good else 'FAIL'} {name}: rows={count}, SHA256={'OK' if sha == expected_sha else 'MISMATCH'}")
        ok = good and ok
    return ok

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-dir", type=Path, required=True)
    parser.add_argument("--adapter-dir", type=Path)
    args = parser.parse_args()
    ok = verify_dataset(args.dataset_dir)
    if args.adapter_dir:
        weights = args.adapter_dir / "adapter_model.safetensors"
        cfg = args.adapter_dir / "adapter_config.json"
        if not weights.is_file() or not cfg.is_file():
            print("FAIL adapter: thieu config hoac weights")
            ok = False
        else:
            sha = checksum(weights)
            passed = sha == ADAPTER_SHA256
            print(f"{'PASS' if passed else 'FAIL'} adapter SHA256")
            ok = passed and ok
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
