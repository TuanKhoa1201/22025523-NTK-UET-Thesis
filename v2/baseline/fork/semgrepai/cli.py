"""M1 scanner-only CLI. Never initializes upstream cloud validators or RAG."""
import argparse
import json
import sys
from pathlib import Path
from .config import OpenGrepConfig, DEFAULT_RULES
from .scanner import SemgrepScanner, ScanError


def main():
    parser = argparse.ArgumentParser(description="NTK M1 local OpenGrep scanner")
    parser.add_argument("target", type=Path)
    parser.add_argument("--rules-path", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--executable", default="opengrep")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args()
    try:
        config = OpenGrepConfig(args.executable, args.rules_path, args.timeout, args.jobs)
        scanner = SemgrepScanner(config, args.output_dir)
        results = scanner.scan(args.target)
        findings = scanner._process_results(results)
        (args.output_dir / "findings.json").write_text(
            json.dumps({"status": "REVIEW", "engine_version": results["engine_version"],
                        "findings": findings}, indent=2), encoding="utf-8")
        print(f"OpenGrep {results['engine_version']}: {len(findings)} findings; human REVIEW required")
        return 0
    except (ScanError, ValueError, OSError) as exc:
        print(f"REVIEW/UNDETERMINED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
