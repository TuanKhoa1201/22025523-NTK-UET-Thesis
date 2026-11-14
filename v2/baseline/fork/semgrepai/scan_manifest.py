"""Portable, unsigned scan receipt: bind source/rules, raw output and recorded exits."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "ntk-scan-capture-1"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def inventory(target):
    target = Path(target).resolve(strict=True)
    root = target.parent if target.is_file() else target
    paths = [target] if target.is_file() else sorted(root.rglob("*.java"))
    found = {}
    for path in paths:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root) or resolved.suffix.lower() != ".java" or not resolved.is_file():
            raise ValueError("unsafe/non-Java scan source")
        found[resolved.relative_to(root).as_posix()] = sha(resolved.read_bytes())
    return found


class ScanCapture:
    def __init__(self, target, rules, output, producer="ntk-local-scan-capture"):
        self.target, self.rules, self.output = Path(target).resolve(), Path(rules).resolve(), Path(output).resolve()
        self.root = self.target.parent if self.target.is_file() else self.target
        self.started = timestamp()
        self.producer = producer
        self.before = inventory(self.target)
        self.rule_bytes = self.rules.read_bytes()
        self.runs = {}
        (self.output / "rules.snapshot.yml").write_bytes(self.rule_bytes)

    def finish(self, success):
        issues = []
        try:
            after = inventory(self.target)
            rule_after = sha(self.rules.read_bytes())
            if self.before != after or rule_after != sha(self.rule_bytes):
                issues.append("source inventory or rules changed during scan")
        except (OSError, ValueError) as exc:
            after, rule_after = None, None
            issues.append("cannot recheck scan inputs: " + str(exc))
        artifacts = {}
        for file in self.output.iterdir():
            if file.is_file() and file.name != "scan-manifest.json" and file.suffix in (".txt", ".json", ".sarif", ".yml") and file.name != "settings.yml":
                artifacts[file.name] = sha(file.read_bytes())
        document = {"schema": SCHEMA, "producer": self.producer, "started_at": self.started,
                    "finished_at": timestamp(), "source_root": str(self.root),
                    "target_kind": "file" if self.target.is_file() else "directory",
                    "sources_before": self.before, "sources_after": after,
                    "rules_before_sha256": sha(self.rule_bytes), "rules_after_sha256": rule_after,
                    "runs": self.runs, "artifacts": artifacts, "issues": issues,
                    "success": bool(success and not issues), "signed_or_independently_attested": False}
        (self.output / "scan-manifest.json").write_text(json.dumps(document, indent=2), encoding="utf-8")
        return document
