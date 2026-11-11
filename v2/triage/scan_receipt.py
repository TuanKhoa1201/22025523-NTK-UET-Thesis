"""Check captured scan integrity; declared exit codes are not recorded process evidence."""
import json
from pathlib import Path
from .evidence import EvidenceError, SourceTree, digest, strict_json


def verify_receipt(manifest_path, raw, root, declared_exit=None):
    metadata = {"origin": "declared_only", "declared_engine_exit": declared_exit,
                "recorded_engine_exit": None, "source_capture_verified": False,
                "exit_capture_verified": False,
                "independently_attested": False, "manifest_sha256": None}
    issues = []
    if manifest_path is None:
        return metadata, ["scan-time source/exit manifest unavailable; declaration alone is insufficient"]
    try:
        manifest_path = Path(manifest_path).resolve(strict=True)
        metadata["manifest_path"] = str(manifest_path)
        encoded = manifest_path.read_bytes()
        metadata["manifest_sha256"] = digest(encoded)
        document = strict_json(encoded.decode("utf-8"))
        if not isinstance(document, dict) or document.get("schema") != "ntk-scan-capture-1":
            raise EvidenceError("unsupported scan manifest schema")
        directory = manifest_path.parent
        def artifact(name):
            if not isinstance(name, str) or Path(name).name != name or "/" in name or "\\" in name or ":" in name or name in (".", ".."):
                raise EvidenceError("unsafe manifest artifact path")
            p = (directory / name).resolve(strict=True)
            if not p.is_relative_to(directory) or not p.is_file():
                raise EvidenceError("manifest artifact escapes capture directory")
            data = p.read_bytes()
            if digest(data) != document["artifacts"].get(name):
                raise EvidenceError("capture artifact hash mismatch: " + name)
            return data
        if not isinstance(document.get("artifacts"), dict):
            raise EvidenceError("missing capture artifacts")
        for name in document["artifacts"]:
            artifact(name)
        if artifact("opengrep.json") != raw:
            raise EvidenceError("raw JSON differs from captured process stdout")
        failures = []
        for label in ("version", "json", "sarif"):
            run = document["runs"][label]
            if not isinstance(run, dict) or not isinstance(run.get("argv"), list) or not all(isinstance(x, str) for x in run["argv"]):
                raise EvidenceError("invalid recorded process argv")
            recorded = run["exit_code"]
            if type(recorded) is not int or recorded != int(artifact(label + ".exit.txt")):
                raise EvidenceError("recorded process exit mismatch: " + label)
            if strict_json(artifact(label + ".command.json").decode("utf-8")) != run["argv"]:
                raise EvidenceError("recorded process command mismatch: " + label)
            if label in ("json", "sarif"):
                mode = run.get("output_mode", "stdout")
                if mode == "stdout":
                    if artifact(label + ".stdout.txt") != artifact("opengrep." + label):
                        raise EvidenceError("raw output differs from recorded stdout: " + label)
                elif mode == "file":
                    argv = run["argv"]
                    if (argv.count("--output") != 1 or argv.index("--output") + 1 >= len(argv) or "--" + label not in argv or
                            argv[argv.index("--output") + 1] != run.get("engine_output_path")):
                        raise EvidenceError("invalid file-output engine capture")
                else:
                    raise EvidenceError("unsupported capture output mode")
            if recorded != 0:
                failures.append(label)
        metadata["recorded_engine_exit"] = document["runs"]["json"]["exit_code"]
        metadata.update(exit_capture_verified=True, origin="recorded_capture_unsigned")
        if failures:
            raise EvidenceError("recorded engine failure: " + ", ".join(failures))
        if declared_exit is not None and (type(declared_exit) is not int or declared_exit != metadata["recorded_engine_exit"]):
            raise EvidenceError("declared exit contradicts recorded engine exit")
        if document.get("success") is not True or document.get("issues"):
            raise EvidenceError("capture failed or inputs changed during scan")
        if (document["sources_before"] != document["sources_after"] or
                document["rules_before_sha256"] != document["rules_after_sha256"] or
                digest(artifact("rules.snapshot.yml")) != document["rules_before_sha256"]):
            raise EvidenceError("source/rules changed during scan")
        tree = SourceTree(root)
        before = document["sources_before"]
        if not isinstance(before, dict):
            raise EvidenceError("invalid captured source inventory")
        for path, expected in before.items():
            # Manifest source keys are canonical relative paths, not remapped absolute paths.
            if not isinstance(path, str) or path.startswith("/") or "\\" in path or ":" in path or ".." in path.split("/"):
                raise EvidenceError("unsafe captured source key")
            relative, data, _ = tree.read(path)
            if relative != path or digest(data) != expected:
                raise EvidenceError("current source differs from scan-time hash: " + path)
        if document["target_kind"] == "directory":
            current = {tree.resolve(str(p)).relative_to(tree.root).as_posix() for p in tree.root.rglob("*.java")}
            if current != set(before):
                raise EvidenceError("source inventory differs from captured scan")
        elif document["target_kind"] != "file" or len(before) != 1:
            raise EvidenceError("invalid captured target kind")
        sarif = strict_json(artifact("opengrep.sarif").decode("utf-8"))
        if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
            raise EvidenceError("invalid captured SARIF")
        metadata.update(origin="recorded_capture_unsigned", source_capture_verified=True,
                        source_hashes=before, producer=document.get("producer"))
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RuntimeError) as exc:
        issues.append("scan receipt invalid: " + str(exc))
    return metadata, issues
