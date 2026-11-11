"""Collect source-grounded evidence without trusting paths or code in engine JSON."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


class EvidenceError(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise EvidenceError("duplicate JSON key: " + key)
            result[key] = value
        return result
    try:
        return json.loads(text, object_pairs_hook=pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(EvidenceError("nonfinite JSON")))
    except (ValueError, TypeError, RecursionError) as exc:
        raise EvidenceError("invalid JSON: " + str(exc)) from exc


class SourceTree:
    def __init__(self, root, path_base=None):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise EvidenceError("source root must be a directory")
        self.path_base = Path(path_base).resolve() if path_base else self.root

    def resolve(self, raw):
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise EvidenceError("invalid source path")
        path = Path(raw)
        if not path.is_absolute():
            path = self.path_base / path
        path = path.resolve(strict=True)
        if not path.is_relative_to(self.root) or path.suffix.lower() != ".java":
            raise EvidenceError("source path outside configured root or not Java")
        if not path.is_file():
            raise EvidenceError("source is not a regular file")
        return path

    def read(self, raw):
        path = self.resolve(raw)
        if path.stat().st_size > 1_000_000:
            raise EvidenceError("source exceeds 1 MB evidence limit")
        with path.open("rb") as handle:
            data = handle.read(1_000_001)
        if len(data) > 1_000_000 or self.resolve(raw) != path:
            raise EvidenceError("source changed while reading")
        text = data.decode("utf-8")
        return path.relative_to(self.root).as_posix(), data, text


def location_evidence(tree, loc, role, snapshots, expected=None):
    if not isinstance(loc, dict):
        raise EvidenceError("invalid location")
    relative, data, text = tree.read(loc.get("path"))
    sha = digest(data)
    if relative in snapshots and snapshots[relative]["sha256"] != sha:
        raise EvidenceError("source changed during collection")
    snapshots[relative] = {"sha256": sha, "size": len(data)}
    start, end = loc.get("start"), loc.get("end")
    if not isinstance(start, dict) or not isinstance(end, dict):
        raise EvidenceError("missing start/end location")
    for point in (start, end):
        if any(type(point.get(k)) is not int or point[k] < 1 for k in ("line", "col")):
            raise EvidenceError("invalid line/column")
    lines = text.splitlines(keepends=True)
    sl, el = start["line"], end["line"]
    if not 1 <= sl <= el <= len(lines):
        raise EvidenceError("line out of range")
    # OpenGrep columns/offsets are byte coordinates. Preserve CRLF and UTF-8.
    def offset(point):
        line = lines[point["line"] - 1].rstrip("\r\n").encode("utf-8")
        col = point["col"] - 1
        if col > len(line):
            raise EvidenceError("column out of range")
        return sum(len(x.encode("utf-8")) for x in lines[:point["line"] - 1]) + col
    begin, finish = offset(start), offset(end)
    if finish <= begin:
        raise EvidenceError("empty or reversed source range")
    for point, computed in ((start, begin), (end, finish)):
        if "offset" in point and (type(point["offset"]) is not int or point["offset"] != computed):
            raise EvidenceError("byte offset disagrees with line/column")
    matched = data[begin:finish].decode("utf-8")
    if expected is not None and (not isinstance(expected, str) or matched != expected):
        raise EvidenceError("engine trace content does not match source")
    lower, upper = max(1, sl - 3), min(len(lines), el + 3)
    if upper - lower > 150:
        raise EvidenceError("source span exceeds evidence limit")
    return {"role": role, "path": relative, "start": start, "end": end,
            "sha256": sha, "matched": matched,
            "lines": [{"line": i, "text": lines[i-1].rstrip("\r\n")}
                      for i in range(lower, upper + 1)]}


def collect(raw_json, root, path_base=None, engine_exit=None, scan_issues=()):
    """Keep even malformed/partial findings; issues force UNDETERMINED downstream."""
    tree = SourceTree(root, path_base)
    raw_bytes = raw_json if isinstance(raw_json, bytes) else raw_json.encode("utf-8")
    scan_hash = digest(raw_bytes)
    issues = list(scan_issues)
    if engine_exit is None:
        issues.append("engine exit unavailable; scan completeness unverified")
    elif engine_exit != 0:
        issues.append("engine exit is nonzero: " + str(engine_exit))
    try:
        doc = strict_json(raw_bytes.decode("utf-8"))
    except (EvidenceError, UnicodeError) as exc:
        return {"scan_sha256": scan_hash, "root": str(tree.root), "collected_at": now(),
                "issues": issues + [str(exc)], "records": [], "raw_document": None}
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        return {"scan_sha256": scan_hash, "root": str(tree.root), "collected_at": now(),
                "issues": issues + ["invalid OpenGrep results envelope"], "records": [], "raw_document": doc}
    if not isinstance(doc.get("errors", []), list) or doc.get("errors"):
        issues.append("OpenGrep reported errors or partial scan")
    skipped = doc.get("paths", {}).get("skipped", []) if isinstance(doc.get("paths", {}), dict) else []
    if skipped:
        issues.append("OpenGrep reported skipped paths; completeness unverified")
    records = []
    for index, original in enumerate(doc["results"]):
        problems = list(issues)
        snapshots, snippets = {}, []
        item = original if isinstance(original, dict) else {}
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        trace = extra.get("dataflow_trace", item.get("dataflow_trace"))
        if not item.get("check_id") or not isinstance(item.get("check_id"), str):
            problems.append("missing rule ID")
        if not isinstance(extra.get("severity"), str):
            problems.append("missing severity")
        cwe = metadata.get("cwe", [])
        if isinstance(cwe, str):
            cwe = [cwe]
        if not isinstance(cwe, list) or not all(isinstance(x, str) for x in cwe) or not cwe:
            problems.append("missing or invalid CWE metadata")
            cwe = []
        def add(loc, role, expected=None):
            try:
                snippets.append(location_evidence(tree, loc, role, snapshots, expected))
            except (EvidenceError, OSError, UnicodeError, ValueError, RuntimeError) as exc:
                problems.append(role + ": " + str(exc))
        add(item, "finding")
        if not isinstance(trace, dict) or not trace:
            problems.append("missing or unsupported dataflow trace; no flow inferred")
        else:
            def visit(node, role, depth=0):
                if depth > 20:
                    problems.append("trace nesting limit")
                    return
                if isinstance(node, list) and len(node) == 2 and node[0] == "CliLoc":
                    payload = node[1]
                    if isinstance(payload, list) and len(payload) == 2:
                        add(payload[0], role, payload[1])
                        return
                # Preserve CliCall raw; do not guess its semantics or flatten it.
                problems.append("unsupported or missing " + role + " trace structure")
            visit(trace.get("taint_source"), "source")
            steps = trace.get("intermediate_vars", [])
            if isinstance(steps, list):
                for step in steps:
                    if isinstance(step, dict) and "content" in step:
                        add(step.get("location"), "intermediate", step["content"])
                    else:
                        problems.append("invalid intermediate trace step")
            else:
                problems.append("invalid intermediate trace list")
            visit(trace.get("taint_sink"), "sink")
        identifier = digest((scan_hash + ":" + str(index)).encode())
        records.append({"id": identifier, "scan_sha256": scan_hash, "root": str(tree.root),
                        "rule_id": item.get("check_id"), "cwe": cwe, "severity": extra.get("severity"),
                        "path": item.get("path"), "start": item.get("start"), "end": item.get("end"),
                        "raw_finding": original, "raw_trace": trace,
                        "snapshots": snapshots, "snippets": snippets, "issues": problems,
                        "collected_at": now()})
    return {"scan_sha256": scan_hash, "root": str(tree.root), "collected_at": now(),
            "issues": issues, "records": records, "raw_document": doc}


def check_current(record):
    """All trace files are part of the version, not just the sink file."""
    if not record.get("snapshots"):
        raise EvidenceError("no source hashes; rescan required")
    tree = SourceTree(record["root"])
    for path, snapshot in record["snapshots"].items():
        _, data, _ = tree.read(path)
        if digest(data) != snapshot["sha256"]:
            raise EvidenceError("source hash mismatch; rescan required: " + path)
