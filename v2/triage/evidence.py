"""Collect source-grounded evidence without trusting paths or code in engine JSON."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from .runtime import SCHEMA_VERSION
from .java_context import extract_java_context


class EvidenceError(ValueError):
    error_code = "EVIDENCE_ERROR"


class StaleSourceError(EvidenceError):
    error_code = "STALE_SOURCE"

    def __init__(self, message, *, mismatched_paths=(), expected_hashes=None, observed_hashes=None):
        prefix = "" if str(message).startswith("STALE_SOURCE:") else "STALE_SOURCE: "
        super().__init__(prefix + str(message))
        self.mismatched_paths = list(mismatched_paths)
        self.expected_hashes = dict(expected_hashes or {})
        self.observed_hashes = dict(observed_hashes or {})

    def to_dict(self):
        return {
            "error_code": self.error_code,
            "message": str(self),
            "mismatched_paths": list(self.mismatched_paths),
            "expected_hashes": dict(self.expected_hashes),
            "observed_hashes": dict(self.observed_hashes),
        }


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
    def __init__(self, root, path_base=None, path_maps=()):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise EvidenceError("source root must be a directory")
        self.path_base = Path(path_base).resolve() if path_base else self.root
        self.path_maps = []
        for entry in path_maps:
            if isinstance(entry, str) and "=" in entry:
                prefix, destination = entry.split("=", 1)
            elif isinstance(entry, dict) and set(entry) == {"from", "to"}:
                prefix, destination = entry["from"], entry["to"]
            else:
                raise EvidenceError("path map must be PREFIX=LOCAL_DIR or {from,to}")
            if (not isinstance(prefix, str) or not prefix.startswith("/") or "\\" in prefix
                    or ".." in PurePosixPath(prefix).parts or str(PurePosixPath(prefix)) == "/"):
                raise EvidenceError("path map needs an explicit non-root absolute POSIX prefix")
            prefix = str(PurePosixPath(prefix))
            target = Path(destination).resolve(strict=True)
            if not target.is_dir() or not target.is_relative_to(self.root):
                raise EvidenceError("mapped directory must stay inside configured source-root")
            if any(m["from"] == prefix for m in self.path_maps):
                raise EvidenceError("duplicate path-map prefix")
            self.path_maps.append({"from": prefix, "to": str(target)})
        self.path_maps.sort(key=lambda m: len(m["from"]), reverse=True)

    def resolve(self, raw):
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise EvidenceError("invalid source path")
        path = None
        for mapping in self.path_maps:
            prefix = mapping["from"]
            if raw == prefix or raw.startswith(prefix + "/"):
                suffix = raw[len(prefix):].lstrip("/")
                if ".." in PurePosixPath(suffix).parts or "\\" in suffix or ":" in suffix:
                    raise EvidenceError("invalid mapped path suffix")
                path = Path(mapping["to"]).joinpath(*PurePosixPath(suffix).parts)
                break
        if path is None:
            if os.name == "nt" and raw.startswith("/"):
                raise EvidenceError("POSIX/WSL source path requires an explicit --path-map")
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
    return {"role": role, "path": relative, "raw_path": loc.get("path"), "start": start, "end": end,
            "sha256": sha, "matched": matched,
            "lines": [{"line": i, "text": lines[i-1].rstrip("\r\n")}
                      for i in range(lower, upper + 1)]}


def collect(raw_json, root, path_base=None, engine_exit=None, scan_issues=(), path_maps=(), scan_provenance=None):
    """Keep even malformed/partial findings; issues force UNDETERMINED downstream."""
    tree = SourceTree(root, path_base, path_maps)
    raw_bytes = raw_json if isinstance(raw_json, bytes) else raw_json.encode("utf-8")
    scan_hash = digest(raw_bytes)
    issues = list(scan_issues)
    provenance = scan_provenance or {"origin": "collection_only", "source_capture_verified": False}
    if provenance.get("source_capture_verified") is not True:
        issues.append("scan-time source identity not verified; rescan or supply a valid capture")
    if engine_exit is None:
        issues.append("engine exit unavailable; scan completeness unverified")
    elif engine_exit != 0:
        issues.append("engine exit is nonzero: " + str(engine_exit))
    try:
        doc = strict_json(raw_bytes.decode("utf-8"))
    except (EvidenceError, UnicodeError) as exc:
        return {"schema_version": SCHEMA_VERSION, "scan_sha256": scan_hash, "root": str(tree.root), "collected_at": now(),
                "path_mappings": tree.path_maps,
                "issues": issues + [str(exc)], "records": [], "raw_document": None}
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        return {"schema_version": SCHEMA_VERSION, "scan_sha256": scan_hash, "root": str(tree.root), "collected_at": now(),
                "path_mappings": tree.path_maps,
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
                if isinstance(node, list) and len(node) == 2 and node[0] == "CliCall":
                    payload = node[1]
                    if (isinstance(payload, list) and len(payload) == 3
                            and isinstance(payload[0], list) and len(payload[0]) == 2
                            and isinstance(payload[0][0], dict) and isinstance(payload[0][1], str)
                            and isinstance(payload[1], list)
                            and isinstance(payload[2], list) and len(payload[2]) == 2):
                        call_site, call_steps, inner = payload
                        if role == "source":
                            visit(inner, "source", depth + 1)
                            add(call_site[0], "intermediate", call_site[1])
                            for step in call_steps:
                                if isinstance(step, dict) and "content" in step:
                                    add(step.get("location"), "intermediate", step["content"])
                                else:
                                    problems.append("invalid intermediate trace step")
                        else:
                            add(call_site[0], "intermediate", call_site[1])
                            for step in call_steps:
                                if isinstance(step, dict) and "content" in step:
                                    add(step.get("location"), "intermediate", step["content"])
                                else:
                                    problems.append("invalid intermediate trace step")
                            visit(inner, role, depth + 1)
                        return
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
        java_ctx = None
        if snippets and snippets[0].get("role") == "finding":
            try:
                f_snip = snippets[0]
                _, _, f_text = tree.read(f_snip.get("raw_path") or f_snip["path"])
                f_lines = f_text.splitlines(keepends=True)
                f_sl, f_el = f_snip["start"]["line"], f_snip["end"]["line"]
                if f_el - f_sl <= 140:
                    t_lines = [
                        s["start"]["line"]
                        for s in snippets[1:]
                        if s.get("path") == f_snip["path"] and isinstance(s.get("start"), dict)
                    ]
                    java_ctx = extract_java_context(f_text, f_sl, f_el, trace_lines=t_lines, max_span=140)
                    c_low = max(1, min(f_sl, java_ctx["context_start_line"]))
                    c_high = min(len(f_lines), max(f_el, java_ctx["context_end_line"]))
                    if c_high - c_low <= 150:
                        f_snip["lines"] = [
                            {"line": i, "text": f_lines[i - 1].rstrip("\r\n")}
                            for i in range(c_low, c_high + 1)
                        ]
            except (EvidenceError, OSError, UnicodeError, ValueError, RuntimeError):
                java_ctx = None
        identifier = digest((scan_hash + ":" + str(index)).encode())
        rec_obj = {"schema_version": SCHEMA_VERSION, "id": identifier, "alert_id": identifier,
                   "finding_index": index, "scan_sha256": scan_hash, "root": str(tree.root),
                   "path_mappings": tree.path_maps,
                   "scan_provenance": {k: v for k, v in provenance.items() if k != "source_hashes"},
                   "rule_id": item.get("check_id"), "cwe": cwe, "severity": extra.get("severity"),
                   "path": item.get("path"), "start": item.get("start"), "end": item.get("end"),
                   "raw_finding": original, "raw_trace": trace,
                   "snapshots": snapshots, "snippets": snippets, "issues": problems,
                   "java_context": java_ctx,
                   "collected_at": now()}
        try:
            from .heuristics import extract_evidence_signals
            rec_obj["heuristic_signals"] = extract_evidence_signals(rec_obj) if snippets else None
        except Exception:
            rec_obj["heuristic_signals"] = None
        records.append(rec_obj)
    return {"schema_version": SCHEMA_VERSION, "scan_sha256": scan_hash, "root": str(tree.root), "collected_at": now(),
            "path_mappings": tree.path_maps,
            "issues": issues, "records": records, "raw_document": doc}


def check_current(record):
    """All trace files are part of the version, not just the sink file."""
    provenance = record.get("scan_provenance")
    if not isinstance(provenance, dict) or provenance.get("source_capture_verified") is not True:
        raise EvidenceError("scan-time source identity unavailable; rescan required")
    if not record.get("snapshots"):
        raise EvidenceError("no source hashes; rescan required")
    expected = {p: v.get("sha256") for p, v in record["snapshots"].items() if isinstance(v, dict)}
    try:
        tree = SourceTree(record["root"])
    except (EvidenceError, OSError, ValueError, RuntimeError) as exc:
        raise StaleSourceError(
            "source root unavailable; rescan required: " + str(exc),
            mismatched_paths=sorted(expected),
            expected_hashes=expected,
            observed_hashes={p: "MISSING_OR_UNREADABLE" for p in expected},
        ) from exc
    observed = {}
    mismatched = []
    first_reason = None
    for path, snapshot in record["snapshots"].items():
        exp_sha = snapshot.get("sha256") if isinstance(snapshot, dict) else None
        try:
            _, data, _ = tree.read(path)
            obs_sha = digest(data)
            observed[path] = obs_sha
            if obs_sha != exp_sha:
                mismatched.append(path)
                if first_reason is None:
                    first_reason = "source hash mismatch; rescan required: " + path
        except (EvidenceError, OSError, UnicodeError, ValueError, RuntimeError) as exc:
            observed[path] = "MISSING_OR_UNREADABLE"
            mismatched.append(path)
            if first_reason is None:
                first_reason = f"source unavailable/changed ({path}); rescan required: {exc}"
    if mismatched:
        raise StaleSourceError(
            first_reason or ("source hash mismatch; rescan required: " + ", ".join(mismatched)),
            mismatched_paths=mismatched,
            expected_hashes=expected,
            observed_hashes=observed,
        )
