"""Read-only forensic helper utilities for auditing server OpenGrep, Ollama, and Ground-Truth artifacts.

Strictly read-only on historical evidence directories:
- Never modifies, touches, or opens SQLite files in place (copies SQLite to TemporaryDirectory first).
- Separates raw LLM responses from post-validator assessments and human review states.
"""
from __future__ import annotations

import csv
import hashlib
import json
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from statistics import median
from typing import Any


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_lf_text(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    normalized = "\n".join(line.rstrip("\r") for line in text.splitlines())
    return sha256_bytes(normalized.encode("utf-8"))


def compute_contract_alert_id(scan_sha256: str, finding_index: int) -> str:
    token = f"{scan_sha256.strip().lower()}:{finding_index}".encode("utf-8")
    return hashlib.sha256(token).hexdigest()


def normalize_cwe(raw_cwe: Any) -> str:
    if isinstance(raw_cwe, list):
        raw_cwe = raw_cwe[0] if raw_cwe else ""
    text = str(raw_cwe or "").strip().upper()
    if "CWE-22" in text or "CWE-022" in text or text == "22":
        return "CWE-22"
    if "CWE-89" in text or "CWE-089" in text or text == "89":
        return "CWE-89"
    if ":" in text:
        text = text.split(":", 1)[0].strip()
    return text or "UNKNOWN_CWE"


def percentile_nearest_rank(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, int((pct / 100.0) * len(ordered) + 0.999999))
    idx = min(len(ordered) - 1, rank - 1)
    return round(ordered[idx], 2)


def summarize_latencies_ms(values_ms: list[float]) -> dict[str, float | int | None]:
    if not values_ms:
        return {
            "count": 0,
            "total_ms": 0.0,
            "total_s": 0.0,
            "mean_ms": None,
            "p50_ms": None,
            "p95_ms": None,
            "min_ms": None,
            "max_ms": None,
        }
    total_ms = sum(values_ms)
    return {
        "count": len(values_ms),
        "total_ms": round(total_ms, 2),
        "total_s": round(total_ms / 1000.0, 2),
        "mean_ms": round(total_ms / len(values_ms), 2),
        "p50_ms": round(float(median(values_ms)), 2),
        "p95_ms": percentile_nearest_rank(values_ms, 95.0),
        "min_ms": round(min(values_ms), 2),
        "max_ms": round(max(values_ms), 2),
    }


def inspect_sqlite_readonly_copy(sqlite_path: Path) -> dict[str, Any]:
    """Copy a SQLite DB to a temporary directory before reading so historical files are untouched."""
    if not sqlite_path.is_file():
        return {"present": False, "path": str(sqlite_path)}

    raw_sha = sha256_file(sqlite_path)
    size_bytes = sqlite_path.stat().st_size
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_db = Path(tmpdir) / sqlite_path.name
        shutil.copy2(sqlite_path, tmp_db)
        conn = sqlite3.connect(str(tmp_db))
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            tables = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
            ]
            table_counts: dict[str, int] = {}
            for tbl in tables:
                table_counts[tbl] = int(conn.execute(f"SELECT COUNT(*) FROM [{tbl}]").fetchone()[0])

            states: dict[str, int] = {}
            scan_ids: list[str] = []
            if "warnings" in tables:
                for st_val, cnt in conn.execute(
                    "SELECT state, COUNT(*) FROM warnings GROUP BY state ORDER BY state"
                ).fetchall():
                    states[str(st_val)] = int(cnt)
                scan_ids = [
                    str(r[0])
                    for r in conn.execute("SELECT DISTINCT scan_id FROM warnings ORDER BY scan_id").fetchall()
                ]

            events_rows: list[dict[str, Any]] = []
            if "events" in tables:
                cols = [c[1] for c in conn.execute("PRAGMA table_info(events)").fetchall()]
                for row in conn.execute("SELECT * FROM events ORDER BY sequence").fetchall():
                    events_rows.append(dict(zip(cols, row)))
        finally:
            conn.close()

    return {
        "present": True,
        "path": str(sqlite_path),
        "size_bytes": size_bytes,
        "sha256": raw_sha,
        "integrity_check": integrity,
        "table_counts": table_counts,
        "warning_states": states,
        "distinct_scan_ids": scan_ids,
        "human_events_count": len(events_rows),
        "events": events_rows,
    }


def scan_json_for_forbidden_label_keys(obj: Any, path_prefix: str = "") -> list[str]:
    """Recursively scan an evidence dict to verify ground_truth labels were not leaked into prompt inputs."""
    forbidden_keys = {
        "ground_truth",
        "expected_label",
        "verified_ground_truth",
        "real_vulnerability",
        "expectedresults",
        "annotator_rationale",
        "annotated_by",
    }
    hits: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_lower = str(k).strip().lower()
            cur = f"{path_prefix}.{k}" if path_prefix else str(k)
            if key_lower in forbidden_keys:
                hits.append(cur)
            hits.extend(scan_json_for_forbidden_label_keys(v, cur))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            hits.extend(scan_json_for_forbidden_label_keys(item, f"{path_prefix}[{idx}]"))
    return hits


def read_zip_member_sha256(zip_path: Path, member_suffix: str) -> dict[str, Any]:
    if not zip_path.is_file():
        return {"present": False}
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.filename.replace("\\", "/").endswith(member_suffix):
                raw = zf.read(info.filename)
                return {
                    "present": True,
                    "member": info.filename,
                    "size_bytes": len(raw),
                    "sha256": sha256_bytes(raw),
                    "lf_sha256": sha256_lf_text(raw),
                }
    return {"present": False, "member_suffix": member_suffix}


def load_owasp_expected_csv(csv_path: Path) -> dict[str, dict[str, Any]]:
    """Parse OWASP Benchmark v1.2 expectedresults-1.2.csv keyed by testcase name."""
    mapping: dict[str, dict[str, Any]] = {}
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            row = next(csv.reader([line]))
            if len(row) < 4:
                continue
            name, category, real_vuln, cwe_num = (
                row[0].strip(),
                row[1].strip(),
                row[2].strip().lower(),
                row[3].strip(),
            )
            if name.lower().startswith("test name"):
                continue
            mapping[name] = {
                "test_name": name,
                "category": category,
                "real_vulnerability": real_vuln == "true",
                "expected_label": "TRUE_POSITIVE" if real_vuln == "true" else "FALSE_POSITIVE",
                "cwe": f"CWE-{int(cwe_num)}" if cwe_num.isdigit() else normalize_cwe(cwe_num),
            }
    return mapping
