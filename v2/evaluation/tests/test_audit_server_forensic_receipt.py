"""Unit tests for independent server forensic audit helpers and metric recomputation."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from v2.evaluation.audit_server_forensic_receipt import (
    _compute_bucket_metrics,
    verify_evidence_root_immutability,
)
from v2.evaluation.server_forensic_helpers import (
    compute_contract_alert_id,
    inspect_sqlite_readonly_copy,
    load_owasp_expected_csv,
    normalize_cwe,
    scan_json_for_forbidden_label_keys,
    sha256_bytes,
    sha256_file,
    sha256_lf_text,
)


def test_contract_alert_id_deterministic() -> None:
    scan_sha = "67c3b04903e75f4bd7294cb17452d0dcb2b6d56244330cec485c4422efabfa8b"
    aid0 = compute_contract_alert_id(scan_sha.upper(), 0)
    aid0_lower = compute_contract_alert_id(scan_sha.lower(), 0)
    assert aid0 == aid0_lower
    assert len(aid0) == 64
    assert aid0 != compute_contract_alert_id(scan_sha, 1)


def test_normalize_cwe_variants() -> None:
    assert normalize_cwe(["CWE-22: Improper Limitation of a Pathname"]) == "CWE-22"
    assert normalize_cwe("CWE-089") == "CWE-89"
    assert normalize_cwe("22") == "CWE-22"
    assert normalize_cwe("89") == "CWE-89"


def test_forbidden_label_key_scanner() -> None:
    clean_evidence = {
        "rule_id": "tainted-sql-string",
        "heuristic_signals": {
            "recommended_status": "REFUTED",
            "candidate_citations": [{"line": 10}],
        },
    }
    assert scan_json_for_forbidden_label_keys(clean_evidence) == []

    leaked_evidence = {
        "rule_id": "tainted-sql-string",
        "nested": [{"ground_truth": "TRUE_POSITIVE"}, {"annotated_by": "human"}],
    }
    hits = scan_json_for_forbidden_label_keys(leaked_evidence)
    assert "nested[0].ground_truth" in hits
    assert "nested[1].annotated_by" in hits


def test_owasp_expected_csv_parser(tmp_path: Path) -> None:
    csv_file = tmp_path / "expectedresults-1.2.csv"
    csv_file.write_text(
        "# test name, category, real vulnerability, cwe, benchmark version: 1.2\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00002,sqli,false,89\n",
        encoding="utf-8",
    )
    parsed = load_owasp_expected_csv(csv_file)
    assert parsed["BenchmarkTest00001"]["expected_label"] == "TRUE_POSITIVE"
    assert parsed["BenchmarkTest00001"]["cwe"] == "CWE-22"
    assert parsed["BenchmarkTest00002"]["expected_label"] == "FALSE_POSITIVE"
    assert parsed["BenchmarkTest00002"]["cwe"] == "CWE-89"


def test_sqlite_readonly_copy_preserves_original_bytes(tmp_path: Path) -> None:
    db_path = tmp_path / "review.sqlite"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE scans (id TEXT PRIMARY KEY, bundle TEXT)")
    conn.execute("CREATE TABLE warnings (id TEXT PRIMARY KEY, scan_id TEXT, state TEXT)")
    conn.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY, warning_id TEXT, action TEXT)")
    conn.execute("INSERT INTO scans VALUES ('abc123', '{}')")
    conn.execute("INSERT INTO warnings VALUES ('w1', 'abc123', 'OPEN')")
    conn.commit()
    conn.close()

    before_sha = sha256_file(db_path)
    before_mtime = db_path.stat().st_mtime_ns

    info = inspect_sqlite_readonly_copy(db_path)
    assert info["present"] is True
    assert info["integrity_check"] == "ok"
    assert info["warning_states"] == {"OPEN": 1}
    assert info["human_events_count"] == 0
    assert sha256_file(db_path) == before_sha
    assert db_path.stat().st_mtime_ns == before_mtime


def test_bucket_metrics_drop_fp_and_keep_tp_only() -> None:
    rows = [
        {"ground_truth": "TRUE_POSITIVE", "post_status": "SUPPORTED", "citation_check": "MATCHED", "elapsed_seconds": 1.0},
        {"ground_truth": "TRUE_POSITIVE", "post_status": "UNDETERMINED", "citation_check": "NOT_VERIFIED", "elapsed_seconds": 2.0},
        {"ground_truth": "FALSE_POSITIVE", "post_status": "REFUTED", "citation_check": "MATCHED", "elapsed_seconds": 3.0},
        {"ground_truth": "FALSE_POSITIVE", "post_status": "UNDETERMINED", "citation_check": "NOT_VERIFIED", "elapsed_seconds": 4.0},
    ]
    m = _compute_bucket_metrics(rows)
    assert m["tp_kept_supported"] == "1/2"
    assert m["fp_proposed_refuted"] == "1/2"
    assert m["tp_erroneously_refuted"] == "0/2"
    assert m["undetermined_display"] == "2/4"
    # drop_fp retains 2 TPs (1 SUPPORTED + 1 UNDETERMINED) and 1 FP (1 UNDETERMINED) => precision 2/3, recall 2/2
    assert m["policy_drop_fp_precision"] == "2/3"
    assert m["policy_drop_fp_recall"] == "2/2"
    # keep_tp_only retains only SUPPORTED => 1 TP, 0 FP => precision 1/1, recall 1/2
    assert m["policy_keep_tp_only_precision"] == "1/1"
    assert m["policy_keep_tp_only_recall"] == "1/2"


def test_evidence_immutability_detector(tmp_path: Path) -> None:
    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir()
    f1 = ev_dir / "a.txt"
    f1.write_bytes(b"hello\r\nworld")
    assert sha256_lf_text(f1.read_bytes()) == sha256_bytes(b"hello\nworld")

    snap = tmp_path / "pre.json"
    snap.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "rel_path": "a.txt",
                        "size_bytes": f1.stat().st_size,
                        "mtime_ns": f1.stat().st_mtime_ns,
                        "sha256": sha256_file(f1),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    res_clean = verify_evidence_root_immutability(snap, ev_dir)
    assert res_clean["zero_mutation_verified"] is True

    f1.write_bytes(b"tampered")
    res_tampered = verify_evidence_root_immutability(snap, ev_dir)
    assert res_tampered["zero_mutation_verified"] is False
    assert len(res_tampered["modified_files"]) == 1
