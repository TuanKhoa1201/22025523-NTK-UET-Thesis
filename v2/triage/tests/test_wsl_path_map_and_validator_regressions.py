"""Security and regression tests for WSL2/Windows path mapping and validator path normalization (G1-C2).

Covers:
1. Valid Windows <-> WSL2 `/mnt/<drive>/...` mapping anchored to trusted `source_root` with lossless raw provenance.
2. Native Windows paths and pure POSIX compatibility.
3. Arbitrary/unmapped POSIX paths, cross-drive paths, and forged sibling-prefix attacks (`/mnt/c/root-evil/...`).
4. Path traversal (`..`) in mapped suffixes, relative paths, and `--path-map` definitions.
5. Symlink / NTFS directory junction escaping `source_root`.
6. Mismatched SHA-256 citation hashes, unnormalized raw citation paths, and post-scan `STALE_SOURCE`.
7. Enclosing-method / helper-callee citation scope and unreachable dead-branch rejection under WSL2 `record['path']`.
8. Invalid-sanitizer `REFUTED` (`encodeForHTML`, `escapeHtml`, `URLDecoder.decode`, unsafe `startsWith`, `replace` blacklist)
   under WSL2 and Windows absolute `record['path']` -> fail-closed `UNDETERMINED` (`UNVERIFIED_REFUTATION`).
"""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from v2.g1_integration.bridge import derive_trusted_path_maps
from v2.triage.evidence import EvidenceError, SourceTree, StaleSourceError, check_current, collect
from v2.triage.ollama import OllamaClient, inspect_citations_provenance, validate_answer
from v2.triage.store import ReviewStore


def _create_dir_escape_link(link_path: Path, target_dir: Path) -> bool:
    """Create a directory symlink or Windows NTFS junction (no admin privilege needed for junctions)."""
    try:
        os.symlink(str(target_dir), str(link_path), target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(target_dir), str(link_path))
            return True
    return False


def _pt(lines_keepends: list[str], ln: int, col: int) -> dict[str, int]:
    return {
        "line": ln,
        "col": col,
        "offset": sum(len(x.encode("utf-8")) for x in lines_keepends[: ln - 1]) + col - 1,
    }


def _loc_node(raw_path: str, code: str, ln: int, snippet_txt: str) -> list:
    lines_keepends = code.splitlines(keepends=True)
    col = code.splitlines()[ln - 1].index(snippet_txt) + 1
    return [
        "CliLoc",
        [
            {
                "path": raw_path,
                "start": _pt(lines_keepends, ln, col),
                "end": _pt(lines_keepends, ln, col + len(snippet_txt.encode("utf-8"))),
            },
            snippet_txt,
        ],
    ]


def _wsl_path_for(root: Path, rel_posix: str) -> str:
    if os.name == "nt" and root.drive:
        drive_letter = root.drive[0].lower()
        root_rel = root.relative_to(root.anchor).as_posix().strip("/")
        return str(PurePosixPath(f"/mnt/{drive_letter}/{root_rel}/{rel_posix}"))
    return str(PurePosixPath(f"/mnt/c/ntk_mapped_src/{rel_posix}"))


def _path_maps_for(root: Path) -> list[str]:
    if os.name == "nt":
        return derive_trusted_path_maps(root)
    return [f"/mnt/c/ntk_mapped_src={root}"]


class WslPathMappingAndSecurityBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve(strict=True)
        self.src_root = self.base / "src"
        self.src_root.mkdir()
        self.outside_dir = self.base / "outside"
        self.outside_dir.mkdir()
        self.sibling_evil = self.base / "src-evil"
        self.sibling_evil.mkdir()

        self.java_code = (
            "import javax.servlet.http.*;\n"
            "import java.sql.*;\n"
            "class Vuln {\n"
            "  void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String q = req.getParameter("q");\n'
            '    String sql = "SELECT * FROM t WHERE a=\'" + q + "\'";\n'
            "    st.executeQuery(sql);\n"
            "  }\n"
            "}\n"
        )
        (self.src_root / "Vuln.java").write_bytes(self.java_code.encode("utf-8"))
        (self.outside_dir / "Secret.java").write_bytes(self.java_code.encode("utf-8"))
        (self.sibling_evil / "Secret.java").write_bytes(self.java_code.encode("utf-8"))

    def _raw_doc(self, raw_path: str) -> dict:
        lines_ke = self.java_code.splitlines(keepends=True)
        sink_txt = "st.executeQuery(sql)"
        col = self.java_code.splitlines()[6].index(sink_txt) + 1
        return {
            "results": [
                {
                    "check_id": "ntk.g1.java.cwe89.sql-injection",
                    "path": raw_path,
                    "start": _pt(lines_ke, 7, col),
                    "end": _pt(lines_ke, 7, col + len(sink_txt)),
                    "extra": {
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-89"]},
                        "dataflow_trace": {
                            "taint_source": _loc_node(raw_path, self.java_code, 5, 'req.getParameter("q")'),
                            "intermediate_vars": [
                                {
                                    "location": _loc_node(raw_path, self.java_code, 6, "sql")[1][0],
                                    "content": "sql",
                                }
                            ],
                            "taint_sink": _loc_node(raw_path, self.java_code, 7, sink_txt),
                        },
                    },
                }
            ],
            "errors": [],
        }

    def test_01_valid_wsl2_mapping_preserves_raw_json_and_verifies_check_current(self):
        wsl_file = _wsl_path_for(self.src_root, "Vuln.java")
        raw_doc = self._raw_doc(wsl_file)
        raw_bytes = json.dumps(raw_doc).encode("utf-8")
        maps = _path_maps_for(self.src_root)

        bundle = collect(
            raw_bytes,
            self.src_root,
            engine_exit=0,
            path_maps=maps,
            scan_provenance={"origin": "UNIT_TEST_CAPTURE", "source_capture_verified": True},
        )
        self.assertEqual(bundle["issues"], [])
        rec = bundle["records"][0]
        self.assertEqual(rec["issues"], [])
        # Raw provenance must remain 100% lossless (never rewritten to relative path)
        self.assertEqual(rec["path"], wsl_file)
        self.assertEqual(rec["raw_finding"]["path"], wsl_file)
        self.assertEqual(rec["raw_trace"], raw_doc["results"][0]["extra"]["dataflow_trace"])
        # Evidence snapshots and snippets use verified canonical relative path
        self.assertIn("Vuln.java", rec["snapshots"])
        self.assertEqual(rec["snippets"][0]["path"], "Vuln.java")
        self.assertEqual(rec["snippets"][0]["raw_path"], wsl_file)
        check_current(rec)

    def test_02_native_windows_and_relative_paths_still_work_with_trusted_path_maps(self):
        maps = _path_maps_for(self.src_root)
        for native_raw in ("Vuln.java", str((self.src_root / "Vuln.java").resolve())):
            bundle = collect(
                json.dumps(self._raw_doc(native_raw)),
                self.src_root,
                engine_exit=0,
                path_maps=maps,
                scan_provenance={"origin": "UNIT_TEST_CAPTURE", "source_capture_verified": True},
            )
            self.assertEqual(bundle["issues"], [])
            self.assertEqual(bundle["records"][0]["issues"], [])
            self.assertEqual(bundle["records"][0]["path"], native_raw)
            check_current(bundle["records"][0])

        # Pure Linux mode synthesizes no Windows /mnt/<drive> mapping
        self.assertEqual(derive_trusted_path_maps(self.src_root, os_name="posix"), [])

    def test_03_invalid_posix_cross_drive_and_forged_sibling_prefix_fail_closed(self):
        maps = _path_maps_for(self.src_root)
        wsl_root_prefix = maps[0].split("=", 1)[0]
        bad_paths = [
            "/etc/passwd",
            "/tmp/Secret.java",
            "/mnt/z/other_drive/Vuln.java",
            wsl_root_prefix + "-evil/Secret.java",
        ]
        client = OllamaClient(model="qwen3.5:9b-q4_K_M", runtime_origin="mock")
        for bad_raw in bad_paths:
            with self.subTest(bad_raw=bad_raw):
                bundle = collect(
                    json.dumps(self._raw_doc(bad_raw)),
                    self.src_root,
                    engine_exit=0,
                    path_maps=maps,
                    scan_provenance={"origin": "UNIT_TEST_CAPTURE", "source_capture_verified": True},
                )
                rec = bundle["records"][0]
                self.assertTrue(rec["issues"], f"Expected Evidence issues for {bad_raw}")
                self.assertEqual(rec["snapshots"], {})
                out = client.analyze(rec)
                self.assertEqual(out["validated_status"], "UNDETERMINED")
                self.assertEqual(out["status"], "UNDETERMINED")
                self.assertEqual(out["failure_kind"], "EVIDENCE_PRECHECK_FAILED")

        # Explicit --path-map pointing outside source_root or cross-drive is refused immediately
        with self.assertRaisesRegex(EvidenceError, "inside configured source-root"):
            derive_trusted_path_maps(self.src_root, extra_path_maps=[f"/mnt/x/escape={self.outside_dir}"])
        with self.assertRaisesRegex(EvidenceError, "inside configured source-root"):
            derive_trusted_path_maps(self.src_root, extra_path_maps=[f"/mnt/x/sibling={self.sibling_evil}"])

    def test_04_path_traversal_variants_fail_closed_to_undetermined(self):
        maps = _path_maps_for(self.src_root)
        wsl_root_prefix = maps[0].split("=", 1)[0]
        traversal_paths = [
            f"{wsl_root_prefix}/../outside/Secret.java",
            f"{wsl_root_prefix}/sub/../../outside/Secret.java",
            "../outside/Secret.java",
            "..\\outside\\Secret.java",
        ]
        client = OllamaClient(model="qwen3.5:9b-q4_K_M", runtime_origin="mock")
        for trav in traversal_paths:
            with self.subTest(trav=trav):
                bundle = collect(
                    json.dumps(self._raw_doc(trav)),
                    self.src_root,
                    engine_exit=0,
                    path_maps=maps,
                    scan_provenance={"origin": "UNIT_TEST_CAPTURE", "source_capture_verified": True},
                )
                rec = bundle["records"][0]
                self.assertTrue(rec["issues"])
                self.assertEqual(rec["snapshots"], {})
                out = client.analyze(rec)
                self.assertEqual(out["validated_status"], "UNDETERMINED")

        with self.assertRaises(EvidenceError):
            SourceTree(self.src_root, path_maps=[f"/mnt/c/../evil={self.src_root}"])

    def test_05_symlink_or_junction_escaping_source_root_fails_closed(self):
        escape_dir = self.src_root / "escape_link"
        created = _create_dir_escape_link(escape_dir, self.outside_dir)
        self.assertTrue(created, "Expected symlink or NTFS junction creation to succeed")

        maps = _path_maps_for(self.src_root)
        wsl_escape = _wsl_path_for(self.src_root, "escape_link/Secret.java")
        for raw_candidate in (wsl_escape, str(escape_dir / "Secret.java"), "escape_link/Secret.java"):
            with self.subTest(raw_candidate=raw_candidate):
                with self.assertRaisesRegex(EvidenceError, "outside configured root"):
                    SourceTree(self.src_root, path_maps=maps).resolve(raw_candidate)
                bundle = collect(
                    json.dumps(self._raw_doc(raw_candidate)),
                    self.src_root,
                    engine_exit=0,
                    path_maps=maps,
                    scan_provenance={"origin": "UNIT_TEST_CAPTURE", "source_capture_verified": True},
                )
                rec = bundle["records"][0]
                self.assertTrue(rec["issues"])
                out = OllamaClient(model="qwen3.5:9b-q4_K_M", runtime_origin="mock").analyze(rec)
                self.assertEqual(out["validated_status"], "UNDETERMINED")

        # Attempting to map a prefix onto an escaping junction inside source_root is also rejected
        with self.assertRaisesRegex(EvidenceError, "inside configured source-root"):
            derive_trusted_path_maps(self.src_root, extra_path_maps=[f"/mnt/x/escaped={escape_dir}"])

    def test_06_wrong_sha256_raw_citation_path_and_mutated_source_fail_closed(self):
        wsl_file = _wsl_path_for(self.src_root, "Vuln.java")
        maps = _path_maps_for(self.src_root)
        bundle = collect(
            json.dumps(self._raw_doc(wsl_file)),
            self.src_root,
            engine_exit=0,
            path_maps=maps,
            scan_provenance={"origin": "UNIT_TEST_CAPTURE", "source_capture_verified": True},
        )
        rec = bundle["records"][0]
        sha = rec["snapshots"]["Vuln.java"]["sha256"]
        line6 = self.java_code.splitlines()[5]

        # 6a. Mismatched SHA-256 in citation
        bad_hash_ans = json.dumps({
            "status": "SUPPORTED",
            "explanation": "SQLi.",
            "fix_suggestion": "Dùng PreparedStatement.",
            "citations": [{"path": "Vuln.java", "start_line": 6, "end_line": 6, "quote": line6, "sha256": "a" * 64}],
        })
        with self.assertRaisesRegex(EvidenceError, "citation path/hash not in evidence"):
            validate_answer(bad_hash_ans, rec)

        # 6b. Model cites raw `/mnt/...` path instead of verified relative `Vuln.java`
        raw_path_ans = json.dumps({
            "status": "SUPPORTED",
            "explanation": "SQLi.",
            "fix_suggestion": "Dùng PreparedStatement.",
            "citations": [{"path": wsl_file, "start_line": 6, "end_line": 6, "quote": line6, "sha256": sha}],
        })
        with self.assertRaisesRegex(EvidenceError, "citation path/hash not in evidence"):
            validate_answer(raw_path_ans, rec)

        # 6c. Mutated file on disk after scan triggers StaleSourceError -> UNDETERMINED
        (self.src_root / "Vuln.java").write_text(self.java_code + "// edited\n", encoding="utf-8")
        good_ans = json.dumps({
            "status": "SUPPORTED",
            "explanation": "SQLi.",
            "fix_suggestion": "Dùng PreparedStatement.",
            "citations": [{"path": "Vuln.java", "start_line": 6, "end_line": 6, "quote": line6, "sha256": sha}],
        })
        with self.assertRaises(StaleSourceError):
            validate_answer(good_ans, rec)
        client = OllamaClient(model="qwen3.5:9b-q4_K_M", runtime_origin="mock")
        out = client.analyze(rec)
        self.assertEqual(out["validated_status"], "UNDETERMINED")
        self.assertEqual(out["failure_kind"], "EVIDENCE_PRECHECK_FAILED")


class ValidatorMappedPathScopeAndSanitizerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = (Path(self.tmp.name) / "src").resolve()
        self.root.mkdir()
        self.maps = _path_maps_for(self.root)

    def _collect_wsl(self, filename: str, code: str, cwe: str, src_ln: int, src_txt: str, sink_ln: int, sink_txt: str) -> dict:
        fpath = self.root / filename
        fpath.write_bytes(code.encode("utf-8"))
        wsl_path = _wsl_path_for(self.root, filename)
        lines_ke = code.splitlines(keepends=True)
        sink_col = code.splitlines()[sink_ln - 1].index(sink_txt) + 1
        doc = {
            "results": [
                {
                    "check_id": f"ntk.g1.java.{cwe.lower().replace('-', '')}.rule",
                    "path": wsl_path,
                    "start": _pt(lines_ke, sink_ln, sink_col),
                    "end": _pt(lines_ke, sink_ln, sink_col + len(sink_txt)),
                    "extra": {
                        "severity": "ERROR",
                        "metadata": {"cwe": [cwe]},
                        "dataflow_trace": {
                            "taint_source": _loc_node(wsl_path, code, src_ln, src_txt),
                            "intermediate_vars": [],
                            "taint_sink": _loc_node(wsl_path, code, sink_ln, sink_txt),
                        },
                    },
                }
            ],
            "errors": [],
        }
        bundle = collect(
            json.dumps(doc),
            self.root,
            engine_exit=0,
            path_maps=self.maps,
            scan_provenance={"origin": "UNIT_TEST_CAPTURE", "source_capture_verified": True},
        )
        self.assertEqual(bundle["issues"], [])
        self.assertEqual(bundle["records"][0]["issues"], [])
        return bundle

    def test_07_citation_scope_and_dead_branch_enforced_under_wsl2_mapped_record_path(self):
        # `unrelated()` (lines 16-18) sits between `vuln()` (lines 4-15) and same-file callee `idPass()` (lines 19-21),
        # so line 17 IS supplied in the contiguous prompt snippet window `[4..21]`, testing pure scope enforcement!
        code = (
            "import javax.servlet.http.*;\n"
            "import java.sql.*;\n"
            "class Scoped {\n"
            "  void vuln(HttpServletRequest req, Statement st) throws Exception {\n"
            "    int num = 86;\n"
            '    String p = req.getParameter("id");\n'
            '    String bar = "safe";\n'
            "    if ((7 * 42) - num > 200) {\n"
            "      bar = idPass(p);\n"
            "    }\n"
            "    else {\n"
            '      bar = "dead_safe_branch";\n'
            "    }\n"
            '    st.executeQuery("SELECT * FROM u WHERE id=\'" + bar + "\'");\n'
            "  }\n"
            "  int unrelated() {\n"
            "    int z = 42; return z;\n"
            "  }\n"
            "  String idPass(String x) {\n"
            "    return x;\n"
            "  }\n"
            "}\n"
        )
        bundle = self._collect_wsl(
            "Scoped.java", code, "CWE-89", 6, 'req.getParameter("id")', 14, 'st.executeQuery("SELECT * FROM u WHERE id=\'" + bar + "\'")'
        )
        rec = bundle["records"][0]
        self.assertTrue(rec["path"].startswith("/mnt/"))
        sha = rec["snapshots"]["Scoped.java"]["sha256"]
        lines = code.splitlines()

        # 7a. Valid non-trace statement inside enclosing_method (line 9: `bar = idPass(p);`) and same-file callee (line 20: `return x;`) MUST be accepted
        for valid_ln in (9, 20):
            in_method_ans = json.dumps({
                "status": "SUPPORTED",
                "explanation": "Nhánh điều kiện hằng số luôn đúng truyền tham số qua hàm nội bộ vào truy vấn.",
                "fix_suggestion": "Dùng PreparedStatement.",
                "citations": [{"path": "Scoped.java", "start_line": valid_ln, "end_line": valid_ln, "quote": lines[valid_ln - 1], "sha256": sha}],
            })
            validated = validate_answer(in_method_ans, rec)
            self.assertEqual(validated["validated_status"], "SUPPORTED")

        # 7b. Out-of-scope line in sandwiched unrelated method (line 17: `int z = 42; return z;`) MUST be rejected
        prov_out = inspect_citations_provenance(
            [{"path": "Scoped.java", "start_line": 17, "end_line": 17, "quote": lines[16], "sha256": sha}],
            rec,
        )
        self.assertTrue(prov_out["citation_in_prompt"])
        self.assertFalse(prov_out["any_in_relevant_scope"])
        out_scope_ans = json.dumps({
            "status": "SUPPORTED",
            "explanation": "Trích dẫn nhầm phương thức khác.",
            "fix_suggestion": "",
            "citations": [{"path": "Scoped.java", "start_line": 17, "end_line": 17, "quote": lines[16], "sha256": sha}],
        })
        with self.assertRaisesRegex(EvidenceError, "outside enclosing method and dataflow trace scope"):
            validate_answer(out_scope_ans, rec)

        # 7c. Unreachable dead-branch citation (line 12: `bar = "dead_safe_branch";`) MUST be rejected even with `/mnt/...` record["path"]
        dead_ans = json.dumps({
            "status": "REFUTED",
            "explanation": "Nhánh else gán hằng số.",
            "fix_suggestion": "",
            "citations": [{"path": "Scoped.java", "start_line": 12, "end_line": 12, "quote": lines[11], "sha256": sha}],
        })
        with self.assertRaisesRegex(EvidenceError, "unreachable dead-branch code"):
            validate_answer(dead_ans, rec)

    def test_08_invalid_sanitizer_refuted_rejected_under_wsl2_and_windows_abs_record_path(self):
        cases = [
            (
                "HtmlEnc.java",
                (
                    "import java.io.*;\n"
                    "import javax.servlet.http.*;\n"
                    "class HtmlEnc {\n"
                    "  FileInputStream f(HttpServletRequest req) throws Exception {\n"
                    '    String p = req.getParameter("f");\n'
                    "    String h = org.owasp.esapi.ESAPI.encoder().encodeForHTML(p);\n"
                    "    return new FileInputStream(h);\n"
                    "  }\n"
                    "}\n"
                ),
                6,
                "wrong-context encoder/decoder",
            ),
            (
                "EscHtml.java",
                (
                    "import java.io.*;\n"
                    "import javax.servlet.http.*;\n"
                    "class EscHtml {\n"
                    "  FileInputStream f(HttpServletRequest req) throws Exception {\n"
                    '    String p = req.getParameter("f");\n'
                    "    String h = org.apache.commons.lang.StringEscapeUtils.escapeHtml(p);\n"
                    "    return new FileInputStream(h);\n"
                    "  }\n"
                    "}\n"
                ),
                6,
                "wrong-context encoder/decoder",
            ),
            (
                "UrlDec.java",
                (
                    "import java.io.*;\n"
                    "import java.net.URLDecoder;\n"
                    "import javax.servlet.http.*;\n"
                    "class UrlDec {\n"
                    "  FileInputStream f(HttpServletRequest req) throws Exception {\n"
                    '    String p = URLDecoder.decode(req.getParameter("f"), "UTF-8");\n'
                    "    return new FileInputStream(p);\n"
                    "  }\n"
                    "}\n"
                ),
                6,
                "wrong-context encoder/decoder",
            ),
            (
                "BadStartsWith.java",
                (
                    "import java.io.*;\n"
                    "import javax.servlet.http.*;\n"
                    "class BadStartsWith {\n"
                    "  FileInputStream f(HttpServletRequest req) throws Exception {\n"
                    '    String p = req.getParameter("f");\n'
                    '    if (!p.startsWith("/srv/reports")) throw new SecurityException("x");\n'
                    "    return new FileInputStream(p);\n"
                    "  }\n"
                    "}\n"
                ),
                6,
                "startsWith guard lacks verified canonical path",
            ),
            (
                "BadReplace.java",
                (
                    "import java.io.*;\n"
                    "import javax.servlet.http.*;\n"
                    "class BadReplace {\n"
                    "  FileInputStream f(HttpServletRequest req) throws Exception {\n"
                    '    String p = req.getParameter("f");\n'
                    '    String clean = p.replace("../", "");\n'
                    "    return new FileInputStream(clean);\n"
                    "  }\n"
                    "}\n"
                ),
                6,
                "string replace blacklist",
            ),
        ]

        client = OllamaClient(model="qwen3.5:9b-q4_K_M", runtime_origin="mock")
        for fname, code, cite_ln, expected_err in cases:
            with self.subTest(fname=fname):
                sink_line = 7
                sink_call = [ln.strip().rstrip(";") for ln in code.splitlines() if "new FileInputStream" in ln][0].replace("return ", "")
                bundle = self._collect_wsl(fname, code, "CWE-22", 5 if "UrlDec" not in fname else 6, 'req.getParameter("f")', sink_line, sink_call)
                rec = bundle["records"][0]
                self.assertTrue(rec["path"].startswith("/mnt/"))
                sha = rec["snapshots"][fname]["sha256"]
                quote = code.splitlines()[cite_ln - 1]
                refuted_payload = json.dumps({
                    "status": "REFUTED",
                    "explanation": "Đã lọc đầu vào.",
                    "fix_suggestion": "",
                    "citations": [{"path": fname, "start_line": cite_ln, "end_line": cite_ln, "quote": quote, "sha256": sha}],
                })
                with self.assertRaisesRegex(EvidenceError, expected_err):
                    validate_answer(refuted_payload, rec)

                mock_resp = {
                    "done": True,
                    "done_reason": "stop",
                    "model": "qwen3.5:9b-q4_K_M",
                    "mock_test_fixture": True,
                    "message": {"content": refuted_payload},
                }
                with patch.object(client, "request", return_value=mock_resp):
                    analyzed = client.analyze(rec)
                self.assertEqual(analyzed["raw_model_status"], "REFUTED")
                self.assertEqual(analyzed["validated_status"], "UNDETERMINED")
                self.assertEqual(analyzed["status"], "UNDETERMINED")
                self.assertTrue(analyzed["validator_downgraded"])
                self.assertEqual(analyzed["failure_kind"], "UNVERIFIED_REFUTATION")

                db_path = Path(self.tmp.name) / f"{fname}.sqlite"
                store = ReviewStore(db_path)
                try:
                    store.add(bundle, [analyzed])
                    q = store.queue()
                    self.assertEqual(len(q), 1)
                    self.assertEqual(q[0]["state"], "OPEN")
                finally:
                    store.close()


if __name__ == "__main__":
    unittest.main()
