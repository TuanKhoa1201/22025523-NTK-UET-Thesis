import copy
import io
import json
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from test_triage import Fixture
from v2.triage.cli import main
from v2.triage.evidence import collect, digest, SourceTree, EvidenceError
from v2.triage.ollama import validate_answer
from capture_fixture import make_capture


class QueueContractTests(Fixture):
    def test_cli_hidden_all_history_reopen_and_stale_refusal(self):
        store = self.store()
        identifier = self.record["id"]
        db = str(Path(self.tmp.name) / "review.sqlite")
        def call(argv, expected=0):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(main(argv), expected)
            return json.loads(out.getvalue()) if out.getvalue() else err.getvalue()
        call(["decide", "--db", db, identifier, "confirm-false", "--actor", "SCRIPTED-DEMO", "--reason", "Synthetic API test only, not a production dismissal"])
        self.assertEqual(call(["queue", "--db", db])["warnings"], [])
        self.assertEqual(len(call(["queue", "--db", db, "--all"])["warnings"]), 1)
        self.assertEqual(call(["show", "--db", db, identifier])["state"], "CONFIRMED_FALSE")
        self.assertEqual(len(call(["history", "--db", db, identifier])), 1)
        call(["decide", "--db", db, identifier, "reopen", "--actor", "SCRIPTED-DEMO", "--reason", "Recheck synthetic test"])
        self.assertEqual(len(call(["queue", "--db", db])["warnings"]), 1)
        before = store.history(identifier)
        self.source.write_bytes(self.source.read_bytes() + b"// edit\n")
        self.assertIn("rescan", call(["decide", "--db", db, identifier, "confirm-false", "--actor", "SCRIPTED-DEMO", "--reason", "stale"], 2))
        self.assertEqual(store.history(identifier), before)
        self.assertEqual(len(store.queue(include_all=True)), 1)

    def test_supported_does_not_hide_confirmed_true(self):
        assessment = validate_answer(json.dumps(self.answer("SUPPORTED")), self.record)
        store = self.store(assessment)
        self.assertEqual(len(store.queue()), 1)
        store.decide(self.record["id"], "confirm-true", "SCRIPTED-DEMO", "Synthetic test")
        self.assertEqual(len(store.queue()), 1)


class PathMappingTests(Fixture):
    def wsl_document(self):
        doc = copy.deepcopy(self.doc)
        item = doc["results"][0]
        item["path"] = "/mnt/c/project/Demo.java"
        trace = item["extra"]["dataflow_trace"]
        for name in ("taint_source", "taint_sink"):
            trace[name][1][0]["path"] = item["path"]
        for step in trace["intermediate_vars"]:
            step["location"]["path"] = item["path"]
        return doc

    def test_wsl_mapping_preserves_raw_hash_id_trace_and_checks_source(self):
        doc = self.wsl_document()
        raw = json.dumps(doc).encode()
        bundle = collect(raw, self.root, engine_exit=0, path_maps=["/mnt/c/project=" + str(self.root)],
                         scan_provenance={"source_capture_verified": True, "origin": "UNIT_TEST_MOCK_CAPTURE"})
        record = bundle["records"][0]
        self.assertEqual(record["issues"], [])
        self.assertEqual(bundle["scan_sha256"], digest(raw))
        self.assertEqual(record["raw_finding"], doc["results"][0])
        self.assertEqual(record["raw_trace"], doc["results"][0]["extra"]["dataflow_trace"])
        self.assertEqual(record["snapshots"]["Demo.java"]["sha256"], digest(self.source.read_bytes()))
        self.assertEqual(record["snippets"][0]["raw_path"], "/mnt/c/project/Demo.java")
        self.assertEqual(record["snippets"][0]["path"], "Demo.java")
        self.assertEqual(len(bundle["path_mappings"]), 1)

    def test_cli_wsl_import_keeps_exact_input_bytes(self):
        raw = json.dumps(self.wsl_document()).encode()
        input_file = Path(self.tmp.name) / "wsl.json"
        input_file.write_bytes(raw)
        output = Path(self.tmp.name) / "wsl-run"
        manifest = make_capture(self.root, raw, Path(self.tmp.name) / "wsl-capture")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["run", "--source-root", str(self.root), "--json", str(input_file),
                                   "--engine-exit", "0", "--scan-manifest", str(manifest), "--path-map", "/mnt/c/project=" + str(self.root),
                                   "--output-dir", str(output), "--no-llm"]), 0)
        self.assertEqual((output / "input.opengrep.json").read_bytes(), raw)
        evidence = json.loads((output / "evidence.json").read_bytes())
        self.assertEqual(evidence["records"][0]["issues"], [])
        self.assertEqual(evidence["scan_sha256"], digest(raw))

    def test_missing_mapping_does_not_guess(self):
        record = collect(json.dumps(self.wsl_document()), self.root, engine_exit=0)["records"][0]
        self.assertTrue(record["issues"])

    def test_mapping_outside_root_and_duplicate_rejected(self):
        for maps in (["/mnt/c/project=" + str(self.root.parent)],
                     ["/mnt/c/project=" + str(self.root)] * 2):
            with self.assertRaises(EvidenceError):
                SourceTree(self.root, path_maps=maps)

    def test_mapping_prefix_boundary_and_traversal(self):
        tree = SourceTree(self.root, path_maps=["/mnt/c/project=" + str(self.root)])
        for raw in ("/mnt/c/project-other/Demo.java", "/mnt/c/project/../Outside.java"):
            with self.assertRaises((EvidenceError, OSError)):
                tree.read(raw)

    def test_mapping_never_weakens_offset_or_content_check(self):
        doc = self.wsl_document()
        doc["results"][0]["extra"]["dataflow_trace"]["taint_source"][1][0]["start"]["offset"] += 1
        record = collect(json.dumps(doc), self.root, engine_exit=0,
                         path_maps=["/mnt/c/project=" + str(self.root)])["records"][0]
        self.assertTrue(record["issues"])
