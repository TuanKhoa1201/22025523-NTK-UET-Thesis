"""Focused relocation tests for v2.g1_integration.evaluate_r01_r03.

Covers operator-pinned original scenario + capture vs relocated review copy verification:
1. Non-relocated scenarios remain valid under default strict-in-place mode.
2. Relocated Demo1 human-review copy (both retained_legacy and stripped_legacy) passes when paired with pinned original scenario + capture.
3. Relocated AllowlistedQuery P5/P6 copy passes with pinned original scenario, capture, and source root.
4. Missing, unpaired, self-pinned, nested, or cross-wired trusted roots fail/stop safely in relocation mode.
5. Swapped original roots, altered JSON/SARIF, SHA-256 mismatches, manifest swaps, and coordinated triage bundle substitutions (capture A + triage B) fail closed via both API and CLI.
6. Traversal, '--output' inside pinned dirs, live source drift, and junction/symlink escapes fail closed (explicit skipTest if host cannot create junctions/symlinks).
7. R01 keeps exact 4 historical Qwen calls; mock/synthetic records are excluded and cannot PASS official mode.

Includes both:
- `R03RelocationTests`: runs with a real OpenGrep binary when available on PATH / OPENGREP_BINARY.
- `R03RelocationOfflineSyntheticTests` (`SYNTHETIC_MOCK_TEST_ONLY`): runs full CLI + evaluator logic offline using a deterministic synthetic OpenGrep stub and loopback mock Ollama server so zero real OpenGrep or Qwen calls occur during unit testing.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from v2.g1_integration.evaluate_r01_r03 import evaluate_acceptance, main as evaluate_main
from v2.g1_integration.prepare_g1_fork import apply_g1_overlay, apply_ntk_cleanroom_scanner_layer
from v2.g1_integration.run_g1_demo import run_demo_suite
from v2.triage.evidence import digest, strict_json


def _find_opengrep_binary() -> str | None:
    env_bin = os.environ.get("OPENGREP_BINARY")
    if env_bin and shutil.which(env_bin):
        return env_bin
    found = shutil.which("opengrep")
    if found:
        return found
    cli_root = Path.home() / ".opengrep" / "cli"
    if cli_root.is_dir():
        for exe_name in ("opengrep.exe", "opengrep"):
            matches = sorted(cli_root.glob(f"*/{exe_name}"), reverse=True)
            if matches:
                return str(matches[0])
    return None


def _build_synthetic_opengrep_shim(dest_dir: Path) -> str:
    """Create a SYNTHETIC_MOCK_TEST_ONLY OpenGrep stub CLI for offline relocation testing."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    stub_py = dest_dir / "_synthetic_opengrep.py"
    stub_py.write_text(
        textwrap.dedent(
            """\
            import json
            from pathlib import Path
            import sys

            def _line_span(lines_nl, line_no, substr):
                raw_line = lines_nl[line_no - 1]
                clean = raw_line.rstrip("\\r\\n")
                char_idx = clean.index(substr)
                prefix_bytes = len(clean[:char_idx].encode("utf-8"))
                sub_bytes = len(substr.encode("utf-8"))
                base_offset = sum(len(x.encode("utf-8")) for x in lines_nl[:line_no - 1])
                start_col = prefix_bytes + 1
                end_col = prefix_bytes + sub_bytes + 1
                return (
                    {"line": line_no, "col": start_col, "offset": base_offset + prefix_bytes},
                    {"line": line_no, "col": end_col, "offset": base_offset + prefix_bytes + sub_bytes},
                )

            def _loc(path_str, lines_nl, line_no, substr):
                s, e = _line_span(lines_nl, line_no, substr)
                return {"path": path_str, "start": s, "end": e}

            def _scan_java(path_obj):
                path_str = str(path_obj).replace("\\\\", "/")
                lines_nl = path_obj.read_text(encoding="utf-8").splitlines(keepends=True)
                clean_lines = [ln.rstrip("\\r\\n") for ln in lines_nl]
                findings = []

                req_lines = [
                    (idx + 1, ln) for idx, ln in enumerate(clean_lines)
                    if "req.getParameter(" in ln and not ln.lstrip().startswith(("//", "*", "/*"))
                ]
                for idx, ln in enumerate(clean_lines, start=1):
                    stripped = ln.lstrip()
                    if stripped.startswith(("//", "*", "/*")):
                        continue
                    if "stmt.executeQuery(" in ln and ");" in ln[ln.index("stmt.executeQuery("):]:
                        start_idx = ln.index("stmt.executeQuery(")
                        end_idx = ln.index(");", start_idx) + 1
                        sink_sub = ln[start_idx:end_idx]
                        src_ln = max(
                            (sl for sl, _ in req_lines if sl < idx),
                            default=idx,
                        )
                        src_text = clean_lines[src_ln - 1]
                        s_i = src_text.index("req.getParameter(")
                        s_sub = src_text[s_i:src_text.index(")", s_i) + 1]
                        f_loc = _loc(path_str, lines_nl, idx, sink_sub)
                        src_loc = _loc(path_str, lines_nl, src_ln, s_sub)
                        findings.append({
                            "check_id": "ntk.g1.java.cwe89.sql-injection",
                            "path": f_loc["path"],
                            "start": f_loc["start"],
                            "end": f_loc["end"],
                            "extra": {
                                "severity": "ERROR",
                                "message": "[CWE-89] Untrusted HTTP input reaches SQL sink.",
                                "metadata": {
                                    "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
                                },
                                "dataflow_trace": {
                                    "taint_source": ["CliLoc", [src_loc, s_sub]],
                                    "intermediate_vars": [],
                                    "taint_sink": ["CliLoc", [f_loc, sink_sub]],
                                },
                            },
                        })
                    elif "new FileInputStream(" in ln and ");" in ln[ln.index("new FileInputStream("):]:
                        start_idx = ln.index("new FileInputStream(")
                        end_idx = ln.index(");", start_idx) + 1
                        sink_sub = ln[start_idx:end_idx]
                        src_ln = max(
                            (sl for sl, _ in req_lines if sl < idx),
                            default=idx,
                        )
                        src_text = clean_lines[src_ln - 1]
                        s_i = src_text.index("req.getParameter(")
                        s_sub = src_text[s_i:src_text.index(")", s_i) + 1]
                        f_loc = _loc(path_str, lines_nl, idx, sink_sub)
                        src_loc = _loc(path_str, lines_nl, src_ln, s_sub)
                        findings.append({
                            "check_id": "ntk.g1.java.cwe22.path-traversal",
                            "path": f_loc["path"],
                            "start": f_loc["start"],
                            "end": f_loc["end"],
                            "extra": {
                                "severity": "ERROR",
                                "message": "[CWE-22] Untrusted HTTP input reaches filesystem sink.",
                                "metadata": {
                                    "cwe": ["CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"],
                                },
                                "dataflow_trace": {
                                    "taint_source": ["CliLoc", [src_loc, s_sub]],
                                    "intermediate_vars": [],
                                    "taint_sink": ["CliLoc", [f_loc, sink_sub]],
                                },
                            },
                        })
                return findings

            def main():
                args = sys.argv[1:]
                if "--version" in args:
                    sys.stdout.write("1.25.0\\n")
                    return 0
                out_path = None
                fmt_sarif = "--sarif" in args
                targets = []
                i = 0
                while i < len(args):
                    a = args[i]
                    if a in ("--config", "-f", "--output", "-o", "--jobs", "-j"):
                        if a in ("--output", "-o") and i + 1 < len(args):
                            out_path = args[i + 1]
                        i += 2
                        continue
                    if a.startswith("-") or a == "scan":
                        i += 1
                        continue
                    p = Path(a)
                    if p.exists():
                        targets.append(p)
                    i += 1

                java_files = []
                for t in targets:
                    if t.is_dir():
                        java_files.extend(sorted(t.rglob("*.java")))
                    elif t.is_file() and t.suffix.lower() == ".java":
                        java_files.append(t)

                all_findings = []
                for jf in java_files:
                    all_findings.extend(_scan_java(jf))

                if fmt_sarif:
                    rules = []
                    seen_r = {}
                    results = []
                    for f in all_findings:
                        cid = f["check_id"]
                        if cid not in seen_r:
                            seen_r[cid] = len(rules)
                            rules.append({
                                "id": cid,
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"tags": f["extra"]["metadata"]["cwe"]},
                            })
                        results.append({
                            "ruleId": cid,
                            "ruleIndex": seen_r[cid],
                            "level": "error",
                            "message": {"text": f["extra"]["message"]},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f["path"]},
                                    "region": {
                                        "startLine": f["start"]["line"],
                                        "startColumn": f["start"]["col"],
                                        "endLine": f["end"]["line"],
                                        "endColumn": f["end"]["col"],
                                    },
                                }
                            }],
                            "properties": {"metadata": f["extra"]["metadata"]},
                        })
                    payload = json.dumps({
                        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                        "version": "2.1.0",
                        "runs": [{
                            "tool": {"driver": {"name": "OpenGrep", "semanticVersion": "1.25.0", "rules": rules}},
                            "invocations": [{"executionSuccessful": True}],
                            "results": results,
                        }],
                    })
                else:
                    payload = json.dumps({
                        "version": "1.25.0",
                        "results": all_findings,
                        "errors": [],
                        "paths": {"scanned": [str(p).replace("\\\\", "/") for p in java_files], "skipped": []},
                    })

                if out_path is not None:
                    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
                    Path(out_path).write_text(payload, encoding="utf-8")
                else:
                    sys.stdout.write(payload)
                return 0

            raise SystemExit(main())
            """
        ),
        encoding="utf-8",
    )
    if os.name == "nt":
        shim = dest_dir / "opengrep.cmd"
        shim.write_text(f'@echo off\r\n"{sys.executable}" -X utf8 -B "{stub_py}" %*\r\n', encoding="utf-8")
    else:
        shim = dest_dir / "opengrep"
        shim.write_text(f'#!/usr/bin/env sh\nexec "{sys.executable}" -X utf8 -B "{stub_py}" "$@"\n', encoding="utf-8")
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(shim)


def _build_prepared_fork(dest_dir: Path) -> Path:
    source = dest_dir / "source"
    (source / "semgrepai").mkdir(parents=True, exist_ok=True)
    upstream_base = REPO_ROOT / "v2" / "baseline" / "upstream"
    for name in ("LICENSE", "pyproject.toml", "semgrepai.yml"):
        shutil.copy2(upstream_base / name, source / name)
    for mod in ("cli.py", "config.py", "scanner.py"):
        shutil.copy2(upstream_base / "semgrepai" / mod, source / "semgrepai" / mod)
    (source / "semgrepai" / "__main__.py").write_text(
        "from .cli import app\nif __name__ == '__main__':\n    app()\n",
        encoding="utf-8",
    )
    apply_ntk_cleanroom_scanner_layer(source)
    apply_g1_overlay(source, dest_dir)
    (dest_dir / "g1_repo_binding.json").write_text(
        json.dumps({"repo_root": str(REPO_ROOT)}, indent=2),
        encoding="utf-8",
    )
    return source


def _run_cli(prepared_source: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(prepared_source), str(REPO_ROOT)])
    env["NTK_G1_REPO_ROOT"] = str(REPO_ROOT)
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-X", "utf8", "-B", "-m", "semgrepai", *args],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _dir_inventory(root: Path) -> dict[str, tuple[int, str]]:
    inv: dict[str, tuple[int, str]] = {}
    for cur, _, files in os.walk(root):
        cur_p = Path(cur)
        for fn in sorted(files):
            fp = cur_p / fn
            raw = fp.read_bytes()
            inv[fp.relative_to(root).as_posix()] = (len(raw), digest(raw))
    return inv


def _start_mock_server(explanation_tag: str = "RUN_A") -> tuple[ThreadingHTTPServer, str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/api/tags":
                raw = (
                    f'{{"models":[{{"name":"qwen3.5:9b-q4_K_M","digest":"mockdigest-{explanation_tag}","size":100}}]}}'
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            else:
                self.send_error(404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            req_doc = json.loads(self.rfile.read(length).decode("utf-8"))
            user_ev = json.loads(req_doc["messages"][1]["content"])
            snip = user_ev["snippets"][0]
            rel_path = snip["path"]
            snap_sha = snip["sha256"]
            line_map = {ln["line"]: ln["text"] for ln in snip["lines"]}
            sink_ln = user_ev["start"]["line"]

            if "Demo1TruePositive.java" in rel_path:
                ans = {
                    "status": "SUPPORTED",
                    "explanation": f"SCRIPTED_TEST_ONLY [{explanation_tag}]: untrusted parameter reaches sink.",
                    "citations": [{
                        "path": rel_path,
                        "start_line": sink_ln,
                        "end_line": sink_ln,
                        "quote": line_map[sink_ln],
                        "sha256": snap_sha,
                    }],
                    "fix_suggestion": "SCRIPTED_TEST_ONLY: parameterize query.",
                }
            elif "Demo2ProtectedFalsePositive.java" in rel_path:
                g_lines = [
                    ln for ln in sorted(line_map)
                    if "getCanonicalPath" in line_map[ln] or 'startsWith("/srv/reports/")' in line_map[ln]
                ]
                ans = {
                    "status": "REFUTED",
                    "explanation": f"SCRIPTED_TEST_ONLY [{explanation_tag}]: canonical path prefix check.",
                    "citations": [{
                        "path": rel_path,
                        "start_line": min(g_lines),
                        "end_line": max(g_lines),
                        "quote": "\n".join(line_map[i] for i in range(min(g_lines), max(g_lines) + 1)),
                        "sha256": snap_sha,
                    }],
                    "fix_suggestion": "",
                }
            elif "AllowlistedQuery.java" in rel_path:
                guard_ln = next(ln for ln, txt in sorted(line_map.items()) if "SELECT 1" in txt)
                throw_ln = guard_ln + 1
                ans = {
                    "status": "REFUTED",
                    "explanation": f"SCRIPTED_TEST_ONLY [{explanation_tag}]: strict literal SELECT 1 allowlist.",
                    "citations": [{
                        "path": rel_path,
                        "start_line": guard_ln,
                        "end_line": throw_ln,
                        "quote": f"{line_map[guard_ln]}\n{line_map[throw_ln]}",
                        "sha256": snap_sha,
                    }],
                    "fix_suggestion": "",
                }
            else:
                ans = {
                    "status": "UNDETERMINED",
                    "explanation": f"SCRIPTED_TEST_ONLY [{explanation_tag}]: external helper missing.",
                    "citations": [{
                        "path": rel_path,
                        "start_line": sink_ln,
                        "end_line": sink_ln,
                        "quote": line_map[sink_ln],
                        "sha256": snap_sha,
                    }],
                    "fix_suggestion": "SCRIPTED_TEST_ONLY: inspect external helper.",
                }

            body = json.dumps({
                "mock_test_fixture": True,
                "done": True,
                "done_reason": "stop",
                "model": "qwen3.5:9b-q4_K_M",
                "message": {"role": "assistant", "content": json.dumps(ans)},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def _make_dir_link(link_path: Path, target_dir: Path) -> bool:
    if os.name == "nt":
        proc = subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(link_path), str(target_dir)],
            capture_output=True,
            text=True,
        )
        return proc.returncode == 0
    try:
        os.symlink(str(target_dir), str(link_path), target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        return False


def _remove_dir_link(link_path: Path) -> None:
    if os.name == "nt":
        subprocess.run(["cmd.exe", "/c", "rmdir", str(link_path)], capture_output=True, text=True)
    elif link_path.is_symlink():
        link_path.unlink()


def _make_file_link(link_path: Path, target_file: Path) -> bool:
    try:
        os.symlink(str(target_file), str(link_path), target_is_directory=False)
        return True
    except (OSError, NotImplementedError):
        return False


def _remove_file_link(link_path: Path) -> None:
    if os.path.lexists(link_path):
        try:
            link_path.unlink()
        except OSError:
            pass


def _copy_review_scenario(src_dir: Path, dst_dir: Path, *, strip_legacy_reports: bool = False) -> Path:
    shutil.copytree(src_dir, dst_dir)
    if strip_legacy_reports:
        legacy_dir = dst_dir / "capture" / "legacy_reports"
        if legacy_dir.exists():
            shutil.rmtree(legacy_dir)
    return dst_dir


class _RelocationTestMixin:
    """Shared relocation verification assertions run against both real OpenGrep and offline synthetic stub."""

    @classmethod
    def _setup_relocation_fixture(cls, opengrep_exe: str) -> None:
        cls.opengrep = opengrep_exe
        cls.prepared_source = _build_prepared_fork(cls.base_tmp / "prepared_fork")
        cls.rules = REPO_ROOT / "v2" / "g1_integration" / "rules" / "java_g1_cwe22_cwe89.yml"
        cls.fixtures = REPO_ROOT / "v2" / "g1_integration" / "demo_fixtures"

        cls.srv, cls.endpoint = _start_mock_server("RUN_A")
        cls.addClassCleanup(cls.srv.server_close)
        cls.addClassCleanup(cls.srv.shutdown)

        cls.orig_root = cls.base_tmp / "orig_acceptance"
        cls.m1_dir = cls.orig_root / "m1_scan_only"
        rc_m1 = _run_cli(cls.prepared_source, [
            "scan", str(cls.fixtures / "Demo1TruePositive.java"),
            "--rules-path", str(cls.rules),
            "--output-dir", str(cls.m1_dir),
            "--executable", cls.opengrep,
            "--scan-only",
        ])
        if rc_m1.returncode != 0:
            raise RuntimeError(f"M1 scan failed rc={rc_m1.returncode}\nSTDOUT:\n{rc_m1.stdout}\nSTDERR:\n{rc_m1.stderr}")

        cls.d1_orig_pristine = cls.orig_root / "demo1_true_positive"
        cls.d1_orig = cls.orig_root / "demo1_in_place"
        cls.d2_untouched = cls.orig_root / "demo2_untouched"
        cls.d2_locked = cls.orig_root / "demo2_locked"
        cls.d3a_orig = cls.orig_root / "demo3a_missing_helper"
        cls.aq_orig_pristine = cls.orig_root / "allowlisted_query_fp"
        cls.aq_orig = cls.orig_root / "allowlisted_query_in_place"
        for src_java, out_d in (
            (cls.fixtures / "Demo1TruePositive.java", cls.d1_orig_pristine),
            (cls.fixtures / "Demo1TruePositive.java", cls.d1_orig),
            (cls.fixtures / "Demo2ProtectedFalsePositive.java", cls.d2_untouched),
            (cls.fixtures / "Demo2ProtectedFalsePositive.java", cls.d2_locked),
            (cls.fixtures / "Demo3ExternalHelperUndetermined.java", cls.d3a_orig),
            (cls.fixtures / "AllowlistedQuery.java", cls.aq_orig_pristine),
            (cls.fixtures / "AllowlistedQuery.java", cls.aq_orig),
        ):
            r = _run_cli(cls.prepared_source, [
                "scan", str(src_java),
                "--rules-path", str(cls.rules),
                "--output-dir", str(out_d),
                "--executable", cls.opengrep,
                "--local-triage",
                "--endpoint", cls.endpoint,
                "--model", "qwen3.5:9b-q4_K_M",
                "--prompt-contract", "blind",
                "--runtime-origin", "mock",
            ])
            if r.returncode != 0:
                raise RuntimeError(
                    f"scan failed for {src_java.name} rc={r.returncode}\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
                )
            shutil.copy2(out_d / "triage" / "review.sqlite", out_d / "triage" / "review.post_ingestion.sqlite")

        # Build locked-mode Demo2 lifecycle in-place (confirm-false -> reopen)
        d2_db = str(cls.d2_locked / "triage" / "review.sqlite")
        d2_id = json.loads(_run_cli(cls.prepared_source, ["queue", "--db", d2_db]).stdout)["warnings"][0]["id"]
        assert _run_cli(cls.prepared_source, [
            "confirm-false", d2_id, "--db", d2_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: verified Demo2 FP",
        ]).returncode == 0
        shutil.copy2(cls.d2_locked / "triage" / "review.sqlite", cls.d2_locked / "triage" / "review.after_confirm_false.sqlite")
        assert _run_cli(cls.prepared_source, [
            "reopen", d2_id, "--db", d2_db,
            "--actor", "SCRIPTED_TEST_ONLY-lead",
            "--reason", "SCRIPTED_TEST_ONLY: reopened Demo2",
        ]).returncode == 0

        # Auxiliary controls (demo3b mock + demo4 stale source)
        cls.aux_dir = cls.orig_root / "aux_controls"
        run_demo_suite(
            prepared_source=cls.prepared_source,
            output_dir=cls.aux_dir,
            executable=cls.opengrep,
            auxiliary_controls_only=True,
        )
        cls.d3b_dir = cls.aux_dir / "demo3b_malformed_llm_synthetic_mock"
        cls.d4_dir = cls.aux_dir / "demo4_stale_source"

        # Relocated review copies copied from pristine originals (d1_orig_pristine / aq_orig_pristine stay untouched)
        cls.review_root = cls.base_tmp / "review_copies"
        cls.d1_review = _copy_review_scenario(
            cls.d1_orig_pristine, cls.review_root / "demo1_human_review", strip_legacy_reports=True
        )
        cls.d1_review_retained = _copy_review_scenario(
            cls.d1_orig_pristine, cls.review_root / "demo1_human_review_retained", strip_legacy_reports=False
        )
        cls.d1_review_from_reviewed = _copy_review_scenario(
            cls.d1_orig, cls.review_root / "demo1_from_reviewed_orig", strip_legacy_reports=True
        )
        for rev_d1 in (cls.d1_review, cls.d1_review_retained, cls.d1_review_from_reviewed):
            d1_db = str(rev_d1 / "triage" / "review.sqlite")
            d1_id = json.loads(_run_cli(cls.prepared_source, ["queue", "--db", d1_db]).stdout)["warnings"][0]["id"]
            assert _run_cli(cls.prepared_source, [
                "confirm-true", d1_id, "--db", d1_db,
                "--actor", "SCRIPTED_TEST_ONLY-op",
                "--reason", "SCRIPTED_TEST_ONLY: confirmed TP on relocated review copy",
            ]).returncode == 0

        cls.aq_review = _copy_review_scenario(
            cls.aq_orig_pristine, cls.review_root / "allowq_human_review", strip_legacy_reports=False
        )
        cls.aq_review_stripped = _copy_review_scenario(
            cls.aq_orig_pristine, cls.review_root / "allowq_human_review_stripped", strip_legacy_reports=True
        )
        for rev_aq in (cls.aq_review, cls.aq_review_stripped):
            aq_db = str(rev_aq / "triage" / "review.sqlite")
            aq_id = json.loads(_run_cli(cls.prepared_source, ["queue", "--db", aq_db]).stdout)["warnings"][0]["id"]
            assert _run_cli(cls.prepared_source, [
                "confirm-false", aq_id, "--db", aq_db,
                "--actor", "SCRIPTED_TEST_ONLY-op",
                "--reason", "SCRIPTED_TEST_ONLY: verified strict SELECT 1 allowlist",
            ]).returncode == 0
            shutil.copy2(rev_aq / "triage" / "review.sqlite", rev_aq / "triage" / "review.after_confirm_false.sqlite")
            assert _run_cli(cls.prepared_source, [
                "reopen", aq_id, "--db", aq_db,
                "--actor", "SCRIPTED_TEST_ONLY-lead",
                "--reason", "SCRIPTED_TEST_ONLY: reopened AllowlistedQuery",
            ]).returncode == 0

        # Apply human review to cls.d1_orig / cls.aq_orig for strict-in-place checks (pristine copies stay untouched)
        d1_ip_db = str(cls.d1_orig / "triage" / "review.sqlite")
        d1_ip_id = json.loads(_run_cli(cls.prepared_source, ["queue", "--db", d1_ip_db]).stdout)["warnings"][0]["id"]
        assert _run_cli(cls.prepared_source, [
            "confirm-true", d1_ip_id, "--db", d1_ip_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: in-place Demo1 confirm-true",
        ]).returncode == 0
        aq_ip_db = str(cls.aq_orig / "triage" / "review.sqlite")
        aq_ip_id = json.loads(_run_cli(cls.prepared_source, ["queue", "--db", aq_ip_db]).stdout)["warnings"][0]["id"]
        assert _run_cli(cls.prepared_source, [
            "confirm-false", aq_ip_id, "--db", aq_ip_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: in-place AllowlistedQuery confirm-false",
        ]).returncode == 0
        shutil.copy2(cls.aq_orig / "triage" / "review.sqlite", cls.aq_orig / "triage" / "review.after_confirm_false.sqlite")
        assert _run_cli(cls.prepared_source, [
            "reopen", aq_ip_id, "--db", aq_ip_db,
            "--actor", "SCRIPTED_TEST_ONLY-lead",
            "--reason", "SCRIPTED_TEST_ONLY: in-place AllowlistedQuery reopen",
        ]).returncode == 0

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_root = Path(self.tmp.name).resolve()

    def test_01_in_place_scenarios_remain_valid_and_strict_mode_rejects_relocated(self):
        rep_locked = evaluate_acceptance(
            demo1_dir=self.d1_orig,
            demo2_dir=self.d2_locked,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allow_mock_primary=True,
        )
        self.assertEqual(rep_locked["overall_status"], "PASS", rep_locked["criteria"])
        self.assertEqual(rep_locked["capture_relocation_mode"], "strict-in-place")
        self.assertEqual(rep_locked["pinned_original_scenario_roots"], {})
        self.assertEqual(rep_locked["pinned_original_capture_roots"], {})

        rep_proposed = evaluate_acceptance(
            demo1_dir=self.d1_orig,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=self.aq_orig,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_proposed["overall_status"], "PASS", rep_proposed["criteria"])

        # Strict-in-place MUST fail closed on relocated review copies (both stripped and retained engine paths)
        for bad_d1 in (self.d1_review, self.d1_review_retained):
            rep_fail_d1 = evaluate_acceptance(
                demo1_dir=bad_d1,
                demo2_dir=self.d2_untouched,
                demo3a_dir=self.d3a_orig,
                m1_dir=self.m1_dir,
                demo4_dir=self.d4_dir,
                demo3b_dir=self.d3b_dir,
                allowlisted_fp_dir=self.aq_orig,
                allowlisted_trusted_source_root=self.fixtures,
                r03_fp_mode="proposed-allowlisted-fp",
                allow_mock_primary=True,
            )
            self.assertEqual(rep_fail_d1["overall_status"], "FAIL")
            self.assertEqual(rep_fail_d1["criteria"]["R02"]["status"], "FAIL")

        rep_fail_aq = evaluate_acceptance(
            demo1_dir=self.d1_orig,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=self.aq_review,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_fail_aq["overall_status"], "FAIL")
        self.assertEqual(rep_fail_aq["criteria"]["R03"]["status"], "FAIL")

    def test_02_relocated_demo1_review_copy_accepted_when_pinned_to_original_scenario_and_capture(self):
        # Verify retained_legacy (with legacy_reports present), stripped_legacy vs pristine original,
        # and a relocated review copy paired against an original that also had in-place review applied.
        cases = (
            ("retained_legacy", self.d1_review_retained, self.d1_orig_pristine, True),
            ("stripped_legacy", self.d1_review, self.d1_orig_pristine, False),
            ("stripped_vs_reviewed_orig", self.d1_review_from_reviewed, self.d1_orig, False),
        )
        for name, src_review, orig_scen, expect_legacy in cases:
            with self.subTest(name=name):
                d1_copy = _copy_review_scenario(src_review, self.tmp_root / f"d1_{name}", strip_legacy_reports=False)
                legacy_dir = d1_copy / "capture" / "legacy_reports"
                if expect_legacy:
                    self.assertTrue((legacy_dir / "semgrep.json").is_file(), "retained_legacy fixture must hold semgrep.json")
                    self.assertTrue((legacy_dir / "semgrep.sarif").is_file(), "retained_legacy fixture must hold semgrep.sarif")
                else:
                    self.assertFalse(legacy_dir.exists())

                before_inv = _dir_inventory(d1_copy)
                orig_inv = _dir_inventory(orig_scen)
                rep = evaluate_acceptance(
                    demo1_dir=d1_copy,
                    demo2_dir=self.d2_locked,
                    demo3a_dir=self.d3a_orig,
                    m1_dir=self.m1_dir,
                    demo4_dir=self.d4_dir,
                    demo3b_dir=self.d3b_dir,
                    capture_relocation_mode="pinned-original-capture",
                    demo1_trusted_scenario_root=orig_scen,
                    demo1_trusted_capture_root=orig_scen / "capture",
                    allow_mock_primary=True,
                )
                self.assertEqual(rep["overall_status"], "PASS", (name, rep["criteria"]))
                self.assertEqual(rep["criteria"]["R01"]["status"], "PASS")
                self.assertEqual(rep["criteria"]["R02"]["status"], "PASS")
                self.assertEqual(rep["criteria"]["R03"]["status"], "PASS")
                self.assertTrue(rep["scenarios"]["demo1_true_positive"]["capture_relocation"]["relocated_mode"])
                self.assertEqual(_dir_inventory(d1_copy), before_inv)
                self.assertEqual(_dir_inventory(orig_scen), orig_inv)

                # If legacy_reports is retained in review copy and modified, evaluator MUST reject it
                if expect_legacy:
                    semgrep_copy = legacy_dir / "semgrep.json"
                    orig_bytes = semgrep_copy.read_bytes()
                    try:
                        semgrep_copy.write_bytes(orig_bytes + b" ")
                        rep_tampered_leg = evaluate_acceptance(
                            demo1_dir=d1_copy,
                            demo2_dir=self.d2_locked,
                            demo3a_dir=self.d3a_orig,
                            m1_dir=self.m1_dir,
                            demo4_dir=self.d4_dir,
                            demo3b_dir=self.d3b_dir,
                            capture_relocation_mode="pinned-original-capture",
                            demo1_trusted_scenario_root=orig_scen,
                            demo1_trusted_capture_root=orig_scen / "capture",
                            allow_mock_primary=True,
                        )
                        self.assertEqual(rep_tampered_leg["overall_status"], "FAIL")
                        self.assertEqual(rep_tampered_leg["criteria"]["R02"]["status"], "FAIL")
                    finally:
                        semgrep_copy.write_bytes(orig_bytes)

    def test_03_relocated_allowlisted_fp_and_demo1_pass_via_cli_and_source_root_must_match(self):
        out_json = self.tmp_root / "reloc_proposed_cli.json"
        before_d1 = _dir_inventory(self.d1_review)
        before_aq = _dir_inventory(self.aq_review_stripped)

        rc = evaluate_main([
            "--demo1-dir", str(self.d1_review),
            "--demo2-dir", str(self.d2_untouched),
            "--demo3a-dir", str(self.d3a_orig),
            "--m1-dir", str(self.m1_dir),
            "--demo4-dir", str(self.d4_dir),
            "--demo3b-dir", str(self.d3b_dir),
            "--r03-fp-mode", "proposed-allowlisted-fp",
            "--allowlisted-fp-dir", str(self.aq_review_stripped),
            "--allowlisted-trusted-source-root", str(self.fixtures),
            "--capture-relocation-mode", "pinned-original-capture",
            "--demo1-trusted-scenario-root", str(self.d1_orig_pristine),
            "--demo1-trusted-capture-root", str(self.d1_orig_pristine / "capture"),
            "--allowlisted-trusted-scenario-root", str(self.aq_orig_pristine),
            "--allowlisted-trusted-capture-root", str(self.aq_orig_pristine / "capture"),
            "--output", str(out_json),
            "--allow-mock-primary",
        ])
        self.assertEqual(rc, 0)
        self.assertEqual(_dir_inventory(self.d1_review), before_d1)
        self.assertEqual(_dir_inventory(self.aq_review_stripped), before_aq)
        doc = strict_json(out_json.read_text(encoding="utf-8"))
        self.assertEqual(doc["overall_status"], "PASS")
        self.assertEqual(doc["capture_relocation_mode"], "pinned-original-capture")
        self.assertIn("demo1", doc["pinned_original_scenario_roots"])
        self.assertIn("allowlisted", doc["pinned_original_scenario_roots"])
        self.assertIn("demo1", doc["pinned_original_capture_roots"])
        self.assertIn("allowlisted", doc["pinned_original_capture_roots"])
        self.assertEqual(doc["supplementary_r03_control"]["merged_with_g1_c5_session"], False)
        self.assertEqual(doc["supplementary_r03_control"]["model_fp_concurrence"], "CONCURRED_REFUTED")

        # Wrong allowlisted_trusted_source_root MUST fail closed even with valid scenario/capture relocation
        wrong_src_dir = self.tmp_root / "wrong_src_root"
        wrong_src_dir.mkdir()
        shutil.copy2(self.fixtures / "AllowlistedQuery.java", wrong_src_dir / "AllowlistedQuery.java")
        rep_bad_src = evaluate_acceptance(
            demo1_dir=self.d1_review,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=self.aq_review_stripped,
            allowlisted_trusted_source_root=wrong_src_dir,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.d1_orig_pristine,
            demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
            allowlisted_trusted_scenario_root=self.aq_orig_pristine,
            allowlisted_trusted_capture_root=self.aq_orig_pristine / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_bad_src["overall_status"], "FAIL")
        self.assertEqual(rep_bad_src["criteria"]["R03"]["status"], "FAIL")

    def test_04_missing_unpaired_self_pinned_or_nested_roots_fail_safely(self):
        # CLI stops safely if pinned-original-capture mode has NO trusted roots
        with self.assertRaises(SystemExit) as ctx1:
            evaluate_main([
                "--demo1-dir", str(self.d1_review),
                "--demo2-dir", str(self.d2_untouched),
                "--demo3a-dir", str(self.d3a_orig),
                "--m1-dir", str(self.m1_dir),
                "--demo4-dir", str(self.d4_dir),
                "--capture-relocation-mode", "pinned-original-capture",
                "--output", str(self.tmp_root / "never_written_1.json"),
            ])
        self.assertNotEqual(ctx1.exception.code, 0)

        with self.assertRaises(ValueError):
            evaluate_acceptance(
                demo1_dir=self.d1_review,
                demo2_dir=self.d2_locked,
                demo3a_dir=self.d3a_orig,
                m1_dir=self.m1_dir,
                demo4_dir=self.d4_dir,
                capture_relocation_mode="pinned-original-capture",
                allow_mock_primary=True,
            )

        # CLI rejects trusted capture or scenario roots in strict-in-place mode
        for bad_flag, bad_val in (
            ("--demo1-trusted-capture-root", str(self.d1_orig_pristine / "capture")),
            ("--demo1-trusted-scenario-root", str(self.d1_orig_pristine)),
        ):
            with self.assertRaises(SystemExit):
                evaluate_main([
                    "--demo1-dir", str(self.d1_orig),
                    "--demo2-dir", str(self.d2_locked),
                    "--demo3a-dir", str(self.d3a_orig),
                    "--m1-dir", str(self.m1_dir),
                    "--demo4-dir", str(self.d4_dir),
                    bad_flag, bad_val,
                    "--output", str(self.tmp_root / f"never_written_{bad_flag}.json"),
                ])

        # Unpaired trusted_scenario_root without trusted_capture_root (and vice versa) MUST raise ValueError / SystemExit
        with self.assertRaises(ValueError):
            evaluate_acceptance(
                demo1_dir=self.d1_review,
                demo2_dir=self.d2_locked,
                demo3a_dir=self.d3a_orig,
                m1_dir=self.m1_dir,
                demo4_dir=self.d4_dir,
                capture_relocation_mode="pinned-original-capture",
                demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
                allow_mock_primary=True,
            )
        with self.assertRaises(ValueError):
            evaluate_acceptance(
                demo1_dir=self.d1_review,
                demo2_dir=self.d2_locked,
                demo3a_dir=self.d3a_orig,
                m1_dir=self.m1_dir,
                demo4_dir=self.d4_dir,
                capture_relocation_mode="pinned-original-capture",
                demo1_trusted_scenario_root=self.d1_orig_pristine,
                allow_mock_primary=True,
            )
        with self.assertRaises(SystemExit):
            evaluate_main([
                "--demo1-dir", str(self.d1_review),
                "--demo2-dir", str(self.d2_locked),
                "--demo3a-dir", str(self.d3a_orig),
                "--m1-dir", str(self.m1_dir),
                "--demo4-dir", str(self.d4_dir),
                "--capture-relocation-mode", "pinned-original-capture",
                "--demo1-trusted-capture-root", str(self.d1_orig_pristine / "capture"),
                "--output", str(self.tmp_root / "never_written_unpaired.json"),
            ])

        with self.assertRaises(ValueError):
            evaluate_acceptance(
                demo1_dir=self.d1_review,
                demo2_dir=self.d2_locked,
                demo3a_dir=self.d3a_orig,
                m1_dir=self.m1_dir,
                demo4_dir=self.d4_dir,
                r03_fp_mode="locked-demo2",
                capture_relocation_mode="pinned-original-capture",
                demo1_trusted_scenario_root=self.d1_orig_pristine,
                demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
                allowlisted_trusted_scenario_root=self.aq_orig_pristine,
                allowlisted_trusted_capture_root=self.aq_orig_pristine / "capture",
                allow_mock_primary=True,
            )

        # Pinning only Demo1 while AllowlistedQuery is relocated without its trusted pair -> R03 FAIL
        rep_missing_aq_root = evaluate_acceptance(
            demo1_dir=self.d1_review,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=self.aq_review_stripped,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.d1_orig_pristine,
            demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_missing_aq_root["overall_status"], "FAIL")
        self.assertEqual(rep_missing_aq_root["criteria"]["R03"]["status"], "FAIL")

        # Pinning only AllowlistedQuery while Demo1 is relocated without its trusted pair -> R02 FAIL
        rep_missing_d1_root = evaluate_acceptance(
            demo1_dir=self.d1_review,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=self.aq_review_stripped,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="pinned-original-capture",
            allowlisted_trusted_scenario_root=self.aq_orig_pristine,
            allowlisted_trusted_capture_root=self.aq_orig_pristine / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_missing_d1_root["overall_status"], "FAIL")
        self.assertEqual(rep_missing_d1_root["criteria"]["R02"]["status"], "FAIL")

        # Self-pinning (EVEN when review copy retained legacy_reports!) MUST fail closed
        for self_label, self_dir in (
            ("stripped", self.d1_review),
            ("retained_legacy", self.d1_review_retained),
        ):
            with self.subTest(self_pin=self_label):
                rep_self_pin = evaluate_acceptance(
                    demo1_dir=self_dir,
                    demo2_dir=self.d2_locked,
                    demo3a_dir=self.d3a_orig,
                    m1_dir=self.m1_dir,
                    demo4_dir=self.d4_dir,
                    demo3b_dir=self.d3b_dir,
                    capture_relocation_mode="pinned-original-capture",
                    demo1_trusted_scenario_root=self_dir,
                    demo1_trusted_capture_root=self_dir / "capture",
                    allow_mock_primary=True,
                )
                self.assertEqual(rep_self_pin["overall_status"], "FAIL")
                self.assertEqual(rep_self_pin["criteria"]["R02"]["status"], "FAIL")

        # Nested review copy inside original scenario folder MUST fail closed
        nested_holder = self.tmp_root / "orig_with_nested_review"
        shutil.copytree(self.d1_orig_pristine, nested_holder)
        shutil.copytree(self.d1_review, nested_holder / "nested_review")
        rep_nested = evaluate_acceptance(
            demo1_dir=nested_holder / "nested_review",
            demo2_dir=self.d2_locked,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=nested_holder,
            demo1_trusted_capture_root=nested_holder / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_nested["overall_status"], "FAIL")
        self.assertEqual(rep_nested["criteria"]["R02"]["status"], "FAIL")

        # Cross-wired scenario root and capture root MUST fail closed
        rep_cross = evaluate_acceptance(
            demo1_dir=self.d1_review,
            demo2_dir=self.d2_locked,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.d1_orig_pristine,
            demo1_trusted_capture_root=self.aq_orig_pristine / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_cross["overall_status"], "FAIL")
        self.assertEqual(rep_cross["criteria"]["R02"]["status"], "FAIL")

        # Nonexistent scenario/capture pair MUST fail
        rep_bad = evaluate_acceptance(
            demo1_dir=self.d1_review,
            demo2_dir=self.d2_locked,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.tmp_root / "does_not_exist",
            demo1_trusted_capture_root=self.tmp_root / "does_not_exist" / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_bad["overall_status"], "FAIL")
        self.assertEqual(rep_bad["criteria"]["R02"]["status"], "FAIL")

    def test_05_rejects_swapped_original_root_modified_reports_sha_mismatch_or_manifest_swap(self):
        d1_orig_copy = self.tmp_root / "d1_orig_tamper"
        aq_orig_copy = self.tmp_root / "aq_orig_tamper"
        for src_java, out_d in (
            (self.fixtures / "Demo1TruePositive.java", d1_orig_copy),
            (self.fixtures / "AllowlistedQuery.java", aq_orig_copy),
        ):
            self.assertEqual(_run_cli(self.prepared_source, [
                "scan", str(src_java),
                "--rules-path", str(self.rules),
                "--output-dir", str(out_d),
                "--executable", self.opengrep,
                "--local-triage",
                "--endpoint", self.endpoint,
                "--model", "qwen3.5:9b-q4_K_M",
                "--prompt-contract", "blind",
                "--runtime-origin", "mock",
            ]).returncode, 0)
            shutil.copy2(out_d / "triage" / "review.sqlite", out_d / "triage" / "review.post_ingestion.sqlite")

        d1_rev_copy = _copy_review_scenario(d1_orig_copy, self.tmp_root / "d1_rev_copy", strip_legacy_reports=True)
        d1_db = str(d1_rev_copy / "triage" / "review.sqlite")
        d1_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", d1_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-true", d1_id, "--db", d1_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: tamper test review copy",
        ]).returncode, 0)

        aq_rev_copy = _copy_review_scenario(aq_orig_copy, self.tmp_root / "aq_rev_copy", strip_legacy_reports=True)
        aq_db = str(aq_rev_copy / "triage" / "review.sqlite")
        aq_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", aq_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-false", aq_id, "--db", aq_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: tamper test confirm-false",
        ]).returncode, 0)
        shutil.copy2(aq_rev_copy / "triage" / "review.sqlite", aq_rev_copy / "triage" / "review.after_confirm_false.sqlite")
        self.assertEqual(_run_cli(self.prepared_source, [
            "reopen", aq_id, "--db", aq_db,
            "--actor", "SCRIPTED_TEST_ONLY-lead",
            "--reason", "SCRIPTED_TEST_ONLY: tamper test reopen",
        ]).returncode, 0)

        def _eval_copies(**overrides):
            kwargs = {
                "demo1_dir": d1_rev_copy,
                "demo2_dir": self.d2_untouched,
                "demo3a_dir": self.d3a_orig,
                "m1_dir": self.m1_dir,
                "demo4_dir": self.d4_dir,
                "demo3b_dir": self.d3b_dir,
                "allowlisted_fp_dir": aq_rev_copy,
                "allowlisted_trusted_source_root": self.fixtures,
                "r03_fp_mode": "proposed-allowlisted-fp",
                "capture_relocation_mode": "pinned-original-capture",
                "demo1_trusted_scenario_root": d1_orig_copy,
                "demo1_trusted_capture_root": d1_orig_copy / "capture",
                "allowlisted_trusted_scenario_root": aq_orig_copy,
                "allowlisted_trusted_capture_root": aq_orig_copy / "capture",
                "allow_mock_primary": True,
            }
            kwargs.update(overrides)
            return evaluate_acceptance(**kwargs)

        self.assertEqual(_eval_copies()["overall_status"], "PASS")

        # Case 5a: Swap original scenario/capture pair
        rep_swap_d1 = _eval_copies(
            demo1_trusted_scenario_root=self.d2_untouched,
            demo1_trusted_capture_root=self.d2_untouched / "capture",
        )
        self.assertEqual(rep_swap_d1["overall_status"], "FAIL")
        self.assertEqual(rep_swap_d1["criteria"]["R02"]["status"], "FAIL")

        rep_swap_aq = _eval_copies(
            allowlisted_trusted_scenario_root=d1_orig_copy,
            allowlisted_trusted_capture_root=d1_orig_copy / "capture",
        )
        self.assertEqual(rep_swap_aq["overall_status"], "FAIL")
        self.assertEqual(rep_swap_aq["criteria"]["R03"]["status"], "FAIL")

        # Case 5b/c/d: Tamper JSON, SARIF, legacy_reports, SHA-256, cli-origin, or swap manifest
        def _assert_tampered(path: Path, mutator, criterion: str):
            orig_bytes = path.read_bytes()
            try:
                mutator(path)
                rep = _eval_copies()
                self.assertEqual(rep["overall_status"], "FAIL", path.name)
                self.assertEqual(rep["criteria"][criterion]["status"], "FAIL", rep["criteria"][criterion])
            finally:
                path.write_bytes(orig_bytes)

        _assert_tampered(
            d1_orig_copy / "capture" / "legacy_reports" / "semgrep.json",
            lambda p: p.write_bytes(p.read_bytes() + b" "),
            "R02",
        )
        _assert_tampered(
            aq_orig_copy / "capture" / "legacy_reports" / "semgrep.sarif",
            lambda p: p.write_bytes(p.read_bytes() + b" "),
            "R03",
        )
        rev_og = d1_rev_copy / "capture" / "opengrep.json"
        rev_man = d1_rev_copy / "capture" / "scan-manifest.json"
        orig_og = rev_og.read_bytes()
        orig_man = rev_man.read_bytes()
        try:
            mutated_og = orig_og + b"\n"
            rev_og.write_bytes(mutated_og)
            man_doc = json.loads(orig_man.decode("utf-8"))
            man_doc["artifacts"]["opengrep.json"] = digest(mutated_og)
            rev_man.write_text(json.dumps(man_doc, indent=2), encoding="utf-8")
            rep_sha_swap = _eval_copies()
            self.assertEqual(rep_sha_swap["overall_status"], "FAIL")
            self.assertEqual(rep_sha_swap["criteria"]["R02"]["status"], "FAIL")
        finally:
            rev_og.write_bytes(orig_og)
            rev_man.write_bytes(orig_man)

        _assert_tampered(
            aq_rev_copy / "capture" / "scan-manifest.json",
            lambda p: p.write_bytes((d1_orig_copy / "capture" / "scan-manifest.json").read_bytes()),
            "R03",
        )
        _assert_tampered(
            d1_rev_copy / "capture" / "cli-origin.json",
            lambda p: p.write_text(p.read_text(encoding="utf-8") + " ", encoding="utf-8"),
            "R02",
        )

    def test_05b_rejects_coordinated_triage_bundle_substitution_and_triage_tampers(self):
        # Generate authentic alternate triage runs B (different HTTP responses / timestamps / SQLite DBs)
        srv_b, endpoint_b = _start_mock_server("RUN_B_ALT")
        self.addCleanup(srv_b.server_close)
        self.addCleanup(srv_b.shutdown)

        d1_alt_b = self.tmp_root / "d1_alt_b"
        aq_alt_b = self.tmp_root / "aq_alt_b"
        for src_java, out_d in (
            (self.fixtures / "Demo1TruePositive.java", d1_alt_b),
            (self.fixtures / "AllowlistedQuery.java", aq_alt_b),
        ):
            self.assertEqual(_run_cli(self.prepared_source, [
                "scan", str(src_java),
                "--rules-path", str(self.rules),
                "--output-dir", str(out_d),
                "--executable", self.opengrep,
                "--local-triage",
                "--endpoint", endpoint_b,
                "--model", "qwen3.5:9b-q4_K_M",
                "--prompt-contract", "blind",
                "--runtime-origin", "mock",
            ]).returncode, 0)
            shutil.copy2(out_d / "triage" / "review.sqlite", out_d / "triage" / "review.post_ingestion.sqlite")

        # Complete valid confirm-true on d1_alt_b and confirm-false->reopen on aq_alt_b
        d1b_db = str(d1_alt_b / "triage" / "review.sqlite")
        d1b_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", d1b_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-true", d1b_id, "--db", d1b_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: valid lifecycle on alternate bundle B",
        ]).returncode, 0)

        aqb_db = str(aq_alt_b / "triage" / "review.sqlite")
        aqb_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", aqb_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-false", aqb_id, "--db", aqb_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: confirm-false on alternate bundle B",
        ]).returncode, 0)
        shutil.copy2(aq_alt_b / "triage" / "review.sqlite", aq_alt_b / "triage" / "review.after_confirm_false.sqlite")
        self.assertEqual(_run_cli(self.prepared_source, [
            "reopen", aqb_id, "--db", aqb_db,
            "--actor", "SCRIPTED_TEST_ONLY-lead",
            "--reason", "SCRIPTED_TEST_ONLY: reopen on alternate bundle B",
        ]).returncode, 0)

        # Attack 1: Keep genuine capture A on d1_attack, substitute g1-run-manifest.json + entire triage/* from B
        d1_attack = _copy_review_scenario(self.d1_review, self.tmp_root / "d1_coordinated_sub", strip_legacy_reports=False)
        shutil.copy2(d1_alt_b / "g1-run-manifest.json", d1_attack / "g1-run-manifest.json")
        if (d1_alt_b / "g1-cli-summary.json").exists():
            shutil.copy2(d1_alt_b / "g1-cli-summary.json", d1_attack / "g1-cli-summary.json")
        shutil.rmtree(d1_attack / "triage")
        shutil.copytree(d1_alt_b / "triage", d1_attack / "triage")

        rep_sub_d1 = evaluate_acceptance(
            demo1_dir=d1_attack,
            demo2_dir=self.d2_locked,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.d1_orig_pristine,
            demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_sub_d1["overall_status"], "FAIL", "Coordinated triage substitution B on capture A MUST fail")
        self.assertEqual(rep_sub_d1["criteria"]["R01"]["status"], "FAIL")
        self.assertEqual(rep_sub_d1["criteria"]["R02"]["status"], "FAIL")

        cli_sub_d1 = self.tmp_root / "cli_sub_d1.json"
        rc_sub_d1 = evaluate_main([
            "--demo1-dir", str(d1_attack),
            "--demo2-dir", str(self.d2_locked),
            "--demo3a-dir", str(self.d3a_orig),
            "--m1-dir", str(self.m1_dir),
            "--demo4-dir", str(self.d4_dir),
            "--demo3b-dir", str(self.d3b_dir),
            "--capture-relocation-mode", "pinned-original-capture",
            "--demo1-trusted-scenario-root", str(self.d1_orig_pristine),
            "--demo1-trusted-capture-root", str(self.d1_orig_pristine / "capture"),
            "--output", str(cli_sub_d1),
            "--allow-mock-primary",
        ])
        self.assertEqual(rc_sub_d1, 2)
        self.assertEqual(strict_json(cli_sub_d1.read_text(encoding="utf-8"))["overall_status"], "FAIL")

        # Attack 2: Coordinated triage substitution on AllowlistedQuery via API + CLI
        aq_attack = _copy_review_scenario(self.aq_review_stripped, self.tmp_root / "aq_coordinated_sub", strip_legacy_reports=False)
        shutil.copy2(aq_alt_b / "g1-run-manifest.json", aq_attack / "g1-run-manifest.json")
        if (aq_alt_b / "g1-cli-summary.json").exists():
            shutil.copy2(aq_alt_b / "g1-cli-summary.json", aq_attack / "g1-cli-summary.json")
        shutil.rmtree(aq_attack / "triage")
        shutil.copytree(aq_alt_b / "triage", aq_attack / "triage")

        rep_sub_aq = evaluate_acceptance(
            demo1_dir=self.d1_review,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=aq_attack,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.d1_orig_pristine,
            demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
            allowlisted_trusted_scenario_root=self.aq_orig_pristine,
            allowlisted_trusted_capture_root=self.aq_orig_pristine / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_sub_aq["overall_status"], "FAIL")
        self.assertEqual(rep_sub_aq["criteria"]["R03"]["status"], "FAIL")

        cli_sub_aq = self.tmp_root / "cli_sub_aq.json"
        rc_sub_aq = evaluate_main([
            "--demo1-dir", str(self.d1_review),
            "--demo2-dir", str(self.d2_untouched),
            "--demo3a-dir", str(self.d3a_orig),
            "--m1-dir", str(self.m1_dir),
            "--demo4-dir", str(self.d4_dir),
            "--demo3b-dir", str(self.d3b_dir),
            "--r03-fp-mode", "proposed-allowlisted-fp",
            "--allowlisted-fp-dir", str(aq_attack),
            "--allowlisted-trusted-source-root", str(self.fixtures),
            "--capture-relocation-mode", "pinned-original-capture",
            "--demo1-trusted-scenario-root", str(self.d1_orig_pristine),
            "--demo1-trusted-capture-root", str(self.d1_orig_pristine / "capture"),
            "--allowlisted-trusted-scenario-root", str(self.aq_orig_pristine),
            "--allowlisted-trusted-capture-root", str(self.aq_orig_pristine / "capture"),
            "--output", str(cli_sub_aq),
            "--allow-mock-primary",
        ])
        self.assertEqual(rc_sub_aq, 2)

        # Single-file triage & raw HTTP parity tampers (whitespace / body byte / pre-review DB / rogue file)
        d1_single = _copy_review_scenario(self.d1_review, self.tmp_root / "d1_single_tamper", strip_legacy_reports=False)
        first_resp_bin = next((d1_single / "triage" / "llm_io").glob("*.response.body.bin"))
        single_targets: list[Path] = [
            d1_single / "g1-run-manifest.json",
            d1_single / "triage" / "assessments.jsonl",
            d1_single / "triage" / "http-capture-check.json",
            d1_single / "triage" / "review.post_ingestion.sqlite",
            first_resp_bin,
        ]
        if (d1_single / "g1-cli-summary.json").exists():
            single_targets.append(d1_single / "g1-cli-summary.json")
        for target_p in single_targets:
            orig_b = target_p.read_bytes()
            try:
                if target_p.suffix == ".sqlite":
                    shutil.copy2(d1_single / "triage" / "review.sqlite", target_p)
                else:
                    target_p.write_bytes(orig_b + b" ")
                rep_t = evaluate_acceptance(
                    demo1_dir=d1_single,
                    demo2_dir=self.d2_locked,
                    demo3a_dir=self.d3a_orig,
                    m1_dir=self.m1_dir,
                    demo4_dir=self.d4_dir,
                    demo3b_dir=self.d3b_dir,
                    capture_relocation_mode="pinned-original-capture",
                    demo1_trusted_scenario_root=self.d1_orig_pristine,
                    demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
                    allow_mock_primary=True,
                )
                self.assertEqual(rep_t["overall_status"], "FAIL", target_p.name)
                self.assertEqual(rep_t["criteria"]["R02"]["status"], "FAIL", target_p.name)
            finally:
                target_p.write_bytes(orig_b)

        # Unexpected extra file in triage/ MUST fail closed
        rogue_file = d1_single / "triage" / "rogue.txt"
        rogue_file.write_text("rogue", encoding="utf-8")
        try:
            rep_rogue = evaluate_acceptance(
                demo1_dir=d1_single,
                demo2_dir=self.d2_locked,
                demo3a_dir=self.d3a_orig,
                m1_dir=self.m1_dir,
                demo4_dir=self.d4_dir,
                demo3b_dir=self.d3b_dir,
                capture_relocation_mode="pinned-original-capture",
                demo1_trusted_scenario_root=self.d1_orig_pristine,
                demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
                allow_mock_primary=True,
            )
            self.assertEqual(rep_rogue["overall_status"], "FAIL")
        finally:
            rogue_file.unlink()

    def test_05c_coordinated_qwen_substitution_with_consistent_scanner_manifest(self):
        """D4: Two internally valid scenarios A and B with consistent scanner captures/manifests;
        B passes on its own and passes pinned-to-B, coordinated attack (capture A + triage B +
        reconciled scanner manifest) passes strict-in-place (zero scanner errors) yet FAILS
        relocation provenance when pinned to original A."""
        srv_b, endpoint_b = _start_mock_server("RUN_B_CONSISTENT")
        self.addCleanup(srv_b.server_close)
        self.addCleanup(srv_b.shutdown)

        # Pre-scan in-place base directories BEFORE scanning B so their scan/ingestion
        # timestamps strictly precede triage B and review B timestamps.
        d1_coord_inplace = self.tmp_root / "d1_coord_inplace"
        aq_coord_inplace = self.tmp_root / "aq_coord_inplace"
        for src_java, out_d in (
            (self.fixtures / "Demo1TruePositive.java", d1_coord_inplace),
            (self.fixtures / "AllowlistedQuery.java", aq_coord_inplace),
        ):
            self.assertEqual(_run_cli(self.prepared_source, [
                "scan", str(src_java),
                "--rules-path", str(self.rules),
                "--output-dir", str(out_d),
                "--executable", self.opengrep,
                "--local-triage",
                "--endpoint", self.endpoint,
                "--model", "qwen3.5:9b-q4_K_M",
                "--prompt-contract", "blind",
                "--runtime-origin", "mock",
            ]).returncode, 0)
            shutil.copy2(out_d / "triage" / "review.sqlite", out_d / "triage" / "review.post_ingestion.sqlite")

        d1_b_orig = self.tmp_root / "d1_b_orig"
        aq_b_orig = self.tmp_root / "aq_b_orig"
        for src_java, out_d in (
            (self.fixtures / "Demo1TruePositive.java", d1_b_orig),
            (self.fixtures / "AllowlistedQuery.java", aq_b_orig),
        ):
            self.assertEqual(_run_cli(self.prepared_source, [
                "scan", str(src_java),
                "--rules-path", str(self.rules),
                "--output-dir", str(out_d),
                "--executable", self.opengrep,
                "--local-triage",
                "--endpoint", endpoint_b,
                "--model", "qwen3.5:9b-q4_K_M",
                "--prompt-contract", "blind",
                "--runtime-origin", "mock",
            ]).returncode, 0)
            shutil.copy2(out_d / "triage" / "review.sqlite", out_d / "triage" / "review.post_ingestion.sqlite")

        d1_b_rev = _copy_review_scenario(d1_b_orig, self.tmp_root / "d1_b_rev", strip_legacy_reports=True)
        d1b_db = str(d1_b_rev / "triage" / "review.sqlite")
        d1b_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", d1b_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-true", d1b_id, "--db", d1b_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: valid confirm-true on scenario B",
        ]).returncode, 0)

        aq_b_rev = _copy_review_scenario(aq_b_orig, self.tmp_root / "aq_b_rev", strip_legacy_reports=True)
        aqb_db = str(aq_b_rev / "triage" / "review.sqlite")
        aqb_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", aqb_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-false", aqb_id, "--db", aqb_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: valid confirm-false on scenario B",
        ]).returncode, 0)
        shutil.copy2(aq_b_rev / "triage" / "review.sqlite", aq_b_rev / "triage" / "review.after_confirm_false.sqlite")
        self.assertEqual(_run_cli(self.prepared_source, [
            "reopen", aqb_id, "--db", aqb_db,
            "--actor", "SCRIPTED_TEST_ONLY-lead",
            "--reason", "SCRIPTED_TEST_ONLY: valid reopen on scenario B",
        ]).returncode, 0)

        # 1. Verify B passes relocation checks cleanly when pinned to its own original B
        rep_b_pinned = evaluate_acceptance(
            demo1_dir=d1_b_rev,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=aq_b_rev,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=d1_b_orig,
            demo1_trusted_capture_root=d1_b_orig / "capture",
            allowlisted_trusted_scenario_root=aq_b_orig,
            allowlisted_trusted_capture_root=aq_b_orig / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_b_pinned["overall_status"], "PASS", rep_b_pinned["criteria"])

        # 2. Verify B has zero independent scanner/hash errors (strict-in-place on d1_b_orig / aq_b_orig)
        shutil.copy2(d1_b_rev / "triage" / "review.sqlite", d1_b_orig / "triage" / "review.sqlite")
        shutil.copy2(aq_b_rev / "triage" / "review.sqlite", aq_b_orig / "triage" / "review.sqlite")
        shutil.copy2(aq_b_rev / "triage" / "review.after_confirm_false.sqlite", aq_b_orig / "triage" / "review.after_confirm_false.sqlite")

        rep_b_inplace = evaluate_acceptance(
            demo1_dir=d1_b_orig,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=aq_b_orig,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="strict-in-place",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_b_inplace["overall_status"], "PASS", rep_b_inplace["criteria"])

        # Helper: replace dst_dir/triage with triage B and reconcile dst_dir/g1-run-manifest.json
        def _apply_coordinated_triage_b(
            dst_dir: Path,
            alt_b_rev: Path,
            *,
            after_false: bool,
        ) -> Path:
            cap_a = dst_dir / "capture"
            shutil.rmtree(dst_dir / "triage")
            if (cap_a / "opengrep.json").read_bytes() == (alt_b_rev / "capture" / "opengrep.json").read_bytes():
                shutil.copytree(alt_b_rev / "triage", dst_dir / "triage")
                triage_recorded_at = json.loads((alt_b_rev / "g1-run-manifest.json").read_text(encoding="utf-8"))["recorded_at"]
            else:
                from datetime import datetime, timezone
                from types import SimpleNamespace
                from v2.triage import cli as triage_cli, live_check, verify_http_capture
                from v2.g1_integration.bridge import derive_trusted_path_maps

                src_root = Path(json.loads((dst_dir / "g1-run-manifest.json").read_text(encoding="utf-8"))["source_root"])
                triage_args = SimpleNamespace(
                    source_root=str(src_root),
                    output_dir=str(dst_dir / "triage"),
                    json=str(cap_a / "opengrep.json"),
                    scan_manifest=cap_a / "scan-manifest.json",
                    path_base=None,
                    path_map=list(derive_trusted_path_maps(src_root)),
                    engine_exit=None,
                    rules=str(self.rules),
                    executable=self.opengrep,
                    no_llm=False,
                    mode="evidence+llm",
                    prompt_contract="blind",
                    checkpoint=None,
                    endpoint=endpoint_b,
                    model="qwen3.5:9b-q4_K_M",
                    timeout=30.0,
                    runtime_origin="mock",
                )
                triage_cli.run(triage_args)
                triage_recorded_at = datetime.now(timezone.utc).isoformat()
                rows_b = [
                    strict_json(ln)
                    for ln in (dst_dir / "triage" / "assessments.jsonl").read_text(encoding="utf-8").splitlines()
                    if ln.strip()
                ]
                (dst_dir / "triage" / "live-protocol-check.json").write_text(
                    json.dumps(live_check.inspect(rows_b, minimum=max(1, len(rows_b))), indent=2),
                    encoding="utf-8",
                )
                (dst_dir / "triage" / "http-capture-check.json").write_text(
                    json.dumps(verify_http_capture.verify_run_http_captures(dst_dir / "triage", require_live_chat=False), indent=2) + "\n",
                    encoding="utf-8",
                )
                shutil.copy2(dst_dir / "triage" / "review.sqlite", dst_dir / "triage" / "review.post_ingestion.sqlite")
                db_p = str(dst_dir / "triage" / "review.sqlite")
                wid = json.loads(_run_cli(self.prepared_source, ["queue", "--db", db_p]).stdout)["warnings"][0]["id"]
                if after_false:
                    _run_cli(self.prepared_source, ["confirm-false", wid, "--db", db_p, "--actor", "SCRIPTED_TEST_ONLY-op", "--reason", "SCRIPTED_TEST_ONLY: b"])
                    shutil.copy2(dst_dir / "triage" / "review.sqlite", dst_dir / "triage" / "review.after_confirm_false.sqlite")
                    _run_cli(self.prepared_source, ["reopen", wid, "--db", db_p, "--actor", "SCRIPTED_TEST_ONLY-lead", "--reason", "SCRIPTED_TEST_ONLY: b"])
                else:
                    _run_cli(self.prepared_source, ["confirm-true", wid, "--db", db_p, "--actor", "SCRIPTED_TEST_ONLY-op", "--reason", "SCRIPTED_TEST_ONLY: b"])

            man_a = json.loads((dst_dir / "g1-run-manifest.json").read_text(encoding="utf-8"))
            man_a["recorded_at"] = triage_recorded_at
            # Reconcile scanner + triage manifest entries to dst_dir so zero local manifest/hash mismatches exist
            for k in ("opengrep_json", "opengrep_sarif", "scan_manifest", "cli_origin"):
                man_a["artifacts"][k] = {
                    "path": str(cap_a / Path(man_a["artifacts"][k]["path"]).name),
                    "sha256": digest((cap_a / Path(man_a["artifacts"][k]["path"]).name).read_bytes()),
                }
            for k, rel_t in (
                ("evidence_json", "evidence.json"),
                ("assessments_jsonl", "assessments.jsonl"),
                ("http_capture_check", "http-capture-check.json"),
                ("review_sqlite", "review.post_ingestion.sqlite"),
            ):
                man_a["artifacts"][k] = {
                    "path": str(dst_dir / "triage" / ("review.sqlite" if k == "review_sqlite" else rel_t)),
                    "sha256": digest((dst_dir / "triage" / rel_t).read_bytes()),
                }
            (dst_dir / "g1-run-manifest.json").write_text(
                json.dumps(man_a, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return dst_dir

        # 3a. Prove the coordinated capture + substituted-triage attack PASSES strict-in-place
        #     (existing local scanner/manifest/hash checks do NOT catch it!)
        _apply_coordinated_triage_b(d1_coord_inplace, d1_b_rev, after_false=False)
        _apply_coordinated_triage_b(aq_coord_inplace, aq_b_rev, after_false=True)

        rep_coord_inplace = evaluate_acceptance(
            demo1_dir=d1_coord_inplace,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=aq_coord_inplace,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="strict-in-place",
            allow_mock_primary=True,
        )
        self.assertEqual(
            rep_coord_inplace["overall_status"],
            "PASS",
            f"Consistent attack must pass strict-in-place to isolate relocation provenance check: {rep_coord_inplace['criteria']}",
        )

        # 3b. Coordinated capture A + triage B on relocated review copy pinned to Original A
        #     MUST FAIL solely on provenance, with zero scanner_manifest/opengrep_json/local artifact errors
        d1_coord = _copy_review_scenario(self.d1_orig_pristine, self.tmp_root / "d1_coord_consistent", strip_legacy_reports=True)
        aq_coord = _copy_review_scenario(self.aq_orig_pristine, self.tmp_root / "aq_coord_consistent", strip_legacy_reports=True)
        _apply_coordinated_triage_b(d1_coord, d1_b_rev, after_false=False)
        _apply_coordinated_triage_b(aq_coord, aq_b_rev, after_false=True)

        rep_coord_d1 = evaluate_acceptance(
            demo1_dir=d1_coord,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.d1_orig_pristine,
            demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_coord_d1["overall_status"], "FAIL")
        self.assertEqual(rep_coord_d1["criteria"]["R01"]["status"], "FAIL")
        self.assertEqual(rep_coord_d1["criteria"]["R02"]["status"], "FAIL")
        d1_errs = rep_coord_d1["criteria"]["R02"]["failures"]
        self.assertTrue(any("diverges from pinned original" in e for e in d1_errs), d1_errs)
        self.assertTrue(any("triage/llm_io raw capture file" in e or "triage pre-review artifact" in e for e in d1_errs), d1_errs)
        self.assertFalse(any("scan_manifest.sha256 mismatch" in e or "opengrep_json.sha256 mismatch" in e for e in d1_errs), d1_errs)
        self.assertFalse(any("engine_output_path escapes capture dir" in e or "sha256 mismatch" in e for e in d1_errs), d1_errs)

        cli_coord_out = self.tmp_root / "cli_coord_consistent.json"
        rc_coord = evaluate_main([
            "--demo1-dir", str(d1_coord),
            "--demo2-dir", str(self.d2_untouched),
            "--demo3a-dir", str(self.d3a_orig),
            "--m1-dir", str(self.m1_dir),
            "--demo4-dir", str(self.d4_dir),
            "--demo3b-dir", str(self.d3b_dir),
            "--r03-fp-mode", "proposed-allowlisted-fp",
            "--allowlisted-fp-dir", str(aq_coord),
            "--allowlisted-trusted-source-root", str(self.fixtures),
            "--capture-relocation-mode", "pinned-original-capture",
            "--demo1-trusted-scenario-root", str(self.d1_orig_pristine),
            "--demo1-trusted-capture-root", str(self.d1_orig_pristine / "capture"),
            "--allowlisted-trusted-scenario-root", str(self.aq_orig_pristine),
            "--allowlisted-trusted-capture-root", str(self.aq_orig_pristine / "capture"),
            "--output", str(cli_coord_out),
            "--allow-mock-primary",
        ])
        self.assertEqual(rc_coord, 2)
        cli_doc = strict_json(cli_coord_out.read_text(encoding="utf-8"))
        self.assertEqual(cli_doc["overall_status"], "FAIL")
        self.assertEqual(cli_doc["criteria"]["R03"]["status"], "FAIL")
        aq_errs = cli_doc["scenarios"]["allowlisted_query_fp_control"]["r03_errors"]
        self.assertTrue(any("diverges from pinned original" in e for e in aq_errs), aq_errs)
        self.assertFalse(any("engine_output_path escapes capture dir" in e or "sha256 mismatch" in e for e in aq_errs), aq_errs)

    def test_05d_rejects_post_ingestion_sqlite_sidecars_and_missing_files_in_relocation(self):
        """D3: Reject review.post_ingestion.sqlite-wal and -shm (both empty and non-empty)
        on both original scenario and review copy, while preserving valid post-review sidecars
        and default strict-in-place behavior."""
        d1_orig_copy = self.tmp_root / "d1_orig_sidecar"
        aq_orig_copy = self.tmp_root / "aq_orig_sidecar"
        for src_java, out_d in (
            (self.fixtures / "Demo1TruePositive.java", d1_orig_copy),
            (self.fixtures / "AllowlistedQuery.java", aq_orig_copy),
        ):
            self.assertEqual(_run_cli(self.prepared_source, [
                "scan", str(src_java),
                "--rules-path", str(self.rules),
                "--output-dir", str(out_d),
                "--executable", self.opengrep,
                "--local-triage",
                "--endpoint", self.endpoint,
                "--model", "qwen3.5:9b-q4_K_M",
                "--prompt-contract", "blind",
                "--runtime-origin", "mock",
            ]).returncode, 0)
            shutil.copy2(out_d / "triage" / "review.sqlite", out_d / "triage" / "review.post_ingestion.sqlite")

        d1_rev_copy = _copy_review_scenario(d1_orig_copy, self.tmp_root / "d1_rev_sidecar", strip_legacy_reports=True)
        d1_db = str(d1_rev_copy / "triage" / "review.sqlite")
        d1_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", d1_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-true", d1_id, "--db", d1_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: sidecar baseline confirm-true",
        ]).returncode, 0)

        aq_rev_copy = _copy_review_scenario(aq_orig_copy, self.tmp_root / "aq_rev_sidecar", strip_legacy_reports=True)
        aq_db = str(aq_rev_copy / "triage" / "review.sqlite")
        aq_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", aq_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-false", aq_id, "--db", aq_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: sidecar baseline confirm-false",
        ]).returncode, 0)
        shutil.copy2(aq_rev_copy / "triage" / "review.sqlite", aq_rev_copy / "triage" / "review.after_confirm_false.sqlite")
        self.assertEqual(_run_cli(self.prepared_source, [
            "reopen", aq_id, "--db", aq_db,
            "--actor", "SCRIPTED_TEST_ONLY-lead",
            "--reason", "SCRIPTED_TEST_ONLY: sidecar baseline reopen",
        ]).returncode, 0)

        def _eval_side(**overrides):
            kwargs = {
                "demo1_dir": d1_rev_copy,
                "demo2_dir": self.d2_untouched,
                "demo3a_dir": self.d3a_orig,
                "m1_dir": self.m1_dir,
                "demo4_dir": self.d4_dir,
                "demo3b_dir": self.d3b_dir,
                "allowlisted_fp_dir": aq_rev_copy,
                "allowlisted_trusted_source_root": self.fixtures,
                "r03_fp_mode": "proposed-allowlisted-fp",
                "capture_relocation_mode": "pinned-original-capture",
                "demo1_trusted_scenario_root": d1_orig_copy,
                "demo1_trusted_capture_root": d1_orig_copy / "capture",
                "allowlisted_trusted_scenario_root": aq_orig_copy,
                "allowlisted_trusted_capture_root": aq_orig_copy / "capture",
                "allow_mock_primary": True,
            }
            kwargs.update(overrides)
            return evaluate_acceptance(**kwargs)

        self.assertEqual(_eval_side()["overall_status"], "PASS")

        # 1. Empty & non-empty -wal / -shm on review.post_ingestion.sqlite in both original & review copy MUST FAIL
        sidecar_cases = [
            (d1_rev_copy / "triage" / "review.post_ingestion.sqlite-shm", b"", "R02"),
            (d1_rev_copy / "triage" / "review.post_ingestion.sqlite-shm", b"ARBITRARY_SHM_BYTES", "R02"),
            (d1_rev_copy / "triage" / "review.post_ingestion.sqlite-wal", b"", "R02"),
            (d1_rev_copy / "triage" / "review.post_ingestion.sqlite-wal", b"WAL_BYTES", "R02"),
            (d1_orig_copy / "triage" / "review.post_ingestion.sqlite-shm", b"", "R02"),
            (d1_orig_copy / "triage" / "review.post_ingestion.sqlite-wal", b"WAL_BYTES", "R02"),
            (aq_rev_copy / "triage" / "review.post_ingestion.sqlite-shm", b"ARBITRARY_SHM_BYTES", "R03"),
            (aq_orig_copy / "triage" / "review.post_ingestion.sqlite-wal", b"", "R03"),
        ]
        for side_path, payload, crit in sidecar_cases:
            with self.subTest(sidecar=str(side_path.relative_to(self.tmp_root)), size=len(payload)):
                side_path.write_bytes(payload)
                try:
                    rep = _eval_side()
                    self.assertEqual(rep["overall_status"], "FAIL")
                    self.assertEqual(rep["criteria"][crit]["status"], "FAIL")
                    errs = rep["criteria"][crit]["failures"]
                    self.assertTrue(
                        any("forbidden ingestion snapshot SQLite sidecar" in e and side_path.name in e for e in errs),
                        errs,
                    )
                finally:
                    side_path.unlink()

        # Verify CLI main also rejects review.post_ingestion.sqlite-shm with exit code 2
        cli_shm_path = d1_rev_copy / "triage" / "review.post_ingestion.sqlite-shm"
        cli_shm_path.write_bytes(b"ROGUE_SHM")
        try:
            cli_out = self.tmp_root / "cli_sidecar_reject.json"
            rc = evaluate_main([
                "--demo1-dir", str(d1_rev_copy),
                "--demo2-dir", str(self.d2_untouched),
                "--demo3a-dir", str(self.d3a_orig),
                "--m1-dir", str(self.m1_dir),
                "--demo4-dir", str(self.d4_dir),
                "--demo3b-dir", str(self.d3b_dir),
                "--r03-fp-mode", "proposed-allowlisted-fp",
                "--allowlisted-fp-dir", str(aq_rev_copy),
                "--allowlisted-trusted-source-root", str(self.fixtures),
                "--capture-relocation-mode", "pinned-original-capture",
                "--demo1-trusted-scenario-root", str(d1_orig_copy),
                "--demo1-trusted-capture-root", str(d1_orig_copy / "capture"),
                "--allowlisted-trusted-scenario-root", str(aq_orig_copy),
                "--allowlisted-trusted-capture-root", str(aq_orig_copy / "capture"),
                "--output", str(cli_out),
                "--allow-mock-primary",
            ])
            self.assertEqual(rc, 2)
            self.assertEqual(strict_json(cli_out.read_text(encoding="utf-8"))["overall_status"], "FAIL")
        finally:
            cli_shm_path.unlink()

        # 2. Missing mandatory immutable files on original or review copy MUST fail closed
        for miss_p, crit in (
            (d1_rev_copy / "triage" / "review.post_ingestion.sqlite", "R02"),
            (d1_orig_copy / "triage" / "review.post_ingestion.sqlite", "R02"),
            (aq_rev_copy / "triage" / "input.opengrep.json", "R03"),
        ):
            orig_b = miss_p.read_bytes()
            miss_p.unlink()
            try:
                rep_m = _eval_side()
                self.assertEqual(rep_m["overall_status"], "FAIL", miss_p.name)
                self.assertEqual(rep_m["criteria"][crit]["status"], "FAIL", miss_p.name)
            finally:
                miss_p.write_bytes(orig_b)

        # 3. Valid post-review mutable empty sidecars on review.sqlite & review.after_confirm_false.sqlite remain allowed
        valid_mutable_sidecars = [
            d1_rev_copy / "triage" / "review.sqlite-shm",
            d1_rev_copy / "triage" / "review.sqlite-wal",
            aq_rev_copy / "triage" / "review.after_confirm_false.sqlite-shm",
            aq_rev_copy / "triage" / "review.after_confirm_false.sqlite-wal",
        ]
        try:
            for mp in valid_mutable_sidecars:
                mp.write_bytes(b"")
            rep_mut = _eval_side()
            self.assertEqual(rep_mut["overall_status"], "PASS", rep_mut["criteria"])
        finally:
            for mp in valid_mutable_sidecars:
                if mp.exists():
                    mp.unlink()

        # 4. Default strict-in-place behavior (non-relocation) remains unchanged
        d1_orig_db = str(d1_orig_copy / "triage" / "review.sqlite")
        d1_orig_wid = json.loads(_run_cli(self.prepared_source, ["queue", "--db", d1_orig_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-true", d1_orig_wid, "--db", d1_orig_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: in-place sidecar compatibility check",
        ]).returncode, 0)
        (d1_orig_copy / "triage" / "review.post_ingestion.sqlite-shm").write_bytes(b"")
        rep_inplace = evaluate_acceptance(
            demo1_dir=d1_orig_copy,
            demo2_dir=self.d2_locked,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            capture_relocation_mode="strict-in-place",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_inplace["overall_status"], "PASS", rep_inplace["criteria"])

    def test_06_blocks_traversal_output_inside_pins_and_source_drift_in_relocation(self):
        # 6a: '..' traversal in trusted scenario or capture root
        for bad_scen, bad_cap in (
            (self.d1_orig_pristine / ".." / self.d1_orig_pristine.name, self.d1_orig_pristine / "capture"),
            (self.d1_orig_pristine, self.d1_orig_pristine / "capture" / ".." / "capture"),
        ):
            rep_trav = evaluate_acceptance(
                demo1_dir=self.d1_review,
                demo2_dir=self.d2_locked,
                demo3a_dir=self.d3a_orig,
                m1_dir=self.m1_dir,
                demo4_dir=self.d4_dir,
                capture_relocation_mode="pinned-original-capture",
                demo1_trusted_scenario_root=bad_scen,
                demo1_trusted_capture_root=bad_cap,
                allow_mock_primary=True,
            )
            self.assertEqual(rep_trav["overall_status"], "FAIL")
            self.assertEqual(rep_trav["criteria"]["R02"]["status"], "FAIL")

        # 6b: '--output' inside pinned original scenario or capture root MUST be blocked by CLI
        for sneaky_out in (
            self.d1_orig_pristine / "sneaky_out.json",
            self.d1_orig_pristine / "capture" / "sneaky_out.json",
        ):
            with self.assertRaises(SystemExit):
                evaluate_main([
                    "--demo1-dir", str(self.d1_review),
                    "--demo2-dir", str(self.d2_locked),
                    "--demo3a-dir", str(self.d3a_orig),
                    "--m1-dir", str(self.m1_dir),
                    "--demo4-dir", str(self.d4_dir),
                    "--capture-relocation-mode", "pinned-original-capture",
                    "--demo1-trusted-scenario-root", str(self.d1_orig_pristine),
                    "--demo1-trusted-capture-root", str(self.d1_orig_pristine / "capture"),
                    "--output", str(sneaky_out),
                    "--allow-mock-primary",
                ])

        # 6c: Live source drift on disk after scan MUST fail closed even in relocated review mode
        mutable_src_dir = self.tmp_root / "mutable_allowq_src"
        mutable_src_dir.mkdir()
        mutable_java = mutable_src_dir / "AllowlistedQuery.java"
        shutil.copy2(self.fixtures / "AllowlistedQuery.java", mutable_java)

        aq_drift_orig = self.tmp_root / "aq_drift_orig"
        self.assertEqual(_run_cli(self.prepared_source, [
            "scan", str(mutable_java),
            "--rules-path", str(self.rules),
            "--output-dir", str(aq_drift_orig),
            "--executable", self.opengrep,
            "--local-triage",
            "--endpoint", self.endpoint,
            "--model", "qwen3.5:9b-q4_K_M",
            "--prompt-contract", "blind",
            "--runtime-origin", "mock",
        ]).returncode, 0)
        shutil.copy2(aq_drift_orig / "triage" / "review.sqlite", aq_drift_orig / "triage" / "review.post_ingestion.sqlite")
        aq_drift_rev = _copy_review_scenario(aq_drift_orig, self.tmp_root / "aq_drift_rev", strip_legacy_reports=True)
        aq_db = str(aq_drift_rev / "triage" / "review.sqlite")
        aq_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", aq_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-false", aq_id, "--db", aq_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: pre-drift confirm-false",
        ]).returncode, 0)
        shutil.copy2(aq_drift_rev / "triage" / "review.sqlite", aq_drift_rev / "triage" / "review.after_confirm_false.sqlite")
        self.assertEqual(_run_cli(self.prepared_source, [
            "reopen", aq_id, "--db", aq_db,
            "--actor", "SCRIPTED_TEST_ONLY-lead",
            "--reason", "SCRIPTED_TEST_ONLY: pre-drift reopen",
        ]).returncode, 0)

        rep_clean = evaluate_acceptance(
            demo1_dir=self.d1_review,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=aq_drift_rev,
            allowlisted_trusted_source_root=mutable_src_dir,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.d1_orig_pristine,
            demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
            allowlisted_trusted_scenario_root=aq_drift_orig,
            allowlisted_trusted_capture_root=aq_drift_orig / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_clean["overall_status"], "PASS", rep_clean["criteria"])

        mutable_java.write_text(mutable_java.read_text(encoding="utf-8") + "\n// DRIFT_TEST\n", encoding="utf-8")
        rep_drift = evaluate_acceptance(
            demo1_dir=self.d1_review,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=aq_drift_rev,
            allowlisted_trusted_source_root=mutable_src_dir,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.d1_orig_pristine,
            demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
            allowlisted_trusted_scenario_root=aq_drift_orig,
            allowlisted_trusted_capture_root=aq_drift_orig / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_drift["overall_status"], "FAIL")
        self.assertEqual(rep_drift["criteria"]["R03"]["status"], "FAIL")

    def test_06b_junction_and_symlink_reparse_links_rejected_or_explicitly_skipped(self):
        # Never silently pass if host cannot create directory junctions/symlinks; raise SkipTest explicitly
        junc_holder = self.tmp_root / "junc_holder"
        junc_holder.mkdir()
        junc_link = junc_holder / "linked_orig"
        if not _make_dir_link(junc_link, self.d1_orig_pristine):
            self.skipTest("BLOCKED/SKIP: host environment cannot create directory junction/symlink")
        try:
            rep_junc = evaluate_acceptance(
                demo1_dir=self.d1_review,
                demo2_dir=self.d2_locked,
                demo3a_dir=self.d3a_orig,
                m1_dir=self.m1_dir,
                demo4_dir=self.d4_dir,
                capture_relocation_mode="pinned-original-capture",
                demo1_trusted_scenario_root=junc_link,
                demo1_trusted_capture_root=junc_link / "capture",
                allow_mock_primary=True,
            )
            self.assertEqual(rep_junc["overall_status"], "FAIL")
            self.assertEqual(rep_junc["criteria"]["R02"]["status"], "FAIL")
        finally:
            _remove_dir_link(junc_link)

        d1_rev_junc_copy = _copy_review_scenario(self.d1_review, self.tmp_root / "d1_rev_junc", strip_legacy_reports=True)
        rev_leg_link = d1_rev_junc_copy / "capture" / "legacy_reports"
        if not _make_dir_link(rev_leg_link, self.d1_orig_pristine / "capture" / "legacy_reports"):
            self.skipTest("BLOCKED/SKIP: host environment cannot create review legacy_reports junction/symlink")
        try:
            rep_rev_junc = evaluate_acceptance(
                demo1_dir=d1_rev_junc_copy,
                demo2_dir=self.d2_locked,
                demo3a_dir=self.d3a_orig,
                m1_dir=self.m1_dir,
                demo4_dir=self.d4_dir,
                capture_relocation_mode="pinned-original-capture",
                demo1_trusted_scenario_root=self.d1_orig_pristine,
                demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
                allow_mock_primary=True,
            )
            self.assertEqual(rep_rev_junc["overall_status"], "FAIL")
            self.assertEqual(rep_rev_junc["criteria"]["R02"]["status"], "FAIL")
        finally:
            _remove_dir_link(rev_leg_link)

        # Reparse link inside review triage/llm_io MUST also fail closed
        d1_llm_junc_copy = _copy_review_scenario(self.d1_review, self.tmp_root / "d1_llm_junc", strip_legacy_reports=True)
        shutil.rmtree(d1_llm_junc_copy / "triage" / "llm_io")
        llm_link = d1_llm_junc_copy / "triage" / "llm_io"
        if not _make_dir_link(llm_link, self.d1_orig_pristine / "triage" / "llm_io"):
            self.skipTest("BLOCKED/SKIP: host environment cannot create triage/llm_io junction/symlink")
        try:
            rep_llm_junc = evaluate_acceptance(
                demo1_dir=d1_llm_junc_copy,
                demo2_dir=self.d2_locked,
                demo3a_dir=self.d3a_orig,
                m1_dir=self.m1_dir,
                demo4_dir=self.d4_dir,
                capture_relocation_mode="pinned-original-capture",
                demo1_trusted_scenario_root=self.d1_orig_pristine,
                demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
                allow_mock_primary=True,
            )
            self.assertEqual(rep_llm_junc["overall_status"], "FAIL")
            self.assertEqual(rep_llm_junc["criteria"]["R02"]["status"], "FAIL")
        finally:
            _remove_dir_link(llm_link)

    def test_06c_post_ingestion_sidecar_reparse_link_rejected_or_explicitly_skipped(self):
        """D3 symlink/junction check on review.post_ingestion.sqlite-wal / -shm."""
        d1_rev_sym = _copy_review_scenario(self.d1_review, self.tmp_root / "d1_rev_side_sym", strip_legacy_reports=True)
        dummy_target = self.tmp_root / "dummy_sidecar_target.bin"
        dummy_target.write_bytes(b"SYMLINK_TARGET")
        shm_link = d1_rev_sym / "triage" / "review.post_ingestion.sqlite-shm"
        if not _make_file_link(shm_link, dummy_target):
            self.skipTest("BLOCKED/SKIP: host environment cannot create file symlink for SQLite sidecar")
        try:
            rep_sym = evaluate_acceptance(
                demo1_dir=d1_rev_sym,
                demo2_dir=self.d2_locked,
                demo3a_dir=self.d3a_orig,
                m1_dir=self.m1_dir,
                demo4_dir=self.d4_dir,
                capture_relocation_mode="pinned-original-capture",
                demo1_trusted_scenario_root=self.d1_orig_pristine,
                demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
                allow_mock_primary=True,
            )
            self.assertEqual(rep_sym["overall_status"], "FAIL")
            self.assertEqual(rep_sym["criteria"]["R02"]["status"], "FAIL")
        finally:
            _remove_file_link(shm_link)

    def test_07_r01_preserves_4_historical_qwen_calls_and_blocks_mock_synthetic_official_mode(self):
        rep_reloc = evaluate_acceptance(
            demo1_dir=self.d1_review,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=self.aq_review_stripped,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.d1_orig_pristine,
            demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
            allowlisted_trusted_scenario_root=self.aq_orig_pristine,
            allowlisted_trusted_capture_root=self.aq_orig_pristine / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_reloc["criteria"]["R01"]["status"], "PASS")
        self.assertEqual(rep_reloc["real_qwen_denominator"]["expected"], 4)
        self.assertEqual(rep_reloc["real_qwen_denominator"]["observed"], 4)
        self.assertEqual(
            rep_reloc["real_qwen_denominator"]["breakdown"],
            {"demo1_true_positive": 2, "demo2_protected_false_positive": 1, "demo3a_missing_helper": 1},
        )
        self.assertEqual(
            set(rep_reloc["real_qwen_denominator"]["excluded_auxiliary_controls"]),
            {"m1_scan_only", "demo3b_malformed_json_mock", "demo4_stale_source", "allowlisted_query_fp_control"},
        )

        # Official mode (allow_mock_primary=False) MUST reject mock/scripted captures even when relocated validly
        rep_official_mock = evaluate_acceptance(
            demo1_dir=self.d1_review,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=self.aq_review_stripped,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.d1_orig_pristine,
            demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
            allowlisted_trusted_scenario_root=self.aq_orig_pristine,
            allowlisted_trusted_capture_root=self.aq_orig_pristine / "capture",
            allow_mock_primary=False,
        )
        self.assertNotEqual(rep_official_mock["overall_status"], "PASS")
        self.assertEqual(rep_official_mock["criteria"]["R01"]["status"], "BLOCKED")
        self.assertEqual(rep_official_mock["criteria"]["R03"]["status"], "FAIL")

    def test_08_p11_historical_runbook_contract_and_cross_session_rejection(self):
        """D1 + D2: Verify P11_HISTORICAL_READ_ONLY_ACCEPTANCE runbook block is standalone,
        never inherits P1-P10 fresh-scan variables, never invokes scan/Ollama/confirm/reopen,
        accepts valid historical-shaped bindings, and rejects cross-session mixing."""
        plan_path = REPO_ROOT / "v2" / "g1_integration" / "RUNTIME_ACCEPTANCE_PLAN.md"
        plan_bytes = plan_path.read_bytes()
        self.assertNotIn(b"\r\n", plan_bytes, "RUNTIME_ACCEPTANCE_PLAN.md must remain LF")
        plan_text = plan_bytes.decode("utf-8")

        sec_header = "### 12.3."
        self.assertIn(sec_header, plan_text)
        sec_start = plan_text.index(sec_header)
        next_sec = plan_text.index("\n### 12.4.", sec_start)
        p11_section = plan_text[sec_start:next_sec]
        self.assertIn("P11_HISTORICAL_READ_ONLY_ACCEPTANCE", p11_section.splitlines()[0])
        m_ps = re.search(r"```powershell\n(.*?)```", p11_section, flags=re.DOTALL)
        self.assertIsNotNone(m_ps, "Expected standalone PowerShell block in P11_HISTORICAL_READ_ONLY_ACCEPTANCE")
        assert m_ps is not None
        p11_ps = m_ps.group(1)

        # D1a: Must declare distinct historical original vs review vs source vs checkout vars
        for req_var in (
            "$EvaluatorCheckoutDir",
            "$Demo1OriginalDir",
            "$Demo1OriginalCaptureDir",
            "$Demo1ReviewDir",
            "$Demo2OriginalDir",
            "$Demo3aOriginalDir",
            "$M1OriginalDir",
            "$Demo3bOriginalDir",
            "$Demo4OriginalDir",
            "$AllowQOriginalSourceRoot",
            "$AllowQOriginalDir",
            "$AllowQOriginalCaptureDir",
            "$AllowQReviewDir",
            "$P11OutputRoot",
            "$P11EvalJson",
        ):
            self.assertIn(f"{req_var}", p11_ps)
            self.assertRegex(p11_ps, rf"(?m)^\s*{re.escape(req_var)}\s*=")

        # Must NOT inherit fresh-scan variables from P1-P10 or sections 4-11
        for forbidden_var in (
            "$Demo1Dir",
            "$Demo2Dir",
            "$Demo3aDir",
            "$M1Dir",
            "$ControlsDir",
            "$AllowQDir",
            "$AllowQDb",
            "$SessionRoot",
            "$CheckoutDir",
            "$PrimaryRoot",
            "$AuxRoot",
            "$AuditOut",
        ):
            self.assertNotRegex(p11_ps, rf"{re.escape(forbidden_var)}\b", f"P11 must not use P1-P10 var {forbidden_var}")

        # Must NOT invoke scan, Ollama, or human-review write commands
        for forbidden_call in (
            "11434",
            "/api/chat",
            "/api/tags",
            "run_g1_demo",
            "semgrepai\", \"scan",
            "semgrepai\", \"confirm-true",
            "semgrepai\", \"confirm-false",
            "semgrepai\", \"reopen",
            "semgrepai scan",
            "ollama",
        ):
            self.assertNotIn(forbidden_call.lower(), p11_ps.lower())

        self.assertIn("v2.g1_integration.evaluate_r01_r03", p11_ps)
        self.assertIn("--capture-relocation-mode", p11_ps)
        self.assertIn("pinned-original-capture", p11_ps)
        self.assertIn("proposed-allowlisted-fp", p11_ps)

        # Verify every $Var referenced in P11 (outside PowerShell built-ins and $env:) is defined in P11
        defined_vars = set(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=", p11_ps))
        defined_vars.update(re.findall(r"\[[^\]]+\]\$([A-Za-z_][A-Za-z0-9_]*)", p11_ps))
        defined_vars.update(re.findall(r"foreach\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s+in\b", p11_ps))
        builtin_vars = {"LASTEXITCODE", "ErrorActionPreference", "null", "true", "false", "env"}
        # Strip Python -c here-string before scanning PowerShell variable reads (except interpolated vars)
        used_vars = set(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)\b", p11_ps)) - builtin_vars
        undefined_vars = sorted(used_vars - defined_vars)
        self.assertEqual(undefined_vars, [], f"Undefined variables in P11 block: {undefined_vars}")

        # D1b: Valid P11-shaped historical layout passes via API & CLI
        separate_allowq_src = self.tmp_root / "historical_p1_source_root"
        separate_allowq_src.mkdir()
        shutil.copy2(self.fixtures / "AllowlistedQuery.java", separate_allowq_src / "AllowlistedQuery.java")
        aq_p1_orig = self.tmp_root / "aq_p1_orig"
        self.assertEqual(_run_cli(self.prepared_source, [
            "scan", str(separate_allowq_src / "AllowlistedQuery.java"),
            "--rules-path", str(self.rules),
            "--output-dir", str(aq_p1_orig),
            "--executable", self.opengrep,
            "--local-triage",
            "--endpoint", self.endpoint,
            "--model", "qwen3.5:9b-q4_K_M",
            "--prompt-contract", "blind",
            "--runtime-origin", "mock",
        ]).returncode, 0)
        shutil.copy2(aq_p1_orig / "triage" / "review.sqlite", aq_p1_orig / "triage" / "review.post_ingestion.sqlite")

        aq_p5_rev = _copy_review_scenario(aq_p1_orig, self.tmp_root / "aq_p5_rev", strip_legacy_reports=False)
        aq_db = str(aq_p5_rev / "triage" / "review.sqlite")
        aq_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", aq_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-false", aq_id, "--db", aq_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: P5 historical-shape confirm-false",
        ]).returncode, 0)
        shutil.copy2(aq_p5_rev / "triage" / "review.sqlite", aq_p5_rev / "triage" / "review.after_confirm_false.sqlite")
        self.assertEqual(_run_cli(self.prepared_source, [
            "reopen", aq_id, "--db", aq_db,
            "--actor", "SCRIPTED_TEST_ONLY-lead",
            "--reason", "SCRIPTED_TEST_ONLY: P6 historical-shape reopen",
        ]).returncode, 0)

        p11_out = self.tmp_root / "p11_valid_out.json"
        rc_p11 = evaluate_main([
            "--demo1-dir", str(self.d1_review_retained),
            "--demo2-dir", str(self.d2_untouched),
            "--demo3a-dir", str(self.d3a_orig),
            "--m1-dir", str(self.m1_dir),
            "--demo4-dir", str(self.d4_dir),
            "--demo3b-dir", str(self.d3b_dir),
            "--r03-fp-mode", "proposed-allowlisted-fp",
            "--allowlisted-fp-dir", str(aq_p5_rev),
            "--allowlisted-trusted-source-root", str(separate_allowq_src),
            "--capture-relocation-mode", "pinned-original-capture",
            "--demo1-trusted-scenario-root", str(self.d1_orig_pristine),
            "--demo1-trusted-capture-root", str(self.d1_orig_pristine / "capture"),
            "--allowlisted-trusted-scenario-root", str(aq_p1_orig),
            "--allowlisted-trusted-capture-root", str(aq_p1_orig / "capture"),
            "--output", str(p11_out),
            "--allow-mock-primary",
        ])
        self.assertEqual(rc_p11, 0)
        self.assertEqual(strict_json(p11_out.read_text(encoding="utf-8"))["overall_status"], "PASS")

        # D2: Cross-session mixing (pair session A review copy with independent session B original/capture) MUST FAIL
        srv_mix, endpoint_mix = _start_mock_server("RUN_MIX_B")
        self.addCleanup(srv_mix.server_close)
        self.addCleanup(srv_mix.shutdown)
        d1_mix_orig = self.tmp_root / "d1_mix_session_b"
        aq_mix_orig = self.tmp_root / "aq_mix_session_b"
        for src_java, out_d in (
            (self.fixtures / "Demo1TruePositive.java", d1_mix_orig),
            (separate_allowq_src / "AllowlistedQuery.java", aq_mix_orig),
        ):
            self.assertEqual(_run_cli(self.prepared_source, [
                "scan", str(src_java),
                "--rules-path", str(self.rules),
                "--output-dir", str(out_d),
                "--executable", self.opengrep,
                "--local-triage",
                "--endpoint", endpoint_mix,
                "--model", "qwen3.5:9b-q4_K_M",
                "--prompt-contract", "blind",
                "--runtime-origin", "mock",
            ]).returncode, 0)
            shutil.copy2(out_d / "triage" / "review.sqlite", out_d / "triage" / "review.post_ingestion.sqlite")

        rep_mix_d1 = evaluate_acceptance(
            demo1_dir=self.d1_review_retained,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=aq_p5_rev,
            allowlisted_trusted_source_root=separate_allowq_src,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=d1_mix_orig,
            demo1_trusted_capture_root=d1_mix_orig / "capture",
            allowlisted_trusted_scenario_root=aq_p1_orig,
            allowlisted_trusted_capture_root=aq_p1_orig / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_mix_d1["overall_status"], "FAIL")
        self.assertEqual(rep_mix_d1["criteria"]["R02"]["status"], "FAIL")
        self.assertTrue(
            any("diverges from pinned original" in e for e in rep_mix_d1["criteria"]["R02"]["failures"]),
            rep_mix_d1["criteria"]["R02"]["failures"],
        )

        rep_mix_aq = evaluate_acceptance(
            demo1_dir=self.d1_review_retained,
            demo2_dir=self.d2_untouched,
            demo3a_dir=self.d3a_orig,
            m1_dir=self.m1_dir,
            demo4_dir=self.d4_dir,
            demo3b_dir=self.d3b_dir,
            allowlisted_fp_dir=aq_p5_rev,
            allowlisted_trusted_source_root=separate_allowq_src,
            r03_fp_mode="proposed-allowlisted-fp",
            capture_relocation_mode="pinned-original-capture",
            demo1_trusted_scenario_root=self.d1_orig_pristine,
            demo1_trusted_capture_root=self.d1_orig_pristine / "capture",
            allowlisted_trusted_scenario_root=aq_mix_orig,
            allowlisted_trusted_capture_root=aq_mix_orig / "capture",
            allow_mock_primary=True,
        )
        self.assertEqual(rep_mix_aq["overall_status"], "FAIL")
        self.assertEqual(rep_mix_aq["criteria"]["R03"]["status"], "FAIL")
        self.assertTrue(
            any("diverges from pinned original" in e for e in rep_mix_aq["criteria"]["R03"]["failures"]),
            rep_mix_aq["criteria"]["R03"]["failures"],
        )

    def test_09_allowlisted_native_posix_and_path_mapping_security_boundaries(self):
        """Verify native POSIX paths inside pinned_root without mappings pass on Linux,
        any un-derived/self-declared non-empty path_mappings fail closed on Linux
        (even when evidence and manifest agree), Windows keeps strict OS-derived
        WSL mapping enforcement, and prefix/sibling/traversal/hash/drift fail specifically."""
        from v2.g1_integration.bridge import derive_trusted_path_maps
        from v2.g1_integration.evaluate_r01_r03 import _verify_allowlisted_fp_scenario_identity
        from v2.triage.evidence import EvidenceError, SourceTree

        self.assertEqual(
            _verify_allowlisted_fp_scenario_identity(self.aq_orig_pristine, trusted_source_root=self.fixtures),
            [],
        )
        base_ev = strict_json((self.aq_orig_pristine / "triage" / "evidence.json").read_text(encoding="utf-8"))
        allow_bytes = (self.fixtures / "AllowlistedQuery.java").read_bytes()

        outside_dir = self.tmp_root / "outside_allowq_sec"
        outside_dir.mkdir()
        (outside_dir / "AllowlistedQuery.java").write_bytes(allow_bytes)

        fixtures_copy = self.tmp_root / "fixtures_copy_sec"
        fixtures_copy.mkdir()
        (fixtures_copy / "AllowlistedQuery.java").write_bytes(allow_bytes)

        sibling_fixtures = self.tmp_root / f"{fixtures_copy.name}-evil"
        sibling_fixtures.mkdir()
        (sibling_fixtures / "AllowlistedQuery.java").write_bytes(allow_bytes)

        def _check(name: str, ev_mut, *, manifest_doc=None, root_override=None) -> list[str]:
            scen = self.tmp_root / f"pathmap_sec_{name}"
            (scen / "triage").mkdir(parents=True, exist_ok=True)
            ev_doc = json.loads(json.dumps(base_ev))
            ev_mut(ev_doc)
            (scen / "triage" / "evidence.json").write_text(json.dumps(ev_doc), encoding="utf-8")
            if manifest_doc is not None:
                (scen / "g1-run-manifest.json").write_text(json.dumps(manifest_doc), encoding="utf-8")
            return _verify_allowlisted_fp_scenario_identity(
                scen, trusted_source_root=self.fixtures if root_override is None else root_override,
            )

        # Positive baseline on fixtures_copy (identical fixture bytes, no mapping) before negative mutations
        self.assertEqual(
            _check(
                "baseline_valid_copy",
                lambda d: (
                    d.__setitem__("root", str(fixtures_copy)),
                    d.__setitem__("path_mappings", []),
                    d["records"][0].__setitem__("root", str(fixtures_copy)),
                    d["records"][0].__setitem__("path_mappings", []),
                    d["records"][0].__setitem__("path", str((fixtures_copy / "AllowlistedQuery.java").resolve())),
                ),
                root_override=fixtures_copy,
            ),
            [],
        )

        # Common negative security boundaries with exact expected root-cause error assertions
        errs_outside = _check(
            "outside_direct",
            lambda d: (
                d.__setitem__("root", str(fixtures_copy)),
                d.__setitem__("path_mappings", []),
                d["records"][0].__setitem__("root", str(fixtures_copy)),
                d["records"][0].__setitem__("path_mappings", []),
                d["records"][0].__setitem__("path", str((outside_dir / "AllowlistedQuery.java").resolve())),
            ),
            root_override=fixtures_copy,
        )
        self.assertTrue(
            any("source path outside configured root" in e for e in errs_outside),
            errs_outside,
        )

        errs_sibling_native = _check(
            "sibling_native_direct",
            lambda d: (
                d.__setitem__("root", str(fixtures_copy)),
                d.__setitem__("path_mappings", []),
                d["records"][0].__setitem__("root", str(fixtures_copy)),
                d["records"][0].__setitem__("path_mappings", []),
                d["records"][0].__setitem__("path", str((sibling_fixtures / "AllowlistedQuery.java").resolve())),
            ),
            root_override=fixtures_copy,
        )
        self.assertTrue(
            any("source path outside configured root" in e for e in errs_sibling_native),
            errs_sibling_native,
        )

        # Paired SourceTree segment-boundary & unmatched-prefix check against real files on disk
        mapped_root_prefix = "/mnt/sim" if os.name == "nt" else fixtures_copy.resolve().as_posix()
        valid_tree = SourceTree(fixtures_copy, path_maps=[f"{mapped_root_prefix}={fixtures_copy}"])
        self.assertEqual(
            valid_tree.resolve(f"{mapped_root_prefix}/AllowlistedQuery.java"),
            (fixtures_copy / "AllowlistedQuery.java").resolve(),
        )
        if os.name == "nt":
            with self.assertRaisesRegex(EvidenceError, "requires an explicit --path-map"):
                valid_tree.resolve(f"{mapped_root_prefix}-evil/AllowlistedQuery.java")
            with self.assertRaisesRegex(EvidenceError, "requires an explicit --path-map"):
                SourceTree(fixtures_copy, path_maps=[f"/mnt/other={fixtures_copy}"]).resolve(
                    f"{mapped_root_prefix}/AllowlistedQuery.java"
                )
        else:
            with self.assertRaisesRegex(EvidenceError, "source path outside configured root"):
                valid_tree.resolve(f"{mapped_root_prefix}-evil/AllowlistedQuery.java")

        errs_outside_to = _check(
            "outside_to_target",
            lambda d: (
                d.__setitem__("path_mappings", [{"from": "/mnt/c/ntk_wsl_sim", "to": str(outside_dir)}]),
                d["records"][0].__setitem__("path_mappings", [{"from": "/mnt/c/ntk_wsl_sim", "to": str(outside_dir)}]),
                d["records"][0].__setitem__("path", "/mnt/c/ntk_wsl_sim/AllowlistedQuery.java"),
            ),
        )
        expected_outside_to_msg = (
            "mapped directory must stay inside configured source-root"
            if os.name == "nt"
            else "untrusted path_mappings: POSIX/Linux host has no independent mapping authority"
        )
        self.assertTrue(any(expected_outside_to_msg in e for e in errs_outside_to), errs_outside_to)

        errs_traversal = _check(
            "traversal_path",
            lambda d: (
                d.__setitem__("path_mappings", []),
                d["records"][0].__setitem__("path_mappings", []),
                d["records"][0].__setitem__("path", "../outside_allowq_sec/AllowlistedQuery.java"),
            ),
        )
        self.assertTrue(any("without traversal" in e for e in errs_traversal), errs_traversal)

        errs_bad_hash = _check(
            "wrong_snapshot_sha",
            lambda d: d["records"][0]["snapshots"]["AllowlistedQuery.java"].__setitem__("sha256", "0" * 64),
        )
        self.assertTrue(any("snapshot hash/size mismatch" in e for e in errs_bad_hash), errs_bad_hash)

        if os.name != "nt":
            native_file = str((fixtures_copy / "AllowlistedQuery.java").resolve())
            self.assertEqual(
                _check(
                    "posix_native_valid",
                    lambda d: (
                        d.__setitem__("root", str(fixtures_copy)),
                        d.__setitem__("path_mappings", []),
                        d["records"][0].__setitem__("root", str(fixtures_copy)),
                        d["records"][0].__setitem__("path_mappings", []),
                        d["records"][0].__setitem__("path", native_file),
                    ),
                    manifest_doc={"source_root": str(fixtures_copy), "trusted_path_maps": []},
                    root_override=fixtures_copy,
                ),
                [],
            )

            errs_manifest_disagree = _check(
                "manifest_maps_disagree",
                lambda d: (
                    d.__setitem__("root", str(fixtures_copy)),
                    d.__setitem__("path_mappings", []),
                    d["records"][0].__setitem__("root", str(fixtures_copy)),
                    d["records"][0].__setitem__("path_mappings", []),
                    d["records"][0].__setitem__("path", native_file),
                ),
                manifest_doc={"source_root": str(fixtures_copy), "trusted_path_maps": [f"/mnt/c/other={fixtures_copy}"]},
                root_override=fixtures_copy,
            )
            self.assertTrue(
                any("disagrees with g1-run-manifest trusted_path_maps" in e for e in errs_manifest_disagree),
                errs_manifest_disagree,
            )

            # Codex counterexamples: forged outside -> trusted mappings MUST FAIL CLOSED on Linux
            # whether evidence + manifest agree, manifest is absent, or manifest omits trusted_path_maps
            forged_maps = [{"from": "/tmp/evil_outside", "to": str(fixtures_copy)}]
            for case_tag, man_doc in (
                ("consistent_manifest", {"source_root": str(fixtures_copy), "trusted_path_maps": [f"/tmp/evil_outside={fixtures_copy}"]}),
                ("no_manifest", None),
                ("manifest_without_maps", {"source_root": str(fixtures_copy)}),
            ):
                with self.subTest(posix_forged_case=case_tag):
                    errs_forged = _check(
                        f"posix_forged_{case_tag}",
                        lambda d: (
                            d.__setitem__("root", str(fixtures_copy)),
                            d.__setitem__("path_mappings", list(forged_maps)),
                            d["records"][0].__setitem__("root", str(fixtures_copy)),
                            d["records"][0].__setitem__("path_mappings", list(forged_maps)),
                            d["records"][0].__setitem__("path", "/tmp/evil_outside/AllowlistedQuery.java"),
                        ),
                        manifest_doc=man_doc,
                        root_override=fixtures_copy,
                    )
                    self.assertTrue(
                        any("untrusted path_mappings: POSIX/Linux host has no independent mapping authority" in e for e in errs_forged),
                        f"{case_tag}: forged mapping must fail closed on Linux, got {errs_forged!r}",
                    )
            errs_posix_rel_with_map = _check(
                "posix_relative_with_forged_map",
                lambda d: (
                    d.__setitem__("root", str(fixtures_copy)),
                    d.__setitem__("path_mappings", list(forged_maps)),
                    d["records"][0].__setitem__("root", str(fixtures_copy)),
                    d["records"][0].__setitem__("path_mappings", list(forged_maps)),
                    d["records"][0].__setitem__("path", "AllowlistedQuery.java"),
                ),
                root_override=fixtures_copy,
            )
            self.assertTrue(
                any("untrusted path_mappings: POSIX/Linux host has no independent mapping authority" in e for e in errs_posix_rel_with_map),
                errs_posix_rel_with_map,
            )
        else:
            os_maps = derive_trusted_path_maps(fixtures_copy)
            self.assertTrue(os_maps)
            wsl_prefix = os_maps[0].split("=", 1)[0]
            self.assertEqual(
                _check(
                    "win_wsl_valid",
                    lambda d: (
                        d.__setitem__("root", str(fixtures_copy)),
                        d.__setitem__("path_mappings", [{"from": wsl_prefix, "to": str(fixtures_copy)}]),
                        d["records"][0].__setitem__("root", str(fixtures_copy)),
                        d["records"][0].__setitem__("path_mappings", [{"from": wsl_prefix, "to": str(fixtures_copy)}]),
                        d["records"][0].__setitem__("path", f"{wsl_prefix}/AllowlistedQuery.java"),
                    ),
                    manifest_doc={"source_root": str(fixtures_copy), "trusted_path_maps": os_maps},
                    root_override=fixtures_copy,
                ),
                [],
            )
            # Paired Windows wrong-prefix & sibling-prefix attacks under otherwise valid copy + fixture bytes
            errs_win_wrong_prefix = _check(
                "win_wrong_prefix",
                lambda d: (
                    d.__setitem__("root", str(fixtures_copy)),
                    d.__setitem__("path_mappings", [{"from": "/mnt/c/unmatched", "to": str(fixtures_copy)}]),
                    d["records"][0].__setitem__("root", str(fixtures_copy)),
                    d["records"][0].__setitem__("path_mappings", [{"from": "/mnt/c/unmatched", "to": str(fixtures_copy)}]),
                    d["records"][0].__setitem__("path", f"{wsl_prefix}/AllowlistedQuery.java"),
                ),
                root_override=fixtures_copy,
            )
            self.assertTrue(
                any("untrusted path_mappings: do not match OS-derived source-root mapping" in e for e in errs_win_wrong_prefix),
                errs_win_wrong_prefix,
            )

            errs_win_sibling_prefix = _check(
                "win_sibling_prefix",
                lambda d: (
                    d.__setitem__("root", str(fixtures_copy)),
                    d.__setitem__("path_mappings", [{"from": wsl_prefix, "to": str(fixtures_copy)}]),
                    d["records"][0].__setitem__("root", str(fixtures_copy)),
                    d["records"][0].__setitem__("path_mappings", [{"from": wsl_prefix, "to": str(fixtures_copy)}]),
                    d["records"][0].__setitem__("path", f"{wsl_prefix}-evil/AllowlistedQuery.java"),
                ),
                manifest_doc={"source_root": str(fixtures_copy), "trusted_path_maps": os_maps},
                root_override=fixtures_copy,
            )
            self.assertTrue(
                any("POSIX/WSL source path requires an explicit --path-map" in e for e in errs_win_sibling_prefix),
                errs_win_sibling_prefix,
            )

            errs_win_missing = _check(
                "win_wsl_missing_maps",
                lambda d: (
                    d.__setitem__("root", str(fixtures_copy)),
                    d.__setitem__("path_mappings", []),
                    d["records"][0].__setitem__("root", str(fixtures_copy)),
                    d["records"][0].__setitem__("path_mappings", []),
                    d["records"][0].__setitem__("path", f"{wsl_prefix}/AllowlistedQuery.java"),
                ),
                root_override=fixtures_copy,
            )
            self.assertTrue(any("requires explicit path_mappings" in e for e in errs_win_missing), errs_win_missing)

            for case_tag, man_doc in (
                ("consistent_manifest", {"source_root": str(fixtures_copy), "trusted_path_maps": [f"/mnt/z/forged_outside={fixtures_copy}"]}),
                ("no_manifest", None),
                ("manifest_without_maps", {"source_root": str(fixtures_copy)}),
            ):
                with self.subTest(win_forged_case=case_tag):
                    errs_win_forged = _check(
                        f"win_wsl_forged_{case_tag}",
                        lambda d: (
                            d.__setitem__("root", str(fixtures_copy)),
                            d.__setitem__("path_mappings", [{"from": "/mnt/z/forged_outside", "to": str(fixtures_copy)}]),
                            d["records"][0].__setitem__("root", str(fixtures_copy)),
                            d["records"][0].__setitem__("path_mappings", [{"from": "/mnt/z/forged_outside", "to": str(fixtures_copy)}]),
                            d["records"][0].__setitem__("path", "/mnt/z/forged_outside/AllowlistedQuery.java"),
                        ),
                        manifest_doc=man_doc,
                        root_override=fixtures_copy,
                    )
                    self.assertTrue(
                        any("untrusted path_mappings: do not match OS-derived source-root mapping" in e for e in errs_win_forged),
                        errs_win_forged,
                    )

        # Mutate fixtures_copy ONLY at the end to verify source drift detection cleanly
        (fixtures_copy / "AllowlistedQuery.java").write_text("// drifted\n", encoding="utf-8")
        errs_drift = _check(
            "source_drift",
            lambda d: (
                d.__setitem__("root", str(fixtures_copy)),
                d.__setitem__("path_mappings", []),
                d["records"][0].__setitem__("root", str(fixtures_copy)),
                d["records"][0].__setitem__("path_mappings", []),
                d["records"][0].__setitem__("path", str(fixtures_copy / "AllowlistedQuery.java")),
            ),
            root_override=fixtures_copy,
        )
        self.assertTrue(any("source drift or disk fixture mismatch" in e for e in errs_drift), errs_drift)

    def test_09b_allowlisted_symlink_escape_rejected_or_explicitly_skipped(self):
        """Verify real outside-root file symlink fails closed on POSIX/WSL2 (mandatory)
        and either fails closed or explicitly reports SkipTest on unprivileged Windows hosts."""
        from v2.g1_integration.evaluate_r01_r03 import _verify_allowlisted_fp_scenario_identity

        base_ev = strict_json((self.aq_orig_pristine / "triage" / "evidence.json").read_text(encoding="utf-8"))
        allow_bytes = (self.fixtures / "AllowlistedQuery.java").read_bytes()

        outside_dir = self.tmp_root / "outside_sym_target"
        outside_dir.mkdir()
        outside_java = outside_dir / "AllowlistedQuery.java"
        outside_java.write_bytes(allow_bytes)

        sym_root = self.tmp_root / "sym_fixtures_root"
        sym_root.mkdir()
        sym_file = sym_root / "AllowlistedQuery.java"
        sym_file.write_bytes(allow_bytes)

        scen = self.tmp_root / "sym_allowq_scen"
        (scen / "triage").mkdir(parents=True)
        ev_doc = json.loads(json.dumps(base_ev))
        ev_doc["root"] = str(sym_root)
        ev_doc["path_mappings"] = []
        ev_doc["records"][0]["root"] = str(sym_root)
        ev_doc["records"][0]["path_mappings"] = []
        ev_doc["records"][0]["path"] = str(sym_file.resolve())
        (scen / "triage" / "evidence.json").write_text(json.dumps(ev_doc), encoding="utf-8")

        # Paired valid regular-file control must pass first
        self.assertEqual(_verify_allowlisted_fp_scenario_identity(scen, trusted_source_root=sym_root), [])

        sym_file.unlink()
        link_created = _make_file_link(sym_file, outside_java)
        if not link_created:
            if os.name != "nt":
                self.fail("POSIX/Linux host must support creating real file symlinks for symlink security tests")
            self.skipTest("BLOCKED/SKIP: host Windows privilege prevented creating file symlink for allowlisted symlink check")
        try:
            self.assertTrue(sym_file.is_symlink(), "Expected real OS symlink on disk before verification")
            errs_sym = _verify_allowlisted_fp_scenario_identity(scen, trusted_source_root=sym_root)
            self.assertTrue(
                any(
                    "source path outside configured root" in e or "unsafe symlink/junction" in e
                    for e in errs_sym
                ),
                errs_sym,
            )
        finally:
            _remove_file_link(sym_file)


class R03RelocationTests(_RelocationTestMixin, unittest.TestCase):
    """Real-OpenGrep relocation tests (skipped cleanly when OpenGrep binary is not installed on host)."""

    @classmethod
    def setUpClass(cls):
        opengrep_bin = _find_opengrep_binary()
        if not opengrep_bin:
            raise unittest.SkipTest("OpenGrep binary not available on test host")
        cls._cls_tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._cls_tmp.cleanup)
        cls.base_tmp = Path(cls._cls_tmp.name).resolve()
        cls._setup_relocation_fixture(opengrep_bin)


class R03RelocationOfflineSyntheticTests(_RelocationTestMixin, unittest.TestCase):
    """SYNTHETIC_MOCK_TEST_ONLY: Offline relocation verification using synthetic OpenGrep stub + mock Ollama HTTP."""

    @classmethod
    def setUpClass(cls):
        cls._cls_tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._cls_tmp.cleanup)
        cls.base_tmp = Path(cls._cls_tmp.name).resolve()
        synth_opengrep = _build_synthetic_opengrep_shim(cls.base_tmp / "synthetic_opengrep")
        cls._setup_relocation_fixture(synth_opengrep)


if __name__ == "__main__":
    unittest.main()
