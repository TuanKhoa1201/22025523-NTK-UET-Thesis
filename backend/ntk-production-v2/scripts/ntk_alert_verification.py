#!/usr/bin/env python3
"""
NTK Alert Verification & False Positive Triage Layer (`ntk_alert_verification.py`)
Architecture: FROZEN_ARCHITECTURE_V1
  OpenGrep v1.25.0 -> IRIS Java AST/Dataflow (OpenJDK 17 JavacTask AST)
  -> Qwen2.5-Coder-0.5B-Instruct LoRA -> Evidence Fusion -> Alert Triage

Responsibilities:
1. Genuine Java Compiler AST (`javax.tools.JavaCompiler` / `com.sun.source.tree.*` `JavacTask.parse()`)
   and lexical-scope-aware intraprocedural def-use dataflow extraction (`analyze_java_site_ast_and_taint`)
   from real `.java` source files and OpenGrep match lines (zero reliance on ground-truth labels or fixture names).
2. Strict separation between semantic AST evidence (`OPENJDK17_JAVAC_TASK_AST`) and fallback lexical patterns
   (`FALLBACK_LEXICAL_PARSER`): automatic `SUPPRESS` is strictly forbidden unless verified by the semantic AST.
3. Neuro-symbolic Evidence Fusion & Alert Triage (`verify_and_triage_finding`) built on top of the frozen
   `ntk_iris_shared.evaluate_bounded_safety_floor` (0.55) and `verify_ast_release_evidence` engine.
4. Three orthogonal state dimensions per finding:
   - `triage_status`: `LIKELY_TRUE_POSITIVE` | `LIKELY_FALSE_POSITIVE` | `NEEDS_REVIEW`
   - `decision`: `REPORT` | `REVIEW` | `SUPPRESS`
   - `review_status`: `NOT_REVIEWED` | `CONFIRMED_TRUE_POSITIVE` | `CONFIRMED_FALSE_POSITIVE`
5. Full preservation of suppressed findings (`decision == "SUPPRESS"`) with structured `reason_codes`,
   `fusion_score_breakdown`, and `evidence_refs` for security auditing.
6. `FindingSchemaV2` JSON Schema generation and strict runtime schema validation.
"""

import hashlib
import urllib.parse
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import ntk_iris_shared as shared

MODEL_VERSION_DEFAULT: str = "eo06_vnext31_trackb_main_epoch3"
RULESET_VERSION_DEFAULT: str = "NTK_OPENGREP_JAVA_RULESET_V1.4"
SCORING_POLICY_VERSION_DEFAULT: str = "NTK_BOUNDED_SAFETY_FLOOR_FUSION_V1.2"
SCORE_KIND_DEFAULT: str = "HEURISTIC_EVIDENCE_FUSION_SCORE_NOT_CALIBRATED_PROBABILITY"
AST_ANALYSIS_VERSION = "JAVAC_AST_V4_STANDARD_API_TRANSFERS"

INFRASTRUCTURE_PARAM_TYPES: Set[str] = {
    "Connection",
    "java.sql.Connection",
    "Statement",
    "java.sql.Statement",
    "PreparedStatement",
    "java.sql.PreparedStatement",
    "CallableStatement",
    "java.sql.CallableStatement",
    "PrintWriter",
    "java.io.PrintWriter",
    "HttpServletResponse",
    "javax.servlet.http.HttpServletResponse",
    "jakarta.servlet.http.HttpServletResponse",
    "OutputStream",
    "Writer",
    "HttpSession",
    "javax.servlet.http.HttpSession",
    "jakarta.servlet.http.HttpSession",
}

SHELL_EXECUTABLES: Set[str] = {
    "sh",
    "/bin/sh",
    "bash",
    "/bin/bash",
    "zsh",
    "/bin/zsh",
    "dash",
    "/bin/dash",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
}

# In-memory cache mapping sha256(java_source_text) -> parsed file AST dict from NtkJavacAstExtractor
_JAVAC_AST_CACHE: Dict[str, Dict[str, Any]] = {}
_JAVAC_PATH_TO_HASH_CACHE: Dict[str, str] = {}

SCRIPT_DIR = Path(__file__).resolve().parent
JAVAC_BRIDGE_DIR = SCRIPT_DIR / "javac_ast_bridge"
JAVAC_BRIDGE_JAVA = JAVAC_BRIDGE_DIR / "NtkJavacAstExtractor.java"
JAVAC_BRIDGE_CLASS = JAVAC_BRIDGE_DIR / "NtkJavacAstExtractor.class"


@dataclass(frozen=True)
class ManualReviewRecord:
    """
    Explicit human/auditor verification record required to transition `review_status`
    from `NOT_REVIEWED` to `CONFIRMED_TRUE_POSITIVE` or `CONFIRMED_FALSE_POSITIVE`.
    """

    finding_id: str
    confirmed_status: str  # CONFIRMED_TRUE_POSITIVE or CONFIRMED_FALSE_POSITIVE
    reviewer_id: str
    reviewed_at_utc: str
    review_notes: str = ""
    confirmation_source: str = "MANUAL_SECURITY_REVIEW"


@dataclass(frozen=True)
class JavaAstSiteAnalysis:
    file_path: str
    match_line: int
    cwe: int
    package_name: str
    class_name: str
    enclosing_method: str
    enclosing_signature: str
    untrusted_params: Tuple[str, ...]
    target_callee_identity: Dict[str, str]
    matched_code_line: str
    source_sink_trace_status: str
    taint_reaches_sink: bool
    taint_source_params: Tuple[str, ...]
    taint_trace_steps: Tuple[str, ...]
    sanitizer_status: str
    ast_evidence: shared.AstReleaseEvidence
    extra_reason_codes: Tuple[str, ...] = ()
    ast_parser_engine: str = "OPENJDK17_JAVAC_TASK_AST"
    ast_overloaded_signature: str = ""

    @property
    def flow_proof_state(self) -> str:
        if self.taint_reaches_sink:
            return "PROVEN_TAINT"
        if self.source_sink_trace_status in ("SAFE_CONSTANT_OR_PARAMETERIZED", "SAFE_SANITIZED_OR_GUARDED"):
            return "PROVEN_SAFE"
        return "UNKNOWN"


def ensure_javac_ast_bridge_compiled(
    javac_bin: str = "/usr/bin/javac",
    timeout_sec: float = 15.0,
) -> bool:
    inner_visitor_cls = JAVAC_BRIDGE_DIR / "NtkJavacAstExtractor$1MethodBodyVisitor.class"
    if JAVAC_BRIDGE_CLASS.exists() and inner_visitor_cls.exists() and JAVAC_BRIDGE_JAVA.exists():
        cls_files = list(JAVAC_BRIDGE_DIR.glob("NtkJavacAstExtractor*.class"))
        java_mtime = JAVAC_BRIDGE_JAVA.stat().st_mtime
        if cls_files and min(c.stat().st_mtime for c in cls_files) >= java_mtime:
            return True
    if not JAVAC_BRIDGE_JAVA.exists() or not Path(javac_bin).exists():
        return False
    try:
        for old_cls in JAVAC_BRIDGE_DIR.glob("NtkJavacAstExtractor*.class"):
            try:
                old_cls.unlink()
            except Exception:
                pass
        proc = subprocess.run(
            [javac_bin, str(JAVAC_BRIDGE_JAVA)],
            cwd=str(JAVAC_BRIDGE_DIR),
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        return proc.returncode == 0 and JAVAC_BRIDGE_CLASS.exists() and inner_visitor_cls.exists()
    except Exception:
        return False


def prewarm_javac_ast_cache(
    java_files: Sequence[Path],
    java_bin: str = "/usr/bin/java",
    javac_bin: str = "/usr/bin/javac",
    timeout_sec: float = 20.0,
) -> int:
    """
    Parses a batch of `.java` files in a single OpenJDK 17 `JavacTask` invocation
    and populates `_JAVAC_AST_CACHE`. Returns number of newly cached files.
    """
    if not java_files or not ensure_javac_ast_bridge_compiled(javac_bin=javac_bin):
        return 0
    if not Path(java_bin).exists():
        return 0

    uncached_paths: List[str] = []
    path_to_sha: Dict[str, str] = {}
    for p in java_files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
            abs_s = str(p.resolve())
            _JAVAC_PATH_TO_HASH_CACHE[abs_s] = sha
            if sha not in _JAVAC_AST_CACHE:
                uncached_paths.append(abs_s)
                path_to_sha[abs_s] = sha
        except Exception:
            continue

    if not uncached_paths:
        return 0

    batch_size = 250
    total_cached = 0
    batch_timeout = max(timeout_sec, 45.0)
    for start_idx in range(0, len(uncached_paths), batch_size):
        chunk = uncached_paths[start_idx : start_idx + batch_size]
        try:
            proc = subprocess.run(
                [java_bin, "-cp", str(JAVAC_BRIDGE_DIR), "NtkJavacAstExtractor"] + chunk,
                capture_output=True,
                text=True,
                timeout=batch_timeout,
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                continue
            payload = json.loads(proc.stdout)
            for f_entry in payload.get("files", []):
                fp = str(f_entry.get("file_path", ""))
                sha = path_to_sha.get(fp)
                if not sha and fp and Path(fp).exists():
                    sha = hashlib.sha256(Path(fp).read_bytes()).hexdigest()
                if sha:
                    _JAVAC_AST_CACHE[sha] = f_entry
                    total_cached += 1
        except Exception:
            continue
    return total_cached


def parse_java_source_with_javac_ast(
    java_source_text: str,
    file_path: str = "",
    java_bin: str = "/usr/bin/java",
    javac_bin: str = "/usr/bin/javac",
    timeout_sec: float = 15.0,
) -> Optional[Dict[str, Any]]:
    """
    Parses `java_source_text` into an OpenJDK 17 `CompilationUnitTree` AST dictionary
    using `NtkJavacAstExtractor` (with SHA-256 content caching).
    """
    sha = hashlib.sha256(java_source_text.encode("utf-8")).hexdigest()
    if sha in _JAVAC_AST_CACHE:
        return _JAVAC_AST_CACHE[sha]

    if not ensure_javac_ast_bridge_compiled(javac_bin=javac_bin) or not Path(java_bin).exists():
        return None

    # If file_path exists on disk and matches sha, parse it directly; otherwise use a temp .java file
    target_path: Optional[Path] = None
    tmp_dir: Optional[tempfile.TemporaryDirectory] = None
    try:
        if file_path and Path(file_path).is_file():
            disk_bytes = Path(file_path).read_bytes()
            if hashlib.sha256(disk_bytes).hexdigest() == sha:
                target_path = Path(file_path).resolve()

        if target_path is None:
            tmp_dir = tempfile.TemporaryDirectory(prefix="ntk_javac_ast_")
            fname = Path(file_path).name if (file_path and file_path.endswith(".java")) else "Snippet.java"
            target_path = Path(tmp_dir.name) / fname
            target_path.write_text(java_source_text, encoding="utf-8", newline="\n")

        proc = subprocess.run(
            [java_bin, "-cp", str(JAVAC_BRIDGE_DIR), "NtkJavacAstExtractor", str(target_path)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        payload = json.loads(proc.stdout)
        files = payload.get("files", [])
        if not files:
            return None
        ast_dict = files[0]
        _JAVAC_AST_CACHE[sha] = ast_dict
        return ast_dict
    except Exception:
        return None
    finally:
        if tmp_dir is not None:
            try:
                tmp_dir.cleanup()
            except Exception:
                pass


def _strip_java_comments_multiline(text: str) -> str:
    """Removes /* ... */ block comments and // line comments outside string literals."""
    out: List[str] = []
    i = 0
    n = len(text)
    in_str = False
    in_char = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
        elif in_char:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == "'":
                in_char = False
            i += 1
        else:
            if ch == '"':
                in_str = True
                out.append(ch)
                i += 1
            elif ch == "'":
                in_char = True
                out.append(ch)
                i += 1
            elif ch == "/" and i + 1 < n and text[i + 1] == "*":
                # Skip block comment while preserving newlines for line numbers
                i += 2
                while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                    if text[i] == "\n":
                        out.append("\n")
                    i += 1
                i += 2
            elif ch == "/" and i + 1 < n and text[i + 1] == "/":
                while i < n and text[i] != "\n":
                    i += 1
            else:
                out.append(ch)
                i += 1
    return "".join(out)


def _strip_java_comments(line: str) -> str:
    idx = line.find("//")
    if idx != -1:
        prefix = line[:idx]
        if prefix.count('"') % 2 == 0:
            return prefix.strip()
    return line.strip()


def _is_const_ast_kind(kind: str) -> bool:
    return kind in (
        "STRING_LITERAL",
        "PRIMITIVE_LITERAL",
        "STATIC_FINAL_CONST_IDENT",
        "CONSTANT_CONCAT_EXPR",
    )


def _is_pure_const_path_factory_expr(
    expr_str: str,
    invocations: Sequence[Dict[str, Any]],
    new_classes: Sequence[Dict[str, Any]],
    static_final_consts: Set[str],
) -> Tuple[bool, str]:
    cleaned = expr_str.strip().rstrip(";").strip()
    m_str = re.match(r'^"((?:\\.|[^"\\])*)"$', cleaned)
    if m_str:
        return True, m_str.group(1)

    for inv in invocations:
        if inv.get("call_expr", "").strip() == cleaned and inv.get("method_name") in ("get", "of"):
            recv = inv.get("receiver", "").strip()
            if recv in ("Paths", "Path", "java.nio.file.Paths", "java.nio.file.Path"):
                arg_kinds = inv.get("arg_kinds", [])
                if arg_kinds and all(_is_const_ast_kind(k) for k in arg_kinds):
                    lits = inv.get("arg_string_literals", [])
                    return True, "/".join(lits) if lits else cleaned

    for nc in new_classes:
        if nc.get("new_expr", "").strip() == cleaned and nc.get("class_type") in (
            "File",
            "java.io.File",
            "FileInputStream",
            "java.io.FileInputStream",
            "FileOutputStream",
            "java.io.FileOutputStream",
            "FileReader",
            "java.io.FileReader",
            "FileWriter",
            "java.io.FileWriter",
        ):
            arg_kinds = nc.get("arg_kinds", [])
            if arg_kinds and all(_is_const_ast_kind(k) for k in arg_kinds):
                lits = nc.get("arg_string_literals", [])
                return True, "/".join(lits) if lits else cleaned

    return False, ""


def _extract_non_literal_identifiers(expr_str: str) -> List[str]:
    """Extracts Java identifiers from `expr_str` outside string/char literals."""
    if not expr_str:
        return []
    masked = re.sub(r'"(?:\\.|[^"\\])*"', '""', expr_str)
    masked = re.sub(r"'(?:\\.|[^'\\])*'", "''", masked)
    java_keywords = {
        "new",
        "null",
        "true",
        "false",
        "int",
        "long",
        "short",
        "byte",
        "boolean",
        "char",
        "float",
        "double",
        "void",
        "class",
    }
    return [
        tok
        for tok in re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b", masked)
        if tok not in java_keywords
    ]


def _eval_const_int_expr(expr_str: str, const_int_vars: Dict[str, int]) -> Optional[int]:
    """
    Safely evaluates compile-time constant integer arithmetic expressions
    (`+`, `-`, `*`, `/`, `%`, parentheses, integer literals, and constant local `int` variables).
    """
    s = expr_str.strip()
    if not s:
        return None

    def _sub_ident(m: re.Match) -> str:
        ident = m.group(0)
        if ident in const_int_vars:
            return str(const_int_vars[ident])
        return ident

    s_sub = re.sub(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b", _sub_ident, s)
    if not re.match(r"^[\d\s\+\-\*\/\%\(\)]+$", s_sub):
        return None
    # Replace Java integer division `/` with Python integer division `//`
    s_py = re.sub(r"(?<!/)/(?!/)", "//", s_sub)
    try:
        val = eval(s_py, {"__builtins__": {}}, {})
        return int(val) if isinstance(val, (int, float)) else None
    except Exception:
        return None


def _eval_const_bool_condition(cond_str: str, const_int_vars: Dict[str, int]) -> Optional[bool]:
    """
    Evaluates relational integer conditions (`>`, `<`, `>=`, `<=`, `==`, `!=`) when both operands
    are compile-time integer constants. Returns `True`, `False`, or `None` if not constant.
    """
    s = cond_str.strip()
    while s.startswith("(") and s.endswith(")"):
        # Check if outer parens wrap the entire condition
        depth = 0
        wrapped = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(s) - 1:
                    wrapped = False
                    break
        if wrapped:
            s = s[1:-1].strip()
        else:
            break

    for op in (">=", "<=", "==", "!=", ">", "<"):
        # Find top-level relational operator
        depth = 0
        i = 0
        while i <= len(s) - len(op):
            ch = s[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and s[i : i + len(op)] == op:
                # Ensure single `>` or `<` is not part of `>=` or `<=`
                if len(op) == 1 and i + 1 < len(s) and s[i + 1] == "=":
                    i += 2
                    continue
                lhs = _eval_const_int_expr(s[:i], const_int_vars)
                rhs = _eval_const_int_expr(s[i + len(op) :], const_int_vars)
                if lhs is not None and rhs is not None:
                    if op == ">=":
                        return lhs >= rhs
                    if op == "<=":
                        return lhs <= rhs
                    if op == "==":
                        return lhs == rhs
                    if op == "!=":
                        return lhs != rhs
                    if op == ">":
                        return lhs > rhs
                    if op == "<":
                        return lhs < rhs
                return None
            i += 1
    return None


def _split_top_level_ternary(expr_str: str) -> Optional[Tuple[str, str, str]]:
    """Splits a top-level `cond ? true_expr : false_expr` into `(cond, true_expr, false_expr)`."""
    s = expr_str.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        wrapped = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(s) - 1:
                    wrapped = False
                    break
        if wrapped:
            s = s[1:-1].strip()
        else:
            break

    depth = 0
    in_str = False
    in_chr = False
    q_idx = -1
    c_idx = -1
    q_depth = 0
    i = 0
    while i < len(s):
        ch = s[i]
        if in_str:
            if ch == "\\" and i + 1 < len(s):
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif in_chr:
            if ch == "\\" and i + 1 < len(s):
                i += 2
                continue
            if ch == "'":
                in_chr = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "'":
                in_chr = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            elif ch == "?" and depth == 0:
                if q_idx == -1:
                    q_idx = i
                else:
                    q_depth += 1
            elif ch == ":" and depth == 0 and q_idx != -1:
                if q_depth > 0:
                    q_depth -= 1
                else:
                    c_idx = i
                    break
        i += 1

    if q_idx != -1 and c_idx != -1 and q_idx < c_idx:
        return s[:q_idx].strip(), s[q_idx + 1 : c_idx].strip(), s[c_idx + 1 :].strip()
    return None


def _compute_const_local_maps(
    local_variables: Sequence[Dict[str, Any]],
    assignments: Sequence[Dict[str, Any]],
) -> Tuple[Dict[str, int], Dict[str, str]]:
    """
    Identifies local `int` and `String` variables that are initialized once to a compile-time literal
    and never reassigned anywhere in the method.
    """
    assigned_targets = {str(a.get("target", "")) for a in assignments}
    const_ints: Dict[str, int] = {}
    const_strs: Dict[str, str] = {}
    name_counts: Dict[str, int] = {}
    for v in local_variables:
        nm = str(v.get("name", ""))
        name_counts[nm] = name_counts.get(nm, 0) + 1

    for v in local_variables:
        nm = str(v.get("name", ""))
        if not nm or nm in assigned_targets or name_counts.get(nm, 0) != 1:
            continue
        vtype = str(v.get("type", "")).strip()
        ikind = str(v.get("init_kind", "")).strip()
        iexpr = str(v.get("init_expr", "")).strip()
        if vtype in ("int", "long", "short", "byte", "Integer") and ikind == "PRIMITIVE_LITERAL":
            try:
                const_ints[nm] = int(re.sub(r"[Ll]$", "", iexpr))
            except Exception:
                pass
        elif vtype in ("String", "java.lang.String") and ikind == "STRING_LITERAL":
            lits = v.get("string_literals", [])
            if lits:
                const_strs[nm] = str(lits[0])
            elif iexpr.startswith('"') and iexpr.endswith('"'):
                const_strs[nm] = iexpr[1:-1]
    return const_ints, const_strs


def _eval_switch_taken_line_ranges(
    sw: Dict[str, Any],
    const_str_vars: Dict[str, str],
    const_int_vars: Dict[str, int],
) -> Optional[Tuple[int, int, List[Tuple[int, int]]]]:
    """
    If `sw` (`SwitchTree`) has a compile-time constant selector (such as `guess.charAt(1)` on a
    constant `String guess = "ABC"` or a constant int expression), returns
    `(cases_min_line, cases_max_line, taken_line_ranges)`.
    """
    sel = str(sw.get("selector_expr", "")).strip()
    cases = sw.get("cases", [])
    if not cases:
        return None

    target_labels: Set[str] = set()
    m_char = re.match(r"^([A-Za-z_$][A-Za-z0-9_$]*)\.charAt\(\s*(\d+)\s*\)$", sel)
    if m_char:
        vname = m_char.group(1)
        idx = int(m_char.group(2))
        if vname in const_str_vars and 0 <= idx < len(const_str_vars[vname]):
            ch = const_str_vars[vname][idx]
            target_labels.add(f"'{ch}'")
            target_labels.add(f'"{ch}"')
            target_labels.add(ch)
    else:
        ival = _eval_const_int_expr(sel, const_int_vars)
        if ival is not None:
            target_labels.add(str(ival))

    if not target_labels:
        return None

    min_ln = min(int(c.get("start_line", 0)) for c in cases)
    max_ln = max(int(c.get("end_line", 0)) for c in cases)

    match_idx = -1
    default_idx = -1
    for idx, c in enumerate(cases):
        if bool(c.get("is_default")):
            default_idx = idx
        labels = {str(lbl).strip() for lbl in c.get("labels", [])}
        if labels & target_labels:
            match_idx = idx
            break

    start_idx = match_idx if match_idx != -1 else default_idx
    if start_idx == -1:
        return (min_ln, max_ln, [])

    taken_ranges: List[Tuple[int, int]] = []
    for idx in range(start_idx, len(cases)):
        c = cases[idx]
        taken_ranges.append((int(c.get("start_line", 0)), int(c.get("end_line", 0))))
        if bool(c.get("has_break")):
            break
    return (min_ln, max_ln, taken_ranges)


def _resolve_variable_in_scope(
    var_name: str,
    ref_ancestors: Sequence[int],
    ref_stmt_order: int,
    ref_line: int,
    local_variables: Sequence[Dict[str, Any]],
    assignments: Sequence[Dict[str, Any]],
    invocations: Sequence[Dict[str, Any]] = (),
    if_guards: Sequence[Dict[str, Any]] = (),
    switches: Sequence[Dict[str, Any]] = (),
    const_int_vars: Optional[Dict[str, int]] = None,
    const_str_vars: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Resolves `var_name` at `(ref_ancestors, ref_stmt_order, ref_line)` using lexical block scopes,
    constant-condition dead-branch elimination, receiver-mutating invocations, and statement-order
    reaching definitions.
    """
    ref_anc_list = list(ref_ancestors)
    ref_anc_set = set(ref_anc_list)
    c_ints = const_int_vars or {}
    c_strs = const_str_vars or {}

    candidates = [
        v
        for v in local_variables
        if v.get("name") == var_name
        and v.get("scope_id") in ref_anc_set
        and int(v.get("start_line", 0)) <= ref_line
        and int(v.get("stmt_order", 0)) <= ref_stmt_order
    ]
    if not candidates:
        return None

    # Sort by innermost scope in ref_anc_list (lowest index in ref_anc_list), then highest stmt_order
    candidates.sort(
        key=lambda v: (
            ref_anc_list.index(v["scope_id"]),
            -int(v.get("stmt_order", 0)),
        )
    )
    decl = candidates[0]
    decl_scope = int(decl["scope_id"])
    decl_order = int(decl["stmt_order"])

    # Pre-evaluate constant if_guards and switches
    dead_line_ranges: List[Tuple[int, int]] = []
    always_taken_line_ranges: List[Tuple[int, int, int]] = []  # (start_line, end_line, parent_scope_id)
    for g in if_guards:
        cval = _eval_const_bool_condition(str(g.get("condition", "")), c_ints)
        if cval is None:
            continue
        g_scope = int(g.get("scope_id", -1))
        t_s, t_e = int(g.get("then_start_line", -1)), int(g.get("then_end_line", -1))
        e_s, e_e = int(g.get("else_start_line", -1)), int(g.get("else_end_line", -1))
        if cval is True:
            if e_s > 0 and e_e >= e_s:
                dead_line_ranges.append((e_s, e_e))
            if t_s > 0 and t_e >= t_s:
                always_taken_line_ranges.append((t_s, t_e, g_scope))
        else:
            if t_s > 0 and t_e >= t_s:
                dead_line_ranges.append((t_s, t_e))
            if e_s > 0 and e_e >= e_s:
                always_taken_line_ranges.append((e_s, e_e, g_scope))

    const_switches_info: List[Tuple[int, int, List[Tuple[int, int]], int]] = []
    for sw in switches:
        sw_res = _eval_switch_taken_line_ranges(sw, c_strs, c_ints)
        if sw_res is not None:
            const_switches_info.append((sw_res[0], sw_res[1], sw_res[2], int(sw.get("scope_id", -1))))

    def _is_line_dead_and_dominating(ln: int, a_scope: int) -> Tuple[bool, bool]:
        for d_s, d_e in dead_line_ranges:
            if d_s <= ln <= d_e:
                return True, False
        dom_by_const_branch = False
        for t_s, t_e, p_scope in always_taken_line_ranges:
            if t_s <= ln <= t_e and p_scope in ref_anc_set:
                dom_by_const_branch = True
        for sw_min, sw_max, taken_list, sw_scope in const_switches_info:
            if sw_min <= ln <= sw_max:
                in_taken = any(r_s <= ln <= r_e for r_s, r_e in taken_list)
                if not in_taken:
                    return True, False
                if sw_scope in ref_anc_set:
                    dom_by_const_branch = True
        return False, (a_scope in ref_anc_set) or dom_by_const_branch

    # Active reaching definitions start with the declaration initializer (if non-empty)
    active_defs: List[Dict[str, Any]] = []
    if str(decl.get("init_expr", "")).strip():
        active_defs.append(
            {
                "expr": str(decl.get("init_expr", "")),
                "kind": str(decl.get("init_kind", "")),
                "identifiers": list(decl.get("identifiers", [])),
                "string_literals": list(decl.get("string_literals", [])),
                "stmt_order": decl_order,
                "line": int(decl.get("start_line", 0)),
                "dominating": True,
                "operator": "decl",
            }
        )

    reassigned = False
    last_mutation_order = decl_order
    last_mutation_line = int(decl.get("end_line", decl.get("start_line", 0)))

    relevant_asgns = [
        a
        for a in assignments
        if a.get("target") == var_name
        and decl_order < int(a.get("stmt_order", 0)) < ref_stmt_order
        and int(a.get("start_line", 0)) <= ref_line
        and decl_scope in set(a.get("ancestor_scopes", []))
    ]
    relevant_asgns.sort(key=lambda a: int(a.get("stmt_order", 0)))

    for a in relevant_asgns:
        a_scope = int(a.get("scope_id", -1))
        a_anc = set(a.get("ancestor_scopes", []))
        a_line = int(a.get("start_line", 0))
        shadowed = any(
            v.get("name") == var_name
            and int(v.get("scope_id", -1)) != decl_scope
            and int(v.get("scope_id", -1)) in a_anc
            and decl_scope in set(v.get("ancestor_scopes", []))
            and int(v.get("stmt_order", 0)) < int(a.get("stmt_order", 0))
            for v in local_variables
        )
        if shadowed:
            continue

        is_dead, is_branch_dom = _is_line_dead_and_dominating(a_line, a_scope)
        if is_dead:
            continue

        reassigned = True
        last_mutation_order = int(a.get("stmt_order", 0))
        last_mutation_line = int(a.get("end_line", a_line))
        is_dominating = is_branch_dom and (a.get("operator") == "=")

        new_def = {
            "expr": str(a.get("value_expr", "")),
            "kind": str(a.get("value_kind", "")),
            "identifiers": list(a.get("identifiers", [])),
            "string_literals": list(a.get("string_literals", [])),
            "stmt_order": int(a.get("stmt_order", 0)),
            "line": a_line,
            "dominating": is_dominating,
            "operator": str(a.get("operator", "=")),
        }
        if is_dominating:
            # Dominating unconditional assignment overwrites previous reaching definitions
            active_defs = [new_def]
        else:
            # Conditional branch assignment or += appends to active reaching definitions
            active_defs.append(new_def)

    # Also collect receiver-mutating invocations on `var_name` (e.g. `pb.command(argList)`,
    # `argList.add(x)`, `sb.append(x)`, `sb.replace(...)`, `map.put(k, v)`) after the last dominating assignment
    last_dom_order = max(
        (int(d["stmt_order"]) for d in active_defs if d.get("dominating")),
        default=decl_order,
    )
    mutator_methods = {"append", "replace", "insert", "add", "addAll", "put", "command", "set"}
    for inv in invocations:
        inv_order = int(inv.get("stmt_order", 0))
        inv_line = int(inv.get("start_line", 0))
        if (
            inv.get("receiver") == var_name
            and str(inv.get("method_name", "")) in mutator_methods
            and last_dom_order < inv_order < ref_stmt_order
            and inv_line <= ref_line
            and decl_scope in set(inv.get("ancestor_scopes", []))
        ):
            is_dead, _ = _is_line_dead_and_dominating(inv_line, int(inv.get("scope_id", -1)))
            if is_dead:
                continue
            args_list = inv.get("arguments", [])
            if not args_list:
                continue
            active_defs.append(
                {
                    "expr": " , ".join(str(x) for x in args_list),
                    "kind": (
                        str(inv["arg_kinds"][0])
                        if len(inv.get("arg_kinds", [])) == 1
                        else "METHOD_INVOCATION"
                    ),
                    "identifiers": list(inv.get("arg_identifiers", [])),
                    "string_literals": list(inv.get("arg_string_literals", [])),
                    "stmt_order": inv_order,
                    "line": inv_line,
                    "dominating": False,
                    "operator": f"mutator:{inv.get('method_name')}",
                }
            )
            last_mutation_order = max(last_mutation_order, inv_order)
            last_mutation_line = max(last_mutation_line, inv_line)

    return {
        "declaration": decl,
        "var_type": str(decl.get("type", "")),
        "is_try_resource": bool(decl.get("is_try_resource", False)),
        "reassigned": reassigned,
        "last_mutation_order": last_mutation_order,
        "last_mutation_line": last_mutation_line,
        "reaching_defs": active_defs,
    }


def _unproven_array_state_names(method: Dict[str, Any], sink_order: int) -> Set[str]:
    """Invalidate constant proofs for written/escaped arrays and their local aliases.

    This is a may-alias guard, not heap analysis: branches and ambiguous aliases
    are merged conservatively. An unknown call may mutate an array. Do not use
    the order at a declaration snapshot: aliases share storage until the sink.
    """
    locals_before = [v for v in method.get("local_variables", [])
                     if int(v.get("stmt_order", 0)) < sink_order]
    assignments = [a for a in method.get("assignments", [])
                   if int(a.get("stmt_order", 0)) < sink_order]
    array_names = {str(v.get("name", "")) for v in locals_before
                   if "[]" in str(v.get("type", "")) or v.get("init_kind") == "NEW_ARRAY"
                   or v.get("type", "") in ("", "var", "Object", "java.lang.Object")}
    variable_names = {str(v.get("name", "")) for v in locals_before}
    variable_names.update(str(p.get("name", "")) for p in method.get("parameters", []))
    # `var values = helper()` need not expose [] in the declaration type.
    # An indexed write itself establishes an array root without type attribution.
    for a in assignments:
        target = str(a.get("target", ""))
        if "[" in target:
            array_names.update(set(_extract_non_literal_identifiers(target.split("[", 1)[0])) & variable_names)
    edges: List[Tuple[str, str]] = []
    for v in locals_before:
        if v.get("init_kind") != "NEW_ARRAY" and (v.get("init_kind") in ("IDENTIFIER", "TYPE_CAST", "PARENTHESIZED") or (
            "[]" in str(v.get("type", "")) or v.get("type", "") in ("", "var", "Object", "java.lang.Object")
        )):
            edges.extend((str(v.get("name", "")), str(n)) for n in v.get("identifiers", [])
                         if n in variable_names)
    for a in assignments:
        target = str(a.get("target", ""))
        if re.fullmatch(r"[A-Za-z_$][\w$]*", target) and a.get("value_kind") in (
            "IDENTIFIER", "TYPE_CAST", "PARENTHESIZED"
        ):
            edges.extend((target, str(n)) for n in a.get("identifiers", []) if n in variable_names)

    def closure(names: Set[str]) -> Set[str]:
        names = set(names)
        changed = True
        while changed:
            changed = False
            for left, right in edges:
                if (left in names or right in names) and not {left, right} <= names:
                    names.update((left, right))
                    changed = True
        return names

    aliases = closure(array_names)
    uncertain: Set[str] = set()
    for a in assignments:
        target = str(a.get("target", ""))
        if "[" in target:
            uncertain.update(set(_extract_non_literal_identifiers(target)) & aliases)
        if not re.fullmatch(r"[A-Za-z_$][\w$]*", target):
            uncertain.update(set(a.get("identifiers", [])) & aliases)
    # TreeScanner visits an outer call before its nested argument calls. Include
    # those argument calls too; they can mutate the array before the sink runs.
    sink_calls = [i for i in method.get("invocations", [])
                  if int(i.get("stmt_order", 0)) == sink_order]
    sink_end = int(sink_calls[0].get("end_line", 0)) if sink_calls else 0
    for inv in method.get("invocations", []):
        order = int(inv.get("stmt_order", 0))
        if order == sink_order:
            continue
        if order > sink_order and int(inv.get("start_line", 0)) > sink_end:
            continue
        uncertain.update(set(inv.get("arg_identifiers", [])) & aliases)
        uncertain.update(set(_extract_non_literal_identifiers(str(inv.get("receiver", "")))) & aliases)
    for node in method.get("new_classes", []):
        if int(node.get("stmt_order", 0)) < sink_order:
            uncertain.update(set(node.get("arg_identifiers", [])) & aliases)
    return closure(uncertain)


def java_source_dependency_fingerprint(java_source_text: str, file_path: str) -> str:
    """Content key for named sibling/import sources, including missing files.

    Mirrors bounded source lookup without walking a repository or consulting the
    process-wide AST cache (which can contain unrelated projects).
    """
    pending = [(Path(file_path).resolve(), java_source_text)]
    seen: Dict[str, str] = {}
    while pending:
        path, source = pending.pop()
        if str(path) in seen:
            continue
        seen[str(path)] = hashlib.sha256(source.encode("utf-8")).hexdigest()
        clean = _strip_java_comments_multiline(source)
        pkg = re.search(r"\bpackage\s+([\w.]+)\s*;", clean)
        root = path.parent
        if pkg and list(root.parts[-len(pkg[1].split(".")):]) == pkg[1].split("."):
            for _ in pkg[1].split("."):
                root = root.parent
        imports = re.findall(r"\bimport\s+([\w.]+)\s*;", clean)
        paths = {path.parent / (name + ".java")
                 for name in re.findall(r"\b[A-Z][A-Za-z0-9_$]*\b", clean)}
        qualified_new = re.findall(r"\bnew\s+([a-z][\w.]*\.[A-Z]\w*)\s*\(", clean)
        paths.update(root / (imp.replace(".", "/") + ".java") for imp in imports + qualified_new)
        for candidate in paths:
            if str(candidate) in seen:
                continue
            try:
                pending.append((candidate, candidate.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                seen[str(candidate)] = "MISSING"
    return hashlib.sha256(json.dumps(seen, sort_keys=True).encode("utf-8")).hexdigest()


def _analyze_with_openjdk_ast(
    ast_file: Dict[str, Any],
    java_source_text: str,
    file_path: str,
    match_line: int,
    cwe: int,
    opengrep_rule_id: str,
    opengrep_matched_code: str,
) -> Optional[JavaAstSiteAnalysis]:
    """
    Executes semantic AST + lexical-scope dataflow analysis using the OpenJDK 17 `JavacTask` AST.
    """
    lines = java_source_text.splitlines()
    n_lines = len(lines)
    line_idx = max(0, min(int(match_line) - 1, n_lines - 1)) if n_lines else 0
    matched_code_line = opengrep_matched_code.strip() or (lines[line_idx].strip() if n_lines else "")

    pkg_name = str(ast_file.get("package_name") or "com.ntk.e2e")
    classes = ast_file.get("classes", [])
    if not classes:
        return None

    # Find enclosing class and method containing match_line
    target_class: Optional[Dict[str, Any]] = None
    target_method: Optional[Dict[str, Any]] = None
    for cls in classes:
        for m in cls.get("methods", []):
            if int(m.get("start_line", 0)) <= int(match_line) <= int(m.get("end_line", 0)):
                target_class = cls
                target_method = m
                break
        if target_method is not None:
            break

    if target_class is None:
        target_class = classes[0]
    if target_method is None:
        methods = target_class.get("methods", [])
        if not methods:
            return None
        # Pick method closest to match_line
        target_method = min(
            methods,
            key=lambda m: min(
                abs(int(m.get("start_line", 0)) - int(match_line)),
                abs(int(m.get("end_line", 0)) - int(match_line)),
            ),
        )

    cls_name = str(target_class.get("class_name", "UnknownClass"))
    enclosing_method = str(target_method.get("name", "unknownMethod"))
    enclosing_sig = shared.normalize_signature(str(target_method.get("signature", f"void {enclosing_method}()")))

    static_final_consts: Set[str] = set()
    field_names: Set[str] = set()
    for fld in target_class.get("fields", []):
        fname = str(fld.get("name", ""))
        if fname:
            field_names.add(fname)
            if fld.get("is_static") and fld.get("is_final") and _is_const_ast_kind(str(fld.get("init_kind", ""))):
                static_final_consts.add(fname)

    cwe_int = int(re.sub(r"\D", "", str(cwe)) or "0")

    # Identify untrusted formal parameters from AST MethodTree.parameters
    untrusted_params: List[str] = []
    for p in target_method.get("parameters", []):
        pname = str(p.get("name", "")).strip()
        ptype = str(p.get("type", "")).strip()
        if pname and ptype not in INFRASTRUCTURE_PARAM_TYPES:
            untrusted_params.append(pname)

    local_vars = target_method.get("local_variables", [])
    assignments = target_method.get("assignments", [])
    if_guards = target_method.get("if_guards", [])
    switches = target_method.get("switches", [])
    invocations = target_method.get("invocations", [])
    new_classes = target_method.get("new_classes", [])
    const_int_vars, const_str_vars = _compute_const_local_maps(local_vars, assignments)

    # Locate the primary sink MethodInvocationTree or NewClassTree on match_line
    line_invocations = [
        inv
        for inv in invocations
        if int(inv.get("start_line", 0)) <= int(match_line) <= int(inv.get("end_line", 0))
    ]
    sink_method_priority = {
        "executeQuery": 1,
        "executeUpdate": 1,
        "execute": 1,
        "addBatch": 1,
        "batchUpdate": 1,
        "queryForObject": 1,
        "queryForList": 1,
        "queryForMap": 1,
        "queryForRowSet": 1,
        "queryForInt": 1,
        "queryForLong": 1,
        "query": 1,
        "update": 1,
        "prepareStatement": 2,
        "prepareCall": 2,
        "exec": 1,
        "start": 1,
        "readAllBytes": 1,
        "readString": 1,
        "lines": 1,
        "newInputStream": 1,
        "println": 1,
        "print": 1,
        "write": 1,
        "printf": 1,
        "format": 1,
        "invoke": 3,
    }
    sink_inv: Optional[Dict[str, Any]] = None
    if line_invocations:
        line_invocations.sort(
            key=lambda inv: (
                sink_method_priority.get(str(inv.get("method_name", "")), 10),
                -len(str(inv.get("call_expr", ""))),
            )
        )
        sink_inv = line_invocations[0]

    line_new_classes = [
        nc
        for nc in new_classes
        if int(nc.get("start_line", 0)) <= int(match_line) <= int(nc.get("end_line", 0))
    ]
    sink_nc: Optional[Dict[str, Any]] = None
    if line_new_classes:
        nc_priority = {
            "FileInputStream": 1,
            "java.io.FileInputStream": 1,
            "FileOutputStream": 1,
            "java.io.FileOutputStream": 1,
            "FileReader": 1,
            "java.io.FileReader": 1,
            "FileWriter": 1,
            "java.io.FileWriter": 1,
            "File": 2,
            "java.io.File": 2,
        }
        line_new_classes.sort(
            key=lambda nc: (
                nc_priority.get(str(nc.get("class_type", "")), 10),
                -len(str(nc.get("new_expr", ""))),
            )
        )
        sink_nc = line_new_classes[0]

    use_nc_as_sink = bool(
        cwe_int == 22
        and sink_nc is not None
        and (
            sink_inv is None
            or str(sink_inv.get("method_name", ""))
            not in ("readAllBytes", "readString", "lines", "newInputStream")
        )
    )

    if use_nc_as_sink and sink_nc is not None:
        sink_scope_id = int(sink_nc.get("scope_id", 1))
        sink_ancestors = list(sink_nc.get("ancestor_scopes", [1, 0]))
        sink_stmt_order = int(sink_nc.get("stmt_order", 999999))
        sink_mname = f"new:{sink_nc.get('class_type', 'File')}"
        sink_recv = ""
        sink_args_exprs = list(sink_nc.get("arguments", []))
        sink_arg_kinds = list(sink_nc.get("arg_kinds", []))
        sink_arg_lits = list(sink_nc.get("arg_string_literals", []))
    else:
        sink_scope_id = int(sink_inv.get("scope_id", 1)) if sink_inv else 1
        sink_ancestors = list(sink_inv.get("ancestor_scopes", [1, 0])) if sink_inv else [1, 0]
        sink_stmt_order = int(sink_inv.get("stmt_order", 999999)) if sink_inv else 999999
        sink_mname = str(sink_inv.get("method_name", "")) if sink_inv else ""
        sink_recv = str(sink_inv.get("receiver", "")) if sink_inv else ""
        sink_args_exprs = list(sink_inv.get("arguments", [])) if sink_inv else []
        sink_arg_kinds = list(sink_inv.get("arg_kinds", [])) if sink_inv else []
        sink_arg_lits = list(sink_inv.get("arg_string_literals", [])) if sink_inv else []

    pure_transform_methods = {
        "get",
        "of",
        "toPath",
        "normalize",
        "resolve",
        "getName",
        "toString",
        "trim",
        "toLowerCase",
        "toUpperCase",
        "substring",
        "replace",
        "replaceAll",
        "split",
        "valueOf",
        "format",
        "decode",
        "encode",
        "encodeToString",
        "decodeBase64",
        "encodeBase64",
        "getBytes",
        "charAt",
        "length",
        "append",
        "command",
        "add",
    }

    source_units = [(ast_file, Path(file_path))]

    def source_class(type_name, owner):
        simple = type_name.rsplit(".", 1)[-1]
        contexts = [(unit, path) for unit, path in source_units
                    if any(cls is owner for cls in unit.get("classes", []))]
        if len(contexts) != 1:
            return None
        for unit, path in contexts:
            matches = [cls for cls in unit.get("classes", []) if cls.get("class_name") == simple]
            if matches:
                return matches[0] if len(matches) == 1 else None
            pkg = str(unit.get("package_name", ""))
            root = path.parent
            if pkg and list(root.parts[-len(pkg.split(".")):]) == pkg.split("."):
                for _ in pkg.split("."):
                    root = root.parent
            candidates = {path.parent / (simple + ".java")}
            if "." in type_name:
                candidates.add(root / (type_name.replace(".", "/") + ".java"))
            for imp in unit.get("imports", []):
                if str(imp).endswith("." + simple) and not str(imp).startswith("static "):
                    candidates.add(root / (str(imp).replace(".", "/") + ".java"))
            existing = [cp for cp in candidates if cp.is_file()]
            if len(existing) != 1:
                continue
            cp = existing[0]
            parsed = next((unit for unit, old_path in source_units if cp == old_path), None)
            if parsed is None:
                try:
                    helper_source = cp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    return None
                parsed = parse_java_source_with_javac_ast(helper_source, str(cp))
            if parsed:
                if not any(cp == old_path for _, old_path in source_units):
                    source_units.append((parsed, cp))
                matches = [c for c in parsed.get("classes", []) if c.get("class_name") == simple]
                if len(matches) == 1:
                    return matches[0]
        return None

    def _build_method_tracer(
        m_dict: Dict[str, Any],
        m_untrusted_map: Dict[str, Tuple[str, ...]],
        m_const_overrides: Dict[str, str],
        max_stmt_order: int,
        visited_methods: Set[str],
        owner_class: Optional[Dict[str, Any]] = None,
    ):
        owner_class = owner_class or target_class
        owner_fields = {str(f.get("name", "")) for f in owner_class.get("fields", [])}
        owner_consts = {str(f.get("name", "")) for f in owner_class.get("fields", [])
                        if f.get("is_static") and f.get("is_final")
                        and _is_const_ast_kind(str(f.get("init_kind", "")))}
        m_local_vars = m_dict.get("local_variables", [])
        m_assignments = m_dict.get("assignments", [])
        m_if_guards = m_dict.get("if_guards", [])
        m_switches = m_dict.get("switches", [])
        m_invocations = m_dict.get("invocations", [])
        m_new_classes = m_dict.get("new_classes", [])
        unproven_arrays = _unproven_array_state_names(m_dict, max_stmt_order)
        # Array parameters do not have a local heap-state proof. A literal
        # initializer at the caller does not prove the callee cannot mutate it.
        unproven_arrays.update(str(p.get("name", "")) for p in m_dict.get("parameters", [])
                               if "[]" in str(p.get("type", ""))
                               or p.get("type") in ("Object", "java.lang.Object"))
        m_c_ints, m_c_strs = _compute_const_local_maps(m_local_vars, m_assignments)
        for k_ov, v_ov in m_const_overrides.items():
            m_c_strs[k_ov] = v_ov

        servlet_types = {"HttpServletRequest", "javax.servlet.http.HttpServletRequest",
                         "jakarta.servlet.http.HttpServletRequest"}

        def standard_type(receiver, qualified):
            # JavacTask.parse has no classpath attribution. Admit only an explicit
            # JDK name/import with no local, field or source-class shadow.
            root = receiver.split(".", 1)[0]
            if root in owner_fields or any(v.get("name") == root for v in m_local_vars + m_dict.get("parameters", [])):
                return False
            if receiver == qualified:
                return True
            simple = qualified.rsplit(".", 1)[-1]
            units = [u for u, _ in source_units if any(c is owner_class for c in u.get("classes", []))]
            return (receiver == simple and len(units) == 1
                    and qualified in units[0].get("imports", [])
                    and not any(c.get("class_name") == simple for c in units[0].get("classes", []))
                    and source_class(simple, owner_class) is None)

        def servlet_receiver(receiver):
            return (receiver in m_untrusted_map and any(
                p.get("name") == receiver and p.get("type") in servlet_types
                for p in m_dict.get("parameters", []))
                and not any(c.get("class_name") == "HttpServletRequest"
                            for u, _ in source_units for c in u.get("classes", [])))

        def declared_type(expr, ancestors, order, line):
            if re.fullmatch(r'"(?:\\.|[^"\\])*"', expr.strip()):
                return "String"
            local = _resolve_variable_in_scope(expr, ancestors, order, line, m_local_vars, m_assignments)
            if local:
                return str(local["var_type"])
            return next((str(p.get("type", "")) for p in m_dict.get("parameters", [])
                         if p.get("name") == expr), "")

        def header_origin(expr, ancestors, order, line, seen=frozenset()):
            if expr in seen or len(seen) >= 12:
                return None
            calls = [i for i in m_invocations if i.get("call_expr") == expr
                     and i.get("method_name") == "getHeaders" and servlet_receiver(i.get("receiver"))
                     and len(i.get("arguments", [])) == 1
                     and declared_type(str(i["arguments"][0]), ancestors, order, line) in ("String", "java.lang.String")]
            if calls:
                return calls[0]
            local = _resolve_variable_in_scope(expr, ancestors, order, line, m_local_vars,
                                                m_assignments, m_invocations, m_if_guards, m_switches)
            defs = local["reaching_defs"] if local else []
            if len(defs) != 1 or not defs[0].get("dominating"):
                return None
            aliases = {expr}
            edges = [(v.get("name"), v.get("init_expr")) for v in m_local_vars
                     if v.get("init_kind") == "IDENTIFIER"]
            while True:
                previous = set(aliases)
                for a, b in edges:
                    if a in aliases or b in aliases:
                        aliases.update((a, b))
                if previous == aliases:
                    break
            if any(int(i.get("stmt_order", 0)) < max_stmt_order
                   and aliases.intersection(i.get("arg_identifiers", [])) for i in m_invocations):
                return None
            if any(int(a.get("stmt_order", 0)) < max_stmt_order
                   and not re.fullmatch(r"[A-Za-z_$][\w$]*", str(a.get("target", "")))
                   and aliases.intersection(a.get("identifiers", [])) for a in m_assignments):
                return None
            if any(int(n.get("stmt_order", 0)) < max_stmt_order
                   and aliases.intersection(n.get("arg_identifiers", [])) for n in m_new_classes):
                return None
            d = defs[0]
            return header_origin(str(d["expr"]), local["declaration"]["ancestor_scopes"],
                                 int(d["stmt_order"]), int(d["line"]), seen | {expr})

        def expression_type(expr, ancestors, order, line):
            declared = declared_type(expr, ancestors, order, line)
            if declared:
                return declared
            for i in m_invocations:
                if i.get("call_expr") != expr:
                    continue
                if (servlet_receiver(i.get("receiver")) and i.get("method_name") in
                        ("getParameter", "getHeader", "getQueryString")):
                    return "String"
                if (i.get("method_name") == "nextElement" and not i.get("arguments")
                        and header_origin(str(i.get("receiver")), ancestors, order, line)):
                    return "String"
            return ""

        def _trace_expr(
            expr_str: str,
            expr_kind: str,
            expr_idents: Sequence[str],
            ref_anc: Sequence[int],
            ref_order: int,
            ref_ln: int,
            visited_vars: Optional[Set[Tuple[str, int, int]]] = None,
        ) -> Dict[str, Any]:
            if visited_vars is None:
                visited_vars = set()

            cleaned_expr = expr_str.strip()

            # 1. Constant-condition ternary expression (`cond ? true_expr : false_expr`)
            if expr_kind == "CONDITIONAL_EXPR" or ("?" in cleaned_expr and ":" in cleaned_expr):
                tern = _split_top_level_ternary(cleaned_expr)
                if tern is not None:
                    cond_s, t_s, f_s = tern
                    c_bool = _eval_const_bool_condition(cond_s, m_c_ints)
                    if c_bool is not None:
                        chosen_s = t_s if c_bool else f_s
                        chosen_kind = (
                            "STRING_LITERAL"
                            if (chosen_s.startswith('"') and chosen_s.endswith('"'))
                            else "IDENTIFIER"
                        )
                        chosen_idents = _extract_non_literal_identifiers(chosen_s)
                        return _trace_expr(
                            expr_str=chosen_s,
                            expr_kind=chosen_kind,
                            expr_idents=chosen_idents,
                            ref_anc=ref_anc,
                            ref_order=ref_order,
                            ref_ln=ref_ln,
                            visited_vars=visited_vars,
                        )

            # 2. Key-sensitive `Map.get("literalKey")` resolution
            m_map_get = re.match(
                r'^(?:\([\w\.\[\]\s]+\)\s*)?([A-Za-z_$][A-Za-z0-9_$]*)\.get\(\s*("(?:\\.|[^"\\])*")\s*\)$',
                cleaned_expr,
            )
            if m_map_get:
                map_var = m_map_get.group(1)
                key_lit = m_map_get.group(2)
                matching_puts = [
                    inv
                    for inv in m_invocations
                    if inv.get("receiver") == map_var
                    and inv.get("method_name") == "put"
                    and len(inv.get("arguments", [])) == 2
                    and int(inv.get("stmt_order", 0)) < ref_order
                    and str(inv["arguments"][0]).strip() == key_lit
                ]
                if matching_puts:
                    matching_puts.sort(key=lambda inv: int(inv.get("stmt_order", 0)))
                    last_put = matching_puts[-1]
                    val_expr = str(last_put["arguments"][1]).strip()
                    val_kind = (
                        str(last_put["arg_kinds"][1])
                        if len(last_put.get("arg_kinds", [])) >= 2
                        else "UNKNOWN"
                    )
                    val_idents = _extract_non_literal_identifiers(val_expr)
                    return _trace_expr(
                        expr_str=val_expr,
                        expr_kind=val_kind,
                        expr_idents=val_idents,
                        ref_anc=last_put.get("ancestor_scopes", ref_anc),
                        ref_order=int(last_put.get("stmt_order", ref_order)),
                        ref_ln=int(last_put.get("start_line", ref_ln)),
                        visited_vars=visited_vars,
                    )

            # 3. Index-sensitive `List.get(intLiteral)` resolution
            m_list_get = re.match(
                r"^(?:\([\w\.\[\]\s]+\)\s*)?([A-Za-z_$][A-Za-z0-9_$]*)\.get\(\s*(\d+)\s*\)$",
                cleaned_expr,
            )
            if m_list_get:
                list_var = m_list_get.group(1)
                idx_val = int(m_list_get.group(2))
                list_ops = [
                    inv
                    for inv in m_invocations
                    if inv.get("receiver") == list_var
                    and inv.get("method_name") in ("add", "remove", "clear")
                    and int(inv.get("stmt_order", 0)) < ref_order
                ]
                if list_ops:
                    list_ops.sort(key=lambda inv: int(inv.get("stmt_order", 0)))
                    sim_items: List[Tuple[str, str, Dict[str, Any]]] = []
                    sim_ok = True
                    for op_inv in list_ops:
                        op_m = op_inv.get("method_name")
                        op_args = op_inv.get("arguments", [])
                        op_kinds = op_inv.get("arg_kinds", [])
                        if op_m == "add" and len(op_args) == 1:
                            sim_items.append(
                                (
                                    str(op_args[0]).strip(),
                                    str(op_kinds[0]) if op_kinds else "UNKNOWN",
                                    op_inv,
                                )
                            )
                        elif op_m == "remove" and len(op_args) == 1 and re.match(r"^\d+$", str(op_args[0]).strip()):
                            r_idx = int(str(op_args[0]).strip())
                            if 0 <= r_idx < len(sim_items):
                                sim_items.pop(r_idx)
                        elif op_m == "clear" and len(op_args) == 0:
                            sim_items.clear()
                        else:
                            sim_ok = False
                            break
                    if sim_ok and 0 <= idx_val < len(sim_items):
                        el_expr, el_kind, el_inv = sim_items[idx_val]
                        el_idents = _extract_non_literal_identifiers(el_expr)
                        return _trace_expr(
                            expr_str=el_expr,
                            expr_kind=el_kind,
                            expr_idents=el_idents,
                            ref_anc=el_inv.get("ancestor_scopes", ref_anc),
                            ref_order=int(el_inv.get("stmt_order", ref_order)),
                            ref_ln=int(el_inv.get("start_line", ref_ln)),
                            visited_vars=visited_vars,
                        )

            trace_steps: List[str] = [expr_str] if expr_str else []
            all_kinds: Set[str] = {expr_kind} if expr_kind else set()
            all_idents: Set[str] = set(expr_idents)
            all_lits: List[str] = []
            reaching_invocations: List[Dict[str, Any]] = []
            reaching_new_classes: List[Dict[str, Any]] = []
            has_non_const_reassignment = False
            mapped_tainted_params: Set[str] = set()

            direct_invs: List[Dict[str, Any]] = []
            for inv in m_invocations:
                if (
                    (int(inv.get("stmt_order", 0)) <= max_stmt_order
                     or int(inv.get("start_line", 0)) <= match_line <= int(inv.get("end_line", 0)))
                    and inv.get("call_expr", "")
                    and inv.get("call_expr", "") in expr_str
                ):
                    reaching_invocations.append(inv)
                    direct_invs.append(inv)
                    all_lits.extend(inv.get("arg_string_literals", []))
            for nc in m_new_classes:
                if (
                    int(nc.get("stmt_order", 0)) <= max_stmt_order
                    and nc.get("new_expr", "")
                    and nc.get("new_expr", "") in expr_str
                ):
                    reaching_new_classes.append(nc)
                    all_lits.extend(nc.get("arg_string_literals", []))

            # Calls carry return-value evidence, not lexical argument membership.
            # Only outer calls are evaluated here; nested calls are evaluated through
            # their arguments/returns so an unknown wrapper cannot inherit source taint.
            known_constructors = {"String", "java.lang.String", "StringBuilder", "java.lang.StringBuilder",
                                  "File", "java.io.File", "ProcessBuilder", "java.lang.ProcessBuilder",
                                  "ArrayList", "java.util.ArrayList", "ArrayList<String>", "java.util.ArrayList<String>"}
            unknown_constructors = [nc for nc in reaching_new_classes
                                    if nc.get("class_type") not in known_constructors]
            direct_invs = [inv for inv in direct_invs if not any(
                inv["call_expr"] in str(nc.get("new_expr", "")) for nc in unknown_constructors)]
            direct_invs = [inv for inv in direct_invs if not any(
                inv["call_expr"] != outer["call_expr"]
                and inv["call_expr"] in outer["call_expr"] for outer in direct_invs)]
            helper_resolved_const = False
            helper_const_val = ""
            call_unknown = bool(unknown_constructors)
            call_results = []
            residual = expr_str
            for nc in unknown_constructors:
                unknown_expr = str(nc.get("new_expr", ""))
                trace_steps.append("UNKNOWN_CALL_RETURN:" + unknown_expr)
            for inv in direct_invs:
                call = str(inv.get("call_expr", ""))
                name = str(inv.get("method_name", ""))
                recv = str(inv.get("receiver", "")).strip()
                callee_class = None
                if recv in ("", "this", str(owner_class.get("class_name", ""))):
                    callee_class = owner_class
                else:
                    # Resolve an exact newly constructed local receiver, or a class
                    # reference. Interface/field/ambiguous receiver state stays unknown.
                    local = _resolve_variable_in_scope(
                        recv, ref_anc, ref_order, ref_ln, m_local_vars, m_assignments)
                    if local:
                        defs = local["reaching_defs"]
                        if len(defs) == 1:
                            ctor = re.match(r"^new\s+([\w.]+)\s*\(", defs[0]["expr"])
                            if ctor:
                                callee_class = source_class(ctor.group(1), owner_class)
                    elif re.fullmatch(r"[\w.]+", recv) and recv[:1].isupper():
                        callee_class = source_class(recv, owner_class)
                    else:
                        ctor = re.match(r"^new\s+([\w.]+)\s*\(", recv)
                        if ctor:
                            callee_class = source_class(ctor.group(1), owner_class)

                candidates = [cm for cm in (callee_class or {}).get("methods", [])
                              if cm.get("name") == name
                              and len(cm.get("parameters", [])) == len(inv.get("arguments", []))]
                key = str((callee_class or {}).get("class_name", "")) + ":" + name
                result = None
                if len(candidates) == 1 and key not in visited_methods and len(visited_methods) < 12:
                    cm = candidates[0]
                    cm_map, cm_consts = {}, {}
                    for i, param in enumerate(cm.get("parameters", [])):
                        arg = str(inv["arguments"][i])
                        sub = _trace_expr(arg, inv["arg_kinds"][i],
                                          _extract_non_literal_identifiers(arg), ref_anc,
                                          int(inv.get("stmt_order", ref_order)), ref_ln, set(visited_vars))
                        if sub["tainted_params_used"]:
                            cm_map[param["name"]] = sub["tainted_params_used"]
                        elif sub["is_pure_compile_time_constant"]:
                            cm_consts[param["name"]] = sub["const_repr"]
                    tracer = _build_method_tracer(cm, cm_map, cm_consts, 999999,
                                                  visited_methods | {key}, callee_class)
                    returns = [tracer(str(r.get("expr", "")), str(r.get("kind", "")),
                                      r.get("identifiers", []), r.get("ancestor_scopes", [1, 0]),
                                      int(r.get("stmt_order", 999999)), int(r.get("start_line", 0)))
                               for r in cm.get("returns", [])]
                    if returns:
                        # A branch-dependent tainted return is a possible flow, not
                        # proof of a feasible source-to-sink return path.
                        all_safe = all(r["is_pure_compile_time_constant"] for r in returns)
                        unconditional_return = any(
                            r.get("ancestor_scopes") == [1, 0]
                            and not any(int(g.get(prefix + "_start_line", -1)) <= int(r.get("start_line", 0))
                                        <= int(g.get(prefix + "_end_line", -1))
                                        for g in cm.get("if_guards", []) for prefix in ("then", "else"))
                            for r in cm.get("returns", []))
                        all_taint = unconditional_return and all(r["tainted_params_used"] for r in returns)
                        result = dict(returns[0])
                        result["is_pure_compile_time_constant"] = all_safe
                        result["tainted_params_used"] = tuple(sorted(set().union(
                            *(set(r["tainted_params_used"]) for r in returns)))) if all_taint else ()
                        result["trace_steps"] = ["HELPER_RETURN:" + key] + [
                            step for r in returns for step in r["trace_steps"]]
                        result["reaching_invocations"] = [i for r in returns for i in r["reaching_invocations"]]
                        result["reaching_new_classes"] = [n for r in returns for n in r["reaching_new_classes"]]
                        result["all_idents"] = set()  # callee names are in a different scope
                # Explicit external source APIs and modeled value transforms.
                source_getters = {"getParameter", "getParameterValues", "getHeader", "getHeaders", "getQueryString"}
                source_recv = recv in m_untrusted_map and any(
                    p.get("name") == recv and str(p.get("type", "")).endswith("HttpServletRequest")
                    for p in m_dict.get("parameters", []))
                sanitizer_names = {sig.rsplit("::", 1)[-1] for sigs in
                                   shared.APPROVED_CWE_SANITIZER_SIGNATURES.values() for sig in sigs}
                receiver_type = next((str(p.get("type", "")) for p in m_dict.get("parameters", [])
                                      if p.get("name") == recv), "")
                receiver_local = _resolve_variable_in_scope(
                    recv, ref_anc, ref_order, ref_ln, m_local_vars, m_assignments)
                if receiver_local:
                    receiver_type = str(receiver_local["var_type"])
                known_types = {"String", "StringBuilder", "StringBuffer", "Path", "File",
                               "List", "ArrayList", "Map", "HashMap", "ProcessBuilder"}
                simple_type = receiver_type.split("<", 1)[0].rsplit(".", 1)[-1]
                static_receiver = recv in ("String", "java.lang.String", "Paths", "java.nio.file.Paths",
                                           "Path", "java.nio.file.Path", "Base64", "java.util.Base64")
                nested_receiver = "(" in recv and not recv.startswith("new ")
                modeled = (callee_class is None and name in pure_transform_methods
                           and (simple_type in known_types or static_receiver or nested_receiver))
                # Approved sanitizer identity is checked again by the release engine.
                modeled = modeled or (name in sanitizer_names and (
                    "ESAPI" in recv or "Encode" in recv or "FilenameUtils" in recv))
                transfer = None
                transfer_signature = ""
                transfer_encoding_constant = False
                args = inv.get("arguments", [])
                kinds = inv.get("arg_kinds", [])
                if result is None and name == "decode" and standard_type(recv, "java.net.URLDecoder") and len(args) == 2:
                    data_type = expression_type(str(args[0]), ref_anc, ref_order, ref_ln)
                    encoding_type = declared_type(str(args[1]), ref_anc, ref_order, ref_ln)
                    # Charset constants have a verified declaring class/import.
                    charset = str(args[1]).rsplit(".", 1)
                    charset_constant = (len(charset) == 2 and standard_type(charset[0], "java.nio.charset.StandardCharsets")
                                        and charset[1] in {"UTF_8", "US_ASCII", "ISO_8859_1", "UTF_16", "UTF_16BE", "UTF_16LE"})
                    if encoding_type == "Charset" and not standard_type("Charset", "java.nio.charset.Charset"):
                        encoding_type = ""
                    if charset_constant:
                        encoding_type = "java.nio.charset.Charset"
                    if data_type in ("String", "java.lang.String") and encoding_type in (
                            "String", "java.lang.String", "Charset", "java.nio.charset.Charset"):
                        signature_arg = "java.nio.charset.Charset" if "Charset" in encoding_type else "String"
                        transfer_signature = f"String decode(String, {signature_arg})"
                        transfer = (str(args[0]), str(kinds[0]), ref_anc, ref_order, ref_ln)
                        enc_sub = _trace_expr(str(args[1]), str(kinds[1]),
                                              _extract_non_literal_identifiers(str(args[1])), ref_anc,
                                              ref_order, ref_ln, set(visited_vars))
                        transfer_encoding_constant = charset_constant or enc_sub["is_pure_compile_time_constant"]
                elif result is None and name == "nextElement" and not args:
                    origin = header_origin(recv, ref_anc, ref_order, ref_ln)
                    if origin:
                        transfer_signature = "E nextElement() [E=String; HttpServletRequest.getHeaders(String)]"
                        transfer = (str(origin["call_expr"]), "METHOD_INVOCATION", origin["ancestor_scopes"],
                                    int(origin["stmt_order"]), int(origin["start_line"]))
                if transfer:
                    operand, kind, ancestors, order, line = transfer
                    sub = _trace_expr(operand, kind, _extract_non_literal_identifiers(operand),
                                      ancestors, order, line, set(visited_vars))
                    result = dict(sub)
                    identity = "java.net.URLDecoder" if name == "decode" else "java.util.Enumeration"
                    result["trace_steps"] = [f"API_TAINT_TRANSFER:{identity}::{transfer_signature}"] + sub["trace_steps"]
                    result["reaching_invocations"] = [inv] + sub["reaching_invocations"]
                    # Decoding is not sanitization. Constant propagation requires
                    # independently proven constant data AND encoding operands.
                    result["is_pure_compile_time_constant"] = False
                    if name == "decode" and transfer_encoding_constant and kinds[0] == "STRING_LITERAL":
                        # Fold literal inputs only when the output value can be
                        # computed exactly; an undecoded const_repr could select
                        # the wrong switch/guard path in a downstream helper.
                        try:
                            literal = json.loads(str(args[0]))
                            encoding = ({"UTF_8": "UTF-8", "US_ASCII": "US-ASCII", "ISO_8859_1": "ISO-8859-1"}
                                        .get(charset[-1], "") if charset_constant else json.loads(str(args[1])))
                            if encoding.upper().replace("_", "-") in {"UTF-8", "UTF8", "US-ASCII", "ISO-8859-1"} and not re.search(r"%(?![0-9a-fA-F]{2})", literal):
                                result["const_repr"] = urllib.parse.unquote_plus(literal, encoding=encoding, errors="replace")
                                result["is_pure_compile_time_constant"] = True
                        except (ValueError, LookupError, TypeError):
                            pass

                if result is None and source_recv and name in source_getters:
                    result = {
                        "trace_steps": ["SOURCE_API:" + call], "all_kinds": {"METHOD_INVOCATION"},
                        "all_idents": set(), "all_lits": [], "reaching_invocations": [inv],
                        "reaching_new_classes": [], "tainted_params_used": m_untrusted_map[recv],
                        "is_pure_compile_time_constant": False, "const_repr": "",
                    }
                elif result is None and modeled:
                    operands = [(str(a), str(k)) for a, k in zip(inv.get("arguments", []), inv.get("arg_kinds", []))]
                    if not static_receiver and name not in sanitizer_names:
                        operands.append((recv, "METHOD_INVOCATION" if "(" in recv else "IDENTIFIER"))
                    subs = [_trace_expr(a, k, _extract_non_literal_identifiers(a), ref_anc,
                                        ref_order, ref_ln, set(visited_vars)) for a, k in operands]
                    if subs:
                        result = {
                            "trace_steps": [step for sub in subs for step in sub["trace_steps"]],
                            "all_kinds": set().union(*(sub["all_kinds"] for sub in subs)),
                            "all_idents": set().union(*(sub["all_idents"] for sub in subs)),
                            "all_lits": [lit for sub in subs for lit in sub["all_lits"]],
                            "reaching_invocations": [inv] + [i for sub in subs for i in sub["reaching_invocations"]],
                            "reaching_new_classes": [n for sub in subs for n in sub["reaching_new_classes"]],
                            "tainted_params_used": tuple(sorted(set().union(*(set(sub["tainted_params_used"]) for sub in subs)))),
                            "is_pure_compile_time_constant": all(sub["is_pure_compile_time_constant"] for sub in subs),
                            "const_repr": " ".join(sub["const_repr"] for sub in subs),
                        }
                if result is None:
                    call_unknown = True
                    trace_steps.append("UNKNOWN_CALL_RETURN:" + call)
                else:
                    call_results.append(result)
                    if not result["is_pure_compile_time_constant"] and not result["tainted_params_used"]:
                        trace_steps.append("UNKNOWN_CALL_RETURN:" + call)
                    trace_steps.extend(result["trace_steps"])
                    reaching_invocations.extend(result["reaching_invocations"])
                    reaching_new_classes.extend(result["reaching_new_classes"])
                    mapped_tainted_params.update(result["tainted_params_used"])
                residual = residual.replace(call, "")
            for nc in unknown_constructors:
                residual = residual.replace(str(nc.get("new_expr", "")), "")
            if direct_invs or unknown_constructors:
                all_idents = set(_extract_non_literal_identifiers(residual))
                helper_resolved_const = (not residual.strip() and not call_unknown and bool(call_results)
                                         and all(r["is_pure_compile_time_constant"] for r in call_results))
                if helper_resolved_const:
                    helper_const_val = call_results[0]["const_repr"]

            is_const_leaf, const_leaf_val = _is_pure_const_path_factory_expr(
                expr_str, m_invocations, m_new_classes, static_final_consts
            )
            all_invs_pure = all(
                str(inv.get("method_name", "")) in pure_transform_methods for inv in direct_invs
            )
            all_ncs_pure = all(
                str(nc.get("class_type", ""))
                in (
                    "String",
                    "java.lang.String",
                    "StringBuilder",
                    "java.lang.StringBuilder",
                    "File",
                    "java.io.File",
                    "FileInputStream",
                    "java.io.FileInputStream",
                    "FileOutputStream",
                    "java.io.FileOutputStream",
                    "FileReader",
                    "java.io.FileReader",
                    "FileWriter",
                    "java.io.FileWriter",
                    "ProcessBuilder",
                    "java.lang.ProcessBuilder",
                    "ArrayList",
                    "java.util.ArrayList",
                    "ArrayList<String>",
                    "java.util.ArrayList<String>",
                )
                for nc in reaching_new_classes
            )

            if _is_const_ast_kind(expr_kind) or is_const_leaf or helper_resolved_const:
                all_defs_const = True
            elif (
                expr_kind
                in (
                    "IDENTIFIER",
                    "BINARY_PLUS",
                    "PARENTHESIZED",
                    "NEW_ARRAY",
                    "ARRAY_ACCESS",
                    "TYPE_CAST",
                    "METHOD_INVOCATION",
                    "NEW_CLASS",
                )
                and (len(expr_idents) > 0 or direct_invs or reaching_new_classes)
                and all_invs_pure
                and all_ncs_pure
            ):
                all_defs_const = True
            else:
                all_defs_const = False
            if call_unknown or any(not r["is_pure_compile_time_constant"] for r in call_results):
                all_defs_const = False
            const_repr = helper_const_val or const_leaf_val or expr_str.strip('"')

            for ident in list(all_idents):
                if ident in m_const_overrides:
                    const_repr = m_const_overrides[ident]
                    continue

                resolved = _resolve_variable_in_scope(
                    var_name=ident,
                    ref_ancestors=ref_anc,
                    ref_stmt_order=ref_order,
                    ref_line=ref_ln,
                    local_variables=m_local_vars,
                    assignments=m_assignments,
                    invocations=m_invocations,
                    if_guards=m_if_guards,
                    switches=m_switches,
                    const_int_vars=m_c_ints,
                    const_str_vars=m_c_strs,
                )
                if resolved is None:
                    if ident in m_untrusted_map:
                        all_defs_const = False
                        mapped_tainted_params.update(m_untrusted_map[ident])
                    elif ident in owner_consts:
                        continue
                    elif ident in owner_fields or any(p.get("name") == ident for p in m_dict.get("parameters", [])):
                        all_defs_const = False
                    elif expr_kind in ("IDENTIFIER", "MEMBER_SELECT"):
                        all_defs_const = False
                    continue

                decl_scope = int(resolved["declaration"]["scope_id"])
                mut_order = int(resolved["last_mutation_order"])
                visit_key = (ident, decl_scope, mut_order)
                if visit_key in visited_vars:
                    continue
                visited_vars.add(visit_key)

                r_defs = resolved["reaching_defs"]
                if not r_defs:
                    all_defs_const = False
                    continue
                # A conditional branch `=` assignment (non-dominating, not a deterministic container mutator)
                # means the variable has multiple branch-dependent reaching definitions
                if len(r_defs) > 1 and any(
                    not d.get("dominating")
                    and not str(d.get("operator", "")).startswith("mutator:")
                    for d in r_defs
                ):
                    has_non_const_reassignment = True

                for d in r_defs:
                    d_expr = d["expr"]
                    d_kind = d["kind"]
                    d_order = d["stmt_order"]
                    d_line = d["line"]
                    trace_steps.append(f"{ident} = {d_expr} (line {d_line})")
                    all_lits.extend(d.get("string_literals", []))

                    # Empty container constructor declaration followed by mutators is neutral if mutators are constant
                    if (
                        d.get("operator") == "decl"
                        and len(r_defs) > 1
                        and d_kind == "NEW_CLASS"
                        and not d.get("identifiers")
                    ):
                        continue

                    sub = _trace_expr(
                        expr_str=d_expr,
                        expr_kind=d_kind,
                        expr_idents=d.get("identifiers", []),
                        ref_anc=resolved["declaration"]["ancestor_scopes"],
                        ref_order=d_order,
                        ref_ln=d_line,
                        visited_vars=visited_vars,
                    )
                    for st in sub["trace_steps"]:
                        if st not in trace_steps:
                            trace_steps.append(st)
                    all_kinds.update(sub["all_kinds"])
                    all_idents.update(sub["all_idents"])
                    all_lits.extend(sub["all_lits"])
                    for r_inv in sub["reaching_invocations"]:
                        if r_inv not in reaching_invocations:
                            reaching_invocations.append(r_inv)
                    for r_nc in sub["reaching_new_classes"]:
                        if r_nc not in reaching_new_classes:
                            reaching_new_classes.append(r_nc)
                    mapped_tainted_params.update(sub["tainted_params_used"])
                    if not sub["is_pure_compile_time_constant"]:
                        all_defs_const = False
                    else:
                        const_repr = sub["const_repr"]

            tainted_used = tuple(p for p in untrusted_params if p in mapped_tainted_params)
            unproven_array_dependencies = all_idents & unproven_arrays
            if unproven_array_dependencies:
                tainted_used = ()  # unknown heap state invalidates the old value proof too
                trace_steps.append("ARRAY_STATE_UNPROVEN:" + ",".join(sorted(unproven_array_dependencies)))
            is_pure_const = (
                all_defs_const
                and not tainted_used
                and not has_non_const_reassignment
                and not unproven_array_dependencies
                and not any(f in all_idents for f in (owner_fields - owner_consts))
            )

            return {
                "trace_steps": trace_steps,
                "all_kinds": all_kinds,
                "all_idents": all_idents,
                "all_lits": all_lits,
                "reaching_invocations": reaching_invocations,
                "reaching_new_classes": reaching_new_classes,
                "tainted_params_used": tainted_used,
                "is_pure_compile_time_constant": is_pure_const,
                "const_repr": const_repr,
                "proof_state": "PROVEN_TAINT" if tainted_used else ("PROVEN_SAFE" if is_pure_const else "UNKNOWN"),
            }

        return _trace_expr

    root_untrusted_map = {p: (p,) for p in untrusted_params}
    trace_expression = _build_method_tracer(
        m_dict=target_method,
        m_untrusted_map=root_untrusted_map,
        m_const_overrides={},
        max_stmt_order=sink_stmt_order,
        visited_methods={cls_name + ":" + enclosing_method},
    )

    # Resolve canonical target callee identity & primary sink argument expression
    ast_overloaded_sig = ""
    is_prepared_stmt_call = False
    ps_var_name = ""

    sql_sink_methods = {
        "executeQuery",
        "executeUpdate",
        "execute",
        "addBatch",
        "batchUpdate",
        "queryForObject",
        "queryForList",
        "queryForMap",
        "queryForRowSet",
        "queryForInt",
        "queryForLong",
        "query",
        "update",
        "prepareStatement",
        "prepareCall",
    }

    if sink_mname in sql_sink_methods:
        recv_resolved = _resolve_variable_in_scope(
            var_name=sink_recv,
            ref_ancestors=sink_ancestors,
            ref_stmt_order=sink_stmt_order,
            ref_line=int(match_line),
            local_variables=local_vars,
            assignments=assignments,
            invocations=invocations,
            if_guards=if_guards,
            switches=switches,
            const_int_vars=const_int_vars,
            const_str_vars=const_str_vars,
        )
        recv_type = recv_resolved["var_type"] if recv_resolved else ""
        if not recv_type:
            recv_type = next((str(p.get("type", "")) for p in target_method.get("parameters", [])
                              if p.get("name") == sink_recv), "")
        recv_simple = recv_type.rsplit(".", 1)[-1]
        is_prepared_stmt_call = recv_simple in ("PreparedStatement", "CallableStatement") and not sink_args_exprs
        if is_prepared_stmt_call:
            ps_var_name = sink_recv
        ret_type = {"executeQuery": "ResultSet", "executeUpdate": "int", "execute": "boolean",
                    "addBatch": "void", "prepareStatement": "PreparedStatement",
                    "prepareCall": "CallableStatement"}.get(sink_mname, "Object")
        params = "String sql" if sink_args_exprs else ""
        if len(sink_args_exprs) > 1:
            # Extra overload arguments have no complete safety model here.
            params += ", " + ", ".join("Object arg" + str(i) for i in range(1, len(sink_args_exprs)))
        ast_overloaded_sig = f"{ret_type} {sink_mname}({params})"
        target_ident = {
            "package": "java.sql",
            "class": recv_simple if recv_simple in ("Statement", "PreparedStatement", "CallableStatement", "Connection") else "Statement",
            "method": sink_mname,
            "signature": ast_overloaded_sig,
        }
        primary_arg_expr = sink_args_exprs[0] if sink_args_exprs else ""
        primary_arg_kind = sink_arg_kinds[0] if sink_arg_kinds else "NULL"
        primary_arg_idents = (
            _extract_non_literal_identifiers(primary_arg_expr)
            if primary_arg_expr
            else (list(sink_inv.get("arg_identifiers", [])) if sink_inv else [])
        )
    elif sink_mname == "exec":
        arg_var = _resolve_variable_in_scope(
            sink_args_exprs[0] if sink_args_exprs else "", sink_ancestors, sink_stmt_order,
            int(match_line), local_vars, assignments)
        array_arg = bool(arg_var and arg_var["var_type"] in ("String[]", "java.lang.String[]"))
        if sink_args_exprs and (array_arg or "String[]" in sink_args_exprs[0] or sink_arg_kinds[0] == "NEW_ARRAY"):
            ast_overloaded_sig = "Process exec(String[] cmdarray)"
        else:
            ast_overloaded_sig = "Process exec(String command)"
        target_ident = {
            "package": "java.lang",
            "class": "Runtime",
            "method": "exec",
            "signature": ast_overloaded_sig,
        }
        primary_arg_expr = sink_args_exprs[0] if sink_args_exprs else ""
        primary_arg_kind = sink_arg_kinds[0] if sink_arg_kinds else "METHOD_INVOCATION"
        primary_arg_idents = _extract_non_literal_identifiers(primary_arg_expr)
    elif sink_mname == "start":
        ast_overloaded_sig = "Process start()"
        target_ident = {
            "package": "java.lang",
            "class": "ProcessBuilder",
            "method": "start",
            "signature": "Process start()",
        }
        primary_arg_expr = sink_recv
        primary_arg_kind = "IDENTIFIER" if re.match(r"^\w+$", sink_recv) else "NEW_CLASS"
        primary_arg_idents = _extract_non_literal_identifiers(sink_recv)
    elif sink_mname in ("readAllBytes", "readString", "lines", "newInputStream") or use_nc_as_sink:
        ast_overloaded_sig = (
            f"{sink_nc.get('class_type', 'File')}({', '.join(sink_args_exprs)})"
            if (use_nc_as_sink and sink_nc is not None)
            else f"byte[] {sink_mname}(Path path)"
        )
        target_ident = {
            "package": "java.nio.file",
            "class": "Files",
            "method": "readAllBytes",
            "signature": "byte[] readAllBytes(Path path)",
        }
        if use_nc_as_sink and sink_nc is not None:
            primary_arg_expr = " , ".join(sink_args_exprs)
            primary_arg_kind = sink_arg_kinds[0] if len(sink_arg_kinds) == 1 else "NEW_CLASS"
            primary_arg_idents = list(sink_nc.get("arg_identifiers", []))
        else:
            primary_arg_expr = sink_args_exprs[0] if sink_args_exprs else ""
            primary_arg_kind = sink_arg_kinds[0] if sink_arg_kinds else "NULL"
            primary_arg_idents = list(sink_inv.get("arg_identifiers", [])) if sink_inv else []
    elif sink_mname in ("println", "print", "write", "printf", "format"):
        ast_overloaded_sig = f"void {sink_mname}(String x)"
        target_ident = {
            "package": "java.io",
            "class": "PrintWriter",
            "method": "println",
            "signature": "void println(String x)",
        }
        if sink_mname in ("printf", "format") and len(sink_args_exprs) >= 2:
            # Skip leading Locale argument (e.g. `java.util.Locale.US`) if present
            start_arg_idx = 1 if "Locale" in sink_args_exprs[0] else 0
            rel_args = sink_args_exprs[start_arg_idx:]
            rel_kinds = sink_arg_kinds[start_arg_idx:]
            primary_arg_expr = " + ".join(rel_args)
            primary_arg_kind = (
                "STRING_LITERAL"
                if (rel_kinds and all(_is_const_ast_kind(k) for k in rel_kinds))
                else "BINARY_PLUS"
            )
            primary_arg_idents = _extract_non_literal_identifiers(primary_arg_expr)
        else:
            primary_arg_expr = sink_args_exprs[0] if sink_args_exprs else ""
            primary_arg_kind = sink_arg_kinds[0] if sink_arg_kinds else "NULL"
            primary_arg_idents = _extract_non_literal_identifiers(primary_arg_expr)
    else:
        ast_overloaded_sig = enclosing_sig
        target_ident = {
            "package": pkg_name,
            "class": cls_name,
            "method": enclosing_method,
            "signature": enclosing_sig,
        }
        primary_arg_expr = matched_code_line
        primary_arg_kind = "UNKNOWN"
        primary_arg_idents = list(sink_inv.get("arg_identifiers", [])) if sink_inv else []

    sink_param_names = [
        pname or f"arg{i}"
        for i, (_, pname) in enumerate(shared.extract_formal_params_from_signature(target_ident["signature"]))
    ]
    if not sink_param_names:
        sink_param_names = ["this"]
    # Coverage is about the traced argument or receiver, never synthetic arg0
    # coverage for a zero-argument API. Additional SQL arguments stay uncovered.
    covered_args_tuple = (("this",) if not sink_args_exprs else
                          tuple(dict.fromkeys([sink_param_names[0], "0", "arg0"])))

    # =========================================================================
    # CASE 1: CWE-089 PreparedStatement / CallableStatement Execution (`ps.execute*()`)
    # =========================================================================
    prepared_trace = None
    if is_prepared_stmt_call and ps_var_name:
        receiver_aliases = {ps_var_name}
        alias_edges = [(str(v.get("name", "")), str(v.get("init_expr", "")).strip())
                       for v in local_vars if v.get("init_kind") == "IDENTIFIER"
                       and int(v.get("stmt_order", 0)) < sink_stmt_order]
        changed = True
        while changed:
            previous = set(receiver_aliases)
            for left, right in alias_edges:
                if left in receiver_aliases or right in receiver_aliases:
                    receiver_aliases.update((left, right))
            changed = previous != receiver_aliases

        def prepared_origin(name, seen, ref_order, ref_line, ref_anc):
            if name in seen:
                return None
            resolved = _resolve_variable_in_scope(
                name, ref_anc, ref_order, ref_line, local_vars,
                assignments, invocations, if_guards, switches, const_int_vars, const_str_vars)
            defs = resolved["reaching_defs"] if resolved else []
            if len(defs) != 1 or not defs[0].get("dominating"):
                return None
            # Receiver escape/unknown mutation makes its prepared SQL state unknown.
            if any(int(i.get("stmt_order", 0)) < sink_stmt_order and (
                receiver_aliases.intersection(i.get("arg_identifiers", [])) or (
                    i.get("receiver") in receiver_aliases and not str(i.get("method_name", "")).startswith("set")))
                   for i in invocations):
                return None
            expr = str(defs[0]["expr"]).strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", expr):
                return prepared_origin(expr, seen | {name}, int(defs[0]["stmt_order"]),
                                       int(defs[0]["line"]), resolved["declaration"]["ancestor_scopes"])
            origins = [i for i in invocations if i.get("method_name") in ("prepareStatement", "prepareCall")
                       and i.get("call_expr") == expr and int(i.get("stmt_order", 0)) < sink_stmt_order]
            return origins[0] if len(origins) == 1 else None

        prep_inv = prepared_origin(ps_var_name, set(), sink_stmt_order, int(match_line), sink_ancestors)
        if prep_inv is not None and prep_inv.get("arguments"):
            sql_tpl_expr = str(prep_inv["arguments"][0])
            sql_tpl_kind = str(prep_inv["arg_kinds"][0]) if prep_inv.get("arg_kinds") else "UNKNOWN"
            sql_tpl_idents = _extract_non_literal_identifiers(sql_tpl_expr)
            tpl_trace = trace_expression(
                expr_str=sql_tpl_expr,
                expr_kind=sql_tpl_kind,
                expr_idents=sql_tpl_idents,
                ref_anc=prep_inv.get("ancestor_scopes", sink_ancestors),
                ref_order=int(prep_inv.get("stmt_order", sink_stmt_order)),
                ref_ln=int(prep_inv.get("start_line", match_line)),
            )

            prepared_trace = tpl_trace
            has_param_binding = any(
                inv.get("receiver") == ps_var_name
                and str(inv.get("method_name", "")).startswith("set")
                and int(inv.get("stmt_order", 0)) < sink_stmt_order
                for inv in invocations
            )

            if (
                tpl_trace["is_pure_compile_time_constant"]
                and not tpl_trace["tainted_params_used"]
                and has_param_binding
            ):
                ast_ev = shared.AstReleaseEvidence(
                    is_compile_time_constant_arg=False,
                    has_cwe_matched_sanitizer=True,
                    verified_sanitizer_cwe=89,
                    covered_sink_args=covered_args_tuple,
                    ast_proof_node="SANITIZER_CALL:java.sql.PreparedStatement::setString",
                    sanitizer_method_signature="java.sql.PreparedStatement::setString",
                    output_context="",
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                )
                return JavaAstSiteAnalysis(
                    file_path=file_path,
                    match_line=match_line,
                    cwe=cwe_int,
                    package_name=pkg_name,
                    class_name=cls_name,
                    enclosing_method=enclosing_method,
                    enclosing_signature=enclosing_sig,
                    untrusted_params=tuple(untrusted_params),
                    target_callee_identity=target_ident,
                    matched_code_line=matched_code_line,
                    source_sink_trace_status="SAFE_CONSTANT_OR_PARAMETERIZED",
                    taint_reaches_sink=False,
                    taint_source_params=(),
                    taint_trace_steps=tuple(tpl_trace["trace_steps"] + [f"{ps_var_name}.setParameter(...)"]),
                    sanitizer_status="VERIFIED_PARAMETERIZED_QUERY",
                    ast_evidence=ast_ev,
                    extra_reason_codes=("RC_AST_VERIFIED_PARAMETERIZED_PREPARED_STATEMENT",),
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                    ast_overloaded_signature=ast_overloaded_sig,
                )
            elif tpl_trace["is_pure_compile_time_constant"] and not tpl_trace["tainted_params_used"]:
                ast_ev = shared.AstReleaseEvidence(
                    is_compile_time_constant_arg=True,
                    has_cwe_matched_sanitizer=False,
                    covered_sink_args=covered_args_tuple,
                    ast_proof_node=f"LITERAL:{tpl_trace['const_repr']}",
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                )
                return JavaAstSiteAnalysis(
                    file_path=file_path,
                    match_line=match_line,
                    cwe=cwe_int,
                    package_name=pkg_name,
                    class_name=cls_name,
                    enclosing_method=enclosing_method,
                    enclosing_signature=enclosing_sig,
                    untrusted_params=tuple(untrusted_params),
                    target_callee_identity=target_ident,
                    matched_code_line=matched_code_line,
                    source_sink_trace_status="SAFE_CONSTANT_OR_PARAMETERIZED",
                    taint_reaches_sink=False,
                    taint_source_params=(),
                    taint_trace_steps=tuple(tpl_trace["trace_steps"]),
                    sanitizer_status="NONE_DETECTED",
                    ast_evidence=ast_ev,
                    extra_reason_codes=("RC_AST_VERIFIED_COMPILE_TIME_CONSTANT",),
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                    ast_overloaded_signature=ast_overloaded_sig,
                )
            elif tpl_trace["tainted_params_used"]:
                return JavaAstSiteAnalysis(
                    file_path=file_path,
                    match_line=match_line,
                    cwe=cwe_int,
                    package_name=pkg_name,
                    class_name=cls_name,
                    enclosing_method=enclosing_method,
                    enclosing_signature=enclosing_sig,
                    untrusted_params=tuple(untrusted_params),
                    target_callee_identity=target_ident,
                    matched_code_line=matched_code_line,
                    source_sink_trace_status="VERIFIED_TAINT_FLOW",
                    taint_reaches_sink=True,
                    taint_source_params=tpl_trace["tainted_params_used"],
                    taint_trace_steps=tuple(tpl_trace["trace_steps"] + [matched_code_line]),
                    sanitizer_status="PARTIAL_OR_INSUFFICIENT_GUARD",
                    ast_evidence=shared.AstReleaseEvidence(covered_sink_args=covered_args_tuple, ast_parser_engine="OPENJDK17_JAVAC_TASK_AST"),
                    extra_reason_codes=("RC_PREPARED_STATEMENT_DYNAMIC_SQL_CONCAT",),
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                    ast_overloaded_signature=ast_overloaded_sig,
                )

    # Trace primary sink argument expression across lexical scopes & reaching definitions
    arg_trace = prepared_trace or trace_expression(
        expr_str=primary_arg_expr,
        expr_kind=primary_arg_kind,
        expr_idents=primary_arg_idents,
        ref_anc=sink_ancestors,
        ref_order=sink_stmt_order,
        ref_ln=int(match_line),
    )
    tainted_params_used = arg_trace["tainted_params_used"]
    reaching_invs = arg_trace["reaching_invocations"]
    reaching_ncs = arg_trace["reaching_new_classes"]
    trace_steps = arg_trace["trace_steps"]

    # A sanitizer in an old array initializer is not a proof about its state
    # after a write/escape. Do not let later sanitizer heuristics release it.
    array_unknown = any(step.startswith("ARRAY_STATE_UNPROVEN:") for step in trace_steps)
    call_unknown = any(step.startswith("UNKNOWN_CALL_RETURN:") for step in trace_steps)
    if array_unknown or call_unknown:
        independent_taint = bool(tainted_params_used) and not array_unknown
        return JavaAstSiteAnalysis(
            file_path=file_path, match_line=match_line, cwe=cwe_int,
            package_name=pkg_name, class_name=cls_name,
            enclosing_method=enclosing_method, enclosing_signature=enclosing_sig,
            untrusted_params=tuple(untrusted_params), target_callee_identity=target_ident,
            matched_code_line=matched_code_line,
            source_sink_trace_status=("VERIFIED_TAINT_FLOW" if independent_taint else "NO_FLOW_DETECTED_INTRAPROCEDURAL_LIMIT"),
            taint_reaches_sink=independent_taint,
            taint_source_params=tainted_params_used if independent_taint else (), taint_trace_steps=tuple(trace_steps),
            sanitizer_status="NONE_DETECTED",
            ast_evidence=shared.AstReleaseEvidence(covered_sink_args=covered_args_tuple if independent_taint else (),
                                                  ast_parser_engine="OPENJDK17_JAVAC_TASK_AST"),
            extra_reason_codes=(("RC_ARRAY_STATE_UNPROVEN_AFTER_MUTATION_OR_ESCAPE",) if array_unknown
                                else ("RC_HELPER_RETURN_UNPROVEN",)),
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            ast_overloaded_signature=ast_overloaded_sig,
        )

    # =========================================================================
    # CASE 2: Pure Compile-Time Constant Sink Arguments
    # =========================================================================
    if arg_trace["is_pure_compile_time_constant"] and not tainted_params_used:
        ast_ev = shared.AstReleaseEvidence(
            is_compile_time_constant_arg=True,
            has_cwe_matched_sanitizer=False,
            covered_sink_args=covered_args_tuple,
            ast_proof_node=f"LITERAL:{arg_trace['const_repr']}",
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
        )
        return JavaAstSiteAnalysis(
            file_path=file_path,
            match_line=match_line,
            cwe=cwe_int,
            package_name=pkg_name,
            class_name=cls_name,
            enclosing_method=enclosing_method,
            enclosing_signature=enclosing_sig,
            untrusted_params=tuple(untrusted_params),
            target_callee_identity=target_ident,
            matched_code_line=matched_code_line,
            source_sink_trace_status="SAFE_CONSTANT_OR_PARAMETERIZED",
            taint_reaches_sink=False,
            taint_source_params=(),
            taint_trace_steps=tuple(trace_steps),
            sanitizer_status="NONE_DETECTED",
            ast_evidence=ast_ev,
            extra_reason_codes=("RC_AST_VERIFIED_COMPILE_TIME_CONSTANT",),
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            ast_overloaded_signature=ast_overloaded_sig,
        )

    # =========================================================================
    # CASE 3: Check Actual AST MethodInvocationTree Sanitizers & Guards
    # =========================================================================
    inv_method_names = {str(inv.get("method_name", "")) for inv in reaching_invs}

    # 3A. CWE-022 Path Normalization & Dominating Path.startsWith(Path) Containment Guard
    if "normalize" in inv_method_names or "getName" in inv_method_names:
        if "getName" in inv_method_names and any(
            "FilenameUtils" in str(inv.get("receiver", "")) for inv in reaching_invs if inv.get("method_name") == "getName"
        ):
            san_sig = "org.apache.commons.io.FilenameUtils::getName"
            if cwe_int == 22:
                ast_ev = shared.AstReleaseEvidence(
                    is_compile_time_constant_arg=False,
                    has_cwe_matched_sanitizer=True,
                    verified_sanitizer_cwe=22,
                    covered_sink_args=covered_args_tuple,
                    ast_proof_node=f"SANITIZER_CALL:{san_sig}",
                    sanitizer_method_signature=san_sig,
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                )
                return JavaAstSiteAnalysis(
                    file_path=file_path,
                    match_line=match_line,
                    cwe=cwe_int,
                    package_name=pkg_name,
                    class_name=cls_name,
                    enclosing_method=enclosing_method,
                    enclosing_signature=enclosing_sig,
                    untrusted_params=tuple(untrusted_params),
                    target_callee_identity=target_ident,
                    matched_code_line=matched_code_line,
                    source_sink_trace_status="SAFE_SANITIZED_OR_GUARDED",
                    taint_reaches_sink=False,
                    taint_source_params=tainted_params_used,
                    taint_trace_steps=tuple(trace_steps),
                    sanitizer_status="VERIFIED_NORMALIZED_PATH_WITH_PREFIX_GUARD",
                    ast_evidence=ast_ev,
                    extra_reason_codes=("RC_AST_VERIFIED_FILENAMEUTILS_GETNAME",),
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                    ast_overloaded_signature=ast_overloaded_sig,
                )

        # Verify Path.normalize() + dominating Path.startsWith(Path) guard on the sink variable
        san_sig = "java.nio.file.Path::normalize"
        sink_var = primary_arg_expr.strip()
        sink_var_resolved = _resolve_variable_in_scope(
            var_name=sink_var,
            ref_ancestors=sink_ancestors,
            ref_stmt_order=sink_stmt_order,
            ref_line=int(match_line),
            local_variables=local_vars,
            assignments=assignments,
        )
        sink_var_is_path = bool(
            sink_var_resolved and sink_var_resolved["var_type"] in ("Path", "java.nio.file.Path")
        )
        sink_last_mut_order = sink_var_resolved["last_mutation_order"] if sink_var_resolved else 0

        # Inspect all startsWith MethodInvocationTree nodes in the method before sink_stmt_order
        startswith_invs = [
            inv
            for inv in invocations
            if inv.get("method_name") == "startsWith" and int(inv.get("stmt_order", 0)) < sink_stmt_order
        ]

        guard_status = "WITHOUT_PREFIX_GUARD"
        verified_base_var = ""
        for sw_inv in startswith_invs:
            sw_recv = str(sw_inv.get("receiver", "")).strip()
            sw_args = sw_inv.get("arguments", [])
            sw_arg0 = str(sw_args[0]).strip() if sw_args else ""
            sw_line = int(sw_inv.get("start_line", 0))
            sw_order = int(sw_inv.get("stmt_order", 0))

            # Check if startsWith is called on a String (e.g. resolved.toString().startsWith(...) or String base)
            if "toString()" in sw_recv or sw_arg0.startswith('"'):
                guard_status = "STRING_STARTSWITH_WEAK_GUARD"
                continue

            if sw_recv != sink_var or not sink_var_is_path:
                guard_status = "UNBOUND_GUARD_TARGET"
                continue

            # Check that sw_arg0 (baseDir) has declared type Path / java.nio.file.Path
            base_resolved = _resolve_variable_in_scope(
                var_name=sw_arg0,
                ref_ancestors=sink_ancestors,
                ref_stmt_order=sink_stmt_order,
                ref_line=int(match_line),
                local_variables=local_vars,
                assignments=assignments,
            )
            base_is_path = bool(
                base_resolved and base_resolved["var_type"] in ("Path", "java.nio.file.Path")
            )
            if not base_is_path:
                guard_status = "STRING_STARTSWITH_WEAK_GUARD"
                continue

            # Check that sink_var was NOT reassigned after the startsWith check
            if sink_last_mut_order > sw_order:
                guard_status = "REASSIGNED_AFTER_GUARD"
                continue

            # Check control-flow dominance via IfTree
            dominates = False
            for g in if_guards:
                if int(g.get("start_line", 0)) <= sw_line <= int(g.get("end_line", 0)):
                    cond_str = str(g.get("condition", ""))
                    g_scope = int(g.get("scope_id", -1))
                    # Pattern 1: if (!resolved.startsWith(baseDir)) { throw/return; } in dominating scope
                    if (
                        "!" in cond_str
                        and bool(g.get("then_terminates"))
                        and g_scope in set(sink_ancestors)
                        and int(g.get("end_line", 0)) < int(match_line)
                    ):
                        dominates = True
                        break
                    # Pattern 2: if (resolved.startsWith(baseDir)) { ... sink(resolved); ... }
                    if (
                        "!" not in cond_str
                        and int(g.get("then_start_line", 0)) <= int(match_line) <= int(g.get("then_end_line", 0))
                    ):
                        dominates = True
                        break

            if dominates:
                guard_status = "VERIFIED_DOMINATING_PATH_CONTAINMENT_GUARD"
                verified_base_var = sw_arg0
                break
            else:
                guard_status = "NON_DOMINATING_PREFIX_GUARD"

        if cwe_int == 22 and guard_status == "VERIFIED_DOMINATING_PATH_CONTAINMENT_GUARD":
            ast_ev = shared.AstReleaseEvidence(
                is_compile_time_constant_arg=False,
                has_cwe_matched_sanitizer=True,
                verified_sanitizer_cwe=22,
                covered_sink_args=covered_args_tuple,
                ast_proof_node=f"SANITIZER_CALL:{san_sig}+STARTSWITH_PREFIX_GUARD:{sink_var}.startsWith({verified_base_var})",
                sanitizer_method_signature=san_sig,
                output_context="",
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            )
            return JavaAstSiteAnalysis(
                file_path=file_path,
                match_line=match_line,
                cwe=cwe_int,
                package_name=pkg_name,
                class_name=cls_name,
                enclosing_method=enclosing_method,
                enclosing_signature=enclosing_sig,
                untrusted_params=tuple(untrusted_params),
                target_callee_identity=target_ident,
                matched_code_line=matched_code_line,
                source_sink_trace_status="SAFE_SANITIZED_OR_GUARDED",
                taint_reaches_sink=False,
                taint_source_params=tainted_params_used,
                taint_trace_steps=tuple(trace_steps + [f"GUARD:{sink_var}.startsWith({verified_base_var})"]),
                sanitizer_status="VERIFIED_NORMALIZED_PATH_WITH_PREFIX_GUARD",
                ast_evidence=ast_ev,
                extra_reason_codes=("RC_AST_VERIFIED_PATH_NORMALIZE_AND_PREFIX_GUARD",),
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                ast_overloaded_signature=ast_overloaded_sig,
            )
        elif cwe_int == 22:
            rc_map = {
                "WITHOUT_PREFIX_GUARD": "RC_REJECTED_PATH_NORMALIZE_WITHOUT_PREFIX_GUARD",
                "STRING_STARTSWITH_WEAK_GUARD": "RC_REJECTED_STRING_STARTSWITH_NOT_PATH_CONTAINMENT",
                "NON_DOMINATING_PREFIX_GUARD": "RC_REJECTED_NON_DOMINATING_PATH_PREFIX_GUARD",
                "UNBOUND_GUARD_TARGET": "RC_REJECTED_GUARD_DOES_NOT_BIND_SINK_VARIABLE",
                "REASSIGNED_AFTER_GUARD": "RC_REJECTED_PATH_REASSIGNED_AFTER_PREFIX_GUARD",
            }
            ast_ev = shared.AstReleaseEvidence(
                is_compile_time_constant_arg=False,
                has_cwe_matched_sanitizer=True,
                verified_sanitizer_cwe=22,
                covered_sink_args=covered_args_tuple,
                ast_proof_node=f"SANITIZER_CALL:{san_sig}:{guard_status}",
                sanitizer_method_signature=san_sig,
                output_context="",
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            )
            return JavaAstSiteAnalysis(
                file_path=file_path,
                match_line=match_line,
                cwe=cwe_int,
                package_name=pkg_name,
                class_name=cls_name,
                enclosing_method=enclosing_method,
                enclosing_signature=enclosing_sig,
                untrusted_params=tuple(untrusted_params),
                target_callee_identity=target_ident,
                matched_code_line=matched_code_line,
                source_sink_trace_status="PARTIAL_OR_INSUFFICIENT_GUARD",
                taint_reaches_sink=bool(tainted_params_used),
                taint_source_params=tainted_params_used,
                taint_trace_steps=tuple(trace_steps + [f"INSUFFICIENT_GUARD:{guard_status}"]),
                sanitizer_status="INSUFFICIENT_PATH_NORMALIZE_WITHOUT_PREFIX_GUARD",
                ast_evidence=ast_ev,
                extra_reason_codes=(rc_map.get(guard_status, "RC_REJECTED_PATH_NORMALIZE_WITHOUT_PREFIX_GUARD"),),
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                ast_overloaded_signature=ast_overloaded_sig,
            )

    # 3B. CWE-078 OS Command Encoder (`encodeForOS`) & Non-Shell ProcessBuilder Allowlist Guard Check
    if "encodeForOS" in inv_method_names:
        san_sig = "org.owasp.esapi.Encoder::encodeForOS"
        is_cwe_match = cwe_int == 78
        ast_ev = shared.AstReleaseEvidence(
            is_compile_time_constant_arg=False,
            has_cwe_matched_sanitizer=True,
            verified_sanitizer_cwe=78,
            covered_sink_args=covered_args_tuple,
            ast_proof_node=f"SANITIZER_CALL:{san_sig}",
            sanitizer_method_signature=san_sig,
            output_context="",
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
        )
        return JavaAstSiteAnalysis(
            file_path=file_path,
            match_line=match_line,
            cwe=cwe_int,
            package_name=pkg_name,
            class_name=cls_name,
            enclosing_method=enclosing_method,
            enclosing_signature=enclosing_sig,
            untrusted_params=tuple(untrusted_params),
            target_callee_identity=target_ident,
            matched_code_line=matched_code_line,
            source_sink_trace_status="SAFE_SANITIZED_OR_GUARDED" if is_cwe_match else "PARTIAL_OR_INSUFFICIENT_GUARD",
            taint_reaches_sink=not is_cwe_match and bool(tainted_params_used),
            taint_source_params=tainted_params_used,
            taint_trace_steps=tuple(trace_steps),
            sanitizer_status="VERIFIED_CWE_MATCHED_SANITIZER" if is_cwe_match else "MISMATCHED_CWE_SANITIZER",
            ast_evidence=ast_ev,
            extra_reason_codes=(
                ("RC_AST_VERIFIED_CWE078_OS_ENCODER",)
                if is_cwe_match
                else ("RC_REJECTED_MISMATCHED_CWE_SANITIZER",)
            ),
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            ast_overloaded_signature=ast_overloaded_sig,
        )

    # Check non-shell ProcessBuilder with fixed binary + dominating .matches(...) allowlist guard
    if cwe_int == 78 and sink_mname == "start" and tainted_params_used:
        pb_ncs = [nc for nc in reaching_ncs if "ProcessBuilder" in str(nc.get("class_type", ""))]
        if pb_ncs:
            pb_nc = pb_ncs[0]
            pb_args = pb_nc.get("arguments", [])
            pb_kinds = pb_nc.get("arg_kinds", [])
            first_arg_lit = pb_args[0].strip('"') if pb_args else ""
            first_arg_base = os.path.basename(first_arg_lit.replace("\\", "/")).lower()
            is_fixed_non_shell_bin = (
                bool(pb_kinds)
                and _is_const_ast_kind(pb_kinds[0])
                and first_arg_base not in SHELL_EXECUTABLES
                and first_arg_lit.lower() not in SHELL_EXECUTABLES
            )
            has_dominating_regex_guard = False
            for p in tainted_params_used:
                for g in if_guards:
                    if (
                        int(g.get("end_line", 0)) < int(match_line)
                        and bool(g.get("then_terminates"))
                        and int(g.get("scope_id", -1)) in set(sink_ancestors)
                        and f"!{p}.matches(" in str(g.get("condition", "")).replace(" ", "")
                    ):
                        has_dominating_regex_guard = True
                        break
            if is_fixed_non_shell_bin and has_dominating_regex_guard:
                # Conservative Phase C policy: fixed non-shell binary + custom regex guard is NOT
                # auto-suppressed (requires human review to verify regex blocks option/flag injection),
                # so route to NEEDS_REVIEW (REVIEW).
                return JavaAstSiteAnalysis(
                    file_path=file_path,
                    match_line=match_line,
                    cwe=cwe_int,
                    package_name=pkg_name,
                    class_name=cls_name,
                    enclosing_method=enclosing_method,
                    enclosing_signature=enclosing_sig,
                    untrusted_params=tuple(untrusted_params),
                    target_callee_identity=target_ident,
                    matched_code_line=matched_code_line,
                    source_sink_trace_status="PARTIAL_OR_INSUFFICIENT_GUARD",
                    taint_reaches_sink=False,
                    taint_source_params=tainted_params_used,
                    taint_trace_steps=tuple(trace_steps + [f"GUARD:dominating_regex_allowlist_on_{','.join(tainted_params_used)}"]),
                    sanitizer_status="UNVERIFIED_CUSTOM_SANITIZER",
                    ast_evidence=shared.AstReleaseEvidence(ast_parser_engine="OPENJDK17_JAVAC_TASK_AST"),
                    extra_reason_codes=("RC_NON_SHELL_PROCESSBUILDER_WITH_REGEX_GUARD_NEEDS_REVIEW",),
                    ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                    ast_overloaded_signature=ast_overloaded_sig,
                )

    # 3C. CWE-079 HTML / XSS Sanitizers (`htmlEscape`, `Encode.forHtml*`, `encodeForHTML*`, `escapeHtml*`, `Jsoup.clean`)
    html_san_invs = [
        inv
        for inv in reaching_invs
        if inv.get("method_name")
        in (
            "htmlEscape",
            "forHtml",
            "forHtmlContent",
            "forHtmlAttribute",
            "encodeForHTML",
            "encodeForHTMLAttribute",
            "escapeHtml",
            "escapeHtml4",
            "clean",
        )
    ]
    if html_san_invs:
        san_inv = html_san_invs[0]
        m_tok = str(san_inv.get("method_name", ""))
        r_tok = str(san_inv.get("receiver", ""))
        if m_tok == "forHtmlAttribute":
            san_sig = "org.owasp.encoder.Encode::forHtmlAttribute"
        elif m_tok == "forHtmlContent":
            san_sig = "org.owasp.encoder.Encode::forHtmlContent"
        elif m_tok == "forHtml":
            san_sig = "org.owasp.encoder.Encode::forHtml"
        elif m_tok == "encodeForHTMLAttribute":
            san_sig = "org.owasp.esapi.Encoder::encodeForHTMLAttribute"
        elif m_tok == "encodeForHTML":
            san_sig = "org.owasp.esapi.Encoder::encodeForHTML"
        elif m_tok == "escapeHtml4":
            san_sig = "org.apache.commons.text.StringEscapeUtils::escapeHtml4"
        elif m_tok == "escapeHtml":
            san_sig = "org.apache.commons.lang.StringEscapeUtils::escapeHtml"
        elif m_tok == "clean" and "Jsoup" in r_tok:
            san_sig = "org.jsoup.Jsoup::clean"
        else:
            san_sig = "org.springframework.web.util.HtmlUtils::htmlEscape"

        # Inspect AST string literals in the sink invocation and def-use chain to determine HTML context
        combined_sink_lits = list(sink_arg_lits) + list(arg_trace["all_lits"])
        joined_sink_lits = " ".join(combined_sink_lits).lower()
        if "<script" in joined_sink_lits or "</script>" in joined_sink_lits:
            out_ctx = "HTML_SCRIPT_TAG"
        elif "javascript:" in joined_sink_lits or re.search(r"\bon[a-z]+\s*=", joined_sink_lits):
            out_ctx = "HTML_JAVASCRIPT_URI"
        elif re.search(r"=\s*$", combined_sink_lits[0] if combined_sink_lits else ""):
            # Unquoted HTML attribute like "<input value=" + safeAttr + ">"
            out_ctx = "HTML_ATTRIBUTE_UNQUOTED"
        elif m_tok in ("forHtmlAttribute", "encodeForHTMLAttribute") or any(
            '"' in lit or "'" in lit for lit in combined_sink_lits
        ):
            out_ctx = "HTML_ATTRIBUTE_QUOTED"
        else:
            out_ctx = "HTML_BODY"

        ast_ev = shared.AstReleaseEvidence(
            is_compile_time_constant_arg=False,
            has_cwe_matched_sanitizer=True,
            verified_sanitizer_cwe=79,
            covered_sink_args=covered_args_tuple,
            ast_proof_node=f"SANITIZER_CALL:{san_sig}",
            sanitizer_method_signature=san_sig,
            output_context=out_ctx,
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
        )

        if cwe_int != 79:
            return JavaAstSiteAnalysis(
                file_path=file_path,
                match_line=match_line,
                cwe=cwe_int,
                package_name=pkg_name,
                class_name=cls_name,
                enclosing_method=enclosing_method,
                enclosing_signature=enclosing_sig,
                untrusted_params=tuple(untrusted_params),
                target_callee_identity=target_ident,
                matched_code_line=matched_code_line,
                source_sink_trace_status="PARTIAL_OR_INSUFFICIENT_GUARD",
                taint_reaches_sink=bool(tainted_params_used),
                taint_source_params=tainted_params_used,
                taint_trace_steps=tuple(trace_steps),
                sanitizer_status="MISMATCHED_CWE_SANITIZER",
                ast_evidence=ast_ev,
                extra_reason_codes=("RC_REJECTED_MISMATCHED_CWE_SANITIZER",),
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                ast_overloaded_signature=ast_overloaded_sig,
            )
        if out_ctx not in shared.SAFE_XSS_ENCODING_CONTEXTS:
            return JavaAstSiteAnalysis(
                file_path=file_path,
                match_line=match_line,
                cwe=cwe_int,
                package_name=pkg_name,
                class_name=cls_name,
                enclosing_method=enclosing_method,
                enclosing_signature=enclosing_sig,
                untrusted_params=tuple(untrusted_params),
                target_callee_identity=target_ident,
                matched_code_line=matched_code_line,
                source_sink_trace_status="PARTIAL_OR_INSUFFICIENT_GUARD",
                taint_reaches_sink=bool(tainted_params_used),
                taint_source_params=tainted_params_used,
                taint_trace_steps=tuple(trace_steps),
                sanitizer_status="UNSAFE_OUTPUT_ENCODING_CONTEXT",
                ast_evidence=ast_ev,
                extra_reason_codes=("RC_REJECTED_UNSAFE_XSS_OUTPUT_CONTEXT",),
                ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
                ast_overloaded_signature=ast_overloaded_sig,
            )
        return JavaAstSiteAnalysis(
            file_path=file_path,
            match_line=match_line,
            cwe=cwe_int,
            package_name=pkg_name,
            class_name=cls_name,
            enclosing_method=enclosing_method,
            enclosing_signature=enclosing_sig,
            untrusted_params=tuple(untrusted_params),
            target_callee_identity=target_ident,
            matched_code_line=matched_code_line,
            source_sink_trace_status="SAFE_SANITIZED_OR_GUARDED",
            taint_reaches_sink=False,
            taint_source_params=tainted_params_used,
            taint_trace_steps=tuple(trace_steps),
            sanitizer_status="VERIFIED_CWE_MATCHED_SANITIZER",
            ast_evidence=ast_ev,
            extra_reason_codes=("RC_AST_VERIFIED_XSS_SAFE_ENCODING",),
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            ast_overloaded_signature=ast_overloaded_sig,
        )

    # 3D. Unverified Custom Sanitizer / Validator Helper (`sanitize*`, `clean*`, `validate*`, `filter*`)
    custom_san_invs = [
        inv
        for inv in reaching_invs
        if re.match(r"^(sanitize|clean|validate|filter|purify)[A-Z_]", str(inv.get("method_name", "")))
    ]
    if tainted_params_used and custom_san_invs:
        c_inv = custom_san_invs[0]
        c_mname = str(c_inv.get("method_name", "customSanitizer"))
        return JavaAstSiteAnalysis(
            file_path=file_path,
            match_line=match_line,
            cwe=cwe_int,
            package_name=pkg_name,
            class_name=cls_name,
            enclosing_method=enclosing_method,
            enclosing_signature=enclosing_sig,
            untrusted_params=tuple(untrusted_params),
            target_callee_identity=target_ident,
            matched_code_line=matched_code_line,
            source_sink_trace_status="PARTIAL_OR_INSUFFICIENT_GUARD",
            taint_reaches_sink=False,
            taint_source_params=tainted_params_used,
            taint_trace_steps=tuple(trace_steps + [f"UNVERIFIED_CUSTOM_SANITIZER:{c_mname}"]),
            sanitizer_status="UNVERIFIED_CUSTOM_SANITIZER",
            ast_evidence=shared.AstReleaseEvidence(ast_parser_engine="OPENJDK17_JAVAC_TASK_AST"),
            extra_reason_codes=("RC_UNVERIFIED_CUSTOM_SANITIZER_NEEDS_REVIEW",),
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            ast_overloaded_signature=ast_overloaded_sig,
        )

    # =========================================================================
    # CASE 4: Verified Taint Flow from Formal Parameter to Sink (No Valid Sanitizer)
    # =========================================================================
    if tainted_params_used:
        return JavaAstSiteAnalysis(
            file_path=file_path,
            match_line=match_line,
            cwe=cwe_int,
            package_name=pkg_name,
            class_name=cls_name,
            enclosing_method=enclosing_method,
            enclosing_signature=enclosing_sig,
            untrusted_params=tuple(untrusted_params),
            target_callee_identity=target_ident,
            matched_code_line=matched_code_line,
            source_sink_trace_status="VERIFIED_TAINT_FLOW",
            taint_reaches_sink=True,
            taint_source_params=tainted_params_used,
            taint_trace_steps=tuple([f"SOURCE_PARAM:{','.join(tainted_params_used)}"] + trace_steps),
            sanitizer_status="NONE_DETECTED",
            ast_evidence=shared.AstReleaseEvidence(covered_sink_args=covered_args_tuple, ast_parser_engine="OPENJDK17_JAVAC_TASK_AST"),
            extra_reason_codes=("RC_IRIS_VERIFIED_SOURCE_TO_SINK_TAINT_FLOW",),
            ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
            ast_overloaded_signature=ast_overloaded_sig,
        )

    # =========================================================================
    # CASE 5: Interprocedural / External Field / Unresolved Dataflow -> NEEDS_REVIEW
    # =========================================================================
    return JavaAstSiteAnalysis(
        file_path=file_path,
        match_line=match_line,
        cwe=cwe_int,
        package_name=pkg_name,
        class_name=cls_name,
        enclosing_method=enclosing_method,
        enclosing_signature=enclosing_sig,
        untrusted_params=tuple(untrusted_params),
        target_callee_identity=target_ident,
        matched_code_line=matched_code_line,
        source_sink_trace_status="NO_FLOW_DETECTED_INTRAPROCEDURAL_LIMIT",
        taint_reaches_sink=False,
        taint_source_params=(),
        taint_trace_steps=tuple(trace_steps),
        sanitizer_status="NONE_DETECTED",
        ast_evidence=shared.AstReleaseEvidence(ast_parser_engine="OPENJDK17_JAVAC_TASK_AST"),
        extra_reason_codes=("RC_INSUFFICIENT_TAINT_TRACE_INTRAPROCEDURAL_LIMIT",),
        ast_parser_engine="OPENJDK17_JAVAC_TASK_AST",
        ast_overloaded_signature=ast_overloaded_sig,
    )


def analyze_java_site_ast_and_taint(
    java_source_text: str,
    file_path: str,
    match_line: int,
    cwe: int,
    opengrep_rule_id: str = "",
    opengrep_matched_code: str = "",
    force_fallback_regex_only: bool = False,
) -> JavaAstSiteAnalysis:
    """
    Primary entrypoint for Java AST & intraprocedural dataflow extraction.
    1. First parses the `.java` source using the OpenJDK 17 Compiler Tree API (`NtkJavacAstExtractor` /
       `JavacTask.parse()`), performing scope-aware reaching definitions and dominating guard analysis.
    2. If `force_fallback_regex_only=True` (used in fault-injection tests) or if the `.java` snippet
       cannot be parsed by `JavacTask`, falls back to the conservative lexical analyzer with
       `ast_parser_engine = "FALLBACK_LEXICAL_PARSER"`, which is strictly prohibited from granting
       automatic `SUPPRESS` (`verify_ast_release_evidence` rejects `FALLBACK_LEXICAL_PARSER` and
       escalates to `NEEDS_REVIEW`).
    """
    if not force_fallback_regex_only:
        ast_file = parse_java_source_with_javac_ast(java_source_text=java_source_text, file_path=file_path)
        if ast_file is not None:
            res = _analyze_with_openjdk_ast(
                ast_file=ast_file,
                java_source_text=java_source_text,
                file_path=file_path,
                match_line=match_line,
                cwe=cwe,
                opengrep_rule_id=opengrep_rule_id,
                opengrep_matched_code=opengrep_matched_code,
            )
            if res is not None:
                return res

    # Fallback conservative lexical mode (NEVER allowed to auto-suppress; always downgrades to NEEDS_REVIEW)
    cleaned_source = _strip_java_comments_multiline(java_source_text)
    lines = cleaned_source.splitlines()
    n_lines = len(lines)
    line_idx = max(0, min(int(match_line) - 1, n_lines - 1)) if n_lines else 0
    matched_code_line = opengrep_matched_code.strip() or (lines[line_idx].strip() if n_lines else "")

    pkg_name = "com.ntk.e2e"
    cls_name = "UnknownClass"
    for ln in lines:
        s = ln.strip()
        m_pkg = re.match(r"^package\s+([\w\.]+)\s*;", s)
        if m_pkg:
            pkg_name = m_pkg.group(1).strip()
        m_cls = re.search(r"\bclass\s+(\w+)", s)
        if m_cls:
            cls_name = m_cls.group(1).strip()

    enclosing_method = "unknownMethod"
    enclosing_sig = "void unknownMethod()"
    method_decl_regex = re.compile(
        r"(?:public|protected|private)\s+(?:static\s+)?([\w\[\]<>?,\s]+?)\s+(\w+)\s*\(([^)]*)\)"
    )
    for idx in range(line_idx, -1, -1):
        m_decl = method_decl_regex.search(lines[idx])
        if m_decl:
            ret_type = shared.normalize_whitespace(m_decl.group(1))
            enclosing_method = m_decl.group(2).strip()
            params_str = shared.normalize_whitespace(m_decl.group(3))
            enclosing_sig = shared.normalize_signature(f"{ret_type} {enclosing_method}({params_str})")
            break

    formal_params = shared.extract_formal_params_from_signature(enclosing_sig)
    untrusted_params = tuple(
        pname for ptype, pname in formal_params if pname and ptype not in INFRASTRUCTURE_PARAM_TYPES
    )

    cwe_int = int(re.sub(r"\D", "", str(cwe)) or "0")
    default_ident_by_cwe = {
        89: {
            "package": "java.sql",
            "class": "Statement",
            "method": "executeQuery",
            "signature": "ResultSet executeQuery(String sql)",
        },
        78: {
            "package": "java.lang",
            "class": "Runtime",
            "method": "exec",
            "signature": "Process exec(String command)",
        },
        22: {
            "package": "java.nio.file",
            "class": "Files",
            "method": "readAllBytes",
            "signature": "byte[] readAllBytes(Path path)",
        },
        79: {
            "package": "java.io",
            "class": "PrintWriter",
            "method": "println",
            "signature": "void println(String x)",
        },
    }
    target_ident = default_ident_by_cwe.get(
        cwe_int,
        {
            "package": pkg_name,
            "class": cls_name,
            "method": enclosing_method,
            "signature": enclosing_sig,
        },
    )

    fallback_ev = shared.AstReleaseEvidence(
        is_compile_time_constant_arg=False,
        has_cwe_matched_sanitizer=False,
        covered_sink_args=("arg0",),
        ast_proof_node="FALLBACK_LEXICAL_NO_SEMANTIC_AST",
        ast_parser_engine="FALLBACK_LEXICAL_PARSER",
    )
    return JavaAstSiteAnalysis(
        file_path=file_path,
        match_line=match_line,
        cwe=cwe_int,
        package_name=pkg_name,
        class_name=cls_name,
        enclosing_method=enclosing_method,
        enclosing_signature=enclosing_sig,
        untrusted_params=untrusted_params,
        target_callee_identity=target_ident,
        matched_code_line=matched_code_line,
        source_sink_trace_status="NO_FLOW_DETECTED_INTRAPROCEDURAL_LIMIT",
        taint_reaches_sink=False,
        taint_source_params=(),
        taint_trace_steps=(matched_code_line,),
        sanitizer_status="NONE_DETECTED",
        ast_evidence=fallback_ev,
        extra_reason_codes=("RC_FALLBACK_LEXICAL_PARSER_DOWNGRADED_TO_REVIEW",),
        ast_parser_engine="FALLBACK_LEXICAL_PARSER",
        ast_overloaded_signature=target_ident["signature"],
    )


def verify_and_triage_finding(
    finding_id: str,
    cwe: int,
    file_path: str,
    line_number: int,
    scanner_rule_id: str,
    static_severity: str,
    base_scanner_score: float,
    ast_analysis: JavaAstSiteAnalysis,
    callee_prediction: Optional[shared.CalleeRolePrediction],
    llm_raw_output: str = "",
    llm_latency_ms: float = 0.0,
    manual_review: Optional[ManualReviewRecord] = None,
    model_version: str = MODEL_VERSION_DEFAULT,
    ruleset_version: str = RULESET_VERSION_DEFAULT,
    scoring_policy_version: str = SCORING_POLICY_VERSION_DEFAULT,
    legacy_score_compatibility: bool = True,
) -> shared.FindingSchemaV2:
    """
    Executes Evidence Fusion (`evaluate_bounded_safety_floor`) and applies the deterministic
    Alert Verification & Triage state machine (`LIKELY_TRUE_POSITIVE` / `LIKELY_FALSE_POSITIVE` /
    `NEEDS_REVIEW`, `REPORT` / `REVIEW` / `SUPPRESS`, `NOT_REVIEWED` / `CONFIRMED_*`).
    """
    cwe_int = int(re.sub(r"\D", "", str(cwe)) or "0")
    cwe_str = f"CWE-{cwe_int:03d}"

    cand = shared.FindingCandidate(
        finding_id=finding_id,
        cwe=cwe_int,
        file_path=file_path,
        line_number=int(line_number),
        severity=static_severity,
        base_scanner_score=float(base_scanner_score),
        callee_prediction=callee_prediction,
        ast_evidence=ast_analysis.ast_evidence,
    )
    # Production decisions depend on semantic evidence, never a numeric score.
    # The old scorer remains opt-in for historical API/replay compatibility.
    explicit_release, release_reason = shared.verify_ast_release_evidence(cand)
    floor_res = (shared.evaluate_bounded_safety_floor(cand)
                 if legacy_score_compatibility else {})

    reason_codes: List[str] = ["RC_OPENGREP_CANDIDATE_MATCH"]
    for rc in ast_analysis.extra_reason_codes:
        if rc not in reason_codes:
            reason_codes.append(rc)

    llm_valid = bool(callee_prediction is not None and callee_prediction.strict_valid)
    llm_role = callee_prediction.role if (callee_prediction is not None and llm_valid) else None
    llm_abstain = True if callee_prediction is None else bool(callee_prediction.abstain)
    llm_abstain_reason = (
        "ABSTAIN_NO_PREDICTION" if callee_prediction is None else str(callee_prediction.abstain_reason)
    )

    if llm_valid:
        reason_codes.append(f"RC_LLM_STRICT_JSON_ROLE_{str(llm_role).upper().replace('-', '_')}")
    else:
        reason_codes.append(f"RC_LLM_INVALID_OR_ABSTAIN:{llm_abstain_reason}")

    # Triage State Machine
    # Invariant: Automatic SUPPRESS requires BOTH explicit_ast_release_verified == True AND
    # semantic AST parser engine (never fallback regex-only) AND safe trace status.
    if (
        explicit_release
        and ast_analysis.ast_parser_engine == "OPENJDK17_JAVAC_TASK_AST"
        and ast_analysis.source_sink_trace_status
        in (
            "SAFE_CONSTANT_OR_PARAMETERIZED",
            "SAFE_SANITIZED_OR_GUARDED",
        )
    ):
        triage_status = "LIKELY_FALSE_POSITIVE"
        decision = "SUPPRESS"
        kept_by_pipeline = False
        effective_score = 0.0 if legacy_score_compatibility else None
        reason_codes.append(f"RC_AUTO_SUPPRESS_AST_VERIFIED:{release_reason}")
        disposition = f"SUPPRESSED_FALSE_POSITIVE (AST_SAFETY_RELEASE:{release_reason})"
    elif (
        not explicit_release
        and ast_analysis.ast_parser_engine == "OPENJDK17_JAVAC_TASK_AST"
        and ast_analysis.flow_proof_state == "PROVEN_TAINT"
        and bool(ast_analysis.ast_evidence.covered_sink_args)
        and set(callee_prediction.canonical_sink_args if callee_prediction else ()).issubset(
            ast_analysis.ast_evidence.covered_sink_args)
        and ast_analysis.source_sink_trace_status in ("VERIFIED_TAINT_FLOW", "PARTIAL_OR_INSUFFICIENT_GUARD")
        and llm_valid
        and llm_role == "sink"
    ):
        triage_status = "LIKELY_TRUE_POSITIVE"
        decision = "REPORT"
        kept_by_pipeline = True
        effective_score = float(floor_res["final_score"]) if legacy_score_compatibility else None
        if release_reason != "NO_AST_RELEASE_CLAIMED":
            reason_codes.append(f"RC_AST_RELEASE_REJECTED:{release_reason}")
        else:
            reason_codes.append("RC_NO_AST_SAFETY_RELEASE")
        reason_codes.append("RC_TRIAGE_LIKELY_TRUE_POSITIVE_CONVERGENT_EVIDENCE")
        disposition = "RETAINED_VULNERABILITY_ALERT (LIKELY_TRUE_POSITIVE:REPORT)"
    else:
        # Ambiguous, missing intraprocedural taint trace, fallback parser, custom regex guard,
        # LLM abstain/timeout, or IRIS-vs-LLM conflict
        triage_status = "NEEDS_REVIEW"
        decision = "REVIEW"
        kept_by_pipeline = True
        effective_score = float(floor_res["final_score"]) if legacy_score_compatibility else None
        if floor_res.get("safety_floor_applied"):
            reason_codes.append("RC_SAFETY_FLOOR_055_CLAMPED")
        if ast_analysis.taint_reaches_sink and llm_role != "sink":
            reason_codes.append("RC_CONFLICT_IRIS_TAINT_VS_LLM_ROLE")
        if not ast_analysis.taint_reaches_sink and llm_role == "sink":
            reason_codes.append("RC_LLM_SINK_WITHOUT_VERIFIED_INTRAPROCEDURAL_TAINT_FLOW")
        if release_reason not in ("NO_AST_RELEASE_CLAIMED",):
            reason_codes.append(f"RC_AST_RELEASE_REJECTED:{release_reason}")
        reason_codes.append("RC_TRIAGE_ESCALATED_TO_HUMAN_REVIEW")
        disposition = "RETAINED_VULNERABILITY_ALERT (NEEDS_REVIEW:REVIEW)"

    # Independent Verification Status (`review_status`)
    # Strictly gated: never auto-confirmed without an explicit ManualReviewRecord
    if manual_review is not None:
        if manual_review.confirmed_status not in ("CONFIRMED_TRUE_POSITIVE", "CONFIRMED_FALSE_POSITIVE"):
            raise ValueError(f"Invalid confirmed_status in ManualReviewRecord: {manual_review.confirmed_status}")
        review_status = manual_review.confirmed_status
        review_metadata = {
            "reviewed_by": manual_review.reviewer_id,
            "reviewed_at_utc": manual_review.reviewed_at_utc,
            "review_notes": manual_review.review_notes,
            "confirmation_source": manual_review.confirmation_source,
        }
    else:
        review_status = "NOT_REVIEWED"
        review_metadata = {
            "reviewed_by": None,
            "reviewed_at_utc": None,
            "review_notes": "Awaiting human security analyst review or ground-truth audit confirmation.",
            "confirmation_source": None,
        }

    sev_norm = "HIGH" if static_severity.upper() in ("ERROR", "HIGH", "CRITICAL") else static_severity.upper()

    evidence_refs = {
        "file_path": file_path,
        "line_number": int(line_number),
        "enclosing_method": ast_analysis.enclosing_method,
        "enclosing_signature": ast_analysis.enclosing_signature,
        "matched_code_snippet": ast_analysis.matched_code_line,
        "taint_source_params": list(ast_analysis.taint_source_params),
        "taint_trace_steps": list(ast_analysis.taint_trace_steps),
        "ast_proof_node": ast_analysis.ast_evidence.ast_proof_node,
        "sanitizer_method_signature": ast_analysis.ast_evidence.sanitizer_method_signature,
        "ast_parser_engine": ast_analysis.ast_parser_engine,
    }

    opengrep_evidence = {
        "matched": True,
        "rule_id": scanner_rule_id,
        "cwe": cwe_str,
        "file_path": file_path,
        "line_number": int(line_number),
        "matched_code": ast_analysis.matched_code_line,
        "scanner_severity": static_severity,
        "base_scanner_score": round(float(base_scanner_score), 4),
    }

    iris_evidence = {
        "ast_parser_engine": ast_analysis.ast_parser_engine,
        "enclosing_method": ast_analysis.enclosing_method,
        "enclosing_signature": ast_analysis.enclosing_signature,
        "ast_overloaded_signature": ast_analysis.ast_overloaded_signature or ast_analysis.enclosing_signature,
        "target_callee_identity": dict(ast_analysis.target_callee_identity),
        "source_sink_trace_status": ast_analysis.source_sink_trace_status,
        "flow_proof_state": ast_analysis.flow_proof_state,
        "taint_reaches_sink": bool(ast_analysis.taint_reaches_sink),
        "taint_source_params": list(ast_analysis.taint_source_params),
        "taint_trace_steps": list(ast_analysis.taint_trace_steps),
        "sanitizer_status": ast_analysis.sanitizer_status,
        "explicit_ast_release_verified": explicit_release,
        "ast_release_reason": release_reason,
        "ast_proof_node": ast_analysis.ast_evidence.ast_proof_node,
        "covered_sink_args": list(ast_analysis.ast_evidence.covered_sink_args),
        "output_context": ast_analysis.ast_evidence.output_context,
    }

    llm_api_role = {
        "raw_output": llm_raw_output,
        "strict_json_valid": llm_valid,
        "predicted_role": llm_role,
        "sink_args": list(callee_prediction.sink_args) if callee_prediction is not None else [],
        "canonical_sink_args": list(callee_prediction.canonical_sink_args) if callee_prediction is not None else [],
        "abstain": llm_abstain,
        "abstain_reason": llm_abstain_reason,
        "inference_latency_ms": round(float(llm_latency_ms), 2),
        "prompt_contract": "CANONICAL_IRIS_2MSG_PROMPT_V1",
    }

    fusion_score_breakdown = {
        "base_scanner_score": round(float(base_scanner_score), 4),
        "llm_role_delta": float(floor_res["llm_role_delta"]),
        "raw_adjusted_score": float(floor_res["raw_adjusted_score"]),
        "safety_floor_threshold": shared.SAFETY_FLOOR_SCORE,
        "safety_floor_applied": bool(floor_res["safety_floor_applied"]),
        "explicit_ast_release_verified": explicit_release,
        "post_release_veto_applied": bool(floor_res["post_release_veto_applied"]),
        "retention_threshold": 0.50,
        "pre_veto_floor_score": float(floor_res["final_score"]),
        "effective_post_release_score": float(floor_res["effective_post_release_score"]),
        "final_heuristic_score": round(float(effective_score), 4),
        "is_calibrated_probability": False,
        "scoring_note": (
            "Heuristic neuro-symbolic evidence fusion score in [0.0, 1.0]; "
            "NOT a calibrated statistical probability."
        ),
    } if legacy_score_compatibility else {
        "policy": "NTK_EVIDENCE_TRIAGE_V1",
        "legacy_score_status": "REMOVED_FROM_PRODUCTION",
        "explicit_ast_release_verified": explicit_release,
        "ast_release_reason": release_reason,
        "numeric_score_used_for_decision": False,
        "priority_engine": "NTK_CWSS_INFERENCE_V2",
    }

    return shared.FindingSchemaV2(
        schema_version="NTK_WEB_FINDING_SCHEMA_V2",
        architecture_version="FROZEN_ARCHITECTURE_V1",
        model_version=model_version,
        finding_id=finding_id,
        cwe=cwe_str,
        cwe_id=cwe_int,
        file_path=file_path,
        line_number=int(line_number),
        enclosing_method=ast_analysis.enclosing_method,
        static_severity=static_severity,
        scanner_rule_id=scanner_rule_id,
        matched_code=ast_analysis.matched_code_line,
        target_callee_identity=dict(ast_analysis.target_callee_identity),
        llm_prediction={
            "raw_output": llm_raw_output,
            "strict_json_valid": llm_valid,
            "predicted_role": llm_role,
            "sink_args": list(callee_prediction.sink_args) if callee_prediction is not None else [],
            "canonical_sink_args": list(callee_prediction.canonical_sink_args) if callee_prediction is not None else [],
            "abstain": llm_abstain,
            "abstain_reason": llm_abstain_reason,
        },
        ast_evidence={
            "ast_parser_engine": ast_analysis.ast_parser_engine,
            "explicit_ast_release_verified": explicit_release,
            "ast_release_reason": release_reason,
            "ast_proof_node": ast_analysis.ast_evidence.ast_proof_node,
            "sanitizer_method_signature": ast_analysis.ast_evidence.sanitizer_method_signature,
            "output_context": ast_analysis.ast_evidence.output_context,
        },
        score_breakdown=fusion_score_breakdown,
        final_heuristic_score=round(float(effective_score), 4) if effective_score is not None else None,
        is_calibrated_probability=False,
        kept_by_pipeline=kept_by_pipeline,
        disposition=disposition,
        triage_status=triage_status,
        decision=decision,
        confidence_score=round(float(effective_score), 4) if effective_score is not None else None,
        score_kind=SCORE_KIND_DEFAULT if legacy_score_compatibility else "EVIDENCE_POLICY_NOT_CALIBRATED_PROBABILITY_CWSS_V2_PRIORITY",
        severity=sev_norm,
        reason_codes=tuple(reason_codes),
        evidence_refs=evidence_refs,
        source_sink_trace_status=ast_analysis.source_sink_trace_status,
        sanitizer_status=ast_analysis.sanitizer_status,
        opengrep_evidence=opengrep_evidence,
        iris_evidence=iris_evidence,
        llm_api_role=llm_api_role,
        fusion_score_breakdown=fusion_score_breakdown,
        review_status=review_status,
        review_metadata=review_metadata,
        ruleset_version=ruleset_version,
        scoring_policy_version=scoring_policy_version,
    )


REQUIRED_FINDING_SCHEMA_V2_KEYS: Set[str] = {
    # All 20 keys from FindingSchemaV1
    "schema_version",
    "architecture_version",
    "model_version",
    "finding_id",
    "cwe",
    "cwe_id",
    "file_path",
    "line_number",
    "enclosing_method",
    "static_severity",
    "scanner_rule_id",
    "matched_code",
    "target_callee_identity",
    "llm_prediction",
    "ast_evidence",
    "score_breakdown",
    "final_heuristic_score",
    "is_calibrated_probability",
    "kept_by_pipeline",
    "disposition",
    # All 17 new keys in FindingSchemaV2
    "triage_status",
    "decision",
    "confidence_score",
    "score_kind",
    "severity",
    "reason_codes",
    "evidence_refs",
    "source_sink_trace_status",
    "sanitizer_status",
    "opengrep_evidence",
    "iris_evidence",
    "llm_api_role",
    "fusion_score_breakdown",
    "review_status",
    "review_metadata",
    "ruleset_version",
    "scoring_policy_version",
}


def validate_finding_schema_v2_dict(d: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validates a serialized `FindingSchemaV2` dictionary against all schema, enum, range,
    and non-fabrication invariants.
    """
    errors: List[str] = []
    missing = sorted(REQUIRED_FINDING_SCHEMA_V2_KEYS - set(d.keys()))
    if missing:
        errors.append(f"MISSING_REQUIRED_KEYS:{missing}")
        return False, errors

    if d["triage_status"] not in shared.VALID_TRIAGE_STATUSES:
        errors.append(f"INVALID_TRIAGE_STATUS:{d['triage_status']}")
    if d["decision"] not in shared.VALID_TRIAGE_DECISIONS:
        errors.append(f"INVALID_DECISION:{d['decision']}")
    if d["review_status"] not in shared.VALID_REVIEW_STATUSES:
        errors.append(f"INVALID_REVIEW_STATUS:{d['review_status']}")
    if d["source_sink_trace_status"] not in shared.VALID_SOURCE_SINK_TRACE_STATUSES:
        errors.append(f"INVALID_SOURCE_SINK_TRACE_STATUS:{d['source_sink_trace_status']}")
    if d["sanitizer_status"] not in shared.VALID_SANITIZER_STATUSES:
        errors.append(f"INVALID_SANITIZER_STATUS:{d['sanitizer_status']}")

    raw_score = d["confidence_score"]
    evidence_policy = d.get('fusion_score_breakdown', {}).get('policy') == 'NTK_EVIDENCE_TRIAGE_V1'
    if raw_score is None:
        if not evidence_policy or d.get('final_heuristic_score') is not None:
            errors.append('NULL_SCORE_REQUIRES_EVIDENCE_POLICY')
    elif not (0.0 <= float(raw_score) <= 1.0):
        errors.append(f"CONFIDENCE_SCORE_OUT_OF_RANGE:{raw_score}")
    if d["is_calibrated_probability"] is not False:
        errors.append("IS_CALIBRATED_PROBABILITY_MUST_BE_FALSE")
    if "NOT_CALIBRATED_PROBABILITY" not in str(d["score_kind"]):
        errors.append(f"INVALID_SCORE_KIND:{d['score_kind']}")

    # Consistency invariants between triage_status, decision, and kept_by_pipeline
    if d["decision"] == "SUPPRESS":
        if d["triage_status"] != "LIKELY_FALSE_POSITIVE":
            errors.append("SUPPRESS_REQUIRES_LIKELY_FALSE_POSITIVE")
        if d["kept_by_pipeline"] is not False:
            errors.append("SUPPRESS_REQUIRES_KEPT_BY_PIPELINE_FALSE")
        if not d["ast_evidence"].get("explicit_ast_release_verified", False):
            errors.append("SUPPRESS_WITHOUT_EXPLICIT_AST_RELEASE_FORBIDDEN")
        if d["ast_evidence"].get("ast_parser_engine") in ("REGEX_ONLY", "FALLBACK_LEXICAL_PARSER"):
            errors.append("SUPPRESS_WITH_FALLBACK_LEXICAL_PARSER_FORBIDDEN")
    elif d["decision"] == "REPORT":
        if d["triage_status"] != "LIKELY_TRUE_POSITIVE":
            errors.append("REPORT_REQUIRES_LIKELY_TRUE_POSITIVE")
        if d["kept_by_pipeline"] is not True:
            errors.append("REPORT_REQUIRES_KEPT_BY_PIPELINE_TRUE")
    elif d["decision"] == "REVIEW":
        if d["triage_status"] != "NEEDS_REVIEW":
            errors.append("REVIEW_REQUIRES_NEEDS_REVIEW")
        if d["kept_by_pipeline"] is not True:
            errors.append("REVIEW_REQUIRES_KEPT_BY_PIPELINE_TRUE")

    # Confirmed status gating invariant
    if d["review_status"] in ("CONFIRMED_TRUE_POSITIVE", "CONFIRMED_FALSE_POSITIVE"):
        rev_meta = d.get("review_metadata", {})
        if not rev_meta.get("reviewed_by") or not rev_meta.get("confirmation_source"):
            errors.append("CONFIRMED_STATUS_WITHOUT_REVIEWER_METADATA_FORBIDDEN")

    collisions = shared.find_case_insensitive_duplicate_keys(d)
    if collisions:
        errors.append(f"CASE_INSENSITIVE_KEY_COLLISIONS:{collisions}")

    return len(errors) == 0, errors


def get_finding_schema_v2_json_schema() -> Dict[str, Any]:
    """
    Returns the formal JSON Schema (Draft 2020-12 compatible) for `FindingSchemaV2`.
    """
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://greta.ntk.local/schemas/finding_schema_v2.json",
        "title": "FindingSchemaV2",
        "description": (
            "Backward-compatible extension of FindingSchemaV1 (20 fields) adding Alert Verification "
            "& True/False Positive Triage state machine, neuro-symbolic evidence breakdown, and versioning (37 fields total)."
        ),
        "schema_version": "NTK_WEB_FINDING_SCHEMA_V2",
        "backward_compatible_with": "NTK_WEB_FINDING_SCHEMA_V1",
        "type": "object",
        "required": sorted(REQUIRED_FINDING_SCHEMA_V2_KEYS),
        "additionalProperties": False,
        "properties": {
            "schema_version": {"type": "string", "const": "NTK_WEB_FINDING_SCHEMA_V2"},
            "architecture_version": {"type": "string", "const": "FROZEN_ARCHITECTURE_V1"},
            "model_version": {"type": "string"},
            "ruleset_version": {"type": "string"},
            "scoring_policy_version": {"type": "string"},
            "finding_id": {"type": "string", "minLength": 1},
            "cwe": {"type": "string", "pattern": "^CWE-0(22|78|79|89)$"},
            "cwe_id": {"type": "integer", "enum": [22, 78, 79, 89]},
            "file_path": {"type": "string"},
            "line_number": {"type": "integer", "minimum": 1},
            "enclosing_method": {"type": "string"},
            "static_severity": {"type": "string", "enum": ["ERROR", "HIGH", "CRITICAL", "WARNING", "INFO"]},
            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ERROR"]},
            "scanner_rule_id": {"type": "string"},
            "matched_code": {"type": "string"},
            "triage_status": {"type": "string", "enum": list(shared.VALID_TRIAGE_STATUSES)},
            "decision": {"type": "string", "enum": list(shared.VALID_TRIAGE_DECISIONS)},
            "review_status": {"type": "string", "enum": list(shared.VALID_REVIEW_STATUSES)},
            "review_metadata": {"type": "object"},
            "confidence_score": {"type": ["number", "null"], "minimum": 0.0, "maximum": 1.0},
            "final_heuristic_score": {"type": ["number", "null"], "minimum": 0.0, "maximum": 1.0},
            "score_kind": {"type": "string", "const": SCORE_KIND_DEFAULT},
            "is_calibrated_probability": {"type": "boolean", "const": False},
            "kept_by_pipeline": {"type": "boolean"},
            "disposition": {"type": "string"},
            "reason_codes": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "evidence_refs": {"type": "object"},
            "source_sink_trace_status": {
                "type": "string",
                "enum": list(shared.VALID_SOURCE_SINK_TRACE_STATUSES),
            },
            "sanitizer_status": {"type": "string", "enum": list(shared.VALID_SANITIZER_STATUSES)},
            "target_callee_identity": {
                "type": "object",
                "required": ["package", "class", "method", "signature"],
            },
            "opengrep_evidence": {"type": "object"},
            "iris_evidence": {"type": "object"},
            "llm_prediction": {"type": "object"},
            "llm_api_role": {"type": "object"},
            "ast_evidence": {"type": "object"},
            "score_breakdown": {"type": "object"},
            "fusion_score_breakdown": {"type": "object"},
        },
    }
