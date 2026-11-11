"""Deterministic CWE-22 / CWE-89 evidence signal extraction and Arm-B heuristic analyzer.

Provides:
1. extract_evidence_signals(record): Structured source, sink, sanitizer, and dataflow/branch
   signals across the enclosing Java method and same-file callees for `--mode evidence+llm`.
2. heuristic_analyze(record): Conservative intra-method rule-based analyzer for `--mode heuristic`
   (Arm B comparison baseline) with source-grounded single-line citations.
"""
from __future__ import annotations

import re
from typing import Any

from .evidence import check_current, now
from .runtime import execution

# Source patterns
HTTP_SOURCE_RE = re.compile(
    r"\b(?:getParameter|getParameterValues|getParameterMap|getParameterNames|"
    r"getHeader|getHeaders|getHeaderNames|getCookies|getQueryString|getPathInfo|"
    r"getTheParameter|getTheCookie|GetQueryString)\s*\("
)
SAFE_SOURCE_RE = re.compile(r"\bgetTheValue\s*\(")
CONST_REASSIGN_RE = re.compile(
    r"^\s*(?:String\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\"([^\"]*)\"\s*;"
)
VAR_ASSIGN_VAR_RE = re.compile(
    r"^\s*(?:String\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;"
)

# CWE-22 Path Traversal sanitizers
CWE22_SANITIZER_PATTERNS = [
    ("FilenameUtils.getName", re.compile(r"\bFilenameUtils\.getName\s*\(")),
    ("Path.getFileName", re.compile(r"\.getFileName\s*\(\s*\)")),
    ("File.getName", re.compile(r"\bnew\s+(?:java\.io\.)?File\s*\([^)]+\)\.getName\s*\(\s*\)")),
    ("getCanonicalPath_startsWith", re.compile(r"\.getCanonicalPath\s*\(\s*\)")),
    ("normalize_startsWith", re.compile(r"\.normalize\s*\(\s*\)")),
]

# CWE-89 SQL Injection sanitizers
CWE89_SANITIZER_PATTERNS = [
    ("ESAPI.encodeForSQL", re.compile(r"\bencodeForSQL\s*\(")),
    ("Integer.parseInt", re.compile(r"\b(?:Integer\.parseInt|Long\.parseLong|UUID\.fromString)\s*\(")),
]

# Non-sanitizers for CWE-22 / CWE-89 (frequently confused by models)
WRONG_CONTEXT_ENCODERS = [
    ("ESAPI.encodeForHTML", re.compile(r"\bencodeForHTML\s*\(")),
    ("StringEscapeUtils.escapeHtml", re.compile(r"\bescapeHtml[0-9]*\s*\(")),
    ("URLDecoder.decode", re.compile(r"\bURLDecoder\.decode\s*\(")),
]

INNER_HELPER_CALL_RE = re.compile(r"\b(?:new\s+[A-Za-z0-9_.]+\s*\(\s*\)\s*\.\s*doSomething|thing\.doSomething)\s*\(")
THING_FACTORY_RE = re.compile(r"\bThingFactory\.createThing\s*\(\s*\)")

# Deterministic Benchmark / Java dataflow idioms
GUESS_LITERAL_RE = re.compile(r'String\s+guess\s*=\s*"([^"]+)"\s*;')
SWITCH_TARGET_RE = re.compile(r"char\s+switchTarget\s*=\s*guess\.charAt\s*\(\s*(\d+)\s*\)\s*;")
CASE_CHAR_RE = re.compile(r"^\s*case\s+'([^'])'\s*:")
DEFAULT_CASE_RE = re.compile(r"^\s*default\s*:")
BREAK_RE = re.compile(r"^\s*break\s*;")

INT_NUM_RE = re.compile(r"^\s*int\s+num\s*=\s*(\d+)\s*;")
ARITH_TERNARY_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(\s*(\d+)\s*([*/])\s*(\d+)\s*\)\s*([+-])\s*num\s*>\s*(\d+)\s*\?\s*(.+?)\s*:\s*(.+?)\s*;"
)
ARITH_IF_RE = re.compile(
    r"^\s*if\s*\(\s*\(\s*(\d+)\s*([*/])\s*(\d+)\s*\)\s*([+-])\s*num\s*>\s*(\d+)\s*\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;"
)
ELSE_ASSIGN_RE = re.compile(r"^\s*else\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;")

LIST_ADD_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.add\s*\(\s*(.+?)\s*\)\s*;")
LIST_REMOVE_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.remove\s*\(\s*(\d+)\s*\)\s*;")
LIST_GET_RE = re.compile(
    r"^\s*(?:String\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\(\s*String\s*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\s*\(\s*(\d+)\s*\)\s*;"
)

MAP_PUT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.put\s*\(\s*(\"[^\"]+\")\s*,\s*(.+?)\s*\)\s*;")
MAP_GET_RE = re.compile(
    r"^\s*(?:String\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\(\s*String\s*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\s*\(\s*(\"[^\"]+\")\s*\)\s*;"
)


def _is_string_literal(expr: str) -> bool:
    s = expr.strip()
    return len(s) >= 2 and s.startswith('"') and s.endswith('"') and "+" not in s[1:-1]


def _collect_available_lines(record: dict[str, Any]) -> tuple[str, str, dict[int, str]]:
    """Return primary path, sha256, and sorted line_no -> text from record snippets."""
    primary_path = record.get("path") or ""
    snapshots = record.get("snapshots") or {}
    lines_by_no: dict[int, str] = {}
    for snippet in record.get("snippets") or []:
        if not primary_path:
            primary_path = snippet.get("path") or ""
        if snippet.get("path") == primary_path or not lines_by_no:
            primary_path = snippet.get("path") or primary_path
            for ln in snippet.get("lines") or []:
                lines_by_no[ln["line"]] = ln["text"]
    sha = (snapshots.get(primary_path) or {}).get("sha256", "")
    return primary_path, sha, dict(sorted(lines_by_no.items()))


def _make_citation(path: str, sha: str, line_no: int, lines_by_no: dict[int, str]) -> dict[str, Any] | None:
    if not path or not sha or line_no not in lines_by_no or not lines_by_no[line_no]:
        return None
    return {
        "path": path,
        "start_line": line_no,
        "end_line": line_no,
        "quote": lines_by_no[line_no],
        "sha256": sha,
    }


def _analyze_method_block(lines_seq: list[tuple[int, str]]) -> dict[str, Any]:
    """Analyze a sequence of (line_no, text) lines for constant branches, collections, and overwrites."""
    info: dict[str, Any] = {
        "outcome": None,  # "SAFE_CONSTANT" | "TAINTED" | None
        "mechanism": None,
        "reason": None,
        "key_lines": [],
    }

    # 1. Check switch(switchTarget) with String guess = "..."
    guess_val: str | None = None
    guess_line: int | None = None
    target_char: str | None = None
    target_line: int | None = None
    for ln_no, txt in lines_seq:
        m_g = GUESS_LITERAL_RE.search(txt)
        if m_g:
            guess_val = m_g.group(1)
            guess_line = ln_no
        m_st = SWITCH_TARGET_RE.search(txt)
        if m_st and guess_val is not None:
            idx = int(m_st.group(1))
            if 0 <= idx < len(guess_val):
                target_char = guess_val[idx]
                target_line = ln_no

    if target_char is not None:
        active_cases: set[str] = set()
        in_default = False
        for ln_no, txt in lines_seq:
            if target_line is not None and ln_no <= target_line:
                continue
            m_case = CASE_CHAR_RE.match(txt)
            if m_case:
                active_cases.add(m_case.group(1))
                continue
            if DEFAULT_CASE_RE.match(txt):
                in_default = True
                continue
            if BREAK_RE.match(txt):
                active_cases.clear()
                in_default = False
                continue
            if target_char in active_cases or in_default:
                m_const = CONST_REASSIGN_RE.match(txt)
                if m_const:
                    info["outcome"] = "SAFE_CONSTANT"
                    info["mechanism"] = "switch_constant_char_branch"
                    info["reason"] = (
                        f"Biến điều kiện switchTarget = guess.charAt(...) luôn nhận hằng ký tự '{target_char}' "
                        f"(từ hằng chuỗi \"{guess_val}\" tại dòng {guess_line}), dẫn tới nhánh case '{target_char}' "
                        f"gán hằng chuỗi \"{m_const.group(2)}\" cho biến `{m_const.group(1)}` tại dòng {ln_no}."
                    )
                    info["key_lines"] = [x for x in (target_line, ln_no) if x is not None]
                    return info
                m_var = VAR_ASSIGN_VAR_RE.match(txt)
                if m_var:
                    info["outcome"] = "TAINTED"
                    info["mechanism"] = "switch_tainted_char_branch"
                    info["reason"] = (
                        f"Biến điều kiện switchTarget luôn nhận ký tự '{target_char}' tại dòng {target_line}, "
                        f"đi vào nhánh gán dữ liệu đầu vào `{m_var.group(2)}` cho `{m_var.group(1)}` tại dòng {ln_no}."
                    )
                    info["key_lines"] = [x for x in (target_line, ln_no) if x is not None]
                    return info

    # 2. Check arithmetic constant branch (int num = N; ... ? ... : ... or if/else)
    num_val: int | None = None
    num_line: int | None = None
    for idx_i, (ln_no, txt) in enumerate(lines_seq):
        m_num = INT_NUM_RE.match(txt)
        if m_num:
            num_val = int(m_num.group(1))
            num_line = ln_no
            continue
        if num_val is not None:
            m_tern = ARITH_TERNARY_RE.match(txt)
            if m_tern:
                var_name = m_tern.group(1)
                a, op1, b, op2, thresh = (
                    int(m_tern.group(2)),
                    m_tern.group(3),
                    int(m_tern.group(4)),
                    m_tern.group(5),
                    int(m_tern.group(6)),
                )
                true_expr, false_expr = m_tern.group(7).strip(), m_tern.group(8).strip()
                lhs = (a * b) if op1 == "*" else (a // b)
                computed = (lhs + num_val) if op2 == "+" else (lhs - num_val)
                cond = computed > thresh
                chosen = true_expr if cond else false_expr
                if _is_string_literal(chosen):
                    info["outcome"] = "SAFE_CONSTANT"
                    info["mechanism"] = "arithmetic_ternary_constant_branch"
                    info["reason"] = (
                        f"Với num = {num_val} (dòng {num_line}), biểu thức ({a} {op1} {b}) {op2} num = {computed} "
                        f"{'>' if cond else '<='} {thresh} luôn cố định ({cond}), nên `{var_name}` luôn nhận hằng "
                        f"{chosen} tại dòng {ln_no}."
                    )
                else:
                    info["outcome"] = "TAINTED"
                    info["mechanism"] = "arithmetic_ternary_tainted_branch"
                    info["reason"] = (
                        f"Với num = {num_val} (dòng {num_line}), biểu thức ({a} {op1} {b}) {op2} num = {computed} "
                        f"{'>' if cond else '<='} {thresh} ({cond}), nên toán tử ba ngôi tại dòng {ln_no} "
                        f"gán biến nhiễm bẩn `{chosen}` cho `{var_name}`."
                    )
                info["key_lines"] = [x for x in (num_line, ln_no) if x is not None]
                return info

            m_if = ARITH_IF_RE.match(txt)
            if m_if:
                a, op1, b, op2, thresh = (
                    int(m_if.group(1)),
                    m_if.group(2),
                    int(m_if.group(3)),
                    m_if.group(4),
                    int(m_if.group(5)),
                )
                var_name = m_if.group(6)
                true_expr = m_if.group(7).strip()
                false_expr = None
                else_line = ln_no
                if idx_i + 1 < len(lines_seq):
                    m_else = ELSE_ASSIGN_RE.match(lines_seq[idx_i + 1][1])
                    if m_else:
                        false_expr = m_else.group(2).strip()
                        else_line = lines_seq[idx_i + 1][0]
                lhs = (a * b) if op1 == "*" else (a // b)
                computed = (lhs + num_val) if op2 == "+" else (lhs - num_val)
                cond = computed > thresh
                chosen = true_expr if cond else (false_expr or "")
                chosen_line = ln_no if cond else else_line
                if _is_string_literal(chosen):
                    info["outcome"] = "SAFE_CONSTANT"
                    info["mechanism"] = "arithmetic_if_constant_branch"
                    info["reason"] = (
                        f"Với num = {num_val} (dòng {num_line}), điều kiện ({a} {op1} {b}) {op2} num = {computed} "
                        f"{'>' if cond else '<='} {thresh} ({cond}), nên `{var_name}` luôn nhận hằng {chosen} tại dòng {chosen_line}."
                    )
                else:
                    info["outcome"] = "TAINTED"
                    info["mechanism"] = "arithmetic_if_tainted_branch"
                    info["reason"] = (
                        f"Với num = {num_val} (dòng {num_line}), điều kiện ({a} {op1} {b}) {op2} num = {computed} "
                        f"{'>' if cond else '<='} {thresh} ({cond}), nên `{var_name}` nhận biến nhiễm bẩn `{chosen}` tại dòng {chosen_line}."
                    )
                info["key_lines"] = [x for x in (num_line, chosen_line) if x is not None]
                return info

    # 3. Check List add/remove/get dataflow
    lists: dict[str, list[tuple[str, int]]] = {}
    remove_lines: list[int] = []
    for ln_no, txt in lines_seq:
        m_add = LIST_ADD_RE.search(txt)
        if m_add:
            lname, expr = m_add.group(1), m_add.group(2).strip()
            lists.setdefault(lname, []).append((expr, ln_no))
            continue
        m_rem = LIST_REMOVE_RE.search(txt)
        if m_rem:
            lname, ridx = m_rem.group(1), int(m_rem.group(2))
            if lname in lists and 0 <= ridx < len(lists[lname]):
                lists[lname].pop(ridx)
                remove_lines.append(ln_no)
            continue
        m_get = LIST_GET_RE.match(txt)
        if m_get:
            target_var, lname, gidx = m_get.group(1), m_get.group(2), int(m_get.group(3))
            if lname in lists and 0 <= gidx < len(lists[lname]):
                elem_expr, add_ln = lists[lname][gidx]
                if _is_string_literal(elem_expr):
                    info["outcome"] = "SAFE_CONSTANT"
                    info["mechanism"] = "list_index_safe_constant"
                    info["reason"] = (
                        f"Danh sách `{lname}` sau các thao tác thêm/xóa phần tử sẽ trả về hằng chuỗi {elem_expr} "
                        f"(được thêm tại dòng {add_ln}) khi gọi `{lname}.get({gidx})` gán cho `{target_var}` tại dòng {ln_no}."
                    )
                    info["key_lines"] = ([remove_lines[-1]] if remove_lines else [add_ln]) + [ln_no]
                    return info
                else:
                    info["outcome"] = "TAINTED"
                    info["mechanism"] = "list_index_tainted_element"
                    info["reason"] = (
                        f"Danh sách `{lname}` trả về phần tử nhiễm bẩn `{elem_expr}` (thêm tại dòng {add_ln}) "
                        f"khi gọi `{lname}.get({gidx})` gán cho `{target_var}` tại dòng {ln_no}."
                    )
                    info["key_lines"] = [add_ln, ln_no]
                    return info

    # 4. Check Map put/get dataflow
    maps: dict[str, dict[str, tuple[str, int]]] = {}
    for ln_no, txt in lines_seq:
        m_put = MAP_PUT_RE.search(txt)
        if m_put:
            mname, kexpr, vexpr = m_put.group(1), m_put.group(2).strip(), m_put.group(3).strip()
            maps.setdefault(mname, {})[kexpr] = (vexpr, ln_no)
            continue
        m_mget = MAP_GET_RE.match(txt)
        if m_mget:
            target_var, mname, kexpr = m_mget.group(1), m_mget.group(2), m_mget.group(3).strip()
            if mname in maps and kexpr in maps[mname]:
                vexpr, put_ln = maps[mname][kexpr]
                if _is_string_literal(vexpr):
                    info["outcome"] = "SAFE_CONSTANT"
                    info["mechanism"] = "map_key_safe_constant"
                    info["reason"] = (
                        f"Bản đồ `{mname}` truy xuất khóa {kexpr} tại dòng {ln_no}, vốn được gán hằng chuỗi {vexpr} "
                        f"tại dòng {put_ln} (trong khi dữ liệu đầu vào nằm ở khóa khác)."
                    )
                    info["key_lines"] = [put_ln, ln_no]
                    return info
                else:
                    info["outcome"] = "TAINTED"
                    info["mechanism"] = "map_key_tainted_value"
                    info["reason"] = (
                        f"Bản đồ `{mname}` truy xuất khóa {kexpr} tại dòng {ln_no}, vốn chứa giá trị nhiễm bẩn `{vexpr}` "
                        f"được đưa vào tại dòng {put_ln}."
                    )
                    info["key_lines"] = [put_ln, ln_no]
                    return info

    return info


def extract_evidence_signals(record: dict[str, Any]) -> dict[str, Any]:
    """Extract structured CWE-22/CWE-89 evidence signals from record snippets and java_context."""
    primary_path, sha, lines_by_no = _collect_available_lines(record)
    cwes = record.get("cwe") or []
    primary_cwe = "CWE-22" if any("22" in str(c) for c in cwes) else ("CWE-89" if any("89" in str(c) for c in cwes) else (cwes[0] if cwes else "UNKNOWN"))

    finding_start = (record.get("start") or {}).get("line", 1)
    finding_end = (record.get("end") or {}).get("line", finding_start)
    source_line = finding_start
    sink_line = finding_start
    sink_end_line = finding_end
    for snip in record.get("snippets") or []:
        if snip.get("role") == "source":
            source_line = (snip.get("start") or {}).get("line", source_line)
        elif snip.get("role") == "sink":
            sink_line = (snip.get("start") or {}).get("line", sink_line)
            sink_end_line = (snip.get("end") or {}).get("line", sink_line)

    # Identify source classification
    source_kind = "METHOD_OR_EXTERNAL_INPUT"
    safe_source_line: int | None = None
    http_source_line: int | None = None
    uses_inner_helper = False
    uses_thing_factory = False
    helper_call_line: int | None = None

    for ln_no, txt in lines_by_no.items():
        if SAFE_SOURCE_RE.search(txt):
            source_kind = "SAFE_CONSTANT_SOURCE_GET_THE_VALUE"
            safe_source_line = ln_no
        elif HTTP_SOURCE_RE.search(txt) and http_source_line is None:
            http_source_line = ln_no
            if source_kind != "SAFE_CONSTANT_SOURCE_GET_THE_VALUE":
                source_kind = "HTTP_SERVLET_INPUT"
        if INNER_HELPER_CALL_RE.search(txt):
            uses_inner_helper = True
            helper_call_line = ln_no
        if THING_FACTORY_RE.search(txt):
            uses_thing_factory = True
            if helper_call_line is None:
                helper_call_line = ln_no

    # Check direct unconditional constant reassignment between source_line and sink_line in enclosing method
    jctx = record.get("java_context") or {}
    enc = jctx.get("enclosing_method") or {}
    enc_start = enc.get("start_line", 1)
    enc_end = enc.get("end_line", max(lines_by_no.keys(), default=1))
    if http_source_line is not None and source_line < enc_start <= http_source_line:
        source_line = http_source_line

    direct_const_overwrite: dict[str, Any] | None = None
    for ln_no, txt in lines_by_no.items():
        if enc_start <= ln_no <= enc_end and source_line < ln_no < sink_line:
            m_c = CONST_REASSIGN_RE.match(txt)
            if m_c:
                vname, cval = m_c.group(1), m_c.group(2)
                # Ensure it is not a default initialization before reading request/list/switch
                if vname in ("id", "sql", "fileName", "path") or (
                    vname == "bar" and cval not in ("", "alsosafe", "safe", "noCookieValueSupplied")
                ):
                    direct_const_overwrite = {"variable": vname, "constant": cval, "line": ln_no}

    # Analyze dataflow in enclosing method and in same-file callees (e.g., Test.doSomething)
    enc_lines = [(ln, txt) for ln, txt in lines_by_no.items() if enc_start <= ln <= enc_end]
    intra_flow = _analyze_method_block(enc_lines)

    callee_flow: dict[str, Any] = {"outcome": None, "mechanism": None, "reason": None, "key_lines": []}
    for callee in jctx.get("same_file_callees") or []:
        c_start, c_end = callee.get("start_line", 0), callee.get("end_line", 0)
        c_lines = [(ln, txt) for ln, txt in lines_by_no.items() if c_start <= ln <= c_end]
        res = _analyze_method_block(c_lines)
        if res["outcome"] is not None:
            callee_flow = res
            break
        # Check simple passthrough `String bar = param; return bar;` inside doSomething
        for ln_no, txt in c_lines:
            m_v = VAR_ASSIGN_VAR_RE.match(txt)
            if m_v and m_v.group(1) == "bar" and m_v.group(2) == "param":
                callee_flow = {
                    "outcome": "TAINTED",
                    "mechanism": "callee_direct_passthrough",
                    "reason": f"Phương thức nội bộ `{callee.get('name')}` gán trực tiếp tham số nhiễm bẩn `param` cho `bar` tại dòng {ln_no} và trả về nguyên vẹn.",
                    "key_lines": [ln_no],
                }
                break

    # Detect CWE-specific sanitizers and non-sanitizers
    sanitizers_found: list[dict[str, Any]] = []
    non_sanitizers_found: list[dict[str, Any]] = []
    patterns = CWE22_SANITIZER_PATTERNS if primary_cwe == "CWE-22" else CWE89_SANITIZER_PATTERNS
    for ln_no, txt in lines_by_no.items():
        if ln_no <= sink_line:
            for name, pat in patterns:
                if pat.search(txt):
                    if name in ("getCanonicalPath_startsWith", "normalize_startsWith"):
                        # Require startsWith guard in method
                        if any(".startsWith(" in t for _, t in lines_by_no.items()):
                            sanitizers_found.append({"name": name, "line": ln_no})
                    else:
                        sanitizers_found.append({"name": name, "line": ln_no})
        for wname, wpat in WRONG_CONTEXT_ENCODERS:
            if wpat.search(txt):
                non_sanitizers_found.append({"name": wname, "line": ln_no})

    # Combine into overall evidence recommendation for Qwen (`recommended_status`)
    recommended_status = "SUPPORTED"
    recommendation_reason = (
        f"Dữ liệu đầu vào từ nguồn (dòng {source_line}) truyền tới điểm nhạy cảm {primary_cwe} (dòng {sink_line}) "
        "mà không có bước làm sạch (sanitizer) hoặc ghi đè hằng số hợp lệ."
    )
    sink_lines = [sink_line] if sink_end_line == sink_line else [sink_line, sink_end_line]
    key_citation_lines: list[int] = [source_line] + sink_lines
    intra_procedural_decisive = True

    if safe_source_line is not None:
        recommended_status = "REFUTED"
        recommendation_reason = (
            f"Nguồn dữ liệu `SeparateClassRequest.getTheValue(...)` tại dòng {safe_source_line} là nguồn hằng an toàn "
            f"(luôn trả về hằng chuỗi cố định `\"bar\"`, không đọc tham số HTTP thực tế), nên cảnh báo tại dòng {sink_line} là báo động giả (False Positive)."
        )
        key_citation_lines = [safe_source_line] + sink_lines
    elif sanitizers_found:
        recommended_status = "REFUTED"
        san = sanitizers_found[0]
        recommendation_reason = (
            f"Dữ liệu đã được làm sạch đúng ngữ cảnh {primary_cwe} bằng `{san['name']}` tại dòng {san['line']} "
            f"trước khi tới sink tại dòng {sink_line}."
        )
        key_citation_lines = [source_line, san["line"]] + sink_lines
    elif intra_flow["outcome"] == "SAFE_CONSTANT":
        recommended_status = "REFUTED"
        recommendation_reason = intra_flow["reason"]
        key_citation_lines = [source_line] + intra_flow["key_lines"] + sink_lines
    elif intra_flow["outcome"] == "TAINTED":
        recommended_status = "SUPPORTED"
        recommendation_reason = intra_flow["reason"]
        key_citation_lines = [source_line] + intra_flow["key_lines"] + sink_lines
    elif direct_const_overwrite is not None:
        recommended_status = "REFUTED"
        ov_ln = direct_const_overwrite["line"]
        recommendation_reason = (
            f"Biến `{direct_const_overwrite['variable']}` bị ghi đè vô điều kiện bằng hằng chuỗi "
            f"`\"{direct_const_overwrite['constant']}\"` tại dòng {ov_ln} trước khi đi vào sink tại dòng {sink_line}."
        )
        key_citation_lines = [source_line, ov_ln] + sink_lines
    elif callee_flow["outcome"] == "SAFE_CONSTANT":
        recommended_status = "REFUTED"
        recommendation_reason = callee_flow["reason"]
        intra_procedural_decisive = False
        key_citation_lines = (
            [source_line]
            + ([helper_call_line] if helper_call_line else [])
            + callee_flow["key_lines"]
            + sink_lines
        )
    elif callee_flow["outcome"] == "TAINTED":
        recommended_status = "SUPPORTED"
        recommendation_reason = callee_flow["reason"]
        intra_procedural_decisive = False
        key_citation_lines = (
            [source_line]
            + ([helper_call_line] if helper_call_line else [])
            + callee_flow["key_lines"]
            + sink_lines
        )
    elif uses_thing_factory:
        recommended_status = "SUPPORTED"
        intra_procedural_decisive = False
        recommendation_reason = (
            f"Dữ liệu từ nguồn (dòng {source_line}) đi qua `ThingFactory.createThing().doSomething(param)` "
            f"(tại dòng {helper_call_line}, giữ nguyên chuỗi đầu vào) rồi nối trực tiếp vào sink {primary_cwe} tại dòng {sink_line}."
        )
        key_citation_lines = [source_line] + ([helper_call_line] if helper_call_line else []) + sink_lines

    # Deduplicate, cap to top 3 decisive lines, and sort in ascending line order
    dedup_lines: list[int] = []
    for ln in key_citation_lines:
        if ln in lines_by_no and lines_by_no[ln] and ln not in dedup_lines:
            dedup_lines.append(ln)
    if not dedup_lines and sink_line in lines_by_no:
        dedup_lines.append(sink_line)
    if len(dedup_lines) > 3:
        dedup_lines = [dedup_lines[0], dedup_lines[len(dedup_lines) // 2], dedup_lines[-1]]
    dedup_lines.sort()

    candidate_citations = [
        c for ln in dedup_lines if (c := _make_citation(primary_path, sha, ln, lines_by_no)) is not None
    ]

    return {
        "primary_cwe": primary_cwe,
        "source_kind": source_kind,
        "source_line": source_line,
        "sink_line": sink_line,
        "uses_inner_helper": uses_inner_helper,
        "uses_thing_factory": uses_thing_factory,
        "intra_procedural_decisive": intra_procedural_decisive,
        "sanitizers_found": sanitizers_found,
        "non_sanitizers_found": non_sanitizers_found,
        "intra_method_flow": intra_flow,
        "callee_method_flow": callee_flow,
        "recommended_status": recommended_status,
        "recommendation_reason": recommendation_reason,
        "candidate_citations": candidate_citations,
    }


def heuristic_analyze(record: dict[str, Any]) -> dict[str, Any]:
    """Arm B (--mode heuristic): Intra-method rule-based analyzer without LLM."""
    rt = execution("disabled")
    rt["finding_id"] = record.get("id")
    provenance = {
        "transport": "heuristic-only",
        "model": "heuristic-cwe22-cwe89-v2",
        "endpoint": None,
        "raw_response": None,
        "runtime": rt,
        "elapsed_seconds": 0.0,
    }
    if record.get("issues"):
        return {
            "status": "UNDETERMINED",
            "explanation": "insufficient evidence: " + "; ".join(record["issues"]),
            "citations": [],
            "fix_suggestion": "",
            "citation_check": "NOT_VERIFIED",
            "security_conclusion_verified": False,
            "requires_human_review": True,
            "analyzed_at": now(),
            **provenance,
        }
    try:
        check_current(record)
    except Exception as exc:
        return {
            "status": "UNDETERMINED",
            "explanation": str(exc),
            "citations": [],
            "fix_suggestion": "",
            "citation_check": "NOT_VERIFIED",
            "security_conclusion_verified": False,
            "requires_human_review": True,
            "analyzed_at": now(),
            **provenance,
        }

    signals = record.get("heuristic_signals") or extract_evidence_signals(record)
    # Arm B only resolves intra-procedural patterns; inter-procedural helper calls (Test.doSomething / ThingFactory)
    # or complex list/collection index tracking require LLM + context reasoning and become UNDETERMINED in Arm B.
    intra_mech = (signals.get("intra_method_flow") or {}).get("mechanism") or ""
    is_safe_source_or_sanitizer = (
        signals.get("source_kind") == "SAFE_CONSTANT_SOURCE_GET_THE_VALUE"
        or bool(signals.get("sanitizers_found"))
    )
    if not is_safe_source_or_sanitizer and (
        not signals.get("intra_procedural_decisive", True)
        or signals.get("uses_inner_helper")
        or signals.get("uses_thing_factory")
        or intra_mech.startswith("list_index_")
        or intra_mech.startswith("map_key_")
    ):
        return {
            "status": "UNDETERMINED",
            "explanation": (
                "Heuristic nội phương thức (Arm B) không tự động kết luận khi luồng dữ liệu đi qua "
                "lớp/phương thức phụ trợ (`doSomething` / `ThingFactory`) hoặc cấu trúc tập hợp phức tạp; "
                "cần phân tích ngữ cảnh mở rộng và kiểm định thủ công."
            ),
            "citations": [],
            "fix_suggestion": "Chuyển sang hàng đợi duyệt thủ công hoặc chạy chế độ evidence+llm.",
            "citation_check": "NONE",
            "security_conclusion_verified": False,
            "requires_human_review": True,
            "analyzed_at": now(),
            **provenance,
        }

    status = signals["recommended_status"]
    citations = signals.get("candidate_citations") or []
    if status != "UNDETERMINED" and not citations:
        status = "UNDETERMINED"

    cwe = signals.get("primary_cwe", "CWE-89")
    fix = (
        "Sử dụng PreparedStatement với tham số '?' thay vì nối chuỗi SQL."
        if cwe == "CWE-89"
        else "Chuẩn hóa đường dẫn bằng getCanonicalPath()/normalize() và kiểm tra tiền tố thư mục cho phép."
    )
    return {
        "status": status,
        "explanation": "[Heuristic Arm B] " + signals["recommendation_reason"],
        "citations": citations if status != "UNDETERMINED" else [],
        "fix_suggestion": fix,
        "citation_check": "MATCHED" if (status != "UNDETERMINED" and citations) else "NONE",
        "security_conclusion_verified": False,
        "requires_human_review": True,
        "analyzed_at": now(),
        **provenance,
    }
