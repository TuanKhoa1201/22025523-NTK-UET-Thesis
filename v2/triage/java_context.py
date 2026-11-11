"""Structural Java context extraction (enclosing class/method, same-file callees/callers, AST fallback).

Uses pure Python brace-balanced and token-aware parsing with line-number preservation,
and optionally detects tree-sitter if installed. Never modifies source bytes or line coordinates.
"""
from __future__ import annotations

import re
from typing import Any

PACKAGE_RE = re.compile(r"^\s*package\s+([a-zA-Z0-9_.]+)\s*;")
IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([a-zA-Z0-9_.*]+)\s*;")
CLASS_RE = re.compile(
    r"\b(?:public|protected|private|abstract|final|static|\s)*\b(?:class|interface|enum)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
ANNOTATION_RE = re.compile(r"^\s*@([A-Za-z_][A-Za-z0-9_.]*)")
METHOD_HEADER_RE = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|synchronized|native|abstract)\s+)*"
    r"(?:<[^>]+>\s+)?"
    r"([A-Za-z_][A-Za-z0-9_<>,.\[\]\s]*?)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"
    r"(?:\s*throws\s+[A-Za-z0-9_.,\s]+)?\s*\{"
)
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

CONTROL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "synchronized",
    "try",
    "else",
    "do",
    "return",
    "new",
    "throw",
    "super",
    "this",
}

ENTRYPOINT_NAMES = {
    "doGet",
    "doPost",
    "doPut",
    "doDelete",
    "service",
    "main",
    "handleRequest",
}

ENTRYPOINT_ANNOTATIONS = {
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "DeleteMapping",
    "PatchMapping",
    "RequestMapping",
    "WebServlet",
    "Path",
    "Override",
}


def _strip_comments_and_strings_preserve_lines(text: str) -> list[str]:
    """Replace comments and string/char literal bodies with spaces while preserving exact line count."""
    result: list[str] = []
    in_block_comment = False
    for raw_line in text.splitlines():
        out_chars: list[str] = []
        i = 0
        n = len(raw_line)
        in_str = False
        in_chr = False
        while i < n:
            ch = raw_line[i]
            nxt = raw_line[i + 1] if i + 1 < n else ""
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    out_chars.append("  ")
                    i += 2
                else:
                    out_chars.append(" ")
                    i += 1
                continue
            if in_str:
                if ch == "\\" and i + 1 < n:
                    out_chars.append("  ")
                    i += 2
                elif ch == '"':
                    in_str = False
                    out_chars.append('"')
                    i += 1
                else:
                    out_chars.append(" ")
                    i += 1
                continue
            if in_chr:
                if ch == "\\" and i + 1 < n:
                    out_chars.append("  ")
                    i += 2
                elif ch == "'":
                    in_chr = False
                    out_chars.append("'")
                    i += 1
                else:
                    out_chars.append(" ")
                    i += 1
                continue
            if ch == "/" and nxt == "/":
                out_chars.append(" " * (n - i))
                break
            if ch == "/" and nxt == "*":
                in_block_comment = True
                out_chars.append("  ")
                i += 2
                continue
            if ch == '"':
                in_str = True
                out_chars.append('"')
                i += 1
                continue
            if ch == "'":
                in_chr = True
                out_chars.append("'")
                i += 1
                continue
            out_chars.append(ch)
            i += 1
        result.append("".join(out_chars))
    return result


def parse_java_structure(text: str) -> dict[str, Any]:
    """Parse package, imports, classes, and methods with start/end line spans."""
    raw_lines = text.splitlines()
    clean_lines = _strip_comments_and_strings_preserve_lines(text)
    total_lines = len(raw_lines)

    package_name: str | None = None
    imports: list[str] = []
    classes: list[dict[str, Any]] = []
    methods: list[dict[str, Any]] = []

    for idx, clean in enumerate(clean_lines, start=1):
        if package_name is None:
            m_pkg = PACKAGE_RE.match(clean)
            if m_pkg:
                package_name = m_pkg.group(1)
                continue
        m_imp = IMPORT_RE.match(clean)
        if m_imp:
            imports.append(m_imp.group(1))

    # Brace-balanced scan for classes and methods
    i = 0
    while i < total_lines:
        line_no = i + 1
        clean = clean_lines[i]
        m_cls = CLASS_RE.search(clean)
        if m_cls and "{" in clean[m_cls.start():]:
            cls_name = m_cls.group(1)
            depth = 0
            end_line = line_no
            for j in range(i, total_lines):
                depth += clean_lines[j].count("{") - clean_lines[j].count("}")
                if depth <= 0 and j >= i:
                    end_line = j + 1
                    break
            classes.append({"name": cls_name, "start_line": line_no, "end_line": end_line})

        # Multi-line method signature window (up to 4 lines ending with '{')
        if "(" in clean and not clean.lstrip().startswith(("//", "/*", "*", "@")):
            combined_clean = clean
            sig_end_idx = i
            for k in range(i + 1, min(total_lines, i + 4)):
                if "{" in combined_clean or ";" in combined_clean:
                    break
                combined_clean += " " + clean_lines[k].strip()
                sig_end_idx = k
            m_meth = METHOD_HEADER_RE.match(combined_clean)
            if m_meth:
                ret_type = " ".join(m_meth.group(1).split())
                m_name = m_meth.group(2)
                params_raw = " ".join(m_meth.group(3).split())
                if m_name not in CONTROL_KEYWORDS and ret_type not in CONTROL_KEYWORDS:
                    # Collect preceding annotations
                    annotations: list[str] = []
                    ann_start = line_no
                    for back in range(i - 1, max(-1, i - 5), -1):
                        m_ann = ANNOTATION_RE.match(raw_lines[back])
                        if m_ann:
                            annotations.insert(0, m_ann.group(1))
                            ann_start = back + 1
                        elif not raw_lines[back].strip():
                            continue
                        else:
                            break
                    # Find matching closing brace from i..total_lines
                    depth = 0
                    opened = False
                    end_line = sig_end_idx + 1
                    for j in range(i, total_lines):
                        c_open = clean_lines[j].count("{")
                        c_close = clean_lines[j].count("}")
                        if c_open > 0:
                            opened = True
                        depth += c_open - c_close
                        if opened and depth <= 0:
                            end_line = j + 1
                            break
                    params = [p.strip() for p in params_raw.split(",") if p.strip()]
                    is_entry = (
                        m_name in ENTRYPOINT_NAMES
                        or any(a.split(".")[-1] in ENTRYPOINT_ANNOTATIONS for a in annotations)
                        or any("HttpServletRequest" in p for p in params)
                    )
                    methods.append(
                        {
                            "name": m_name,
                            "return_type": ret_type,
                            "parameters": params,
                            "annotations": annotations,
                            "signature": f"{ret_type} {m_name}({params_raw})".strip(),
                            "header_line": line_no,
                            "start_line": ann_start,
                            "end_line": end_line,
                            "is_entrypoint": is_entry,
                        }
                    )
                    i = sig_end_idx
        i += 1

    return {
        "package_name": package_name,
        "imports": imports,
        "classes": classes,
        "methods": methods,
        "total_lines": total_lines,
    }


def extract_java_context(
    text: str,
    finding_start_line: int,
    finding_end_line: int,
    trace_lines: list[int] | tuple[int, ...] = (),
    max_span: int = 140,
) -> dict[str, Any]:
    """Extract enclosing method, same-file callees/callers, and bounded context window."""
    structure = parse_java_structure(text)
    raw_lines = text.splitlines()
    clean_lines = _strip_comments_and_strings_preserve_lines(text)
    total_lines = len(raw_lines)
    methods = structure["methods"]

    enclosing_method: dict[str, Any] | None = None
    for m in methods:
        if m["start_line"] <= finding_start_line <= m["end_line"]:
            if enclosing_method is None or (m["end_line"] - m["start_line"]) < (
                enclosing_method["end_line"] - enclosing_method["start_line"]
            ):
                enclosing_method = m

    # Identify same-file helper methods called inside enclosing_method or hit by trace_lines
    same_file_callees: list[dict[str, Any]] = []
    same_file_callers: list[dict[str, Any]] = []

    if enclosing_method is not None:
        enc_body = "\n".join(
            clean_lines[enclosing_method["start_line"] - 1 : enclosing_method["end_line"]]
        )
        called_names = {
            m_call.group(1)
            for m_call in CALL_RE.finditer(enc_body)
            if m_call.group(1) not in CONTROL_KEYWORDS
        }
        for other in methods:
            if other["header_line"] == enclosing_method["header_line"]:
                continue
            in_trace = any(other["start_line"] <= tl <= other["end_line"] for tl in trace_lines)
            if other["name"] in called_names or in_trace:
                same_file_callees.append(other)
            else:
                other_body = "\n".join(
                    clean_lines[other["start_line"] - 1 : other["end_line"]]
                )
                if re.search(rf"\b{re.escape(enclosing_method['name'])}\s*\(", other_body):
                    same_file_callers.append(other)

    # Compute bounded context window [lower, upper] around finding + enclosing method + same-file callees
    if enclosing_method is not None:
        lower = enclosing_method["start_line"]
        upper = enclosing_method["end_line"]
        for callee in same_file_callees:
            cand_lower = min(lower, callee["start_line"])
            cand_upper = max(upper, callee["end_line"])
            if cand_upper - cand_lower <= max_span:
                lower, upper = cand_lower, cand_upper
        if upper - lower > max_span:
            half = max_span // 2
            lower = max(1, finding_start_line - half)
            upper = min(total_lines, lower + max_span)
    else:
        lower = max(1, finding_start_line - 15)
        upper = min(total_lines, finding_end_line + 15)
        if upper - lower > max_span:
            upper = lower + max_span

    lower = min(lower, finding_start_line)
    upper = max(upper, finding_end_line)
    if upper - lower > max_span:
        lower = max(1, finding_start_line - 3)
        upper = min(total_lines, finding_end_line + 3)

    enclosing_class = None
    for cls in structure["classes"]:
        if cls["start_line"] <= finding_start_line <= cls["end_line"]:
            enclosing_class = cls["name"]
            break

    return {
        "parser_mode": "brace_token_ast_v2",
        "package_name": structure["package_name"],
        "imports": structure["imports"],
        "enclosing_class": enclosing_class,
        "enclosing_method": enclosing_method,
        "same_file_callees": same_file_callees,
        "same_file_callers": same_file_callers,
        "context_start_line": lower,
        "context_end_line": upper,
    }
