"""Enhanced structural Java context extraction, helper snippet attachment, and prompt compaction.

Operates strictly within v2/api while preserving 100% byte-for-byte compatibility with:
- sealed `v2.triage.ollama.request_payload` / `prompt` / `validate_answer`
- sealed `v2.triage.verify_http_capture.verify_run_http_captures`
- sealed `v2.triage.evidence.check_current` and SHA-256 source snapshots

Never modifies source files, never fabricates source lines, and never injects heuristic
conclusions into LLM prompt fields.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any

from v2.triage.evidence import EvidenceError, SourceTree, digest
from v2.triage.heuristics import extract_evidence_signals
from v2.triage.java_context import (
    CLASS_RE,
    CONTROL_KEYWORDS,
    ENTRYPOINT_ANNOTATIONS,
    ENTRYPOINT_NAMES,
    IMPORT_RE,
    PACKAGE_RE,
    _extract_qualified_calls_in_method,
    _strip_comments_and_strings_preserve_lines,
)
from v2.triage.ollama import prompt as build_ollama_prompt

CONTEXT_V2_VERSION = "v2.3-balanced-java-context"
DEFAULT_MAX_PROMPT_BYTES = 32_000
MAX_FINDING_WINDOW_LINES = 140
MAX_HELPER_SNIPPET_LINES = 80
MAX_HELPER_SNIPPETS = 3

_MODIFIERS = frozenset({
    "public",
    "protected",
    "private",
    "static",
    "final",
    "synchronized",
    "native",
    "abstract",
    "default",
    "strictfp",
})

_METHOD_PREFIX_RE = re.compile(
    r"^\s*((?:(?:public|protected|private|static|final|synchronized|native|abstract|default|strictfp)\s+)*)"
    r"(?:<[^>{};]+>\s+)?"
    r"([A-Za-z_][A-Za-z0-9_<>,.\[\]?\s]*?)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
_THROWS_TRAILER_RE = re.compile(
    r"^(?:\s*throws\s+[A-Za-z0-9_.,\s]+)?\s*\{"
)
_ANN_NAME_RE = re.compile(r"@([A-Za-z_][A-Za-z0-9_.]*)")
_STRONG_GUARD_RE = re.compile(
    r"\b(?:getCanonicalPath|getCanonicalFile|startsWith|normalize|FilenameUtils|getFileName|"
    r"prepareStatement|prepareCall|setString|setInt|setLong|parseInt|parseLong|fromString)\b"
)
_GUARD_HINT_RE = re.compile(
    r"\b(?:getCanonicalPath|getCanonicalFile|startsWith|normalize|FilenameUtils|getFileName|"
    r"prepareStatement|prepareCall|setString|setInt|setLong|parseInt|parseLong|fromString|"
    r"encodeForHTML|escapeHtml|URLDecoder|replace|replaceAll|SecurityException|IllegalArgumentException|throw)\b"
)


def _consume_java_literal(text: str, idx: int) -> int:
    """Advance past a Java string or char literal starting at `idx`, returning index after closing quote."""
    quote = text[idx]
    n = len(text)
    i = idx + 1
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    return n


def _find_matching_paren(text: str, open_idx: int) -> int | None:
    depth = 0
    idx = open_idx
    n = len(text)
    while idx < n:
        ch = text[idx]
        if ch in ('"', "'"):
            idx = _consume_java_literal(text, idx)
            continue
        if ch == "/" and idx + 1 < n and text[idx + 1] == "/":
            nl = text.find("\n", idx)
            idx = nl + 1 if nl != -1 else n
            continue
        if ch == "/" and idx + 1 < n and text[idx + 1] == "*":
            end_c = text.find("*/", idx + 2)
            idx = end_c + 2 if end_c != -1 else n
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return None


def _find_matching_close_angle(text: str, open_idx: int) -> int | None:
    """Find matching `>` for `<` at `open_idx` (handles arbitrarily nested Java generic type arguments)."""
    if open_idx < 0 or open_idx >= len(text) or text[open_idx] != "<":
        return None
    depth = 0
    idx = open_idx
    n = len(text)
    while idx < n:
        ch = text[idx]
        if ch in (";", "{", "}", "(", ")"):
            return None
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return None


def _find_matching_open_angle_backward(text: str, close_idx: int) -> int | None:
    """Find matching `<` for `>` at `close_idx` scanning backwards (handles nested Java generics)."""
    if close_idx < 0 or close_idx >= len(text) or text[close_idx] != ">":
        return None
    depth = 0
    idx = close_idx
    while idx >= 0:
        ch = text[idx]
        if ch in (";", "{", "}", "(", ")"):
            return None
        if ch == ">":
            depth += 1
        elif ch == "<":
            depth -= 1
            if depth == 0:
                return idx
        idx -= 1
    return None


def _strip_java_non_executable_preserve_lines(text: str) -> list[str]:
    """Strip Java // comments, /* */ comments, string/char literals, and Java 15+ text blocks (`\"\"\"...\"\"\"`)
    while preserving exact line count and per-line character offsets."""
    result: list[str] = []
    in_block_comment = False
    in_text_block = False
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
            if in_text_block:
                if ch == "\\" and i + 1 < n:
                    out_chars.append("  ")
                    i += 2
                elif ch == '"' and i + 2 < n and raw_line[i + 1] == '"' and raw_line[i + 2] == '"':
                    in_text_block = False
                    out_chars.append('"""')
                    i += 3
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
            if ch == '"' and i + 2 < n and raw_line[i + 1] == '"' and raw_line[i + 2] == '"':
                in_text_block = True
                out_chars.append('"""')
                i += 3
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


def _split_top_level_commas(text: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    paren = 0
    angle = 0
    brace = 0
    idx = 0
    n = len(text)
    while idx < n:
        ch = text[idx]
        if ch in ('"', "'"):
            end_lit = _consume_java_literal(text, idx)
            buf.append(text[idx:end_lit])
            idx = end_lit
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "<":
            angle += 1
        elif ch == ">":
            angle = max(0, angle - 1)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(0, brace - 1)
        if ch == "," and paren == 0 and angle == 0 and brace == 0:
            item = " ".join("".join(buf).split())
            if item:
                parts.append(item)
            buf = []
        else:
            buf.append(ch)
        idx += 1
    tail = " ".join("".join(buf).split())
    if tail:
        parts.append(tail)
    return parts


def _strip_param_annotations_preserve_len(segment: str) -> str:
    """Replace @Annotation and @Annotation(...) inside a parameter list with spaces, keeping length."""
    chars = list(segment)
    i = 0
    n = len(chars)
    while i < n:
        if chars[i] in ('"', "'"):
            i = _consume_java_literal(segment, i)
            continue
        if chars[i] == "@":
            start = i
            i += 1
            while i < n and (chars[i].isalnum() or chars[i] in "_."):
                i += 1
            j = i
            while j < n and chars[j].isspace():
                j += 1
            if j < n and chars[j] == "(":
                close_idx = _find_matching_paren(segment, j)
                if close_idx is not None:
                    i = close_idx + 1
            for k in range(start, i):
                if chars[k] != "\n":
                    chars[k] = " "
        else:
            i += 1
    return "".join(chars)


def _consume_leading_annotations(text: str) -> tuple[list[str], int]:
    """Consume complete leading `@Ann` / `@Ann(...)` prefixes on a signature line.

    Returns `(annotation_names, offset_after_annotations)`. Returns `([], -1)` if a leading
    annotation opens nested parentheses that do not close within `text` (multi-line standalone annotation).
    """
    anns: list[str] = []
    idx = 0
    n = len(text)
    while idx < n:
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n or text[idx] != "@":
            break
        start_name = idx + 1
        cur = start_name
        while cur < n and (text[cur].isalnum() or text[cur] in "_."):
            cur += 1
        if cur == start_name:
            break
        ann_name = text[start_name:cur]
        j = cur
        while j < n and text[j].isspace():
            j += 1
        if j < n and text[j] == "(":
            close_idx = _find_matching_paren(text, j)
            if close_idx is None:
                return [], -1
            idx = close_idx + 1
        else:
            idx = cur
        anns.append(ann_name)
    while idx < n and text[idx].isspace():
        idx += 1
    return anns, idx


def _collect_preceding_annotations(
    raw_lines: list[str],
    clean_lines: list[str],
    header_idx: int,
) -> tuple[list[str], int]:
    """Walk backwards from method header to capture single-line and multi-line annotations."""
    annotations: list[str] = []
    ann_start_line = header_idx + 1
    back = header_idx - 1
    paren_balance = 0
    brace_balance = 0
    steps = 0
    while back >= 0 and steps < 18:
        steps += 1
        raw = raw_lines[back]
        clean = clean_lines[back].strip()
        if not clean:
            if paren_balance == 0 and brace_balance == 0 and annotations:
                break
            back -= 1
            continue
        if clean.endswith((";", "}")) and paren_balance == 0 and brace_balance == 0:
            break
        # Walking upward: ')' increases needed '(' depth, '(' closes it.
        paren_balance += clean.count(")") - clean.count("(")
        brace_balance += clean.count("}") - clean.count("{")
        found_on_line = _ANN_NAME_RE.findall(clean)
        if found_on_line and paren_balance <= 0 and brace_balance <= 0:
            for name in reversed(found_on_line):
                annotations.insert(0, name)
            ann_start_line = back + 1
            paren_balance = 0
            brace_balance = 0
            back -= 1
            continue
        if paren_balance > 0 or brace_balance > 0:
            ann_start_line = back + 1
            back -= 1
            continue
        # Stop on non-annotation statement/declaration line
        if raw.lstrip().startswith(("//", "/*", "*")):
            back -= 1
            continue
        break
    return annotations, ann_start_line


def _parse_method_at(
    raw_lines: list[str],
    clean_lines: list[str],
    start_idx: int,
) -> tuple[dict[str, Any], int] | None:
    """Attempt to parse a Java method header starting at 0-based `start_idx` using balanced parens."""
    total_lines = len(clean_lines)
    first_clean = clean_lines[start_idx]
    inline_anns, ann_offset = _consume_leading_annotations(first_clean)
    if ann_offset < 0:
        return None
    stripped = first_clean[ann_offset:].lstrip()
    if not stripped or stripped.startswith(("}", "{", "//", "/*", "*", "return ", "throw ", "if ", "for ", "while ", "switch ", "catch ")):
        return None
    if CLASS_RE.search(first_clean[ann_offset:]):
        return None

    # Accumulate up to 12 lines until we find '(' -> matching ')' -> optional throws -> '{'
    combined_clean = first_clean
    combined_raw = raw_lines[start_idx]
    end_idx = start_idx
    open_paren = combined_clean.find("(", ann_offset)
    while open_paren == -1 and end_idx + 1 < min(total_lines, start_idx + 4):
        tail_clean = combined_clean[ann_offset:]
        if ";" in tail_clean or "{" in tail_clean or "}" in tail_clean:
            return None
        end_idx += 1
        combined_clean += "\n" + clean_lines[end_idx]
        combined_raw += "\n" + raw_lines[end_idx]
        open_paren = combined_clean.find("(", ann_offset)
    if open_paren == -1:
        return None

    prefix = combined_clean[ann_offset:open_paren]
    if "=" in prefix or ";" in prefix or "{" in prefix or "}" in prefix:
        return None
    m_prefix = _METHOD_PREFIX_RE.match(" ".join(prefix.split()))
    if not m_prefix:
        return None
    mod_tokens = set(m_prefix.group(1).split())
    ret_type = " ".join(m_prefix.group(2).split())
    m_name = m_prefix.group(3)
    if m_name in CONTROL_KEYWORDS or ret_type in CONTROL_KEYWORDS or ret_type in _MODIFIERS:
        return None
    visibility = next((tok for tok in ("public", "protected", "private") if tok in mod_tokens), "package")

    close_paren = _find_matching_paren(combined_clean, open_paren)
    while close_paren is None and end_idx + 1 < min(total_lines, start_idx + 12):
        end_idx += 1
        combined_clean += "\n" + clean_lines[end_idx]
        combined_raw += "\n" + raw_lines[end_idx]
        close_paren = _find_matching_paren(combined_clean, open_paren)
    if close_paren is None:
        return None

    after_paren = combined_clean[close_paren + 1 :]
    while "{" not in after_paren and ";" not in after_paren and end_idx + 1 < min(total_lines, start_idx + 14):
        end_idx += 1
        combined_clean += "\n" + clean_lines[end_idx]
        combined_raw += "\n" + raw_lines[end_idx]
        after_paren = combined_clean[close_paren + 1 :]

    if not _THROWS_TRAILER_RE.match(after_paren):
        return None

    raw_params_segment = combined_raw[open_paren + 1 : close_paren] if close_paren < len(combined_raw) else combined_clean[open_paren + 1 : close_paren]
    params_clean = " ".join(raw_params_segment.split())
    params = _split_top_level_commas(params_clean)
    has_nested_param_parens = "(" in combined_clean[open_paren + 1 : close_paren] or bool(inline_anns)

    prev_annotations, prev_ann_start = _collect_preceding_annotations(raw_lines, clean_lines, start_idx)
    annotations = prev_annotations + inline_anns
    ann_start = prev_ann_start if prev_annotations else (start_idx + 1)

    # Match closing brace of method body from start_idx..total_lines
    depth = 0
    opened = False
    body_end_line = total_lines
    for j in range(start_idx, total_lines):
        # Count braces only starting at the header's opening brace on end_idx or later
        line_c = clean_lines[j]
        c_open = line_c.count("{")
        c_close = line_c.count("}")
        if c_open > 0:
            opened = True
        depth += c_open - c_close
        if opened and depth <= 0:
            body_end_line = j + 1
            break
    if not opened:
        body_end_line = end_idx + 1

    is_entry = (
        m_name in ENTRYPOINT_NAMES
        or any(a.split(".")[-1] in ENTRYPOINT_ANNOTATIONS for a in annotations)
        or any(
            tok in p
            for p in params
            for tok in ("HttpServletRequest", "@RequestParam", "@PathVariable", "@RequestHeader", "@CookieValue", "@RequestBody")
        )
    )
    return (
        {
            "name": m_name,
            "return_type": ret_type,
            "parameters": params,
            "annotations": annotations,
            "signature": f"{ret_type} {m_name}({params_clean})".strip(),
            "header_line": start_idx + 1,
            "header_end_line": end_idx + 1,
            "start_line": ann_start,
            "end_line": body_end_line,
            "is_entrypoint": is_entry,
            "_has_nested_param_parens": has_nested_param_parens,
            "_is_static": "static" in mod_tokens,
            "_is_private": "private" in mod_tokens,
            "_is_final": "final" in mod_tokens,
            "_is_abstract": "abstract" in mod_tokens,
            "_visibility": visibility,
        },
        end_idx,
    )


_IMPORT_V2_RE = re.compile(
    r"\bimport\s+(static\s+)?([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*(?:[A-Za-z_][A-Za-z0-9_]*|\*))*)\s*;"
)


def parse_java_structure_v2(text: str) -> dict[str, Any]:
    """Balanced-parenthesis Java parser supporting Spring/JAX-RS parameter & multi-line annotations."""
    raw_lines = text.splitlines()
    clean_lines = _strip_comments_and_strings_preserve_lines(text)
    total_lines = len(raw_lines)

    package_name: str | None = None
    imports: list[str] = []
    type_imports: list[str] = []
    static_imports: list[str] = []
    classes: list[dict[str, Any]] = []
    methods: list[dict[str, Any]] = []

    for clean in clean_lines:
        if package_name is None:
            m_pkg = PACKAGE_RE.match(clean)
            if m_pkg:
                package_name = m_pkg.group(1)
        for m_imp in _IMPORT_V2_RE.finditer(clean):
            is_static = bool(m_imp.group(1))
            imp_target = re.sub(r"\s+", "", m_imp.group(2))
            imports.append(imp_target)
            if is_static:
                static_imports.append(imp_target)
            else:
                type_imports.append(imp_target)

    i = 0
    while i < total_lines:
        clean = clean_lines[i]
        m_cls = CLASS_RE.search(clean)
        if m_cls:
            brace_line = None
            for k in range(i, min(total_lines, i + 4)):
                seg = clean_lines[k][m_cls.start() :] if k == i else clean_lines[k]
                if "{" in seg:
                    brace_line = k
                    break
                if ";" in seg:
                    break
            if brace_line is not None:
                cls_name = m_cls.group(1)
                header_clean = " ".join(clean_lines[k].strip() for k in range(i, brace_line + 1))
                prefix_before_kind = header_clean[: header_clean.find(cls_name)]
                cls_kind = (
                    "interface"
                    if re.search(r"\binterface\s+$", prefix_before_kind)
                    else ("enum" if re.search(r"\benum\s+$", prefix_before_kind) else "class")
                )
                cls_mods = set(re.split(r"\s+", prefix_before_kind.strip()))
                m_ext = re.search(
                    rf"\b{re.escape(cls_name)}\b[^{{]*?\bextends\s+([A-Za-z_][A-Za-z0-9_.<>,\s]*?)(?=\bimplements\b|\{{|$)",
                    header_clean,
                )
                m_imp = re.search(
                    rf"\b{re.escape(cls_name)}\b[^{{]*?\bimplements\s+([A-Za-z_][A-Za-z0-9_.<>,\s]*?)(?=\{{|$)",
                    header_clean,
                )
                depth = 0
                opened = False
                end_line = total_lines
                for j in range(brace_line, total_lines):
                    c_open = clean_lines[j].count("{")
                    c_close = clean_lines[j].count("}")
                    if c_open > 0:
                        opened = True
                    depth += c_open - c_close
                    if opened and depth <= 0:
                        end_line = j + 1
                        break
                classes.append(
                    {
                        "name": cls_name,
                        "start_line": i + 1,
                        "end_line": end_line,
                        "kind": cls_kind,
                        "is_final": "final" in cls_mods,
                        "is_abstract": ("abstract" in cls_mods) or (cls_kind == "interface"),
                        "extends": m_ext.group(1).strip() if m_ext else None,
                        "implements": [x.strip() for x in m_imp.group(1).split(",") if x.strip()] if m_imp else [],
                    }
                )

        parsed = _parse_method_at(raw_lines, clean_lines, i)
        if parsed is not None:
            meth, end_idx = parsed
            methods.append(meth)
            i = end_idx + 1
            continue
        i += 1

    for m in methods:
        owner_cls: str | None = None
        best_span: int | None = None
        for cls in classes:
            if cls["start_line"] <= m["header_line"] <= cls["end_line"]:
                span = cls["end_line"] - cls["start_line"]
                if best_span is None or span < best_span:
                    best_span = span
                    owner_cls = cls["name"]
        m["owner_class"] = owner_cls

    return {
        "package_name": package_name,
        "imports": imports,
        "type_imports": type_imports,
        "static_imports": static_imports,
        "classes": classes,
        "methods": methods,
        "total_lines": total_lines,
    }


def _strip_internal_method_keys(method: dict[str, Any] | None) -> dict[str, Any] | None:
    if method is None:
        return None
    return {k: v for k, v in method.items() if not k.startswith("_") and k != "header_end_line"}


_FIELD_DECL_STMT_RE = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|transient|volatile)\s+)*"
    r"([A-Za-z_][A-Za-z0-9_<>,.\[\]?\s]*?)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*\s*(?:=\s*[^;]+)?(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:=\s*[^;]+)?)*)\s*;\s*$"
)


def _extract_class_fields_with_types(
    text: str,
    structure: dict[str, Any] | None = None,
    enclosing_class: str | None = None,
) -> dict[str, str | None]:
    """Extract `{field_name: raw_type}` declared directly inside `enclosing_class` (excluding methods & nested classes).

    If the same field name appears multiple times with conflicting types, maps it to `None` (fail closed).
    """
    parsed = structure if isinstance(structure, dict) else parse_java_structure_v2(text)
    classes = parsed.get("classes") or []
    methods = parsed.get("methods") or []
    clean_lines = _strip_comments_and_strings_preserve_lines(text)
    target_classes = [c for c in classes if not enclosing_class or c.get("name") == enclosing_class]
    if not target_classes:
        target_classes = list(classes)

    field_types: dict[str, str | None] = {}
    for cls in target_classes:
        c_start = int(cls.get("start_line") or 1)
        c_end = int(cls.get("end_line") or len(clean_lines))
        # Exclude method bodies and nested class bodies inside `cls`
        excluded_ranges: list[tuple[int, int]] = []
        for m in methods:
            ms = int(m.get("header_line") or m.get("start_line") or 0)
            me = int(m.get("end_line") or 0)
            if c_start < ms <= c_end:
                excluded_ranges.append((ms, me))
        for other in classes:
            if other is cls:
                continue
            os_ln = int(other.get("start_line") or 0)
            oe_ln = int(other.get("end_line") or 0)
            if c_start < os_ln <= oe_ln <= c_end:
                excluded_ranges.append((os_ln, oe_ln))
        for lno in range(c_start + 1, min(c_end, len(clean_lines)) + 1):
            if any(lo <= lno <= hi for lo, hi in excluded_ranges):
                continue
            cl = clean_lines[lno - 1].strip()
            if not cl or cl.startswith(("{", "}", "package ", "import ")):
                continue
            if cl.startswith("@"):
                _, ann_off = _consume_leading_annotations(cl)
                if ann_off < 0:
                    continue
                cl = cl[ann_off:].strip()
                if not cl:
                    continue
            if "(" in cl and not ("=" in cl and cl.find("=") < cl.find("(")):
                # Skip constructor/method/static-initializer headers that are not field initializers
                continue
            m_f = _FIELD_DECL_STMT_RE.match(cl)
            if not m_f:
                continue
            raw_type = m_f.group(1).strip()
            first_tok = raw_type.split()[0] if raw_type else ""
            if first_tok in CONTROL_KEYWORDS or first_tok in ("class", "interface", "enum", "void"):
                continue
            decls = _split_top_level_commas(m_f.group(2))
            for item in decls:
                lhs = item.split("=", 1)[0].strip()
                lhs = re.sub(r"\s*\[\s*\]\s*", "", lhs).strip()
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", lhs) and lhs not in CONTROL_KEYWORDS:
                    if lhs in field_types and field_types[lhs] != raw_type:
                        field_types[lhs] = None
                    else:
                        field_types[lhs] = raw_type
    return field_types


def extract_class_field_names(text: str, structure: dict[str, Any] | None = None, enclosing_class: str | None = None) -> set[str]:
    """Extract field identifier names declared directly inside `enclosing_class` (or any enclosing class in `text`)."""
    return set(_extract_class_fields_with_types(text, structure=structure, enclosing_class=enclosing_class).keys())


def extract_class_field_types(text: str, structure: dict[str, Any] | None = None, enclosing_class: str | None = None) -> dict[str, str]:
    """Extract `{field_name: raw_type}` for unambiguous fields declared directly inside `enclosing_class`."""
    raw_map = _extract_class_fields_with_types(text, structure=structure, enclosing_class=enclosing_class)
    return {k: v for k, v in raw_map.items() if isinstance(v, str) and v}


def extract_class_declared_method_names(
    text: str,
    structure: dict[str, Any] | None = None,
    enclosing_class: str | None = None,
) -> set[str]:
    """Extract method names declared directly on `enclosing_class` (to detect overrides of inherited stdlib methods)."""
    parsed = structure if isinstance(structure, dict) else parse_java_structure_v2(text)
    methods = parsed.get("methods") or []
    out: set[str] = set()
    for m in methods:
        mname = m.get("name")
        if not isinstance(mname, str) or not mname:
            continue
        if enclosing_class and m.get("owner_class") != enclosing_class:
            continue
        out.add(mname)
    return out


def extract_java_context_v2(
    text: str,
    finding_start_line: int,
    finding_end_line: int,
    trace_lines: list[int] | tuple[int, ...] = (),
    max_span: int = MAX_FINDING_WINDOW_LINES,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any] | None]:
    """Extract enclosing method, 3-hop same-file callees, callers, and distant helper specs.

    Returns `(java_context_dict, distant_callees, raw_enclosing_method_with_meta)`.
    """
    structure = parse_java_structure_v2(text)
    raw_lines = text.splitlines()
    clean_lines = _strip_comments_and_strings_preserve_lines(text)
    total_lines = len(raw_lines)
    methods = structure["methods"]
    same_file_class_names = {c["name"] for c in structure["classes"]}

    enclosing_method: dict[str, Any] | None = None
    for m in methods:
        if m["start_line"] <= finding_start_line <= m["end_line"]:
            if enclosing_method is None or (m["end_line"] - m["start_line"]) < (
                enclosing_method["end_line"] - enclosing_method["start_line"]
            ):
                enclosing_method = m

    same_file_callees: list[dict[str, Any]] = []
    same_file_callers: list[dict[str, Any]] = []

    if enclosing_method is not None:
        seen_headers: set[int] = {enclosing_method["header_line"]}
        frontier: list[dict[str, Any]] = [enclosing_method]
        for _hop in range(3):
            if not frontier:
                break
            next_frontier: list[dict[str, Any]] = []
            resolved_targets: set[tuple[str | None, str]] = set()
            for cur_m in frontier:
                for t_cls, m_name in _extract_qualified_calls_in_method(
                    clean_lines, cur_m, same_file_class_names, structure["package_name"]
                ):
                    if t_cls is not None:
                        resolved_targets.add((t_cls, m_name))
            for other in methods:
                if other["header_line"] in seen_headers:
                    continue
                is_direct_callee = (other.get("owner_class"), other["name"]) in resolved_targets
                in_trace = (_hop == 0) and any(other["start_line"] <= tl <= other["end_line"] for tl in trace_lines)
                if is_direct_callee or in_trace:
                    seen_headers.add(other["header_line"])
                    same_file_callees.append(other)
                    # Only expand transitive callees from true callees of enclosing_method.
                    # Trace-only callers (e.g. a servlet dispatcher like doPost/doGet) must be attached
                    # for source/call-site visibility without pulling unrelated sibling handlers.
                    if is_direct_callee:
                        next_frontier.append(other)
            frontier = next_frontier

        for other in methods:
            if other["header_line"] in seen_headers:
                continue
            other_body = "\n".join(clean_lines[other["start_line"] - 1 : other["end_line"]])
            if re.search(rf"\b{re.escape(enclosing_method['name'])}\s*\(", other_body):
                same_file_callers.append(other)

    distant_callees: list[dict[str, Any]] = []
    if enclosing_method is not None:
        lower = enclosing_method["start_line"]
        upper = enclosing_method["end_line"]
        cls_by_name = {c["name"]: c for c in structure["classes"]}
        for callee in same_file_callees:
            c_start = callee["start_line"]
            c_end = callee["end_line"]
            c_owner = callee.get("owner_class")
            if c_owner and c_owner in cls_by_name and c_owner != enclosing_method.get("owner_class"):
                owner_info = cls_by_name[c_owner]
                if (owner_info["end_line"] - min(lower, owner_info["start_line"])) <= max_span:
                    c_start = min(c_start, owner_info["start_line"])
                    c_end = max(c_end, owner_info["end_line"])
            cand_lower = min(lower, c_start)
            cand_upper = max(upper, c_end)
            if cand_upper - cand_lower <= max_span:
                lower, upper = cand_lower, cand_upper
            else:
                distant_callees.append(callee)
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
    enclosing_class_extends = None
    for cls in structure["classes"]:
        if cls["start_line"] <= finding_start_line <= cls["end_line"]:
            enclosing_class = cls["name"]
            enclosing_class_extends = cls.get("extends")
            break
    enclosing_field_types = extract_class_field_types(text, structure=structure, enclosing_class=enclosing_class)
    enclosing_fields = sorted(extract_class_field_names(text, structure=structure, enclosing_class=enclosing_class))
    enclosing_declared_methods = sorted(
        extract_class_declared_method_names(text, structure=structure, enclosing_class=enclosing_class)
    )

    jctx = {
        "parser_mode": CONTEXT_V2_VERSION,
        "package_name": structure["package_name"],
        "imports": structure["imports"],
        "type_imports": structure["type_imports"],
        "static_imports": structure["static_imports"],
        "declared_class_names": [c["name"] for c in structure["classes"] if isinstance(c.get("name"), str)],
        "enclosing_class": enclosing_class,
        "enclosing_class_extends": enclosing_class_extends,
        "enclosing_class_fields": enclosing_fields,
        "enclosing_class_field_types": enclosing_field_types,
        "enclosing_class_declared_methods": enclosing_declared_methods,
        "enclosing_method": _strip_internal_method_keys(enclosing_method),
        "same_file_callees": [_strip_internal_method_keys(c) for c in same_file_callees],
        "same_file_callers": [_strip_internal_method_keys(c) for c in same_file_callers],
        "context_start_line": lower,
        "context_end_line": upper,
    }
    return jctx, distant_callees, enclosing_method


def effective_prompt_byte_length(record: dict[str, Any]) -> int:
    """Return max serialized byte length across ASCII-escaped and raw UTF-8 prompt encodings."""
    built = build_ollama_prompt(record)
    ascii_bytes = len(json.dumps(built, ensure_ascii=True).encode("utf-8"))
    utf8_bytes = len(json.dumps(built, ensure_ascii=False).encode("utf-8"))
    return max(ascii_bytes, utf8_bytes)


def _prompt_byte_length(record: dict[str, Any]) -> int:
    return effective_prompt_byte_length(record)


def _compact_redundant_snippets(record: dict[str, Any]) -> int:
    """Trim duplicate surrounding lines from secondary snippets whose matched span is covered by primary or helper snippets."""
    snippets = record.get("snippets") or []
    if len(snippets) <= 1:
        return 0
    primary = snippets[0]
    covered: set[tuple[Any, int]] = set()
    for s in snippets:
        if s is primary or s.get("role") == "helper":
            sp = s.get("path")
            for ln in (s.get("lines") or []):
                if isinstance(ln, dict) and type(ln.get("line")) is int:
                    covered.add((sp, ln["line"]))
    compacted_count = 0
    for snip in snippets[1:]:
        if snip.get("role") not in ("source", "sink", "intermediate"):
            continue
        s_path = snip.get("path")
        s_lines = snip.get("lines") or []
        if not s_lines:
            continue
        sl = (snip.get("start") or {}).get("line")
        el = (snip.get("end") or {}).get("line", sl)
        if type(sl) is not int or type(el) is not int:
            continue
        if not all((s_path, ln_no) in covered for ln_no in range(sl, el + 1)):
            continue
        focused = [ln for ln in s_lines if isinstance(ln, dict) and sl <= ln.get("line", -1) <= el]
        if focused and len(focused) < len(s_lines):
            snip["lines"] = focused
            compacted_count += 1
    return compacted_count


def _enforce_prompt_budget(record: dict[str, Any], max_prompt_bytes: int) -> bool:
    """Trim non-essential snippet lines to keep serialized prompt <= max_prompt_bytes without dropping anchors or guards."""
    effective_limit = min(int(max_prompt_bytes), DEFAULT_MAX_PROMPT_BYTES)
    try:
        if _prompt_byte_length(record) <= effective_limit:
            return False
    except EvidenceError:
        return False

    trimmed = False
    snippets = record.get("snippets") or []

    # 1. Drop extra distant helper snippets first (furthest last)
    while len(snippets) > 1 and _prompt_byte_length(record) > effective_limit:
        helper_idx = next(
            (i for i in range(len(snippets) - 1, 0, -1) if snippets[i].get("role") == "helper"),
            None,
        )
        if helper_idx is None:
            break
        snippets.pop(helper_idx)
        trimmed = True

    if _prompt_byte_length(record) <= effective_limit or not snippets:
        return trimmed

    # 2. Progressively trim primary finding snippet around critical anchor lines
    primary = snippets[0]
    p_path = primary.get("path")
    p_lines = primary.get("lines") or []
    if not p_lines:
        return trimmed

    f_sl = (primary.get("start") or {}).get("line", 1)
    f_el = (primary.get("end") or {}).get("line", f_sl)
    trace_anchor_lines: set[int] = set(range(f_sl - 3, f_el + 4))
    jctx = record.get("java_context") if isinstance(record.get("java_context"), dict) else {}
    enc = jctx.get("enclosing_method") if isinstance(jctx.get("enclosing_method"), dict) else None
    if enc and type(enc.get("header_line")) is int:
        trace_anchor_lines.add(enc["header_line"])
    for s in snippets[1:]:
        if s.get("path") == p_path:
            sl = (s.get("start") or {}).get("line")
            el = (s.get("end") or {}).get("line", sl)
            if type(sl) is int and type(el) is int:
                trace_anchor_lines.update(range(sl - 1, el + 2))
    anchor_lines: set[int] = set(trace_anchor_lines)
    strong_guard_lines: set[int] = set()
    p_by_no = {int(ln["line"]): str(ln.get("text") or "") for ln in p_lines if isinstance(ln, dict) and type(ln.get("line")) is int}
    for ln in p_lines:
        if isinstance(ln, dict):
            txt = str(ln.get("text") or "")
            lno = int(ln["line"])
            if _STRONG_GUARD_RE.search(txt):
                # Keep enclosing `if (...) { throw ...; }` guard block intact (including closing `}`).
                span_hi = lno + 2
                if "{" in txt:
                    depth = txt.count("{") - txt.count("}")
                    cur = lno
                    while depth > 0 and cur < lno + 6 and (cur + 1) in p_by_no:
                        cur += 1
                        nxt_t = p_by_no[cur]
                        depth += nxt_t.count("{") - nxt_t.count("}")
                    span_hi = max(span_hi, cur)
                strong_guard_lines.update(range(lno - 1, span_hi + 1))
                anchor_lines.update(range(lno - 1, span_hi + 1))
            elif _GUARD_HINT_RE.search(txt):
                anchor_lines.add(lno)

    for radius in (40, 25, 15, 8, 3):
        if _prompt_byte_length(record) <= effective_limit:
            break
        keep_window = set(range(f_sl - radius, f_el + radius + 1)) | anchor_lines
        candidate_lines = [ln for ln in p_lines if isinstance(ln, dict) and ln.get("line") in keep_window]
        if candidate_lines and len(candidate_lines) < len(primary["lines"]):
            primary["lines"] = candidate_lines
            trimmed = True

    # Narrow to strict finding +/- 3 + source/sink/helper trace anchors + strong guards + method header;
    # NEVER silently drop guards, sources, or sinks to fit under budget.
    if _prompt_byte_length(record) > effective_limit:
        core_keep = trace_anchor_lines | strong_guard_lines
        candidate_core = [ln for ln in p_lines if isinstance(ln, dict) and ln.get("line") in core_keep]
        if candidate_core and len(candidate_core) < len(primary["lines"]):
            primary["lines"] = candidate_core
            trimmed = True

    return trimmed


def _refresh_heuristic_signals(record: dict[str, Any], raw_enclosing: dict[str, Any] | None) -> None:
    """Recompute heuristic_signals safely; recover method parsing when Spring param/inline annotations confuse sealed regex."""
    try:
        sig = extract_evidence_signals(record)
    except Exception:
        return
    record["heuristic_signals"] = sig

    if not raw_enclosing or not raw_enclosing.get("_has_nested_param_parens"):
        return
    if sig.get("recommended_status") != "UNDETERMINED":
        return

    # Only mask parameter/inline annotations in an ephemeral copy of method header lines so line numbers stay identical.
    h_start = raw_enclosing.get("header_line")
    h_end = raw_enclosing.get("header_end_line", h_start)
    if type(h_start) is not int or type(h_end) is not int:
        return
    tmp = copy.deepcopy(record)
    snippets = tmp.get("snippets") or []
    if not snippets:
        return
    primary_lines = snippets[0].get("lines") or []
    real_by_ln = {
        ln["line"]: ln["text"]
        for ln in (record.get("snippets") or [{}])[0].get("lines") or []
        if isinstance(ln, dict) and type(ln.get("line")) is int
    }
    header_objs = [ln for ln in primary_lines if isinstance(ln, dict) and h_start <= ln.get("line", -1) <= h_end]
    if not header_objs:
        return
    joined = "\n".join(ln["text"] for ln in header_objs)
    _, hdr_ann_off = _consume_leading_annotations(joined)
    if hdr_ann_off < 0:
        return
    open_p = joined.find("(", hdr_ann_off)
    if open_p == -1:
        return
    close_p = _find_matching_paren(joined, open_p)
    if close_p is None:
        return
    masked_lead = "".join(ch if ch == "\n" else " " for ch in joined[:hdr_ann_off])
    masked_params = _strip_param_annotations_preserve_len(joined[open_p + 1 : close_p])
    masked_joined = masked_lead + joined[hdr_ann_off : open_p + 1] + masked_params + joined[close_p:]
    masked_split = masked_joined.splitlines()
    if len(masked_split) != len(header_objs):
        return
    masked_by_ln = {ln_obj["line"]: new_txt for ln_obj, new_txt in zip(header_objs, masked_split)}
    primary_path = snippets[0].get("path")
    for snip in snippets:
        if isinstance(snip, dict) and snip.get("path") == primary_path:
            for ln_obj in snip.get("lines") or []:
                if isinstance(ln_obj, dict) and ln_obj.get("line") in masked_by_ln:
                    ln_obj["text"] = masked_by_ln[ln_obj["line"]]

    try:
        recovered = extract_evidence_signals(tmp)
    except Exception:
        return
    # Restore verbatim source text in candidate_citations (both single-line and multi-line spans)
    for cite in recovered.get("candidate_citations") or []:
        if isinstance(cite, dict):
            sl = cite.get("start_line")
            el = cite.get("end_line")
            if type(sl) is int and type(el) is int and sl <= el and all(ln in real_by_ln for ln in range(sl, el + 1)):
                cite["quote"] = "\n".join(real_by_ln[ln] for ln in range(sl, el + 1))
    record["heuristic_signals"] = recovered


def enrich_record_context(
    record: dict[str, Any],
    tree: SourceTree,
    *,
    max_prompt_bytes: int = DEFAULT_MAX_PROMPT_BYTES,
) -> dict[str, Any]:
    """Enrich a collected evidence record in-place and return prompt size / context telemetry."""
    stats: dict[str, Any] = {
        "before_prompt_bytes": None,
        "after_prompt_bytes": None,
        "spring_method_recovered": False,
        "helpers_attached": 0,
        "compacted_snippets": 0,
        "budget_trimmed": False,
    }
    try:
        stats["before_prompt_bytes"] = _prompt_byte_length(record)
    except Exception:
        stats["before_prompt_bytes"] = None

    snippets = record.get("snippets") or []
    snapshots = record.get("snapshots") if isinstance(record.get("snapshots"), dict) else {}
    if not snippets or snippets[0].get("role") != "finding":
        stats["after_prompt_bytes"] = stats["before_prompt_bytes"]
        return stats

    f_snip = snippets[0]
    rel_path = f_snip.get("path")
    snap = snapshots.get(rel_path) if isinstance(rel_path, str) else None
    if not isinstance(snap, dict) or not isinstance(snap.get("sha256"), str):
        stats["after_prompt_bytes"] = stats["before_prompt_bytes"]
        return stats

    old_enc = (record.get("java_context") or {}).get("enclosing_method") if isinstance(record.get("java_context"), dict) else None
    raw_enc: dict[str, Any] | None = None
    enclosing_strong_guard_lines: set[int] = set()
    try:
        resolved_rel, data, f_text = tree.read(f_snip.get("raw_path") or rel_path)
        if resolved_rel != rel_path or digest(data) != snap["sha256"]:
            stats["after_prompt_bytes"] = stats["before_prompt_bytes"]
            return stats
        f_lines = f_text.splitlines(keepends=True)
        f_sl, f_el = f_snip["start"]["line"], f_snip["end"]["line"]
        if f_el - f_sl <= MAX_FINDING_WINDOW_LINES:
            t_lines = [
                s["start"]["line"]
                for s in snippets[1:]
                if s.get("path") == rel_path and isinstance(s.get("start"), dict) and type(s["start"].get("line")) is int
            ]
            java_ctx, distant_callees, raw_enc = extract_java_context_v2(
                f_text,
                f_sl,
                f_el,
                trace_lines=t_lines,
                max_span=MAX_FINDING_WINDOW_LINES,
            )
            if isinstance(raw_enc, dict):
                enc_s = max(1, int(raw_enc["start_line"]))
                enc_e = min(len(f_lines), int(raw_enc["end_line"]))
                clean_full = _strip_comments_and_strings_preserve_lines(f_text)
                for lno in range(enc_s, enc_e + 1):
                    if lno - 1 < len(clean_full) and _STRONG_GUARD_RE.search(clean_full[lno - 1]):
                        enclosing_strong_guard_lines.add(lno)
            c_low = max(1, min(f_sl, java_ctx["context_start_line"]))
            c_high = min(len(f_lines), max(f_el, java_ctx["context_end_line"]))
            if c_high - c_low <= 150:
                f_snip["lines"] = [
                    {"line": i, "text": f_lines[i - 1].rstrip("\r\n")}
                    for i in range(c_low, c_high + 1)
                ]
            record["java_context"] = java_ctx
            if old_enc is None and java_ctx.get("enclosing_method") is not None:
                stats["spring_method_recovered"] = True

            # Attach verified same-file helper snippets that did not fit in the contiguous 140-line window
            covered_lines = {ln["line"] for ln in f_snip["lines"]}
            attached = 0
            for callee in distant_callees:
                if attached >= MAX_HELPER_SNIPPETS:
                    break
                h_start = max(1, int(callee["start_line"]))
                h_end = min(len(f_lines), int(callee["end_line"]))
                if h_end < h_start or (h_end - h_start + 1) > MAX_HELPER_SNIPPET_LINES:
                    continue
                if all(i in covered_lines for i in range(h_start, h_end + 1)):
                    continue
                end_text = f_lines[h_end - 1].rstrip("\r\n")
                snippets.append(
                    {
                        "role": "helper",
                        "path": rel_path,
                        "raw_path": f_snip.get("raw_path") or rel_path,
                        "start": {"line": h_start, "col": 1},
                        "end": {"line": h_end, "col": max(1, len(end_text))},
                        "sha256": snap["sha256"],
                        "matched": f_lines[h_start - 1].rstrip("\r\n"),
                        "lines": [
                            {"line": i, "text": f_lines[i - 1].rstrip("\r\n")}
                            for i in range(h_start, h_end + 1)
                        ],
                    }
                )
                covered_lines.update(range(h_start, h_end + 1))
                attached += 1
            stats["helpers_attached"] = attached
    except (EvidenceError, OSError, UnicodeError, ValueError, RuntimeError):
        pass

    stats["compacted_snippets"] = _compact_redundant_snippets(record)
    stats["budget_trimmed"] = _enforce_prompt_budget(record, max_prompt_bytes)

    # Fail closed if span or prompt budget truncation dropped any strong guard/sanitizer line inside the enclosing method.
    if enclosing_strong_guard_lines:
        surviving_lines = {
            ln["line"]
            for s in (record.get("snippets") or [])
            if isinstance(s, dict) and s.get("path") == rel_path
            for ln in (s.get("lines") or [])
            if isinstance(ln, dict) and type(ln.get("line")) is int
        }
        dropped_guards = sorted(enclosing_strong_guard_lines - surviving_lines)
        if dropped_guards:
            stats["guard_lines_truncated"] = dropped_guards
            issues = record.setdefault("issues", [])
            msg = (
                "prompt/context budget truncated guard or sanitizer lines inside enclosing method "
                f"(lines {dropped_guards[:8]}); manual inspection required"
            )
            if msg not in issues:
                issues.append(msg)

    _refresh_heuristic_signals(record, raw_enc)

    effective_limit = min(int(max_prompt_bytes), DEFAULT_MAX_PROMPT_BYTES)
    try:
        after_bytes = _prompt_byte_length(record)
    except Exception:
        after_bytes = None
    if type(after_bytes) is int and after_bytes > effective_limit:
        if _enforce_prompt_budget(record, effective_limit):
            stats["budget_trimmed"] = True
            _refresh_heuristic_signals(record, raw_enc)
            try:
                after_bytes = _prompt_byte_length(record)
            except Exception:
                after_bytes = None
    if type(after_bytes) is int and after_bytes > effective_limit:
        stats["prompt_budget_exceeded"] = True
        issues = record.setdefault("issues", [])
        msg = (
            f"prompt byte budget exceeded after compaction ({after_bytes} > {effective_limit} bytes); "
            "manual inspection required"
        )
        if msg not in issues:
            issues.append(msg)
    stats["after_prompt_bytes"] = after_bytes
    return stats


def enrich_bundle_context(
    bundle: dict[str, Any],
    source_root: Any,
    *,
    path_base: Any = None,
    path_maps: tuple[str, ...] | list[str] = (),
    max_prompt_bytes: int = DEFAULT_MAX_PROMPT_BYTES,
) -> dict[str, Any]:
    """Enrich every record in a collected evidence bundle and return aggregate telemetry."""
    tree = SourceTree(source_root, path_base, path_maps)
    before_bytes: list[int] = []
    after_bytes: list[int] = []
    spring_recovered = 0
    helpers_attached = 0
    compacted_snippets = 0
    budget_trimmed = 0

    for record in bundle.get("records") or []:
        st = enrich_record_context(record, tree, max_prompt_bytes=max_prompt_bytes)
        if type(st["before_prompt_bytes"]) is int:
            before_bytes.append(st["before_prompt_bytes"])
        if type(st["after_prompt_bytes"]) is int:
            after_bytes.append(st["after_prompt_bytes"])
        if st["spring_method_recovered"]:
            spring_recovered += 1
        helpers_attached += int(st["helpers_attached"])
        compacted_snippets += int(st["compacted_snippets"])
        if st["budget_trimmed"]:
            budget_trimmed += 1

    return {
        "context_version": CONTEXT_V2_VERSION,
        "records_processed": len(bundle.get("records") or []),
        "spring_methods_recovered": spring_recovered,
        "helpers_attached": helpers_attached,
        "compacted_snippets": compacted_snippets,
        "budget_trimmed": budget_trimmed,
        "before_prompt_bytes_total": sum(before_bytes),
        "after_prompt_bytes_total": sum(after_bytes),
        "before_prompt_bytes_avg": round(sum(before_bytes) / len(before_bytes), 1) if before_bytes else 0.0,
        "after_prompt_bytes_avg": round(sum(after_bytes) / len(after_bytes), 1) if after_bytes else 0.0,
        "before_prompt_bytes_max": max(before_bytes) if before_bytes else 0,
        "after_prompt_bytes_max": max(after_bytes) if after_bytes else 0,
    }


_STD_FLOW_QUALIFIERS = frozenset(
    {
        "Files",
        "Paths",
        "Path",
        "File",
        "FilenameUtils",
        "FileUtils",
        "IOUtils",
        "StringUtils",
        "StringEscapeUtils",
        "HtmlUtils",
        "UriUtils",
        "UriComponentsBuilder",
        "StreamUtils",
        "CollectionUtils",
        "ObjectUtils",
        "Assert",
        "String",
        "StringBuilder",
        "StringBuffer",
        "Integer",
        "Long",
        "Double",
        "Float",
        "Boolean",
        "Short",
        "Byte",
        "Character",
        "UUID",
        "Pattern",
        "Matcher",
        "Objects",
        "Arrays",
        "Collections",
        "List",
        "Set",
        "Map",
        "Optional",
        "Stream",
        "Collectors",
        "DriverManager",
        "PreparedStatement",
        "Statement",
        "Connection",
        "ResultSet",
        "JdbcTemplate",
        "NamedParameterJdbcTemplate",
        "NamedParameterJdbcOperations",
        "ResponseEntity",
        "HttpStatus",
        "HttpHeaders",
        "URLEncoder",
        "URLDecoder",
        "Base64",
        "Charset",
        "StandardCharsets",
        "StandardOpenOption",
        "Logger",
        "LoggerFactory",
        "LogManager",
        "System",
        "Math",
        "Thread",
        "ESAPI",
        "req",
        "request",
        "resp",
        "response",
        "stmt",
        "statement",
        "ps",
        "pstmt",
        "conn",
        "connection",
        "jdbc",
        "jdbcTemplate",
        "namedJdbc",
        "ops",
        "log",
        "logger",
        "LOGGER",
        "LOG",
        "out",
        "err",
        "sb",
        "buf",
    }
)

_STD_FLOW_METHODS = frozenset(
    {
        "getParameter",
        "getParameterValues",
        "getHeader",
        "getHeaders",
        "getQueryString",
        "getPathInfo",
        "getRequestURI",
        "getRequestURL",
        "getCookies",
        "getAttribute",
        "getSession",
        "getPrincipal",
        "getUserPrincipal",
        "getRemoteUser",
        "getOriginalFilename",
        "getSubmittedFileName",
        "getName",
        "getValue",
        "getInputStream",
        "getReader",
        "getCanonicalPath",
        "getCanonicalFile",
        "getAbsolutePath",
        "getParentFile",
        "getParent",
        "toPath",
        "toFile",
        "toRealPath",
        "normalize",
        "resolve",
        "relativize",
        "getFileName",
        "toString",
        "toLowerCase",
        "toUpperCase",
        "readString",
        "readAllBytes",
        "readAllLines",
        "newInputStream",
        "newBufferedReader",
        "list",
        "walk",
        "find",
        "exists",
        "isRegularFile",
        "isDirectory",
        "of",
        "ofNullable",
        "orElse",
        "get",
        "executeQuery",
        "executeUpdate",
        "execute",
        "executeLargeUpdate",
        "addBatch",
        "executeBatch",
        "prepareStatement",
        "prepareCall",
        "setString",
        "setInt",
        "setLong",
        "setBoolean",
        "setObject",
        "query",
        "queryForObject",
        "queryForList",
        "queryForMap",
        "queryForRowSet",
        "update",
        "batchUpdate",
        "startsWith",
        "endsWith",
        "equals",
        "equalsIgnoreCase",
        "contains",
        "matches",
        "indexOf",
        "lastIndexOf",
        "substring",
        "subSequence",
        "trim",
        "strip",
        "replace",
        "replaceAll",
        "split",
        "concat",
        "format",
        "join",
        "isEmpty",
        "isBlank",
        "length",
        "size",
        "charAt",
        "chars",
        "codePoints",
        "getBytes",
        "valueOf",
        "parseInt",
        "parseLong",
        "parseDouble",
        "fromString",
        "compile",
        "matcher",
        "group",
        "append",
        "insert",
        "add",
        "put",
        "remove",
        "clear",
        "containsKey",
        "containsValue",
        "stream",
        "map",
        "filter",
        "collect",
        "toList",
        "toSet",
        "info",
        "debug",
        "warn",
        "error",
        "trace",
        "log",
        "record",
        "audit",
        "println",
        "print",
        "printf",
        "flush",
        "close",
        "requireNonNull",
        "requireNonNullElse",
        "encode",
        "decode",
        "htmlEscape",
        "singletonList",
        "asList",
    }
)

_STD_TAINT_PASSTHROUGH_CALLS = frozenset(
    {
        ("Path", "of"),
        ("Paths", "get"),
        ("String", "valueOf"),
        ("String", "format"),
        ("String", "join"),
        ("Objects", "toString"),
        ("Objects", "requireNonNull"),
        ("Objects", "requireNonNullElse"),
    }
)

_STDLIB_PKG_PREFIXES = (
    "java.",
    "javax.",
    "jakarta.",
    "org.springframework.",
    "org.apache.commons.",
    "org.owasp.",
    "org.slf4j.",
    "org.apache.logging.log4j.",
)

# Exact mapping of recognized standard/framework simple class names to their legitimate package(s).
# Used by JLS §6.5.5.1 FQN resolution so non-java.lang classes NEVER match without an import,
# and java.lang / wildcard classes NEVER bypass shadowing by same-file, explicit-import, or same-package classes.
_STDLIB_SIMPLE_TO_PACKAGES: dict[str, tuple[str, ...]] = {
    # java.lang (implicitly imported per JLS §7.3, unless shadowed by same-file, explicit import, or same-package class)
    "Object": ("java.lang",),
    "String": ("java.lang",),
    "CharSequence": ("java.lang",),
    "StringBuilder": ("java.lang",),
    "StringBuffer": ("java.lang",),
    "Integer": ("java.lang",),
    "Long": ("java.lang",),
    "Double": ("java.lang",),
    "Float": ("java.lang",),
    "Boolean": ("java.lang",),
    "Short": ("java.lang",),
    "Byte": ("java.lang",),
    "Character": ("java.lang",),
    "Number": ("java.lang",),
    "System": ("java.lang",),
    "Math": ("java.lang",),
    "Thread": ("java.lang",),
    "Runtime": ("java.lang",),
    "Class": ("java.lang",),
    "Enum": ("java.lang",),
    "Throwable": ("java.lang",),
    "Exception": ("java.lang",),
    "RuntimeException": ("java.lang",),
    "IllegalArgumentException": ("java.lang",),
    "IllegalStateException": ("java.lang",),
    "SecurityException": ("java.lang",),
    "AutoCloseable": ("java.lang",),
    "Iterable": ("java.lang",),
    # java.io / java.nio / java.util.zip
    "IOException": ("java.io",),
    "FileNotFoundException": ("java.io",),
    "File": ("java.io",),
    "FileInputStream": ("java.io",),
    "FileOutputStream": ("java.io",),
    "FileReader": ("java.io",),
    "FileWriter": ("java.io",),
    "InputStream": ("java.io",),
    "OutputStream": ("java.io",),
    "Reader": ("java.io",),
    "Writer": ("java.io",),
    "InputStreamReader": ("java.io",),
    "OutputStreamWriter": ("java.io",),
    "BufferedReader": ("java.io",),
    "BufferedWriter": ("java.io",),
    "BufferedInputStream": ("java.io",),
    "BufferedOutputStream": ("java.io",),
    "ByteArrayInputStream": ("java.io",),
    "ByteArrayOutputStream": ("java.io",),
    "ObjectInputStream": ("java.io",),
    "ObjectOutputStream": ("java.io",),
    "DataInputStream": ("java.io",),
    "DataOutputStream": ("java.io",),
    "PrintWriter": ("java.io",),
    "PrintStream": ("java.io",),
    "RandomAccessFile": ("java.io",),
    "ZipInputStream": ("java.util.zip",),
    "ZipOutputStream": ("java.util.zip",),
    "ZipEntry": ("java.util.zip",),
    "ZipFile": ("java.util.zip",),
    "GZIPInputStream": ("java.util.zip",),
    "GZIPOutputStream": ("java.util.zip",),
    "Files": ("java.nio.file",),
    "Paths": ("java.nio.file",),
    "Path": ("java.nio.file",),
    "StandardOpenOption": ("java.nio.file",),
    "LinkOption": ("java.nio.file",),
    "Charset": ("java.nio.charset",),
    "StandardCharsets": ("java.nio.charset",),
    # java.util / java.text / regex / stream / net / sql / security / swing / awt
    "UUID": ("java.util",),
    "Objects": ("java.util",),
    "Arrays": ("java.util",),
    "Collections": ("java.util",),
    "Collection": ("java.util",),
    "List": ("java.util",),
    "ArrayList": ("java.util",),
    "LinkedList": ("java.util",),
    "Set": ("java.util",),
    "HashSet": ("java.util",),
    "Map": ("java.util",),
    "HashMap": ("java.util",),
    "Optional": ("java.util",),
    "Base64": ("java.util", "org.apache.commons.codec.binary"),
    "Enumeration": ("java.util",),
    "Iterator": ("java.util",),
    "Scanner": ("java.util",),
    "Properties": ("java.util",),
    "Date": ("java.util",),
    "Calendar": ("java.util",),
    "Format": ("java.text",),
    "DateFormat": ("java.text",),
    "SimpleDateFormat": ("java.text",),
    "Pattern": ("java.util.regex",),
    "Matcher": ("java.util.regex",),
    "Stream": ("java.util.stream",),
    "Collectors": ("java.util.stream",),
    "URLEncoder": ("java.net",),
    "URLDecoder": ("java.net",),
    "URI": ("java.net",),
    "URL": ("java.net",),
    "DriverManager": ("java.sql",),
    "DataSource": ("javax.sql",),
    "PreparedStatement": ("java.sql",),
    "Statement": ("java.sql",),
    "Connection": ("java.sql",),
    "CallableStatement": ("java.sql",),
    "ResultSet": ("java.sql",),
    "SQLException": ("java.sql",),
    "MessageDigest": ("java.security",),
    "SecureRandom": ("java.security",),
    "Cipher": ("javax.crypto",),
    "JTextField": ("javax.swing",),
    "JPasswordField": ("javax.swing",),
    "JTextArea": ("javax.swing",),
    "JTextPane": ("javax.swing",),
    "JEditorPane": ("javax.swing",),
    "JTextComponent": ("javax.swing.text",),
    "JLabel": ("javax.swing",),
    "JButton": ("javax.swing",),
    "JFrame": ("javax.swing",),
    "JPanel": ("javax.swing",),
    "TextField": ("java.awt",),
    "TextArea": ("java.awt",),
    "TextComponent": ("java.awt",),
    "ActionEvent": ("java.awt.event",),
    # Servlet / JPA / Hibernate / Spring / Apache Commons / OWASP / Logging
    "HttpServlet": ("javax.servlet.http", "jakarta.servlet.http"),
    "GenericServlet": ("javax.servlet", "jakarta.servlet"),
    "ServletContext": ("javax.servlet", "jakarta.servlet"),
    "ServletRequest": ("javax.servlet", "jakarta.servlet"),
    "ServletResponse": ("javax.servlet", "jakarta.servlet"),
    "ServletInputStream": ("javax.servlet", "jakarta.servlet"),
    "ServletOutputStream": ("javax.servlet", "jakarta.servlet"),
    "ServletException": ("javax.servlet", "jakarta.servlet"),
    "HttpServletRequest": ("javax.servlet.http", "jakarta.servlet.http"),
    "HttpServletResponse": ("javax.servlet.http", "jakarta.servlet.http"),
    "Cookie": ("javax.servlet.http", "jakarta.servlet.http"),
    "HttpSession": ("javax.servlet.http", "jakarta.servlet.http"),
    "Part": ("javax.servlet.http", "jakarta.servlet.http"),
    "MultipartFile": ("org.springframework.web.multipart",),
    "EntityManager": ("javax.persistence", "jakarta.persistence"),
    "Query": ("javax.persistence", "jakarta.persistence"),
    "TypedQuery": ("javax.persistence", "jakarta.persistence"),
    "Session": ("org.hibernate",),
    "JdbcTemplate": ("org.springframework.jdbc.core",),
    "JdbcOperations": ("org.springframework.jdbc.core",),
    "NamedParameterJdbcTemplate": ("org.springframework.jdbc.core.namedparam",),
    "NamedParameterJdbcOperations": ("org.springframework.jdbc.core.namedparam",),
    "ResponseEntity": ("org.springframework.http",),
    "HttpStatus": ("org.springframework.http",),
    "HttpHeaders": ("org.springframework.http",),
    "HtmlUtils": ("org.springframework.web.util",),
    "UriUtils": ("org.springframework.web.util",),
    "UriComponentsBuilder": ("org.springframework.web.util",),
    "StreamUtils": ("org.springframework.util",),
    "FileCopyUtils": ("org.springframework.util",),
    "CollectionUtils": ("org.springframework.util",),
    "ObjectUtils": ("org.springframework.util",),
    "Assert": ("org.springframework.util",),
    "FilenameUtils": ("org.apache.commons.io",),
    "FileUtils": ("org.apache.commons.io",),
    "IOUtils": ("org.apache.commons.io",),
    "StringUtils": ("org.apache.commons.lang3", "org.apache.commons.lang", "org.springframework.util"),
    "StringEscapeUtils": ("org.apache.commons.text", "org.apache.commons.lang3", "org.apache.commons.lang"),
    "ESAPI": ("org.owasp.esapi",),
    "Logger": ("org.slf4j", "java.util.logging", "org.apache.logging.log4j"),
    "LoggerFactory": ("org.slf4j",),
    "LogManager": ("org.apache.logging.log4j", "java.util.logging"),
}
_STDLIB_KNOWN_CLASSES = frozenset(_STDLIB_SIMPLE_TO_PACKAGES.keys())
_STDLIB_DECLARED_TYPES = _STDLIB_KNOWN_CLASSES

# Strictly per-FQN stdlib supertype graph and method contracts (NO global method-name whitelist!).
_STDLIB_SUPERTYPES: dict[str, tuple[str, ...]] = {
    "java.lang.String": ("java.lang.CharSequence",),
    "java.lang.StringBuilder": ("java.lang.CharSequence",),
    "java.lang.StringBuffer": ("java.lang.CharSequence",),
    "java.lang.Exception": ("java.lang.Throwable",),
    "java.lang.RuntimeException": ("java.lang.Exception",),
    "java.lang.IllegalArgumentException": ("java.lang.RuntimeException",),
    "java.lang.IllegalStateException": ("java.lang.RuntimeException",),
    "java.lang.SecurityException": ("java.lang.RuntimeException",),
    "java.io.IOException": ("java.lang.Exception",),
    "java.io.FileNotFoundException": ("java.io.IOException",),
    "java.sql.SQLException": ("java.lang.Exception",),
    "javax.servlet.ServletException": ("java.lang.Exception",),
    "jakarta.servlet.ServletException": ("java.lang.Exception",),
    "java.io.FileInputStream": ("java.io.InputStream",),
    "java.io.BufferedInputStream": ("java.io.InputStream",),
    "java.io.ByteArrayInputStream": ("java.io.InputStream",),
    "java.io.ObjectInputStream": ("java.io.InputStream",),
    "java.io.DataInputStream": ("java.io.InputStream",),
    "java.util.zip.ZipInputStream": ("java.io.InputStream",),
    "java.util.zip.GZIPInputStream": ("java.io.InputStream",),
    "javax.servlet.ServletInputStream": ("java.io.InputStream",),
    "jakarta.servlet.ServletInputStream": ("java.io.InputStream",),
    "java.io.FileOutputStream": ("java.io.OutputStream",),
    "java.io.BufferedOutputStream": ("java.io.OutputStream",),
    "java.io.ByteArrayOutputStream": ("java.io.OutputStream",),
    "java.io.ObjectOutputStream": ("java.io.OutputStream",),
    "java.io.DataOutputStream": ("java.io.OutputStream",),
    "java.io.PrintStream": ("java.io.OutputStream",),
    "java.util.zip.ZipOutputStream": ("java.io.OutputStream",),
    "java.util.zip.GZIPOutputStream": ("java.io.OutputStream",),
    "javax.servlet.ServletOutputStream": ("java.io.OutputStream",),
    "jakarta.servlet.ServletOutputStream": ("java.io.OutputStream",),
    "java.io.BufferedReader": ("java.io.Reader",),
    "java.io.InputStreamReader": ("java.io.Reader",),
    "java.io.FileReader": ("java.io.InputStreamReader",),
    "java.io.BufferedWriter": ("java.io.Writer",),
    "java.io.OutputStreamWriter": ("java.io.Writer",),
    "java.io.FileWriter": ("java.io.OutputStreamWriter",),
    "java.io.PrintWriter": ("java.io.Writer",),
    "java.util.List": ("java.util.Collection",),
    "java.util.ArrayList": ("java.util.List",),
    "java.util.LinkedList": ("java.util.List",),
    "java.util.Set": ("java.util.Collection",),
    "java.util.HashSet": ("java.util.Set",),
    "java.util.HashMap": ("java.util.Map",),
    "java.text.DateFormat": ("java.text.Format",),
    "java.text.SimpleDateFormat": ("java.text.DateFormat",),
    "java.sql.PreparedStatement": ("java.sql.Statement",),
    "java.sql.CallableStatement": ("java.sql.PreparedStatement",),
    "javax.servlet.http.HttpServlet": ("javax.servlet.GenericServlet",),
    "jakarta.servlet.http.HttpServlet": ("jakarta.servlet.GenericServlet",),
    "javax.servlet.http.HttpServletRequest": ("javax.servlet.ServletRequest",),
    "jakarta.servlet.http.HttpServletRequest": ("jakarta.servlet.ServletRequest",),
    "javax.servlet.http.HttpServletResponse": ("javax.servlet.ServletResponse",),
    "jakarta.servlet.http.HttpServletResponse": ("jakarta.servlet.ServletResponse",),
    "javax.swing.JTextField": ("javax.swing.text.JTextComponent",),
    "javax.swing.JPasswordField": ("javax.swing.JTextField",),
    "javax.swing.JTextArea": ("javax.swing.text.JTextComponent",),
    "javax.swing.JTextPane": ("javax.swing.text.JTextComponent",),
    "javax.swing.JEditorPane": ("javax.swing.text.JTextComponent",),
    "java.awt.TextField": ("java.awt.TextComponent",),
    "java.awt.TextArea": ("java.awt.TextComponent",),
    "javax.persistence.TypedQuery": ("javax.persistence.Query",),
    "jakarta.persistence.TypedQuery": ("jakarta.persistence.Query",),
    "org.springframework.jdbc.core.JdbcTemplate": ("org.springframework.jdbc.core.JdbcOperations",),
    "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate": (
        "org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations",
    ),
}

_STDLIB_FQN_METHODS: dict[str, frozenset[str]] = {
    "java.lang.Object": frozenset({"toString", "equals", "hashCode", "getClass"}),
    "java.lang.CharSequence": frozenset({"length", "charAt", "subSequence", "chars", "codePoints", "isEmpty"}),
    "java.lang.String": frozenset(
        {
            "trim", "strip", "stripLeading", "stripTrailing", "toLowerCase", "toUpperCase",
            "startsWith", "endsWith", "equalsIgnoreCase", "contains", "matches", "indexOf",
            "lastIndexOf", "substring", "replace", "replaceAll", "replaceFirst", "split",
            "concat", "format", "join", "valueOf", "isEmpty", "isBlank", "getBytes",
            "toCharArray", "intern",
        }
    ),
    "java.lang.StringBuilder": frozenset({"append", "insert", "delete", "replace", "reverse", "substring", "indexOf", "lastIndexOf"}),
    "java.lang.StringBuffer": frozenset({"append", "insert", "delete", "replace", "reverse", "substring", "indexOf", "lastIndexOf"}),
    "java.lang.Integer": frozenset({"parseInt", "valueOf", "toString", "intValue", "compare", "compareTo"}),
    "java.lang.Long": frozenset({"parseLong", "valueOf", "toString", "longValue", "compare", "compareTo"}),
    "java.lang.Short": frozenset({"parseShort", "valueOf", "toString", "shortValue", "compare", "compareTo"}),
    "java.lang.Byte": frozenset({"parseByte", "valueOf", "toString", "byteValue", "compare", "compareTo"}),
    "java.lang.Double": frozenset({"parseDouble", "valueOf", "toString", "doubleValue", "compare", "compareTo"}),
    "java.lang.Float": frozenset({"parseFloat", "valueOf", "toString", "floatValue", "compare", "compareTo"}),
    "java.lang.Boolean": frozenset({"parseBoolean", "valueOf", "toString", "booleanValue", "compare", "compareTo"}),
    "java.lang.Character": frozenset({"isDigit", "isLetter", "isLetterOrDigit", "isWhitespace", "toLowerCase", "toUpperCase", "valueOf"}),
    "java.lang.Number": frozenset({"intValue", "longValue", "doubleValue", "floatValue", "shortValue", "byteValue"}),
    "java.lang.System": frozenset({"getenv", "getProperty", "currentTimeMillis", "nanoTime", "arraycopy", "lineSeparator"}),
    "java.lang.Math": frozenset({"min", "max", "abs", "floor", "ceil", "round"}),
    "java.lang.Class": frozenset({"getName", "getSimpleName", "getResource", "getResourceAsStream", "forName"}),
    "java.lang.Enum": frozenset({"name", "ordinal", "valueOf"}),
    "java.lang.Throwable": frozenset({"getMessage", "getLocalizedMessage", "getCause", "printStackTrace"}),
    "java.io.File": frozenset(
        {
            "exists", "isFile", "isDirectory", "canRead", "canWrite", "isAbsolute",
            "getName", "getPath", "getParent", "getParentFile", "getAbsolutePath",
            "getAbsoluteFile", "getCanonicalPath", "getCanonicalFile", "toPath",
            "toURI", "length", "list", "listFiles", "mkdir", "mkdirs",
            "createNewFile", "delete", "renameTo",
        }
    ),
    "java.io.InputStream": frozenset({"read", "readAllBytes", "readNBytes", "skip", "available", "close", "mark", "reset", "transferTo"}),
    "java.io.OutputStream": frozenset({"write", "flush", "close"}),
    "java.io.Reader": frozenset({"read", "ready", "skip", "close"}),
    "java.io.Writer": frozenset({"write", "append", "flush", "close"}),
    "java.io.BufferedReader": frozenset({"readLine", "lines"}),
    "java.io.BufferedWriter": frozenset({"newLine"}),
    "java.io.ByteArrayOutputStream": frozenset({"toByteArray", "toString", "size", "reset"}),
    "java.io.ObjectInputStream": frozenset({"readObject", "readUnshared", "readUTF", "readInt", "readLong", "readBoolean", "defaultReadObject"}),
    "java.io.ObjectOutputStream": frozenset({"writeObject", "writeUnshared", "writeUTF", "defaultWriteObject"}),
    "java.io.DataInputStream": frozenset({"readUTF", "readInt", "readLong", "readFully", "readBoolean"}),
    "java.io.DataOutputStream": frozenset({"writeUTF", "writeInt", "writeLong", "writeBoolean"}),
    "java.io.PrintWriter": frozenset({"print", "println", "printf", "format", "checkError"}),
    "java.io.PrintStream": frozenset({"print", "println", "printf", "format", "checkError"}),
    "java.io.RandomAccessFile": frozenset({"read", "readFully", "readLine", "write", "writeBytes", "seek", "length", "close"}),
    "java.util.zip.ZipInputStream": frozenset({"getNextEntry", "closeEntry"}),
    "java.util.zip.ZipOutputStream": frozenset({"putNextEntry", "closeEntry", "finish"}),
    "java.util.zip.ZipEntry": frozenset({"getName", "isDirectory", "getSize", "getCompressedSize", "getMethod", "getComment"}),
    "java.util.zip.ZipFile": frozenset({"getEntry", "entries", "getInputStream", "getName", "size", "close"}),
    "java.nio.file.Path": frozenset(
        {
            "of", "resolve", "resolveSibling", "relativize", "normalize",
            "toAbsolutePath", "toRealPath", "toFile", "getFileName", "getParent",
            "getRoot", "startsWith", "endsWith", "toUri",
        }
    ),
    "java.nio.file.Paths": frozenset({"get"}),
    "java.nio.file.Files": frozenset(
        {
            "readString", "readAllBytes", "readAllLines", "lines", "newInputStream",
            "newOutputStream", "newBufferedReader", "newBufferedWriter", "write",
            "writeString", "copy", "move", "delete", "deleteIfExists", "createFile",
            "createDirectory", "createDirectories", "createTempDirectory", "createTempFile",
            "list", "walk", "find",
            "exists", "notExists", "isRegularFile", "isDirectory", "isSymbolicLink",
            "isReadable", "size",
        }
    ),
    "java.util.UUID": frozenset({"fromString", "randomUUID"}),
    "java.util.Objects": frozenset({"toString", "requireNonNull", "requireNonNullElse", "equals", "isNull", "nonNull", "hash", "hashCode"}),
    "java.util.Arrays": frozenset({"asList", "stream", "copyOf", "equals", "toString", "sort"}),
    "java.util.Collections": frozenset({"singletonList", "singleton", "singletonMap", "emptyList", "emptySet", "emptyMap", "unmodifiableList", "unmodifiableSet", "unmodifiableMap", "sort"}),
    "java.util.Collection": frozenset({"add", "addAll", "remove", "clear", "contains", "isEmpty", "size", "iterator", "stream", "toArray"}),
    "java.util.List": frozenset({"get", "set", "indexOf", "lastIndexOf", "subList", "of"}),
    "java.util.Set": frozenset({"of"}),
    "java.util.Map": frozenset({"get", "getOrDefault", "put", "putIfAbsent", "remove", "clear", "containsKey", "containsValue", "isEmpty", "size", "keySet", "values", "entrySet", "of"}),
    "java.util.Optional": frozenset({"of", "ofNullable", "empty", "get", "orElse", "orElseGet", "orElseThrow", "isPresent", "isEmpty", "map", "flatMap", "filter"}),
    "java.util.Base64": frozenset({"getDecoder", "getEncoder", "getUrlDecoder", "getUrlEncoder", "getMimeDecoder", "getMimeEncoder"}),
    "java.util.Base64$Decoder": frozenset({"decode"}),
    "java.util.Base64$Encoder": frozenset({"encode", "encodeToString"}),
    "org.apache.commons.codec.binary.Base64": frozenset({"encodeBase64", "decodeBase64", "encodeBase64String", "encodeBase64URLSafe", "encodeBase64URLSafeString", "isBase64"}),
    "java.util.Calendar": frozenset({"getInstance", "getTime", "get", "set", "add", "getTimeInMillis", "setTime", "setTimeInMillis", "getTimeZone"}),
    "java.util.Date": frozenset({"getTime", "before", "after", "compareTo", "toInstant"}),
    "java.text.Format": frozenset({"format", "parseObject"}),
    "java.text.DateFormat": frozenset({"format", "parse", "getInstance", "getDateInstance", "getTimeInstance", "getDateTimeInstance", "setTimeZone", "setLenient"}),
    "java.text.SimpleDateFormat": frozenset({"applyPattern", "toPattern"}),
    "java.util.Iterator": frozenset({"hasNext", "next", "remove"}),
    "java.util.Enumeration": frozenset({"hasMoreElements", "nextElement"}),
    "java.util.Scanner": frozenset({"next", "nextLine", "nextInt", "nextLong", "hasNext", "hasNextLine", "close"}),
    "java.util.Properties": frozenset({"getProperty", "setProperty", "load", "containsKey"}),
    "java.util.regex.Pattern": frozenset({"compile", "matcher", "matches", "quote", "split"}),
    "java.util.regex.Matcher": frozenset({"matches", "find", "lookingAt", "group", "groupCount", "replaceAll", "replaceFirst", "start", "end"}),
    "java.util.stream.Stream": frozenset({"map", "flatMap", "filter", "sorted", "distinct", "limit", "skip", "collect", "toList", "count", "findFirst", "findAny", "anyMatch", "allMatch", "noneMatch", "forEach"}),
    "java.util.stream.Collectors": frozenset({"toList", "toSet", "joining", "toMap"}),
    "java.net.URLEncoder": frozenset({"encode"}),
    "java.net.URLDecoder": frozenset({"decode"}),
    "java.net.URI": frozenset({"create", "normalize", "resolve", "getPath", "getHost", "getScheme", "toURL", "toASCIIString"}),
    "java.net.URL": frozenset({"openStream", "openConnection", "getHost", "getPath", "getProtocol", "getPort", "getQuery", "toURI"}),
    "java.sql.DriverManager": frozenset({"getConnection"}),
    "javax.sql.DataSource": frozenset({"getConnection"}),
    "java.sql.Connection": frozenset({"createStatement", "prepareStatement", "prepareCall", "close", "commit", "rollback", "setAutoCommit", "isClosed", "isValid"}),
    "java.sql.Statement": frozenset({"executeQuery", "executeUpdate", "execute", "executeLargeUpdate", "addBatch", "executeBatch", "close", "getResultSet", "getUpdateCount"}),
    "java.sql.PreparedStatement": frozenset({"setString", "setInt", "setLong", "setShort", "setByte", "setDouble", "setFloat", "setBoolean", "setObject", "setNull", "setTimestamp", "setDate", "setBytes", "clearParameters"}),
    "java.sql.ResultSet": frozenset({"next", "first", "last", "previous", "getString", "getInt", "getLong", "getShort", "getByte", "getDouble", "getFloat", "getBoolean", "getObject", "getBytes", "getDate", "getTimestamp", "wasNull", "close"}),
    "java.sql.SQLException": frozenset({"getSQLState", "getErrorCode", "getNextException"}),
    "java.security.MessageDigest": frozenset({"getInstance", "digest", "update"}),
    "javax.crypto.Cipher": frozenset({"getInstance", "init", "doFinal", "update"}),
    "javax.swing.text.JTextComponent": frozenset({"getText", "setText", "getSelectedText", "getDocument"}),
    "javax.swing.JPasswordField": frozenset({"getPassword"}),
    "javax.swing.JLabel": frozenset({"getText", "setText"}),
    "javax.swing.JFrame": frozenset({"setVisible", "setTitle", "dispose"}),
    "java.awt.TextComponent": frozenset({"getText", "setText", "getSelectedText"}),
    "java.awt.event.ActionEvent": frozenset({"getActionCommand", "getSource", "getID"}),
    "javax.servlet.GenericServlet": frozenset({"getServletContext", "getServletConfig", "getInitParameter", "getServletName", "log"}),
    "jakarta.servlet.GenericServlet": frozenset({"getServletContext", "getServletConfig", "getInitParameter", "getServletName", "log"}),
    "javax.servlet.ServletContext": frozenset({"getMimeType", "getRealPath", "getResource", "getResourceAsStream", "getInitParameter", "getAttribute", "getContextPath", "log"}),
    "jakarta.servlet.ServletContext": frozenset({"getMimeType", "getRealPath", "getResource", "getResourceAsStream", "getInitParameter", "getAttribute", "getContextPath", "log"}),
    "javax.servlet.ServletRequest": frozenset({"getParameter", "getParameterValues", "getParameterMap", "getParameterNames", "getAttribute", "getInputStream", "getReader", "getContentType", "getCharacterEncoding", "getRemoteAddr", "getServerName", "getServletContext"}),
    "jakarta.servlet.ServletRequest": frozenset({"getParameter", "getParameterValues", "getParameterMap", "getParameterNames", "getAttribute", "getInputStream", "getReader", "getContentType", "getCharacterEncoding", "getRemoteAddr", "getServerName", "getServletContext"}),
    "javax.servlet.http.HttpServletRequest": frozenset({"getHeader", "getHeaders", "getHeaderNames", "getCookies", "getQueryString", "getPathInfo", "getRequestURI", "getRequestURL", "getServletPath", "getContextPath", "getMethod", "getSession", "getUserPrincipal", "getRemoteUser", "getPart", "getParts", "getAuthType"}),
    "jakarta.servlet.http.HttpServletRequest": frozenset({"getHeader", "getHeaders", "getHeaderNames", "getCookies", "getQueryString", "getPathInfo", "getRequestURI", "getRequestURL", "getServletPath", "getContextPath", "getMethod", "getSession", "getUserPrincipal", "getRemoteUser", "getPart", "getParts", "getAuthType"}),
    "javax.servlet.ServletResponse": frozenset({"getOutputStream", "getWriter", "setContentType", "setCharacterEncoding", "setContentLength", "flushBuffer", "isCommitted"}),
    "jakarta.servlet.ServletResponse": frozenset({"getOutputStream", "getWriter", "setContentType", "setCharacterEncoding", "setContentLength", "flushBuffer", "isCommitted"}),
    "javax.servlet.http.HttpServletResponse": frozenset({"setHeader", "addHeader", "setStatus", "sendError", "sendRedirect", "addCookie", "encodeURL", "encodeRedirectURL"}),
    "jakarta.servlet.http.HttpServletResponse": frozenset({"setHeader", "addHeader", "setStatus", "sendError", "sendRedirect", "addCookie", "encodeURL", "encodeRedirectURL"}),
    "javax.servlet.http.Cookie": frozenset({"getName", "getValue", "getPath", "getDomain", "getMaxAge", "getSecure", "isHttpOnly"}),
    "jakarta.servlet.http.Cookie": frozenset({"getName", "getValue", "getPath", "getDomain", "getMaxAge", "getSecure", "isHttpOnly"}),
    "javax.servlet.http.HttpSession": frozenset({"getAttribute", "setAttribute", "removeAttribute", "getId", "invalidate"}),
    "jakarta.servlet.http.HttpSession": frozenset({"getAttribute", "setAttribute", "removeAttribute", "getId", "invalidate"}),
    "javax.servlet.http.Part": frozenset({"getSubmittedFileName", "getName", "getInputStream", "getSize", "getContentType", "write"}),
    "jakarta.servlet.http.Part": frozenset({"getSubmittedFileName", "getName", "getInputStream", "getSize", "getContentType", "write"}),
    "org.springframework.web.multipart.MultipartFile": frozenset({"getOriginalFilename", "getName", "getInputStream", "getBytes", "getSize", "getContentType", "isEmpty", "transferTo"}),
    "javax.persistence.EntityManager": frozenset({"createQuery", "createNativeQuery", "find", "persist", "merge", "remove"}),
    "jakarta.persistence.EntityManager": frozenset({"createQuery", "createNativeQuery", "find", "persist", "merge", "remove"}),
    "javax.persistence.Query": frozenset({"setParameter", "getResultList", "getSingleResult", "executeUpdate"}),
    "jakarta.persistence.Query": frozenset({"setParameter", "getResultList", "getSingleResult", "executeUpdate"}),
    "org.hibernate.Session": frozenset({"createQuery", "createNativeQuery", "createSQLQuery", "get", "load", "save", "update", "delete"}),
    "org.springframework.jdbc.core.JdbcOperations": frozenset({"execute", "query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet", "update", "batchUpdate"}),
    "org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations": frozenset({"execute", "query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet", "update", "batchUpdate"}),
    "org.springframework.http.ResponseEntity": frozenset({"ok", "status", "badRequest", "notFound", "body", "build"}),
    "org.springframework.web.util.HtmlUtils": frozenset({"htmlEscape", "htmlUnescape"}),
    "org.springframework.web.util.UriUtils": frozenset({"encode", "encodePath", "encodePathSegment", "encodeQueryParam", "decode"}),
    "org.springframework.web.util.UriComponentsBuilder": frozenset({"fromHttpUrl", "fromUriString", "fromPath", "path", "pathSegment", "queryParam", "build", "encode", "toUriString", "toUri"}),
    "org.springframework.util.StreamUtils": frozenset({"copy", "copyToByteArray", "copyToString"}),
    "org.springframework.util.FileCopyUtils": frozenset({"copy", "copyToByteArray", "copyToString"}),
    "org.springframework.util.CollectionUtils": frozenset({"isEmpty"}),
    "org.springframework.util.ObjectUtils": frozenset({"isEmpty", "nullSafeEquals"}),
    "org.springframework.util.Assert": frozenset({"notNull", "hasText", "isTrue", "state"}),
    "org.springframework.util.StringUtils": frozenset({"hasText", "hasLength", "isEmpty", "cleanPath", "replace", "split", "trimWhitespace"}),
    "org.apache.commons.io.FilenameUtils": frozenset({"getName", "getBaseName", "getExtension", "normalize", "normalizeNoEndSeparator", "concat"}),
    "org.apache.commons.io.FileUtils": frozenset({"readFileToString", "readFileToByteArray", "readLines", "writeStringToFile", "copyFile", "deleteQuietly", "forceDelete", "openInputStream", "openOutputStream"}),
    "org.apache.commons.io.IOUtils": frozenset({"toString", "toByteArray", "copy", "readLines", "closeQuietly"}),
    "org.apache.commons.lang3.StringUtils": frozenset({"isEmpty", "isBlank", "isNotBlank", "isNotEmpty", "trim", "strip", "replace", "split", "join", "substring", "substringAfter", "substringBefore", "startsWith", "endsWith", "contains", "equals"}),
    "org.apache.commons.lang.StringUtils": frozenset({"isEmpty", "isBlank", "isNotBlank", "isNotEmpty", "trim", "strip", "replace", "split", "join", "substring", "substringAfter", "substringBefore", "startsWith", "endsWith", "contains", "equals"}),
    "org.apache.commons.text.StringEscapeUtils": frozenset({"escapeHtml4", "escapeXml11", "escapeEcmaScript", "escapeJava", "unescapeHtml4"}),
    "org.apache.commons.lang3.StringEscapeUtils": frozenset({"escapeHtml4", "escapeXml", "escapeEcmaScript", "escapeJava", "unescapeHtml4"}),
    "org.apache.commons.lang.StringEscapeUtils": frozenset({"escapeHtml", "escapeXml", "escapeSql", "escapeJava", "unescapeHtml"}),
    "org.owasp.esapi.ESAPI": frozenset({"encoder", "validator"}),
    "org.slf4j.Logger": frozenset({"info", "debug", "warn", "error", "trace", "isDebugEnabled", "isInfoEnabled"}),
    "java.util.logging.Logger": frozenset({"info", "warning", "severe", "fine", "finer", "finest", "log"}),
    "org.apache.logging.log4j.Logger": frozenset({"info", "debug", "warn", "error", "trace", "fatal", "log"}),
    "org.slf4j.LoggerFactory": frozenset({"getLogger"}),
    "org.apache.logging.log4j.LogManager": frozenset({"getLogger"}),
    "java.util.logging.LogManager": frozenset({"getLogManager"}),
}

_STDLIB_METHOD_RETURN_FQN: dict[tuple[str, str], str] = {
    ("java.lang.Object", "toString"): "java.lang.String",
    ("java.lang.String", "trim"): "java.lang.String",
    ("java.lang.String", "strip"): "java.lang.String",
    ("java.lang.String", "stripLeading"): "java.lang.String",
    ("java.lang.String", "stripTrailing"): "java.lang.String",
    ("java.lang.String", "toLowerCase"): "java.lang.String",
    ("java.lang.String", "toUpperCase"): "java.lang.String",
    ("java.lang.String", "replace"): "java.lang.String",
    ("java.lang.String", "replaceAll"): "java.lang.String",
    ("java.lang.String", "replaceFirst"): "java.lang.String",
    ("java.lang.String", "substring"): "java.lang.String",
    ("java.lang.String", "concat"): "java.lang.String",
    ("java.lang.String", "valueOf"): "java.lang.String",
    ("java.lang.String", "format"): "java.lang.String",
    ("java.lang.String", "join"): "java.lang.String",
    ("java.lang.StringBuilder", "append"): "java.lang.StringBuilder",
    ("java.lang.StringBuffer", "append"): "java.lang.StringBuffer",
    ("java.lang.System", "getenv"): "java.lang.String",
    ("java.lang.System", "getProperty"): "java.lang.String",
    ("java.io.File", "getParentFile"): "java.io.File",
    ("java.io.File", "getCanonicalFile"): "java.io.File",
    ("java.io.File", "getAbsoluteFile"): "java.io.File",
    ("java.io.File", "toPath"): "java.nio.file.Path",
    ("java.io.File", "getName"): "java.lang.String",
    ("java.io.File", "getPath"): "java.lang.String",
    ("java.io.File", "getParent"): "java.lang.String",
    ("java.io.File", "getCanonicalPath"): "java.lang.String",
    ("java.io.File", "getAbsolutePath"): "java.lang.String",
    ("java.io.BufferedReader", "readLine"): "java.lang.String",
    ("java.nio.file.Paths", "get"): "java.nio.file.Path",
    ("java.nio.file.Path", "of"): "java.nio.file.Path",
    ("java.nio.file.Path", "resolve"): "java.nio.file.Path",
    ("java.nio.file.Path", "resolveSibling"): "java.nio.file.Path",
    ("java.nio.file.Path", "relativize"): "java.nio.file.Path",
    ("java.nio.file.Path", "normalize"): "java.nio.file.Path",
    ("java.nio.file.Path", "toAbsolutePath"): "java.nio.file.Path",
    ("java.nio.file.Path", "toRealPath"): "java.nio.file.Path",
    ("java.nio.file.Path", "getFileName"): "java.nio.file.Path",
    ("java.nio.file.Path", "getParent"): "java.nio.file.Path",
    ("java.nio.file.Path", "toFile"): "java.io.File",
    ("java.nio.file.Files", "createTempDirectory"): "java.nio.file.Path",
    ("java.nio.file.Files", "createTempFile"): "java.nio.file.Path",
    ("java.util.Base64", "getDecoder"): "java.util.Base64$Decoder",
    ("java.util.Base64", "getUrlDecoder"): "java.util.Base64$Decoder",
    ("java.util.Base64", "getMimeDecoder"): "java.util.Base64$Decoder",
    ("java.util.Base64", "getEncoder"): "java.util.Base64$Encoder",
    ("java.util.Base64", "getUrlEncoder"): "java.util.Base64$Encoder",
    ("java.util.Base64", "getMimeEncoder"): "java.util.Base64$Encoder",
    ("java.util.Base64$Encoder", "encodeToString"): "java.lang.String",
    ("org.apache.commons.codec.binary.Base64", "encodeBase64String"): "java.lang.String",
    ("org.apache.commons.codec.binary.Base64", "encodeBase64URLSafeString"): "java.lang.String",
    ("java.util.Calendar", "getInstance"): "java.util.Calendar",
    ("java.util.Calendar", "getTime"): "java.util.Date",
    ("java.text.Format", "format"): "java.lang.String",
    ("java.text.DateFormat", "format"): "java.lang.String",
    ("java.text.DateFormat", "parse"): "java.util.Date",
    ("java.util.zip.ZipInputStream", "getNextEntry"): "java.util.zip.ZipEntry",
    ("java.util.zip.ZipEntry", "getName"): "java.lang.String",
    ("java.util.Optional", "of"): "java.util.Optional",
    ("java.util.Optional", "ofNullable"): "java.util.Optional",
    ("java.util.Optional", "map"): "java.util.Optional",
    ("java.util.Optional", "filter"): "java.util.Optional",
    ("java.util.Collection", "stream"): "java.util.stream.Stream",
    ("java.util.stream.Stream", "map"): "java.util.stream.Stream",
    ("java.util.stream.Stream", "filter"): "java.util.stream.Stream",
    ("java.util.stream.Stream", "sorted"): "java.util.stream.Stream",
    ("java.util.stream.Stream", "distinct"): "java.util.stream.Stream",
    ("java.util.regex.Pattern", "compile"): "java.util.regex.Pattern",
    ("java.util.regex.Pattern", "matcher"): "java.util.regex.Matcher",
    ("java.util.regex.Matcher", "group"): "java.lang.String",
    ("java.net.URLEncoder", "encode"): "java.lang.String",
    ("java.net.URLDecoder", "decode"): "java.lang.String",
    ("java.net.URL", "openStream"): "java.io.InputStream",
    ("java.net.URI", "create"): "java.net.URI",
    ("java.net.URI", "normalize"): "java.net.URI",
    ("java.net.URI", "resolve"): "java.net.URI",
    ("java.sql.DriverManager", "getConnection"): "java.sql.Connection",
    ("javax.sql.DataSource", "getConnection"): "java.sql.Connection",
    ("java.sql.Connection", "createStatement"): "java.sql.Statement",
    ("java.sql.Connection", "prepareStatement"): "java.sql.PreparedStatement",
    ("java.sql.Connection", "prepareCall"): "java.sql.CallableStatement",
    ("java.sql.Statement", "executeQuery"): "java.sql.ResultSet",
    ("java.sql.PreparedStatement", "executeQuery"): "java.sql.ResultSet",
    ("java.sql.ResultSet", "getString"): "java.lang.String",
    ("javax.swing.text.JTextComponent", "getText"): "java.lang.String",
    ("java.awt.TextComponent", "getText"): "java.lang.String",
    ("javax.swing.JLabel", "getText"): "java.lang.String",
    ("javax.servlet.GenericServlet", "getServletContext"): "javax.servlet.ServletContext",
    ("jakarta.servlet.GenericServlet", "getServletContext"): "jakarta.servlet.ServletContext",
    ("javax.servlet.ServletRequest", "getServletContext"): "javax.servlet.ServletContext",
    ("jakarta.servlet.ServletRequest", "getServletContext"): "jakarta.servlet.ServletContext",
    ("javax.servlet.ServletRequest", "getParameter"): "java.lang.String",
    ("jakarta.servlet.ServletRequest", "getParameter"): "java.lang.String",
    ("javax.servlet.ServletRequest", "getInputStream"): "javax.servlet.ServletInputStream",
    ("jakarta.servlet.ServletRequest", "getInputStream"): "jakarta.servlet.ServletInputStream",
    ("javax.servlet.ServletRequest", "getReader"): "java.io.BufferedReader",
    ("jakarta.servlet.ServletRequest", "getReader"): "java.io.BufferedReader",
    ("javax.servlet.http.HttpServletRequest", "getHeader"): "java.lang.String",
    ("jakarta.servlet.http.HttpServletRequest", "getHeader"): "java.lang.String",
    ("javax.servlet.http.HttpServletRequest", "getQueryString"): "java.lang.String",
    ("jakarta.servlet.http.HttpServletRequest", "getQueryString"): "java.lang.String",
    ("javax.servlet.http.HttpServletRequest", "getPathInfo"): "java.lang.String",
    ("jakarta.servlet.http.HttpServletRequest", "getPathInfo"): "java.lang.String",
    ("javax.servlet.http.HttpServletRequest", "getRequestURI"): "java.lang.String",
    ("jakarta.servlet.http.HttpServletRequest", "getRequestURI"): "java.lang.String",
    ("javax.servlet.http.HttpServletRequest", "getContextPath"): "java.lang.String",
    ("jakarta.servlet.http.HttpServletRequest", "getContextPath"): "java.lang.String",
    ("javax.servlet.http.HttpServletRequest", "getServletPath"): "java.lang.String",
    ("jakarta.servlet.http.HttpServletRequest", "getServletPath"): "java.lang.String",
    ("javax.servlet.http.HttpServletRequest", "getMethod"): "java.lang.String",
    ("jakarta.servlet.http.HttpServletRequest", "getMethod"): "java.lang.String",
    ("javax.servlet.http.HttpServletRequest", "getRemoteUser"): "java.lang.String",
    ("jakarta.servlet.http.HttpServletRequest", "getRemoteUser"): "java.lang.String",
    ("javax.servlet.http.HttpServletRequest", "getSession"): "javax.servlet.http.HttpSession",
    ("jakarta.servlet.http.HttpServletRequest", "getSession"): "jakarta.servlet.http.HttpSession",
    ("javax.servlet.http.Cookie", "getName"): "java.lang.String",
    ("jakarta.servlet.http.Cookie", "getName"): "java.lang.String",
    ("javax.servlet.http.Cookie", "getValue"): "java.lang.String",
    ("jakarta.servlet.http.Cookie", "getValue"): "java.lang.String",
    ("javax.servlet.http.Cookie", "getPath"): "java.lang.String",
    ("jakarta.servlet.http.Cookie", "getPath"): "java.lang.String",
    ("javax.servlet.http.Cookie", "getDomain"): "java.lang.String",
    ("jakarta.servlet.http.Cookie", "getDomain"): "java.lang.String",
    ("org.springframework.util.FileCopyUtils", "copyToString"): "java.lang.String",
    ("javax.servlet.ServletResponse", "getOutputStream"): "javax.servlet.ServletOutputStream",
    ("jakarta.servlet.ServletResponse", "getOutputStream"): "jakarta.servlet.ServletOutputStream",
    ("javax.servlet.ServletResponse", "getWriter"): "java.io.PrintWriter",
    ("jakarta.servlet.ServletResponse", "getWriter"): "java.io.PrintWriter",
    ("javax.servlet.ServletContext", "getMimeType"): "java.lang.String",
    ("jakarta.servlet.ServletContext", "getMimeType"): "java.lang.String",
    ("javax.servlet.ServletContext", "getRealPath"): "java.lang.String",
    ("jakarta.servlet.ServletContext", "getRealPath"): "java.lang.String",
    ("javax.servlet.ServletContext", "getResourceAsStream"): "java.io.InputStream",
    ("jakarta.servlet.ServletContext", "getResourceAsStream"): "java.io.InputStream",
    ("javax.persistence.EntityManager", "createQuery"): "javax.persistence.Query",
    ("javax.persistence.EntityManager", "createNativeQuery"): "javax.persistence.Query",
    ("jakarta.persistence.EntityManager", "createQuery"): "jakarta.persistence.Query",
    ("jakarta.persistence.EntityManager", "createNativeQuery"): "jakarta.persistence.Query",
    ("javax.persistence.Query", "setParameter"): "javax.persistence.Query",
    ("jakarta.persistence.Query", "setParameter"): "jakarta.persistence.Query",
    ("org.apache.commons.io.FilenameUtils", "getName"): "java.lang.String",
    ("org.springframework.web.util.UriComponentsBuilder", "fromHttpUrl"): "org.springframework.web.util.UriComponentsBuilder",
    ("org.springframework.web.util.UriComponentsBuilder", "fromUriString"): "org.springframework.web.util.UriComponentsBuilder",
    ("org.springframework.web.util.UriComponentsBuilder", "path"): "org.springframework.web.util.UriComponentsBuilder",
    ("org.springframework.web.util.UriComponentsBuilder", "queryParam"): "org.springframework.web.util.UriComponentsBuilder",
    ("org.springframework.web.util.UriComponentsBuilder", "build"): "org.springframework.web.util.UriComponentsBuilder",
    ("org.springframework.web.util.UriComponentsBuilder", "encode"): "org.springframework.web.util.UriComponentsBuilder",
    ("org.springframework.http.ResponseEntity", "ok"): "org.springframework.http.ResponseEntity",
    ("org.springframework.http.ResponseEntity", "status"): "org.springframework.http.ResponseEntity",
}

_STDLIB_METHODS_CACHE: dict[str, frozenset[str]] = {}


def _stdlib_ancestors(fqn: str) -> list[str]:
    """Return `[fqn, *supertypes..., 'java.lang.Object']` in BFS order."""
    seen: list[str] = []
    queue: list[str] = [fqn]
    while queue:
        cur = queue.pop(0)
        if cur in seen:
            continue
        seen.append(cur)
        for parent in _STDLIB_SUPERTYPES.get(cur, ()):
            if parent not in seen:
                queue.append(parent)
    if "java.lang.Object" not in seen:
        seen.append("java.lang.Object")
    return seen


def _stdlib_methods_for_fqn(fqn: str) -> frozenset[str]:
    """Return exact set of methods supported by verified stdlib FQN (including stdlib supertypes)."""
    cached = _STDLIB_METHODS_CACHE.get(fqn)
    if cached is not None:
        return cached
    acc: set[str] = set()
    for anc in _stdlib_ancestors(fqn):
        acc.update(_STDLIB_FQN_METHODS.get(anc, ()))
    res = frozenset(acc)
    _STDLIB_METHODS_CACHE[fqn] = res
    return res


def _stdlib_return_fqn(fqn: str, method: str) -> str | None:
    """Return proven stdlib return FQN for `(fqn, method)` along the stdlib supertype chain, else `None`."""
    for anc in _stdlib_ancestors(fqn):
        ret = _stdlib_return_fqn_direct(anc, method)
        if ret is not None:
            return ret
    return None


def _stdlib_return_fqn_direct(anc: str, method: str) -> str | None:
    return _STDLIB_METHOD_RETURN_FQN.get((anc, method))


_CALL_SITE_RE = re.compile(
    r"(?:([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*)\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_ASSIGN_OR_COND_RE = re.compile(r"(?:^|[^=!<>])=[^=]|\b(?:return|if|else\s+if|while|switch|assert)\b|\?")
_DECL_TYPE_VAR_RE = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|transient|volatile)\s+)*"
    r"([A-Za-z_][A-Za-z0-9_.]*(?:\s*<[^;={}()]*>)?(?:\s*\[\s*\])*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*(.+?))?;\s*$"
)
_PENDING_DECL_START_RE = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|transient|volatile)\s+)*"
    r"([A-Za-z_][A-Za-z0-9_.]*(?:\s*<[^;={}()]*>)?(?:\s*\[\s*\])*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$"
)
_NEW_CTOR_RE = re.compile(r"^new\s+([A-Za-z_][A-Za-z0-9_.]*)(?:\s*<[^>{};]*>)?\s*\(")


@dataclass(frozen=True)
class _JavaTypeRef:
    """Package-preserving Java type identity (never drops package qualifiers)."""

    raw_type: str
    qualified_name: str
    package_name: str | None
    simple_name: str
    is_qualified: bool
    is_nested_or_ambiguous: bool = False
    is_var: bool = False


def _parse_java_type_ref(raw_type: str | None) -> _JavaTypeRef | None:
    """Parse a Java type or constructor name while preserving package qualifiers end-to-end."""
    if not isinstance(raw_type, str):
        return None
    cleaned = re.sub(r"<.*>", "", raw_type).replace("[]", "").strip()
    cleaned = re.sub(r"\s*\.\s*", ".", cleaned)
    if not cleaned:
        return None
    if cleaned == "var":
        return _JavaTypeRef(
            raw_type=raw_type.strip(),
            qualified_name="var",
            package_name=None,
            simple_name="var",
            is_qualified=False,
            is_nested_or_ambiguous=True,
            is_var=True,
        )
    if cleaned in CONTROL_KEYWORDS or cleaned in _MODIFIERS or cleaned == "void":
        return None
    segs = [s.strip() for s in cleaned.split(".")]
    if any(not s or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s) for s in segs):
        return None
    simple = segs[-1]
    if simple in CONTROL_KEYWORDS or simple in _MODIFIERS or simple == "void":
        return None
    if len(segs) == 1:
        return _JavaTypeRef(
            raw_type=raw_type.strip(),
            qualified_name=simple,
            package_name=None,
            simple_name=simple,
            is_qualified=False,
            is_nested_or_ambiguous=False,
            is_var=False,
        )
    pkg_segs = segs[:-1]
    # Standard Java package segments are lowercase; uppercase intermediate segments indicate nested types (ambiguous).
    valid_pkg = bool(simple[0].isupper()) and all(s and s[0].islower() for s in pkg_segs)
    return _JavaTypeRef(
        raw_type=raw_type.strip(),
        qualified_name=".".join(segs),
        package_name=".".join(pkg_segs) if valid_pkg else None,
        simple_name=simple,
        is_qualified=True,
        is_nested_or_ambiguous=not valid_pkg,
        is_var=False,
    )


def _simple_java_type(raw_type: str | None) -> str | None:
    """Legacy simple-name helper kept for compatibility; call resolution NEVER uses this to drop packages."""
    ref = _parse_java_type_ref(raw_type)
    if ref is None or ref.is_var:
        return None
    return ref.simple_name


def _extract_param_types_and_count(params: list[str] | None) -> tuple[dict[str, _JavaTypeRef | None], int, bool]:
    """Return `(var_to_type_ref, param_count, has_varargs)` preserving full package qualifiers."""
    if not params:
        return {}, 0, False
    var_types: dict[str, _JavaTypeRef | None] = {}
    has_varargs = False
    for idx, p in enumerate(params):
        if not isinstance(p, str) or not p.strip():
            continue
        stripped = _strip_param_annotations_preserve_len(p).strip()
        is_vararg = "..." in stripped
        if is_vararg and idx == len(params) - 1:
            has_varargs = True
        norm = stripped.replace("...", " ").replace("final ", " ").strip()
        toks = norm.split()
        if len(toks) >= 2:
            vname = re.sub(r"\s*\[\s*\]\s*", "", toks[-1]).strip()
            vtype = _parse_java_type_ref(" ".join(toks[:-1]))
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", vname):
                var_types[vname] = vtype
    return var_types, len(params), has_varargs


def _extract_call_arg_count_at_line(
    lines_by_no: dict[int, str],
    line_no: int | None,
    qualifier: str | None,
    method_name: str,
    *,
    is_new_ctor_chain: bool = False,
) -> int | None:
    """Count arguments at a call site starting on `line_no` using balanced parenthesis scanning."""
    if type(line_no) is not int or line_no not in lines_by_no:
        return None
    window_lns = [ln for ln in range(line_no, line_no + 6) if ln in lines_by_no]
    if not window_lns:
        return None
    window_txt = "\n".join(lines_by_no[ln] for ln in window_lns)
    if is_new_ctor_chain and qualifier:
        qual_parts = [re.escape(part) for part in qualifier.split(".")]
        qual_pat = r"\s*\.\s*".join(qual_parts)
        m_new = re.search(rf"\bnew\s+{qual_pat}(?:\s*<[^>{{}};]*>)?\s*\(", window_txt)
        if not m_new:
            return None
        ctor_close = _find_matching_paren(window_txt, m_new.end() - 1)
        if ctor_close is None:
            return None
        after = window_txt[ctor_close + 1 :]
        m_after = re.match(rf"^\s*\.\s*{re.escape(method_name)}\s*\(", after)
        if not m_after:
            return None
        open_idx = ctor_close + 1 + m_after.end() - 1
    else:
        if qualifier:
            qual_parts = [re.escape(part) for part in qualifier.split(".")]
            qual_pat = r"\s*\.\s*".join(qual_parts)
            pat = re.compile(rf"(?<![.\w]){qual_pat}\s*\.\s*{re.escape(method_name)}\s*\(")
        else:
            pat = re.compile(rf"(?<![.\w]){re.escape(method_name)}\s*\(")
        m = pat.search(window_txt)
        if not m:
            return None
        open_idx = m.end() - 1
    close_idx = _find_matching_paren(window_txt, open_idx)
    if close_idx is None:
        return None
    inner = window_txt[open_idx + 1 : close_idx].strip()
    if not inner:
        return 0
    return len(_split_top_level_commas(inner))


def _resolve_canonical_fqn_for_type_ref(
    tref: _JavaTypeRef | None,
    caller_pkg: str | None,
    caller_imports: list[str],
    *,
    caller_unit: dict[str, Any] | None = None,
) -> tuple[str | None, str | None] | None:
    """Resolve a `_JavaTypeRef` to `(package_name, simple_name)` without ever stripping explicit packages.

    Returns `None` when ambiguous (e.g., `var`, nested class, static/nested import shadowing,
    conflicting imports, or wildcard ambiguity).
    """
    if tref is None or tref.is_var or tref.is_nested_or_ambiguous:
        return None
    if tref.is_qualified:
        if not tref.package_name:
            return None
        return (tref.package_name, tref.simple_name)

    simple_cls = tref.simple_name
    classified = _classify_java_imports(caller_unit, caller_imports)
    # Single-static-import (`import static p.Outer.Cls;`) or single nested-type import (`import p.Outer.Cls;`)
    # takes Precedence 2 over same-package and binds to a nested type -> NEVER conflate with top-level same-package class!
    if any("." in imp and imp.rsplit(".", 1)[1] == simple_cls for imp in classified["single_static_imports"]):
        return None
    explicit_single = [
        imp
        for imp in classified["single_type_imports"]
        if "." in imp and imp.rsplit(".", 1)[1] == simple_cls
    ]
    if len(explicit_single) > 1:
        return None
    if len(explicit_single) == 1:
        pkg_part = explicit_single[0].rsplit(".", 1)[0]
        if not all(s and s[0].islower() for s in pkg_part.split(".")):
            # Nested type single-type-import (`import p.Outer.Cls;`) -> cannot reduce to top-level `(pkg, simple)`
            return None
        return (pkg_part, simple_cls)

    has_wildcard = bool(classified["wildcard_type_imports"] or classified["wildcard_static_imports"])
    if caller_pkg:
        return (caller_pkg, simple_cls)
    if not has_wildcard:
        return (None, simple_cls)
    return None


def _classify_java_imports(
    caller_unit: dict[str, Any] | None,
    fallback_imports: list[str] | None = None,
) -> dict[str, list[str]]:
    """Classify imports into single-type, wildcard-type, single-static, and wildcard-static per JLS §7.5.

    CRITICAL: Preserves BOTH `import static pkg.Outer.Nested;` AND `import pkg.Outer.Nested;` as well as
    `import static pkg.Outer.*;` so nested types introduced via single-static or nested imports NEVER
    silently fall through to `java.lang.*` or same-package classes!
    """
    single_type: list[str] = []
    wild_type: list[str] = []
    single_static: list[str] = []
    wild_static: list[str] = []

    has_split = (
        isinstance(caller_unit, dict)
        and isinstance(caller_unit.get("type_imports"), list)
        and isinstance(caller_unit.get("static_imports"), list)
    )
    if has_split:
        assert caller_unit is not None
        for imp in caller_unit["type_imports"]:
            if not isinstance(imp, str) or "." not in imp:
                continue
            if imp.endswith(".*"):
                pkg_part = imp[:-2]
                segs = pkg_part.split(".")
                if segs and all(s and s[0].islower() for s in segs):
                    wild_type.append(imp)
                else:
                    # `import pkg.Outer.*;` imports nested types of Outer on demand
                    wild_static.append(imp)
            else:
                single_type.append(imp)
        for imp in caller_unit["static_imports"]:
            if not isinstance(imp, str) or "." not in imp:
                continue
            if imp.endswith(".*"):
                wild_static.append(imp)
            else:
                single_static.append(imp)
        return {
            "single_type_imports": single_type,
            "wildcard_type_imports": wild_type,
            "single_static_imports": single_static,
            "wildcard_static_imports": wild_static,
        }

    # Legacy fallback when only flat `imports` list is provided (no `static` keyword flag available)
    if isinstance(caller_unit, dict) and isinstance(caller_unit.get("imports"), list):
        raw_imps = caller_unit["imports"]
    elif isinstance(caller_unit, dict) and isinstance(caller_unit.get("type_imports"), list):
        raw_imps = caller_unit["type_imports"]
    else:
        raw_imps = list(fallback_imports or [])

    for imp in raw_imps:
        if not isinstance(imp, str) or "." not in imp:
            continue
        if imp.endswith(".*"):
            pkg_part = imp[:-2]
            segs = pkg_part.split(".")
            if segs and all(s and s[0].islower() for s in segs):
                wild_type.append(imp)
            else:
                wild_static.append(imp)
        else:
            pkg_part, tail = imp.rsplit(".", 1)
            pkg_segs = pkg_part.split(".")
            if tail and tail[0].isupper() and all(s and s[0].islower() for s in pkg_segs):
                single_type.append(imp)
            else:
                # Could be `import static pkg.Outer.Nested;` or `import pkg.Outer.Nested;`
                single_static.append(imp)
    return {
        "single_type_imports": single_type,
        "wildcard_type_imports": wild_type,
        "single_static_imports": single_static,
        "wildcard_static_imports": wild_static,
    }


def _extract_non_static_type_imports(caller_unit: dict[str, Any] | None, fallback_imports: list[str] | None = None) -> list[str]:
    """Compatibility helper returning non-static package-level type imports (`import pkg.Cls;` and `import pkg.*;`)."""
    classified = _classify_java_imports(caller_unit, fallback_imports)
    out: list[str] = []
    for imp in classified["single_type_imports"]:
        pkg_part, tail = imp.rsplit(".", 1)
        if tail and tail[0].isupper() and all(s and s[0].islower() for s in pkg_part.split(".")):
            out.append(imp)
    out.extend(classified["wildcard_type_imports"])
    return out


_SAFE_STATIC_WILDCARD_STDLIB_OWNERS = frozenset(
    {
        "java.lang.Math",
        "java.nio.charset.StandardCharsets",
        "java.nio.file.StandardOpenOption",
        "java.util.Collections",
        "java.util.Arrays",
        "java.util.Objects",
        "java.util.stream.Collectors",
        "org.springframework.http.HttpStatus",
    }
)


def _is_safe_static_wildcard_owner(owner_qual: str) -> bool:
    """Return True only for a small allowlist of stdlib classes guaranteed to have no nested type shadowing stdlib classes."""
    return owner_qual in _SAFE_STATIC_WILDCARD_STDLIB_OWNERS


def _scan_java_file_pkg_and_classes(file_path: Path) -> tuple[str | None, set[str]]:
    """Read a Java source file read-only to extract its package declaration and top-level type names."""
    try:
        if not file_path.is_file() or file_path.stat().st_size > 1_000_000:
            return None, set()
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, set()
    clean_lines = _strip_comments_and_strings_preserve_lines(text)
    pkg: str | None = None
    classes: set[str] = set()
    for cl in clean_lines:
        if pkg is None:
            m_pkg = PACKAGE_RE.match(cl)
            if m_pkg:
                pkg = m_pkg.group(1)
                continue
        m_cls = CLASS_RE.search(cl)
        if m_cls:
            classes.add(m_cls.group(1))
    return pkg, classes


def collect_project_package_classes(
    record: dict[str, Any],
    all_units: list[dict[str, Any]],
    *,
    primary_path: str | None = None,
    primary_pkg: str | None = None,
    extra_pkgs: list[str] | tuple[str, ...] = (),
) -> dict[str | None, set[str]]:
    """Collect project-defined Java type names per package across verified snippets, snapshots, source_hashes, and source root.

    Used to detect same-package and wildcard-package shadowing of `java.lang.*` and other stdlib classes
    (e.g. `audit.Integer` shadowing `java.lang.Integer`).
    """
    pkg_classes: dict[str | None, set[str]] = {}

    def _add(pkg: str | None, cls_name: str) -> None:
        if cls_name and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", cls_name):
            pkg_classes.setdefault(pkg, set()).add(cls_name)

    for u in all_units:
        upkg = u.get("package_name")
        for cname in (u.get("classes") or {}):
            _add(upkg, cname)

    primary_dir_norm: str | None = None
    if isinstance(primary_path, str) and primary_path:
        p_norm = primary_path.replace("\\", "/")
        primary_dir_norm = p_norm.rsplit("/", 1)[0] if "/" in p_norm else ""

    known_rel_paths: set[str] = set()
    snapshots = record.get("snapshots") if isinstance(record.get("snapshots"), dict) else {}
    for k in snapshots:
        if isinstance(k, str) and k.endswith(".java"):
            known_rel_paths.add(k.replace("\\", "/"))
    prov = record.get("scan_provenance") if isinstance(record.get("scan_provenance"), dict) else {}
    src_hashes = prov.get("source_hashes") if isinstance(prov.get("source_hashes"), dict) else {}
    for k in src_hashes:
        if isinstance(k, str) and k.endswith(".java"):
            known_rel_paths.add(k.replace("\\", "/"))
    pre_hashes = record.get("pre_scan_hashes") if isinstance(record.get("pre_scan_hashes"), dict) else {}
    for k in pre_hashes:
        if isinstance(k, str) and k.endswith(".java"):
            known_rel_paths.add(k.replace("\\", "/"))

    root_raw = record.get("root")
    root_dir: Path | None = None
    if isinstance(root_raw, str) and root_raw.strip():
        cand_root = Path(root_raw)
        try:
            if cand_root.is_dir():
                root_dir = cand_root.resolve()
        except OSError:
            root_dir = None

    inspected_disk_files: set[Path] = set()

    def _inspect_disk_java(fp: Path) -> None:
        try:
            res = fp.resolve()
            if root_dir is not None:
                res.relative_to(root_dir)
        except (OSError, ValueError):
            return
        if res in inspected_disk_files or len(inspected_disk_files) >= 512:
            return
        inspected_disk_files.add(res)
        f_pkg, f_classes = _scan_java_file_pkg_and_classes(res)
        for cname in f_classes:
            _add(f_pkg, cname)
        if not f_classes and res.suffix == ".java":
            _add(f_pkg, res.stem)

    if root_dir is not None:
        # 1. Inspect every sibling `.java` file in the primary file's directory (catches package-private classes too!)
        if isinstance(primary_path, str) and primary_path:
            p_abs = root_dir / primary_path
            if p_abs.parent.is_dir():
                try:
                    for sib in sorted(p_abs.parent.glob("*.java")):
                        _inspect_disk_java(sib)
                except OSError:
                    pass
        # 2. Inspect package-matching directories under root (primary package + wildcard-imported non-stdlib packages)
        pkgs_to_scan: list[str] = []
        if isinstance(primary_pkg, str) and primary_pkg:
            pkgs_to_scan.append(primary_pkg)
        for ep in extra_pkgs:
            if isinstance(ep, str) and ep and ep not in pkgs_to_scan and not (ep + ".").startswith(_STDLIB_PKG_PREFIXES):
                pkgs_to_scan.append(ep)
        for pkg_name in pkgs_to_scan:
            pkg_rel = Path(*pkg_name.split("."))
            for base_prefix in (Path("."), Path("src"), Path("src/main/java"), Path("src/test/java")):
                pdir = root_dir / base_prefix / pkg_rel
                if pdir.is_dir():
                    try:
                        for sib in sorted(pdir.glob("*.java")):
                            _inspect_disk_java(sib)
                    except OSError:
                        pass
        # 3. Inspect known `.java` files listed in snapshots / scan_provenance.source_hashes
        for rel in sorted(known_rel_paths):
            _inspect_disk_java(root_dir / rel)

    # Fallback path-based inference when `root` is absent (e.g., offline records carrying only `snapshots`/`source_hashes`)
    for rel in sorted(known_rel_paths):
        rel_dir = rel.rsplit("/", 1)[0] if "/" in rel else ""
        stem = Path(rel).stem
        if primary_dir_norm is not None and rel_dir == primary_dir_norm:
            _add(primary_pkg, stem)
        if rel_dir:
            segs = [s for s in rel_dir.split("/") if s]
            # Strip conventional Maven/Gradle source prefixes when inferring package from relative path
            if len(segs) >= 3 and segs[:3] == ["src", "main", "java"]:
                segs = segs[3:]
            elif len(segs) >= 3 and segs[:3] == ["src", "test", "java"]:
                segs = segs[3:]
            elif len(segs) >= 1 and segs[0] == "src":
                segs = segs[1:]
            if segs and all(re.fullmatch(r"[a-z_][a-z0-9_]*", s) for s in segs):
                _add(".".join(segs), stem)
        else:
            _add(None, stem)

    return pkg_classes


def _is_leading_qualifier_shadowed(
    qual_or_pkg: str | None,
    *,
    visible_var_info: dict[str, dict[str, Any]] | None = None,
    caller_unit: dict[str, Any] | None = None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
    caller_imports: list[str] | None = None,
    require_expr_scope: bool = False,
) -> bool:
    """Return True when the leading identifier of `qual_or_pkg` is shadowed (JLS §6.5.2/§6.5.5) or unverified.

    - ExpressionName shadowing: local variables, parameters, and class fields (`Root java`, `private AppRoot java;`).
    - Truncated mid-file expression scope without verified disk source / complete header+fields -> fail closed.
    - TypeName shadowing: same-unit `class java`, single-type/single-static imports, or same-package `class java`.
    """
    if not isinstance(qual_or_pkg, str) or not qual_or_pkg.strip():
        return True
    first_seg = qual_or_pkg.strip().split(".", 1)[0]
    if not first_seg or first_seg in ("this", "super"):
        return True
    if visible_var_info is not None and first_seg in visible_var_info:
        return True
    if require_expr_scope and isinstance(caller_unit, dict):
        if int(caller_unit.get("min_line") or 1) > 1 and not caller_unit.get("has_complete_scope_context", True):
            return True
    if isinstance(caller_unit, dict):
        if first_seg in (caller_unit.get("classes") or {}):
            return True
        if first_seg in (caller_unit.get("declared_class_names") or ()):
            return True
    classified = _classify_java_imports(caller_unit, caller_imports)
    for imp in classified["single_static_imports"]:
        if "." in imp and imp.rsplit(".", 1)[1] == first_seg:
            return True
    single_type_matched_stdlib = False
    for imp in classified["single_type_imports"]:
        if "." in imp and imp.rsplit(".", 1)[1] == first_seg:
            imp_pkg = imp.rsplit(".", 1)[0]
            if (
                all(s and s[0].islower() for s in imp_pkg.split("."))
                and imp_pkg in (_STDLIB_SIMPLE_TO_PACKAGES.get(first_seg) or ())
            ):
                single_type_matched_stdlib = True
            else:
                return True
    if not single_type_matched_stdlib:
        caller_pkg = caller_unit.get("package_name") if isinstance(caller_unit, dict) else None
        if project_pkg_classes and first_seg in project_pkg_classes.get(caller_pkg, set()):
            return True
        if all_units:
            for u in all_units:
                if u.get("package_name") == caller_pkg and first_seg in (u.get("classes") or {}):
                    return True
    return False


def resolve_stdlib_class_fqn(
    raw_type_or_qual: _JavaTypeRef | str | None,
    *,
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
    caller_imports: list[str] | None = None,
) -> str | None:
    """Resolve a Java type reference or static qualifier to a PROVEN stdlib FQN per JLS §6.5.5.1.

    Exact precedence order for unqualified simple type name `Q`:
    1. Enclosing / same-compilation-unit type declaration -> project type (NEVER stdlib).
    2. Single-type-import declaration (`import pkg.Q;`) -> proves `pkg.Q` (beats same-package!).
    3. Same-package type declaration (`caller_pkg.Q`) -> project type (SHADOWS `java.lang.*` and wildcard imports!).
    4. Type-import-on-demand (`import pkg.*;`) and implicit `java.lang.*` -> stdlib ONLY when uniquely resolved
       to a known stdlib package for `Q` and not shadowed by any project type in an imported wildcard package.

    Returns canonical FQN string (e.g. `"java.lang.Integer"`, `"java.nio.file.Files"`) or `None`.
    """
    tref = raw_type_or_qual if isinstance(raw_type_or_qual, _JavaTypeRef) else _parse_java_type_ref(raw_type_or_qual)
    if tref is None or tref.is_var or tref.is_nested_or_ambiguous:
        return None
    simple = tref.simple_name
    if not simple or not simple[0].isupper():
        return None

    def _is_known_stdlib_fqn(pkg: str, cls_name: str) -> bool:
        allowed_pkgs = _STDLIB_SIMPLE_TO_PACKAGES.get(cls_name)
        if allowed_pkgs is not None:
            return pkg in allowed_pkgs
        return False

    # Case 0: Explicitly qualified type name (`java.lang.Integer`, `audit.Integer`, `com.evil.String`)
    if tref.is_qualified:
        if not tref.package_name:
            return None
        if _is_leading_qualifier_shadowed(
            tref.package_name,
            visible_var_info=None,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=caller_imports,
            require_expr_scope=False,
        ):
            return None
        if _is_known_stdlib_fqn(tref.package_name, simple):
            return f"{tref.package_name}.{simple}"
        return None

    # Unqualified simple class name `Q`: require known header context when snippet starts mid-file
    if isinstance(caller_unit, dict):
        if int(caller_unit.get("min_line") or 1) > 1 and not caller_unit.get("has_complete_header", False):
            return None

    # Precedence 1: Same-file / enclosing compilation unit class declaration (including nested classes)
    if isinstance(caller_unit, dict):
        if simple in (caller_unit.get("classes") or {}):
            return None
        if simple in (caller_unit.get("declared_class_names") or ()):
            return None

    classified = _classify_java_imports(caller_unit, caller_imports)
    single_type_imports = classified["single_type_imports"]
    wild_type_imports = classified["wildcard_type_imports"]
    single_static_imports = classified["single_static_imports"]
    wild_static_imports = classified["wildcard_static_imports"]

    # Precedence 2: Explicit single-type-import (`import pkg.Q;` OR nested `import pkg.Outer.Q;`)
    # AND single-static-import (`import static pkg.Outer.Q;`) — BOTH beat same-package AND `java.lang.*` per JLS §6.5.5.1!
    single_static_matches = [
        imp
        for imp in single_static_imports
        if "." in imp and imp.rsplit(".", 1)[1] == simple
    ]
    if single_static_matches:
        # A single-static-import brings a nested static type or static member named `simple` into scope;
        # NEVER treat `simple` as `java.lang.<simple>` or another stdlib top-level class!
        return None

    explicit_single_matches = [
        imp
        for imp in single_type_imports
        if "." in imp and imp.rsplit(".", 1)[1] == simple
    ]
    if len(explicit_single_matches) > 1:
        return None
    if len(explicit_single_matches) == 1:
        imp_pkg = explicit_single_matches[0].rsplit(".", 1)[0]
        # Require pure lowercase package segments (rejects nested-type imports such as `import evil.Holder.Integer;`)
        if not all(s and s[0].islower() for s in imp_pkg.split(".")):
            return None
        return f"{imp_pkg}.{simple}" if _is_known_stdlib_fqn(imp_pkg, simple) else None

    # Precedence 3: Same-package project type (`caller_pkg.Q`) — shadows `java.lang.*` and wildcard imports!
    caller_pkg = caller_unit.get("package_name") if isinstance(caller_unit, dict) else None
    if project_pkg_classes and simple in project_pkg_classes.get(caller_pkg, set()):
        return None
    if all_units:
        for u in all_units:
            if u.get("package_name") == caller_pkg and simple in (u.get("classes") or {}):
                return None

    # Precedence 4: Type-import-on-demand (`import pkg.*;`), static-import-on-demand (`import static Outer.*;`),
    # and implicit `java.lang.*`.
    # Any unverified static-import-on-demand (`import static evil.Holder.*;` or `import evil.Holder.*;`) may bring
    # a nested type named `simple` into scope; fail closed unless explicitly qualified or single-type imported above!
    for w_static in wild_static_imports:
        owner_qual = w_static[:-2] if w_static.endswith(".*") else w_static
        if not _is_safe_static_wildcard_owner(owner_qual):
            return None

    wild_pkgs = [imp[:-2] for imp in wild_type_imports if imp.endswith(".*")]

    # If any wildcard-imported package defines a project class `Q`, reject as shadowed/ambiguous
    for wp in wild_pkgs:
        if project_pkg_classes and simple in project_pkg_classes.get(wp, set()):
            return None
        if all_units:
            for u in all_units:
                if u.get("package_name") == wp and simple in (u.get("classes") or {}):
                    return None

    allowed_pkgs = _STDLIB_SIMPLE_TO_PACKAGES.get(simple, ())
    matched_std_pkgs: list[str] = []
    if "java.lang" in allowed_pkgs:
        matched_std_pkgs.append("java.lang")
    for wp in wild_pkgs:
        if _is_known_stdlib_fqn(wp, simple) and wp not in matched_std_pkgs:
            matched_std_pkgs.append(wp)

    if len(matched_std_pkgs) == 1:
        return f"{matched_std_pkgs[0]}.{simple}"
    return None


def _is_verified_stdlib_type_ref(
    tref: _JavaTypeRef | None,
    caller_imports: list[str],
    *,
    caller_unit: dict[str, Any] | None = None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
) -> bool:
    """Return True ONLY when `tref` resolves via JLS §6.5.5.1 to a proven stdlib FQN."""
    return (
        resolve_stdlib_class_fqn(
            tref,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=caller_imports,
        )
        is not None
    )


def _extract_exact_new_ctor_ref(
    rhs: str,
    decl_ref: _JavaTypeRef,
    *,
    caller_pkg: str | None,
    caller_imports: list[str],
    caller_unit: dict[str, Any] | None = None,
) -> _JavaTypeRef | None:
    """Return package-preserving `_JavaTypeRef` ONLY when `rhs` is exact `new ExactType(...)` matching `decl_ref`."""
    rhs_s = rhs.strip()
    m_new = _NEW_CTOR_RE.match(rhs_s)
    if not m_new:
        return None
    open_idx = m_new.end() - 1
    close_idx = _find_matching_paren(rhs_s, open_idx)
    if close_idx is None:
        return None
    trailer = rhs_s[close_idx + 1 :].strip()
    if trailer and trailer != ";":
        # Trailing `{ ... }` anonymous subclass or chained `.method()` -> concrete dispatch type is NOT exact
        return None
    ctor_ref = _parse_java_type_ref(m_new.group(1))
    if ctor_ref is None or ctor_ref.is_var or ctor_ref.is_nested_or_ambiguous:
        return None
    if decl_ref.is_var or decl_ref.is_nested_or_ambiguous:
        return None

    decl_fqn = _resolve_canonical_fqn_for_type_ref(decl_ref, caller_pkg, caller_imports, caller_unit=caller_unit)
    ctor_fqn = _resolve_canonical_fqn_for_type_ref(ctor_ref, caller_pkg, caller_imports, caller_unit=caller_unit)
    if decl_fqn is None or ctor_fqn is None:
        return None
    if decl_fqn != ctor_fqn:
        # Declared type and constructor package/class differ -> never guess or conflate packages!
        return None
    return _JavaTypeRef(
        raw_type=ctor_ref.raw_type,
        qualified_name=f"{ctor_fqn[0]}.{ctor_fqn[1]}" if ctor_fqn[0] else ctor_fqn[1],
        package_name=ctor_fqn[0],
        simple_name=ctor_fqn[1],
        is_qualified=ctor_fqn[0] is not None,
        is_nested_or_ambiguous=False,
        is_var=False,
    )


def _line_reassigns_var(clean_line: str, vname: str) -> bool:
    """Detect variable reassignment anywhere in a comment/string-stripped line (including `if (flag) v = other;`)."""
    pat = re.compile(rf"(?<![.\w]){re.escape(vname)}\s*(?:(?<![=!<>+\-*/%&|^])=(?!=)|[+\-*/%&|^]=)")
    return bool(pat.search(clean_line))


def _split_top_level_semicolons(text: str) -> list[str]:
    """Split `text` on `;` at paren/bracket depth 0."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in text:
        if ch in "([{":
            depth += 1
            buf.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == ";" and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


_TRY_RESOURCE_DECL_RE = re.compile(
    r"^\s*(?:final\s+)?([A-Za-z_][A-Za-z0-9_<>,.\[\]?\s]*?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$"
)
_ENHANCED_FOR_DECL_RE = re.compile(
    r"^\s*for\s*\(\s*(?:final\s+)?([A-Za-z_][A-Za-z0-9_<>,.\[\]?\s]*?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*:"
)
_CATCH_PARAM_DECL_RE = re.compile(
    r"\bcatch\s*\(\s*(?:final\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\)"
)


def _extract_line_var_decls(c_txt: str, try_depth: int = 0) -> tuple[list[tuple[str, str, str]], int]:
    """Extract `(raw_type, var_name, rhs)` declarations from a comment/string-stripped Java line.

    Supports standard local/field declarations, single-line and multi-line `try (...)` resources,
    `catch (Type e)` exception parameters, enhanced-for loop variables `for (Type v : expr)`,
    and comma-separated multi-var declarations.
    """
    decls: list[tuple[str, str, str]] = []
    m_try = re.match(r"^\s*try\s*\(", c_txt) if try_depth == 0 else None
    if try_depth > 0 or m_try:
        pos = m_try.end() if m_try else 0
        depth = 1 if m_try else try_depth
        end_pos = len(c_txt)
        for idx in range(pos, len(c_txt)):
            ch = c_txt[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end_pos = idx
                    break
        header_slice = c_txt[pos:end_pos]
        for seg in _split_top_level_semicolons(header_slice):
            m_res = _TRY_RESOURCE_DECL_RE.match(seg)
            if m_res:
                decls.append((m_res.group(1).strip(), m_res.group(2).strip(), m_res.group(3).strip()))
        return decls, depth

    m_catch = _CATCH_PARAM_DECL_RE.search(c_txt)
    if m_catch:
        decls.append((m_catch.group(1).strip(), m_catch.group(2).strip(), ""))
        return decls, 0

    m_for = _ENHANCED_FOR_DECL_RE.match(c_txt)
    if m_for:
        decls.append((m_for.group(1).strip(), m_for.group(2).strip(), ""))
        return decls, 0

    m_cfor = re.match(r"^\s*for\s*\(", c_txt)
    if m_cfor:
        pos = m_cfor.end()
        depth = 1
        semi_pos = None
        for idx in range(pos, len(c_txt)):
            ch = c_txt[idx]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth == 0:
                    break
            elif ch == ";" and depth == 1:
                semi_pos = idx
                break
        if semi_pos is not None:
            init_clause = c_txt[pos:semi_pos].strip()
            if init_clause:
                init_stmt = init_clause + ";"
                if len(_split_top_level_commas(init_clause)) == 1:
                    m_ci = _DECL_TYPE_VAR_RE.match(init_stmt)
                    if m_ci:
                        decls.append((m_ci.group(1).strip(), m_ci.group(2).strip(), (m_ci.group(3) or "").strip()))
                        return decls, 0
                m_cm = _FIELD_DECL_STMT_RE.match(init_stmt)
                if m_cm:
                    raw_type = m_cm.group(1).strip()
                    first_tok = raw_type.split()[0] if raw_type else ""
                    if first_tok not in CONTROL_KEYWORDS and first_tok not in ("class", "interface", "enum", "void"):
                        for item in _split_top_level_commas(m_cm.group(2)):
                            if "=" in item:
                                lhs_raw, rhs_raw = item.split("=", 1)
                            else:
                                lhs_raw, rhs_raw = item, ""
                            vname = re.sub(r"\s*\[\s*\]\s*", "", lhs_raw).strip()
                            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", vname) and vname not in CONTROL_KEYWORDS:
                                decls.append((raw_type, vname, rhs_raw.strip()))
                        if decls:
                            return decls, 0

    m_decl = _DECL_TYPE_VAR_RE.match(c_txt)
    if m_decl:
        decls.append((m_decl.group(1).strip(), m_decl.group(2).strip(), (m_decl.group(3) or "").strip()))
        return decls, 0

    stripped = c_txt.strip()
    if stripped.endswith(";") and (("(" not in stripped) or ("=" in stripped and stripped.find("=") < stripped.find("("))):
        m_multi = _FIELD_DECL_STMT_RE.match(stripped)
        if m_multi:
            raw_type = m_multi.group(1).strip()
            first_tok = raw_type.split()[0] if raw_type else ""
            if first_tok not in CONTROL_KEYWORDS and first_tok not in ("class", "interface", "enum", "void"):
                for item in _split_top_level_commas(m_multi.group(2)):
                    if "=" in item:
                        lhs_raw, rhs_raw = item.split("=", 1)
                    else:
                        lhs_raw, rhs_raw = item, ""
                    vname = re.sub(r"\s*\[\s*\]\s*", "", lhs_raw).strip()
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", vname) and vname not in CONTROL_KEYWORDS:
                        decls.append((raw_type, vname, rhs_raw.strip()))
    return decls, 0


def _collect_visible_var_info(
    p_verified: dict[int, str],
    enc: dict[str, Any] | None,
    enclosing_class: str | None,
    *,
    caller_pkg: str | None = None,
    caller_imports: list[str] | None = None,
    caller_unit: dict[str, Any] | None = None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
    static_field_resolver: Any = None,
) -> dict[str, dict[str, Any]]:
    """Collect package-preserving declared types, verified `new` concrete types, and reassignment flags.

    Scoping rules enforced:
    - Class fields (outside sibling method bodies & nested classes) are seeded with `concrete_type_ref=None`.
    - Sibling method local variables above `h_line` are NEVER mistaken for class fields.
    - Parameters and local variables inside `enc` properly shadow class fields (Java scoping).
    - Multi-line local declarations and multi-line `try (...)` resource headers are accumulated before parsing.
    - Java 10+ `var` locals infer a stdlib type ONLY when the RHS resolves via JLS §6.5.5.1 to a proven
      stdlib FQN (no anonymous subclass/lambda); reassigned or duplicated `var` locals fail closed to `None`.
    - Duplicate local/parameter declarations inside `enc` still fail closed (`declared_type_ref=None`).
    """
    imports = list(caller_imports or [])
    field_info: dict[str, dict[str, Any]] = {}
    local_info: dict[str, dict[str, Any]] = {}
    local_counts: dict[str, int] = {}

    def _record_field(vname: str, declared_type_ref: _JavaTypeRef | None, decl_line: int) -> None:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", vname) or vname in CONTROL_KEYWORDS:
            return
        if vname in field_info:
            existing = field_info[vname].get("declared_type_ref")
            if existing is None or declared_type_ref is None or existing.qualified_name != declared_type_ref.qualified_name:
                field_info[vname] = {
                    "declared_type": None,
                    "declared_type_ref": None,
                    "concrete_type": None,
                    "concrete_type_ref": None,
                    "decl_line": decl_line,
                    "decl_end_line": decl_line,
                    "is_param": False,
                    "is_field": True,
                    "reassigned": True,
                    "inferred_from_var": False,
                }
            return
        field_info[vname] = {
            "declared_type": declared_type_ref.qualified_name if declared_type_ref else None,
            "declared_type_ref": declared_type_ref,
            "concrete_type": None,
            "concrete_type_ref": None,
            "decl_line": decl_line,
            "decl_end_line": decl_line,
            "is_param": False,
            "is_field": True,
            "reassigned": False,
            "inferred_from_var": False,
        }

    def _record_local(
        vname: str,
        *,
        declared_type_ref: _JavaTypeRef | None,
        concrete_type_ref: _JavaTypeRef | None,
        decl_line: int,
        decl_end_line: int | None = None,
        is_param: bool = False,
        inferred_from_var: bool = False,
    ) -> None:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", vname) or vname in CONTROL_KEYWORDS:
            return
        eff_end = decl_end_line if type(decl_end_line) is int and decl_end_line >= decl_line else decl_line
        local_counts[vname] = local_counts.get(vname, 0) + 1
        if local_counts[vname] > 1:
            local_info[vname] = {
                "declared_type": None,
                "declared_type_ref": None,
                "concrete_type": None,
                "concrete_type_ref": None,
                "decl_line": decl_line,
                "decl_end_line": eff_end,
                "is_param": is_param,
                "is_field": False,
                "reassigned": True,
                "inferred_from_var": False,
            }
        else:
            local_info[vname] = {
                "declared_type": declared_type_ref.qualified_name if declared_type_ref else None,
                "declared_type_ref": declared_type_ref,
                "concrete_type": concrete_type_ref.qualified_name if concrete_type_ref else None,
                "concrete_type_ref": concrete_type_ref,
                "decl_line": decl_line,
                "decl_end_line": eff_end,
                "is_param": is_param,
                "is_field": False,
                "reassigned": False,
                "inferred_from_var": inferred_from_var,
            }

    def _record_local_decl(raw_type: str, vname: str, rhs: str, d_start: int, d_end: int) -> None:
        decl_ref = _parse_java_type_ref(raw_type)
        if decl_ref is None:
            return
        inferred_var = False
        concrete_ref: _JavaTypeRef | None = None
        if decl_ref.is_var:
            rhs_clean = rhs.strip().rstrip(";").strip()
            if rhs_clean and rhs_clean.endswith(")") and "{" not in rhs_clean and "->" not in rhs_clean:
                cur_visible = {**field_info, **local_info}
                inferred_fqn = _resolve_expr_stdlib_fqn(
                    rhs_clean,
                    visible_var_info=cur_visible,
                    caller_imports=imports,
                    caller_unit=caller_unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                    enclosing_class=enclosing_class,
                    static_field_resolver=static_field_resolver,
                )
                if inferred_fqn is not None:
                    inferred_ref = _parse_java_type_ref(inferred_fqn)
                    if inferred_ref is not None and not inferred_ref.is_var:
                        decl_ref = inferred_ref
                        inferred_var = True
        else:
            concrete_ref = _extract_exact_new_ctor_ref(
                rhs,
                decl_ref,
                caller_pkg=caller_pkg,
                caller_imports=imports,
                caller_unit=caller_unit,
            )
        _record_local(
            vname,
            declared_type_ref=decl_ref,
            concrete_type_ref=concrete_ref,
            decl_line=d_start,
            decl_end_line=d_end,
            inferred_from_var=inferred_var,
        )

    # Seed verified class fields from full primary header metadata (e.g. Swing JTextField fields declared anywhere in class)
    if isinstance(caller_unit, dict):
        if isinstance(caller_unit.get("enclosing_class_field_types"), dict):
            for fname, ftype_raw in caller_unit["enclosing_class_field_types"].items():
                if isinstance(fname, str) and isinstance(ftype_raw, str):
                    fref = _parse_java_type_ref(ftype_raw)
                    if fref is not None:
                        _record_field(fname, fref, 0)
        if isinstance(caller_unit.get("enclosing_class_fields"), list):
            for fname in caller_unit["enclosing_class_fields"]:
                if isinstance(fname, str) and fname not in field_info:
                    _record_field(fname, None, 0)

    if isinstance(enc, dict):
        p_types, _, _ = _extract_param_types_and_count(enc.get("parameters"))
        p_line = int(enc["header_line"]) if type(enc.get("header_line")) is int else 0
        for vn, vt_ref in p_types.items():
            # Parameters may hold any runtime subtype -> concrete_type_ref is ALWAYS None (dynamic dispatch).
            _record_local(vn, declared_type_ref=vt_ref, concrete_type_ref=None, decl_line=p_line, is_param=True)

    if p_verified:
        min_ln = min(p_verified)
        max_ln = max(p_verified)
        virtual = [p_verified.get(i, "") for i in range(min_ln, max_ln + 1)]
        clean_lines = _strip_comments_and_strings_preserve_lines("\n".join(virtual))
        h_line = int(enc["header_line"]) if (enc and type(enc.get("header_line")) is int) else min_ln
        e_line = int(enc["end_line"]) if (enc and type(enc.get("end_line")) is int) else max_ln

        enc_cls_bounds: tuple[int, int] | None = None
        if isinstance(caller_unit, dict) and isinstance(enclosing_class, str) and enclosing_class:
            cls_map = caller_unit.get("classes") or {}
            cinfo = cls_map.get(enclosing_class) or cls_map.get(enclosing_class.rsplit(".", 1)[-1])
            if isinstance(cinfo, dict):
                cs = int(cinfo.get("start_line") or 0)
                ce = int(cinfo.get("end_line") or 0)
                if cs > 0 and ce >= cs:
                    enc_cls_bounds = (cs, ce)

        # Exclude all sibling method bodies and nested class bodies when scanning lines before `h_line` or after `e_line`
        excluded_field_ranges: list[tuple[int, int]] = []
        if isinstance(caller_unit, dict):
            for m in caller_unit.get("methods") or []:
                ms = int(m.get("header_line") or m.get("start_line") or 0)
                me = int(m.get("end_line") or 0)
                if ms > 0 and me >= ms and ms != h_line:
                    excluded_field_ranges.append((ms, me))
            for cname, cinfo in (caller_unit.get("classes") or {}).items():
                if enclosing_class and cname != enclosing_class:
                    cs = int(cinfo.get("start_line") or 0)
                    ce = int(cinfo.get("end_line") or 0)
                    if cs > 0 and ce >= cs:
                        excluded_field_ranges.append((cs, ce))

        # Pass 1: collect fields before `h_line` or after `e_line` (within enclosing class, outside sibling methods)
        # and locals inside `h_line..e_line` (supporting multi-line declarations & multi-line try-with-resources).
        method_body_clean: list[tuple[int, str]] = []
        try_depth = 0
        try_buf: list[tuple[int, str]] = []
        pending_decl: list[tuple[int, str]] = []
        pending_paren_depth = 0
        for lno, c_txt in zip(range(min_ln, max_ln + 1), clean_lines):
            if lno not in p_verified:
                continue
            if lno < h_line or lno > e_line:
                if any(lo <= lno <= hi for lo, hi in excluded_field_ranges):
                    continue
                if enc_cls_bounds is not None and not (enc_cls_bounds[0] <= lno <= enc_cls_bounds[1]):
                    continue
                decls, _ = _extract_line_var_decls(c_txt, 0)
                for raw_type, vname, _rhs in decls:
                    decl_ref = _parse_java_type_ref(raw_type)
                    if decl_ref is not None:
                        _record_field(vname, decl_ref, lno)
                continue
            if h_line < lno <= e_line:
                method_body_clean.append((lno, c_txt))
                stripped_c = c_txt.strip()

                # Multi-line `try (...)` resource header accumulation
                m_try_start = re.match(r"^\s*try\s*\(", c_txt) if try_depth == 0 else None
                if try_depth > 0 or m_try_start:
                    pending_decl = []
                    pending_paren_depth = 0
                    pos = m_try_start.end() if m_try_start else 0
                    depth = 1 if m_try_start else try_depth
                    end_pos = len(c_txt)
                    for idx_ch in range(pos, len(c_txt)):
                        ch = c_txt[idx_ch]
                        if ch == "(":
                            depth += 1
                        elif ch == ")":
                            depth -= 1
                            if depth == 0:
                                end_pos = idx_ch
                                break
                    header_slice = c_txt[pos:end_pos]
                    try_buf.append((lno, header_slice))
                    try_depth = depth
                    if try_depth == 0:
                        t_start = try_buf[0][0]
                        t_end = try_buf[-1][0]
                        full_hdr = " ".join(seg.strip() for _, seg in try_buf if seg.strip())
                        try_buf = []
                        for seg in _split_top_level_semicolons(full_hdr):
                            m_res = _TRY_RESOURCE_DECL_RE.match(seg)
                            if m_res:
                                _record_local_decl(
                                    m_res.group(1).strip(),
                                    m_res.group(2).strip(),
                                    m_res.group(3).strip(),
                                    t_start,
                                    t_end,
                                )
                    continue

                # Multi-line regular declaration continuation (`Type v =\n rhs...;`)
                if pending_decl:
                    if not stripped_c:
                        continue
                    if "{" in stripped_c or "}" in stripped_c or len(pending_decl) >= 12:
                        pending_decl = []
                        pending_paren_depth = 0
                    else:
                        pending_decl.append((lno, stripped_c))
                        pending_paren_depth += stripped_c.count("(") - stripped_c.count(")")
                        if pending_paren_depth <= 0 and stripped_c.endswith(";"):
                            d_start = pending_decl[0][0]
                            d_end = pending_decl[-1][0]
                            joined_stmt = " ".join(s for _, s in pending_decl)
                            pending_decl = []
                            pending_paren_depth = 0
                            decls, _ = _extract_line_var_decls(joined_stmt, 0)
                            for raw_type, vname, rhs in decls:
                                _record_local_decl(raw_type, vname, rhs, d_start, d_end)
                        continue

                decls, _ = _extract_line_var_decls(c_txt, 0)
                if decls:
                    for raw_type, vname, rhs in decls:
                        _record_local_decl(raw_type, vname, rhs, lno, lno)
                    continue

                if (
                    stripped_c
                    and not stripped_c.endswith((";", "{", "}", ":"))
                    and "{" not in stripped_c
                    and "}" not in stripped_c
                ):
                    m_pend = _PENDING_DECL_START_RE.match(c_txt)
                    if m_pend:
                        p_type = m_pend.group(1).strip()
                        p_var = m_pend.group(2).strip()
                        first_t = p_type.split()[0] if p_type else ""
                        if (
                            first_t not in CONTROL_KEYWORDS
                            and first_t not in _MODIFIERS
                            and first_t not in ("class", "interface", "enum", "void")
                            and p_var not in CONTROL_KEYWORDS
                        ):
                            pending_decl = [(lno, stripped_c)]
                            pending_paren_depth = stripped_c.count("(") - stripped_c.count(")")

        # Pass 2: detect ANY reassignment inside the method body (including inline `if (flag) t = other;`)
        for lno, c_txt in method_body_clean:
            for vname, info in local_info.items():
                if info["reassigned"]:
                    continue
                d_start = info["decl_line"]
                d_end = info.get("decl_end_line", d_start)
                if d_start <= lno < d_end:
                    continue
                if lno == d_end:
                    parts_same = _split_top_level_semicolons(c_txt)
                    if len(parts_same) > 1:
                        decl_seg_idx = (
                            next(
                                (i for i, seg in enumerate(parts_same) if re.search(rf"\b{re.escape(vname)}\b", seg)),
                                0,
                            )
                            if d_start == d_end
                            else 0
                        )
                        if any(_line_reassigns_var(seg, vname) for seg in parts_same[decl_seg_idx + 1 :]):
                            info["reassigned"] = True
                            info["concrete_type"] = None
                            info["concrete_type_ref"] = None
                            if info.get("inferred_from_var"):
                                info["declared_type"] = None
                                info["declared_type_ref"] = None
                    continue
                if lno > d_end and _line_reassigns_var(c_txt, vname):
                    info["reassigned"] = True
                    info["concrete_type"] = None
                    info["concrete_type_ref"] = None
                    if info.get("inferred_from_var"):
                        info["declared_type"] = None
                        info["declared_type_ref"] = None

    var_info: dict[str, dict[str, Any]] = {**field_info, **local_info}

    if enclosing_class:
        this_ref = _JavaTypeRef(
            raw_type=enclosing_class,
            qualified_name=f"{caller_pkg}.{enclosing_class}" if caller_pkg else enclosing_class,
            package_name=caller_pkg,
            simple_name=enclosing_class,
            is_qualified=caller_pkg is not None,
        )
        var_info.setdefault(
            "this",
            {
                "declared_type": this_ref.qualified_name,
                "declared_type_ref": this_ref,
                "concrete_type": None,
                "concrete_type_ref": None,
                "decl_line": 0,
                "is_param": False,
                "is_field": False,
                "reassigned": False,
            },
        )
    return var_info


def _collect_visible_var_types(
    p_verified: dict[int, str],
    enc: dict[str, Any] | None,
    enclosing_class: str | None,
) -> dict[str, str | None]:
    """Compatibility wrapper returning `{var_name: declared_type}`."""
    info = _collect_visible_var_info(p_verified, enc, enclosing_class)
    return {k: v["declared_type"] for k, v in info.items()}


def _method_matches_arity(params: list[str] | None, arg_count: int | None) -> bool:
    if arg_count is None:
        return False
    _, p_count, has_varargs = _extract_param_types_and_count(params)
    if has_varargs:
        return arg_count >= max(0, p_count - 1)
    return p_count == arg_count


def _parse_verified_java_units(
    verified_lines_by_path: dict[str, dict[int, str]],
) -> dict[str, dict[str, Any]]:
    """Parse verified source line maps keyed by path with class, package, import, and modifier metadata."""
    units: dict[str, dict[str, Any]] = {}
    for f_path, line_map in verified_lines_by_path.items():
        if not f_path or not line_map:
            continue
        min_ln = min(line_map)
        max_ln = max(line_map)
        virtual = [line_map.get(i, "") for i in range(1, max_ln + 1)]
        parsed = parse_java_structure_v2("\n".join(virtual))
        cls_by_name = {
            c["name"]: c
            for c in (parsed.get("classes") or [])
            if isinstance(c.get("name"), str)
        }
        units[f_path] = {
            "path": f_path,
            "min_line": min_ln,
            "has_complete_header": min_ln == 1,
            "package_name": parsed.get("package_name"),
            "imports": list(parsed.get("imports") or []),
            "type_imports": list(parsed.get("type_imports") or []),
            "static_imports": list(parsed.get("static_imports") or []),
            "classes": cls_by_name,
            "methods": parsed.get("methods") or [],
            "line_map": line_map,
        }
    return units


def _extract_call_sites_on_line(s_clean: str) -> list[dict[str, Any]]:
    """Extract call sites preserving full dotted qualifiers, start offsets, paren indices, chained indicators, and `new C().m()`."""
    sites: list[dict[str, Any]] = []
    for m_call in _CALL_SITE_RE.finditer(s_clean):
        prefix_before = s_clean[: m_call.start()].rstrip()
        raw_qual = m_call.group(1)
        mname = m_call.group(2)
        open_paren_idx = m_call.end() - 1
        if mname in CONTROL_KEYWORDS or mname in _MODIFIERS:
            continue
        if re.search(r"\bnew$", prefix_before):
            # Constructor call `new Type(args)`: inspect whether `.method(` directly chains after it.
            close_idx = _find_matching_paren(s_clean, open_paren_idx)
            if close_idx is not None:
                after = s_clean[close_idx + 1 :]
                m_after = re.match(r"^\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", after)
                if m_after:
                    ctor_qual = f"{raw_qual}.{mname}" if raw_qual else mname
                    sites.append(
                        {
                            "qualifier": ctor_qual,
                            "method": m_after.group(1),
                            "chained": False,
                            "is_new_ctor_chain": True,
                            "ctor_open_idx": open_paren_idx,
                            "open_paren_idx": close_idx + 1 + m_after.end() - 1,
                            "start": close_idx + 1 + m_after.start(1),
                        }
                    )
            continue

        qual = ".".join(p.strip() for p in raw_qual.split(".")) if raw_qual else None
        # Also treat explicit type-witness calls (`obj.<T>method(`) as chained so they are never mistaken for `this.method(`.
        chained = bool(prefix_before.endswith(".") or prefix_before.endswith(">"))
        if chained and qual is None and prefix_before.endswith("."):
            # Skip chained method already emitted as `is_new_ctor_chain` when immediately preceded by `new ...).`
            prev_stmt = s_clean[: m_call.start()]
            if re.search(r"\bnew\s+[A-Za-z_][A-Za-z0-9_.]*\s*\([^()]*\)\s*\.\s*$", prev_stmt):
                continue
        sites.append(
            {
                "qualifier": qual,
                "method": mname,
                "chained": chained,
                "is_new_ctor_chain": False,
                "open_paren_idx": open_paren_idx,
                "start": m_call.start(),
            }
        )
    return sites


def _find_matching_open_paren_backward(text: str, close_idx: int) -> int | None:
    """Find the index of `(` matching `)` at `close_idx` scanning backwards."""
    if close_idx < 0 or close_idx >= len(text) or text[close_idx] != ")":
        return None
    depth = 0
    for i in range(close_idx, -1, -1):
        ch = text[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
            if depth == 0:
                return i
    return None


def _extract_chain_receiver_expr(s_clean: str, call_start: int | None) -> str | None:
    """Extract the exact Java receiver expression immediately preceding `.method(` at `call_start`."""
    if not isinstance(s_clean, str) or type(call_start) is not int or call_start <= 0:
        return None
    i = call_start - 1
    while i >= 0 and s_clean[i].isspace():
        i -= 1
    if i < 0 or s_clean[i] != ".":
        return None
    end = i
    pos = end - 1
    while pos >= 0 and s_clean[pos].isspace():
        pos -= 1
    if pos < 0:
        return None

    start = pos + 1
    while pos >= 0:
        ch = s_clean[pos]
        if ch == ")":
            open_idx = _find_matching_open_paren_backward(s_clean, pos)
            if open_idx is None:
                return None
            j = open_idx - 1
            while j >= 0 and s_clean[j].isspace():
                j -= 1
            if j >= 0 and (s_clean[j].isalnum() or s_clean[j] == "_"):
                # Method or constructor name before `(`
                while j >= 0 and (s_clean[j].isalnum() or s_clean[j] == "_"):
                    j -= 1
                start = j + 1
                # Also check for `new pkg.Type(` prefix
                k = j
                while k >= 0 and s_clean[k].isspace():
                    k -= 1
                # Consume any dotted qualifiers if followed by `new` or chain
                probe = j
                while True:
                    p2 = probe
                    while p2 >= 0 and s_clean[p2].isspace():
                        p2 -= 1
                    if p2 >= 0 and s_clean[p2] == ".":
                        p3 = p2 - 1
                        while p3 >= 0 and s_clean[p3].isspace():
                            p3 -= 1
                        if p3 >= 0 and (s_clean[p3].isalnum() or s_clean[p3] == "_"):
                            while p3 >= 0 and (s_clean[p3].isalnum() or s_clean[p3] == "_"):
                                p3 -= 1
                            probe = p3
                            start = p3 + 1
                            continue
                    break
                p_new = start - 1
                while p_new >= 0 and s_clean[p_new].isspace():
                    p_new -= 1
                if p_new >= 2 and s_clean[p_new - 2 : p_new + 1] == "new" and (
                    p_new - 3 < 0 or not (s_clean[p_new - 3].isalnum() or s_clean[p_new - 3] == "_")
                ):
                    start = p_new - 2
                    break
                pos = start - 1
            else:
                start = open_idx
                pos = open_idx - 1
        elif ch == '"':
            j = pos - 1
            while j >= 0 and s_clean[j] != '"':
                j -= 1
            if j < 0:
                return None
            start = j
            break
        elif ch.isalnum() or ch == "_":
            j = pos
            while j >= 0 and (s_clean[j].isalnum() or s_clean[j] == "_"):
                j -= 1
            start = j + 1
            pos = j
        else:
            break

        # Continue backwards ONLY if immediately preceded by `.`
        k = pos
        while k >= 0 and s_clean[k].isspace():
            k -= 1
        if k >= 0 and s_clean[k] == ".":
            pos = k - 1
            while pos >= 0 and s_clean[pos].isspace():
                pos -= 1
            continue
        break

    expr = s_clean[start:end].strip()
    return expr or None


def _resolve_inherited_stdlib_method_fqn(
    mname: str,
    *,
    enclosing_class: str | None,
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None,
    all_units: list[dict[str, Any]] | None,
    caller_imports: list[str],
) -> str | None:
    """Resolve an unqualified or `this.m()` call to a verified stdlib superclass FQN ONLY when:
    1. `enclosing_class` does NOT declare/override `mname`, AND
    2. `enclosing_class`'s `extends` clause resolves via JLS §6.5.5.1 to a verified stdlib FQN
       whose API contract includes `mname` (e.g. `HttpServlet`/`GenericServlet.getServletContext`).
    """
    if not enclosing_class or not isinstance(caller_unit, dict):
        return None
    # Fail closed if enclosing_class itself declares/overrides `mname` anywhere in the unit
    declared_methods = caller_unit.get("enclosing_class_declared_methods")
    if isinstance(declared_methods, (list, set, frozenset)) and mname in declared_methods:
        return None
    for m in caller_unit.get("methods") or []:
        if m.get("name") == mname and (m.get("owner_class") == enclosing_class or m.get("owner_class") is None):
            return None
    cls_info = (caller_unit.get("classes") or {}).get(enclosing_class)
    ext_raw = cls_info.get("extends") if isinstance(cls_info, dict) else None
    if not isinstance(ext_raw, str) or not ext_raw.strip():
        ext_raw = caller_unit.get("enclosing_class_extends")
    if not isinstance(ext_raw, str) or not ext_raw.strip():
        return None
    super_fqn = resolve_stdlib_class_fqn(
        ext_raw.strip(),
        caller_unit=caller_unit,
        project_pkg_classes=project_pkg_classes,
        all_units=all_units,
        caller_imports=caller_imports,
    )
    if super_fqn is not None and mname in _stdlib_methods_for_fqn(super_fqn):
        return super_fqn
    return None


_CLASS_FIELD_MOD_RE = re.compile(
    r"^\s*((?:(?:public|protected|private|static|final|transient|volatile)\s+)*)"
    r"([A-Za-z_][A-Za-z0-9_.]*(?:\s*<[^;={}()]*>)?(?:\s*\[\s*\])*)\s+"
    r"(.+?)\s*;\s*$"
)


def extract_class_static_field_decls(
    text: str,
    structure: dict[str, Any] | None = None,
    class_name: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Extract class-level field declarations inside `class_name` (excluding methods, static blocks, and nested classes).

    Supports multi-line field declarations ending with `;` and preserves both stripped (`rhs_clean`)
    and literal-preserving (`rhs_keep`) initializer text for fail-closed constant/type verification.
    """
    parsed = structure if isinstance(structure, dict) else parse_java_structure_v2(text)
    classes = parsed.get("classes") or []
    methods = parsed.get("methods") or []
    clean_lines = _strip_comments_and_strings_preserve_lines(text)
    # Also produce comment-stripped but string-preserving lines via simple scanner
    keep_lines: list[str] = []
    in_blk = False
    for raw_ln in text.splitlines():
        out_ch: list[str] = []
        i = 0
        n = len(raw_ln)
        in_s = False
        in_c = False
        while i < n:
            ch = raw_ln[i]
            nxt = raw_ln[i + 1] if i + 1 < n else ""
            if in_blk:
                if ch == "*" and nxt == "/":
                    in_blk = False
                    out_ch.append("  ")
                    i += 2
                else:
                    out_ch.append(" ")
                    i += 1
                continue
            if in_s:
                if ch == "\\" and i + 1 < n:
                    out_ch.append(raw_ln[i : i + 2])
                    i += 2
                    continue
                if ch == '"':
                    in_s = False
                out_ch.append(ch)
                i += 1
                continue
            if in_c:
                if ch == "\\" and i + 1 < n:
                    out_ch.append(raw_ln[i : i + 2])
                    i += 2
                    continue
                if ch == "'":
                    in_c = False
                out_ch.append(ch)
                i += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_blk = True
                out_ch.append("  ")
                i += 2
                continue
            if ch == '"':
                in_s = True
            elif ch == "'":
                in_c = True
            out_ch.append(ch)
            i += 1
        keep_lines.append("".join(out_ch))

    target_classes = [c for c in classes if not class_name or c.get("name") == class_name]
    out: dict[str, list[dict[str, Any]]] = {}
    for cls in target_classes:
        c_start = int(cls.get("start_line") or 1)
        c_end = int(cls.get("end_line") or len(clean_lines))
        excluded_ranges: list[tuple[int, int]] = []
        for m in methods:
            ms = int(m.get("header_line") or m.get("start_line") or 0)
            me = int(m.get("end_line") or 0)
            if c_start < ms <= c_end:
                excluded_ranges.append((ms, me))
        for other in classes:
            if other is cls:
                continue
            os_ln = int(other.get("start_line") or 0)
            oe_ln = int(other.get("end_line") or 0)
            if c_start < os_ln <= oe_ln <= c_end:
                excluded_ranges.append((os_ln, oe_ln))

        brace_depth = 0
        stmt_clean_parts: list[str] = []
        stmt_keep_parts: list[str] = []
        stmt_start_ln = 0

        def _flush_stmt() -> None:
            nonlocal stmt_clean_parts, stmt_keep_parts, stmt_start_ln
            if not stmt_clean_parts:
                return
            joined_c = " ".join(stmt_clean_parts).strip()
            joined_k = " ".join(stmt_keep_parts).strip()
            s_ln = stmt_start_ln
            stmt_clean_parts = []
            stmt_keep_parts = []
            stmt_start_ln = 0
            if not joined_c or not joined_c.endswith(";"):
                return
            while joined_c.startswith("@"):
                _, ann_off = _consume_leading_annotations(joined_c)
                if ann_off < 0:
                    return
                joined_c = joined_c[ann_off:].strip()
                _, ann_off_k = _consume_leading_annotations(joined_k)
                if ann_off_k >= 0:
                    joined_k = joined_k[ann_off_k:].strip()
            if not joined_c:
                return
            if "(" in joined_c and not ("=" in joined_c and joined_c.find("=") < joined_c.find("(")):
                return
            m_c = _CLASS_FIELD_MOD_RE.match(joined_c)
            m_k = _CLASS_FIELD_MOD_RE.match(joined_k)
            if not m_c:
                return
            mods = set((m_c.group(1) or "").split())
            raw_type = m_c.group(2).strip()
            first_tok = raw_type.split()[0] if raw_type else ""
            if first_tok in CONTROL_KEYWORDS or first_tok in ("class", "interface", "enum", "void"):
                return
            c_items = _split_top_level_commas(m_c.group(3))
            k_items = _split_top_level_commas(m_k.group(3)) if m_k else c_items
            if len(k_items) != len(c_items):
                k_items = c_items
            for c_item, k_item in zip(c_items, k_items):
                if "=" in c_item:
                    lhs_c, rhs_c = c_item.split("=", 1)
                    rhs_k = k_item.split("=", 1)[1] if "=" in k_item else rhs_c
                else:
                    lhs_c, rhs_c, rhs_k = c_item, "", ""
                fname = re.sub(r"\s*\[\s*\]\s*", "", lhs_c).strip()
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", fname) and fname not in CONTROL_KEYWORDS:
                    out.setdefault(fname, []).append(
                        {
                            "raw_type": raw_type,
                            "is_static": "static" in mods,
                            "is_final": "final" in mods,
                            "rhs_clean": rhs_c.strip(),
                            "rhs_keep": rhs_k.strip(),
                            "line": s_ln,
                        }
                    )

        for lno in range(c_start + 1, min(c_end, len(clean_lines)) + 1):
            if any(lo <= lno <= hi for lo, hi in excluded_ranges):
                stmt_clean_parts = []
                stmt_keep_parts = []
                continue
            cl = clean_lines[lno - 1].strip()
            kl = keep_lines[lno - 1].strip() if lno - 1 < len(keep_lines) else cl
            if not cl:
                continue
            # Skip static/instance initializer blocks (`static { ... }`, `{ ... }`) inside class body
            if brace_depth > 0 or "{" in cl or "}" in cl:
                brace_depth = max(0, brace_depth + cl.count("{") - cl.count("}"))
                stmt_clean_parts = []
                stmt_keep_parts = []
                continue
            if cl.startswith(("package ", "import ")):
                continue
            if not stmt_clean_parts:
                stmt_start_ln = lno
            stmt_clean_parts.append(cl)
            stmt_keep_parts.append(kl)
            if cl.endswith(";"):
                _flush_stmt()
            elif len(stmt_clean_parts) > 12:
                stmt_clean_parts = []
                stmt_keep_parts = []
    return out


def load_verified_project_class_unit(
    record: dict[str, Any] | None,
    owner_pkg: str | None,
    owner_simple: str,
) -> dict[str, Any] | None:
    """Load the unique SHA-256-verified `.java` source unit declaring `(owner_pkg, owner_simple)` under `record['root']`.

    Fails closed (`None`) unless `scan_provenance.source_capture_verified` is True, the target file
    lies strictly inside `record['root']`, its exact byte SHA-256 matches the locked hash table, and
    EXACTLY ONE verified file defines `(owner_pkg, owner_simple)`.
    """
    if not isinstance(record, dict) or not owner_simple or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", owner_simple):
        return None
    prov = record.get("scan_provenance") if isinstance(record.get("scan_provenance"), dict) else {}
    if prov.get("source_capture_verified") is not True:
        return None
    root_raw = record.get("root")
    if not isinstance(root_raw, str) or not root_raw.strip():
        return None
    try:
        root_dir = Path(root_raw).resolve(strict=True)
    except OSError:
        return None
    if not root_dir.is_dir():
        return None

    verified_hashes: dict[str, str] = {}
    for mapping in (prov.get("source_hashes"), record.get("pre_scan_hashes")):
        if isinstance(mapping, dict):
            for rel_k, sha_v in mapping.items():
                if isinstance(rel_k, str) and isinstance(sha_v, str) and len(sha_v) == 64:
                    verified_hashes.setdefault(rel_k.replace("\\", "/"), sha_v)
    manifest_path_raw = prov.get("manifest_path")
    manifest_sha_expected = prov.get("manifest_sha256")
    if (
        isinstance(manifest_path_raw, str)
        and manifest_path_raw.strip()
        and isinstance(manifest_sha_expected, str)
        and len(manifest_sha_expected) == 64
    ):
        try:
            m_path = Path(manifest_path_raw).resolve(strict=True)
            if m_path.is_file() and m_path.stat().st_size <= 20_000_000:
                m_raw = m_path.read_bytes()
                if digest(m_raw) == manifest_sha_expected:
                    m_doc = json.loads(m_raw.decode("utf-8"))
                    if isinstance(m_doc, dict):
                        s_before = m_doc.get("sources_before")
                        s_after = m_doc.get("sources_after")
                        if isinstance(s_before, dict) and isinstance(s_after, dict):
                            for rel_k, sha_b in s_before.items():
                                if (
                                    isinstance(rel_k, str)
                                    and isinstance(sha_b, str)
                                    and len(sha_b) == 64
                                    and s_after.get(rel_k) == sha_b
                                ):
                                    verified_hashes.setdefault(rel_k.replace("\\", "/"), sha_b)
        except (OSError, ValueError, UnicodeDecodeError):
            pass
    snaps = record.get("snapshots") if isinstance(record.get("snapshots"), dict) else {}
    for rel_k, snap_v in snaps.items():
        if isinstance(rel_k, str) and isinstance(snap_v, dict):
            sha_v = snap_v.get("sha256")
            if isinstance(sha_v, str) and len(sha_v) == 64:
                verified_hashes.setdefault(rel_k.replace("\\", "/"), sha_v)
    if not verified_hashes:
        return None

    target_name = f"{owner_simple}.java"
    cand_rels = [rel for rel in sorted(verified_hashes) if Path(rel).name == target_name]
    if not cand_rels:
        return None

    matches: list[dict[str, Any]] = []
    for rel in cand_rels:
        expected_sha = verified_hashes[rel]
        try:
            fp = (root_dir / rel).resolve(strict=True)
            fp.relative_to(root_dir)
            if not fp.is_file() or fp.stat().st_size > 2_000_000:
                continue
            raw = fp.read_bytes()
        except (OSError, ValueError):
            continue
        if digest(raw) != expected_sha:
            continue
        text = raw.decode("utf-8", errors="replace")
        parsed = parse_java_structure_v2(text)
        if parsed.get("package_name") != owner_pkg:
            continue
        cls_by_name = {c["name"]: c for c in (parsed.get("classes") or []) if isinstance(c.get("name"), str)}
        if owner_simple not in cls_by_name:
            continue
        owner_unit = {
            "path": rel,
            "min_line": 1,
            "has_complete_header": True,
            "has_complete_scope_context": True,
            "package_name": parsed.get("package_name"),
            "imports": list(parsed.get("imports") or []),
            "type_imports": list(parsed.get("type_imports") or []),
            "static_imports": list(parsed.get("static_imports") or []),
            "classes": cls_by_name,
            "declared_class_names": list(cls_by_name.keys()),
            "methods": list(parsed.get("methods") or []),
        }
        matches.append(
            {
                "path": rel,
                "sha256": expected_sha,
                "text": text,
                "parsed": parsed,
                "unit": owner_unit,
                "class_info": cls_by_name[owner_simple],
            }
        )
        if len(matches) > 1:
            return None
    return matches[0] if len(matches) == 1 else None


def make_verified_static_stdlib_field_resolver(record: dict[str, Any] | None):
    """Build a cached resolver mapping `OwnerClass.STATIC_FIELD` -> proven stdlib FQN using SHA-256-locked source."""
    class_unit_cache: dict[tuple[str | None, str], dict[str, Any] | None] = {}
    field_decls_cache: dict[tuple[str | None, str], dict[str, list[dict[str, Any]]]] = {}
    qual_cache: dict[str, str | None] = {}

    def _resolve(
        qual: str,
        *,
        caller_unit: dict[str, Any] | None,
        project_pkg_classes: dict[str | None, set[str]] | None,
        all_units: list[dict[str, Any]] | None,
        caller_imports: list[str] | None,
    ) -> str | None:
        if "." not in qual or not isinstance(record, dict):
            return None
        if qual in qual_cache:
            return qual_cache[qual]
        owner_qual, field_name = qual.rsplit(".", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field_name):
            qual_cache[qual] = None
            return None
        owner_ref = _parse_java_type_ref(owner_qual)
        if owner_ref is None or owner_ref.is_var or owner_ref.is_nested_or_ambiguous:
            qual_cache[qual] = None
            return None
        caller_pkg = caller_unit.get("package_name") if isinstance(caller_unit, dict) else None
        resolved_owner = _resolve_canonical_fqn_for_type_ref(
            owner_ref,
            caller_pkg,
            list(caller_imports or []),
            caller_unit=caller_unit,
        )
        if resolved_owner is None:
            qual_cache[qual] = None
            return None
        owner_pkg, owner_simple = resolved_owner
        if not owner_simple:
            qual_cache[qual] = None
            return None
        ckey = (owner_pkg, owner_simple)
        if ckey not in class_unit_cache:
            class_unit_cache[ckey] = load_verified_project_class_unit(record, owner_pkg, owner_simple)
        loaded = class_unit_cache[ckey]
        if loaded is None:
            qual_cache[qual] = None
            return None
        if ckey not in field_decls_cache:
            field_decls_cache[ckey] = extract_class_static_field_decls(
                loaded["text"],
                structure=loaded["parsed"],
                class_name=owner_simple,
            )
        decls = field_decls_cache[ckey].get(field_name) or []
        if len(decls) != 1 or not decls[0].get("is_static"):
            qual_cache[qual] = None
            return None
        owner_unit = loaded["unit"]
        fqn = resolve_stdlib_class_fqn(
            decls[0]["raw_type"],
            caller_unit=owner_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=owner_unit.get("imports"),
        )
        qual_cache[qual] = fqn
        return fqn

    return _resolve


def _resolve_expr_stdlib_fqn(
    expr: str | None,
    *,
    visible_var_info: dict[str, dict[str, Any]],
    caller_imports: list[str],
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None,
    all_units: list[dict[str, Any]] | None,
    enclosing_class: str | None,
    static_field_resolver: Any = None,
    depth: int = 6,
) -> str | None:
    """Resolve a chained Java receiver expression to its proven stdlib FQN, failing closed on any unknown step."""
    if not isinstance(expr, str) or depth <= 0:
        return None
    cur = expr.strip()
    if not cur:
        return None
    # Strip redundant balanced outer parentheses `(expr)` ONLY when the opening `(` matches the final `)`
    while cur.startswith("(") and cur.endswith(")"):
        if _find_matching_paren(cur, 0) == len(cur) - 1:
            cur = cur[1:-1].strip()
        else:
            break
    if not cur:
        return None

    # Java string literal `"..."` always has type java.lang.String (JLS §3.10.5)
    if len(cur) >= 2 and cur.startswith('"') and cur.endswith('"') and '"' not in cur[1:-1]:
        return "java.lang.String"

    # Call or constructor expression ending with `)`
    if cur.endswith(")"):
        open_idx = _find_matching_open_paren_backward(cur, len(cur) - 1)
        if open_idx is None:
            return None
        head = cur[:open_idx].strip()
        m_new = re.fullmatch(r"new\s+([A-Za-z_][A-Za-z0-9_.]*)(?:\s*<[^>{};]*>)?", head)
        if m_new:
            return resolve_stdlib_class_fqn(
                m_new.group(1),
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                caller_imports=caller_imports,
            )
        m_call = re.match(r"^(?:(.+?)\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)$", head)
        if not m_call:
            return None
        prev_prefix = m_call.group(1).strip() if m_call.group(1) else None
        prev_m = m_call.group(2)
        if prev_prefix is None or prev_prefix == "this":
            super_fqn = _resolve_inherited_stdlib_method_fqn(
                prev_m,
                enclosing_class=enclosing_class,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                caller_imports=caller_imports,
            )
            if super_fqn is None:
                return None
            return _stdlib_return_fqn(super_fqn, prev_m)
        recv_fqn = _resolve_expr_stdlib_fqn(
            prev_prefix,
            visible_var_info=visible_var_info,
            caller_imports=caller_imports,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            enclosing_class=enclosing_class,
            static_field_resolver=static_field_resolver,
            depth=depth - 1,
        )
        if recv_fqn is None or prev_m not in _stdlib_methods_for_fqn(recv_fqn):
            return None
        return _stdlib_return_fqn(recv_fqn, prev_m)

    # `System.out` / `System.err` (fail closed if `System`/`java` is shadowed or scope is truncated)
    if cur in ("System.out", "System.err", "java.lang.System.out", "java.lang.System.err"):
        if _is_leading_qualifier_shadowed(
            cur,
            visible_var_info=visible_var_info,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=caller_imports,
            require_expr_scope=True,
        ):
            return None
        sys_qual = cur.rsplit(".", 1)[0]
        if (
            resolve_stdlib_class_fqn(
                sys_qual,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                caller_imports=caller_imports,
            )
            == "java.lang.System"
        ):
            return "java.io.PrintStream"
        return None

    # Simple identifier (declared variable or static stdlib class ONLY; NEVER infer type from undeclared variable name)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", cur):
        if cur in ("this", "super"):
            return None
        if cur in visible_var_info:
            decl_ref = visible_var_info[cur].get("declared_type_ref")
            return resolve_stdlib_class_fqn(
                decl_ref,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                caller_imports=caller_imports,
            )
        if cur[0].isupper():
            if _is_leading_qualifier_shadowed(
                cur,
                visible_var_info=visible_var_info,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                caller_imports=caller_imports,
                require_expr_scope=True,
            ):
                return None
            return resolve_stdlib_class_fqn(
                cur,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                caller_imports=caller_imports,
            )
        return None

    # Dotted qualified type (e.g. `java.nio.file.Paths`) or SHA-256-verified static stdlib field
    # (e.g. `pkg.Helper.STATIC_JDBC_TEMPLATE`), failing closed on ExpressionName/TypeName shadowing or truncated scope.
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", cur):
        if _is_leading_qualifier_shadowed(
            cur,
            visible_var_info=visible_var_info,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=caller_imports,
            require_expr_scope=True,
        ):
            return None
        direct_fqn = resolve_stdlib_class_fqn(
            cur,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=caller_imports,
        )
        if direct_fqn is not None:
            return direct_fqn
        if callable(static_field_resolver):
            return static_field_resolver(
                cur,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                caller_imports=caller_imports,
            )
    return None


def _is_stdlib_call(
    qual: str | None,
    mname: str,
    chained: bool,
    visible_var_info: dict[str, dict[str, Any]],
    caller_imports: list[str] | None = None,
    *,
    caller_unit: dict[str, Any] | None = None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
    enclosing_class: str | None = None,
    line_clean: str | None = None,
    call_start: int | None = None,
    is_new_ctor_chain: bool = False,
    static_field_resolver: Any = None,
) -> bool:
    """Return True ONLY when receiver identity resolves via JLS §6.5.5.1 to a proven stdlib FQN
    AND `mname` belongs to that specific FQN's API contract (NO global method-name whitelist!).
    """
    imports = list(caller_imports or [])
    if qual == "super":
        return False

    # 0. `new StdlibType(...).method()`
    if is_new_ctor_chain:
        if not qual:
            return False
        fqn = resolve_stdlib_class_fqn(
            qual,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=imports,
        )
        return fqn is not None and mname in _stdlib_methods_for_fqn(fqn)

    # 1. Chained call (`<expr>.method(...)`): MUST prove `<expr>` returns a verified stdlib FQN supporting `mname`!
    if chained:
        if qual is not None or not line_clean or call_start is None:
            return False
        recv_expr = _extract_chain_receiver_expr(line_clean, call_start)
        if not recv_expr:
            return False
        recv_fqn = _resolve_expr_stdlib_fqn(
            recv_expr,
            visible_var_info=visible_var_info,
            caller_imports=imports,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            enclosing_class=enclosing_class,
            static_field_resolver=static_field_resolver,
        )
        return recv_fqn is not None and mname in _stdlib_methods_for_fqn(recv_fqn)

    # 2. Unqualified or `this.method()` inherited from a verified stdlib superclass (e.g. `HttpServlet.getServletContext()`)
    if qual is None or qual == "this":
        return (
            _resolve_inherited_stdlib_method_fqn(
                mname,
                enclosing_class=enclosing_class,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                caller_imports=imports,
            )
            is not None
        )

    # 3. `System.out.*` / `System.err.*` (fail closed if `System`/`java` is shadowed or scope is truncated)
    if qual in ("System.out", "System.err", "java.lang.System.out", "java.lang.System.err"):
        if _is_leading_qualifier_shadowed(
            qual,
            visible_var_info=visible_var_info,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=imports,
            require_expr_scope=True,
        ):
            return False
        sys_qual = qual.rsplit(".", 1)[0]
        if (
            resolve_stdlib_class_fqn(
                sys_qual,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                caller_imports=imports,
            )
            == "java.lang.System"
        ):
            return mname in _stdlib_methods_for_fqn("java.io.PrintStream")
        return False

    # 4. Declared local/param/field receivers FIRST (even if variable is named `req`/`stmt`/`log`)!
    if "." not in qual and qual in visible_var_info:
        vinfo = visible_var_info[qual]
        decl_ref = vinfo.get("declared_type_ref")
        fqn = resolve_stdlib_class_fqn(
            decl_ref,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=imports,
        )
        if fqn is not None and mname in _stdlib_methods_for_fqn(fqn):
            return True
        # Known local/param/field whose type is NOT proven stdlib (including `com.evil.String`,
        # same-package shadowed `audit.Integer`, `CustomStore`, or `var`) MUST NEVER bypass helper verification!
        return False

    # 5. Qualified type (`java.lang.Integer`), simple uppercase type (`Integer`, `Files`, `DriverManager`),
    # or SHA-256-verified static stdlib-typed field (`pkg.Helper.STATIC_JDBC_TEMPLATE`):
    # MUST prove exact stdlib FQN under JLS §6.5.5.1 AND verify leading identifier is NOT shadowed!
    if "." in qual or qual[0].isupper():
        if not _is_leading_qualifier_shadowed(
            qual,
            visible_var_info=visible_var_info,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=imports,
            require_expr_scope=True,
        ):
            fqn = resolve_stdlib_class_fqn(
                qual,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                caller_imports=imports,
            )
            if fqn is not None and mname in _stdlib_methods_for_fqn(fqn):
                return True
        if "." in qual and callable(static_field_resolver):
            first_seg = qual.strip().split(".", 1)[0]
            expr_shadowed = (
                not first_seg
                or first_seg in ("this", "super")
                or (visible_var_info is not None and first_seg in visible_var_info)
                or (
                    isinstance(caller_unit, dict)
                    and int(caller_unit.get("min_line") or 1) > 1
                    and not caller_unit.get("has_complete_scope_context", True)
                )
            )
            if not expr_shadowed and qual.count(".") >= 2:
                expr_shadowed = _is_leading_qualifier_shadowed(
                    qual,
                    visible_var_info=visible_var_info,
                    caller_unit=caller_unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                    caller_imports=imports,
                    require_expr_scope=True,
                )
            if not expr_shadowed:
                fqn = static_field_resolver(
                    qual,
                    caller_unit=caller_unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                    caller_imports=imports,
                )
                if fqn is not None and mname in _stdlib_methods_for_fqn(fqn):
                    return True
        return False

    # 6. Undeclared lowercase receiver has NO verified Java type evidence -> ALWAYS fail closed.
    return False


def _resolve_package_for_simple_class(
    simple_cls: str,
    caller_pkg: str | None,
    caller_imports: list[str],
    all_units: list[dict[str, Any]],
    *,
    caller_unit: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Find unambiguous target `(unit, cls_info)` candidates for an unqualified class name per JLS §6.5.5.1."""
    classified = _classify_java_imports(caller_unit, caller_imports)
    # Single-static-import (`import static p.Outer.Cls;`) takes Precedence 2 over same-package top-level classes!
    if any("." in imp and imp.rsplit(".", 1)[1] == simple_cls for imp in classified["single_static_imports"]):
        return []
    explicit_single = [
        imp
        for imp in classified["single_type_imports"]
        if "." in imp and imp.rsplit(".", 1)[1] == simple_cls
    ]
    if len(explicit_single) > 1:
        return []
    explicit_pkgs: set[str] = set()
    if len(explicit_single) == 1:
        pkg_part = explicit_single[0].rsplit(".", 1)[0]
        if not all(s and s[0].islower() for s in pkg_part.split(".")):
            # Nested type import (`import p.Outer.Cls;`) beats same-package -> cannot bind to top-level class
            return []
        explicit_pkgs.add(pkg_part)

    candidates: list[dict[str, Any]] = []
    for unit in all_units:
        cls_info = unit["classes"].get(simple_cls)
        if cls_info is None:
            continue
        h_pkg = unit.get("package_name")
        if h_pkg is None and unit.get("min_line", 1) > 1 and not unit.get("has_complete_header", False):
            # Snippet started mid-file; cannot safely assume default package
            continue
        if explicit_pkgs:
            if h_pkg in explicit_pkgs:
                candidates.append({"unit": unit, "class_info": cls_info})
        elif caller_pkg is not None:
            if h_pkg == caller_pkg:
                candidates.append({"unit": unit, "class_info": cls_info})
        else:
            # Caller is in default package: same-package (default package) classes take precedence over wildcard imports
            if h_pkg is None:
                candidates.append({"unit": unit, "class_info": cls_info})
    return candidates


def _resolve_type_ref_to_candidates(
    tref: _JavaTypeRef | None,
    caller_pkg: str | None,
    caller_imports: list[str],
    all_units: list[dict[str, Any]],
    *,
    caller_unit: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Resolve a package-preserving `_JavaTypeRef` to exact verified `(unit, cls_info)` candidates."""
    if tref is None or tref.is_var or tref.is_nested_or_ambiguous:
        return []
    if tref.is_qualified:
        if not tref.package_name:
            return []
        return [
            {"unit": u, "class_info": u["classes"][tref.simple_name]}
            for u in all_units
            if tref.simple_name in u["classes"] and u.get("package_name") == tref.package_name
        ]
    return _resolve_package_for_simple_class(
        tref.simple_name,
        caller_pkg,
        caller_imports,
        all_units,
        caller_unit=caller_unit,
    )


def _resolve_and_verify_call(
    *,
    qual: str | None,
    mname: str,
    chained: bool,
    is_new_ctor_chain: bool,
    arg_count: int | None,
    caller_unit: dict[str, Any],
    enclosing_class: str | None,
    enclosing_method: dict[str, Any] | None,
    visible_var_info: dict[str, dict[str, Any]],
    all_units: list[dict[str, Any]],
) -> tuple[bool, dict[str, Any] | None]:
    """Strictly verify call site target identity, package, static/instance mode, dispatch, inheritance, and arity."""
    if chained or qual == "super" or arg_count is None:
        return False, None

    caller_pkg = caller_unit.get("package_name")
    caller_imports = caller_unit.get("imports") or []

    def _verify_method_lines(unit: dict[str, Any], method: dict[str, Any]) -> bool:
        hs = method.get("header_line") or method.get("start_line")
        he = method.get("end_line")
        lmap = unit.get("line_map") or {}
        return type(hs) is int and type(he) is int and he >= hs and all(ln in lmap for ln in range(hs, he + 1))

    # 1. Local unqualified or `this.m(...)` inside `enclosing_class`
    if not is_new_ctor_chain and (qual is None or qual == "this"):
        if not enclosing_class:
            return False, None
        cls_info = caller_unit["classes"].get(enclosing_class)
        # Primary/focused verified snippets often start at the enclosing method header (line > class header),
        # so the enclosing `class` declaration sits just above `min_line`. Allow private/static/final resolution
        # within that scoped snippet only when no inner/other `class` declaration appeared in `caller_unit`.
        in_scoped_snippet = cls_info is None and not caller_unit["classes"] and int(caller_unit.get("min_line") or 1) > 1
        if cls_info is None and not in_scoped_snippet:
            return False, None
        owner_methods = [
            m for m in caller_unit["methods"]
            if m.get("name") == mname
            and (
                (cls_info is not None and m.get("owner_class") == enclosing_class)
                or (in_scoped_snippet and m.get("owner_class") is None)
            )
        ]
        if not owner_methods:
            return False, None
        arity_hits = [m for m in owner_methods if _method_matches_arity(m.get("parameters"), arg_count)]
        if len(arity_hits) != 1:
            return False, None
        target = arity_hits[0]
        if target.get("_is_abstract"):
            return False, None
        if enclosing_method and enclosing_method.get("_is_static") and not target.get("_is_static"):
            return False, None
        # Prevent dynamic dispatch via subclass overrides unless non-virtual (`private`/`static`/`final`) or `final class`
        non_virtual = (
            bool(target.get("_is_private"))
            or bool(target.get("_is_static"))
            or bool(target.get("_is_final"))
            or (cls_info is not None and bool(cls_info.get("is_final")) and not cls_info.get("extends"))
        )
        if not non_virtual:
            return False, None
        if not _verify_method_lines(caller_unit, target):
            return False, None
        return True, {"unit": caller_unit, "class_info": cls_info, "method": target}

    # 2. `new ClassName(...).m(...)` or `new pkg.ClassName(...).m(...)` (instance call on concrete new object)
    if is_new_ctor_chain and qual:
        ctor_ref = _parse_java_type_ref(qual)
        cands = _resolve_type_ref_to_candidates(ctor_ref, caller_pkg, caller_imports, all_units, caller_unit=caller_unit)
        if len(cands) != 1:
            return False, None
        cand = cands[0]
        cls_info = cand["class_info"]
        if cls_info.get("kind") != "class" or cls_info.get("is_abstract") or cls_info.get("extends"):
            return False, None
        u = cand["unit"]
        cls_methods = [m for m in u["methods"] if m.get("owner_class") == cls_info["name"] and m.get("name") == mname]
        arity_hits = [m for m in cls_methods if _method_matches_arity(m.get("parameters"), arg_count)]
        if len(arity_hits) != 1:
            return False, None
        target = arity_hits[0]
        if target.get("_is_static") or target.get("_is_abstract"):
            return False, None
        if not _verify_method_lines(u, target):
            return False, None
        return True, {"unit": u, "class_info": cls_info, "method": target}

    assert qual is not None
    first_seg = qual.split(".", 1)[0]

    # 3. Variable receiver `v.m(...)` (must prove package-qualified concrete non-reassigned runtime type)
    if first_seg in visible_var_info:
        if "." in qual:
            return False, None
        vinfo = visible_var_info[qual]
        concrete_ref: _JavaTypeRef | None = vinfo.get("concrete_type_ref")
        if vinfo.get("reassigned") or concrete_ref is None:
            return False, None
        cands = _resolve_type_ref_to_candidates(concrete_ref, caller_pkg, caller_imports, all_units, caller_unit=caller_unit)
        if len(cands) != 1:
            return False, None
        cand = cands[0]
        cls_info = cand["class_info"]
        if cls_info.get("kind") != "class" or cls_info.get("is_abstract") or cls_info.get("extends"):
            return False, None
        u = cand["unit"]
        cls_methods = [m for m in u["methods"] if m.get("owner_class") == concrete_ref.simple_name and m.get("name") == mname]
        arity_hits = [m for m in cls_methods if _method_matches_arity(m.get("parameters"), arg_count)]
        if len(arity_hits) != 1:
            return False, None
        target = arity_hits[0]
        if target.get("_is_static") or target.get("_is_abstract"):
            return False, None
        if not _verify_method_lines(u, target):
            return False, None
        return True, {"unit": u, "class_info": cls_info, "method": target}

    # 4. Fully package-qualified static call `pkg.ClassName.m(...)`
    if "." in qual:
        q_ref = _parse_java_type_ref(qual)
        if q_ref is None or not q_ref.is_qualified or q_ref.is_nested_or_ambiguous:
            return False, None
        cands = _resolve_type_ref_to_candidates(q_ref, caller_pkg, caller_imports, all_units, caller_unit=caller_unit)
        if len(cands) != 1:
            return False, None
        cand = cands[0]
        cls_info = cand["class_info"]
        if cls_info.get("extends"):
            return False, None
        u = cand["unit"]
        cls_methods = [m for m in u["methods"] if m.get("owner_class") == q_ref.simple_name and m.get("name") == mname]
        arity_hits = [m for m in cls_methods if _method_matches_arity(m.get("parameters"), arg_count)]
        if len(arity_hits) != 1:
            return False, None
        target = arity_hits[0]
        if not target.get("_is_static") or target.get("_is_abstract"):
            return False, None
        if not _verify_method_lines(u, target):
            return False, None
        return True, {"unit": u, "class_info": cls_info, "method": target}

    # 5. Simple class static call `ClassName.m(...)`
    if qual[0].isupper():
        cands = _resolve_package_for_simple_class(qual, caller_pkg, caller_imports, all_units, caller_unit=caller_unit)
        if len(cands) != 1:
            return False, None
        cand = cands[0]
        cls_info = cand["class_info"]
        if cls_info.get("extends"):
            return False, None
        u = cand["unit"]
        cls_methods = [m for m in u["methods"] if m.get("owner_class") == qual and m.get("name") == mname]
        arity_hits = [m for m in cls_methods if _method_matches_arity(m.get("parameters"), arg_count)]
        if len(arity_hits) != 1:
            return False, None
        target = arity_hits[0]
        if not target.get("_is_static") or target.get("_is_abstract"):
            return False, None
        if not _verify_method_lines(u, target):
            return False, None
        return True, {"unit": u, "class_info": cls_info, "method": target}

    return False, None


def load_verified_primary_unit_header(record: dict[str, Any], p_path: str | None) -> dict[str, Any] | None:
    """When snippet lines begin mid-file, read the full primary Java file from `record['root']` ONLY if its SHA-256
    matches `record['snapshots'][p_path]['sha256']`, preserving exact `type_imports`, `static_imports`, classes,
    enclosing class fields, and superclass metadata.
    """
    if not isinstance(p_path, str) or not p_path:
        return None
    root_raw = record.get("root")
    snaps = record.get("snapshots") if isinstance(record.get("snapshots"), dict) else {}
    snap = snaps.get(p_path)
    expected_sha = snap.get("sha256") if isinstance(snap, dict) else None
    if not isinstance(root_raw, str) or not root_raw.strip() or not isinstance(expected_sha, str):
        return None
    try:
        root_dir = Path(root_raw).resolve(strict=True)
        fp = (root_dir / p_path).resolve(strict=True)
        fp.relative_to(root_dir)
        if not fp.is_file() or fp.stat().st_size > 2_000_000:
            return None
        raw = fp.read_bytes()
    except (OSError, ValueError):
        return None
    if digest(raw) != expected_sha:
        return None
    text = raw.decode("utf-8", errors="replace")
    parsed = parse_java_structure_v2(text)
    cls_by_name = {c["name"]: c for c in (parsed.get("classes") or []) if isinstance(c.get("name"), str)}
    jctx = record.get("java_context") if isinstance(record.get("java_context"), dict) else {}
    enc_cls = jctx.get("enclosing_class") if isinstance(jctx.get("enclosing_class"), str) else None
    fields = sorted(extract_class_field_names(text, structure=parsed, enclosing_class=enc_cls))
    field_types = extract_class_field_types(text, structure=parsed, enclosing_class=enc_cls)
    declared_methods = sorted(extract_class_declared_method_names(text, structure=parsed, enclosing_class=enc_cls))
    enc_extends = cls_by_name.get(enc_cls, {}).get("extends") if enc_cls and enc_cls in cls_by_name else None
    return {
        "package_name": parsed.get("package_name"),
        "imports": list(parsed.get("imports") or []),
        "type_imports": list(parsed.get("type_imports") or []),
        "static_imports": list(parsed.get("static_imports") or []),
        "classes": cls_by_name,
        "methods": list(parsed.get("methods") or []),
        "declared_class_names": list(cls_by_name.keys()),
        "enclosing_class_fields": fields,
        "enclosing_class_field_types": field_types,
        "enclosing_class_declared_methods": declared_methods,
        "enclosing_class_extends": enc_extends,
    }


def _merge_header_metadata_into_unit(
    caller_unit: dict[str, Any],
    record: dict[str, Any],
    p_path: str | None,
) -> None:
    """Populate `type_imports`, `static_imports`, `declared_class_names`, `enclosing_class_fields`,
    `enclosing_class_field_types`, `enclosing_class_declared_methods`, and `extends` when snippet lines
    do not start at line 1, using `jctx` and/or SHA-256-verified source file on disk.
    """
    jctx = record.get("java_context") if isinstance(record.get("java_context"), dict) else {}
    if caller_unit.get("has_complete_header"):
        # Snippet starts at line 1, so parsed imports/classes are authoritative; also fill fields & declared methods.
        lmap = caller_unit.get("line_map") or {}
        enc_cls = jctx.get("enclosing_class") if isinstance(jctx.get("enclosing_class"), str) else None
        enc_jctx = jctx.get("enclosing_method") if isinstance(jctx.get("enclosing_method"), dict) else None
        caller_unit["has_complete_scope_context"] = bool(
            enc_jctx is None or (type(enc_jctx.get("header_line")) is int and enc_jctx["header_line"] in lmap)
        )
        if lmap and ("enclosing_class_fields" not in caller_unit or "enclosing_class_field_types" not in caller_unit or "enclosing_class_declared_methods" not in caller_unit):
            max_ln = max(lmap)
            full_txt = "\n".join(lmap.get(i, "") for i in range(1, max_ln + 1))
            parsed_full = parse_java_structure_v2(full_txt)
            caller_unit.setdefault(
                "enclosing_class_fields",
                sorted(extract_class_field_names(full_txt, structure=parsed_full, enclosing_class=enc_cls)),
            )
            caller_unit.setdefault(
                "enclosing_class_field_types",
                extract_class_field_types(full_txt, structure=parsed_full, enclosing_class=enc_cls),
            )
            caller_unit.setdefault(
                "enclosing_class_declared_methods",
                sorted(extract_class_declared_method_names(full_txt, structure=parsed_full, enclosing_class=enc_cls)),
            )
        else:
            if "enclosing_class_fields" not in caller_unit and isinstance(jctx.get("enclosing_class_fields"), list):
                caller_unit["enclosing_class_fields"] = [str(x) for x in jctx["enclosing_class_fields"] if isinstance(x, str)]
            if "enclosing_class_field_types" not in caller_unit and isinstance(jctx.get("enclosing_class_field_types"), dict):
                caller_unit["enclosing_class_field_types"] = {
                    str(k): str(v) for k, v in jctx["enclosing_class_field_types"].items() if isinstance(k, str) and isinstance(v, str)
                }
            if "enclosing_class_declared_methods" not in caller_unit and isinstance(jctx.get("enclosing_class_declared_methods"), list):
                caller_unit["enclosing_class_declared_methods"] = [
                    str(x) for x in jctx["enclosing_class_declared_methods"] if isinstance(x, str)
                ]
        return

    # Mid-file snippet: prefer SHA-256-verified disk source first, then structured jctx metadata.
    disk_hdr = load_verified_primary_unit_header(record, p_path)
    if disk_hdr is not None:
        caller_unit["package_name"] = disk_hdr["package_name"]
        caller_unit["imports"] = disk_hdr["imports"]
        caller_unit["type_imports"] = disk_hdr["type_imports"]
        caller_unit["static_imports"] = disk_hdr["static_imports"]
        caller_unit["declared_class_names"] = disk_hdr["declared_class_names"]
        caller_unit["enclosing_class_fields"] = disk_hdr["enclosing_class_fields"]
        caller_unit["enclosing_class_field_types"] = disk_hdr["enclosing_class_field_types"]
        caller_unit["enclosing_class_declared_methods"] = disk_hdr["enclosing_class_declared_methods"]
        caller_unit["enclosing_class_extends"] = disk_hdr["enclosing_class_extends"]
        if not caller_unit.get("classes"):
            caller_unit["classes"] = disk_hdr["classes"]
            # Backfill `owner_class` on snippet-parsed methods whose enclosing class header sat above `min_line`
            cls_list = list(disk_hdr["classes"].values())
            for m in caller_unit.get("methods") or []:
                if isinstance(m, dict) and m.get("owner_class") is None and type(m.get("header_line")) is int:
                    best_span: int | None = None
                    owner_cls: str | None = None
                    for cls in cls_list:
                        if cls["start_line"] <= m["header_line"] <= cls["end_line"]:
                            span = cls["end_line"] - cls["start_line"]
                            if best_span is None or span < best_span:
                                best_span = span
                                owner_cls = cls["name"]
                    m["owner_class"] = owner_cls
        caller_unit["has_complete_header"] = True
        caller_unit["has_complete_scope_context"] = True
        return

    jctx_has_header = "imports" in jctx and isinstance(jctx.get("imports"), list)
    if not caller_unit.get("package_name") and isinstance(jctx.get("package_name"), str):
        caller_unit["package_name"] = jctx["package_name"]
    if jctx_has_header:
        j_imps = [str(x) for x in jctx["imports"] if isinstance(x, str)]
        if not caller_unit.get("imports"):
            caller_unit["imports"] = j_imps
        if isinstance(jctx.get("type_imports"), list) and isinstance(jctx.get("static_imports"), list):
            caller_unit["type_imports"] = [str(x) for x in jctx["type_imports"] if isinstance(x, str)]
            caller_unit["static_imports"] = [str(x) for x in jctx["static_imports"] if isinstance(x, str)]
        else:
            # No explicit split available: clear split lists so `_classify_java_imports` runs safe heuristic fallback
            caller_unit.pop("type_imports", None)
            caller_unit.pop("static_imports", None)
        if isinstance(jctx.get("declared_class_names"), list):
            caller_unit["declared_class_names"] = [str(x) for x in jctx["declared_class_names"] if isinstance(x, str)]
        if isinstance(jctx.get("enclosing_class_fields"), list):
            caller_unit["enclosing_class_fields"] = [str(x) for x in jctx["enclosing_class_fields"] if isinstance(x, str)]
        if isinstance(jctx.get("enclosing_class_field_types"), dict):
            caller_unit["enclosing_class_field_types"] = {
                str(k): str(v) for k, v in jctx["enclosing_class_field_types"].items() if isinstance(k, str) and isinstance(v, str)
            }
        if isinstance(jctx.get("enclosing_class_declared_methods"), list):
            caller_unit["enclosing_class_declared_methods"] = [
                str(x) for x in jctx["enclosing_class_declared_methods"] if isinstance(x, str)
            ]
        if isinstance(jctx.get("enclosing_class_extends"), str):
            caller_unit["enclosing_class_extends"] = jctx["enclosing_class_extends"]
        caller_unit["has_complete_header"] = True
        lmap = caller_unit.get("line_map") or {}
        enc_jctx = jctx.get("enclosing_method") if isinstance(jctx.get("enclosing_method"), dict) else None
        enc_hdr_in_snippet = (
            enc_jctx is None
            or (type(enc_jctx.get("header_line")) is int and enc_jctx["header_line"] in lmap)
        )
        has_verified_fields = isinstance(jctx.get("enclosing_class_fields"), list)
        caller_unit["has_complete_scope_context"] = bool(has_verified_fields and enc_hdr_in_snippet)
    else:
        caller_unit["has_complete_scope_context"] = False


_FLOW_JAVA_KEYWORDS = frozenset(
    {
        "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class",
        "const", "continue", "default", "do", "double", "else", "enum", "extends", "false",
        "final", "finally", "float", "for", "goto", "if", "implements", "import", "instanceof",
        "int", "interface", "long", "native", "new", "null", "package", "private", "protected",
        "public", "return", "short", "static", "strictfp", "super", "switch", "synchronized",
        "this", "throw", "throws", "transient", "true", "try", "var", "void", "volatile",
        "while", "yield",
    }
)
_FLOW_PRIMITIVE_OR_VAR_TYPES = frozenset(
    {"boolean", "byte", "char", "double", "float", "int", "long", "short", "var"}
)
_FLOW_NON_TYPE_KEYWORDS = _FLOW_JAVA_KEYWORDS - _FLOW_PRIMITIVE_OR_VAR_TYPES

_FLOW_IMMUTABLE_TYPES = frozenset(
    {
        "boolean", "byte", "char", "short", "int", "long", "float", "double",
        "java.lang.String", "java.lang.Boolean", "java.lang.Byte", "java.lang.Character",
        "java.lang.Short", "java.lang.Integer", "java.lang.Long", "java.lang.Float",
        "java.lang.Double", "java.math.BigInteger", "java.math.BigDecimal",
        "java.util.UUID", "java.nio.file.Path",
    }
)

_METHOD_REF_SITE_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*(?:\s*<[^>{};()]*>)?(?:\s*\[\s*\])*)"
    r"\s*::\s*(?:<[^>{};()]*>\s*)?(new|[A-Za-z_][A-Za-z0-9_]*)"
)

_FLOW_MUTATING_STDLIB_METHODS = frozenset(
    {
        "append", "insert", "delete", "replace", "reverse", "add", "addAll", "put",
        "putIfAbsent", "set", "remove", "clear", "setString", "setInt", "setLong",
        "setShort", "setByte", "setDouble", "setFloat", "setBoolean", "setObject",
        "setNull", "setTimestamp", "setDate", "setTime", "setBytes", "setBigDecimal",
        "clearParameters", "setParameter", "setProperty", "load", "setAttribute",
        "removeAttribute", "setText",
    }
)

_JDBC_RESOURCE_HANDLE_FQNS = frozenset(
    {
        "java.sql.Connection",
        "javax.sql.DataSource",
        "java.sql.Statement",
        "java.sql.PreparedStatement",
        "java.sql.CallableStatement",
    }
)

_SQL_SINK_RECEIVER_FQNS = frozenset(
    {
        "java.sql.Statement",
        "java.sql.PreparedStatement",
        "java.sql.CallableStatement",
        "java.sql.Connection",
        "org.springframework.jdbc.core.JdbcTemplate",
        "org.springframework.jdbc.core.JdbcOperations",
        "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate",
        "org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations",
        "javax.persistence.EntityManager",
        "jakarta.persistence.EntityManager",
        "org.hibernate.Session",
    }
)

_SQL_SINK_METHODS = frozenset(
    {
        "executeQuery", "executeUpdate", "execute", "executeLargeUpdate", "addBatch",
        "prepareStatement", "prepareCall",
        "query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet",
        "update", "batchUpdate",
        "createNativeQuery", "createQuery", "createSQLQuery",
    }
)

_TAINT_SOURCE_METHOD_RE = re.compile(
    r"\b(?:getParameter|getParameterValues|getParameterMap|getParameterNames|"
    r"getHeader|getHeaders|getHeaderNames|getCookies|getQueryString|getPathInfo|"
    r"getRequestURI|getRequestURL|getServletPath|getReader|getInputStream|"
    r"getOriginalFilename|getSubmittedFileName|getText|getPassword)\s*\("
)

_FLOW_ASSIGN_STMT_RE = re.compile(
    r"^\s*(?:final\s+)?(?:([A-Za-z_][A-Za-z0-9_<>,.\[\]]*(?:\s*\[\s*\])*)\s+)?"
    r"((?:this\s*\.\s*)?[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]*\])?(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*)\s*"
    r"(<<=|>>=|>>>=|[+\-*/%&|^]?=)\s*(.+?)\s*;?\s*$"
)
_FLOW_DECL_ONLY_RE = re.compile(
    r"^\s*(?:final\s+)?([A-Za-z_][A-Za-z0-9_<>,.\[\]]*(?:\s*\[\s*\])*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;?\s*$"
)
_FLOW_MULTI_DECL_RE = re.compile(
    r"^\s*(?:final\s+)?([A-Za-z_][A-Za-z0-9_<>,.\[\]]*(?:\s*\[\s*\])*)\s+(.+?)\s*;?\s*$"
)


@dataclass(frozen=True)
class _FlowTok:
    kind: str  # WORD | NUM | LIT | SYM
    text: str
    start: int
    end: int
    line: int


@dataclass
class _FlowStmt:
    kind: str
    start_line: int
    end_line: int
    code: str = ""
    lines: set[int] | None = None
    cond_text: str = ""
    cond_lines: set[int] | None = None
    then_stmt: "_FlowStmt | None" = None
    else_stmt: "_FlowStmt | None" = None
    body_stmts: list["_FlowStmt"] | None = None
    body_stmt: "_FlowStmt | None" = None
    catches: list["_FlowStmt"] | None = None
    finally_stmt: "_FlowStmt | None" = None
    resources_text: str = ""
    resource_lines: set[int] | None = None
    subkind: str = ""
    has_brace_or_lambda: bool = False


class _FlowMethodParser:
    """Conservative recursive-descent Java method-body statement parser over comment/string-masked lines."""

    def __init__(self, start_ln: int, end_ln: int, clean_by_ln: dict[int, str]) -> None:
        chunks: list[str] = []
        line_of_off: list[int] = []
        for ln in range(start_ln, end_ln + 1):
            txt = clean_by_ln.get(ln, "")
            chunks.append(txt)
            line_of_off.extend([ln] * len(txt))
            chunks.append("\n")
            line_of_off.append(ln)
        self.stream = "".join(chunks)
        self.line_of_off = line_of_off
        self.parse_errors: list[str] = []
        self.tokens: list[_FlowTok] = self._tokenize()
        self.pos = 0

    def _tokenize(self) -> list[_FlowTok]:
        toks: list[_FlowTok] = []
        s = self.stream
        n = len(s)
        i = 0
        while i < n:
            ch = s[i]
            if ch.isspace():
                i += 1
                continue
            if ch in ('"', "'"):
                quote = ch
                start = i
                i += 1
                while i < n and s[i] != quote:
                    i += 1
                if i < n:
                    i += 1
                else:
                    self.parse_errors.append("unterminated_literal")
                toks.append(_FlowTok("LIT", s[start:i], start, i, self.line_of_off[start]))
                continue
            if ch.isalpha() or ch == "_":
                start = i
                i += 1
                while i < n and (s[i].isalnum() or s[i] == "_"):
                    i += 1
                toks.append(_FlowTok("WORD", s[start:i], start, i, self.line_of_off[start]))
                continue
            if ch.isdigit():
                start = i
                i += 1
                while i < n and (s[i].isalnum() or s[i] == "_"):
                    i += 1
                toks.append(_FlowTok("NUM", s[start:i], start, i, self.line_of_off[start]))
                continue
            if ch == "-" and i + 1 < n and s[i + 1] == ">":
                toks.append(_FlowTok("SYM", "->", i, i + 2, self.line_of_off[i]))
                i += 2
                continue
            toks.append(_FlowTok("SYM", ch, i, i + 1, self.line_of_off[i]))
            i += 1
        return toks

    def _peek(self, offset: int = 0) -> _FlowTok | None:
        idx = self.pos + offset
        return self.tokens[idx] if 0 <= idx < len(self.tokens) else None

    def _slice_span(self, start_off: int, end_off: int) -> tuple[str, set[int]]:
        txt = " ".join(self.stream[start_off:end_off].split())
        lns = {self.line_of_off[i] for i in range(max(0, start_off), min(len(self.line_of_off), end_off))}
        return txt, lns

    def _consume_balanced_parens(self) -> tuple[int, int, int, int, set[int]] | None:
        t = self._peek()
        if t is None or t.kind != "SYM" or t.text != "(":
            self.parse_errors.append("expected_lparen")
            return None
        inner_start = t.end
        open_ln = t.line
        depth = 0
        lines: set[int] = set()
        while self.pos < len(self.tokens):
            cur = self.tokens[self.pos]
            self.pos += 1
            lines.add(cur.line)
            if cur.kind == "SYM" and cur.text == "(":
                depth += 1
            elif cur.kind == "SYM" and cur.text == ")":
                depth -= 1
                if depth == 0:
                    return inner_start, cur.start, open_ln, cur.line, lines
        self.parse_errors.append("unbalanced_parens")
        return None

    def _parse_block(self) -> _FlowStmt:
        open_tok = self._peek()
        if open_tok is None or open_tok.kind != "SYM" or open_tok.text != "{":
            self.parse_errors.append("expected_lbrace")
            ln = open_tok.line if open_tok else 1
            return _FlowStmt("UNKNOWN", ln, ln, lines={ln}, subkind="missing_lbrace")
        self.pos += 1
        stmts: list[_FlowStmt] = []
        end_ln = open_tok.line
        while self.pos < len(self.tokens):
            cur = self._peek()
            if cur is None:
                break
            if cur.kind == "SYM" and cur.text == "}":
                end_ln = cur.line
                self.pos += 1
                return _FlowStmt("BLOCK", open_tok.line, end_ln, body_stmts=stmts)
            st = self.parse_stmt()
            stmts.append(st)
            end_ln = max(end_ln, st.end_line)
        self.parse_errors.append("unclosed_block")
        return _FlowStmt("BLOCK", open_tok.line, end_ln, body_stmts=stmts, subkind="unclosed")

    def parse_method_body(self) -> list[_FlowStmt]:
        stmts: list[_FlowStmt] = []
        while self.pos < len(self.tokens):
            cur = self._peek()
            if cur is None:
                break
            if cur.kind == "SYM" and cur.text == "}":
                self.pos += 1
                break
            stmts.append(self.parse_stmt())
        return stmts

    def parse_stmt(self) -> _FlowStmt:
        tok = self._peek()
        if tok is None:
            return _FlowStmt("EMPTY", 1, 1, lines=set())
        if tok.kind == "SYM" and tok.text == ";":
            self.pos += 1
            return _FlowStmt("EMPTY", tok.line, tok.line, lines={tok.line})
        if tok.kind == "SYM" and tok.text == "{":
            return self._parse_block()
        if tok.kind == "SYM" and tok.text == "}":
            self.parse_errors.append("unexpected_rbrace")
            self.pos += 1
            return _FlowStmt("UNKNOWN", tok.line, tok.line, lines={tok.line}, subkind="unexpected_rbrace")

        if tok.kind == "WORD" and tok.text == "default":
            nxt = self._peek(1)
            if nxt is not None and nxt.kind == "SYM" and nxt.text == ":":
                self.pos += 2
                return _FlowStmt("CASE", tok.line, nxt.line, lines={tok.line, nxt.line}, subkind="default")
        if tok.kind == "WORD" and tok.text == "case":
            self.pos += 1
            end_ln = tok.line
            p_depth = 0
            while self.pos < len(self.tokens):
                cur = self.tokens[self.pos]
                self.pos += 1
                end_ln = cur.line
                if cur.kind == "SYM" and cur.text == "(":
                    p_depth += 1
                elif cur.kind == "SYM" and cur.text == ")":
                    p_depth = max(0, p_depth - 1)
                elif cur.kind == "SYM" and cur.text in (":", "->") and p_depth == 0:
                    return _FlowStmt("CASE", tok.line, end_ln, lines=set(range(tok.line, end_ln + 1)), subkind="case")
            self.parse_errors.append("unterminated_case")
            return _FlowStmt("UNKNOWN", tok.line, end_ln, lines=set(range(tok.line, end_ln + 1)), subkind="malformed_case")

        if tok.kind == "WORD" and tok.text not in ("default", "case"):
            nxt = self._peek(1)
            if nxt is not None and nxt.kind == "SYM" and nxt.text == ":":
                self.pos += 2
                inner = self.parse_stmt()
                return _FlowStmt("LABELED", tok.line, inner.end_line, body_stmt=inner, subkind=tok.text)

        if tok.kind == "WORD" and tok.text == "if":
            self.pos += 1
            cspan = self._consume_balanced_parens()
            if cspan is None:
                return _FlowStmt("UNKNOWN", tok.line, tok.line, lines={tok.line}, subkind="malformed_if")
            cs, ce, _, c_end_ln, c_lines = cspan
            cond_txt, inner_lines = self._slice_span(cs, ce)
            cond_lines = c_lines | inner_lines | {tok.line}
            then_stmt = self.parse_stmt()
            else_stmt: _FlowStmt | None = None
            end_ln = max(c_end_ln, then_stmt.end_line)
            nxt = self._peek()
            if nxt is not None and nxt.kind == "WORD" and nxt.text == "else":
                self.pos += 1
                else_stmt = self.parse_stmt()
                end_ln = max(end_ln, else_stmt.end_line)
            return _FlowStmt(
                "IF",
                tok.line,
                end_ln,
                cond_text=cond_txt,
                cond_lines=cond_lines,
                then_stmt=then_stmt,
                else_stmt=else_stmt,
            )

        if tok.kind == "WORD" and tok.text in ("for", "while"):
            kw = tok.text
            self.pos += 1
            hspan = self._consume_balanced_parens()
            if hspan is None:
                return _FlowStmt("UNKNOWN", tok.line, tok.line, lines={tok.line}, subkind=f"malformed_{kw}")
            hs, he, _, h_end_ln, h_lines = hspan
            hdr_txt, inner_lines = self._slice_span(hs, he)
            body = self.parse_stmt()
            return _FlowStmt(
                "LOOP",
                tok.line,
                max(h_end_ln, body.end_line),
                cond_text=hdr_txt,
                cond_lines=h_lines | inner_lines | {tok.line},
                body_stmt=body,
                subkind=kw,
            )

        if tok.kind == "WORD" and tok.text == "do":
            self.pos += 1
            body = self.parse_stmt()
            nxt = self._peek()
            end_ln = body.end_line
            if nxt is None or nxt.kind != "WORD" or nxt.text != "while":
                self.parse_errors.append("missing_do_while")
                return _FlowStmt("UNKNOWN", tok.line, end_ln, lines={tok.line, end_ln}, subkind="malformed_do")
            self.pos += 1
            hspan = self._consume_balanced_parens()
            if hspan is None:
                return _FlowStmt("UNKNOWN", tok.line, end_ln, lines={tok.line, end_ln}, subkind="malformed_do_while")
            hs, he, _, h_end_ln, h_lines = hspan
            hdr_txt, inner_lines = self._slice_span(hs, he)
            end_ln = max(end_ln, h_end_ln)
            semi = self._peek()
            if semi is not None and semi.kind == "SYM" and semi.text == ";":
                end_ln = max(end_ln, semi.line)
                self.pos += 1
            else:
                self.parse_errors.append("missing_do_while_semi")
            return _FlowStmt(
                "LOOP",
                tok.line,
                end_ln,
                cond_text=hdr_txt,
                cond_lines=h_lines | inner_lines,
                body_stmt=body,
                subkind="do",
            )

        if tok.kind == "WORD" and tok.text == "try":
            self.pos += 1
            res_txt = ""
            res_lines: set[int] = set()
            nxt = self._peek()
            if nxt is not None and nxt.kind == "SYM" and nxt.text == "(":
                rspan = self._consume_balanced_parens()
                if rspan is None:
                    return _FlowStmt("UNKNOWN", tok.line, tok.line, lines={tok.line}, subkind="malformed_try_resources")
                res_txt, inner_rl = self._slice_span(rspan[0], rspan[1])
                res_lines = rspan[4] | inner_rl | {tok.line}
            try_blk = self._parse_block()
            catches: list[_FlowStmt] = []
            finally_blk: _FlowStmt | None = None
            end_ln = try_blk.end_line
            while True:
                c_tok = self._peek()
                if c_tok is not None and c_tok.kind == "WORD" and c_tok.text == "catch":
                    self.pos += 1
                    cspan = self._consume_balanced_parens()
                    if cspan is None:
                        self.parse_errors.append("malformed_catch")
                        break
                    c_blk = self._parse_block()
                    catches.append(c_blk)
                    end_ln = max(end_ln, c_blk.end_line)
                else:
                    break
            f_tok = self._peek()
            if f_tok is not None and f_tok.kind == "WORD" and f_tok.text == "finally":
                self.pos += 1
                finally_blk = self._parse_block()
                end_ln = max(end_ln, finally_blk.end_line)
            return _FlowStmt(
                "TRY",
                tok.line,
                end_ln,
                body_stmt=try_blk,
                catches=catches,
                finally_stmt=finally_blk,
                resources_text=res_txt,
                resource_lines=res_lines,
            )

        if tok.kind == "WORD" and tok.text in ("switch", "synchronized"):
            kw = tok.text
            self.pos += 1
            hspan = self._consume_balanced_parens()
            if hspan is None:
                return _FlowStmt("UNKNOWN", tok.line, tok.line, lines={tok.line}, subkind=f"malformed_{kw}")
            hk, inner_l = self._slice_span(hspan[0], hspan[1])
            blk = self._parse_block()
            return _FlowStmt(
                kw.upper(),
                tok.line,
                blk.end_line,
                cond_text=hk,
                cond_lines=hspan[4] | inner_l | {tok.line},
                body_stmt=blk,
                subkind=kw,
            )

        if tok.kind == "WORD" and tok.text in ("else", "catch", "finally"):
            self.parse_errors.append(f"orphan_{tok.text}")
            self.pos += 1
            return _FlowStmt("UNKNOWN", tok.line, tok.line, lines={tok.line}, subkind=f"orphan_{tok.text}")

        start_tok = tok
        start_off = start_tok.start
        paren_d = 0
        bracket_d = 0
        brace_d = 0
        saw_brace_or_arrow = False
        end_off = start_tok.end
        end_ln = start_tok.line
        terminated = False
        while self.pos < len(self.tokens):
            cur = self.tokens[self.pos]
            if cur.kind == "SYM":
                if cur.text == "(":
                    paren_d += 1
                elif cur.text == ")":
                    if paren_d == 0:
                        self.parse_errors.append("unmatched_rparen")
                        self.pos += 1
                        break
                    paren_d -= 1
                elif cur.text == "[":
                    bracket_d += 1
                elif cur.text == "]":
                    bracket_d = max(0, bracket_d - 1)
                elif cur.text == "{":
                    brace_d += 1
                    saw_brace_or_arrow = True
                elif cur.text == "}":
                    if brace_d == 0 and paren_d == 0 and bracket_d == 0:
                        self.parse_errors.append("missing_semi_before_rbrace")
                        break
                    brace_d = max(0, brace_d - 1)
                elif cur.text == "->":
                    saw_brace_or_arrow = True
                elif cur.text == ";" and paren_d == 0 and bracket_d == 0 and brace_d == 0:
                    end_off = cur.end
                    end_ln = cur.line
                    self.pos += 1
                    terminated = True
                    break
            end_off = cur.end
            end_ln = cur.line
            self.pos += 1
        code_txt, code_lines = self._slice_span(start_off, end_off)
        if not code_lines:
            code_lines = set(range(start_tok.line, end_ln + 1))
        if not terminated:
            self.parse_errors.append("unterminated_statement")
            return _FlowStmt("UNKNOWN", start_tok.line, end_ln, code=code_txt, lines=code_lines, subkind="unterminated")
        if start_tok.kind == "WORD" and start_tok.text in ("return", "throw"):
            return _FlowStmt(
                "EXIT",
                start_tok.line,
                end_ln,
                code=code_txt,
                lines=code_lines,
                subkind=start_tok.text,
                has_brace_or_lambda=saw_brace_or_arrow,
            )
        return _FlowStmt(
            "SIMPLE",
            start_tok.line,
            end_ln,
            code=code_txt,
            lines=code_lines,
            has_brace_or_lambda=saw_brace_or_arrow,
        )


def _find_method_body_open_brace(clean_by_ln: dict[int, str], header_line: int, end_line: int) -> tuple[int, int] | None:
    """Locate `(line_no, col_after_open_brace)` for the enclosing method header's opening `{`."""
    paren_d = 0
    seen_open = False
    for ln in range(header_line, end_line + 1):
        txt = clean_by_ln.get(ln, "")
        for idx, ch in enumerate(txt):
            if ch == "(":
                paren_d += 1
                seen_open = True
            elif ch == ")" and paren_d > 0:
                paren_d -= 1
            elif ch == "{" and seen_open and paren_d == 0:
                if txt[idx + 1 :].strip():
                    return (ln, idx + 1)
                return (ln + 1, 0)
    return None


def _split_top_level_char(text: str, sep: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in text:
        if ch in "([{":
            depth += 1
            buf.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == sep and depth == 0:
            item = "".join(buf).strip()
            if item:
                parts.append(item)
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _split_top_level_bool_clauses(expr: str) -> list[str]:
    """Split a Java boolean condition on top-level `&&` and `||` operators."""
    clauses: list[str] = []
    buf: list[str] = []
    depth = 0
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if ch in "([{":
            depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
            i += 1
            continue
        if depth == 0 and i + 1 < n and expr[i : i + 2] in ("&&", "||"):
            item = "".join(buf).strip()
            if item:
                clauses.append(item)
            buf = []
            i += 2
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        clauses.append(tail)
    return clauses


def _extract_class_final_fields(
    caller_unit: dict[str, Any],
    enclosing_class: str | None,
) -> set[str]:
    """Return names of fields explicitly declared `final` directly on `enclosing_class`."""
    lmap = caller_unit.get("line_map") or {}
    if not lmap:
        return set()
    min_ln = min(lmap)
    max_ln = max(lmap)
    virtual = [lmap.get(i, "") for i in range(1, max_ln + 1)]
    clean_lines = _strip_comments_and_strings_preserve_lines("\n".join(virtual))
    classes = list((caller_unit.get("classes") or {}).values())
    methods = caller_unit.get("methods") or []
    target_classes = [c for c in classes if not enclosing_class or c.get("name") == enclosing_class]
    if not target_classes:
        target_classes = classes
    finals: set[str] = set()
    for cls in target_classes:
        cs = int(cls.get("start_line") or 1)
        ce = int(cls.get("end_line") or max_ln)
        excluded: list[tuple[int, int]] = []
        for m in methods:
            ms = int(m.get("header_line") or m.get("start_line") or 0)
            me = int(m.get("end_line") or 0)
            if cs < ms <= ce:
                excluded.append((ms, me))
        for other in classes:
            if other is cls:
                continue
            os_ln = int(other.get("start_line") or 0)
            oe_ln = int(other.get("end_line") or 0)
            if cs < os_ln <= oe_ln <= ce:
                excluded.append((os_ln, oe_ln))
        for lno in range(max(min_ln, cs + 1), min(ce, len(clean_lines)) + 1):
            if lno not in lmap or any(lo <= lno <= hi for lo, hi in excluded):
                continue
            cl = clean_lines[lno - 1].strip()
            if not cl or "final" not in cl:
                continue
            m_f = _FIELD_DECL_STMT_RE.match(cl)
            if not m_f:
                continue
            prefix_mods = cl[: m_f.start(1)]
            if not re.search(r"\bfinal\b", prefix_mods):
                continue
            for item in _split_top_level_commas(m_f.group(2)):
                lhs = re.sub(r"\s*\[\s*\]\s*", "", item.split("=", 1)[0]).strip()
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", lhs) and lhs not in _FLOW_JAVA_KEYWORDS:
                    finals.add(lhs)
    return finals


def _extract_expr_var_idents(
    expr: str,
    *,
    visible_var_info: dict[str, dict[str, Any]],
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None,
    all_units: list[dict[str, Any]] | None,
) -> set[str]:
    """Extract variable/field identifiers referenced by a comment/string-masked Java expression.

    Excludes Java keywords, method names (`foo(...)` / `.bar(...)`), constructor type names (`new Type(...)`),
    and unshadowed static stdlib class qualifiers (`Paths.get(...)`, `java.lang.Integer.parseInt(...)`).
    """
    if not expr or not expr.strip():
        return set()
    # Mask `new [pkg.]Type<...>` type headers while preserving constructor arguments inside `(...)`
    masked = re.sub(
        r"\bnew\s+[A-Za-z_][A-Za-z0-9_.]*(?:\s*<[^>{};()]*>)?(?=\s*\(|\s*\[)",
        " ",
        expr,
    )
    # Mask simple Java type casts like `(String)` or `(java.lang.String)` when not a variable expr
    masked = re.sub(r"\(\s*(?:[a-z_][a-z0-9_]*\.)*[A-Z][A-Za-z0-9_]*(?:\s*\[\s*\])*\s*\)", " ", masked)

    idents: set[str] = set()
    n = len(masked)
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*)\b", masked):
        chain_raw = m.group(1)
        start_i = m.start()
        end_i = m.end()
        # Check if immediately preceded by `.` or `::` (chained method/field or method reference target)
        prev_j = start_i - 1
        while prev_j >= 0 and masked[prev_j].isspace():
            prev_j -= 1
        after_dot = prev_j >= 0 and masked[prev_j] == "."
        after_double_colon = prev_j >= 1 and masked[prev_j - 1 : prev_j + 1] == "::"
        next_j = end_i
        while next_j < n and masked[next_j].isspace():
            next_j += 1
        followed_by_lparen = next_j < n and masked[next_j] == "("
        followed_by_double_colon = next_j + 1 < n and masked[next_j : next_j + 2] == "::"

        parts = [p.strip() for p in chain_raw.split(".")]
        if after_double_colon:
            # Target method/ctor name after `::` (e.g., `String::trim`, `ExternalSanitizer::clean`)
            continue
        if after_dot:
            # Chained `.method(...)` or `.field` after a parenthesized receiver
            if not followed_by_lparen and not followed_by_double_colon and len(parts) == 1 and parts[0] not in _FLOW_JAVA_KEYWORDS:
                idents.add(parts[0])
            continue

        if len(parts) == 1:
            tok = parts[0]
            if tok == "this":
                idents.add("this")
                continue
            if tok in _FLOW_JAVA_KEYWORDS or followed_by_lparen:
                continue
            if tok in visible_var_info:
                idents.add(tok)
                continue
            if tok[0].isupper() and resolve_stdlib_class_fqn(
                tok,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
            ) is not None:
                continue
            idents.add(tok)
            continue

        # Dotted chain: `a.b.c` or `a.b.c(...)`
        first = parts[0]
        if first == "this":
            idents.add("this")
            if len(parts) >= 2 and parts[1] not in _FLOW_JAVA_KEYWORDS:
                if not (len(parts) == 2 and followed_by_lparen):
                    idents.add(parts[1])
            continue
        if first == "super":
            continue
        if first in visible_var_info:
            idents.add(first)
            continue
        # Static/package qualified call or constant (`java.lang.System.out.println(...)`, `File.separator`, `Pkg.Cls.m(...)`)
        prefix_for_type = ".".join(parts[:-1]) if followed_by_lparen else ".".join(parts)
        if prefix_for_type in ("System.out", "System.err", "java.lang.System.out", "java.lang.System.err"):
            sys_type = prefix_for_type.rsplit(".", 1)[0]
            if (
                not _is_leading_qualifier_shadowed(
                    prefix_for_type,
                    visible_var_info=visible_var_info,
                    caller_unit=caller_unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                    require_expr_scope=True,
                )
                and resolve_stdlib_class_fqn(
                    sys_type,
                    caller_unit=caller_unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                )
                == "java.lang.System"
            ):
                continue
        type_cand = prefix_for_type if followed_by_lparen else ".".join(parts[:-1])
        if (
            type_cand
            and not _is_leading_qualifier_shadowed(
                type_cand,
                visible_var_info=visible_var_info,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                require_expr_scope=True,
            )
            and resolve_stdlib_class_fqn(
                type_cand,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
            )
            is not None
        ):
            continue
        # Non-stdlib static field/class read (`GlobalState.CURRENT_EMAIL`) -> record leading root unless static call
        if not followed_by_lparen:
            if first not in _FLOW_JAVA_KEYWORDS:
                idents.add(first)
    return idents


def _is_proven_immutable_var(
    vname: str,
    *,
    visible_var_info: dict[str, dict[str, Any]],
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None,
    all_units: list[dict[str, Any]] | None,
) -> bool:
    """Return True only when `vname` is proven to be a non-array primitive or immutable Java stdlib value."""
    vinfo = visible_var_info.get(vname)
    if not isinstance(vinfo, dict):
        return False
    raw_decl = str(vinfo.get("declared_type") or "").strip()
    if "[" in raw_decl:
        return False
    if raw_decl in _FLOW_IMMUTABLE_TYPES:
        return True
    decl_ref = vinfo.get("declared_type_ref")
    fqn = resolve_stdlib_class_fqn(
        decl_ref,
        caller_unit=caller_unit,
        project_pkg_classes=project_pkg_classes,
        all_units=all_units,
    )
    return fqn in _FLOW_IMMUTABLE_TYPES


def _extract_call_mutated_args(
    expr: str,
    *,
    visible_var_info: dict[str, dict[str, Any]],
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None,
    all_units: list[dict[str, Any]] | None,
    enclosing_class: str | None,
) -> set[str]:
    """Conservatively collect mutable arguments/receivers passed to non-stdlib calls (e.g., `appendSql(sql, id)`)."""
    mutated: set[str] = set()
    if not expr or "(" not in expr:
        return mutated
    kw_ctx = {
        "visible_var_info": visible_var_info,
        "caller_unit": caller_unit,
        "project_pkg_classes": project_pkg_classes,
        "all_units": all_units,
    }
    caller_imports = caller_unit.get("imports") if isinstance(caller_unit, dict) else None
    for site in _extract_call_sites_on_line(expr):
        qual = site["qualifier"]
        mname = site["method"]
        chained = site["chained"]
        is_new_chain = site["is_new_ctor_chain"]
        is_std = _is_stdlib_call(
            qual,
            mname,
            chained,
            visible_var_info,
            caller_imports,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            enclosing_class=enclosing_class,
            line_clean=expr,
            call_start=site.get("start"),
            is_new_ctor_chain=is_new_chain,
        )
        if is_std:
            # Handle mutating stdlib methods on receiver variable (`sb.append(x)`, `ps.setString(...)`)
            if qual and qual in visible_var_info and qual != "this" and mname in _FLOW_MUTATING_STDLIB_METHODS:
                mutated.add(qual)
            continue
        # Non-stdlib call (same-file helper, static helper, or external call):
        # conservatively treat receiver variable and every non-immutable argument variable as potentially mutated.
        if qual and qual in visible_var_info and qual != "this":
            if not _is_proven_immutable_var(qual, **kw_ctx):
                mutated.add(qual)
        start_pos = site.get("start") or 0
        open_idx = expr.find("(", start_pos)
        if open_idx == -1:
            continue
        close_idx = _find_matching_paren(expr, open_idx)
        args_str = expr[open_idx + 1 : close_idx] if close_idx is not None else expr[open_idx + 1 :]
        if not args_str.strip():
            continue
        for arg_v in _extract_expr_var_idents(args_str, **kw_ctx):
            if arg_v == "this" or arg_v in _FLOW_JAVA_KEYWORDS:
                continue
            if not _is_proven_immutable_var(arg_v, **kw_ctx):
                mutated.add(arg_v)
    return mutated


def _extract_stmt_defs_and_uses(
    code: str,
    kind: str,
    *,
    visible_var_info: dict[str, dict[str, Any]],
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None,
    all_units: list[dict[str, Any]] | None,
    enclosing_class: str | None,
) -> tuple[set[str], set[str]]:
    """Extract conservative `(defs, uses)` variable sets for a single comment/string-masked Java statement."""
    kw_ctx = {
        "visible_var_info": visible_var_info,
        "caller_unit": caller_unit,
        "project_pkg_classes": project_pkg_classes,
        "all_units": all_units,
    }
    s = code.strip()
    if not s:
        return set(), set()

    if kind == "TRY_RESOURCES":
        defs: set[str] = set()
        uses: set[str] = set()
        for seg in _split_top_level_char(s, ";"):
            d, u = _extract_stmt_defs_and_uses(seg, "SIMPLE", enclosing_class=enclosing_class, **kw_ctx)
            defs.update(d)
            uses.update(u)
        return defs, uses

    if kind == "LOOP_HEADER":
        defs = set()
        uses = set()
        m_fe = re.match(
            r"^\s*(?:final\s+)?[A-Za-z_][A-Za-z0-9_<>,.\[\]]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*:(.*)$",
            s,
        )
        if m_fe:
            v = m_fe.group(1)
            if v not in _FLOW_JAVA_KEYWORDS:
                defs.add(v)
            uses.update(_extract_expr_var_idents(m_fe.group(2), **kw_ctx))
            return defs, uses
        parts = _split_top_level_char(s, ";")
        if len(parts) == 3:
            for p in parts:
                for sub in _split_top_level_char(p, ","):
                    d, u = _extract_stmt_defs_and_uses(sub, "SIMPLE", enclosing_class=enclosing_class, **kw_ctx)
                    defs.update(d)
                    uses.update(u)
            return defs, uses
        return set(), _extract_expr_var_idents(s, **kw_ctx)

    if kind == "EXIT":
        body = re.sub(r"^(?:return|throw)\b", "", s).rstrip(";").strip()
        return set(), _extract_expr_var_idents(body, **kw_ctx)

    # Simple statement: declaration-only, assignment, multi-var decl, inc/dec, or expression call
    s_no_semi = s.rstrip(";").strip()
    if not s_no_semi:
        return set(), set()

    m_decl = _FLOW_DECL_ONLY_RE.match(s_no_semi)
    if (
        m_decl
        and m_decl.group(1).strip().split("[")[0].strip() not in _FLOW_NON_TYPE_KEYWORDS
        and m_decl.group(2) not in _FLOW_JAVA_KEYWORDS
    ):
        return {m_decl.group(2)}, set()

    # Check single assignment / declaration (`Type v = rhs`, `v = rhs`, `v += rhs`, `this.f = rhs`, `arr[i] = rhs`)
    m_asgn = _FLOW_ASSIGN_STMT_RE.match(s_no_semi)
    if m_asgn:
        decl_t = (m_asgn.group(1) or "").strip()
        lhs_raw = m_asgn.group(2).strip()
        op_sym = m_asgn.group(3)
        rhs = m_asgn.group(4).strip()
        if not decl_t or decl_t.split("[")[0].strip().split()[0] not in _FLOW_NON_TYPE_KEYWORDS:
            # Handle multi-var decl `String a = x, b = y`
            if decl_t and len(_split_top_level_char(rhs, ",")) > 1:
                m_multi = _FLOW_MULTI_DECL_RE.match(s_no_semi)
                if m_multi:
                    defs_m: set[str] = set()
                    uses_m: set[str] = set()
                    for item in _split_top_level_char(m_multi.group(2), ","):
                        if "=" in item:
                            l_part, r_part = item.split("=", 1)
                            v = re.sub(r"\s*\[\s*\]\s*", "", l_part).strip()
                            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v) and v not in _FLOW_JAVA_KEYWORDS:
                                defs_m.add(v)
                            uses_m.update(_extract_expr_var_idents(r_part, **kw_ctx))
                        else:
                            v = re.sub(r"\s*\[\s*\]\s*", "", item).strip()
                            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v) and v not in _FLOW_JAVA_KEYWORDS:
                                defs_m.add(v)
                    return defs_m, uses_m

            defs_a: set[str] = set()
            uses_a: set[str] | None = None
            if rhs.endswith(")"):
                _open_i = _find_matching_open_paren_backward(rhs, len(rhs) - 1)
                if _open_i is not None:
                    _head = rhs[:_open_i].strip()
                    _args_s = rhs[_open_i + 1 : -1].strip()
                    _m_fac = re.match(r"^(.+?)\s*\.\s*(createStatement|prepareStatement|prepareCall|getConnection)$", _head)
                    if _m_fac:
                        _recv_e = _m_fac.group(1).strip()
                        _imports_u = list(caller_unit.get("imports") or []) if isinstance(caller_unit, dict) else []
                        _rfqn = _resolve_expr_stdlib_fqn(
                            _recv_e,
                            visible_var_info=visible_var_info,
                            caller_imports=_imports_u,
                            caller_unit=caller_unit,
                            project_pkg_classes=project_pkg_classes,
                            all_units=all_units,
                            enclosing_class=enclosing_class,
                        )
                        if _rfqn in ("java.sql.Connection", "javax.sql.DataSource"):
                            uses_a = _extract_expr_var_idents(_args_s, **kw_ctx) if _args_s else set()
            if uses_a is None:
                uses_a = _extract_expr_var_idents(rhs, **kw_ctx)
            # Extract index expressions on LHS (`arr[idx] = rhs`)
            for idx_m in re.finditer(r"\[([^\]]*)\]", lhs_raw):
                uses_a.update(_extract_expr_var_idents(idx_m.group(1), **kw_ctx))
            lhs_base = re.sub(r"\[[^\]]*\]", "", lhs_raw).strip()
            lhs_parts = [p.strip() for p in lhs_base.split(".") if p.strip()]
            if lhs_parts:
                if lhs_parts[0] == "this" and len(lhs_parts) >= 2:
                    defs_a.add(lhs_parts[1])
                else:
                    defs_a.add(lhs_parts[0])
                    if len(lhs_parts) >= 2:
                        defs_a.add(lhs_parts[-1])
            if op_sym != "=":
                uses_a.update(defs_a)
            defs_a.update(_extract_call_mutated_args(rhs, enclosing_class=enclosing_class, **kw_ctx))
            return defs_a, uses_a

    # Standalone expression / call statement (e.g. `sb.append(email)`, `appendSql(sql, id)`, `InputGuard.validate(email)`, `i++`)
    defs_e: set[str] = set()
    uses_e: set[str] = _extract_expr_var_idents(s_no_semi, **kw_ctx)
    for m_inc in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\+|--)|(?:\+\+|--)\s*([A-Za-z_][A-Za-z0-9_]*)\b", s_no_semi):
        v = m_inc.group(1) or m_inc.group(2)
        if v and v not in _FLOW_JAVA_KEYWORDS:
            defs_e.add(v)
            uses_e.add(v)
    defs_e.update(_extract_call_mutated_args(s_no_semi, enclosing_class=enclosing_class, **kw_ctx))
    # Receiver mutation calls (`sb.append(x)`, `list.add(x)`, `ps.setString(1, u)`, or non-stdlib `obj.clean()`)
    m_recv_call = re.match(r"^(?:this\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", s_no_semi)
    if m_recv_call:
        recv_v, meth_v = m_recv_call.group(1), m_recv_call.group(2)
        if recv_v in visible_var_info and recv_v != "this":
            is_std = _is_stdlib_call(
                recv_v,
                meth_v,
                False,
                visible_var_info,
                caller_unit.get("imports") if isinstance(caller_unit, dict) else None,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                enclosing_class=enclosing_class,
                line_clean=s_no_semi,
                call_start=0,
            )
            if meth_v in _FLOW_MUTATING_STDLIB_METHODS or not is_std:
                defs_e.add(recv_v)
    return defs_e, uses_e


def _extract_sink_payload_vars(
    sink_stmts: list[_FlowStmt],
    primary_cwe: str,
    *,
    visible_var_info: dict[str, dict[str, Any]],
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None,
    all_units: list[dict[str, Any]] | None,
    enclosing_class: str | None,
    static_field_resolver: Any = None,
) -> set[str]:
    """Extract variables feeding the vulnerable sink payload (excluding verified JDBC Statement/Connection handles)."""
    kw_ctx = {
        "visible_var_info": visible_var_info,
        "caller_unit": caller_unit,
        "project_pkg_classes": project_pkg_classes,
        "all_units": all_units,
    }
    imports = list(caller_unit.get("imports") or []) if isinstance(caller_unit, dict) else []
    payload_vars: set[str] = set()

    for st in sink_stmts:
        expr = st.code.strip().rstrip(";").strip()
        if not expr:
            continue
        if expr.startswith("return "):
            expr = expr[7:].strip()
        else:
            m_asgn = _FLOW_ASSIGN_STMT_RE.match(expr)
            if m_asgn and (
                not m_asgn.group(1)
                or m_asgn.group(1).strip().split("[")[0].strip().split()[0] not in _FLOW_NON_TYPE_KEYWORDS
            ):
                expr = m_asgn.group(4).strip()

        extracted = False
        if primary_cwe == "CWE-89":
            # Match `<recv>.<sqlMethod>(<args>)` ONLY when `<recv>` resolves to a proven stdlib SQL executor type!
            if expr.endswith(")"):
                open_idx = _find_matching_open_paren_backward(expr, len(expr) - 1)
                if open_idx is not None:
                    head = expr[:open_idx].strip()
                    args_str = expr[open_idx + 1 : -1].strip()
                    m_mc = re.match(r"^(.+?)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)$", head)
                    if m_mc and m_mc.group(2) in _SQL_SINK_METHODS:
                        recv_expr = m_mc.group(1).strip()
                        recv_fqn = _resolve_expr_stdlib_fqn(
                            recv_expr,
                            visible_var_info=visible_var_info,
                            caller_imports=imports,
                            caller_unit=caller_unit,
                            project_pkg_classes=project_pkg_classes,
                            all_units=all_units,
                            enclosing_class=enclosing_class,
                            static_field_resolver=static_field_resolver,
                        )
                        if recv_fqn in _SQL_SINK_RECEIVER_FQNS:
                            args = _split_top_level_char(args_str, ",") if args_str else []
                            if args:
                                payload_vars.update(_extract_expr_var_idents(args[0], **kw_ctx))
                            else:
                                # 0-arg `ps.executeQuery()`: receiver `ps` holds the prepared SQL & bound params
                                payload_vars.update(_extract_expr_var_idents(recv_expr, **kw_ctx))
                            extracted = True

        if not extracted:
            payload_vars.update(_extract_expr_var_idents(expr, **kw_ctx))

    return payload_vars


def _is_pure_jdbc_resource_liveness_clause(
    clause: str,
    *,
    visible_var_info: dict[str, dict[str, Any]],
    tainted_or_sink_vars: set[str],
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None,
    all_units: list[dict[str, Any]] | None,
) -> bool:
    """Return True ONLY when a guard clause purely checks nullability/liveness of an untainted proven JDBC handle.

    Examples: `con != null`, `!con.isClosed()`, `con.isValid(5)` where `con` is proven `java.sql.Connection`
    and has zero data dependency on tainted or sink-payload variables.
    """
    c = clause.strip()
    while c.startswith("(") and c.endswith(")") and _find_matching_paren(c, 0) == len(c) - 1:
        c = c[1:-1].strip()
    while c.startswith("!"):
        c = c[1:].strip()
        while c.startswith("(") and c.endswith(")") and _find_matching_paren(c, 0) == len(c) - 1:
            c = c[1:-1].strip()
    if not c:
        return False

    var_name: str | None = None
    m_null = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*[!=]=\s*null|null\s*[!=]=\s*([A-Za-z_][A-Za-z0-9_]*)", c)
    if m_null:
        var_name = m_null.group(1) or m_null.group(2)
    else:
        m_live = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:isClosed\s*\(\s*\)|isValid\s*\(\s*\d+\s*\))", c)
        if m_live:
            var_name = m_live.group(1)
    if not var_name or var_name in tainted_or_sink_vars or var_name not in visible_var_info:
        return False
    decl_ref = visible_var_info[var_name].get("declared_type_ref")
    fqn = resolve_stdlib_class_fqn(
        decl_ref,
        caller_unit=caller_unit,
        project_pkg_classes=project_pkg_classes,
        all_units=all_units,
    )
    return fqn in _JDBC_RESOURCE_HANDLE_FQNS


def _is_verified_stdlib_constructor_on_line(
    s_clean_line: str,
    mname: str,
    *,
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None,
    all_units: list[dict[str, Any]] | None,
    caller_imports: list[str] | None = None,
) -> bool:
    """Return True when `s_clean_line` invokes `new [pkg.]<mname>(...)` and EVERY match resolves to a proven stdlib FQN."""
    pat = re.compile(
        rf"\bnew\s+(?:([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*)\s*\.\s*)?"
        rf"{re.escape(mname)}(?:\s*<[^>{{}};()]*>)?\s*\("
    )
    matches = list(pat.finditer(s_clean_line))
    if not matches:
        return False
    for m in matches:
        c_qual = ".".join(p.strip() for p in m.group(1).split(".")) if m.group(1) else None
        ctor_type = f"{c_qual}.{mname}" if c_qual else mname
        fqn = resolve_stdlib_class_fqn(
            ctor_type,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=caller_imports,
        )
        if fqn is None:
            return False
    return True


_FINAL_STDLIB_METHOD_REF_FQNS = frozenset(
    {
        "java.lang.String",
        "java.lang.Integer",
        "java.lang.Long",
        "java.lang.Short",
        "java.lang.Byte",
        "java.lang.Boolean",
        "java.lang.Double",
        "java.lang.Float",
        "java.lang.Character",
        "java.lang.Math",
        "java.lang.StrictMath",
        "java.lang.StringBuilder",
        "java.lang.StringBuffer",
        "java.util.Objects",
        "java.util.Optional",
        "java.util.UUID",
    }
)

_SAFE_STDLIB_CTOR_REF_FQNS = frozenset(
    {
        "java.lang.String",
        "java.lang.StringBuilder",
        "java.lang.StringBuffer",
        "java.util.ArrayList",
        "java.util.LinkedList",
        "java.util.HashSet",
        "java.util.LinkedHashSet",
        "java.util.HashMap",
        "java.util.LinkedHashMap",
    }
)

_NON_CALL_PAREN_KEYWORDS = frozenset(
    CONTROL_KEYWORDS
    | _MODIFIERS
    | {
        "return",
        "throw",
        "case",
        "instanceof",
        "new",
        "super",
        "this",
        "try",
        "else",
        "yield",
        "assert",
    }
)


def _extract_non_chained_ctor_sites(s_clean: str) -> list[dict[str, Any]]:
    """Extract constructor sites for EVERY `new` keyword in `s_clean` with balanced generic scanning and fail-closed coverage.

    Never silently drops `new` expressions with nested generics (`new ExternalValidator<List<String>>(id)`),
    anonymous subclasses (`new Type(...) { ... }`), qualified inner constructors (`outer.new Inner(...)`),
    multi-line constructors, or unparseable constructor syntax. Pure array allocations (`new int[n]`, `new String[]{...}`)
    without a constructor `(` are excluded while their inner expressions remain independently scanned.
    """
    sites: list[dict[str, Any]] = []
    n = len(s_clean)
    for m in re.finditer(r"\bnew\b", s_clean):
        # Skip `::new` constructor references (handled exhaustively by `_extract_method_ref_sites_on_line`).
        before_new = s_clean[: m.start()].rstrip()
        if before_new.endswith("::"):
            continue
        # Skip `obj.new`? No! `outer.new Inner(...)` IS a qualified inner-class constructor -> MUST inspect!
        is_qualified_inner = before_new.endswith(".")
        pos = m.end()
        while pos < n and s_clean[pos].isspace():
            pos += 1
        # Optional constructor type arguments: `new <T> Foo(...)`
        if pos < n and s_clean[pos] == "<":
            close_ta = _find_matching_close_angle(s_clean, pos)
            if close_ta is None:
                sites.append(
                    {
                        "ctor_type": "<unparsed_new>",
                        "simple_name": "<init>",
                        "arg_count": None,
                        "args_text": s_clean[pos:].strip(),
                        "multiline": True,
                        "opaque": True,
                        "open_paren_idx": None,
                        "start": m.start(),
                    }
                )
                continue
            pos = close_ta + 1
            while pos < n and s_clean[pos].isspace():
                pos += 1

        # Parse dotted type name (with optional balanced generic type arguments on any segment, e.g. `Outer<A>.Inner<B<C>>`)
        type_parts: list[str] = []
        parse_ok = True
        while pos < n:
            m_id = re.match(r"[A-Za-z_][A-Za-z0-9_]*", s_clean[pos:])
            if not m_id:
                parse_ok = False
                break
            type_parts.append(m_id.group(0))
            pos += m_id.end()
            while pos < n and s_clean[pos].isspace():
                pos += 1
            if pos < n and s_clean[pos] == "<":
                close_g = _find_matching_close_angle(s_clean, pos)
                if close_g is None:
                    parse_ok = False
                    break
                pos = close_g + 1
                while pos < n and s_clean[pos].isspace():
                    pos += 1
            if pos < n and s_clean[pos] == ".":
                pos += 1
                while pos < n and s_clean[pos].isspace():
                    pos += 1
                continue
            break

        if not parse_ok or not type_parts:
            sites.append(
                {
                    "ctor_type": "<unparsed_new>",
                    "simple_name": "<init>",
                    "arg_count": None,
                    "args_text": s_clean[m.end() :].strip(),
                    "multiline": False,
                    "opaque": True,
                    "open_paren_idx": None,
                    "start": m.start(),
                }
            )
            continue

        ctor_type = ".".join(type_parts)
        # Pure array allocation (`new Type[...]` or `new Type[] { ... }`): no constructor invocation `(`.
        if pos < n and s_clean[pos] == "[":
            continue

        # Must see `(` for a constructor invocation; if syntax is split across lines or unexpected, fail closed as opaque.
        if pos >= n or s_clean[pos] != "(":
            sites.append(
                {
                    "ctor_type": ctor_type,
                    "simple_name": ctor_type.rsplit(".", 1)[-1],
                    "arg_count": None,
                    "args_text": s_clean[pos:].strip(),
                    "multiline": pos >= n,
                    "opaque": True,
                    "open_paren_idx": None,
                    "start": m.start(),
                }
            )
            continue

        open_idx = pos
        close_idx = _find_matching_paren(s_clean, open_idx)
        if close_idx is None:
            sites.append(
                {
                    "ctor_type": ctor_type,
                    "simple_name": ctor_type.rsplit(".", 1)[-1],
                    "arg_count": None,
                    "args_text": s_clean[open_idx + 1 :].strip(),
                    "multiline": True,
                    "opaque": is_qualified_inner,
                    "open_paren_idx": open_idx,
                    "start": m.start(),
                }
            )
            continue

        after = s_clean[close_idx + 1 :]
        # Anonymous subclass (`new Type(...) { ... }`) carries custom body/overrides -> ALWAYS opaque fail-closed!
        is_anon_class = bool(re.match(r"^\s*\{", after))
        # Chained `new SimpleType(args).method(` without generics/anonymous-body is handled as `is_new_ctor_chain`
        # ONLY when `_CALL_SITE_RE` actually matched `new SimpleType(` directly (no `<...>` between type and `(`).
        has_generics_before_paren = "<" in s_clean[m.end() : open_idx]
        if (
            not is_anon_class
            and not is_qualified_inner
            and not has_generics_before_paren
            and re.match(r"^\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(", after)
        ):
            continue

        inner = s_clean[open_idx + 1 : close_idx].strip()
        arg_count = 0 if not inner else len(_split_top_level_commas(inner))
        sites.append(
            {
                "ctor_type": ctor_type,
                "simple_name": ctor_type.rsplit(".", 1)[-1],
                "arg_count": arg_count,
                "args_text": inner,
                "multiline": False,
                "opaque": is_anon_class or is_qualified_inner,
                "open_paren_idx": open_idx,
                "start": m.start(),
            }
        )
    return sites


def _extract_method_ref_sites_on_line(s_clean: str) -> list[dict[str, Any]]:
    """Exhaustively extract EVERY Java 8+ method/constructor reference by scanning every `::` token in `s_clean`.

    In comment/string/text-block-stripped Java code, `::` ONLY occurs in method/constructor references (JLS §15.13).
    Any expression-bound receiver (`sanitizers[0]::clean`, `((T) x)::clean`, `new Box()::clean`, `get()::clean`),
    nested generic owner (`External<List<String>>::clean`), or split/unparsed `::` is ALWAYS emitted (marking
    unrecognized/expression-bound receivers `opaque=True`) so no `::` can ever be silently dropped.
    """
    if "::" not in s_clean:
        return []
    sites: list[dict[str, Any]] = []
    n = len(s_clean)
    search_pos = 0
    while True:
        colon_idx = s_clean.find("::", search_pos)
        if colon_idx == -1:
            break
        search_pos = colon_idx + 2

        # 1. Parse RHS after `::`: optional balanced `<...>` type arguments + `new` or method identifier
        rhs_pos = colon_idx + 2
        while rhs_pos < n and s_clean[rhs_pos].isspace():
            rhs_pos += 1
        rhs_opaque = False
        if rhs_pos < n and s_clean[rhs_pos] == "<":
            close_ta = _find_matching_close_angle(s_clean, rhs_pos)
            if close_ta is None:
                rhs_opaque = True
            else:
                rhs_pos = close_ta + 1
                while rhs_pos < n and s_clean[rhs_pos].isspace():
                    rhs_pos += 1
        member = "<unparsed>"
        if not rhs_opaque and rhs_pos < n:
            m_mem = re.match(r"(new|[A-Za-z_][A-Za-z0-9_]*)\b", s_clean[rhs_pos:])
            if m_mem:
                member = m_mem.group(1)
            else:
                rhs_opaque = True
        else:
            rhs_opaque = True

        # 2. Parse LHS immediately preceding `::`
        lhs_end = colon_idx - 1
        while lhs_end >= 0 and s_clean[lhs_end].isspace():
            lhs_end -= 1
        if lhs_end < 0:
            sites.append({"owner": "<expr>", "member": member, "opaque": True, "start": colon_idx})
            continue

        # Expression-bound receivers ending in `)` (`((T) x)::m`, `new Box()::m`, `get()::m`)
        # or non-empty array index (`sanitizers[0]::m`) are ALWAYS opaque (never treated as simple type/var refs).
        is_array_type_ctor_ref = False
        cur = lhs_end
        if s_clean[cur] == "]":
            # Distinguish empty array type dimensions `Type[]::new` from indexed expression `arr[0]::m`
            probe = cur
            only_empty_brackets = True
            while probe >= 0 and s_clean[probe] == "]":
                j = probe - 1
                while j >= 0 and s_clean[j].isspace():
                    j -= 1
                if j >= 0 and s_clean[j] == "[":
                    probe = j - 1
                    while probe >= 0 and s_clean[probe].isspace():
                        probe -= 1
                else:
                    only_empty_brackets = False
                    break
            if not only_empty_brackets or member != "new":
                sites.append({"owner": "<expr>", "member": member, "opaque": True, "start": colon_idx})
                continue
            is_array_type_ctor_ref = True
            cur = probe
            if cur < 0:
                sites.append({"owner": "<expr>", "member": member, "opaque": True, "start": colon_idx})
                continue

        if s_clean[cur] == ")":
            sites.append({"owner": "<expr>", "member": member, "opaque": True, "start": colon_idx})
            continue

        # Walk backward over optional dotted segments with optional balanced `<...>` generics (`pkg.Type<List<String>>`)
        owner_parts: list[str] = []
        lhs_opaque = False
        has_generics = False
        start_idx = cur
        while cur >= 0:
            if s_clean[cur] == ">":
                open_g = _find_matching_open_angle_backward(s_clean, cur)
                if open_g is None:
                    lhs_opaque = True
                    break
                has_generics = True
                cur = open_g - 1
                while cur >= 0 and s_clean[cur].isspace():
                    cur -= 1
                if cur < 0:
                    lhs_opaque = True
                    break
            if not (s_clean[cur].isalnum() or s_clean[cur] == "_"):
                lhs_opaque = True
                break
            seg_end = cur + 1
            while cur >= 0 and (s_clean[cur].isalnum() or s_clean[cur] == "_"):
                cur -= 1
            seg = s_clean[cur + 1 : seg_end]
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", seg):
                lhs_opaque = True
                break
            owner_parts.append(seg)
            start_idx = cur + 1
            probe_dot = cur
            while probe_dot >= 0 and s_clean[probe_dot].isspace():
                probe_dot -= 1
            if probe_dot >= 0 and s_clean[probe_dot] == ".":
                prev_before_dot = probe_dot - 1
                while prev_before_dot >= 0 and s_clean[prev_before_dot].isspace():
                    prev_before_dot -= 1
                # If `.` follows `)` or `]` (e.g. `arr[0].box::clean` or `getBox().san::clean`), receiver is an expression!
                if prev_before_dot < 0 or s_clean[prev_before_dot] in (")", "]"):
                    lhs_opaque = True
                    break
                cur = prev_before_dot
                continue
            # Check token immediately preceding the whole owner chain (e.g. `new Foo::bar` is opaque)
            if probe_dot >= 0 and (s_clean[probe_dot].isalnum() or s_clean[probe_dot] == "_"):
                lhs_opaque = True
            break

        owner_parts.reverse()
        owner = ".".join(owner_parts) if owner_parts and not lhs_opaque else "<expr>"
        sites.append(
            {
                "owner": owner,
                "member": member,
                "opaque": bool(lhs_opaque or rhs_opaque or is_array_type_ctor_ref),
                "has_generics": has_generics,
                "start": start_idx if not lhs_opaque else colon_idx,
            }
        )
    return sites


def _find_uncovered_call_parens(s_clean: str, covered_paren_indices: set[int]) -> list[dict[str, Any]]:
    """Lexical completeness guard: detect any executable `(` invocation site not accounted for by call/ctor extractors."""
    uncovered: list[dict[str, Any]] = []
    n = len(s_clean)
    for idx, ch in enumerate(s_clean):
        if ch != "(" or idx in covered_paren_indices:
            continue
        p = idx - 1
        while p >= 0 and s_clean[p].isspace():
            p -= 1
        if p < 0:
            continue
        prev_ch = s_clean[p]
        # Grouping/cast/lambda parens immediately follow operators or delimiters, not invocation targets.
        if prev_ch in "=(,:;?!&|+-*/%<^~[{":
            continue
        # Explicit generic target or call-on-expression `foo<...>(...)` or `arr[0](...)` or `fn()(...)`
        if prev_ch in (">", "]"):
            # Note: `a > (b)` comparison is preceded by whitespace + binary `>`; generic `<...>` balances back to `<`
            if prev_ch == ">":
                open_g = _find_matching_open_angle_backward(s_clean, p)
                if open_g is None:
                    continue
                before_g = open_g - 1
                while before_g >= 0 and s_clean[before_g].isspace():
                    before_g -= 1
                if before_g < 0 or not (s_clean[before_g].isalnum() or s_clean[before_g] == "_"):
                    continue
            uncovered.append({"qualifier": "<unparsed>", "method": "<unparsed_call>", "opaque": True, "start": idx})
            continue
        if prev_ch.isalnum() or prev_ch == "_":
            end_tok = p + 1
            while p >= 0 and (s_clean[p].isalnum() or s_clean[p] == "_"):
                p -= 1
            tok = s_clean[p + 1 : end_tok]
            if tok in _NON_CALL_PAREN_KEYWORDS:
                continue
            # Annotation `@Name(...)`
            b = p
            while b >= 0 and s_clean[b].isspace():
                b -= 1
            if b >= 0 and s_clean[b] == "@":
                continue
            # Method/lambda header declarations do not occur on executable statements inside method bodies,
            # except anonymous/local class bodies which should fail closed anyway.
            uncovered.append({"qualifier": "<unparsed>", "method": tok, "opaque": True, "start": idx})
    return uncovered


def _is_verified_stdlib_method_ref(
    owner: str,
    member: str,
    *,
    opaque: bool = False,
    visible_var_info: dict[str, dict[str, Any]],
    caller_imports: list[str] | None,
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None,
    all_units: list[dict[str, Any]] | None,
    enclosing_class: str | None,
) -> bool:
    """Return True ONLY when `owner::member` is a non-opaque, unshadowed, non-overridable verified stdlib member.

    Never assumes a method reference is safe merely because its owner belongs to stdlib:
    - Opaque/expression-bound receivers always return False.
    - Non-final/overridable stdlib types (e.g. `Object`, `List`, `Function`, `CharSequence`) return False.
    - Member must be explicitly present in `_stdlib_methods_for_fqn(fqn)` (or `_SAFE_STDLIB_CTOR_REF_FQNS` for `::new`).
    """
    if opaque or not owner or not member or owner in ("this", "super", "<expr>"):
        return False
    # Case 1: Bound instance variable method reference (`var::method`)
    if owner in visible_var_info and member != "new":
        vinfo = visible_var_info[owner]
        decl_ref = vinfo.get("declared_type_ref")
        fqn = resolve_stdlib_class_fqn(
            decl_ref,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            caller_imports=caller_imports,
        )
        return bool(fqn and fqn in _FINAL_STDLIB_METHOD_REF_FQNS and member in _stdlib_methods_for_fqn(fqn))
    # Case 2: Type/static method or constructor reference (`String::trim`, `StringBuilder::new`, `Objects::nonNull`)
    if _is_leading_qualifier_shadowed(
        owner,
        visible_var_info=visible_var_info,
        caller_unit=caller_unit,
        project_pkg_classes=project_pkg_classes,
        all_units=all_units,
        caller_imports=caller_imports,
        require_expr_scope=True,
    ):
        return False
    fqn = resolve_stdlib_class_fqn(
        owner,
        caller_unit=caller_unit,
        project_pkg_classes=project_pkg_classes,
        all_units=all_units,
        caller_imports=caller_imports,
    )
    if fqn is None:
        return False
    if member == "new":
        return fqn in _SAFE_STDLIB_CTOR_REF_FQNS
    return fqn in _FINAL_STDLIB_METHOD_REF_FQNS and member in _stdlib_methods_for_fqn(fqn)


def _build_enclosing_method_flow_slice(
    *,
    record: dict[str, Any],
    p_verified: dict[int, str],
    enc: dict[str, Any] | None,
    enclosing_class: str | None,
    sink_line: int | None,
    visible_var_info: dict[str, dict[str, Any]],
    caller_unit: dict[str, Any],
    project_pkg_classes: dict[str | None, set[str]],
    all_units: list[dict[str, Any]],
    static_field_resolver: Any = None,
) -> dict[str, Any]:
    """Build AST-grounded causal, data-dependency, and control-dependency slices for the enclosing method.

    Fails closed (`valid=False`) whenever method boundaries are missing/incomplete, lines are truncated,
    the sink statement cannot be located, or the method body contains unparseable statements before the sink.
    """
    invalid = {"valid": False}
    if not enc or not p_verified or type(sink_line) is not int:
        return invalid
    h_line = enc.get("header_line")
    e_line = enc.get("end_line")
    if type(h_line) is not int or type(e_line) is not int or not (h_line <= sink_line <= e_line):
        return invalid
    if not all(ln in p_verified for ln in range(h_line, e_line + 1)):
        return invalid

    raw_slice = [p_verified[ln] for ln in range(h_line, e_line + 1)]
    clean_list = _strip_java_non_executable_preserve_lines("\n".join(raw_slice))
    clean_by_ln = {ln: cl for ln, cl in zip(range(h_line, e_line + 1), clean_list)}

    body_pos = _find_method_body_open_brace(clean_by_ln, h_line, e_line)
    if body_pos is None or body_pos[0] > sink_line:
        return invalid
    b_start, b_col = body_pos
    if b_col > 0 and b_start in clean_by_ln:
        clean_by_ln = dict(clean_by_ln)
        clean_by_ln[b_start] = (" " * b_col) + clean_by_ln[b_start][b_col:]

    parser = _FlowMethodParser(b_start, e_line, clean_by_ln)
    stmts = parser.parse_method_body()
    if parser.parse_errors:
        return invalid

    cwes = [str(x).upper() for x in (record.get("cwe") or [])]
    primary_cwe = (
        "CWE-22"
        if any("CWE-22" in c or c == "22" for c in cwes)
        else ("CWE-89" if any("CWE-89" in c or c == "89" for c in cwes) else "UNKNOWN")
    )

    kw_ctx = {
        "visible_var_info": visible_var_info,
        "caller_unit": caller_unit,
        "project_pkg_classes": project_pkg_classes,
        "all_units": all_units,
    }

    causal_stmts: list[_FlowStmt] = []
    sink_stmts: list[_FlowStmt] = []
    governing_guards: list[tuple[str, set[int]]] = []
    conditional_def_guards: list[tuple[str, set[int], set[str]]] = []
    exception_control_lines: set[int] = set()
    conditional_exception_regions: list[tuple[set[int], set[str], bool]] = []
    saw_unknown_causal = False

    def _contains(node: _FlowStmt | None, ln: int) -> bool:
        return node is not None and node.start_line <= ln <= node.end_line

    def _collect_subtree_lines(node: _FlowStmt | None) -> set[int]:
        if node is None:
            return set()
        out_lns: set[int] = set()
        if node.lines:
            out_lns.update(node.lines)
        if node.cond_lines:
            out_lns.update(node.cond_lines)
        if node.resource_lines:
            out_lns.update(node.resource_lines)
        if node.start_line <= node.end_line and node.kind in ("SIMPLE", "EXIT", "TRY_RESOURCES", "LOOP_HEADER", "UNKNOWN"):
            out_lns.update(range(node.start_line, node.end_line + 1))
        for attr in ("then_stmt", "else_stmt", "body_stmt", "finally_stmt"):
            out_lns.update(_collect_subtree_lines(getattr(node, attr)))
        for attr in ("body_stmts", "catches"):
            for ch in getattr(node, attr) or []:
                out_lns.update(_collect_subtree_lines(ch))
        return out_lns

    def _subtree_has_exit(node: _FlowStmt | None) -> bool:
        if node is None:
            return False
        if node.kind == "EXIT":
            return True
        if node.kind == "SIMPLE" and re.match(r"^\s*(?:break|continue)\b", node.code):
            return True
        for attr in ("then_stmt", "else_stmt", "body_stmt", "finally_stmt"):
            if _subtree_has_exit(getattr(node, attr)):
                return True
        for attr in ("body_stmts", "catches"):
            for ch in getattr(node, attr) or []:
                if _subtree_has_exit(ch):
                    return True
        return False

    def _collect_all(node: _FlowStmt | None) -> set[str]:
        """Collect all statements in a preceding or loop-enclosed subtree and return all variables defined inside it."""
        nonlocal saw_unknown_causal
        if node is None or node.kind in ("EMPTY", "CASE"):
            return set()
        if node.kind == "UNKNOWN":
            saw_unknown_causal = True
            return set()
        if node.kind in ("SIMPLE", "EXIT"):
            causal_stmts.append(node)
            d, _ = _extract_stmt_defs_and_uses(node.code, node.kind, enclosing_class=enclosing_class, **kw_ctx)
            return d
        if node.kind == "BLOCK":
            acc: set[str] = set()
            for ch in node.body_stmts or []:
                acc.update(_collect_all(ch))
            return acc
        if node.kind == "LABELED":
            return _collect_all(node.body_stmt)
        if node.kind == "IF":
            c_lines = set(node.cond_lines or {node.start_line})
            b_defs = _collect_all(node.then_stmt) | _collect_all(node.else_stmt)
            if _subtree_has_exit(node.then_stmt) or _subtree_has_exit(node.else_stmt):
                governing_guards.append((node.cond_text, c_lines))
            else:
                conditional_def_guards.append((node.cond_text, c_lines, b_defs))
            return b_defs
        if node.kind == "LOOP":
            c_lines = set(node.cond_lines or {node.start_line})
            hdr_stmt = _FlowStmt("LOOP_HEADER", min(c_lines), max(c_lines), code=node.cond_text, lines=c_lines)
            causal_stmts.append(hdr_stmt)
            hd, _ = _extract_stmt_defs_and_uses(node.cond_text, "LOOP_HEADER", enclosing_class=enclosing_class, **kw_ctx)
            b_defs = hd | _collect_all(node.body_stmt)
            if _subtree_has_exit(node.body_stmt):
                governing_guards.append((node.cond_text, c_lines))
            else:
                conditional_def_guards.append((node.cond_text, c_lines, b_defs))
            return b_defs
        if node.kind == "TRY":
            acc = set()
            all_try_lines: set[int] = set()
            if node.resources_text:
                rl = set(node.resource_lines or {node.start_line})
                all_try_lines.update(rl)
                r_stmt = _FlowStmt("TRY_RESOURCES", min(rl), max(rl), code=node.resources_text, lines=rl)
                causal_stmts.append(r_stmt)
                rd, _ = _extract_stmt_defs_and_uses(node.resources_text, "TRY_RESOURCES", enclosing_class=enclosing_class, **kw_ctx)
                acc.update(rd)
            all_try_lines.update(_collect_subtree_lines(node.body_stmt))
            acc.update(_collect_all(node.body_stmt))
            for cb in node.catches or []:
                all_try_lines.update(_collect_subtree_lines(cb))
                acc.update(_collect_all(cb))
            if node.finally_stmt is not None:
                all_try_lines.update(_collect_subtree_lines(node.finally_stmt))
                acc.update(_collect_all(node.finally_stmt))
            has_exc_exit = (
                _subtree_has_exit(node.body_stmt)
                or any(_subtree_has_exit(cb) for cb in (node.catches or []))
                or _subtree_has_exit(node.finally_stmt)
            )
            conditional_exception_regions.append((all_try_lines, set(acc), has_exc_exit))
            return acc
        if node.kind in ("SWITCH", "SYNCHRONIZED"):
            c_lines = set(node.cond_lines or {node.start_line})
            b_defs = _collect_all(node.body_stmt)
            if node.kind == "SWITCH":
                if _subtree_has_exit(node.body_stmt):
                    governing_guards.append((node.cond_text, c_lines))
                else:
                    conditional_def_guards.append((node.cond_text, c_lines, b_defs))
            else:
                causal_stmts.append(_FlowStmt("SIMPLE", min(c_lines), max(c_lines), code=node.cond_text, lines=c_lines))
            return b_defs
        saw_unknown_causal = True
        return set()

    def _walk(node: _FlowStmt | None, in_loop: bool = False) -> bool:
        nonlocal saw_unknown_causal
        if node is None or node.kind in ("EMPTY", "CASE"):
            return False
        if not in_loop and node.start_line > sink_line:
            return False
        if node.kind == "UNKNOWN":
            saw_unknown_causal = True
            return _contains(node, sink_line)
        if node.kind in ("SIMPLE", "EXIT"):
            causal_stmts.append(node)
            if _contains(node, sink_line):
                sink_stmts.append(node)
                return not in_loop
            return False
        if node.kind == "BLOCK":
            for ch in node.body_stmts or []:
                hit = _walk(ch, in_loop=in_loop)
                if hit and not in_loop:
                    return True
            return False
        if node.kind == "LABELED":
            return _walk(node.body_stmt, in_loop=in_loop)
        if node.kind == "IF":
            c_lines = set(node.cond_lines or {node.start_line})
            cond_hit = sink_line in c_lines
            then_hit = _contains(node.then_stmt, sink_line)
            else_hit = _contains(node.else_stmt, sink_line)
            if cond_hit:
                c_stmt = _FlowStmt("SIMPLE", min(c_lines), max(c_lines), code=node.cond_text, lines=c_lines)
                causal_stmts.append(c_stmt)
                sink_stmts.append(c_stmt)
                governing_guards.append((node.cond_text, c_lines))
                if in_loop:
                    _collect_all(node.then_stmt)
                    _collect_all(node.else_stmt)
                return not in_loop
            if then_hit or else_hit:
                governing_guards.append((node.cond_text, c_lines))
                if in_loop:
                    _walk(node.then_stmt, in_loop=True)
                    _walk(node.else_stmt, in_loop=True)
                    return False
                if then_hit and not else_hit:
                    return _walk(node.then_stmt, in_loop=False)
                if else_hit and not then_hit:
                    return _walk(node.else_stmt, in_loop=False)
                _walk(node.then_stmt, in_loop=False)
                _walk(node.else_stmt, in_loop=False)
                return True
            # Preceding IF (or sibling inside an enclosing loop)
            b_defs = _collect_all(node.then_stmt) | _collect_all(node.else_stmt)
            if _subtree_has_exit(node.then_stmt) or _subtree_has_exit(node.else_stmt):
                governing_guards.append((node.cond_text, c_lines))
            else:
                conditional_def_guards.append((node.cond_text, c_lines, b_defs))
            return False
        if node.kind == "LOOP":
            c_lines = set(node.cond_lines or {node.start_line})
            hdr_stmt = _FlowStmt("LOOP_HEADER", min(c_lines), max(c_lines), code=node.cond_text, lines=c_lines)
            causal_stmts.append(hdr_stmt)
            if sink_line in c_lines:
                sink_stmts.append(hdr_stmt)
                governing_guards.append((node.cond_text, c_lines))
                _walk(node.body_stmt, in_loop=True)
                return not in_loop
            if _contains(node.body_stmt, sink_line):
                governing_guards.append((node.cond_text, c_lines))
                # Enclosing loop: ALL statements in loop body (including post-sink) can precede next iteration!
                _walk(node.body_stmt, in_loop=True)
                return not in_loop
            b_defs = _collect_all(node.body_stmt)
            if _subtree_has_exit(node.body_stmt):
                governing_guards.append((node.cond_text, c_lines))
            else:
                conditional_def_guards.append((node.cond_text, c_lines, b_defs))
            return False
        if node.kind == "TRY":
            res_lns: set[int] = set(node.resource_lines or {node.start_line}) if node.resources_text else set()
            try_region_lines: set[int] = res_lns | _collect_subtree_lines(node.body_stmt)
            res_defs: set[str] = set()
            if node.resources_text:
                r_stmt = _FlowStmt("TRY_RESOURCES", min(res_lns), max(res_lns), code=node.resources_text, lines=res_lns)
                causal_stmts.append(r_stmt)
                res_defs, _ = _extract_stmt_defs_and_uses(
                    node.resources_text, "TRY_RESOURCES", enclosing_class=enclosing_class, **kw_ctx
                )
                if sink_line in res_lns:
                    sink_stmts.append(r_stmt)
                    if in_loop:
                        cf_defs = _collect_all(node.body_stmt)
                        all_lns = set(try_region_lines)
                        for cb in node.catches or []:
                            cf_defs.update(_collect_all(cb))
                            all_lns.update(_collect_subtree_lines(cb))
                        if node.finally_stmt is not None:
                            cf_defs.update(_collect_all(node.finally_stmt))
                            all_lns.update(_collect_subtree_lines(node.finally_stmt))
                        cf_exit = (
                            _subtree_has_exit(node.body_stmt)
                            or any(_subtree_has_exit(cb) for cb in (node.catches or []))
                            or _subtree_has_exit(node.finally_stmt)
                        )
                        conditional_exception_regions.append((all_lns, cf_defs, cf_exit))
                    return not in_loop
            if _contains(node.body_stmt, sink_line):
                hit = _walk(node.body_stmt, in_loop=in_loop)
                if in_loop:
                    cf_defs: set[str] = set()
                    all_lns = set(try_region_lines)
                    for cb in node.catches or []:
                        cf_defs.update(_collect_all(cb))
                        all_lns.update(_collect_subtree_lines(cb))
                    if node.finally_stmt is not None:
                        cf_defs.update(_collect_all(node.finally_stmt))
                        all_lns.update(_collect_subtree_lines(node.finally_stmt))
                    cf_exit = any(_subtree_has_exit(cb) for cb in (node.catches or [])) or _subtree_has_exit(node.finally_stmt)
                    conditional_exception_regions.append((all_lns, cf_defs, cf_exit))
                return hit
            for cb in node.catches or []:
                if _contains(cb, sink_line):
                    # Sink is inside a catch handler: every statement/resource in the guarded try region
                    # (including nested try/catch/finally) can throw an exception controlling entry here.
                    _collect_all(node.body_stmt)
                    exception_control_lines.update(try_region_lines)
                    hit = _walk(cb, in_loop=in_loop)
                    if in_loop:
                        other_defs: set[str] = set()
                        other_lns: set[int] = set(try_region_lines)
                        for other_cb in node.catches or []:
                            if other_cb is not cb:
                                other_defs.update(_collect_all(other_cb))
                                other_lns.update(_collect_subtree_lines(other_cb))
                        if node.finally_stmt is not None:
                            other_defs.update(_collect_all(node.finally_stmt))
                            other_lns.update(_collect_subtree_lines(node.finally_stmt))
                        other_exit = (
                            any(_subtree_has_exit(ocb) for ocb in (node.catches or []) if ocb is not cb)
                            or _subtree_has_exit(node.finally_stmt)
                        )
                        conditional_exception_regions.append((other_lns, other_defs, other_exit))
                    return hit
            if _contains(node.finally_stmt, sink_line):
                # Sink is inside finally: normal and exceptional edges through try/resources/catches
                # govern which statements and handlers execute before finally (fail-closed).
                _collect_all(node.body_stmt)
                exception_control_lines.update(try_region_lines)
                for cb in node.catches or []:
                    _collect_all(cb)
                    exception_control_lines.update(_collect_subtree_lines(cb))
                return _walk(node.finally_stmt, in_loop=in_loop)
            # Preceding TRY before the sink: if any catch/try/finally exits or defines a flow/guard var,
            # exception edges inside the TRY control whether the sink is skipped or receives modified state.
            all_try_lines = set(try_region_lines)
            reg_defs = set(res_defs) | _collect_all(node.body_stmt)
            for cb in node.catches or []:
                all_try_lines.update(_collect_subtree_lines(cb))
                reg_defs.update(_collect_all(cb))
            if node.finally_stmt is not None:
                all_try_lines.update(_collect_subtree_lines(node.finally_stmt))
                reg_defs.update(_collect_all(node.finally_stmt))
            has_exc_exit = (
                _subtree_has_exit(node.body_stmt)
                or any(_subtree_has_exit(cb) for cb in (node.catches or []))
                or _subtree_has_exit(node.finally_stmt)
            )
            conditional_exception_regions.append((all_try_lines, reg_defs, has_exc_exit))
            return False
        if node.kind == "SWITCH":
            c_lines = set(node.cond_lines or {node.start_line})
            if sink_line in c_lines:
                c_stmt = _FlowStmt("SIMPLE", min(c_lines), max(c_lines), code=node.cond_text, lines=c_lines)
                causal_stmts.append(c_stmt)
                sink_stmts.append(c_stmt)
                governing_guards.append((node.cond_text, c_lines))
                return not in_loop
            if _contains(node.body_stmt, sink_line):
                governing_guards.append((node.cond_text, c_lines))
                return _walk(node.body_stmt, in_loop=in_loop)
            b_defs = _collect_all(node.body_stmt)
            if _subtree_has_exit(node.body_stmt):
                governing_guards.append((node.cond_text, c_lines))
            else:
                conditional_def_guards.append((node.cond_text, c_lines, b_defs))
            return False
        if node.kind == "SYNCHRONIZED":
            c_lines = set(node.cond_lines or {node.start_line})
            causal_stmts.append(_FlowStmt("SIMPLE", min(c_lines), max(c_lines), code=node.cond_text, lines=c_lines))
            return _walk(node.body_stmt, in_loop=in_loop)
        saw_unknown_causal = True
        return False

    for st in stmts:
        if _walk(st, in_loop=False):
            break

    if saw_unknown_causal or not sink_stmts:
        return invalid

    # Precompute `(defs, uses)` for every causally reachable statement
    stmt_du: list[tuple[_FlowStmt, set[str], set[str]]] = []
    for st in causal_stmts:
        d, u = _extract_stmt_defs_and_uses(st.code, st.kind, enclosing_class=enclosing_class, **kw_ctx)
        stmt_du.append((st, d, u))

    sink_stmt_lines: set[int] = set()
    for st in sink_stmts:
        sink_stmt_lines.update(st.lines or set(range(st.start_line, st.end_line + 1)))

    # 1. Seed backward data slice from vulnerable sink payload expressions
    sink_backward_vars: set[str] = _extract_sink_payload_vars(
        sink_stmts,
        primary_cwe,
        enclosing_class=enclosing_class,
        static_field_resolver=static_field_resolver,
        **kw_ctx,
    )
    # Remove self-reference noise unless field access exists
    changed = True
    while changed:
        changed = False
        for _st, d, u in stmt_du:
            if d & sink_backward_vars:
                before = len(sink_backward_vars)
                sink_backward_vars.update(u)
                if len(sink_backward_vars) != before:
                    changed = True

    # 2. Seed forward taint slice from sink_backward_vars + OpenGrep source/intermediate lines + HTTP/Swing sources
    trace_lines: set[int] = set()
    sig = record.get("heuristic_signals") if isinstance(record.get("heuristic_signals"), dict) else {}
    if type(sig.get("source_line")) is int:
        trace_lines.add(int(sig["source_line"]))
    for snip in record.get("snippets") or []:
        if isinstance(snip, dict) and snip.get("role") in ("source", "intermediate"):
            sl = (snip.get("start") or {}).get("line")
            el = (snip.get("end") or {}).get("line", sl)
            if type(sl) is int and type(el) is int:
                trace_lines.update(range(sl, el + 1))

    taint_forward_vars: set[str] = {v for v in sink_backward_vars if v != "this"}
    for st, d, u in stmt_du:
        st_lines = st.lines or set(range(st.start_line, st.end_line + 1))
        if (st_lines & trace_lines) or _TAINT_SOURCE_METHOD_RE.search(st.code):
            taint_forward_vars.update(d)
    changed = True
    while changed:
        changed = False
        for _st, d, u in stmt_du:
            if u & taint_forward_vars:
                before = len(taint_forward_vars)
                taint_forward_vars.update(d)
                if len(taint_forward_vars) != before:
                    changed = True

    # 3. Compute control-flow guard & exception-control slices (promoting conditional defs/try regions)
    guard_backward_vars: set[str] = set()
    active_guards: list[tuple[str, set[int]]] = list(governing_guards)
    promoted_cond_idxs: set[int] = set()
    promoted_exc_idxs: set[int] = set()
    seeded_exc_stmts: set[int] = set()
    changed = True
    while changed:
        changed = False
        relevant_all = sink_backward_vars | guard_backward_vars
        for idx, (c_txt, c_lns, b_defs) in enumerate(conditional_def_guards):
            if idx not in promoted_cond_idxs and ((b_defs & relevant_all) or (c_lns & exception_control_lines)):
                promoted_cond_idxs.add(idx)
                active_guards.append((c_txt, c_lns))
                changed = True
        for idx, (reg_lns, reg_defs, reg_has_exit) in enumerate(conditional_exception_regions):
            if idx not in promoted_exc_idxs and (reg_has_exit or (reg_defs & relevant_all)):
                promoted_exc_idxs.add(idx)
                before_lns = len(exception_control_lines)
                exception_control_lines.update(reg_lns)
                if len(exception_control_lines) != before_lns:
                    changed = True
        if exception_control_lines:
            for s_idx, (st, _d, u) in enumerate(stmt_du):
                if s_idx in seeded_exc_stmts:
                    continue
                st_lns = st.lines or set(range(st.start_line, st.end_line + 1))
                if st_lns & exception_control_lines:
                    seeded_exc_stmts.add(s_idx)
                    exc_vars = u | _extract_expr_var_idents(st.code, **kw_ctx)
                    before = len(guard_backward_vars)
                    guard_backward_vars.update(exc_vars)
                    if len(guard_backward_vars) != before:
                        changed = True
        tainted_or_sink = sink_backward_vars | taint_forward_vars
        for c_txt, _c_lns in active_guards:
            for clause in _split_top_level_bool_clauses(c_txt):
                if _is_pure_jdbc_resource_liveness_clause(
                    clause,
                    visible_var_info=visible_var_info,
                    tainted_or_sink_vars=tainted_or_sink,
                    caller_unit=caller_unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                ):
                    continue
                c_vars = _extract_expr_var_idents(clause, **kw_ctx)
                before = len(guard_backward_vars)
                guard_backward_vars.update(c_vars)
                if len(guard_backward_vars) != before:
                    changed = True
        for _st, d, u in stmt_du:
            if d & guard_backward_vars:
                before = len(guard_backward_vars)
                guard_backward_vars.update(u)
                if len(guard_backward_vars) != before:
                    changed = True

    # 4. Check for mutable class fields / non-local state inside sink or guard backward slices
    final_fields = _extract_class_final_fields(caller_unit, enclosing_class)
    has_mutable_nonlocal = False
    for v in (sink_backward_vars | guard_backward_vars):
        if v == "this":
            has_mutable_nonlocal = True
            break
        vinfo = visible_var_info.get(v)
        if vinfo is None:
            has_mutable_nonlocal = True
            break
        if vinfo.get("is_field"):
            decl_fqn = resolve_stdlib_class_fqn(
                vinfo.get("declared_type_ref"),
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
            )
            if not (v in final_fields and decl_fqn in ("java.lang.String", "java.lang.Integer", "java.lang.Long", "java.lang.Boolean")):
                has_mutable_nonlocal = True
                break

    active_guard_lines: set[int] = set()
    for _ct, clns in active_guards:
        active_guard_lines.update(clns)

    causal_by_line: dict[int, list[tuple[_FlowStmt, set[str], set[str]]]] = {}
    for item in stmt_du:
        st = item[0]
        for ln in st.lines or set(range(st.start_line, st.end_line + 1)):
            causal_by_line.setdefault(ln, []).append(item)

    return {
        "valid": True,
        "primary_cwe": primary_cwe,
        "sink_line": sink_line,
        "sink_stmt_lines": sink_stmt_lines,
        "active_guard_lines": active_guard_lines,
        "exception_control_lines": exception_control_lines,
        "sink_backward_vars": sink_backward_vars,
        "taint_forward_vars": taint_forward_vars,
        "guard_backward_vars": guard_backward_vars,
        "has_mutable_nonlocal": has_mutable_nonlocal,
        "causal_by_line": causal_by_line,
        "causal_stmts_du": stmt_du,
        "active_guards": active_guards,
    }


def _classify_unverified_call_decisiveness(
    lno: int,
    site_qual: str | None,
    flow_slice: dict[str, Any],
) -> tuple[bool, str]:
    """Return `(is_decisive, reason)` for an unverified call on `lno` in the enclosing method.

    Always fails closed (`True`) when `flow_slice["valid"]` is False or any data/control/exception/aliasing dependency exists.
    """
    if not flow_slice.get("valid"):
        return True, "unverified_decisive_or_guard_call"

    sink_stmt_lines: set[int] = flow_slice["sink_stmt_lines"]
    active_guard_lines: set[int] = flow_slice["active_guard_lines"]
    exception_control_lines: set[int] = flow_slice.get("exception_control_lines") or set()
    if lno in sink_stmt_lines:
        return True, "unverified_call_on_sink"
    if lno in active_guard_lines:
        return True, "unverified_call_in_governing_guard"
    if lno in exception_control_lines:
        return True, "unverified_call_in_exception_control_region"

    causal_items = flow_slice["causal_by_line"].get(lno)
    if not causal_items:
        sink_ln = flow_slice.get("sink_line")
        if type(sink_ln) is int and lno > sink_ln:
            return False, "post_sink_non_loop"
        return False, "unrelated_branch_not_reaching_sink"

    sink_bwd: set[str] = flow_slice["sink_backward_vars"]
    taint_fwd: set[str] = flow_slice["taint_forward_vars"]
    guard_bwd: set[str] = flow_slice["guard_backward_vars"]
    has_mut_nonlocal: bool = bool(flow_slice["has_mutable_nonlocal"])
    decisive_defs = sink_bwd | guard_bwd
    decisive_uses = sink_bwd | taint_fwd | guard_bwd

    for st, defs, uses in causal_items:
        if st.has_brace_or_lambda:
            return True, "unmodeled_brace_or_lambda_before_sink"
        if defs & decisive_defs:
            return True, "unverified_helper_defines_flow_or_guard_var"
        if uses & decisive_uses:
            return True, "unverified_helper_receives_tainted_or_flow_var"
        if has_mut_nonlocal:
            return True, "unverified_call_may_mutate_nonlocal_flow_state"

    return False, "disjoint_from_sink_and_taint_flow"


def analyze_flow_dependencies(record: dict[str, Any]) -> dict[str, Any]:
    """Inspect whether conclusive triage depends on missing, dropped, >3-hop, ambiguous, dispatch-unproven, or hash-mismatched helpers.

    Uses AST-based causality, sink payload slicing, backward/forward data dependence, and control-flow
    guard analysis to separate flow-deciding unverified helpers from provably independent calls
    (such as DB connection setup independent of tainted input, post-sink non-loop calls, or constant-arg telemetry).
    Always fails closed when method lines are truncated, unparseable, or mutable non-local state could be affected.
    """
    snapshots = record.get("snapshots") if isinstance(record.get("snapshots"), dict) else {}
    snippets = record.get("snippets") or []

    helper_hash_mismatches: list[dict[str, Any]] = []
    verified_lines_by_path: dict[str, dict[int, str]] = {}

    for snip in snippets:
        if not isinstance(snip, dict):
            continue
        sp = snip.get("path")
        ssha = snip.get("sha256")
        snap = snapshots.get(sp) if isinstance(sp, str) else None
        if not isinstance(snap, dict) or not isinstance(ssha, str) or snap.get("sha256") != ssha:
            helper_hash_mismatches.append(
                {
                    "role": snip.get("role"),
                    "path": sp,
                    "snippet_sha256": ssha,
                    "snapshot_sha256": snap.get("sha256") if isinstance(snap, dict) else None,
                }
            )
            continue
        line_map = verified_lines_by_path.setdefault(sp, {})
        for ln in snip.get("lines") or []:
            if isinstance(ln, dict) and type(ln.get("line")) is int:
                line_map[ln["line"]] = str(ln.get("text") or "")

    primary = snippets[0] if snippets and isinstance(snippets[0], dict) else {}
    p_path = primary.get("path") if isinstance(primary.get("path"), str) else None
    p_verified = verified_lines_by_path.get(p_path, {}) if p_path else {}

    jctx = record.get("java_context") if isinstance(record.get("java_context"), dict) else {}
    enc = jctx.get("enclosing_method") if isinstance(jctx.get("enclosing_method"), dict) else None
    enclosing_class = jctx.get("enclosing_class") if isinstance(jctx.get("enclosing_class"), str) else None
    same_file_callees = [c for c in (jctx.get("same_file_callees") or []) if isinstance(c, dict)]

    # Detect same-file callees whose body lines were cut by budget/snippet compaction
    dropped_same_file_helpers: list[dict[str, Any]] = []
    for callee in same_file_callees:
        cname = callee.get("name")
        hs = callee.get("header_line") or callee.get("start_line")
        he = callee.get("end_line")
        if type(hs) is int and type(he) is int and he >= hs and p_verified:
            missing = [ln for ln in range(hs, he + 1) if ln not in p_verified]
            if missing:
                dropped_same_file_helpers.append(
                    {"name": cname, "start_line": hs, "end_line": he, "missing_lines_count": len(missing)}
                )

    units_by_path = _parse_verified_java_units(verified_lines_by_path)
    all_units = list(units_by_path.values())
    caller_unit = units_by_path.get(p_path) if p_path else None
    if caller_unit is None:
        caller_unit = {
            "path": p_path or "",
            "min_line": 2,
            "has_complete_header": False,
            "package_name": jctx.get("package_name") if isinstance(jctx.get("package_name"), str) else None,
            "imports": [],
            "classes": {},
            "methods": [],
            "line_map": p_verified,
        }
    _merge_header_metadata_into_unit(caller_unit, record, p_path)

    wild_extra_pkgs = [
        imp[:-2]
        for imp in _extract_non_static_type_imports(caller_unit)
        if imp.endswith(".*")
    ]
    project_pkg_classes = collect_project_package_classes(
        record,
        all_units,
        primary_path=p_path,
        primary_pkg=caller_unit.get("package_name"),
        extra_pkgs=wild_extra_pkgs,
    )

    static_field_resolver = make_verified_static_stdlib_field_resolver(record)

    primary_enc_method = None
    if enc and type(enc.get("header_line")) is int:
        primary_enc_method = next(
            (m for m in caller_unit["methods"] if m.get("header_line") == enc["header_line"]),
            enc,
        )
    visible_var_info = _collect_visible_var_info(
        p_verified,
        primary_enc_method or enc,
        enclosing_class,
        caller_pkg=caller_unit.get("package_name"),
        caller_imports=caller_unit.get("imports"),
        caller_unit=caller_unit,
        project_pkg_classes=project_pkg_classes,
        all_units=all_units,
        static_field_resolver=static_field_resolver,
    )

    # Resolve authoritative sink line coordinate for AST-based causal & data/control slicing
    sig = record.get("heuristic_signals") if isinstance(record.get("heuristic_signals"), dict) else {}
    resolved_sink_line: int | None = None
    if type(sig.get("sink_line")) is int:
        resolved_sink_line = int(sig["sink_line"])
    else:
        for sn in snippets:
            if isinstance(sn, dict) and sn.get("role") == "sink" and type((sn.get("start") or {}).get("line")) is int:
                resolved_sink_line = int(sn["start"]["line"])
                break
        if resolved_sink_line is None and type((record.get("start") or {}).get("line")) is int:
            resolved_sink_line = int(record["start"]["line"])

    flow_slice = _build_enclosing_method_flow_slice(
        record=record,
        p_verified=p_verified,
        enc=primary_enc_method or enc,
        enclosing_class=enclosing_class,
        sink_line=resolved_sink_line,
        visible_var_info=visible_var_info,
        caller_unit=caller_unit,
        project_pkg_classes=project_pkg_classes,
        all_units=all_units,
        static_field_resolver=static_field_resolver,
    )

    # Check unresolved_calls from heuristics analysis
    max_hop_exceeded: list[dict[str, Any]] = []
    unresolved_calls: list[dict[str, Any]] = []
    non_decisive_unresolved_calls: list[dict[str, Any]] = []
    seen_non_decisive_keys: set[tuple[Any, Any, Any]] = set()
    resolved_callee_queue: list[tuple[dict[str, Any], int]] = []
    visited_callees: set[tuple[str, str | None, str, int]] = set()

    def _record_non_decisive(qual: str | None, mname: str | None, lno: int | None, reason: str) -> None:
        key = (qual, mname, lno)
        if key not in seen_non_decisive_keys:
            seen_non_decisive_keys.add(key)
            non_decisive_unresolved_calls.append(
                {"qualifier": qual, "method": mname, "line": lno, "reason": reason}
            )

    def _enqueue_callee(target_info: dict[str, Any] | None, next_hop: int) -> None:
        if target_info is None:
            return
        tu = target_info["unit"]
        tm = target_info["method"]
        key = (str(tu.get("path")), tm.get("owner_class"), str(tm.get("name")), int(tm.get("header_line") or 0))
        if key not in visited_callees:
            visited_callees.add(key)
            resolved_callee_queue.append((target_info, next_hop))

    for u in sig.get("unresolved_calls") or []:
        if not isinstance(u, dict):
            continue
        if u.get("reason") == "max_hop_depth_exceeded":
            max_hop_exceeded.append(u)
            continue
        qual = u.get("qualifier") if isinstance(u.get("qualifier"), str) else None
        mname = u.get("method") if isinstance(u.get("method"), str) else None
        uline = u.get("line") if type(u.get("line")) is int else None
        if qual and mname and (qual, mname) in _STD_TAINT_PASSTHROUGH_CALLS:
            if (
                not _is_leading_qualifier_shadowed(
                    qual,
                    visible_var_info=visible_var_info,
                    caller_unit=caller_unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                    caller_imports=caller_unit.get("imports"),
                    require_expr_scope=True,
                )
                and resolve_stdlib_class_fqn(
                    qual,
                    caller_unit=caller_unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                    caller_imports=caller_unit.get("imports"),
                )
                is not None
            ):
                continue
        if mname and type(uline) is int and uline in p_verified:
            # Re-verify EVERY matching call site on `uline` (or its verified multi-line statement window when
            # heuristics anchored a multi-line Java statement at its start line `uline`):
            # resolve ONLY if >= 1 matching call site exists AND every matching call site is
            # a proven stdlib/inherited-stdlib API call, a verified stdlib constructor, a verified
            # project helper, or provably non-decisive for the finding's sink/taint/guard slice.
            def _collect_window_call_sites(start_lno: int) -> tuple[list[tuple[int, str, dict[str, Any]]], list[str]]:
                s_l0 = _strip_comments_and_strings_preserve_lines(p_verified[start_lno])[0].strip()
                direct = [(start_lno, s_l0, s) for s in _extract_call_sites_on_line(s_l0) if s["method"] == mname]
                if direct:
                    return direct, [s_l0]
                win_lns: list[int] = [start_lno]
                if flow_slice.get("valid"):
                    c_items = flow_slice.get("causal_by_line", {}).get(start_lno) or []
                    for c_st, _, _ in c_items:
                        for ln_c in sorted(c_st.lines or range(c_st.start_line, c_st.end_line + 1)):
                            if ln_c in p_verified and ln_c >= start_lno and ln_c not in win_lns and ln_c <= start_lno + 10:
                                win_lns.append(ln_c)
                if len(win_lns) == 1 and not s_l0.endswith((";", "{", "}")):
                    cur_ln = start_lno
                    while cur_ln < start_lno + 8 and (cur_ln + 1) in p_verified:
                        cur_ln += 1
                        win_lns.append(cur_ln)
                        nxt_c = _strip_comments_and_strings_preserve_lines(p_verified[cur_ln])[0].strip()
                        if nxt_c.endswith((";", "{", "}")):
                            break
                win_lns = sorted(set(win_lns))
                raw_win = "\n".join(p_verified[ln_w] for ln_w in win_lns)
                clean_win = [cl.strip() for cl in _strip_java_non_executable_preserve_lines(raw_win)]
                found_sites: list[tuple[int, str, dict[str, Any]]] = []
                for idx_w, (ln_w, cl_w) in enumerate(zip(win_lns, clean_win)):
                    if not cl_w:
                        continue
                    for s_item in _extract_call_sites_on_line(cl_w):
                        if s_item["method"] != mname:
                            continue
                        eff_line = cl_w
                        eff_site = dict(s_item)
                        if (
                            eff_site["chained"]
                            and eff_site["qualifier"] is None
                            and _extract_chain_receiver_expr(cl_w, eff_site.get("start")) is None
                            and idx_w > 0
                        ):
                            pref_chunks: list[str] = []
                            for j_back in range(idx_w - 1, max(-1, idx_w - 7), -1):
                                prev_c = clean_win[j_back]
                                if not prev_c:
                                    continue
                                if prev_c.endswith((";", "{", "}", ":")):
                                    break
                                pref_chunks.append(prev_c)
                            if pref_chunks:
                                pref_s = " ".join(reversed(pref_chunks)) + " "
                                eff_line = pref_s + cl_w
                                eff_site["start"] = len(pref_s) + int(eff_site["start"])
                        found_sites.append((ln_w, eff_line, eff_site))
                return found_sites, clean_win

            window_sites, window_cleans = _collect_window_call_sites(uline)
            if not window_sites and any(
                _is_verified_stdlib_constructor_on_line(
                    cw,
                    mname,
                    caller_unit=caller_unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                    caller_imports=caller_unit.get("imports"),
                )
                for cw in window_cleans
                if cw
            ):
                continue
            if window_sites:
                all_sites_ok = True
                resolved_targets_for_line: list[dict[str, Any]] = []
                non_decisive_reasons: list[tuple[str | None, int, str]] = []
                for site_lno, site_clean_line, site in window_sites:
                    s_qual = site["qualifier"]
                    s_chained = site["chained"]
                    s_new = site["is_new_ctor_chain"]
                    if _is_stdlib_call(
                        s_qual,
                        mname,
                        s_chained,
                        visible_var_info,
                        caller_unit.get("imports"),
                        caller_unit=caller_unit,
                        project_pkg_classes=project_pkg_classes,
                        all_units=all_units,
                        enclosing_class=enclosing_class,
                        line_clean=site_clean_line,
                        call_start=site.get("start"),
                        is_new_ctor_chain=s_new,
                        static_field_resolver=static_field_resolver,
                    ):
                        continue
                    s_arg_cnt = _extract_call_arg_count_at_line(
                        p_verified,
                        site_lno,
                        s_qual,
                        mname,
                        is_new_ctor_chain=s_new,
                    )
                    s_ok, s_tinfo = _resolve_and_verify_call(
                        qual=s_qual,
                        mname=mname,
                        chained=s_chained,
                        is_new_ctor_chain=s_new,
                        arg_count=s_arg_cnt,
                        caller_unit=caller_unit,
                        enclosing_class=enclosing_class,
                        enclosing_method=primary_enc_method,
                        visible_var_info=visible_var_info,
                        all_units=all_units,
                    )
                    if s_ok and s_tinfo is not None:
                        is_dec, _ = _classify_unverified_call_decisiveness(site_lno, s_qual, flow_slice)
                        if is_dec:
                            resolved_targets_for_line.append(s_tinfo)
                        continue
                    is_dec, dec_reason = _classify_unverified_call_decisiveness(site_lno, s_qual, flow_slice)
                    if not is_dec:
                        non_decisive_reasons.append((s_qual, site_lno, dec_reason))
                        continue
                    all_sites_ok = False
                    break
                if all_sites_ok:
                    for ti in resolved_targets_for_line:
                        _enqueue_callee(ti, 1)
                    for nd_qual, nd_lno, nd_reason in non_decisive_reasons:
                        _record_non_decisive(nd_qual, mname, nd_lno, nd_reason)
                    continue
        if mname:
            arg_cnt = _extract_call_arg_count_at_line(p_verified, uline, qual, mname)
            ok, tinfo = _resolve_and_verify_call(
                qual=qual,
                mname=mname,
                chained=False,
                is_new_ctor_chain=False,
                arg_count=arg_cnt,
                caller_unit=caller_unit,
                enclosing_class=enclosing_class,
                enclosing_method=primary_enc_method,
                visible_var_info=visible_var_info,
                all_units=all_units,
            )
            if ok:
                if type(uline) is not int or _classify_unverified_call_decisiveness(uline, qual, flow_slice)[0]:
                    _enqueue_callee(tinfo, 1)
                continue
        unresolved_calls.append(u)

    # Check verified enclosing method lines AND resolved helper bodies (up to 3 hops) for unverified decisive calls
    unverified_decisive_calls: list[dict[str, Any]] = []
    seen_decisive_keys: set[tuple[Any, Any, Any]] = set()

    def _record_decisive(qual: str | None, mname: str, lno: int, reason: str) -> None:
        key = (qual, mname, lno)
        if key not in seen_decisive_keys:
            seen_decisive_keys.add(key)
            unverified_decisive_calls.append(
                {"qualifier": qual, "method": mname, "line": lno, "reason": reason}
            )

    def _scan_method_calls(
        unit: dict[str, Any],
        m_enc_cls: str | None,
        m_obj: dict[str, Any] | None,
        vinfo_map: dict[str, dict[str, Any]],
        h_line: int,
        upper_bound: int,
        hop_depth: int,
        method_flow_slice: dict[str, Any] | None = None,
    ) -> None:
        lmap = unit.get("line_map") or {}
        body_lines: list[tuple[int, str]] = []
        if h_line in lmap:
            hdr_txt = lmap[h_line]
            brace_idx = hdr_txt.find("{")
            if brace_idx != -1 and hdr_txt[brace_idx + 1 :].strip():
                body_lines.append((h_line, hdr_txt[brace_idx + 1 :]))
        for lno in sorted(lmap):
            if h_line < lno <= upper_bound:
                body_lines.append((lno, lmap[lno]))
        if not body_lines:
            return
        use_slice = bool(hop_depth == 0 and method_flow_slice and method_flow_slice.get("valid"))
        clean_body = _strip_java_non_executable_preserve_lines("\n".join(txt for _, txt in body_lines))
        clean_rows = [(lno, cline.strip()) for (lno, _raw_t), cline in zip(body_lines, clean_body)]
        for row_idx, (lno, s_clean) in enumerate(clean_rows):
            if not s_clean:
                continue
            covered_paren_indices: set[int] = set()
            for site in _extract_call_sites_on_line(s_clean):
                if type(site.get("open_paren_idx")) is int:
                    covered_paren_indices.add(site["open_paren_idx"])
                if type(site.get("ctor_open_idx")) is int:
                    covered_paren_indices.add(site["ctor_open_idx"])
                qual = site["qualifier"]
                mname = site["method"]
                chained = site["chained"]
                is_new_chain = site["is_new_ctor_chain"]
                eff_line_clean = s_clean
                eff_call_start = site.get("start")
                if (
                    chained
                    and qual is None
                    and _extract_chain_receiver_expr(s_clean, eff_call_start) is None
                    and row_idx > 0
                ):
                    pref_chunks: list[str] = []
                    for j_back in range(row_idx - 1, max(-1, row_idx - 7), -1):
                        prev_c = clean_rows[j_back][1]
                        if not prev_c:
                            continue
                        if prev_c.endswith((";", "{", "}", ":")):
                            break
                        pref_chunks.append(prev_c)
                    if pref_chunks:
                        pref_s = " ".join(reversed(pref_chunks)) + " "
                        eff_line_clean = pref_s + s_clean
                        eff_call_start = len(pref_s) + int(eff_call_start)
                if _is_stdlib_call(
                    qual,
                    mname,
                    chained,
                    vinfo_map,
                    unit.get("imports"),
                    caller_unit=unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                    enclosing_class=m_enc_cls,
                    line_clean=eff_line_clean,
                    call_start=eff_call_start,
                    is_new_ctor_chain=is_new_chain,
                    static_field_resolver=static_field_resolver,
                ):
                    continue
                if use_slice and method_flow_slice is not None:
                    is_dec, dec_reason = _classify_unverified_call_decisiveness(lno, qual, method_flow_slice)
                else:
                    is_dec, dec_reason = True, "unverified_decisive_or_guard_call"
                if hop_depth >= 3:
                    max_hop_exceeded.append({"qualifier": qual, "method": mname, "line": lno, "reason": "max_hop_depth_exceeded"})
                    continue
                arg_cnt = _extract_call_arg_count_at_line(
                    lmap,
                    lno,
                    qual,
                    mname,
                    is_new_ctor_chain=is_new_chain,
                )
                ok, tinfo = _resolve_and_verify_call(
                    qual=qual,
                    mname=mname,
                    chained=chained,
                    is_new_ctor_chain=is_new_chain,
                    arg_count=arg_cnt,
                    caller_unit=unit,
                    enclosing_class=m_enc_cls,
                    enclosing_method=m_obj,
                    visible_var_info=vinfo_map,
                    all_units=all_units,
                )
                if ok:
                    if is_dec:
                        _enqueue_callee(tinfo, hop_depth + 1)
                    continue
                if not is_dec:
                    _record_non_decisive(qual, mname, lno, dec_reason)
                    continue
                _record_decisive(qual, mname, lno, dec_reason)

            # Check EVERY constructor/`new` site (single-line, multi-line, nested generics, anonymous class, or opaque unparsed `new`)
            for csite in _extract_non_chained_ctor_sites(s_clean):
                if type(csite.get("open_paren_idx")) is int:
                    covered_paren_indices.add(csite["open_paren_idx"])
                ctype = csite["ctor_type"]
                is_opaque = bool(csite.get("opaque"))
                if not is_opaque and (
                    resolve_stdlib_class_fqn(
                        ctype,
                        caller_unit=unit,
                        project_pkg_classes=project_pkg_classes,
                        all_units=all_units,
                        caller_imports=unit.get("imports"),
                    )
                    is not None
                ):
                    continue
                # Allow 0-arg default constructor on a single verified concrete helper class in `all_units` (never if opaque/anon)
                if not is_opaque and csite["arg_count"] == 0 and not csite.get("multiline"):
                    cref = _parse_java_type_ref(ctype)
                    cands = _resolve_type_ref_to_candidates(
                        cref,
                        unit.get("package_name"),
                        unit.get("imports") or [],
                        all_units,
                        caller_unit=unit,
                    )
                    if len(cands) == 1 and not cands[0]["class_info"].get("extends"):
                        continue
                if use_slice and method_flow_slice is not None:
                    is_dec, dec_reason = _classify_unverified_call_decisiveness(lno, ctype, method_flow_slice)
                    if is_opaque and not is_dec and dec_reason != "post_sink_non_loop":
                        is_dec, dec_reason = True, "unparsed_constructor_scope_fail_closed"
                else:
                    is_dec, dec_reason = True, (
                        "unparsed_constructor_fail_closed" if is_opaque else "unverified_constructor_call"
                    )
                if not is_dec:
                    _record_non_decisive(ctype, "<init>", lno, dec_reason)
                    continue
                _record_decisive(ctype, "<init>", lno, dec_reason)

            # Exhaustive `::` coverage guard: EVERY `::` in stripped executable code MUST be verified or fail closed!
            for rsite in _extract_method_ref_sites_on_line(s_clean):
                rowner = rsite["owner"]
                rmember = rsite["member"]
                is_opaque = bool(rsite.get("opaque"))
                if _is_verified_stdlib_method_ref(
                    rowner,
                    rmember,
                    opaque=is_opaque,
                    visible_var_info=vinfo_map,
                    caller_imports=unit.get("imports"),
                    caller_unit=unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                    enclosing_class=m_enc_cls,
                ):
                    continue
                if use_slice and method_flow_slice is not None:
                    is_dec, dec_reason = _classify_unverified_call_decisiveness(lno, rowner, method_flow_slice)
                    if is_opaque and not is_dec and dec_reason != "post_sink_non_loop":
                        is_dec, dec_reason = True, "unparsed_method_ref_scope_fail_closed"
                else:
                    is_dec, dec_reason = True, (
                        "unparsed_method_reference" if is_opaque else "unverified_method_reference"
                    )
                if not is_dec:
                    _record_non_decisive(rowner, f"::{rmember}", lno, dec_reason)
                    continue
                _record_decisive(rowner, f"::{rmember}", lno, f"unverified_method_reference:{dec_reason}")

            # Lexical `(` coverage guard: catch any executable invocation `(` missed by regex extractors!
            for usite in _find_uncovered_call_parens(s_clean, covered_paren_indices):
                uqual = usite["qualifier"]
                umethod = usite["method"]
                if use_slice and method_flow_slice is not None:
                    is_dec, dec_reason = _classify_unverified_call_decisiveness(lno, uqual, method_flow_slice)
                    if not is_dec and dec_reason != "post_sink_non_loop":
                        is_dec, dec_reason = True, "unparsed_call_scope_fail_closed"
                else:
                    is_dec, dec_reason = True, "unparsed_call_fail_closed"
                if not is_dec:
                    _record_non_decisive(uqual, umethod, lno, dec_reason)
                    continue
                _record_decisive(uqual, umethod, lno, f"unparsed_call:{dec_reason}")

    if p_verified:
        h_line = int(enc["header_line"]) if (enc and type(enc.get("header_line")) is int) else min(p_verified)
        e_line = int(enc["end_line"]) if (enc and type(enc.get("end_line")) is int) else max(p_verified)
        sink_line_scan = resolved_sink_line if type(resolved_sink_line) is int else e_line
        _scan_method_calls(
            caller_unit,
            enclosing_class,
            primary_enc_method,
            visible_var_info,
            h_line,
            max(sink_line_scan, e_line),
            0,
            method_flow_slice=flow_slice,
        )
        while resolved_callee_queue:
            tinfo, cur_hop = resolved_callee_queue.pop(0)
            tu = tinfo["unit"]
            tm = tinfo["method"]
            t_cls = tm.get("owner_class")
            t_vinfo = _collect_visible_var_info(
                tu["line_map"],
                tm,
                t_cls,
                caller_pkg=tu.get("package_name"),
                caller_imports=tu.get("imports"),
                caller_unit=tu,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
                static_field_resolver=static_field_resolver,
            )
            t_hl = int(tm.get("header_line") or tm.get("start_line") or 1)
            t_el = int(tm.get("end_line") or t_hl)
            _scan_method_calls(tu, t_cls, tm, t_vinfo, t_hl, t_el, cur_hop)

    reasons: list[str] = []
    if helper_hash_mismatches:
        reasons.append(f"helper_hash_mismatch ({len(helper_hash_mismatches)})")
    if max_hop_exceeded:
        reasons.append(f"max_hop_depth_exceeded ({len(max_hop_exceeded)})")
    if dropped_same_file_helpers:
        reasons.append(f"dropped_same_file_helpers ({[d.get('name') for d in dropped_same_file_helpers[:4]]})")
    if unresolved_calls:
        reasons.append(f"unresolved_calls ({[u.get('method') for u in unresolved_calls[:4]]})")
    if unverified_decisive_calls:
        reasons.append(f"unverified_decisive_calls ({[c.get('method') for c in unverified_decisive_calls[:4]]})")

    flow_slice_summary = (
        {
            "valid": True,
            "sink_line": flow_slice["sink_line"],
            "sink_backward_vars": sorted(flow_slice["sink_backward_vars"]),
            "taint_forward_vars": sorted(flow_slice["taint_forward_vars"]),
            "guard_backward_vars": sorted(flow_slice["guard_backward_vars"]),
            "exception_control_lines": sorted(flow_slice.get("exception_control_lines") or ()),
            "has_mutable_nonlocal": flow_slice["has_mutable_nonlocal"],
        }
        if flow_slice.get("valid")
        else {"valid": False}
    )

    return {
        "has_unverified_helper_dependency": bool(reasons),
        "helper_hash_mismatches": helper_hash_mismatches,
        "max_hop_depth_exceeded": max_hop_exceeded,
        "unresolved_calls": unresolved_calls,
        "dropped_same_file_helpers": dropped_same_file_helpers,
        "unverified_decisive_calls": unverified_decisive_calls,
        "non_decisive_unresolved_calls": non_decisive_unresolved_calls,
        "flow_slice_summary": flow_slice_summary,
        "reasons": reasons,
    }
