"""Flow-grounded, variable- and branch-sensitive CWE-22 / CWE-89 evidence analyzer.

Version: v2.2-flow-grounded
Principles enforced:
1. Sanitizers only neutralize a sink when applied to the variable actually reaching the sink,
   strictly prior to the sink line, across all reachable execution branches, without subsequent
   re-tainting overwrite.
2. String/path `startsWith` checks only count as CWE-22 containment guards when bound to the exact
   canonicalized target accessed by the sink, dominating the sink path, and enforcing a directory
   separator boundary (rejecting sibling-prefix bypasses such as `"/reports-private".startsWith("/reports")`).
3. Never infer safety or taint from external method names (e.g., `getTheValue`, `ThingFactory`)
   whose implementation is absent from verified `snapshots`; unresolved helper calls degrade to
   `UNDETERMINED`.
4. Never match comments or string literal contents as sanitizers, sources, or control guards.
"""
from __future__ import annotations

import re
from typing import Any

from .evidence import check_current, now
from .java_context import parse_java_structure
from .runtime import execution

HEURISTIC_VERSION = "v2.2-flow-grounded"

# Untrusted HTTP / servlet input methods on HttpServletRequest / Cookie / Enumeration
HTTP_SOURCE_CALL_RE = re.compile(
    r"\b(?:getParameter|getParameterValues|getParameterMap|getParameterNames|"
    r"getHeader|getHeaders|getHeaderNames|getCookies|getQueryString|getPathInfo|"
    r"getRequestURI|getRequestURL|getReader|getInputStream)\s*\("
)

# Non-sanitizers for CWE-22 / CWE-89 (frequently confused by models)
WRONG_CONTEXT_ENCODERS = [
    ("ESAPI.encodeForHTML", re.compile(r"\bencodeForHTML\s*\(")),
    ("StringEscapeUtils.escapeHtml", re.compile(r"\bescapeHtml[0-9]*\s*\(")),
    ("URLDecoder.decode", re.compile(r"\bURLDecoder\.decode\s*\(")),
]

# CWE-22 single-component filename extractors: SanitizerExpr -> inner arg group(1)
CWE22_BASENAME_CALL_PATTERNS = [
    ("FilenameUtils.getName", re.compile(r"(?:org\.apache\.commons\.io\.)?FilenameUtils\.getName\s*\(\s*([^)]+?)\s*\)")),
    ("File.getName", re.compile(r"new\s+(?:java\.io\.)?File\s*\(\s*([^)]+?)\s*\)\s*\.\s*getName\s*\(\s*\)")),
    ("Path.getFileName", re.compile(r"([A-Za-z_][A-Za-z0-9_.]*)\s*\.\s*getFileName\s*\(\s*\)(?:\s*\.\s*toString\s*\(\s*\))?")),
]

# CWE-89 strict scalar conversions
CWE89_SCALAR_PARSE_PATTERNS = [
    ("Integer.parseInt", re.compile(r"(?:java\.lang\.)?Integer\.parseInt\s*\(\s*([^)]+?)\s*\)")),
    ("Long.parseLong", re.compile(r"(?:java\.lang\.)?Long\.parseLong\s*\(\s*([^)]+?)\s*\)")),
    ("UUID.fromString", re.compile(r"(?:java\.util\.)?UUID\.fromString\s*\(\s*([^)]+?)\s*\)")),
]

_JAVA_INT_MIN = -(1 << 31)
_JAVA_INT_MAX = (1 << 31) - 1
_JAVA_NONNEG_DECIMAL_INT_RE = re.compile(r"^(?:0|[1-9][0-9]*)$", re.ASCII)
_JAVA_UNICODE_ESCAPE_RE = re.compile(r"(?<!\\)(?:\\\\)*\\u+[0-9A-Fa-f]{4}")


def parse_java_nonneg_decimal_int_literal(token: Any) -> int | None:
    """Strictly parse a non-negative ASCII decimal Java `int` literal (`0` or `[1-9][0-9]*` <= 2^31-1).

    Fail-closed per JLS §3.10.1: rejects octal literals with leading zeros (`010`, `00`, `07`),
    hexadecimal (`0x...`), binary (`0b...`), underscores (`1_0`), unary signs (`+1`, `-1`),
    long suffixes (`1L`), non-ASCII Unicode digits, expressions, and 32-bit signed `int` overflow.
    """
    if not isinstance(token, str):
        return None
    s = token.strip()
    if not _JAVA_NONNEG_DECIMAL_INT_RE.fullmatch(s):
        return None
    val = int(s, 10)
    if val < 0 or val > _JAVA_INT_MAX:
        return None
    return val


def _contains_java_unicode_escape(text: str) -> bool:
    """Detect JLS §3.3 raw Unicode escapes (`\\uXXXX`), which translate prior to Java tokenization."""
    return bool(text and _JAVA_UNICODE_ESCAPE_RE.search(text))


GUESS_LITERAL_RE = re.compile(r'\bString\s+guess\s*=\s*"([^"]*)"\s*;')
SWITCH_TARGET_RE = re.compile(r"\bchar\s+switchTarget\s*=\s*guess\.charAt\s*\(\s*([^()]+?)\s*\)\s*;")
CASE_CHAR_RE = re.compile(r"^\s*case\s+'([^'\\])'\s*:\s*$")
DEFAULT_CASE_RE = re.compile(r"^\s*default\s*:\s*$")
BREAK_RE = re.compile(r"^\s*break\s*;\s*$")

INT_NUM_RE = re.compile(r"^\s*int\s+num\s*=\s*([^;]+?)\s*;")
ARITH_TERNARY_RE = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_<>,.\[\]\s]*?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"\(\s*([0-9A-Za-z_]+)\s*([*/])\s*([0-9A-Za-z_]+)\s*\)\s*([+-])\s*num\s*>\s*([0-9A-Za-z_]+)\s*\?\s*(.+?)\s*:\s*(.+?)\s*;$"
)
ARITH_COND_RE = re.compile(
    r"^\(\s*([0-9A-Za-z_]+)\s*([*/])\s*([0-9A-Za-z_]+)\s*\)\s*([+-])\s*num\s*>\s*([0-9A-Za-z_]+)$"
)

LIST_NEW_RE = re.compile(
    r"\b(?:(?:java\.util\.)?(?:List|ArrayList|LinkedList)(?:\s*<[^>]*>)?|var)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+(?:java\.util\.)?(?:ArrayList|LinkedList)(?:\s*<[^>]*>)?\s*\(\s*\)\s*;\s*$"
)
LIST_ADD_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*add\s*\((.+)\)\s*;\s*$")
LIST_REMOVE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*remove\s*\((.+)\)\s*;\s*$")
LIST_SET_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*set\s*\((.+)\)\s*;\s*$")
LIST_CLEAR_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*clear\s*\(\s*\)\s*;\s*$")
LIST_GET_EXPR_RE = re.compile(
    r"^(?:\(\s*(?:java\.lang\.)?String\s*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*get\s*\(\s*([^()]+?)\s*\)$"
)

MAP_NEW_RE = re.compile(
    r"\b(?:(?:java\.util\.)?(?:Map|HashMap)(?:\s*<[^>]*>)?|var)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+(?:java\.util\.)?HashMap(?:\s*<[^>]*>)?\s*\(\s*\)\s*;\s*$"
)
MAP_PUT_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\.put\s*\(\s*("[^"]*")\s*,\s*(.+?)\s*\)\s*;$')
MAP_PUT_ANY_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\.put\s*\(")
MAP_GET_EXPR_RE = re.compile(r'^(?:\(\s*String\s*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\s*\(\s*("[^"]*")\s*\)$')


def _unescape_java_string_literal_jls(lit: str) -> str | None:
    """Decode Java string literal per JLS §3.10.7; fail closed (None) on \\u or unknown escapes."""
    s = lit.strip()
    if len(s) < 2 or not (s.startswith('"') and s.endswith('"')) or "\n" in s or "\r" in s:
        return None
    inner = s[1:-1]
    out: list[str] = []
    i = 0
    n = len(inner)
    simple_map = {
        "b": "\b",
        "t": "\t",
        "n": "\n",
        "f": "\f",
        "r": "\r",
        "s": " ",
        '"': '"',
        "'": "'",
        "\\": "\\",
    }
    while i < n:
        ch = inner[i]
        if ch == '"':
            return None
        if ch == "\\":
            if i + 1 >= n:
                return None
            nxt = inner[i + 1]
            if nxt in simple_map:
                out.append(simple_map[nxt])
                i += 2
                continue
            if nxt in "01234567":
                digits = nxt
                j = i + 2
                if j < n and inner[j] in "01234567":
                    digits += inner[j]
                    j += 1
                    if nxt in "0123" and j < n and inner[j] in "01234567":
                        digits += inner[j]
                        j += 1
                out.append(chr(int(digits, 8)))
                i = j
                continue
            return None
        out.append(ch)
        i += 1
    return "".join(out)


def _has_non_bmp_or_surrogate(val: str) -> bool:
    return any(ord(ch) > 0xFFFF or 0xD800 <= ord(ch) <= 0xDFFF for ch in val)

ASSIGN_STMT_RE = re.compile(
    r"^\s*(?:final\s+)?(?:([A-Za-z_][A-Za-z0-9_<>,.\[\]]*(?:\s*\[\s*\])*)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(\+?=)\s*(.+?)\s*;\s*$"
)
RETURN_STMT_RE = re.compile(r"^\s*return\s+(.+?)\s*;\s*$")
CANONICAL_CALL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*getCanonicalPath\s*\(\s*\)$")
NEW_FILE_EXPR_RE = re.compile(r"\bnew\s+(?:java\.io\.)?File\s*\((.+)\)$")
NEW_OBJ_ASSIGN_RE = re.compile(r"^new\s+([A-Za-z_][A-Za-z0-9_.]*)\s*\((.*)\)$")
NEG_STARTSWITH_IF_RE = re.compile(
    r"^!\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s*\.\s*getCanonicalPath\s*\(\s*\))?\s*\.\s*startsWith\s*\(\s*(.+)\s*\)$"
)
POS_STARTSWITH_IF_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)(?:\s*\.\s*getCanonicalPath\s*\(\s*\))?\s*\.\s*startsWith\s*\(\s*(.+)\s*\)$"
)
IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
ANY_CALL_RE = re.compile(
    r"(?:\bnew\s+([A-Za-z_][A-Za-z0-9_.]*)\s*\([^()]*\)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)"
    r"|\b([A-Za-z_][A-Za-z0-9_.]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)"
    r"|(?<![.\w])([A-Za-z_][A-Za-z0-9_]*))\s*\("
)

JAVA_KEYWORDS_AND_TYPES = {
    "if", "else", "for", "while", "switch", "case", "default", "break", "return", "throw", "new",
    "try", "catch", "finally", "null", "true", "false", "this", "super", "final", "int", "long",
    "char", "boolean", "byte", "double", "float", "String", "Object", "File", "Path", "Paths",
    "URI", "FileInputStream", "FileOutputStream", "FileReader", "Files", "Connection", "Statement",
    "PreparedStatement", "CallableStatement", "ResultSet", "Map", "HashMap", "List", "ArrayList",
    "Enumeration", "Cookie", "HttpServletRequest", "HttpServletResponse", "ServletException",
    "IOException", "System", "Integer", "Long", "UUID", "FilenameUtils", "ESAPI", "URLDecoder",
    "StandardCharsets",
}

BENIGN_PASSTHROUGH_METHODS = {
    "trim", "toString", "valueOf", "replace", "replaceAll", "toLowerCase", "toUpperCase",
    "substring", "concat", "format", "decode", "encode", "encodeBase64", "decodeBase64",
    "encodeToString", "getBytes", "charAt", "encodeForHTML", "escapeHtml", "escapeHtml4",
    "getFD", "getValue", "getName", "nextElement", "resolve",
}


def _strip_comments_and_mask_lines(
    lines_by_no: dict[int, str],
) -> tuple[dict[int, str], dict[int, str]]:
    """Return (code_keep_strings, code_masked_strings) keyed by 1-based line number."""
    keep_str: dict[int, str] = {}
    masked_str: dict[int, str] = {}
    in_block = False
    for ln_no in sorted(lines_by_no):
        raw = lines_by_no[ln_no]
        ks_chars: list[str] = []
        ms_chars: list[str] = []
        i = 0
        n = len(raw)
        in_s = False
        in_c = False
        while i < n:
            ch = raw[i]
            nxt = raw[i + 1] if i + 1 < n else ""
            if in_block:
                if ch == "*" and nxt == "/":
                    in_block = False
                    ks_chars.append("  ")
                    ms_chars.append("  ")
                    i += 2
                else:
                    ks_chars.append(" ")
                    ms_chars.append(" ")
                    i += 1
                continue
            if in_s:
                if ch == "\\" and i + 1 < n:
                    ks_chars.append(raw[i : i + 2])
                    ms_chars.append("  ")
                    i += 2
                elif ch == '"':
                    in_s = False
                    ks_chars.append('"')
                    ms_chars.append('"')
                    i += 1
                else:
                    ks_chars.append(ch)
                    ms_chars.append(" ")
                    i += 1
                continue
            if in_c:
                if ch == "\\" and i + 1 < n:
                    ks_chars.append(raw[i : i + 2])
                    ms_chars.append("  ")
                    i += 2
                elif ch == "'":
                    in_c = False
                    ks_chars.append("'")
                    ms_chars.append("'")
                    i += 1
                else:
                    ks_chars.append(ch)
                    ms_chars.append(" ")
                    i += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block = True
                ks_chars.append("  ")
                ms_chars.append("  ")
                i += 2
                continue
            if ch == '"':
                in_s = True
                ks_chars.append('"')
                ms_chars.append('"')
                i += 1
                continue
            if ch == "'":
                in_c = True
                ks_chars.append("'")
                ms_chars.append("'")
                i += 1
                continue
            ks_chars.append(ch)
            ms_chars.append(ch)
            i += 1
        keep_str[ln_no] = "".join(ks_chars)
        masked_str[ln_no] = "".join(ms_chars)
    return keep_str, masked_str


def _is_pure_string_literal(expr: str) -> bool:
    s = expr.strip()
    if len(s) < 2 or not (s.startswith('"') and s.endswith('"')):
        return False
    # Check there is no unescaped closing quote before the end
    i = 1
    while i < len(s) - 1:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == '"':
            return False
        i += 1
    return True


def _split_top_level_plus(expr: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    in_s = False
    in_c = False
    i = 0
    while i < len(expr):
        ch = expr[i]
        if in_s:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(expr):
                cur.append(expr[i + 1])
                i += 2
                continue
            if ch == '"':
                in_s = False
            i += 1
            continue
        if in_c:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(expr):
                cur.append(expr[i + 1])
                i += 2
                continue
            if ch == "'":
                in_c = False
            i += 1
            continue
        if ch == '"':
            in_s = True
            cur.append(ch)
        elif ch == "'":
            in_c = True
            cur.append(ch)
        elif ch in "([":
            depth += 1
            cur.append(ch)
        elif ch in ")]":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "+" and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts if len(parts) > 1 else [expr.strip()]


def _split_top_level_args(arg_str: str) -> list[str]:
    args: list[str] = []
    cur: list[str] = []
    depth = 0
    in_s = False
    in_c = False
    i = 0
    while i < len(arg_str):
        ch = arg_str[i]
        if in_s:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(arg_str):
                cur.append(arg_str[i + 1])
                i += 2
                continue
            if ch == '"':
                in_s = False
            i += 1
            continue
        if in_c:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(arg_str):
                cur.append(arg_str[i + 1])
                i += 2
                continue
            if ch == "'":
                in_c = False
            i += 1
            continue
        if ch == '"':
            in_s = True
            cur.append(ch)
        elif ch == "'":
            in_c = True
            cur.append(ch)
        elif ch in "([":
            depth += 1
            cur.append(ch)
        elif ch in ")]":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "," and depth == 0:
            if "".join(cur).strip():
                args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    if "".join(cur).strip():
        args.append("".join(cur).strip())
    return args


def _is_safe_path_prefix_expr(prefix_expr: str) -> str:
    """Classify a String.startsWith(prefix_expr) boundary:
    Returns 'SAFE_BOUNDARY', 'UNSAFE_NO_SEPARATOR_LITERAL', or 'AMBIGUOUS_NO_SEPARATOR'.
    """
    p = prefix_expr.strip()
    if _is_pure_string_literal(p):
        dec = _unescape_java_string_literal_jls(p)
        if dec is None or "\x00" in dec:
            return "AMBIGUOUS_NO_SEPARATOR"
        segs = [seg for seg in dec.replace("\\", "/").split("/") if seg]
        if ".." in segs or "." in segs:
            return "AMBIGUOUS_NO_SEPARATOR"
        # Reject bare filesystem/drive roots such as "/", "\\", "C:/", "C:\\"
        non_drive = [seg for seg in segs if not re.fullmatch(r"[A-Za-z]:", seg)]
        if not non_drive:
            return "AMBIGUOUS_NO_SEPARATOR"
        if dec.endswith("/") or dec.endswith("\\"):
            return "SAFE_BOUNDARY"
        return "UNSAFE_NO_SEPARATOR_LITERAL"
    parts = _split_top_level_plus(p)
    if len(parts) >= 2:
        for part in parts:
            if _is_pure_string_literal(part):
                dec_part = _unescape_java_string_literal_jls(part)
                if dec_part is None or "\x00" in dec_part:
                    return "AMBIGUOUS_NO_SEPARATOR"
                segs = [seg for seg in dec_part.replace("\\", "/").split("/") if seg]
                if ".." in segs or "." in segs:
                    return "AMBIGUOUS_NO_SEPARATOR"
        last = parts[-1].strip()
        if last in ("File.separator", "java.io.File.separator", '"/"', '"\\\\"'):
            return "SAFE_BOUNDARY"
        if _is_pure_string_literal(last):
            dec_last = _unescape_java_string_literal_jls(last)
            if dec_last is not None and (dec_last.endswith("/") or dec_last.endswith("\\")):
                return "SAFE_BOUNDARY"
            return "UNSAFE_NO_SEPARATOR_LITERAL"
    return "AMBIGUOUS_NO_SEPARATOR"


def _prefix_expr_has_tainted_ident(prefix_expr: str, env: dict[str, str]) -> bool:
    for part in _split_top_level_plus(prefix_expr.strip()):
        if _is_pure_string_literal(part):
            continue
        for ident in IDENT_RE.findall(part):
            if env.get(ident) == "TAINTED":
                return True
    return False


def _strip_outer_parens_and_cast(expr: str) -> str:
    s = expr.strip()
    while len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        depth = 0
        in_s = False
        in_c = False
        closes_at_end = True
        i = 0
        while i < len(s):
            ch = s[i]
            if in_s:
                if ch == "\\" and i + 1 < len(s):
                    i += 2
                    continue
                if ch == '"':
                    in_s = False
            elif in_c:
                if ch == "\\" and i + 1 < len(s):
                    i += 2
                    continue
                if ch == "'":
                    in_c = False
            elif ch == '"':
                in_s = True
            elif ch == "'":
                in_c = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(s) - 1:
                    closes_at_end = False
                    break
            i += 1
        if closes_at_end and depth == 0:
            s = s[1:-1].strip()
        else:
            break
    s = re.sub(
        r"^\(\s*(?:(?:java\.lang\.)?(?:String|Integer|Long)|int|long)\s*\)\s*",
        "",
        s,
    ).strip()
    return s


def _stmt_mutates_ident(masked_stmt: str, ident: str) -> bool:
    return bool(
        re.search(
            rf"(?:\b{ident}\s*(?:[+\-*/%&|^]?=(?!=)|\+\+|--)|(?:\+\+|--)\s*{ident}\b)",
            masked_stmt,
        )
    )


def _units_mutate_ident(units_slice: list[tuple[int, int, str, str]], ident: str) -> bool:
    return any(_stmt_mutates_ident(u[3], ident) for u in units_slice)


def _invalidate_collections_in_units(
    units_slice: list[tuple[int, int, str, str]],
    lists: dict[str, list[tuple[str, int]]],
    maps: dict[str, dict[str, tuple[str, int]]],
) -> None:
    if not lists and not maps:
        return
    idents: set[str] = set()
    for _, _, _, m_txt in units_slice:
        idents.update(IDENT_RE.findall(m_txt))
    for lk in list(lists):
        if lk in idents:
            lists.pop(lk, None)
    for mk in list(maps):
        if mk in idents:
            maps.pop(mk, None)


def _merge_states(s1: str, s2: str, primary_cwe: str) -> str:
    if s1 == s2:
        return s1
    if "TAINTED" in (s1, s2):
        return "TAINTED"
    if "UNKNOWN" in (s1, s2) or "UNSET" in (s1, s2):
        return "UNKNOWN"
    san_tag = f"SANITIZED_{primary_cwe.replace('-', '')}"
    if {s1, s2} <= {"SAFE_CONST", san_tag}:
        return san_tag
    return "UNKNOWN"


def _collect_available_lines(record: dict[str, Any]) -> tuple[str, str, dict[int, str]]:
    """Return Evidence-verified primary relative path, sha256, and sorted line_no -> text from record snippets."""
    snapshots = record.get("snapshots") if isinstance(record.get("snapshots"), dict) else {}
    snippets = record.get("snippets") if isinstance(record.get("snippets"), list) else []
    primary_path = ""
    for snippet in snippets:
        if isinstance(snippet, dict) and snippet.get("role") == "finding":
            cand = snippet.get("path")
            if isinstance(cand, str) and cand in snapshots:
                primary_path = cand
                break
    if not primary_path:
        raw_p = record.get("path")
        if isinstance(raw_p, str) and raw_p in snapshots:
            primary_path = raw_p
        elif snippets and isinstance(snippets[0], dict) and snippets[0].get("role") is None:
            cand = snippets[0].get("path")
            if isinstance(cand, str) and cand in snapshots:
                primary_path = cand

    lines_by_no: dict[int, str] = {}
    if primary_path:
        for snippet in snippets:
            if isinstance(snippet, dict) and snippet.get("path") == primary_path:
                for ln in snippet.get("lines") or []:
                    if isinstance(ln, dict) and type(ln.get("line")) is int and isinstance(ln.get("text"), str):
                        lines_by_no[ln["line"]] = ln["text"]
    sha = (snapshots.get(primary_path) or {}).get("sha256", "") if primary_path else ""
    return primary_path, sha, dict(sorted(lines_by_no.items()))


def _make_citation(path: str, sha: str, line_no: int, lines_by_no: dict[int, str]) -> dict[str, Any] | None:
    if not path or not sha or line_no not in lines_by_no:
        return None
    raw = lines_by_no[line_no]
    stripped = raw.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return None
    return {
        "path": path,
        "start_line": line_no,
        "end_line": line_no,
        "quote": raw,
        "sha256": sha,
    }


def _group_statements(
    start_ln: int,
    end_ln: int,
    keep_str: dict[int, str],
    masked_str: dict[int, str],
    stop_at_line: int | None = None,
) -> list[tuple[int, int, str, str]]:
    """Group multi-line Java fragments into statement/control units `(s_ln, e_ln, code, masked)`."""
    units: list[tuple[int, int, str, str]] = []
    cur_s: int | None = None
    buf_k: list[str] = []
    buf_m: list[str] = []
    paren_depth = 0

    for ln in range(start_ln, end_ln + 1):
        if stop_at_line is not None and ln > stop_at_line:
            break
        k_txt = keep_str.get(ln, "").strip()
        m_txt = masked_str.get(ln, "").strip()
        if not m_txt:
            continue
        if cur_s is None:
            cur_s = ln
        buf_k.append(k_txt)
        buf_m.append(m_txt)
        paren_depth += m_txt.count("(") - m_txt.count(")")
        if paren_depth <= 0 and (
            m_txt.endswith(";")
            or m_txt.endswith("{")
            or m_txt.endswith("}")
            or m_txt.endswith(":")
        ):
            units.append((cur_s, ln, " ".join(buf_k), " ".join(buf_m)))
            cur_s = None
            buf_k = []
            buf_m = []
            paren_depth = 0

    if cur_s is not None and buf_k:
        units.append((cur_s, stop_at_line or end_ln, " ".join(buf_k), " ".join(buf_m)))
    return units


def _extract_balanced_Condition(header_str: str, keyword: str) -> tuple[str, str] | None:
    """Given `if (cond) rest`, return `(cond, rest)`."""
    m = re.match(rf"^\s*{keyword}\s*\(", header_str)
    if not m:
        return None
    idx = m.end() - 1
    depth = 0
    in_s = False
    in_c = False
    i = idx
    while i < len(header_str):
        ch = header_str[i]
        if in_s:
            if ch == "\\" and i + 1 < len(header_str):
                i += 2
                continue
            if ch == '"':
                in_s = False
        elif in_c:
            if ch == "\\" and i + 1 < len(header_str):
                i += 2
                continue
            if ch == "'":
                in_c = False
        elif ch == '"':
            in_s = True
        elif ch == "'":
            in_c = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return header_str[idx + 1 : i].strip(), header_str[i + 1 :].strip()
        i += 1
    return None


class _FlowAnalyzer:
    """Bounded intra-file (method + class-qualified callees) abstract flow analyzer."""

    def __init__(
        self,
        primary_cwe: str,
        keep_str: dict[int, str],
        masked_str: dict[int, str],
        methods: list[dict[str, Any]],
        same_file_classes: set[str],
        package_name: str | None,
    ) -> None:
        self.primary_cwe = primary_cwe
        self.keep_str = keep_str
        self.masked_str = masked_str
        self.methods = methods
        self.same_file_classes = same_file_classes
        self.package_name = package_name
        self.sanitizers_applied: list[dict[str, Any]] = []
        self.non_sanitizers_seen: list[dict[str, Any]] = []
        self.unresolved_calls: list[dict[str, Any]] = []
        self.dead_branch_lines: set[int] = set()
        self.key_lines: list[int] = []
        self.mechanisms: list[str] = []
        self.reasons: list[str] = []

    def _resolve_same_file_type(self, raw_type: str) -> str | None:
        raw_type = raw_type.strip()
        if "." in raw_type:
            pkg_prefix, simple = raw_type.rsplit(".", 1)
            if self.package_name and pkg_prefix == self.package_name and simple in self.same_file_classes:
                return simple
            if pkg_prefix in self.same_file_classes and simple in self.same_file_classes:
                return simple
            return None
        return raw_type if raw_type in self.same_file_classes else None

    def _find_callee(self, target_cls: str | None, method_name: str) -> dict[str, Any] | None:
        if target_cls is None:
            return None
        matches = [
            m
            for m in self.methods
            if m.get("owner_class") == target_cls and m.get("name") == method_name
        ]
        return matches[0] if len(matches) == 1 else None

    def _eval_expr(
        self,
        expr: str,
        masked_expr: str,
        ln_no: int,
        env: dict[str, str],
        var_types: dict[str, str | None],
        lists: dict[str, list[tuple[str, int]]],
        maps: dict[str, dict[str, tuple[str, int]]],
        owner_cls: str | None,
        depth: int,
        at_top_scope: bool,
    ) -> tuple[str, list[int]]:
        e = expr.strip()
        em = masked_expr.strip()
        if not e or e in ("null", "true", "false") or parse_java_nonneg_decimal_int_literal(e) is not None:
            return "SAFE_CONST", []
        if _is_pure_string_literal(e):
            return "SAFE_CONST", [ln_no]

        # Track wrong-context encoders explicitly
        for wname, wpat in WRONG_CONTEXT_ENCODERS:
            if wpat.search(em):
                self.non_sanitizers_seen.append({"name": wname, "line": ln_no})

        # Top-level string / arithmetic `+` concatenation
        plus_parts = _split_top_level_plus(e)
        plus_masked = _split_top_level_plus(em)
        if len(plus_parts) > 1 and len(plus_parts) == len(plus_masked):
            part_states: list[str] = []
            cites: list[int] = []
            for p_raw, p_msk in zip(plus_parts, plus_masked):
                st, pc = self._eval_expr(
                    p_raw, p_msk, ln_no, env, var_types, lists, maps, owner_cls, depth, at_top_scope
                )
                part_states.append(st)
                cites.extend(pc)
            if "TAINTED" in part_states:
                return "TAINTED", cites
            if "UNKNOWN" in part_states:
                return "UNKNOWN", cites
            san_tag = f"SANITIZED_{self.primary_cwe.replace('-', '')}"
            if san_tag in part_states:
                # For CWE-22, check that no concatenated constant introduces `..` traversal
                if self.primary_cwe == "CWE-22" and any(".." in p for p in plus_parts):
                    return "TAINTED", cites
                return san_tag, cites
            if all(s == "SAFE_CONST" for s in part_states):
                if self.primary_cwe == "CWE-22":
                    decoded_parts = [_unescape_java_string_literal_jls(p) for p in plus_parts]
                    if any(d is None for d in decoded_parts):
                        return "UNKNOWN", cites
                    combined = "".join(d for d in decoded_parts if d is not None)
                    segs = combined.replace("\\", "/").split("/")
                    if "\x00" in combined or ".." in segs or "." in segs:
                        return "UNKNOWN", cites
                return "SAFE_CONST", cites
            return "UNKNOWN", cites

        # HTTP Servlet untrusted source call
        if HTTP_SOURCE_CALL_RE.search(em):
            return "TAINTED", [ln_no]

        # CWE-22 basename extractors (must match the entire expression, never an embedded sub-call)
        e_norm = _strip_outer_parens_and_cast(e)
        em_norm = _strip_outer_parens_and_cast(em)
        for sname, spat in CWE22_BASENAME_CALL_PATTERNS:
            m_san = spat.fullmatch(e_norm)
            if m_san and spat.fullmatch(em_norm):
                arg_raw = m_san.group(1).strip()
                arg_st, _ = self._eval_expr(
                    arg_raw, arg_raw, ln_no, env, var_types, lists, maps, owner_cls, depth, at_top_scope
                )
                if self.primary_cwe == "CWE-22" and arg_st != "UNKNOWN":
                    return "SANITIZED_CWE22", [ln_no]
                return arg_st, [ln_no]

        # CWE-89 scalar parsers (must match the entire expression, never an embedded sub-call)
        for sname, spat in CWE89_SCALAR_PARSE_PATTERNS:
            m_san = spat.fullmatch(e_norm)
            if m_san and spat.fullmatch(em_norm):
                arg_raw = m_san.group(1).strip()
                arg_st, _ = self._eval_expr(
                    arg_raw, arg_raw, ln_no, env, var_types, lists, maps, owner_cls, depth, at_top_scope
                )
                if arg_st == "SAFE_CONST":
                    return "SAFE_CONST", [ln_no]
                if self.primary_cwe == "CWE-89" and arg_st != "UNKNOWN":
                    return "SANITIZED_CWE89", [ln_no]
                return arg_st, [ln_no]

        # Tracked List.get(idx) — strict non-negative ASCII decimal Java int index only (fail-closed)
        m_lget = LIST_GET_EXPR_RE.match(e)
        if m_lget and at_top_scope:
            lname = m_lget.group(1)
            gidx = parse_java_nonneg_decimal_int_literal(m_lget.group(2))
            if gidx is not None and lname in lists and 0 <= gidx < len(lists[lname]):
                elem_state, elem_ln = lists[lname][gidx]
                self.mechanisms.append(f"list_index_{elem_state.lower()}")
                return elem_state, [elem_ln, ln_no]
            if lname in lists:
                return "UNKNOWN", []

        # Tracked Map.get("key")
        m_mget = MAP_GET_EXPR_RE.match(e)
        if m_mget and at_top_scope:
            mname, klit = m_mget.group(1), m_mget.group(2)
            decoded_key = _unescape_java_string_literal_jls(klit)
            if decoded_key is not None and mname in maps and decoded_key in maps[mname]:
                val_state, put_ln = maps[mname][decoded_key]
                self.mechanisms.append(f"map_key_{val_state.lower()}")
                return val_state, [put_ln, ln_no]

        # Direct variable lookup
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", e):
            if e in env:
                return env[e], []
            if e == "request":
                return "TAINTED", []
            return "UNKNOWN", []

        # Array indexing `values[0]`
        m_arr = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([^\]\[]+?)\s*\]", e)
        if m_arr and parse_java_nonneg_decimal_int_literal(m_arr.group(2)) is not None:
            base_var = m_arr.group(1)
            return env.get(base_var, "UNKNOWN"), []

        # Known constant platform separator and JDK enum constants (never mutable System.getProperty/getenv)
        if re.match(
            r"^(?:(?:java\.io\.)?File\.separator|"
            r"(?:(?:java\.nio\.file\.)?(?:StandardOpenOption|LinkOption)\.[A-Z_]+|"
            r"(?:java\.nio\.charset\.)?StandardCharsets\.[A-Z0-9_]+)$)",
            e,
        ):
            return "SAFE_CONST", []

        # Check `new ClassName(args).method(call_args)` or `recv.method(call_args)` or `method(call_args)`
        m_new_call = re.match(
            r"^new\s+([A-Za-z_][A-Za-z0-9_.]*)\s*\(([^()]*)\)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$",
            e,
        )
        if m_new_call:
            raw_cls, ctor_args, mname, raw_args = (
                m_new_call.group(1),
                m_new_call.group(2),
                m_new_call.group(3),
                m_new_call.group(4),
            )
            if raw_cls.rsplit(".", 1)[-1] in (
                "File", "URI", "FileInputStream", "FileOutputStream", "FileReader"
            ) and mname in BENIGN_PASSTHROUGH_METHODS:
                return self._eval_expr(
                    f"new {raw_cls}({ctor_args})",
                    f"new {raw_cls}({ctor_args})",
                    ln_no,
                    env,
                    var_types,
                    lists,
                    maps,
                    owner_cls,
                    depth,
                    at_top_scope,
                )
            target_cls = self._resolve_same_file_type(raw_cls)
            return self._invoke_or_unknown(
                target_cls, raw_cls, mname, raw_args, ln_no, env, var_types, lists, maps, owner_cls, depth
            )

        # Wrapper constructors `new File(...)`, `new URI(...)`, `new FileInputStream(...)`, `Paths.get(...)`
        m_new_obj = NEW_OBJ_ASSIGN_RE.match(e)
        if m_new_obj:
            cls_name, raw_args = m_new_obj.group(1), m_new_obj.group(2)
            simple_cls = cls_name.rsplit(".", 1)[-1]
            if simple_cls in ("File", "URI", "FileInputStream", "FileOutputStream", "FileReader"):
                args = _split_top_level_args(raw_args)
                arg_states = [
                    self._eval_expr(a, a, ln_no, env, var_types, lists, maps, owner_cls, depth, at_top_scope)[0]
                    for a in args
                ]
                if "TAINTED" in arg_states:
                    return "TAINTED", [ln_no]
                if "UNKNOWN" in arg_states:
                    return "UNKNOWN", [ln_no]
                san_tag = f"SANITIZED_{self.primary_cwe.replace('-', '')}"
                if san_tag in arg_states:
                    return san_tag, [ln_no]
                return "SAFE_CONST", [ln_no]
            if simple_cls == "SeparateClassRequest":
                return "UNKNOWN", [ln_no]

        # Qualified call `recv.method(args)`
        m_qcall = re.match(r"^(?:\(\s*String\s*\)\s*)?([A-Za-z_][A-Za-z0-9_.]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$", e)
        if m_qcall:
            recv, mname, raw_args = m_qcall.group(1), m_qcall.group(2), m_qcall.group(3)
            static_util_receivers = (
                "URLDecoder",
                "java.net.URLDecoder",
                "Paths",
                "java.nio.file.Paths",
                "String",
                "Base64",
                "java.util.Base64",
                "org.apache.commons.codec.binary.Base64",
            )
            if mname in BENIGN_PASSTHROUGH_METHODS or recv in static_util_receivers:
                args = _split_top_level_args(raw_args)
                states_involved: list[str] = []
                if recv not in static_util_receivers:
                    states_involved.append(env.get(recv, "UNKNOWN"))
                for a in args:
                    st_a, _ = self._eval_expr(
                        a, a, ln_no, env, var_types, lists, maps, owner_cls, depth, at_top_scope
                    )
                    states_involved.append(st_a)
                if not states_involved:
                    return "UNKNOWN", [ln_no]
                if "TAINTED" in states_involved:
                    return "TAINTED", [ln_no]
                if "UNKNOWN" in states_involved:
                    return "UNKNOWN", [ln_no]
                san_tag = f"SANITIZED_{self.primary_cwe.replace('-', '')}"
                if san_tag in states_involved:
                    return san_tag, [ln_no]
                return "SAFE_CONST", [ln_no]

            if recv == "this":
                target_cls = owner_cls
            elif recv in var_types:
                target_cls = var_types[recv]
            elif recv in self.same_file_classes:
                target_cls = recv
            else:
                target_cls = None
            return self._invoke_or_unknown(
                target_cls, recv, mname, raw_args, ln_no, env, var_types, lists, maps, owner_cls, depth
            )

        # Unqualified helper call `helper(args)`
        m_ucall = re.match(r"^(?:\(\s*String\s*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$", e)
        if m_ucall and m_ucall.group(1) not in JAVA_KEYWORDS_AND_TYPES:
            mname, raw_args = m_ucall.group(1), m_ucall.group(2)
            return self._invoke_or_unknown(
                owner_cls, owner_cls or "unknown", mname, raw_args, ln_no, env, var_types, lists, maps, owner_cls, depth
            )

        # Fallback identifier inspection: never claim SAFE_CONST on arbitrary unknown syntax
        idents = [tok for tok in IDENT_RE.findall(em) if tok not in JAVA_KEYWORDS_AND_TYPES]
        if any(env.get(tok) == "TAINTED" for tok in idents):
            # Check if an unknown call wraps the tainted identifier (could transform or fail to)
            for m_c in ANY_CALL_RE.finditer(em):
                cname = m_c.group(2) or m_c.group(4) or m_c.group(5)
                if cname and cname not in JAVA_KEYWORDS_AND_TYPES and cname not in BENIGN_PASSTHROUGH_METHODS:
                    self.unresolved_calls.append({"method": cname, "line": ln_no})
                    return "UNKNOWN", [ln_no]
            return "TAINTED", [ln_no]
        return "UNKNOWN", [ln_no]

    def _invoke_or_unknown(
        self,
        target_cls: str | None,
        raw_qualifier: str,
        mname: str,
        raw_args: str,
        ln_no: int,
        env: dict[str, str],
        var_types: dict[str, str | None],
        lists: dict[str, list[tuple[str, int]]],
        maps: dict[str, dict[str, tuple[str, int]]],
        owner_cls: str | None,
        depth: int,
    ) -> tuple[str, list[int]]:
        if depth >= 3:
            self.unresolved_calls.append({"qualifier": raw_qualifier, "method": mname, "line": ln_no, "reason": "max_hop_depth_exceeded"})
            return "UNKNOWN", [ln_no]
        callee = self._find_callee(target_cls, mname)
        if callee is None:
            self.unresolved_calls.append({"qualifier": raw_qualifier, "method": mname, "line": ln_no, "reason": "missing_helper_implementation"})
            return "UNKNOWN", [ln_no]

        arg_exprs = _split_top_level_args(raw_args)
        arg_states = [
            self._eval_expr(a, a, ln_no, env, var_types, lists, maps, owner_cls, depth, True)[0]
            for a in arg_exprs
        ]
        callee_env: dict[str, str] = {}
        for p_decl, a_st in zip(callee.get("parameters") or [], arg_states):
            p_tokens = p_decl.replace("final ", "").strip().split()
            if p_tokens:
                p_name = p_tokens[-1].lstrip(".")
                callee_env[p_name] = a_st

        ret_state, ret_lines = self.analyze_method(
            callee,
            initial_env=callee_env,
            stop_before_sink_line=None,
            depth=depth + 1,
        )
        return ret_state, [ln_no] + ret_lines

    def analyze_method(
        self,
        method: dict[str, Any],
        initial_env: dict[str, str] | None = None,
        stop_before_sink_line: int | None = None,
        depth: int = 0,
    ) -> tuple[str, list[int]]:
        """Execute abstract flow over `method`. For callees (`stop_before_sink_line is None`),
        returns merged return state and decisive lines. For enclosing method, updates `initial_env` in place.
        """
        env: dict[str, str] = dict(initial_env or {})
        for p_decl in method.get("parameters") or []:
            if "HttpServletRequest" in p_decl:
                p_name = p_decl.strip().split()[-1]
                env.setdefault(p_name, "TAINTED")

        body_start = method["header_line"] + 1
        body_end = max(body_start, method["end_line"] - 1)

        units = _group_statements(body_start, body_end, self.keep_str, self.masked_str, stop_at_line=None)
        owner_cls = method.get("owner_class")
        var_types: dict[str, str | None] = {}
        canon_of: dict[str, str] = {}
        lists: dict[str, list[tuple[str, int]]] = {}
        maps: dict[str, dict[str, tuple[str, int]]] = {}
        return_states: list[tuple[str, list[int]]] = []

        self._exec_units(
            units,
            0,
            len(units),
            env=env,
            var_types=var_types,
            canon_of=canon_of,
            lists=lists,
            maps=maps,
            owner_cls=owner_cls,
            depth=depth,
            at_top_scope=True,
            sink_line=stop_before_sink_line,
            return_states=return_states,
        )

        if initial_env is not None:
            initial_env.clear()
            initial_env.update(env)

        if stop_before_sink_line is None:
            if not return_states:
                return "UNKNOWN", []
            merged = return_states[0][0]
            r_lines: list[int] = list(return_states[0][1])
            for st, lns in return_states[1:]:
                merged = _merge_states(merged, st, self.primary_cwe)
                r_lines.extend(lns)
            return merged, r_lines

        return "DONE", []

    def _find_block_end(self, units: list[tuple[int, int, str, str]], start_idx: int) -> int:
        """Given unit at `start_idx` containing `{`, return index of matching `}` unit."""
        brace_depth = 0
        opened = False
        for j in range(start_idx, len(units)):
            _, _, _, m_str = units[j]
            opens = m_str.count("{")
            closes = m_str.count("}")
            if opens > 0:
                opened = True
            brace_depth += opens - closes
            if opened and brace_depth <= 0:
                return j
        return len(units) - 1

    def _exec_units(
        self,
        units: list[tuple[int, int, str, str]],
        idx_start: int,
        idx_end: int,
        env: dict[str, str],
        var_types: dict[str, str | None],
        canon_of: dict[str, str],
        lists: dict[str, list[tuple[str, int]]],
        maps: dict[str, dict[str, tuple[str, int]]],
        owner_cls: str | None,
        depth: int,
        at_top_scope: bool,
        sink_line: int | None,
        return_states: list[tuple[str, list[int]]],
    ) -> bool:
        """Execute `units[idx_start:idx_end]`. Returns True if block unconditionally exits (`return`/`throw`)."""
        guess_val: str | None = None
        guess_line: int | None = None
        target_char: str | None = None
        target_line: int | None = None
        guess_count = 0
        target_count = 0

        num_val: int | None = None
        num_line: int | None = None
        num_count = 0

        i = idx_start
        while i < idx_end:
            s_ln, e_ln, code, masked = units[i]
            if sink_line is not None and s_ln >= sink_line:
                break

            stripped_m = masked.strip()
            stripped_k = code.strip()

            if stripped_m in ("{", "}", "};"):
                i += 1
                continue

            # Unconditional exit (`throw ...` or `return ...`)
            if re.match(r"^(?:throw\b|return\s*;)", stripped_m):
                return True

            m_ret = RETURN_STMT_RE.match(stripped_k)
            if m_ret:
                ret_expr = m_ret.group(1)
                ret_m = RETURN_STMT_RE.match(stripped_m)
                ret_mask = ret_m.group(1) if ret_m else ret_expr
                st, cites = self._eval_expr(
                    ret_expr, ret_mask, s_ln, env, var_types, lists, maps, owner_cls, depth, at_top_scope
                )
                return_states.append((st, cites + [s_ln]))
                return True

            # Constant switch tracking (only valid at top scope when assigned once, BMP/JLS decoded)
            m_g = GUESS_LITERAL_RE.search(stripped_k)
            if m_g and at_top_scope:
                guess_count += 1
                dec_guess = _unescape_java_string_literal_jls('"' + m_g.group(1) + '"')
                if guess_count == 1 and dec_guess is not None and not _has_non_bmp_or_surrogate(dec_guess):
                    guess_val = dec_guess
                else:
                    guess_val = None
                guess_line = s_ln
                env["guess"] = "SAFE_CONST" if guess_val is not None else "UNKNOWN"
                i += 1
                continue
            m_st = SWITCH_TARGET_RE.search(stripped_k)
            if m_st and at_top_scope and guess_val is not None:
                target_count += 1
                c_idx = parse_java_nonneg_decimal_int_literal(m_st.group(1))
                target_char = (
                    guess_val[c_idx]
                    if (
                        target_count == 1
                        and c_idx is not None
                        and len(guess_val.encode("utf-16-le")) == 2 * len(guess_val)
                        and 0 <= c_idx < len(guess_val)
                    )
                    else None
                )
                target_line = s_ln
                env["switchTarget"] = "SAFE_CONST" if target_char is not None else "UNKNOWN"
                i += 1
                continue

            m_num = INT_NUM_RE.match(stripped_k)
            if m_num and at_top_scope:
                num_count += 1
                parsed_num = parse_java_nonneg_decimal_int_literal(m_num.group(1))
                num_val = parsed_num if (num_count == 1 and parsed_num is not None) else None
                num_line = s_ln
                env["num"] = "SAFE_CONST" if num_val is not None else "UNKNOWN"
                i += 1
                continue

            # Handle `switch (...) { ... }`
            if re.match(r"^switch\s*\(", stripped_m) and "{" in stripped_m:
                end_sw = self._find_block_end(units, i)
                sw_slice = units[i + 1 : end_sw]
                if at_top_scope and target_char is not None and re.match(r"^switch\s*\(\s*switchTarget\s*\)", stripped_m):
                    self._exec_constant_switch(
                        units, i + 1, end_sw, target_char, target_line, guess_line,
                        env, var_types, canon_of, lists, maps, owner_cls, depth, sink_line, return_states
                    )
                else:
                    self._exec_nonconstant_switch(
                        units, i + 1, end_sw, env, var_types, canon_of,
                        lists, maps, owner_cls, depth, sink_line, return_states
                    )
                if _units_mutate_ident(sw_slice, "guess"):
                    guess_val = None
                    guess_count += 1
                if _units_mutate_ident(sw_slice, "switchTarget"):
                    target_char = None
                    target_count += 1
                if _units_mutate_ident(sw_slice, "num"):
                    num_val = None
                    num_count += 1
                i = end_sw + 1
                continue

            # Handle `if (...)` (both braced and single-statement, with optional `else`)
            parsed_if = _extract_balanced_Condition(stripped_k, "if")
            if parsed_if is not None:
                cond_k, rest_k = parsed_if
                parsed_if_m = _extract_balanced_Condition(stripped_m, "if")
                cond_m = parsed_if_m[0] if parsed_if_m else cond_k
                rest_m = parsed_if_m[1] if parsed_if_m else rest_k

                if "{" in stripped_m:
                    then_end = self._find_block_end(units, i)
                    then_units = units[i + 1 : then_end]
                    next_i = then_end + 1
                elif rest_k.endswith(";"):
                    then_units = [(s_ln, e_ln, rest_k, rest_m)]
                    next_i = i + 1
                elif i + 1 < idx_end:
                    then_units = [units[i + 1]]
                    next_i = i + 2
                else:
                    then_units = []
                    next_i = i + 1

                # Check optional `else` immediately following
                else_units: list[tuple[int, int, str, str]] | None = None
                if next_i < idx_end:
                    es_ln, ee_ln, ek, em = units[next_i]
                    if re.match(r"^\}?\s*else\b", em.strip()):
                        after_else_k = re.sub(r"^\}?\s*else\s*", "", ek.strip(), count=1)
                        after_else_m = re.sub(r"^\}?\s*else\s*", "", em.strip(), count=1)
                        if "{" in after_else_m and not after_else_m.startswith("if"):
                            else_end = self._find_block_end(units, next_i)
                            else_units = units[next_i + 1 : else_end]
                            next_i = else_end + 1
                        elif after_else_k.endswith(";"):
                            else_units = [(es_ln, ee_ln, after_else_k, after_else_m)]
                            next_i = next_i + 1
                        elif after_else_m.startswith("if"):
                            # `else if (...)` treated as nested `if` inside `else`
                            if "{" in after_else_m:
                                else_end = self._find_block_end(units, next_i)
                                else_units = [(es_ln, ee_ln, after_else_k, after_else_m)] + units[next_i + 1 : else_end + 1]
                                next_i = else_end + 1
                            else:
                                else_units = [(es_ln, ee_ln, after_else_k, after_else_m)]
                                next_i = next_i + 1

                # 1. Check compile-time arithmetic constant `if ((A *|/ B) +|- num > THRESH)`
                m_acond = ARITH_COND_RE.match(cond_k.strip())
                if at_top_scope and m_acond and num_val is not None:
                    a_i = parse_java_nonneg_decimal_int_literal(m_acond.group(1))
                    op1 = m_acond.group(2)
                    b_i = parse_java_nonneg_decimal_int_literal(m_acond.group(3))
                    op2 = m_acond.group(4)
                    thresh = parse_java_nonneg_decimal_int_literal(m_acond.group(5))
                    if a_i is not None and b_i is not None and thresh is not None and not (op1 == "/" and b_i == 0):
                        lhs_v = (a_i * b_i) if op1 == "*" else (a_i // b_i)
                        if _JAVA_INT_MIN <= lhs_v <= _JAVA_INT_MAX:
                            comp_v = (lhs_v + num_val) if op2 == "+" else (lhs_v - num_val)
                            if _JAVA_INT_MIN <= comp_v <= _JAVA_INT_MAX:
                                cond_true = comp_v > thresh
                                chosen_units = then_units if cond_true else (else_units or [])
                                dead_units = (else_units or []) if cond_true else then_units
                                for ds, de, _, _ in dead_units:
                                    self.dead_branch_lines.update(range(ds, de + 1))
                                if num_line is not None:
                                    self.key_lines.append(num_line)
                                self._exec_units(
                                    chosen_units, 0, len(chosen_units), env, var_types, canon_of,
                                    lists, maps, owner_cls, depth, at_top_scope, sink_line, return_states
                                )
                                if _units_mutate_ident(chosen_units, "guess"):
                                    guess_val = None
                                    guess_count += 1
                                if _units_mutate_ident(chosen_units, "switchTarget"):
                                    target_char = None
                                    target_count += 1
                                if _units_mutate_ident(chosen_units, "num"):
                                    num_val = None
                                    num_count += 1
                                i = next_i
                                continue

                # 2. Check Negative CWE-22 Containment Guard: `if (!canon.startsWith(prefix)) { return/throw; }`
                m_neg_sw = NEG_STARTSWITH_IF_RE.match(cond_k.strip())
                if at_top_scope and self.primary_cwe == "CWE-22" and m_neg_sw and else_units is None:
                    guard_var, prefix_expr = m_neg_sw.group(1), m_neg_sw.group(2)
                    temp_env = dict(env)
                    exits = self._exec_units(
                        then_units, 0, len(then_units), temp_env, dict(var_types), dict(canon_of),
                        {}, {}, owner_cls, depth, False, sink_line, []
                    )
                    if exits and (sink_line is None or e_ln < sink_line):
                        prefix_kind = _is_safe_path_prefix_expr(prefix_expr)
                        if _prefix_expr_has_tainted_ident(prefix_expr, env):
                            prefix_kind = "UNSAFE_TAINTED_PREFIX"
                        bound_target = canon_of.get(guard_var)
                        uses_inline_canon = ".getCanonicalPath(" in cond_m
                        if bound_target or uses_inline_canon:
                            targets = [guard_var] + ([bound_target] if bound_target else [])
                            if prefix_kind == "SAFE_BOUNDARY":
                                for tv in targets:
                                    env[tv] = "SANITIZED_CWE22"
                                self.sanitizers_applied.append(
                                    {"name": "getCanonicalPath_startsWith", "line": s_ln, "targets": targets}
                                )
                                self.key_lines.append(s_ln)
                            elif prefix_kind == "AMBIGUOUS_NO_SEPARATOR":
                                for tv in targets:
                                    if env.get(tv) == "TAINTED":
                                        env[tv] = "UNKNOWN"
                            # If UNSAFE_NO_SEPARATOR_LITERAL (e.g. "/reports"), leave TAINTED!
                        i = next_i
                        continue

                # 3. Check Positive CWE-22 Containment Guard directly enclosing sink_line
                m_pos_sw = POS_STARTSWITH_IF_RE.match(cond_k.strip())
                if (
                    at_top_scope
                    and self.primary_cwe == "CWE-22"
                    and m_pos_sw
                    and sink_line is not None
                    and then_units
                    and then_units[0][0] <= sink_line <= then_units[-1][1]
                ):
                    guard_var, prefix_expr = m_pos_sw.group(1), m_pos_sw.group(2)
                    prefix_kind = _is_safe_path_prefix_expr(prefix_expr)
                    if _prefix_expr_has_tainted_ident(prefix_expr, env):
                        prefix_kind = "UNSAFE_TAINTED_PREFIX"
                    bound_target = canon_of.get(guard_var)
                    uses_inline_canon = ".getCanonicalPath(" in cond_m
                    if bound_target or uses_inline_canon:
                        targets = [guard_var] + ([bound_target] if bound_target else [])
                        if prefix_kind == "SAFE_BOUNDARY":
                            for tv in targets:
                                env[tv] = "SANITIZED_CWE22"
                            self.sanitizers_applied.append(
                                {"name": "getCanonicalPath_startsWith", "line": s_ln, "targets": targets}
                            )
                            self.key_lines.append(s_ln)
                        elif prefix_kind == "AMBIGUOUS_NO_SEPARATOR":
                            for tv in targets:
                                if env.get(tv) == "TAINTED":
                                    env[tv] = "UNKNOWN"
                    self._exec_units(
                        then_units, 0, len(then_units), env, var_types, canon_of,
                        lists, maps, owner_cls, depth, False, sink_line, return_states
                    )
                    i = next_i
                    continue

                # 4. General non-constant `if / else`: evaluate both branches and conservatively merge!
                pre_env = dict(env)
                then_env = dict(pre_env)
                then_lists = {k: list(v) for k, v in lists.items()}
                then_maps = {k: dict(v) for k, v in maps.items()}
                then_exits = self._exec_units(
                    then_units, 0, len(then_units), then_env, dict(var_types), dict(canon_of),
                    then_lists, then_maps, owner_cls, depth, True, sink_line, return_states
                )

                else_env = dict(pre_env)
                else_lists = {k: list(v) for k, v in lists.items()}
                else_maps = {k: dict(v) for k, v in maps.items()}
                else_exits = False
                if else_units is not None:
                    else_exits = self._exec_units(
                        else_units, 0, len(else_units), else_env, dict(var_types), dict(canon_of),
                        else_lists, else_maps, owner_cls, depth, True, sink_line, return_states
                    )

                branch_all_units = list(then_units) + list(else_units or [])
                if _units_mutate_ident(branch_all_units, "guess"):
                    guess_val = None
                    guess_count += 1
                if _units_mutate_ident(branch_all_units, "switchTarget"):
                    target_char = None
                    target_count += 1
                if _units_mutate_ident(branch_all_units, "num"):
                    num_val = None
                    num_count += 1

                if sink_line is not None and then_units and then_units[0][0] <= sink_line <= then_units[-1][1]:
                    env.clear()
                    env.update(then_env)
                    break
                if sink_line is not None and else_units and else_units[0][0] <= sink_line <= else_units[-1][1]:
                    env.clear()
                    env.update(else_env)
                    break

                if then_exits and else_exits:
                    return True
                if then_exits:
                    env.clear()
                    env.update(else_env)
                    if else_units is not None:
                        lists.clear()
                        lists.update(else_lists)
                        maps.clear()
                        maps.update(else_maps)
                elif else_exits:
                    env.clear()
                    env.update(then_env)
                    lists.clear()
                    lists.update(then_lists)
                    maps.clear()
                    maps.update(then_maps)
                else:
                    for k in set(then_env) | set(else_env):
                        if k in pre_env or (k in then_env and k in else_env):
                            env[k] = _merge_states(
                                then_env.get(k, pre_env.get(k, "UNSET")),
                                else_env.get(k, pre_env.get(k, "UNSET")),
                                self.primary_cwe,
                            )
                    # Fail-closed reconciliation of collections mutated in either branch
                    for lk in list(lists):
                        if then_lists.get(lk) != lists[lk] or else_lists.get(lk) != lists[lk]:
                            lists.pop(lk, None)
                    for mk in list(maps):
                        if then_maps.get(mk) != maps[mk] or else_maps.get(mk) != maps[mk]:
                            maps.pop(mk, None)
                i = next_i
                continue

            # Handle `for (...)` / `while (...)` / `try { ... }` / `catch (...)` blocks
            if re.match(r"^(?:for|while|try|catch)\b", stripped_m) and "{" in stripped_m:
                end_blk = self._find_block_end(units, i)
                blk_slice = units[i : end_blk + 1]
                is_try = stripped_m.startswith("try")
                if is_try:
                    # Statements inside `try { ... }` before sink execute sequentially up to sink_line
                    self._exec_units(
                        units, i + 1, end_blk, env, var_types, canon_of,
                        lists, maps, owner_cls, depth, at_top_scope, sink_line, return_states
                    )
                else:
                    # Loops / catch blocks may execute 0 or >=1 times: merge with pre_env and invalidate touched collections!
                    pre_env = dict(env)
                    loop_env = dict(pre_env)
                    if stripped_m.startswith("for"):
                        parsed_for = _extract_balanced_Condition(stripped_k, "for")
                        if parsed_for is not None and ":" in parsed_for[0]:
                            lhs_for, rhs_for = parsed_for[0].split(":", 1)
                            lhs_tokens = lhs_for.replace("final ", "").strip().split()
                            if lhs_tokens:
                                elem_var = lhs_tokens[-1]
                                iter_st, _ = self._eval_expr(
                                    rhs_for.strip(), rhs_for.strip(), s_ln, pre_env, var_types, lists, maps, owner_cls, depth, False
                                )
                                loop_env[elem_var] = iter_st
                    self._exec_units(
                        units, i + 1, end_blk, loop_env, dict(var_types), dict(canon_of),
                        {}, {}, owner_cls, depth, False, sink_line, return_states
                    )
                    _invalidate_collections_in_units(blk_slice, lists, maps)
                    if sink_line is not None and i + 1 < end_blk and units[i + 1][0] <= sink_line <= units[end_blk][1]:
                        env.clear()
                        env.update(loop_env)
                        break
                    for k in set(pre_env) | set(loop_env):
                        if k in pre_env:
                            env[k] = _merge_states(pre_env[k], loop_env.get(k, pre_env[k]), self.primary_cwe)
                if _units_mutate_ident(blk_slice, "guess"):
                    guess_val = None
                    guess_count += 1
                if _units_mutate_ident(blk_slice, "switchTarget"):
                    target_char = None
                    target_count += 1
                if _units_mutate_ident(blk_slice, "num"):
                    num_val = None
                    num_count += 1
                i = end_blk + 1
                continue

            # Compile-time arithmetic ternary `bar = (7 * 42) - num > 200 ? a : b;`
            m_tern = ARITH_TERNARY_RE.match(stripped_k)
            if m_tern:
                vname = m_tern.group(1)
                a_i = parse_java_nonneg_decimal_int_literal(m_tern.group(2))
                op1 = m_tern.group(3)
                b_i = parse_java_nonneg_decimal_int_literal(m_tern.group(4))
                op2 = m_tern.group(5)
                thresh = parse_java_nonneg_decimal_int_literal(m_tern.group(6))
                t_expr, f_expr = m_tern.group(7).strip(), m_tern.group(8).strip()
                resolved_chosen: str | None = None
                if (
                    at_top_scope
                    and num_val is not None
                    and a_i is not None
                    and b_i is not None
                    and thresh is not None
                    and not (op1 == "/" and b_i == 0)
                ):
                    lhs_v = (a_i * b_i) if op1 == "*" else (a_i // b_i)
                    if _JAVA_INT_MIN <= lhs_v <= _JAVA_INT_MAX:
                        comp_v = (lhs_v + num_val) if op2 == "+" else (lhs_v - num_val)
                        if _JAVA_INT_MIN <= comp_v <= _JAVA_INT_MAX:
                            resolved_chosen = t_expr if (comp_v > thresh) else f_expr
                if resolved_chosen is not None:
                    st, cites = self._eval_expr(
                        resolved_chosen, resolved_chosen, s_ln, env, var_types, lists, maps, owner_cls, depth, at_top_scope
                    )
                    env[vname] = st
                    canon_of.pop(vname, None)
                    self.mechanisms.append(f"arithmetic_ternary_{st.lower()}")
                    if num_line is not None:
                        self.key_lines.append(num_line)
                    self.key_lines.extend([s_ln] + cites)
                else:
                    # Overflow or non-constant `num`: conservatively merge both ternary branches
                    t_st, t_cites = self._eval_expr(
                        t_expr, t_expr, s_ln, env, var_types, lists, maps, owner_cls, depth, False
                    )
                    f_st, f_cites = self._eval_expr(
                        f_expr, f_expr, s_ln, env, var_types, lists, maps, owner_cls, depth, False
                    )
                    env[vname] = _merge_states(t_st, f_st, self.primary_cwe)
                    canon_of.pop(vname, None)
                    self.key_lines.extend([s_ln] + t_cites + f_cites)
                if vname == "guess":
                    guess_val = None
                    guess_count += 1
                elif vname == "switchTarget":
                    target_char = None
                    target_count += 1
                elif vname == "num":
                    num_val = None
                    num_count += 1
                i += 1
                continue

            # Collection mutations (List / Map) — strict fail-closed on non-decimal indices or unmodeled mutations
            m_ln = LIST_NEW_RE.search(stripped_m)
            if m_ln:
                lists[m_ln.group(1)] = []
                i += 1
                continue
            m_ladd = LIST_ADD_RE.match(stripped_k)
            if m_ladd:
                lname = m_ladd.group(1)
                add_args = _split_top_level_args(m_ladd.group(2))
                if lname in lists:
                    if at_top_scope and len(add_args) == 1:
                        est, _ = self._eval_expr(
                            add_args[0], add_args[0], s_ln, env, var_types, lists, maps, owner_cls, depth, at_top_scope
                        )
                        lists[lname].append((est, s_ln))
                    elif at_top_scope and len(add_args) == 2:
                        aidx = parse_java_nonneg_decimal_int_literal(add_args[0])
                        if aidx is not None and 0 <= aidx <= len(lists[lname]):
                            est, _ = self._eval_expr(
                                add_args[1], add_args[1], s_ln, env, var_types, lists, maps, owner_cls, depth, at_top_scope
                            )
                            lists[lname].insert(aidx, (est, s_ln))
                            self.key_lines.append(s_ln)
                        else:
                            lists.pop(lname, None)
                    else:
                        lists.pop(lname, None)
                i += 1
                continue
            m_lrem = LIST_REMOVE_RE.match(stripped_k)
            if m_lrem:
                lname = m_lrem.group(1)
                if lname in lists:
                    ridx = parse_java_nonneg_decimal_int_literal(m_lrem.group(2))
                    if at_top_scope and ridx is not None and 0 <= ridx < len(lists[lname]):
                        lists[lname].pop(ridx)
                        self.key_lines.append(s_ln)
                    else:
                        lists.pop(lname, None)
                i += 1
                continue
            m_lset = LIST_SET_RE.match(stripped_k)
            if m_lset:
                lname = m_lset.group(1)
                set_args = _split_top_level_args(m_lset.group(2))
                if lname in lists:
                    sidx = parse_java_nonneg_decimal_int_literal(set_args[0]) if len(set_args) == 2 else None
                    if at_top_scope and sidx is not None and 0 <= sidx < len(lists[lname]):
                        est, _ = self._eval_expr(
                            set_args[1], set_args[1], s_ln, env, var_types, lists, maps, owner_cls, depth, at_top_scope
                        )
                        lists[lname][sidx] = (est, s_ln)
                        self.key_lines.append(s_ln)
                    else:
                        lists.pop(lname, None)
                i += 1
                continue
            m_lclr = LIST_CLEAR_RE.match(stripped_m)
            if m_lclr:
                lname = m_lclr.group(1)
                if lname in lists:
                    if at_top_scope:
                        lists[lname] = []
                        self.key_lines.append(s_ln)
                    else:
                        lists.pop(lname, None)
                i += 1
                continue

            if MAP_NEW_RE.search(stripped_m):
                m_mn = MAP_NEW_RE.search(stripped_m)
                if m_mn:
                    maps[m_mn.group(1)] = {}
                i += 1
                continue
            m_mput = MAP_PUT_RE.match(stripped_k)
            if m_mput:
                mname, klit, vexpr = m_mput.group(1), m_mput.group(2), m_mput.group(3)
                if mname in maps and at_top_scope:
                    decoded_key = _unescape_java_string_literal_jls(klit)
                    if decoded_key is None:
                        maps.pop(mname, None)
                    else:
                        vst, _ = self._eval_expr(
                            vexpr, vexpr, s_ln, env, var_types, lists, maps, owner_cls, depth, at_top_scope
                        )
                        maps[mname][decoded_key] = (vst, s_ln)
                i += 1
                continue
            m_mput_any = MAP_PUT_ANY_RE.match(stripped_m)
            if m_mput_any and m_mput_any.group(1) in maps:
                maps.pop(m_mput_any.group(1), None)
                i += 1
                continue

            # Variable declaration without initializer `String bar;`
            m_decl_only = re.match(
                r"^\s*(?:final\s+)?[A-Za-z_][A-Za-z0-9_<>,.\[\]]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$",
                stripped_m,
            )
            if m_decl_only and m_decl_only.group(1) not in JAVA_KEYWORDS_AND_TYPES:
                env[m_decl_only.group(1)] = "UNSET"
                i += 1
                continue

            # Assignment `Type v = rhs;` or `v = rhs;` or `v += rhs;`
            m_asgn = ASSIGN_STMT_RE.match(stripped_k)
            m_asgn_m = ASSIGN_STMT_RE.match(stripped_m)
            if m_asgn and m_asgn_m:
                decl_type, vname, op_sym, rhs_k = (
                    m_asgn.group(1),
                    m_asgn.group(2),
                    m_asgn.group(3),
                    m_asgn.group(4).strip(),
                )
                rhs_m = m_asgn_m.group(4).strip()
                if vname not in JAVA_KEYWORDS_AND_TYPES:
                    # Drop tracked collection if reassigned directly (`values = List.of(...)`) or aliased/escaped on RHS
                    lists.pop(vname, None)
                    maps.pop(vname, None)
                    m_rhs_lget = LIST_GET_EXPR_RE.match(rhs_k) if op_sym == "=" else None
                    m_rhs_mget = MAP_GET_EXPR_RE.match(rhs_k) if op_sym == "=" else None
                    allow_l = {m_rhs_lget.group(1)} if (m_rhs_lget and parse_java_nonneg_decimal_int_literal(m_rhs_lget.group(2)) is not None) else set()
                    allow_m = {m_rhs_mget.group(1)} if m_rhs_mget else set()
                    rhs_idents = set(IDENT_RE.findall(rhs_m))
                    for lk in list(lists):
                        if lk in rhs_idents and lk not in allow_l:
                            lists.pop(lk, None)
                    for mk in list(maps):
                        if mk in rhs_idents and mk not in allow_m:
                            maps.pop(mk, None)
                    # Track concrete local class instantiation for receiver resolution
                    m_new_rhs = NEW_OBJ_ASSIGN_RE.match(rhs_k)
                    if m_new_rhs:
                        var_types[vname] = self._resolve_same_file_type(m_new_rhs.group(1))
                    elif decl_type:
                        var_types[vname] = self._resolve_same_file_type(decl_type)

                    # Track `canon = fileObj.getCanonicalPath();` binding
                    m_canon = CANONICAL_CALL_RE.match(rhs_k)
                    if op_sym == "=" and m_canon:
                        src_file_var = m_canon.group(1)
                        canon_of[vname] = src_file_var
                        rhs_st = env.get(src_file_var, "UNKNOWN")
                        cites = [s_ln]
                    else:
                        canon_of.pop(vname, None)
                        # If `vname` was a File object referenced by a canonical string, invalidate that binding!
                        for ck, fv in list(canon_of.items()):
                            if fv == vname:
                                canon_of.pop(ck, None)
                        # JDBC handle acquisition (Connection / Statement) does not carry payload data
                        simple_decl = (decl_type or "").rsplit(".", 1)[-1].strip()
                        if simple_decl in ("Connection", "Statement") and re.search(
                            r"\b(?:getSqlConnection|getSqlStatement|createStatement|getConnection)\s*\(", rhs_m
                        ):
                            rhs_st, cites = "DB_HANDLE", []
                        else:
                            rhs_st, cites = self._eval_expr(
                                rhs_k, rhs_m, s_ln, env, var_types, lists, maps, owner_cls, depth, at_top_scope
                            )

                    if op_sym == "+=":
                        prev_st = env.get(vname, "UNKNOWN")
                        if "TAINTED" in (prev_st, rhs_st):
                            env[vname] = "TAINTED"
                        elif "UNKNOWN" in (prev_st, rhs_st):
                            env[vname] = "UNKNOWN"
                        else:
                            env[vname] = rhs_st
                    else:
                        env[vname] = rhs_st

                    if rhs_st.startswith("SANITIZED_"):
                        self.sanitizers_applied.append({"name": rhs_st, "line": s_ln, "variable": vname})
                        self.key_lines.append(s_ln)
                    elif cites:
                        self.key_lines.extend(cites)
                    # Any subsequent assignment to tracked switch/arithmetic constants invalidates them
                    if vname == "guess":
                        guess_val = None
                        guess_count += 1
                    elif vname == "switchTarget":
                        target_char = None
                        target_count += 1
                    elif vname == "num":
                        num_val = None
                        num_count += 1
            else:
                # Any other unrecognized statement touching a tracked collection (e.g., helper(values), m.replace(...)) invalidates it!
                stmt_idents = set(IDENT_RE.findall(stripped_m))
                for lk in list(lists):
                    if lk in stmt_idents:
                        lists.pop(lk, None)
                for mk in list(maps):
                    if mk in stmt_idents:
                        maps.pop(mk, None)
                if _stmt_mutates_ident(stripped_m, "guess"):
                    guess_val = None
                    guess_count += 1
                if _stmt_mutates_ident(stripped_m, "switchTarget"):
                    target_char = None
                    target_count += 1
                if _stmt_mutates_ident(stripped_m, "num"):
                    num_val = None
                    num_count += 1

            i += 1
        return False

    def _split_inline_switch_statements(
        self, s_ln: int, e_ln: int, code: str, masked: str
    ) -> list[tuple[int, int, str, str]]:
        """Split single-line inline statements (e.g. `{ bar = input; break; }` or `bar = input; break;`)."""
        c = code.strip()
        m = masked.strip()
        while c.startswith("{") and c.endswith("}") and m.startswith("{") and m.endswith("}"):
            c = c[1:-1].strip()
            m = m[1:-1].strip()
        if not c:
            return []
        c_parts = _split_sink_statements(c)
        m_parts = _split_sink_statements(m)
        if len(c_parts) == len(m_parts) and len(c_parts) > 1:
            out: list[tuple[int, int, str, str]] = []
            for cp, mp in zip(c_parts, m_parts):
                cp_s = cp.strip()
                mp_s = mp.strip()
                if not cp_s:
                    continue
                if not cp_s.endswith((";", "{", "}")):
                    cp_s += ";"
                if not mp_s.endswith((";", "{", "}")):
                    mp_s += ";"
                if BREAK_RE.match(mp_s):
                    continue
                out.append((s_ln, e_ln, cp_s, mp_s))
            return out
        if BREAK_RE.match(m):
            return []
        return [(s_ln, e_ln, c, m)]

    def _exec_nonconstant_switch(
        self,
        units: list[tuple[int, int, str, str]],
        idx_start: int,
        idx_end: int,
        env: dict[str, str],
        var_types: dict[str, str | None],
        canon_of: dict[str, str],
        lists: dict[str, list[tuple[str, int]]],
        maps: dict[str, dict[str, tuple[str, int]]],
        owner_cls: str | None,
        depth: int,
        sink_line: int | None,
        return_states: list[tuple[str, list[int]]],
    ) -> None:
        """Conservatively merge every case segment (both fresh entry and fall-through) so no later case masks an earlier taint."""
        sw_slice = units[idx_start:idx_end]
        _invalidate_collections_in_units(sw_slice, lists, maps)

        segments: list[tuple[list[tuple[int, int, str, str]], bool]] = []
        cur_seg: list[tuple[int, int, str, str]] = []
        brace_depth = 0

        label_prefix_re = re.compile(r"^\s*(?:case\b[^:]*:|default\s*:)\s*")
        for s_ln, e_ln, code, masked in sw_slice:
            m_strip = masked.strip()
            c_strip = code.strip()
            if brace_depth == 0 and label_prefix_re.match(m_strip):
                if cur_seg:
                    segments.append((cur_seg, False))
                    cur_seg = []
                # Strip one or more leading `case ...:` / `default:` prefixes on the same line
                rem_k = c_strip
                rem_m = m_strip
                while True:
                    ml_m = label_prefix_re.match(rem_m)
                    ml_k = label_prefix_re.match(rem_k)
                    if not (ml_m and ml_k):
                        break
                    rem_m = rem_m[ml_m.end() :].strip()
                    rem_k = rem_k[ml_k.end() :].strip()
                if rem_k:
                    if rem_m.count("{") == rem_m.count("}") and (";" in rem_m or (rem_m.startswith("{") and rem_m.endswith("}"))):
                        has_inline_break = bool(re.search(r"\bbreak\s*;", rem_m))
                        cur_seg.extend(self._split_inline_switch_statements(s_ln, e_ln, rem_k, rem_m))
                        if has_inline_break:
                            segments.append((cur_seg, True))
                            cur_seg = []
                    else:
                        cur_seg.append((s_ln, e_ln, rem_k, rem_m))
                        brace_depth += rem_m.count("{") - rem_m.count("}")
                continue
            if brace_depth == 0 and BREAK_RE.match(m_strip):
                segments.append((cur_seg, True))
                cur_seg = []
                continue
            cur_seg.append((s_ln, e_ln, code, masked))
            brace_depth += m_strip.count("{") - m_strip.count("}")
        if cur_seg:
            segments.append((cur_seg, False))

        pre_env = dict(env)
        if not segments:
            return

        all_envs: list[dict[str, str]] = [dict(pre_env)]
        fallthrough_env = dict(pre_env)
        sink_env: dict[str, str] | None = None

        for seg_units, ends_with_break in segments:
            if not seg_units:
                if ends_with_break:
                    fallthrough_env = dict(pre_env)
                continue
            seg_fresh = dict(pre_env)
            self._exec_units(
                seg_units, 0, len(seg_units), seg_fresh, dict(var_types), dict(canon_of),
                {}, {}, owner_cls, depth, False, sink_line, return_states
            )
            all_envs.append(seg_fresh)

            seg_ft = dict(fallthrough_env)
            self._exec_units(
                seg_units, 0, len(seg_units), seg_ft, dict(var_types), dict(canon_of),
                {}, {}, owner_cls, depth, False, sink_line, return_states
            )
            all_envs.append(seg_ft)

            if sink_line is not None and seg_units[0][0] <= sink_line <= seg_units[-1][1]:
                sink_env = {}
                for k in set(seg_fresh) | set(seg_ft):
                    sink_env[k] = _merge_states(
                        seg_fresh.get(k, "UNSET"), seg_ft.get(k, "UNSET"), self.primary_cwe
                    )

            if ends_with_break:
                fallthrough_env = dict(pre_env)
            else:
                next_ft: dict[str, str] = {}
                for k in set(seg_fresh) | set(seg_ft):
                    next_ft[k] = _merge_states(
                        seg_fresh.get(k, "UNSET"), seg_ft.get(k, "UNSET"), self.primary_cwe
                    )
                fallthrough_env = next_ft

        if sink_env is not None:
            env.clear()
            env.update(sink_env)
            return

        all_keys: set[str] = set()
        for e_map in all_envs:
            all_keys.update(e_map.keys())
        for k in all_keys:
            merged_st = all_envs[0].get(k, "UNSET")
            for e_map in all_envs[1:]:
                merged_st = _merge_states(merged_st, e_map.get(k, "UNSET"), self.primary_cwe)
            env[k] = merged_st

    def _exec_constant_switch(
        self,
        units: list[tuple[int, int, str, str]],
        idx_start: int,
        idx_end: int,
        target_char: str,
        target_line: int | None,
        guess_line: int | None,
        env: dict[str, str],
        var_types: dict[str, str | None],
        canon_of: dict[str, str],
        lists: dict[str, list[tuple[str, int]]],
        maps: dict[str, dict[str, tuple[str, int]]],
        owner_cls: str | None,
        depth: int,
        sink_line: int | None,
        return_states: list[tuple[str, list[int]]],
    ) -> None:
        # Strict validation: fail closed to conservative multi-branch switch if any label, break, or arrow syntax is non-trivial
        brace_depth = 0
        matched_idx: int | None = None
        default_idx: int | None = None
        for j in range(idx_start, idx_end):
            _, _, c_code, c_mask = units[j]
            m_strip = c_mask.strip()
            if "->" in m_strip or re.search(r"\byield\b", m_strip):
                self._exec_nonconstant_switch(
                    units, idx_start, idx_end, env, var_types, canon_of,
                    lists, maps, owner_cls, depth, sink_line, return_states
                )
                return
            if brace_depth == 0:
                if re.match(r"^\s*case\b", c_code):
                    m_case = CASE_CHAR_RE.match(c_code)
                    if not m_case:
                        self._exec_nonconstant_switch(
                            units, idx_start, idx_end, env, var_types, canon_of,
                            lists, maps, owner_cls, depth, sink_line, return_states
                        )
                        return
                    if m_case.group(1) == target_char:
                        if matched_idx is not None:
                            self._exec_nonconstant_switch(
                                units, idx_start, idx_end, env, var_types, canon_of,
                                lists, maps, owner_cls, depth, sink_line, return_states
                            )
                            return
                        matched_idx = j
                elif re.match(r"^\s*default\b", c_code):
                    if not DEFAULT_CASE_RE.match(c_code) or default_idx is not None:
                        self._exec_nonconstant_switch(
                            units, idx_start, idx_end, env, var_types, canon_of,
                            lists, maps, owner_cls, depth, sink_line, return_states
                        )
                        return
                    default_idx = j
                elif re.search(r"\bbreak\b", m_strip) and not BREAK_RE.match(m_strip):
                    self._exec_nonconstant_switch(
                        units, idx_start, idx_end, env, var_types, canon_of,
                        lists, maps, owner_cls, depth, sink_line, return_states
                    )
                    return
            else:
                if re.search(r"\b(?:case|default|break)\b", m_strip):
                    self._exec_nonconstant_switch(
                        units, idx_start, idx_end, env, var_types, canon_of,
                        lists, maps, owner_cls, depth, sink_line, return_states
                    )
                    return
            brace_depth += m_strip.count("{") - m_strip.count("}")

        # Pass 2 (JLS §14.11): exact case match takes precedence over `default:` regardless of order
        entry_idx = matched_idx if matched_idx is not None else default_idx
        active_indices: set[int] = set()
        active_units: list[tuple[int, int, str, str]] = []
        if entry_idx is not None:
            active_indices.add(entry_idx)
            brace_depth = 0
            for j in range(entry_idx + 1, idx_end):
                s_ln, e_ln, code, masked = units[j]
                m_strip = masked.strip()
                if brace_depth == 0:
                    if BREAK_RE.match(m_strip):
                        active_indices.add(j)
                        break
                    if CASE_CHAR_RE.match(code) or DEFAULT_CASE_RE.match(code):
                        active_indices.add(j)
                        continue
                active_indices.add(j)
                active_units.append((s_ln, e_ln, code, masked))
                brace_depth += m_strip.count("{") - m_strip.count("}")

        for j in range(idx_start, idx_end):
            if j not in active_indices:
                s_ln, e_ln, _, _ = units[j]
                self.dead_branch_lines.update(range(s_ln, e_ln + 1))

        if guess_line is not None:
            self.key_lines.append(guess_line)
        if target_line is not None:
            self.key_lines.append(target_line)
        if active_units:
            self.mechanisms.append("switch_constant_char_branch")
            self._exec_units(
                active_units, 0, len(active_units), env, var_types, canon_of,
                lists, maps, owner_cls, depth, True, sink_line, return_states
            )


def _split_sink_statements(raw_stmt: str) -> list[str]:
    """Split a sink span or try-with-resources header into all top-level statements."""
    s = raw_stmt.strip()
    if s.startswith("try") and "(" in s:
        p_idx = s.find("(")
        s = s[p_idx + 1 :].strip()
    # Remove trailing `); ) {` or `) {` left by try-with-resources blocks
    s = re.sub(r";\s*\)\s*\{\s*$", ";", s)
    s = re.sub(r"\)\s*\{\s*$", "", s)
    s = re.sub(r"\{\s*$", "", s).strip()
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    in_s = False
    in_c = False
    i = 0
    while i < len(s):
        ch = s[i]
        if in_s:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if ch == '"':
                in_s = False
            i += 1
            continue
        if in_c:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if ch == "'":
                in_c = False
            i += 1
            continue
        if ch == '"':
            in_s = True
            cur.append(ch)
        elif ch == "'":
            in_c = True
            cur.append(ch)
        elif ch in "([":
            depth += 1
            cur.append(ch)
        elif ch in ")]":
            if depth > 0:
                depth -= 1
                cur.append(ch)
        elif ch == ";" and depth == 0:
            stmt = "".join(cur).strip()
            if stmt:
                parts.append(stmt)
            cur = []
        else:
            cur.append(ch)
        i += 1
    rem = "".join(cur).strip()
    if rem:
        parts.append(rem)
    if len(parts) > 1:
        filtered = [
            cand for cand in parts
            if not re.search(r"\b(?:printResults|outputUpdateComplete|executeBatch)\s*\(", cand)
        ]
        return filtered if filtered else parts
    return parts if parts else ([s] if s else [])


def _clean_sink_statement(raw_stmt: str) -> str:
    """Select the terminal sink statement from a multi-statement rule span and strip try-with-resources tails."""
    parts = _split_sink_statements(raw_stmt)
    return parts[-1] if parts else raw_stmt.strip()


_CWE22_STATIC_UTIL_RECEIVERS = {
    "Files", "Paths", "Path", "File", "FileUtils", "FilenameUtils", "IOUtils",
    "java.nio.file.Files", "java.nio.file.Paths", "java.nio.file.Path",
    "java.io.File", "org.apache.commons.io.FileUtils",
    "org.apache.commons.io.FilenameUtils", "org.apache.commons.io.IOUtils",
}


def _evaluate_sink_state(
    sink_code: str,
    sink_masked: str,
    sink_line: int,
    env: dict[str, str],
    analyzer: _FlowAnalyzer,
    owner_cls: str | None,
) -> str:
    """Evaluate the abstract state of the sink's vulnerable argument(s) at `sink_line`."""
    k_stmts = _split_sink_statements(sink_code)
    m_stmts = _split_sink_statements(sink_masked)
    if len(k_stmts) != len(m_stmts) or not k_stmts:
        pairs = [(_clean_sink_statement(sink_code), _clean_sink_statement(sink_masked))]
    else:
        pairs = list(zip(k_stmts, m_stmts))

    sink_arg_exprs: list[tuple[str, str]] = []
    for clean_k, clean_m in pairs:
        rhs_k = clean_k
        rhs_m = clean_m
        m_asgn = ASSIGN_STMT_RE.match(clean_k + ";")
        m_asgn_m = ASSIGN_STMT_RE.match(clean_m + ";")
        if m_asgn and m_asgn_m:
            rhs_k = m_asgn.group(4).strip()
            rhs_m = m_asgn_m.group(4).strip()
        rhs_k = re.sub(r"^return\s+", "", rhs_k).strip()
        rhs_m = re.sub(r"^return\s+", "", rhs_m).strip()

        stmt_args: list[tuple[str, str]] = []
        m_new = re.search(r"\bnew\s+[A-Za-z_][A-Za-z0-9_.]*\s*\((.+)\)(?:\s*\.\s*getFD\s*\(\s*\))?$", rhs_k)
        m_new_m = re.search(r"\bnew\s+[A-Za-z_][A-Za-z0-9_.]*\s*\((.+)\)(?:\s*\.\s*getFD\s*\(\s*\))?$", rhs_m)
        if m_new and m_new_m:
            for ak, am in zip(_split_top_level_args(m_new.group(1)), _split_top_level_args(m_new_m.group(1))):
                stmt_args.append((ak, am))
        else:
            # Method call sink e.g. `stmt.executeQuery(sql)`, `jdbcTemplate.queryForMap(sql)`, `baseDir.resolve(p)`
            m_mc = re.search(r"\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$", rhs_k)
            m_mc_m = re.search(r"\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$", rhs_m)
            if m_mc and m_mc_m:
                mname = m_mc.group(1)
                k_args = _split_top_level_args(m_mc.group(2))
                m_args = _split_top_level_args(m_mc_m.group(2))
                if analyzer.primary_cwe == "CWE-89" and mname in (
                    "execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
                    "prepareStatement", "prepareCall", "query", "queryForMap",
                    "queryForObject", "queryForList", "queryForRowSet", "update", "batchUpdate", "addBatch",
                ) and k_args:
                    stmt_args.append((k_args[0], m_args[0] if m_args else k_args[0]))
                else:
                    if analyzer.primary_cwe == "CWE-22":
                        recv_k = rhs_k[: m_mc.start()].strip()
                        recv_m = rhs_m[: m_mc_m.start()].strip()
                        if recv_k and recv_k not in _CWE22_STATIC_UTIL_RECEIVERS:
                            stmt_args.append((recv_k, recv_m))
                    for ak, am in zip(k_args, m_args):
                        stmt_args.append((ak, am))

        if not stmt_args:
            stmt_args = [(rhs_k, rhs_m)]
        sink_arg_exprs.extend(stmt_args)

    states: list[str] = []
    for ak, am in sink_arg_exprs:
        st, _ = analyzer._eval_expr(ak, am, sink_line, env, {}, {}, {}, owner_cls, 0, True)
        states.append(st)

    if "TAINTED" in states:
        return "TAINTED"
    if "UNKNOWN" in states or not states:
        return "UNKNOWN"
    san_tag = f"SANITIZED_{analyzer.primary_cwe.replace('-', '')}"
    if all(s in ("SAFE_CONST", san_tag) for s in states):
        return san_tag if san_tag in states else "SAFE_CONST"
    return "UNKNOWN"


def extract_evidence_signals(record: dict[str, Any]) -> dict[str, Any]:
    """Extract flow-grounded CWE-22/CWE-89 evidence signals from verified record snippets."""
    primary_path, sha, lines_by_no = _collect_available_lines(record)
    cwes = record.get("cwe") or []
    primary_cwe = (
        "CWE-22"
        if any("22" in str(c) for c in cwes)
        else ("CWE-89" if any("89" in str(c) for c in cwes) else (cwes[0] if cwes else "UNKNOWN"))
    )

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

    keep_str, masked_str = _strip_comments_and_mask_lines(lines_by_no)

    # Reconstruct full virtual text preserving 1-based line numbers for structural method parsing
    max_ln = max(lines_by_no.keys(), default=0)
    virtual_lines = [lines_by_no.get(i, "") for i in range(1, max_ln + 1)]
    structure = parse_java_structure("\n".join(virtual_lines)) if max_ln > 0 else {
        "package_name": None, "classes": [], "methods": []
    }
    jctx = record.get("java_context") if isinstance(record.get("java_context"), dict) else {}
    pkg_name = structure["package_name"] or jctx.get("package_name")
    outer_cls = jctx.get("enclosing_class")
    same_file_classes = {c["name"] for c in structure["classes"]}
    if outer_cls:
        same_file_classes.add(outer_cls)
    for m in structure["methods"]:
        if m.get("owner_class") is None and outer_cls:
            m["owner_class"] = outer_cls

    enclosing_method: dict[str, Any] | None = None
    for m in structure["methods"]:
        if m["start_line"] <= sink_line <= m["end_line"]:
            if enclosing_method is None or (m["end_line"] - m["start_line"]) < (
                enclosing_method["end_line"] - enclosing_method["start_line"]
            ):
                enclosing_method = m

    source_kind = "METHOD_OR_EXTERNAL_INPUT"
    http_source_line: int | None = None
    uses_inner_helper = False
    uses_thing_factory = False
    for ln_no, m_txt in masked_str.items():
        if HTTP_SOURCE_CALL_RE.search(m_txt):
            if http_source_line is None or (http_source_line > sink_line and ln_no <= sink_line):
                http_source_line = ln_no
                source_kind = "HTTP_SERVLET_INPUT"
        if re.search(r"\bdoSomething\s*\(", m_txt):
            uses_inner_helper = True
        if re.search(r"\bThingFactory\.createThing\s*\(", m_txt):
            uses_thing_factory = True

    if enclosing_method is not None and http_source_line is not None:
        if source_line < enclosing_method["start_line"] <= http_source_line <= sink_line:
            source_line = http_source_line

    analyzer = _FlowAnalyzer(
        primary_cwe=primary_cwe,
        keep_str=keep_str,
        masked_str=masked_str,
        methods=structure["methods"],
        same_file_classes=same_file_classes,
        package_name=pkg_name,
    )

    if enclosing_method is None or not lines_by_no:
        sink_state = "UNKNOWN"
    elif any(
        _contains_java_unicode_escape(lines_by_no.get(ln, ""))
        for ln in range(enclosing_method["header_line"], enclosing_method["end_line"] + 1)
    ):
        # JLS §3.3 raw Unicode escapes translate before lexical tokenization -> fail closed to UNKNOWN
        sink_state = "UNKNOWN"
    else:
        env: dict[str, str] = {}
        # Seed explicit OpenGrep taint_source variable if source_line is a simple parameter/local read
        if source_line in keep_str and source_line < sink_line:
            src_k = keep_str[source_line].strip()
            src_m = masked_str[source_line].strip()
            if HTTP_SOURCE_CALL_RE.search(src_m):
                pass  # Handled directly during statement execution
        analyzer.analyze_method(enclosing_method, initial_env=env, stop_before_sink_line=sink_line, depth=0)

        # Combine multi-line sink span [sink_line .. sink_end_line]
        sink_k = " ".join(keep_str.get(ln, "").strip() for ln in range(sink_line, sink_end_line + 1) if keep_str.get(ln, "").strip())
        sink_m = " ".join(masked_str.get(ln, "").strip() for ln in range(sink_line, sink_end_line + 1) if masked_str.get(ln, "").strip())
        # If sink statement continues onto subsequent lines (e.g. `new File(\n bar)`), join until `;`
        ext_end = sink_end_line
        while ext_end < enclosing_method["end_line"] and not sink_m.endswith((";", "{", "}")):
            ext_end += 1
            if masked_str.get(ext_end, "").strip():
                sink_k += " " + keep_str[ext_end].strip()
                sink_m += " " + masked_str[ext_end].strip()

        sink_state = _evaluate_sink_state(
            sink_k, sink_m, sink_line, env, analyzer, enclosing_method.get("owner_class")
        )

    san_tag = f"SANITIZED_{primary_cwe.replace('-', '')}"
    sink_lines = [sink_line] if sink_end_line == sink_line else [sink_line, sink_end_line]

    if sink_state == "TAINTED":
        recommended_status = "SUPPORTED"
        recommendation_reason = (
            f"Luồng dữ liệu không tin cậy từ dòng {source_line} truyền tới sink {primary_cwe} "
            f"tại dòng {sink_line} trên nhánh thực thi khả dĩ mà không được làm sạch hợp lệ."
        )
        raw_cite_lines = [source_line] + analyzer.key_lines + sink_lines
    elif sink_state in ("SAFE_CONST", san_tag):
        recommended_status = "REFUTED"
        if sink_state == san_tag and analyzer.sanitizers_applied:
            san_ln = analyzer.sanitizers_applied[-1]["line"]
            recommendation_reason = (
                f"Biến đi vào sink {primary_cwe} (dòng {sink_line}) đã được làm sạch đúng ngữ cảnh "
                f"tại dòng {san_ln} trên mọi nhánh thực thi trước sink và không bị ghi đè lại."
            )
        else:
            recommendation_reason = (
                f"Giá trị đi vào sink {primary_cwe} tại dòng {sink_line} được chứng minh nhận hằng an toàn "
                "trên mọi nhánh thực thi khả dĩ trong phạm vi tệp nguồn đã khóa."
            )
        raw_cite_lines = [source_line] + analyzer.key_lines + sink_lines
    else:
        recommended_status = "UNDETERMINED"
        recommendation_reason = (
            "Không đủ bằng chứng trong phạm vi mã nguồn đã khóa để chứng minh luồng dữ liệu an toàn hay "
            "nhiễm bẩn (tồn tại lời gọi phương thức phụ trợ ngoài phạm vi hoặc kiểm tra đường dẫn chưa đủ chặt)."
        )
        raw_cite_lines = []

    intra_procedural_decisive = not uses_inner_helper and not uses_thing_factory and not analyzer.unresolved_calls

    dedup_lines: list[int] = []
    for ln in raw_cite_lines:
        if (
            ln in lines_by_no
            and ln not in analyzer.dead_branch_lines
            and ln not in dedup_lines
            and _make_citation(primary_path, sha, ln, lines_by_no) is not None
        ):
            dedup_lines.append(ln)
    if recommended_status != "UNDETERMINED" and not dedup_lines:
        if _make_citation(primary_path, sha, sink_line, lines_by_no) is not None:
            dedup_lines.append(sink_line)
    if len(dedup_lines) > 3:
        dedup_lines = [dedup_lines[0], dedup_lines[len(dedup_lines) // 2], dedup_lines[-1]]
    dedup_lines.sort()

    candidate_citations = [
        c for ln in dedup_lines if (c := _make_citation(primary_path, sha, ln, lines_by_no)) is not None
    ]
    if recommended_status != "UNDETERMINED" and not candidate_citations:
        recommended_status = "UNDETERMINED"

    mech_summary = analyzer.mechanisms[-1] if analyzer.mechanisms else None
    flow_summary = {
        "outcome": (
            "SAFE_CONSTANT"
            if sink_state in ("SAFE_CONST", san_tag)
            else ("TAINTED" if sink_state == "TAINTED" else None)
        ),
        "mechanism": mech_summary,
        "key_lines": sorted(set(analyzer.key_lines)),
    }

    return {
        "heuristic_version": HEURISTIC_VERSION,
        "primary_cwe": primary_cwe,
        "source_kind": source_kind,
        "source_line": source_line,
        "sink_line": sink_line,
        "uses_inner_helper": uses_inner_helper,
        "uses_thing_factory": uses_thing_factory,
        "intra_procedural_decisive": intra_procedural_decisive,
        "sanitizers_found": analyzer.sanitizers_applied,
        "non_sanitizers_found": analyzer.non_sanitizers_seen,
        "unresolved_calls": analyzer.unresolved_calls,
        "dead_branch_lines": sorted(analyzer.dead_branch_lines),
        "intra_method_flow": flow_summary if not uses_inner_helper else {"outcome": None, "mechanism": None, "key_lines": []},
        "callee_method_flow": flow_summary if uses_inner_helper else {"outcome": None, "mechanism": None, "key_lines": []},
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
        "model": "heuristic-cwe22-cwe89-v2.2",
        "heuristic_version": HEURISTIC_VERSION,
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

    signals = extract_evidence_signals(record)
    intra_mech = (signals.get("intra_method_flow") or {}).get("mechanism") or ""
    if (
        signals.get("recommended_status") == "UNDETERMINED"
        or not signals.get("intra_procedural_decisive", True)
        or signals.get("uses_inner_helper")
        or signals.get("uses_thing_factory")
        or signals.get("unresolved_calls")
        or intra_mech.startswith("list_index_")
        or intra_mech.startswith("map_key_")
    ):
        return {
            "status": "UNDETERMINED",
            "explanation": (
                "Heuristic nội phương thức (Arm B) chuyển về UNDETERMINED khi luồng dữ liệu phụ thuộc "
                "phương thức phụ trợ, cấu trúc tập hợp hoặc thiếu bằng chứng đầy đủ để tự động kết luận."
            ),
            "citations": [],
            "fix_suggestion": "Chuyển sang hàng đợi duyệt thủ công hoặc kiểm tra ngữ cảnh mở rộng.",
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
        else "Chuẩn hóa đường dẫn bằng getCanonicalPath() và kiểm tra tiền tố thư mục có dấu phân cách biên."
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
