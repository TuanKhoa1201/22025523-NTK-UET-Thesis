"""Fail-closed integration triage gate at the v2/api boundary.

Single authoritative verdict publication gate enforcing:
- Blocker D (P0-IV): Downgrades `SUPPORTED` and `REFUTED` to `UNDETERMINED` (`UNVERIFIED_HELPER_FLOW`)
  when a flow-deciding helper is absent, budget-dropped, >3 hops, ambiguous owner/package/overload,
  static-vs-instance mismatched, subject to dynamic dispatch, or fails SHA-256 verification.
- Blocker C (P0-III & P0-V): NEVER authorizes `REFUTED` from heuristic `recommended_status` or
  heuristic/Qwen agreement alone. Requires independent structural safety verification directly over
  continuous verified Java lines of the enclosing method, parsed with a structured recursive-descent
  statement parser where any unmodeled/unknown statement, unmodeled control flow, or condition
  side effect invalidates prior safety assumptions (fail-closed to `UNDETERMINED`).
  Canonical CWE-22 containment requires both canonical/real path resolution on a non-root constant
  base with a real directory separator boundary AND the checked canonical value (never the raw path)
  flowing to the sink.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from v2.triage.evidence import now
from v2.triage.ollama import inspect_citations_provenance

from .java_context_v2 import (
    _extract_param_types_and_count,
    _find_matching_paren,
    _merge_header_metadata_into_unit,
    _split_top_level_commas,
    analyze_flow_dependencies,
    collect_project_package_classes,
    extract_class_field_names,
    parse_java_structure_v2,
    resolve_stdlib_class_fqn,
)

SUPPORTED_REFUTATION_PROOF_CLASSES = (
    "CWE22_CANONICAL_CONTAINMENT_GUARD",
    "UNCONDITIONAL_CONSTANT_SINK_FLOW",
    "CWE89_CONSTANT_PREPARED_STATEMENT",
    "CWE89_UNCONDITIONAL_SCALAR_PARSE",
)

UNSUPPORTED_REFUTATION_PROOF_LIMITS = (
    "REFUTED auto-triage gate only authorizes independently verified CWE-22 canonical directory "
    "containment guards (with checked canonical value used at the sink), unconditional constant sink flows, "
    "constant-template PreparedStatement, or unconditional scalar parse (Integer.parseInt/Long.parseLong/UUID.fromString); "
    "refutations relying on Java integer/long arithmetic, branch pruning, collections, switch, try/catch fallthrough, "
    "unmodeled statements, or custom allowlists remain UNDETERMINED (affects FP recall in G3).",
)

_BASENAME_SANITIZER_NAMES = (
    "basename",
    "filenameutils",
    "getfilename",
    "cwe22_basename",
)
_BASENAME_CALL_RE = re.compile(
    r"\b(?:FilenameUtils\.getName\s*\(|new\s+(?:java\.io\.)?File\s*\([^)]*\)\s*\.\s*getName\s*\(|"
    r"[A-Za-z_][A-Za-z0-9_.]*\s*\.\s*getFileName\s*\()"
)
_NORMALIZE_CALL_RE = re.compile(r"\.\s*normalize\s*\(\s*\)")
_HTTP_TAINT_RE = re.compile(
    r"\b(?:getParameter|getParameterValues|getParameterMap|getParameterNames|"
    r"getHeader|getHeaders|getHeaderNames|getCookies|getQueryString|getPathInfo|"
    r"getRequestURI|getRequestURL|getReader|getInputStream)\s*\("
)

# Canonical / real path expressions (ONLY filesystem-resolving APIs, never lexical normalize/getAbsolutePath)
_CANON_PATH_STR_RHS_RE = re.compile(
    r"^(?:this\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:"
    r"getCanonicalPath\s*\(\s*\)|"
    r"getCanonicalFile\s*\(\s*\)\s*\.\s*getPath\s*\(\s*\)|"
    r"toRealPath\s*\(\s*\)\s*\.\s*toString\s*\(\s*\)"
    r")$"
)
_CANON_FILE_RHS_RE = re.compile(
    r"^(?:this\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*getCanonicalFile\s*\(\s*\)$"
)
_TO_REAL_PATH_RHS_RE = re.compile(
    r"^(?:this\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*toRealPath\s*\(\s*\)$"
)
_INLINE_CONST_CANON_STR_RE = re.compile(
    r'^new\s+(?:java\.io\.)?File\s*\(\s*("[^"]*")\s*\)\s*\.\s*getCanonicalPath\s*\(\s*\)$'
)
_INLINE_CONST_REAL_PATH_RE = re.compile(
    r'^(?:java\.nio\.file\.)?(?:Paths\.get|Path\.of)\s*\(\s*("[^"]*")\s*\)\s*\.\s*toRealPath\s*\(\s*\)$'
)
_NEW_CONST_FILE_RE = re.compile(
    r'^new\s+(?:java\.io\.)?File\s*\(\s*("[^"]*")\s*\)$'
)
_NEW_FILE_ARGS_RE = re.compile(
    r"^new\s+(?:java\.io\.)?File\s*\(\s*(.+)\s*\)$"
)
_PATHS_GET_ARGS_RE = re.compile(
    r"^(?:java\.nio\.file\.)?(?:Paths\.get|Path\.of)\s*\(\s*(.+)\s*\)$"
)
_NEG_STARTSWITH_COND_RE = re.compile(
    r"^!\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*getPath\s*\(\s*\))?)\s*\.\s*startsWith\s*\(\s*(.+)\s*\)$"
)
_POS_STARTSWITH_COND_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*getPath\s*\(\s*\))?)\s*\.\s*startsWith\s*\(\s*(.+)\s*\)$"
)
_LOCAL_ASSIGN_RE = re.compile(
    r"^\s*(?:final\s+)?(?:([A-Za-z_][A-Za-z0-9_<>,.\[\]]*(?:\s*\[\s*\])*)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(\+?=)\s*(.+?)\s*;\s*$"
)
_DECL_ONLY_RE = re.compile(
    r"^\s*(?:final\s+)?([A-Za-z_][A-Za-z0-9_<>,.\[\]]*(?:\s*\[\s*\])*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$"
)
_PREPARED_STMT_BIND_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:setString|setInt|setLong|setBoolean|setDouble|setFloat|"
    r"setShort|setByte|setBigDecimal|setTimestamp|setDate|setTime|setObject|setNull)\s*\((.*)\)\s*;\s*$"
)
_SCALAR_PARSE_RE = re.compile(
    r"^((?:java\.lang\.)?Integer|(?:java\.lang\.)?Long|(?:java\.util\.)?UUID)\s*\.\s*(parseInt|parseLong|fromString)\s*\(.+\)$"
)
_CWE22_PATH_JOIN_SINK_RE = re.compile(
    r"(?:\bnew\s+(?:java\.io\.)?File\s*\(|\b(?:java\.nio\.file\.)?(?:Paths\.get|Path\.of)\s*\(|\.\s*resolve\s*\()"
)
_PREPARE_CALL_RE = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_.]*)\s*\.\s*(?:prepareStatement|prepareCall)\s*\((.+)\)$"
)
_PREP_EXEC_ZERO_RE = re.compile(
    r"^(?:return\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:executeQuery|executeUpdate|execute)\s*\(\s*\)\s*;?$"
)
_NUM_OR_BOOL_LITERAL_RE = re.compile(r"^(?:null|true|false|-?\d+[lL]?)$")
_SIMPLE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_EXPR_SIDE_EFFECT_RE = re.compile(
    r"(?<![=!<>+\-*/%&|^])=(?!=)|"
    r"(?:<<=|>>=|>>>=|[+\-*/%&|^]=)|"
    r"\+\+|--|->"
)
_ANY_CALL_IN_EXPR_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_JAVA_KEYWORDS = frozenset(
    {
        "if", "else", "for", "while", "do", "switch", "case", "default", "break",
        "continue", "return", "throw", "try", "catch", "finally", "new", "this",
        "super", "null", "true", "false", "final", "int", "long", "char", "boolean",
        "byte", "short", "double", "float", "void", "String", "Object", "File",
        "Path", "Paths", "Files", "UUID", "Integer", "Long", "synchronized",
        "assert", "yield", "package", "import", "class", "interface", "enum",
        "extends", "implements", "throws", "static", "public", "private", "protected",
    }
)
_JAVA_NON_TYPE_KEYWORDS = frozenset(
    {
        "if", "else", "for", "while", "do", "switch", "case", "default", "break",
        "continue", "return", "throw", "try", "catch", "finally", "new", "this",
        "super", "null", "true", "false", "void", "synchronized", "assert", "yield",
        "package", "import", "class", "interface", "enum", "extends", "implements",
        "throws", "static", "public", "private", "protected", "goto", "const",
    }
)


def _is_valid_citation_dict(cite: Any) -> bool:
    if not isinstance(cite, dict):
        return False
    c_path = cite.get("path")
    s_line = cite.get("start_line")
    e_line = cite.get("end_line")
    return (
        isinstance(c_path, str)
        and bool(c_path.strip())
        and type(s_line) is int
        and type(e_line) is int
        and s_line >= 1
        and e_line >= s_line
        and isinstance(cite.get("quote"), str)
        and isinstance(cite.get("sha256"), str)
    )


def _build_citation_provenance_summary(prov: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(prov, dict):
        return {
            "citation_in_source": False,
            "citation_in_prompt": False,
            "citation_posthoc_only": False,
            "supports_security_claim_verified": False,
        }
    return {
        "citation_in_source": bool(prov.get("citation_in_source")),
        "citation_in_prompt": bool(prov.get("citation_in_prompt")),
        "citation_posthoc_only": bool(prov.get("citation_posthoc_only")),
        "supports_security_claim_verified": False,
    }


def _has_forged_empty_citation_claims(assessment: dict[str, Any]) -> bool:
    """Return True if an empty-citation assessment claims MATCHED or verified provenance flags."""
    if assessment.get("citation_check") == "MATCHED":
        return True
    cp = assessment.get("citation_provenance")
    if isinstance(cp, dict):
        if (
            cp.get("citation_in_source") is True
            or cp.get("citation_in_prompt") is True
            or cp.get("supports_security_claim_verified") is True
        ):
            return True
    return False


def _verify_citation_integrity(
    record: dict[str, Any],
    assessment: dict[str, Any],
    *,
    require_non_empty: bool,
    require_relevant_scope: bool,
) -> tuple[bool, str, dict[str, Any], str | None]:
    """Independently verify citation integrity at the Gate 0 trust boundary for EVERY assessment.

    Never trusts caller-supplied `citation_check`, `citation_provenance`, or `validated_status`:
    - Conclusive verdicts (`SUPPORTED` / `REFUTED`) require non-empty citations with valid source SHA-256
      verified via sealed `inspect_citations_provenance` (including scope, executability, and non-dead-branch).
    - Non-conclusive assessments (`UNDETERMINED`) with non-empty citations undergo the same cryptographic
      provenance verification (without upgrading security status); forged `MATCHED` or invalid citations
      are stripped and downgraded to `NOT_VERIFIED` + `INVALID_CITATION`.
    - Non-conclusive assessments with empty citations never retain forged `MATCHED` or forged provenance.
    """
    empty_prov = _build_citation_provenance_summary(None)
    citations = assessment.get("citations")
    if citations is None:
        citations = []
    if not isinstance(citations, list):
        return False, "NOT_VERIFIED", empty_prov, "citations field must be a list"

    if not citations:
        if require_non_empty:
            return (
                False,
                "NOT_VERIFIED",
                empty_prov,
                "conclusive status requires at least one verified source citation",
            )
        if _has_forged_empty_citation_claims(assessment):
            return (
                False,
                "NOT_VERIFIED",
                empty_prov,
                "claimed verified citation status or provenance without verifiable citations",
            )
        existing_check = assessment.get("citation_check")
        existing_fk = assessment.get("failure_kind")
        if existing_check == "NONE" and existing_fk in (None, "NONE"):
            return True, "NONE", empty_prov, None
        return True, "NOT_VERIFIED", empty_prov, None

    for cite in citations:
        if not _is_valid_citation_dict(cite) or not str(cite.get("sha256") or "").strip():
            return (
                False,
                "NOT_VERIFIED",
                empty_prov,
                "citation is missing required path, line range, quote, or source sha256",
            )

    try:
        prov = inspect_citations_provenance(citations, record)
    except Exception as exc:
        return False, "NOT_VERIFIED", empty_prov, f"citation verification error: {exc}"

    summary = _build_citation_provenance_summary(prov)
    failed_prov = {
        "citation_in_source": False,
        "citation_in_prompt": False,
        "citation_posthoc_only": bool(prov.get("citation_posthoc_only")) if isinstance(prov, dict) else False,
        "supports_security_claim_verified": False,
    }
    items = prov.get("items") if isinstance(prov, dict) else None
    if not items:
        return False, "NOT_VERIFIED", failed_prov, "no verifiable citations matched locked source evidence"
    for item in items:
        if isinstance(item, dict) and item.get("error"):
            return False, "NOT_VERIFIED", failed_prov, str(item["error"])
    if not prov.get("citation_in_source"):
        return False, "NOT_VERIFIED", failed_prov, "citation text or SHA-256 does not match locked source evidence"
    if not prov.get("citation_in_prompt") or prov.get("citation_posthoc_only"):
        return False, "NOT_VERIFIED", failed_prov, "citation line was not supplied in locked model prompt"
    if not prov.get("all_executable_code"):
        return False, "NOT_VERIFIED", failed_prov, "citation must reference executable Java code"
    if prov.get("any_dead_branch"):
        return False, "NOT_VERIFIED", failed_prov, "citation references unreachable dead-branch code"
    if require_relevant_scope and not prov.get("any_in_relevant_scope"):
        return False, "NOT_VERIFIED", failed_prov, "citation lies outside enclosing method and dataflow trace scope"

    return True, "MATCHED", summary, None


_VALID_ASSESSMENT_STATUSES = frozenset({"SUPPORTED", "REFUTED", "UNDETERMINED"})
_CONCLUSIVE_STATUSES = frozenset({"SUPPORTED", "REFUTED"})


def _is_valid_status_transition(src: str, dst: str) -> bool:
    """Monotonic verdict transition lattice: `raw_model_status -> status -> validated_status`.

    Allowed transitions:
    - `SUPPORTED    -> SUPPORTED | UNDETERMINED`
    - `REFUTED      -> REFUTED   | UNDETERMINED`
    - `UNDETERMINED -> UNDETERMINED`
    Forbidden:
    - Any upgrade `UNDETERMINED -> SUPPORTED | REFUTED`
    - Any conclusive flip `SUPPORTED <-> REFUTED`
    """
    return src == dst or dst == "UNDETERMINED"


def _resolve_effective_status(assessment: dict[str, Any]) -> tuple[str, str | None]:
    """Resolve authoritative verdict status over the monotonic chain `raw_model_status -> status -> validated_status`.

    Returns `(effective_status, contradiction_reason)`:
    - Validates domain membership for every non-None status field.
    - Enforces `_is_valid_status_transition` uniformly across `(raw_model_status, status)`,
      `(status, validated_status)`, and `(raw_model_status, validated_status)`.
    - Preserves valid monotone downgrades (`SUPPORTED|REFUTED -> UNDETERMINED`) and technical-error
      records (`raw_model_status=None, status=UNDETERMINED, validated_status=UNDETERMINED`).
    - Rejects missing `status` on conclusive claims, explicit `raw_model_status=None` paired with
      a conclusive verdict, unrecognized values, upgrades from `UNDETERMINED`, and conclusive flips.
    """
    has_raw_model_key = "raw_model_status" in assessment
    raw_model = assessment.get("raw_model_status")
    raw_status = assessment.get("status")
    raw_val = assessment.get("validated_status")

    for label, val in (
        ("raw_model_status", raw_model),
        ("status", raw_status),
        ("validated_status", raw_val),
    ):
        if val is not None and val not in _VALID_ASSESSMENT_STATUSES:
            return "UNDETERMINED", f"unrecognized {label}={val!r}"

    if raw_status is None and raw_val is None:
        return "UNDETERMINED", "missing assessment status"

    if raw_status is None and raw_val in _CONCLUSIVE_STATUSES:
        return "UNDETERMINED", f"missing upstream status for conclusive validated_status={raw_val!r}"

    if has_raw_model_key and raw_model is None and (
        raw_status in _CONCLUSIVE_STATUSES or raw_val in _CONCLUSIVE_STATUSES
    ):
        return (
            "UNDETERMINED",
            f"missing raw_model_status for conclusive status={raw_status!r}/validated_status={raw_val!r}",
        )

    for src_lbl, src_val, dst_lbl, dst_val in (
        ("raw_model_status", raw_model, "status", raw_status),
        ("status", raw_status, "validated_status", raw_val),
        ("raw_model_status", raw_model, "validated_status", raw_val),
    ):
        if src_val is not None and dst_val is not None and not _is_valid_status_transition(src_val, dst_val):
            return (
                "UNDETERMINED",
                f"invalid status transition {src_lbl}={src_val!r} -> {dst_lbl}={dst_val!r}",
            )

    if raw_val == "UNDETERMINED" or raw_status == "UNDETERMINED" or raw_model == "UNDETERMINED":
        return "UNDETERMINED", None

    return str(raw_status), None


def _finalize_gate_output(
    out: dict[str, Any],
    *,
    final_status: str,
    citation_check: str,
    citation_provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    """Single authoritative output normalizer for EVERY return path of `apply_integration_gate`."""
    out["status"] = final_status
    out["validated_status"] = final_status
    out["citation_check"] = citation_check
    out["citation_provenance"] = _build_citation_provenance_summary(citation_provenance)
    out["security_conclusion_verified"] = False
    out["supports_security_claim_verified"] = False
    out["requires_human_review"] = True
    return out


def _downgrade_assessment(
    assessment: dict[str, Any],
    *,
    failure_kind: str,
    reason: str,
    citation_check: str = "NOT_VERIFIED",
    citation_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out = dict(assessment)
    raw_model_status = out.get("raw_model_status") if "raw_model_status" in out else out.get("status")
    out["raw_model_status"] = raw_model_status
    out["validator_downgraded"] = True
    out["failure_kind"] = failure_kind
    out["downgrade_reason"] = reason

    orig_cites = out.get("citations")
    if (
        failure_kind != "INVALID_CITATION"
        and isinstance(orig_cites, list)
        and all(_is_valid_citation_dict(c) for c in orig_cites)
    ):
        out["citations"] = list(orig_cites)
    else:
        if orig_cites is not None:
            out["raw_model_citations"] = orig_cites
        out["citations"] = []

    effective_cite_check = citation_check if failure_kind != "INVALID_CITATION" else "NOT_VERIFIED"
    effective_prov = citation_provenance if isinstance(citation_provenance, dict) else out.get("citation_provenance")
    _finalize_gate_output(
        out,
        final_status="UNDETERMINED",
        citation_check=effective_cite_check,
        citation_provenance=effective_prov if isinstance(effective_prov, dict) else None,
    )

    orig_exp = str(out.get("explanation") or "").strip()
    out["explanation"] = (
        f"{reason} (Model returned {raw_model_status}; Human Review remains OPEN. Prior note: {orig_exp})".strip()
        if orig_exp
        else f"{reason} (Model returned {raw_model_status}; Human Review remains OPEN.)"
    )
    rt = dict(out.get("runtime") or {}) if isinstance(out.get("runtime"), dict) else {}
    rt["answer_validated"] = False
    rt["failure_kind"] = failure_kind
    rt["validator_downgraded"] = True
    out["runtime"] = rt
    out.setdefault("analyzed_at", now())
    return out


def _verified_primary_map(record: dict[str, Any]) -> tuple[str | None, dict[int, str]]:
    snaps = record.get("snapshots") if isinstance(record.get("snapshots"), dict) else {}
    snips = record.get("snippets") or []
    if not snips or not isinstance(snips[0], dict):
        return None, {}
    p_path = snips[0].get("path")
    if not isinstance(p_path, str):
        return None, {}
    snap = snaps.get(p_path)
    if not isinstance(snap, dict) or not isinstance(snap.get("sha256"), str):
        return None, {}
    expected_sha = snap["sha256"]
    lines: dict[int, str] = {}
    for s in snips:
        if isinstance(s, dict) and s.get("path") == p_path and s.get("sha256") == expected_sha:
            for ln in s.get("lines") or []:
                if isinstance(ln, dict) and type(ln.get("line")) is int:
                    lines[ln["line"]] = str(ln.get("text") or "")
    return p_path, lines


def _strip_comments_and_mask_strings(lines_by_no: dict[int, str]) -> tuple[dict[int, str], dict[int, str]]:
    """Strip Java comments and return `(code_keep_strings, code_masked_strings)` with identical per-line lengths."""
    keep_str: dict[int, str] = {}
    masked_str: dict[int, str] = {}
    in_block = False
    for ln_no in sorted(lines_by_no):
        raw = lines_by_no[ln_no]
        ks: list[str] = []
        ms: list[str] = []
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
                    ks.append("  ")
                    ms.append("  ")
                    i += 2
                else:
                    ks.append(" ")
                    ms.append(" ")
                    i += 1
                continue
            if in_s:
                if ch == "\\" and i + 1 < n:
                    ks.append(raw[i : i + 2])
                    ms.append("  ")
                    i += 2
                elif ch == '"':
                    in_s = False
                    ks.append('"')
                    ms.append('"')
                    i += 1
                else:
                    ks.append(ch)
                    ms.append(" ")
                    i += 1
                continue
            if in_c:
                if ch == "\\" and i + 1 < n:
                    ks.append(raw[i : i + 2])
                    ms.append("  ")
                    i += 2
                elif ch == "'":
                    in_c = False
                    ks.append("'")
                    ms.append("'")
                    i += 1
                else:
                    ks.append(ch)
                    ms.append(" ")
                    i += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block = True
                ks.append("  ")
                ms.append("  ")
                i += 2
                continue
            if ch == '"':
                in_s = True
                ks.append('"')
                ms.append('"')
                i += 1
                continue
            if ch == "'":
                in_c = True
                ks.append("'")
                ms.append("'")
                i += 1
                continue
            ks.append(ch)
            ms.append(ch)
            i += 1
        keep_str[ln_no] = "".join(ks)
        masked_str[ln_no] = "".join(ms)
    return keep_str, masked_str


def _is_pure_string_literal(expr: str) -> bool:
    s = expr.strip()
    if len(s) < 2 or not (s.startswith('"') and s.endswith('"')):
        return False
    i = 1
    while i < len(s) - 1:
        if s[i] == "\\":
            if i + 1 >= len(s) - 1:
                return False
            i += 2
            continue
        if s[i] == '"':
            return False
        i += 1
    return True


def _unescape_java_string_literal(lit: str) -> str | None:
    if not _is_pure_string_literal(lit):
        return None
    inner = lit.strip()[1:-1]
    out: list[str] = []
    i = 0
    n = len(inner)
    while i < n:
        ch = inner[i]
        if ch == "\\" and i + 1 < n:
            nxt = inner[i + 1]
            if nxt == "\\":
                out.append("\\")
            elif nxt == '"':
                out.append('"')
            elif nxt == "n":
                out.append("\n")
            elif nxt == "r":
                out.append("\r")
            elif nxt == "t":
                out.append("\t")
            elif nxt == "0":
                out.append("\x00")
            else:
                out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _is_non_root_safe_base_literal(lit: str) -> bool:
    val = _unescape_java_string_literal(lit)
    if val is None or "\x00" in val:
        return False
    norm = val.replace("\\", "/")
    segs = [s for s in norm.split("/") if s]
    if not segs or ".." in segs or "." in segs:
        return False
    # Reject drive-relative paths like "C:safe" or bare Windows drive root like "C:" / "C:/"
    for idx, seg in enumerate(segs):
        if ":" in seg:
            if idx == 0 and len(seg) == 2 and seg[0].isalpha() and seg[1] == ":" and (
                norm.startswith(f"{seg}/")
            ):
                continue
            return False
    non_drive = [s for idx, s in enumerate(segs) if not (idx == 0 and len(s) == 2 and s[0].isalpha() and s[1] == ":")]
    return bool(non_drive)


def _split_top_level(text: str, sep: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    in_s = False
    in_c = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_s:
            cur.append(ch)
            if ch == "\\" and i + 1 < n:
                cur.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_s = False
            i += 1
            continue
        if in_c:
            cur.append(ch)
            if ch == "\\" and i + 1 < n:
                cur.append(text[i + 1])
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
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail or parts:
        parts.append(tail)
    return [p for p in parts if p]


def _has_unmodeled_expr_side_effect(masked_expr: str) -> bool:
    """Return True if an expression contains embedded assignments, inc/dec, lambdas, or braces."""
    if not masked_expr:
        return False
    if "{" in masked_expr or "}" in masked_expr:
        return True
    return bool(_EXPR_SIDE_EFFECT_RE.search(masked_expr))


def _has_unmodeled_call(masked_expr: str) -> bool:
    """Return True if an expression invokes any method/constructor call."""
    if not masked_expr:
        return False
    for m in _ANY_CALL_IN_EXPR_RE.finditer(masked_expr):
        if m.group(1) not in _JAVA_KEYWORDS:
            return True
    return False


# ---------------------------------------------------------------------------
# Structured Java Statement Tokenizer & Recursive-Descent Parser
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Tok:
    kind: str  # WORD | SYM
    text: str
    start: int
    end: int
    line: int


@dataclass
class _StmtNode:
    kind: str
    start_line: int
    end_line: int
    code_k: str = ""
    code_m: str = ""
    cond_k: str = ""
    cond_m: str = ""
    then_stmt: "_StmtNode | None" = None
    else_stmt: "_StmtNode | None" = None
    body_stmts: list["_StmtNode"] | None = None
    body_stmt: "_StmtNode | None" = None
    catches: list["_StmtNode"] | None = None
    finally_stmt: "_StmtNode | None" = None
    resources_k: str = ""
    resources_m: str = ""
    subkind: str = ""


class _JavaBodyParser:
    """Conservative recursive-descent Java statement parser over comment-stripped, string-masked streams."""

    def __init__(self, start_ln: int, end_ln: int, keep_str: dict[int, str], masked_str: dict[int, str]) -> None:
        k_chunks: list[str] = []
        m_chunks: list[str] = []
        line_of_off: list[int] = []
        for ln in range(start_ln, end_ln + 1):
            kt = keep_str.get(ln, "")
            mt = masked_str.get(ln, "")
            if len(kt) != len(mt):
                # Guarantee equal indexing defensively
                min_l = min(len(kt), len(mt))
                kt, mt = kt[:min_l], mt[:min_l]
            k_chunks.append(kt)
            m_chunks.append(mt)
            line_of_off.extend([ln] * len(mt))
            k_chunks.append("\n")
            m_chunks.append("\n")
            line_of_off.append(ln)
        self.keep_stream = "".join(k_chunks)
        self.mask_stream = "".join(m_chunks)
        self.line_of_off = line_of_off
        self.tokens: list[_Tok] = self._tokenize()
        self.pos = 0
        self.parse_errors: list[str] = []

    def _tokenize(self) -> list[_Tok]:
        toks: list[_Tok] = []
        s = self.mask_stream
        n = len(s)
        i = 0
        while i < n:
            ch = s[i]
            if ch.isspace():
                i += 1
                continue
            if ch == '"' or ch == "'":
                quote = ch
                start = i
                i += 1
                while i < n and s[i] != quote:
                    i += 1
                if i < n:
                    i += 1
                else:
                    self.parse_errors.append("unterminated_literal")
                toks.append(_Tok("LIT", s[start:i], start, i, self.line_of_off[start]))
                continue
            if ch.isalpha() or ch == "_":
                start = i
                i += 1
                while i < n and (s[i].isalnum() or s[i] == "_"):
                    i += 1
                toks.append(_Tok("WORD", s[start:i], start, i, self.line_of_off[start]))
                continue
            if ch.isdigit():
                start = i
                i += 1
                while i < n and (s[i].isalnum() or s[i] == "_"):
                    i += 1
                toks.append(_Tok("NUM", s[start:i], start, i, self.line_of_off[start]))
                continue
            if ch == "-" and i + 1 < n and s[i + 1] == ">":
                toks.append(_Tok("SYM", "->", i, i + 2, self.line_of_off[i]))
                i += 2
                continue
            toks.append(_Tok("SYM", ch, i, i + 1, self.line_of_off[i]))
            i += 1
        return toks

    def _peek(self, offset: int = 0) -> _Tok | None:
        idx = self.pos + offset
        if 0 <= idx < len(self.tokens):
            return self.tokens[idx]
        return None

    def _slice_km(self, start_off: int, end_off: int) -> tuple[str, str]:
        k_txt = " ".join(self.keep_stream[start_off:end_off].split())
        m_txt = " ".join(self.mask_stream[start_off:end_off].split())
        return k_txt, m_txt

    def _consume_balanced_parens(self) -> tuple[int, int, int, int] | None:
        """Consume `(...)` returning `(inner_start_off, inner_end_off, open_line, close_line)`."""
        t = self._peek()
        if t is None or t.kind != "SYM" or t.text != "(":
            self.parse_errors.append("expected_lparen")
            return None
        inner_start = t.end
        open_line = t.line
        depth = 0
        while self.pos < len(self.tokens):
            cur = self.tokens[self.pos]
            self.pos += 1
            if cur.kind == "SYM" and cur.text == "(":
                depth += 1
            elif cur.kind == "SYM" and cur.text == ")":
                depth -= 1
                if depth == 0:
                    return inner_start, cur.start, open_line, cur.line
        self.parse_errors.append("unbalanced_parens")
        return None

    def _parse_block(self) -> _StmtNode:
        open_tok = self._peek()
        if open_tok is None or open_tok.kind != "SYM" or open_tok.text != "{":
            self.parse_errors.append("expected_lbrace")
            ln = open_tok.line if open_tok else 1
            return _StmtNode("UNKNOWN", ln, ln, subkind="missing_lbrace")
        self.pos += 1
        stmts: list[_StmtNode] = []
        end_ln = open_tok.line
        while self.pos < len(self.tokens):
            cur = self._peek()
            if cur is None:
                break
            if cur.kind == "SYM" and cur.text == "}":
                end_ln = cur.line
                self.pos += 1
                return _StmtNode("BLOCK", open_tok.line, end_ln, body_stmts=stmts)
            st = self.parse_stmt()
            stmts.append(st)
            end_ln = max(end_ln, st.end_line)
        self.parse_errors.append("unclosed_block")
        return _StmtNode("BLOCK", open_tok.line, end_ln, body_stmts=stmts, subkind="unclosed")

    def parse_method_body(self) -> list[_StmtNode]:
        stmts: list[_StmtNode] = []
        while self.pos < len(self.tokens):
            cur = self._peek()
            if cur is None:
                break
            if cur.kind == "SYM" and cur.text == "}":
                # Closing brace of enclosing method body
                self.pos += 1
                break
            stmts.append(self.parse_stmt())
        return stmts

    def parse_stmt(self) -> _StmtNode:
        tok = self._peek()
        if tok is None:
            return _StmtNode("EMPTY", 1, 1)

        if tok.kind == "SYM" and tok.text == ";":
            self.pos += 1
            return _StmtNode("EMPTY", tok.line, tok.line)

        if tok.kind == "SYM" and tok.text == "{":
            return self._parse_block()

        if tok.kind == "SYM" and tok.text == "}":
            # Unexpected stray `}` inside statement position
            self.parse_errors.append("unexpected_rbrace")
            self.pos += 1
            return _StmtNode("UNKNOWN", tok.line, tok.line, subkind="unexpected_rbrace")

        # Labeled statement `label: stmt` (except `default:` inside switch)
        if tok.kind == "WORD" and tok.text not in ("default", "case"):
            nxt = self._peek(1)
            if nxt is not None and nxt.kind == "SYM" and nxt.text == ":":
                self.pos += 2
                inner = self.parse_stmt()
                return _StmtNode(
                    "LABELED",
                    tok.line,
                    inner.end_line,
                    body_stmt=inner,
                    subkind=tok.text,
                )

        if tok.kind == "WORD" and tok.text == "if":
            self.pos += 1
            cond_span = self._consume_balanced_parens()
            if cond_span is None:
                return _StmtNode("UNKNOWN", tok.line, tok.line, subkind="malformed_if")
            cs, ce, _, cond_end_ln = cond_span
            cond_k, cond_m = self._slice_km(cs, ce)
            then_stmt = self.parse_stmt()
            else_stmt: _StmtNode | None = None
            end_ln = max(cond_end_ln, then_stmt.end_line)
            nxt = self._peek()
            if nxt is not None and nxt.kind == "WORD" and nxt.text == "else":
                self.pos += 1
                else_stmt = self.parse_stmt()
                end_ln = max(end_ln, else_stmt.end_line)
            return _StmtNode(
                "IF",
                tok.line,
                end_ln,
                cond_k=cond_k,
                cond_m=cond_m,
                then_stmt=then_stmt,
                else_stmt=else_stmt,
                subkind=str(cond_end_ln),
            )

        if tok.kind == "WORD" and tok.text in ("for", "while"):
            kind_kw = tok.text
            self.pos += 1
            hdr_span = self._consume_balanced_parens()
            if hdr_span is None:
                return _StmtNode("UNKNOWN", tok.line, tok.line, subkind=f"malformed_{kind_kw}")
            hs, he, _, hdr_end_ln = hdr_span
            hdr_k, hdr_m = self._slice_km(hs, he)
            body = self.parse_stmt()
            return _StmtNode(
                "LOOP",
                tok.line,
                max(hdr_end_ln, body.end_line),
                cond_k=hdr_k,
                cond_m=hdr_m,
                body_stmt=body,
                subkind=kind_kw,
            )

        if tok.kind == "WORD" and tok.text == "do":
            self.pos += 1
            body = self.parse_stmt()
            nxt = self._peek()
            hdr_k, hdr_m = "", ""
            end_ln = body.end_line
            if nxt is not None and nxt.kind == "WORD" and nxt.text == "while":
                self.pos += 1
                hdr_span = self._consume_balanced_parens()
                if hdr_span is None:
                    return _StmtNode("UNKNOWN", tok.line, end_ln, subkind="malformed_do_while")
                hs, he, _, hdr_end_ln = hdr_span
                hdr_k, hdr_m = self._slice_km(hs, he)
                end_ln = max(end_ln, hdr_end_ln)
                semi = self._peek()
                if semi is not None and semi.kind == "SYM" and semi.text == ";":
                    end_ln = max(end_ln, semi.line)
                    self.pos += 1
                else:
                    self.parse_errors.append("missing_do_while_semi")
            else:
                self.parse_errors.append("missing_do_while")
                return _StmtNode("UNKNOWN", tok.line, end_ln, subkind="malformed_do")
            return _StmtNode(
                "LOOP",
                tok.line,
                end_ln,
                cond_k=hdr_k,
                cond_m=hdr_m,
                body_stmt=body,
                subkind="do",
            )

        if tok.kind == "WORD" and tok.text == "try":
            self.pos += 1
            res_k, res_m = "", ""
            nxt = self._peek()
            if nxt is not None and nxt.kind == "SYM" and nxt.text == "(":
                rspan = self._consume_balanced_parens()
                if rspan is None:
                    return _StmtNode("UNKNOWN", tok.line, tok.line, subkind="malformed_try_resources")
                res_k, res_m = self._slice_km(rspan[0], rspan[1])
            try_blk = self._parse_block()
            catches: list[_StmtNode] = []
            finally_blk: _StmtNode | None = None
            end_ln = try_blk.end_line
            while True:
                c_tok = self._peek()
                if c_tok is not None and c_tok.kind == "WORD" and c_tok.text == "catch":
                    self.pos += 1
                    c_span = self._consume_balanced_parens()
                    if c_span is None:
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
            return _StmtNode(
                "TRY",
                tok.line,
                end_ln,
                body_stmt=try_blk,
                catches=catches,
                finally_stmt=finally_blk,
                resources_k=res_k,
                resources_m=res_m,
            )

        if tok.kind == "WORD" and tok.text in ("switch", "synchronized"):
            kw = tok.text
            self.pos += 1
            hspan = self._consume_balanced_parens()
            if hspan is None:
                return _StmtNode("UNKNOWN", tok.line, tok.line, subkind=f"malformed_{kw}")
            hk, hm = self._slice_km(hspan[0], hspan[1])
            blk = self._parse_block()
            return _StmtNode(
                kw.upper(),
                tok.line,
                blk.end_line,
                cond_k=hk,
                cond_m=hm,
                body_stmt=blk,
                subkind=kw,
            )

        if tok.kind == "WORD" and tok.text in ("else", "catch", "finally"):
            # Orphaned keyword without matching header
            self.parse_errors.append(f"orphan_{tok.text}")
            self.pos += 1
            return _StmtNode("UNKNOWN", tok.line, tok.line, subkind=f"orphan_{tok.text}")

        # Simple statement or return/throw up to `;` at balanced paren/bracket/brace depth 0
        start_tok = tok
        start_off = start_tok.start
        paren_d = 0
        bracket_d = 0
        brace_d = 0
        saw_arrow = False
        saw_brace = False
        end_off = start_tok.end
        end_ln = start_tok.line
        terminated_semi = False

        while self.pos < len(self.tokens):
            cur = self.tokens[self.pos]
            if cur.kind == "SYM":
                if cur.text == "(":
                    paren_d += 1
                elif cur.text == ")":
                    if paren_d == 0:
                        self.parse_errors.append("unmatched_rparen_in_stmt")
                        self.pos += 1
                        break
                    paren_d -= 1
                elif cur.text == "[":
                    bracket_d += 1
                elif cur.text == "]":
                    bracket_d = max(0, bracket_d - 1)
                elif cur.text == "{":
                    brace_d += 1
                    saw_brace = True
                elif cur.text == "}":
                    if brace_d == 0 and paren_d == 0 and bracket_d == 0:
                        # Reached enclosing block's closing brace before `;`
                        self.parse_errors.append("missing_semicolon_before_rbrace")
                        break
                    brace_d = max(0, brace_d - 1)
                elif cur.text == "->":
                    saw_arrow = True
                elif cur.text == ";" and paren_d == 0 and bracket_d == 0 and brace_d == 0:
                    end_off = cur.end
                    end_ln = cur.line
                    self.pos += 1
                    terminated_semi = True
                    break
            end_off = cur.end
            end_ln = cur.line
            self.pos += 1

        code_k, code_m = self._slice_km(start_off, end_off)
        if not terminated_semi:
            self.parse_errors.append("unterminated_statement")
            return _StmtNode("UNKNOWN", start_tok.line, end_ln, code_k=code_k, code_m=code_m, subkind="unterminated")
        if start_tok.kind == "WORD" and start_tok.text in ("return", "throw"):
            return _StmtNode(
                "EXIT",
                start_tok.line,
                end_ln,
                code_k=code_k,
                code_m=code_m,
                subkind=start_tok.text,
            )
        if saw_brace or saw_arrow:
            return _StmtNode(
                "UNKNOWN",
                start_tok.line,
                end_ln,
                code_k=code_k,
                code_m=code_m,
                subkind="brace_or_lambda_stmt",
            )
        return _StmtNode("SIMPLE", start_tok.line, end_ln, code_k=code_k, code_m=code_m)


def _method_body_start_pos(
    masked_str: dict[int, str],
    header_line: int,
    sink_line: int,
) -> tuple[int, int] | None:
    """Locate `(line_no, col_after_open_brace)` for the enclosing method header's opening `{`."""
    paren_depth = 0
    seen_open_paren = False
    for ln in range(header_line, sink_line + 1):
        txt = masked_str.get(ln, "")
        for idx, ch in enumerate(txt):
            if ch == "(":
                paren_depth += 1
                seen_open_paren = True
            elif ch == ")" and paren_depth > 0:
                paren_depth -= 1
            elif ch == "{" and seen_open_paren and paren_depth == 0:
                if txt[idx + 1 :].strip():
                    return (ln, idx + 1)
                return (ln + 1, 0)
    return None


def _clean_sink_statement(raw_stmt: str) -> str:
    s = raw_stmt.strip()
    if s.startswith("try") and "(" in s:
        s = s[s.find("(") + 1 :].strip()
    s = re.sub(r";\s*\)\s*\{\s*$", ";", s)
    s = re.sub(r"\{\s*$", "", s).strip()
    parts = _split_top_level(s, ";")
    return parts[-1] if parts else s


_SAFE_STDLIB_SUPERCLASS_FQNS = frozenset(
    {
        "java.lang.Object",
        "javax.servlet.http.HttpServlet",
        "jakarta.servlet.http.HttpServlet",
        "javax.servlet.GenericServlet",
        "jakarta.servlet.GenericServlet",
    }
)


def _extract_method_param_names(
    record: dict[str, Any],
    lines_by_no: dict[int, str],
    header_line: int,
    body_start_line: int,
) -> set[str]:
    """Collect formal parameter identifier names of the enclosing method from both `java_context` and raw header lines."""
    names: set[str] = set()
    jctx = record.get("java_context") if isinstance(record.get("java_context"), dict) else {}
    enc = jctx.get("enclosing_method") if isinstance(jctx.get("enclosing_method"), dict) else None
    if isinstance(enc, dict) and isinstance(enc.get("parameters"), list):
        p_types, _, _ = _extract_param_types_and_count(enc["parameters"])
        names.update(p_types.keys())
    hdr_lines = [lines_by_no[ln] for ln in range(header_line, max(header_line, body_start_line) + 1) if ln in lines_by_no]
    if hdr_lines:
        joined = "\n".join(hdr_lines)
        open_p = joined.find("(")
        if open_p != -1:
            close_p = _find_matching_paren(joined, open_p)
            if close_p is not None:
                params_list = _split_top_level_commas(joined[open_p + 1 : close_p])
                p_types2, _, _ = _extract_param_types_and_count(params_list)
                names.update(p_types2.keys())
    return names


def _collect_local_decl_names_in_ast(stmts: list[_StmtNode] | None) -> set[str]:
    """Collect every local variable / loop variable / catch / try-with-resources identifier declared in the method AST.

    Crucially includes identifiers that share names with stdlib classes (e.g. `Holder File = new Holder();`
    or `JRoot java = ...;`), which are valid Java variable names that shadow ExpressionNames per JLS §6.5.2!
    """
    names: set[str] = set()

    def _collect_from_decl_str(decl_str: str) -> None:
        s = decl_str.strip()
        if not s:
            return
        m_a = _LOCAL_ASSIGN_RE.match(s if s.endswith(";") else s + ";")
        if m_a and m_a.group(1) and m_a.group(1).strip() not in _JAVA_NON_TYPE_KEYWORDS:
            vname = m_a.group(2)
            if vname not in _JAVA_NON_TYPE_KEYWORDS:
                names.add(vname)
            return
        m_d = _DECL_ONLY_RE.match(s if s.endswith(";") else s + ";")
        if m_d and m_d.group(1).strip() not in _JAVA_NON_TYPE_KEYWORDS:
            vname = m_d.group(2)
            if vname not in _JAVA_NON_TYPE_KEYWORDS:
                names.add(vname)
            return
        # Multi-variable declaration (`Holder a = ..., File = ...;`)
        m_multi = re.match(
            r"^\s*(?:final\s+)?([A-Za-z_][A-Za-z0-9_<>,.\[\]]*(?:\s*\[\s*\])*)\s+(.+?)\s*;?\s*$",
            s,
        )
        if m_multi and m_multi.group(1).strip() not in _JAVA_NON_TYPE_KEYWORDS:
            for part in _split_top_level(m_multi.group(2), ","):
                lhs = part.split("=", 1)[0].strip()
                lhs = re.sub(r"\s*\[\s*\]\s*", "", lhs).strip()
                if _SIMPLE_IDENT_RE.fullmatch(lhs) and lhs not in _JAVA_NON_TYPE_KEYWORDS:
                    names.add(lhs)

    def _walk(node: _StmtNode | None) -> None:
        if node is None:
            return
        if node.kind == "SIMPLE":
            _collect_from_decl_str(node.code_m)
        elif node.kind == "LOOP":
            if node.subkind == "for" and node.cond_m:
                parts = _split_top_level(node.cond_m, ";")
                if len(parts) == 3:
                    _collect_from_decl_str(parts[0])
                else:
                    m_fe = re.match(
                        r"^\s*(?:final\s+)?[A-Za-z_][A-Za-z0-9_<>,.\[\]]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*:",
                        node.cond_m,
                    )
                    if m_fe and m_fe.group(1) not in _JAVA_NON_TYPE_KEYWORDS:
                        names.add(m_fe.group(1))
        elif node.kind == "TRY":
            if node.resources_m:
                for r_part in _split_top_level(node.resources_m, ";"):
                    _collect_from_decl_str(r_part)
        for attr in ("then_stmt", "else_stmt", "body_stmt", "finally_stmt"):
            _walk(getattr(node, attr))
        for attr in ("body_stmts", "catches"):
            for ch in getattr(node, attr) or []:
                _walk(ch)

    for st in stmts or []:
        _walk(st)
    return names


def _enclosing_class_has_unverified_superclass(
    caller_unit: dict[str, Any] | None,
    project_pkg_classes: dict[str | None, set[str]] | None,
    all_units: list[dict[str, Any]] | None,
    enclosing_class: str | None,
) -> bool:
    """Return True if the enclosing class extends a superclass that is not a proven safe stdlib superclass."""
    if not isinstance(caller_unit, dict):
        return False
    ext = caller_unit.get("enclosing_class_extends")
    if not ext and enclosing_class and isinstance(caller_unit.get("classes"), dict):
        cinfo = caller_unit["classes"].get(enclosing_class)
        if isinstance(cinfo, dict):
            ext = cinfo.get("extends")
    if not isinstance(ext, str) or not ext.strip():
        return False
    base_raw = re.sub(r"<.*>", "", ext).strip()
    if not base_raw:
        return False
    fqn = resolve_stdlib_class_fqn(
        base_raw,
        caller_unit=caller_unit,
        project_pkg_classes=project_pkg_classes,
        all_units=all_units,
    )
    return fqn not in _SAFE_STDLIB_SUPERCLASS_FQNS


def _separator_token_kind(
    expr: str,
    *,
    caller_unit: dict[str, Any] | None = None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
    shadowed_expr_names: set[str] | frozenset[str] = frozenset(),
    has_unverified_superclass: bool = False,
) -> str | None:
    """Classify a standalone Java directory separator token (`platform`, `/`, or `\\`).

    Enforces JLS §6.5.2 (ExpressionName precedence over TypeName) AND JLS §6.5.5.1 (TypeName resolution):
    - `File.separator` / `File.separatorChar` is accepted ONLY when no parameter, local variable, or field
      named `File` is in scope, no unverified superclass can contribute a field/nested class `File`, AND
      `File` resolves unambiguously to `java.io.File`.
    - `java.io.File.separator` / `java.io.File.separatorChar` is accepted ONLY when no parameter, local
      variable, or field named `java` is in scope and no unverified superclass can shadow `java`.
    """
    e = expr.strip()
    if e in ("File.separator", "File.separatorChar"):
        if "File" in shadowed_expr_names or has_unverified_superclass:
            return None
        resolved = resolve_stdlib_class_fqn(
            "File",
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
        )
        if resolved != "java.io.File":
            return None
        return "platform"
    if e in ("java.io.File.separator", "java.io.File.separatorChar"):
        if "java" in shadowed_expr_names or has_unverified_superclass:
            return None
        resolved = resolve_stdlib_class_fqn(
            "java.io.File",
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
        )
        if resolved != "java.io.File":
            return None
        return "platform"
    if e == "'/'":
        return "/"
    if e == "'\\\\'":
        return "\\"
    val = _unescape_java_string_literal(e)
    if val == "/":
        return "/"
    if val == "\\":
        return "\\"
    return None


def _is_separator_token(expr: str) -> bool:
    return _separator_token_kind(expr) is not None


def _canonical_prefix_is_constant_safe(
    prefix_expr: str,
    canon_safe_base_str_vars: dict[str, bool],
    raw_const_path_vars: dict[str, bool],
    *,
    caller_unit: dict[str, Any] | None = None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
    shadowed_expr_names: set[str] | frozenset[str] = frozenset(),
    has_unverified_superclass: bool = False,
) -> bool:
    """Verify `String.startsWith(prefix)` enforces a true directory separator boundary IMMEDIATELY after a canonical non-root base
    and terminates with a consistent directory separator.

    Rejects:
    - Bare root literals (`"/"`, `"\\\\"`)
    - Uncanonicalized lexical string literals (`"/srv/safe/"`) that cannot account for symlinks
    - Sibling-directory prefixes lacking a separator immediately after `baseCanon` (e.g. `baseCanon + "archive/"`,
      `baseCanon + "archive" + File.separator`, `baseCanon + "" + "archive/"`)
    - Prefixes missing a trailing directory separator (`baseCanon + "/sub"`, `baseCanon`, `baseCanon + File.separator + "sub"`)
    - Mixed separator styles (e.g. `baseCanon + File.separator + "archive/"` or `baseCanon + "/archive\\\\"`)
    - Shadowed or unverified `File.separator` / `java.io.File.separator` tokens (param/local/field/static-import/class shadowing)
    - Any `".."`, `"."`, `":"`, empty path segment (`"//"`), or null byte
    """
    p = prefix_expr.strip()
    if not p:
        return False
    # Never accept a raw uncanonicalized string literal as a canonical containment boundary
    if _is_pure_string_literal(p):
        return False
    parts = _split_top_level(p, "+")
    if len(parts) < 2:
        return False

    # First part MUST be a proven canonical safe non-root base string
    first = parts[0].strip()
    first_ok = False
    if _SIMPLE_IDENT_RE.fullmatch(first) and canon_safe_base_str_vars.get(first, False):
        first_ok = True
    else:
        m_can = _CANON_PATH_STR_RHS_RE.match(first)
        if m_can and raw_const_path_vars.get(m_can.group(1), False):
            first_ok = True
        else:
            m_inl = _INLINE_CONST_CANON_STR_RE.match(first)
            if m_inl and _is_non_root_safe_base_literal(m_inl.group(1)):
                file_type_raw = "java.io.File" if "java.io.File" in first else "File"
                if (
                    resolve_stdlib_class_fqn(
                        file_type_raw,
                        caller_unit=caller_unit,
                        project_pkg_classes=project_pkg_classes,
                        all_units=all_units,
                    )
                    == "java.io.File"
                ):
                    first_ok = True
    if not first_ok:
        return False

    # Normalize every tail concatenation part into `(is_sep_token, sep_kind_or_none, text_value)`
    # using a synthetic uniform placeholder `/` to verify exact boundary positions and segment cleanliness.
    sep_kinds: set[str] = set()
    unified_chunks: list[str] = []
    for tp in parts[1:]:
        t = tp.strip()
        tok_kind = _separator_token_kind(
            t,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            shadowed_expr_names=shadowed_expr_names,
            has_unverified_superclass=has_unverified_superclass,
        )
        if tok_kind is not None:
            sep_kinds.add(tok_kind)
            unified_chunks.append("/")
            continue
        val = _unescape_java_string_literal(t)
        if val is None or "\x00" in val or ":" in val:
            return False
        if val == "":
            # Empty literal contributes no characters; must not satisfy the immediate-separator requirement!
            continue
        if "/" in val:
            sep_kinds.add("/")
        if "\\" in val:
            sep_kinds.add("\\")
        unified_chunks.append(val.replace("\\", "/"))

    if not unified_chunks:
        return False
    # Require a single consistent separator convention across the prefix (reject mixed File.separator + `/` or `/` + `\`)
    if len(sep_kinds) != 1:
        return False

    joined_tail = "".join(unified_chunks)
    # INVARIANT 1: Directory separator MUST appear IMMEDIATELY after `baseCanon` (blocks `baseCanon + "archive/"`)!
    if not joined_tail.startswith("/"):
        return False
    # INVARIANT 2: Prefix MUST terminate with a directory separator (blocks `baseCanon + "/sub"` sibling prefix)!
    if not joined_tail.endswith("/"):
        return False
    # Reject empty segments (`"//"` / consecutive separators) and any `".."` or `"."` segment
    if "//" in joined_tail:
        return False
    inner = joined_tail[1:-1]
    if inner:
        for seg in inner.split("/"):
            if not seg or seg in (".", ".."):
                return False
    return True


def _eval_constant_expr(expr: str, const_vars: dict[str, bool], *, is_cwe22: bool) -> bool:
    """Return True ONLY when `expr` is provably composed solely of literals and `const_vars`."""
    e = expr.strip()
    if not e:
        return False
    if _NUM_OR_BOOL_LITERAL_RE.fullmatch(e) or _is_pure_string_literal(e):
        if is_cwe22 and _is_pure_string_literal(e):
            val = _unescape_java_string_literal(e)
            if val is None or ".." in val.replace("\\", "/").split("/") or "\x00" in val:
                return False
        return True
    parts = _split_top_level(e, "+")
    if len(parts) > 1:
        return all(_eval_constant_expr(p, const_vars, is_cwe22=is_cwe22) for p in parts)
    if _SIMPLE_IDENT_RE.fullmatch(e) and e not in _JAVA_KEYWORDS:
        return bool(const_vars.get(e, False))
    m_new_f = _NEW_FILE_ARGS_RE.match(e)
    if m_new_f:
        args = _split_top_level(m_new_f.group(1), ",")
        return bool(args) and all(_eval_constant_expr(a, const_vars, is_cwe22=is_cwe22) for a in args)
    m_pg = _PATHS_GET_ARGS_RE.match(e)
    if m_pg:
        args = _split_top_level(m_pg.group(1), ",")
        return bool(args) and all(_eval_constant_expr(a, const_vars, is_cwe22=is_cwe22) for a in args)
    return False


def _eval_scalar_safe_sql_expr(
    expr: str,
    const_vars: dict[str, bool],
    scalar_vars: dict[str, bool],
) -> bool:
    """Return True only when a SQL query expression concatenates literals/constants with parsed scalar vars."""
    e = expr.strip()
    if not e:
        return False
    if _eval_constant_expr(e, const_vars, is_cwe22=False):
        return True
    parts = _split_top_level(e, "+")
    if len(parts) <= 1:
        return _SIMPLE_IDENT_RE.fullmatch(e) is not None and bool(scalar_vars.get(e, False))
    saw_scalar = False
    for p in parts:
        pt = p.strip()
        if _eval_constant_expr(pt, const_vars, is_cwe22=False):
            continue
        if _SIMPLE_IDENT_RE.fullmatch(pt) and scalar_vars.get(pt, False):
            saw_scalar = True
            continue
        return False
    return saw_scalar


def _extract_sink_args(rhs_k: str, rhs_m: str, primary_cwe: str) -> list[str]:
    clean_k = rhs_k.strip()
    m_asgn = _LOCAL_ASSIGN_RE.match(clean_k if clean_k.endswith(";") else clean_k + ";")
    if m_asgn and (not m_asgn.group(1) or m_asgn.group(1).strip() not in _JAVA_NON_TYPE_KEYWORDS):
        clean_k = m_asgn.group(4).strip()
    if clean_k.startswith("return "):
        clean_k = clean_k[7:].strip()
    clean_k = clean_k.rstrip(";").strip()

    m_new = re.search(r"\bnew\s+[A-Za-z_][A-Za-z0-9_.]*\s*\((.+)\)(?:\s*\.\s*getFD\s*\(\s*\))?$", clean_k)
    if m_new:
        return _split_top_level(m_new.group(1), ",")
    m_mc = re.search(r"\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$", clean_k)
    if m_mc:
        mname = m_mc.group(1)
        args = _split_top_level(m_mc.group(2), ",")
        if primary_cwe == "CWE-89" and mname in (
            "execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
            "prepareStatement", "prepareCall", "query", "queryForMap",
            "queryForObject", "queryForList", "queryForRowSet", "update", "batchUpdate", "addBatch",
        ) and args:
            return [args[0]]
        return args
    return []


def _extract_cwe22_sink_target_var(arg_expr: str) -> str | None:
    """Extract the exact variable passed to a CWE-22 sink without re-invoking filesystem resolution.

    Only pure variable identity or non-resolving 1-arg wrappers (`Paths.get(v)`, `Path.of(v)`,
    `new File(v)`, `v.toPath()`, `v.toFile()`, `v.getPath()`, `v.toString()`) are accepted.
    Re-calling `getCanonicalPath()` / `toRealPath()` at the sink returns None (TOCTOU/unverified).
    """
    e = arg_expr.strip()
    if _SIMPLE_IDENT_RE.fullmatch(e) and e not in _JAVA_KEYWORDS:
        return e
    m_conv = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:toPath|toFile|getPath|toString)\s*\(\s*\)", e)
    if m_conv:
        return m_conv.group(1)
    m_wrap = re.fullmatch(r"(?:java\.nio\.file\.)?(?:Paths\.get|Path\.of)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", e)
    if m_wrap:
        return m_wrap.group(1)
    m_newf = re.fullmatch(r"new\s+(?:java\.io\.)?File\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", e)
    if m_newf:
        return m_newf.group(1)
    return None


def _merge_bool_dicts_intersection(*dicts: dict[str, bool]) -> dict[str, bool]:
    keys = set().union(*(d.keys() for d in dicts)) if dicts else set()
    return {k: all(d.get(k, False) for d in dicts) for k in keys}


def _merge_map_intersection(*dicts: dict[str, Any]) -> dict[str, Any]:
    if not dicts:
        return {}
    out: dict[str, Any] = {}
    for k in dicts[0]:
        val = dicts[0][k]
        if all(k in d and d[k] == val for d in dicts[1:]):
            out[k] = val
    return out


class _IndependentFlowState:
    """Strictly conservative flow state: unknown statements or side effects invalidate all prior safety facts."""

    def __init__(self, primary_cwe: str) -> None:
        self.primary_cwe = primary_cwe
        self.is_cwe22 = primary_cwe == "CWE-22"
        self.declared_locals: set[str] = set()
        self.const_vars: dict[str, bool] = {}
        self.scalar_vars: dict[str, bool] = {}
        self.raw_const_path_vars: dict[str, bool] = {}
        self.canon_safe_base_str_vars: dict[str, bool] = {}
        self.canon_safe_base_path_vars: dict[str, bool] = {}
        self.canon_target_str_vars: dict[str, bool] = {}
        self.canon_target_file_vars: dict[str, bool] = {}
        self.canon_target_path_vars: dict[str, bool] = {}
        self.guarded_vars: dict[str, tuple[int, int]] = {}  # canonical_var -> (guard_line, def_line)
        self.const_assign_lines: dict[str, list[int]] = {}
        self.scalar_assign_lines: dict[str, list[int]] = {}
        self.prepared_stmt_safe: dict[str, list[int]] = {}
        self.sink_reached = False
        self.aborted = False
        self.abort_reason: str | None = None

    def facts_key(self) -> tuple[Any, ...]:
        """Hashable lattice key for monotone loop fixed-point convergence checks."""
        return (
            self.aborted,
            tuple(sorted(self.declared_locals)),
            tuple(sorted(k for k, v in self.const_vars.items() if v)),
            tuple(sorted(k for k, v in self.scalar_vars.items() if v)),
            tuple(sorted(k for k, v in self.raw_const_path_vars.items() if v)),
            tuple(sorted(k for k, v in self.canon_safe_base_str_vars.items() if v)),
            tuple(sorted(k for k, v in self.canon_safe_base_path_vars.items() if v)),
            tuple(sorted(k for k, v in self.canon_target_str_vars.items() if v)),
            tuple(sorted(k for k, v in self.canon_target_file_vars.items() if v)),
            tuple(sorted(k for k, v in self.canon_target_path_vars.items() if v)),
            tuple(sorted(self.guarded_vars.items())),
            tuple(sorted(self.prepared_stmt_safe.keys())),
        )

    def invalidate_var(self, vname: str) -> None:
        self.const_vars[vname] = False
        self.scalar_vars[vname] = False
        self.raw_const_path_vars[vname] = False
        self.canon_safe_base_str_vars[vname] = False
        self.canon_safe_base_path_vars[vname] = False
        self.canon_target_str_vars[vname] = False
        self.canon_target_file_vars[vname] = False
        self.canon_target_path_vars[vname] = False
        self.guarded_vars.pop(vname, None)
        self.const_assign_lines.pop(vname, None)
        self.scalar_assign_lines.pop(vname, None)
        self.prepared_stmt_safe.pop(vname, None)

    def invalidate_all(self, reason: str) -> None:
        """Drop every prior safety assumption whenever an unknown statement or side effect is encountered."""
        self.const_vars.clear()
        self.scalar_vars.clear()
        self.raw_const_path_vars.clear()
        self.canon_safe_base_str_vars.clear()
        self.canon_safe_base_path_vars.clear()
        self.canon_target_str_vars.clear()
        self.canon_target_file_vars.clear()
        self.canon_target_path_vars.clear()
        self.guarded_vars.clear()
        self.const_assign_lines.clear()
        self.scalar_assign_lines.clear()
        self.prepared_stmt_safe.clear()
        if self.abort_reason is None:
            self.abort_reason = reason

    def clone(self) -> "_IndependentFlowState":
        st = _IndependentFlowState(self.primary_cwe)
        st.declared_locals = set(self.declared_locals)
        st.const_vars = dict(self.const_vars)
        st.scalar_vars = dict(self.scalar_vars)
        st.raw_const_path_vars = dict(self.raw_const_path_vars)
        st.canon_safe_base_str_vars = dict(self.canon_safe_base_str_vars)
        st.canon_safe_base_path_vars = dict(self.canon_safe_base_path_vars)
        st.canon_target_str_vars = dict(self.canon_target_str_vars)
        st.canon_target_file_vars = dict(self.canon_target_file_vars)
        st.canon_target_path_vars = dict(self.canon_target_path_vars)
        st.guarded_vars = dict(self.guarded_vars)
        st.const_assign_lines = {k: list(v) for k, v in self.const_assign_lines.items()}
        st.scalar_assign_lines = {k: list(v) for k, v in self.scalar_assign_lines.items()}
        st.prepared_stmt_safe = {k: list(v) for k, v in self.prepared_stmt_safe.items()}
        st.sink_reached = self.sink_reached
        st.aborted = self.aborted
        st.abort_reason = self.abort_reason
        return st

    def adopt_from(self, other: "_IndependentFlowState") -> None:
        self.declared_locals = other.declared_locals
        self.const_vars = other.const_vars
        self.scalar_vars = other.scalar_vars
        self.raw_const_path_vars = other.raw_const_path_vars
        self.canon_safe_base_str_vars = other.canon_safe_base_str_vars
        self.canon_safe_base_path_vars = other.canon_safe_base_path_vars
        self.canon_target_str_vars = other.canon_target_str_vars
        self.canon_target_file_vars = other.canon_target_file_vars
        self.canon_target_path_vars = other.canon_target_path_vars
        self.guarded_vars = other.guarded_vars
        self.const_assign_lines = other.const_assign_lines
        self.scalar_assign_lines = other.scalar_assign_lines
        self.prepared_stmt_safe = other.prepared_stmt_safe
        self.sink_reached = other.sink_reached
        self.aborted = other.aborted
        self.abort_reason = other.abort_reason

    def merge_from(self, *branches: "_IndependentFlowState") -> None:
        if any(b.aborted for b in branches):
            self.aborted = True
            self.abort_reason = next((b.abort_reason for b in branches if b.aborted and b.abort_reason), "branch_aborted")
            self.invalidate_all(self.abort_reason)
            return
        self.declared_locals = set.intersection(*(b.declared_locals for b in branches)) if branches else set()
        self.const_vars = _merge_bool_dicts_intersection(*(b.const_vars for b in branches))
        self.scalar_vars = _merge_bool_dicts_intersection(*(b.scalar_vars for b in branches))
        self.raw_const_path_vars = _merge_bool_dicts_intersection(*(b.raw_const_path_vars for b in branches))
        self.canon_safe_base_str_vars = _merge_bool_dicts_intersection(*(b.canon_safe_base_str_vars for b in branches))
        self.canon_safe_base_path_vars = _merge_bool_dicts_intersection(*(b.canon_safe_base_path_vars for b in branches))
        self.canon_target_str_vars = _merge_bool_dicts_intersection(*(b.canon_target_str_vars for b in branches))
        self.canon_target_file_vars = _merge_bool_dicts_intersection(*(b.canon_target_file_vars for b in branches))
        self.canon_target_path_vars = _merge_bool_dicts_intersection(*(b.canon_target_path_vars for b in branches))
        self.guarded_vars = _merge_map_intersection(*(b.guarded_vars for b in branches))
        merged_prep: dict[str, list[int]] = {}
        if branches:
            for k in set.intersection(*(set(b.prepared_stmt_safe.keys()) for b in branches)):
                merged_prep[k] = sorted({ln for b in branches for ln in b.prepared_stmt_safe[k]})
        self.prepared_stmt_safe = merged_prep
        for k, is_const in list(self.const_vars.items()):
            if is_const:
                self.const_assign_lines[k] = sorted({ln for b in branches for ln in b.const_assign_lines.get(k, [])})
            else:
                self.const_assign_lines.pop(k, None)
        for k, is_sc in list(self.scalar_vars.items()):
            if is_sc:
                self.scalar_assign_lines[k] = sorted({ln for b in branches for ln in b.scalar_assign_lines.get(k, [])})
            else:
                self.scalar_assign_lines.pop(k, None)


def _stmt_unconditionally_exits(node: _StmtNode | None) -> bool:
    """Return True ONLY when `node` unconditionally terminates via simple `throw`/`return` with no branching."""
    if node is None:
        return False
    if node.kind == "EXIT":
        return node.subkind in ("throw", "return")
    if node.kind == "BLOCK" and node.body_stmts:
        saw_exit = False
        for child in node.body_stmts:
            if child.kind == "EMPTY":
                continue
            if child.kind == "EXIT":
                saw_exit = True
                break
            if child.kind in ("IF", "LOOP", "TRY", "SWITCH", "SYNCHRONIZED", "LABELED", "UNKNOWN"):
                return False
        return saw_exit
    return False


def _stmt_contains_line(node: _StmtNode | None, line_no: int | None) -> bool:
    return node is not None and line_no is not None and node.start_line <= line_no <= node.end_line


def _extract_guarded_canonical_var(
    cond_expr_k: str,
    state: _IndependentFlowState,
    *,
    negated: bool,
    caller_unit: dict[str, Any] | None = None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
    shadowed_expr_names: set[str] | frozenset[str] = frozenset(),
    has_unverified_superclass: bool = False,
) -> str | None:
    """Return ONLY the checked canonical variable name (never the raw pre-canonical File/Path)."""
    pat = _NEG_STARTSWITH_COND_RE if negated else _POS_STARTSWITH_COND_RE
    m = pat.match(cond_expr_k.strip())
    if not m:
        return None
    lhs = m.group(1).strip()
    rhs = m.group(2).strip()
    pref_kw = {
        "caller_unit": caller_unit,
        "project_pkg_classes": project_pkg_classes,
        "all_units": all_units,
        "shadowed_expr_names": shadowed_expr_names,
        "has_unverified_superclass": has_unverified_superclass,
    }

    # Case 1: `canonFile.getPath().startsWith(canonBase + File.separator)`
    m_gp = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*getPath\s*\(\s*\)", lhs)
    if m_gp:
        fvar = m_gp.group(1)
        if state.canon_target_file_vars.get(fvar, False) and _canonical_prefix_is_constant_safe(
            rhs, state.canon_safe_base_str_vars, state.raw_const_path_vars, **pref_kw
        ):
            return fvar
        return None

    if not _SIMPLE_IDENT_RE.fullmatch(lhs):
        return None

    # Case 2: `targetCanon.startsWith(baseCanon + File.separator)` (String canonical path)
    if state.canon_target_str_vars.get(lhs, False):
        if _canonical_prefix_is_constant_safe(
            rhs, state.canon_safe_base_str_vars, state.raw_const_path_vars, **pref_kw
        ):
            return lhs
        return None

    # Case 3: `targetReal.startsWith(baseReal)` (java.nio.file.Path.startsWith(Path) component boundary!)
    if state.canon_target_path_vars.get(lhs, False):
        rhs_clean = rhs.strip()
        if _SIMPLE_IDENT_RE.fullmatch(rhs_clean) and state.canon_safe_base_path_vars.get(rhs_clean, False):
            return lhs
        m_inl_real = _INLINE_CONST_REAL_PATH_RE.match(rhs_clean)
        if m_inl_real and _is_non_root_safe_base_literal(m_inl_real.group(1)):
            if _nio_paths_expr_verified(rhs_clean, **pref_kw):
                return lhs
        return None

    return None


def _nio_paths_expr_verified(
    expr: str,
    *,
    caller_unit: dict[str, Any] | None = None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
    shadowed_expr_names: set[str] | frozenset[str] = frozenset(),
    has_unverified_superclass: bool = False,
) -> bool:
    """Verify `Paths.get(...)` / `Path.of(...)` (or FQN) binds to `java.nio.file.Paths`/`Path` without shadowing."""
    s = expr.strip()
    if s.startswith("java.nio.file."):
        if "java" in shadowed_expr_names or has_unverified_superclass:
            return False
        target = "java.nio.file.Paths" if s.startswith("java.nio.file.Paths") else "java.nio.file.Path"
        return (
            resolve_stdlib_class_fqn(
                target,
                caller_unit=caller_unit,
                project_pkg_classes=project_pkg_classes,
                all_units=all_units,
            )
            == target
        )
    qual = "Paths" if s.startswith("Paths") else ("Path" if s.startswith("Path") else "")
    if not qual or qual in shadowed_expr_names or has_unverified_superclass:
        return False
    expected = f"java.nio.file.{qual}"
    return (
        resolve_stdlib_class_fqn(
            qual,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
        )
        == expected
    )


def _exec_simple_stmt(
    node: _StmtNode,
    state: _IndependentFlowState,
    *,
    at_top_unconditional: bool,
    caller_unit: dict[str, Any] | None = None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
    shadowed_expr_names: set[str] | frozenset[str] = frozenset(),
    has_unverified_superclass: bool = False,
) -> None:
    sk = node.code_k.strip()
    sm = node.code_m.strip()
    s_ln = node.start_line

    # 1. PreparedStatement parameter binding (`ps.setString(1, raw);`)
    m_bind = _PREPARED_STMT_BIND_RE.match(sm)
    if m_bind:
        ps_var = m_bind.group(1)
        args_m = m_bind.group(2)
        if ps_var in state.prepared_stmt_safe and not _has_unmodeled_expr_side_effect(args_m):
            return
        state.invalidate_all("unmodeled_bind_or_side_effect")
        return

    # 2. Variable declaration without initializer (`String q;`)
    m_decl = _DECL_ONLY_RE.match(sm)
    if m_decl:
        decl_t = m_decl.group(1).strip()
        vname = m_decl.group(2)
        if decl_t not in _JAVA_NON_TYPE_KEYWORDS and vname not in _JAVA_KEYWORDS:
            state.declared_locals.add(vname)
            state.invalidate_var(vname)
            return
        state.invalidate_all("unmodeled_declaration")
        return

    # 3. Simple local variable assignment (`[Type] v = rhs;` or `v += rhs;`)
    m_asgn = _LOCAL_ASSIGN_RE.match(sk)
    m_asgn_m = _LOCAL_ASSIGN_RE.match(sm)
    if m_asgn and m_asgn_m:
        decl_type = (m_asgn.group(1) or "").strip()
        vname = m_asgn.group(2)
        op_sym = m_asgn.group(3)
        rhs_k = m_asgn.group(4).strip()
        rhs_m = m_asgn_m.group(4).strip()

        if decl_type and decl_type in _JAVA_NON_TYPE_KEYWORDS:
            state.invalidate_all("keyword_misread_as_type")
            return
        if vname in _JAVA_KEYWORDS:
            state.invalidate_all("keyword_as_lvalue")
            return
        # Multi-variable declaration (`String a = "x", b = u;`) or embedded side effects (`=`, `++`, `--`, `->`)
        if len(_split_top_level(rhs_m, ",")) > 1 or _has_unmodeled_expr_side_effect(rhs_m):
            state.invalidate_all("unmodeled_rhs_or_multi_decl")
            return

        if decl_type:
            state.declared_locals.add(vname)
        is_declared_local = vname in state.declared_locals

        prev_const = state.const_vars.get(vname, False)
        prev_guarded_from: tuple[int, int] | None = None
        if op_sym == "=" and is_declared_local:
            wrapped_var = _extract_cwe22_sink_target_var(rhs_k)
            if wrapped_var and wrapped_var in state.guarded_vars:
                prev_guarded_from = state.guarded_vars[wrapped_var]

        state.invalidate_var(vname)
        # Never certify safety properties on undeclared identifiers (which may be shared class fields
        # mutated by helper methods or concurrent servlet requests!).
        if not is_declared_local:
            return

        if op_sym == "=":
            # Propagate canonical containment ONLY across pure 1-arg wrappers of an already-guarded canonical variable
            if prev_guarded_from is not None:
                state.guarded_vars[vname] = prev_guarded_from

            # Track constant non-root base File/Path declarations (`new File("/srv/safe")`, `Paths.get("/srv/safe")`)
            m_nf = _NEW_CONST_FILE_RE.match(rhs_k)
            if m_nf and _is_non_root_safe_base_literal(m_nf.group(1)):
                file_type_raw = "java.io.File" if "java.io.File" in rhs_k else "File"
                if (
                    resolve_stdlib_class_fqn(
                        file_type_raw,
                        caller_unit=caller_unit,
                        project_pkg_classes=project_pkg_classes,
                        all_units=all_units,
                    )
                    == "java.io.File"
                ):
                    state.raw_const_path_vars[vname] = True
            else:
                m_pg = _PATHS_GET_ARGS_RE.match(rhs_k)
                if m_pg:
                    pg_args = _split_top_level(m_pg.group(1), ",")
                    if (
                        len(pg_args) == 1
                        and _is_non_root_safe_base_literal(pg_args[0])
                        and _nio_paths_expr_verified(
                            rhs_k,
                            caller_unit=caller_unit,
                            project_pkg_classes=project_pkg_classes,
                            all_units=all_units,
                            shadowed_expr_names=shadowed_expr_names,
                            has_unverified_superclass=has_unverified_superclass,
                        )
                    ):
                        state.raw_const_path_vars[vname] = True

            # Track canonicalized String / File / Path values (reject binary concat `+` or ternary `?`!)
            is_single_call_expr = len(_split_top_level(rhs_k, "+")) == 1 and "?" not in rhs_m
            m_can_str = _CANON_PATH_STR_RHS_RE.match(rhs_k)
            if m_can_str:
                src_var = m_can_str.group(1)
                state.canon_target_str_vars[vname] = True
                if state.raw_const_path_vars.get(src_var, False):
                    state.canon_safe_base_str_vars[vname] = True
            elif _INLINE_CONST_CANON_STR_RE.match(rhs_k):
                m_ic = _INLINE_CONST_CANON_STR_RE.match(rhs_k)
                assert m_ic is not None
                file_type_raw = "java.io.File" if "java.io.File" in rhs_k else "File"
                if (
                    _is_non_root_safe_base_literal(m_ic.group(1))
                    and resolve_stdlib_class_fqn(
                        file_type_raw,
                        caller_unit=caller_unit,
                        project_pkg_classes=project_pkg_classes,
                        all_units=all_units,
                    )
                    == "java.io.File"
                ):
                    state.canon_safe_base_str_vars[vname] = True
                    state.canon_target_str_vars[vname] = True
            elif is_single_call_expr and re.match(r"^.+?\.\s*(?:getCanonicalPath\s*\(\s*\)|getCanonicalFile\s*\(\s*\)\s*\.\s*getPath\s*\(\s*\)|toRealPath\s*\(\s*\)\s*\.\s*toString\s*\(\s*\))$", rhs_k):
                state.canon_target_str_vars[vname] = True
            elif _CANON_FILE_RHS_RE.match(rhs_k) or (is_single_call_expr and re.match(r"^.+?\.\s*getCanonicalFile\s*\(\s*\)$", rhs_k)):
                state.canon_target_file_vars[vname] = True
            elif _TO_REAL_PATH_RHS_RE.match(rhs_k):
                m_rp = _TO_REAL_PATH_RHS_RE.match(rhs_k)
                assert m_rp is not None
                src_var = m_rp.group(1)
                state.canon_target_path_vars[vname] = True
                if state.raw_const_path_vars.get(src_var, False):
                    state.canon_safe_base_path_vars[vname] = True
            elif _INLINE_CONST_REAL_PATH_RE.match(rhs_k):
                m_irp = _INLINE_CONST_REAL_PATH_RE.match(rhs_k)
                assert m_irp is not None
                if (
                    _is_non_root_safe_base_literal(m_irp.group(1))
                    and _nio_paths_expr_verified(
                        rhs_k,
                        caller_unit=caller_unit,
                        project_pkg_classes=project_pkg_classes,
                        all_units=all_units,
                        shadowed_expr_names=shadowed_expr_names,
                        has_unverified_superclass=has_unverified_superclass,
                    )
                ):
                    state.canon_safe_base_path_vars[vname] = True
                    state.canon_target_path_vars[vname] = True
            elif is_single_call_expr and re.match(r"^.+?\.\s*toRealPath\s*\(\s*\)$", rhs_k):
                state.canon_target_path_vars[vname] = True
            else:
                # Propagate canonical wrapper (`File f = new File(targetCanon);`, `Path p = Paths.get(targetCanon);`)
                m_wrap_p = re.fullmatch(r"(?:java\.nio\.file\.)?(?:Paths\.get|Path\.of)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", rhs_k)
                m_wrap_f = re.fullmatch(r"new\s+(?:java\.io\.)?File\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", rhs_k)
                if m_wrap_p and state.canon_target_str_vars.get(m_wrap_p.group(1), False):
                    state.canon_target_path_vars[vname] = True
                elif m_wrap_f and state.canon_target_str_vars.get(m_wrap_f.group(1), False):
                    state.canon_target_file_vars[vname] = True

        # Track constant literal flow
        if op_sym == "+=":
            if prev_const and _eval_constant_expr(rhs_k, state.const_vars, is_cwe22=state.is_cwe22):
                state.const_vars[vname] = True
                state.const_assign_lines.setdefault(vname, []).append(s_ln)
        else:
            if _eval_constant_expr(rhs_k, state.const_vars, is_cwe22=state.is_cwe22):
                state.const_vars[vname] = True
                state.const_assign_lines[vname] = [s_ln]

        # Track unconditional CWE-89 scalar parse & PreparedStatement
        simple_decl = decl_type.rsplit(".", 1)[-1].strip()
        m_scalar = _SCALAR_PARSE_RE.match(rhs_k)
        scalar_fqn_ok = False
        if m_scalar:
            sp_qual, sp_meth = m_scalar.group(1), m_scalar.group(2)
            sp_head = sp_qual.split(".", 1)[0]
            expected_fqn = {
                "parseInt": "java.lang.Integer",
                "parseLong": "java.lang.Long",
                "fromString": "java.util.UUID",
            }.get(sp_meth)
            if sp_head in shadowed_expr_names or has_unverified_superclass:
                resolved_sp_fqn = None
            else:
                resolved_sp_fqn = resolve_stdlib_class_fqn(
                    sp_qual,
                    caller_unit=caller_unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                )
            decl_fqn_ok = simple_decl in ("int", "long") or (
                resolve_stdlib_class_fqn(
                    decl_type,
                    caller_unit=caller_unit,
                    project_pkg_classes=project_pkg_classes,
                    all_units=all_units,
                )
                in ("java.lang.Integer", "java.lang.Long", "java.util.UUID")
            )
            scalar_fqn_ok = bool(expected_fqn and resolved_sp_fqn == expected_fqn and decl_fqn_ok)
        if (
            at_top_unconditional
            and state.primary_cwe == "CWE-89"
            and op_sym == "="
            and simple_decl in ("int", "long", "Integer", "Long", "UUID")
            and scalar_fqn_ok
            and not _HTTP_TAINT_RE.search(rhs_m)
        ):
            state.scalar_vars[vname] = True
            state.scalar_assign_lines[vname] = [s_ln]
        elif (
            at_top_unconditional
            and state.primary_cwe == "CWE-89"
            and op_sym == "="
            and simple_decl == "PreparedStatement"
        ):
            m_prep = _PREPARE_CALL_RE.match(rhs_k)
            if m_prep:
                p_args = _split_top_level(m_prep.group(1), ",")
                if p_args and _eval_constant_expr(p_args[0], state.const_vars, is_cwe22=False):
                    state.prepared_stmt_safe[vname] = [s_ln]
        return

    # Unknown / unmodeled statement (e.g., `this.q = u;`, `arr[0] = u;`, `mutate();`, `sb.append(u);`):
    # NEVER treat an unknown statement as a no-op! Invalidate all prior safety assumptions!
    state.invalidate_all("unmodeled_statement")


_MAX_LOOP_FIXPOINT_ITERS = 16


def _is_non_mutating_loop_sink_call(node: _StmtNode, primary_cwe: str) -> bool:
    """Return True ONLY when a bare sink statement inside a loop cannot mutate immutable local proof variables.

    Used exclusively during the full-body loop fixed-point pass (`sink_line=None`) so a safe sink call
    like `st.executeQuery(q);` or `Files.readString(Paths.get(targetCanon));` does not falsely clear
    immutable local variable facts while EVERY other statement (before or after the sink) executes normally.
    Any sink statement containing embedded side effects (`=`, `+=`, `++`, `--`, `->`, `{}`) returns False.
    """
    if _has_unmodeled_expr_side_effect(node.code_m):
        return False
    clean_k = _clean_sink_statement(node.code_k)
    clean_m = _clean_sink_statement(node.code_m)
    if primary_cwe == "CWE-89" and (
        _PREP_EXEC_ZERO_RE.match(clean_k) or _PREPARE_CALL_RE.match(clean_k.rstrip(";").strip())
    ):
        return True
    args = _extract_sink_args(clean_k, clean_m, primary_cwe)
    return bool(args)


def _exec_stmt_list(
    stmts: list[_StmtNode],
    state: _IndependentFlowState,
    *,
    sink_line: int | None,
    at_top_unconditional: bool,
    loop_sink_line: int | None = None,
    caller_unit: dict[str, Any] | None = None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
    shadowed_expr_names: set[str] | frozenset[str] = frozenset(),
    has_unverified_superclass: bool = False,
) -> bool:
    if sink_line is not None:
        same_line_nodes = [n for n in stmts if n.kind != "EMPTY" and _stmt_contains_line(n, sink_line)]
        if len(same_line_nodes) > 1:
            # Multiple sibling statements share `sink_line` (e.g., `if (flag) q = u; st.executeQuery(q);`
            # or `st.executeQuery(u); int x = 1;`): line-level sink coordinates cannot prove safety soundly.
            state.aborted = True
            state.invalidate_all("multiple_statements_on_sink_line")
            return True
    for node in stmts:
        if state.aborted:
            return False
        if _exec_stmt_node(
            node,
            state,
            sink_line=sink_line,
            at_top_unconditional=at_top_unconditional,
            loop_sink_line=loop_sink_line,
            caller_unit=caller_unit,
            project_pkg_classes=project_pkg_classes,
            all_units=all_units,
            shadowed_expr_names=shadowed_expr_names,
            has_unverified_superclass=has_unverified_superclass,
        ):
            return True
        if sink_line is not None and node.start_line > sink_line:
            return False
    return False



def _has_unmodeled_continue_in_loop(node: _StmtNode | None) -> bool:
    """Find Java continue edges not supported by loop fixed-point execution."""
    if node is None:
        return False
    if node.kind == "SIMPLE" and re.match(
        r"^\s*continue\b", node.code_m
    ):
        return True
    for attr in ("then_stmt", "else_stmt", "body_stmt", "finally_stmt"):
        if _has_unmodeled_continue_in_loop(getattr(node, attr)):
            return True
    for attr in ("body_stmts", "catches"):
        for child in getattr(node, attr) or []:
            if _has_unmodeled_continue_in_loop(child):
                return True
    return False


def _has_unmodeled_break_in_loop(node: _StmtNode | None) -> bool:
    """Find Java break edges exiting a loop early (which can skip subsequent constant-reset statements)."""
    if node is None:
        return False
    if node.kind == "SWITCH":
        # Unlabeled break inside switch targets switch, while switch itself already invalidates all facts;
        # labeled break inside switch could still target an enclosing loop, so scan for `break <label>;`.
        return _has_labeled_break_in_subtree(node.body_stmt)
    if node.kind == "SIMPLE" and re.match(r"^\s*break\b", node.code_m):
        return True
    for attr in ("then_stmt", "else_stmt", "body_stmt", "finally_stmt"):
        if _has_unmodeled_break_in_loop(getattr(node, attr)):
            return True
    for attr in ("body_stmts", "catches"):
        for child in getattr(node, attr) or []:
            if _has_unmodeled_break_in_loop(child):
                return True
    return False


def _has_labeled_break_in_subtree(node: _StmtNode | None) -> bool:
    if node is None:
        return False
    if node.kind == "SIMPLE" and re.match(r"^\s*break\s+[A-Za-z_]", node.code_m):
        return True
    for attr in ("then_stmt", "else_stmt", "body_stmt", "finally_stmt"):
        if _has_labeled_break_in_subtree(getattr(node, attr)):
            return True
    for attr in ("body_stmts", "catches"):
        for child in getattr(node, attr) or []:
            if _has_labeled_break_in_subtree(child):
                return True
    return False


def _exec_stmt_node(
    node: _StmtNode | None,
    state: _IndependentFlowState,
    *,
    sink_line: int | None,
    at_top_unconditional: bool,
    loop_sink_line: int | None = None,
    caller_unit: dict[str, Any] | None = None,
    project_pkg_classes: dict[str | None, set[str]] | None = None,
    all_units: list[dict[str, Any]] | None = None,
    shadowed_expr_names: set[str] | frozenset[str] = frozenset(),
    has_unverified_superclass: bool = False,
) -> bool:
    """Execute AST statement node conservatively up to `sink_line` (or full subtree when `sink_line is None`)."""
    if node is None or state.aborted:
        return False
    if sink_line is not None and node.start_line > sink_line:
        return False

    ctx_kw = {
        "caller_unit": caller_unit,
        "project_pkg_classes": project_pkg_classes,
        "all_units": all_units,
        "shadowed_expr_names": shadowed_expr_names,
        "has_unverified_superclass": has_unverified_superclass,
    }

    if node.kind == "EMPTY":
        return False

    if node.kind == "UNKNOWN":
        state.aborted = True
        state.invalidate_all(f"unmodeled_or_malformed_stmt:{node.subkind}")
        return _stmt_contains_line(node, sink_line)

    if node.kind in ("SIMPLE", "EXIT"):
        if _stmt_contains_line(node, sink_line):
            state.sink_reached = True
            return True
        if node.kind == "EXIT":
            if _has_unmodeled_expr_side_effect(node.code_m):
                state.invalidate_all("exit_expr_side_effect")
            return False
        if sink_line is None and _stmt_contains_line(node, loop_sink_line):
            # Full-body loop fixed-point pass encountering the sink statement itself:
            # If it assigns to a local variable (`ResultSet rs = st.executeQuery(q);`), execute normally
            # so LHS invalidation happens cleanly; if it is a bare sink call (`st.executeQuery(q);`),
            # preserve immutable local variable facts ONLY when it has zero embedded side effects.
            if _LOCAL_ASSIGN_RE.match(node.code_k.strip()):
                _exec_simple_stmt(node, state, at_top_unconditional=at_top_unconditional, **ctx_kw)
            elif not _is_non_mutating_loop_sink_call(node, state.primary_cwe):
                state.invalidate_all("unmodeled_loop_sink_statement")
            return False
        _exec_simple_stmt(node, state, at_top_unconditional=at_top_unconditional, **ctx_kw)
        return False

    if node.kind == "BLOCK":
        return _exec_stmt_list(
            node.body_stmts or [],
            state,
            sink_line=sink_line,
            at_top_unconditional=at_top_unconditional,
            loop_sink_line=loop_sink_line,
            **ctx_kw,
        )

    if node.kind == "LABELED":
        state.invalidate_all("labeled_statement")
        return _exec_stmt_node(
            node.body_stmt,
            state,
            sink_line=sink_line,
            at_top_unconditional=False,
            loop_sink_line=loop_sink_line,
            **ctx_kw,
        )

    if node.kind == "IF":
        if _has_unmodeled_expr_side_effect(node.cond_m):
            state.invalidate_all("if_condition_side_effect")
            if _stmt_contains_line(node, sink_line):
                state.sink_reached = True
                return True
            return False

        cond_end_ln = int(node.subkind) if node.subkind.isdigit() else node.start_line
        sink_in_then = _stmt_contains_line(node.then_stmt, sink_line)
        sink_in_else = _stmt_contains_line(node.else_stmt, sink_line)
        if sink_in_then and sink_in_else:
            state.aborted = True
            state.invalidate_all("ambiguous_same_line_if_else_at_sink")
            return True

        # 1. Dominating negative CWE-22 canonical containment guard (`if (!canon.startsWith(...)) { throw/return; }`)
        if (
            at_top_unconditional
            and sink_line is not None
            and state.is_cwe22
            and node.else_stmt is None
            and cond_end_ln < sink_line
            and not sink_in_then
            and _stmt_unconditionally_exits(node.then_stmt)
        ):
            gvar = _extract_guarded_canonical_var(node.cond_k, state, negated=True, **ctx_kw)
            if gvar is not None:
                state.guarded_vars[gvar] = (node.start_line, node.start_line)
            return False

        # 2. Enclosing positive CWE-22 canonical containment guard (`if (canon.startsWith(...)) { ... sink ... }`)
        if (
            at_top_unconditional
            and sink_line is not None
            and state.is_cwe22
            and sink_in_then
            and not sink_in_else
        ):
            then_st = state.clone()
            gvar = _extract_guarded_canonical_var(node.cond_k, then_st, negated=False, **ctx_kw)
            if gvar is not None:
                then_st.guarded_vars[gvar] = (node.start_line, node.start_line)
            _exec_stmt_node(
                node.then_stmt,
                then_st,
                sink_line=sink_line,
                at_top_unconditional=at_top_unconditional,
                loop_sink_line=loop_sink_line,
                **ctx_kw,
            )
            state.adopt_from(then_st)
            state.sink_reached = True
            return True

        # 3. General if/else: NEVER prune either branch; execute both & intersect!
        then_st = state.clone()
        hit_then = _exec_stmt_node(
            node.then_stmt,
            then_st,
            sink_line=sink_line,
            at_top_unconditional=False,
            loop_sink_line=loop_sink_line,
            **ctx_kw,
        )
        if hit_then or sink_in_then:
            state.adopt_from(then_st)
            state.sink_reached = True
            return True

        else_st = state.clone()
        if node.else_stmt is not None:
            hit_else = _exec_stmt_node(
                node.else_stmt,
                else_st,
                sink_line=sink_line,
                at_top_unconditional=False,
                loop_sink_line=loop_sink_line,
                **ctx_kw,
            )
            if hit_else or sink_in_else:
                state.adopt_from(else_st)
                state.sink_reached = True
                return True
            then_exits = _stmt_unconditionally_exits(node.then_stmt)
            else_exits = _stmt_unconditionally_exits(node.else_stmt)
            if then_exits and not else_exits:
                state.merge_from(else_st)
            elif else_exits and not then_exits:
                state.merge_from(then_st)
            else:
                state.merge_from(then_st, else_st)
        else:
            state.merge_from(then_st, else_st)
        return False

    if node.kind == "LOOP":
        # Loops (for/while/do, with or without `{}`): compute monotone loop-invariant header state via
        # full-body fixed-point iteration so ALL loop-carried dependencies (including mutations AFTER sink,
        # multi-iteration variable chains, and outer-loop mutations after inner loops) are accounted for!
        if node.subkind != "for":
            if _has_unmodeled_expr_side_effect(node.cond_m) or _has_unmodeled_call(node.cond_m):
                state.invalidate_all("loop_condition_side_effect_or_call")
        else:
            for_parts = _split_top_level(node.cond_m, ";")
            if len(for_parts) == 3:
                init_m, cond_m, upd_m = for_parts
                if (
                    _has_unmodeled_expr_side_effect(cond_m)
                    or _has_unmodeled_call(init_m)
                    or _has_unmodeled_call(cond_m)
                    or _has_unmodeled_call(upd_m)
                ):
                    state.invalidate_all("for_header_side_effect_or_call")
                for v_hit in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:(?<![=!<>])=(?!=)|[+\-*/%&|^]=|\+\+|--)", init_m + " " + upd_m):
                    if v_hit not in _JAVA_KEYWORDS:
                        state.invalidate_var(v_hit)
                for v_hit in re.findall(r"(?:\+\+|--)\s*([A-Za-z_][A-Za-z0-9_]*)\b", init_m + " " + upd_m):
                    if v_hit not in _JAVA_KEYWORDS:
                        state.invalidate_var(v_hit)
            else:
                m_fe = re.match(
                    r"^\s*(?:final\s+)?[A-Za-z_][A-Za-z0-9_<>,.\[\]]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*:(.*)$",
                    node.cond_m,
                )
                if m_fe:
                    state.invalidate_var(m_fe.group(1))
                    iter_expr_m = m_fe.group(2)
                    if _has_unmodeled_expr_side_effect(iter_expr_m) or _has_unmodeled_call(iter_expr_m):
                        state.invalidate_all("enhanced_for_iterable_side_effect_or_call")
                else:
                    state.invalidate_all("unmodeled_for_header")

        # The fixed-point executor does not model Java continue backedges or early loop break exits.
        # Fail closed rather than proving a potentially unsafe sink safe.
        if _has_unmodeled_continue_in_loop(node.body_stmt):
            state.aborted = True
            state.invalidate_all("unmodeled_continue_loop_backedge")
            return False
        if _has_unmodeled_break_in_loop(node.body_stmt):
            state.aborted = True
            state.invalidate_all("unmodeled_break_loop_exit")
            return False
        active_loop_sink = sink_line if sink_line is not None else loop_sink_line
        inv_st = state.clone()
        converged = False
        for _ in range(_MAX_LOOP_FIXPOINT_ITERS):
            body_out = inv_st.clone()
            _exec_stmt_node(
                node.body_stmt,
                body_out,
                sink_line=None,
                at_top_unconditional=False,
                loop_sink_line=active_loop_sink,
                **ctx_kw,
            )
            next_inv = inv_st.clone()
            next_inv.merge_from(inv_st, body_out)
            if next_inv.aborted or next_inv.facts_key() == inv_st.facts_key():
                inv_st = next_inv
                converged = True
                break
            inv_st = next_inv
        if not converged:
            inv_st.invalidate_all("loop_fixpoint_not_converged")

        if sink_line is not None and _stmt_contains_line(node.body_stmt, sink_line):
            # Evaluate the sink starting from the converged loop-invariant header state (sound across ALL iterations!).
            sink_st = inv_st.clone()
            _exec_stmt_node(
                node.body_stmt,
                sink_st,
                sink_line=sink_line,
                at_top_unconditional=False,
                loop_sink_line=sink_line,
                **ctx_kw,
            )
            state.adopt_from(sink_st)
            state.sink_reached = True
            return True

        if sink_line is not None and _stmt_contains_line(node, sink_line):
            # Sink resides inside the loop header condition/update itself (executes on every iteration).
            state.adopt_from(inv_st)
            state.sink_reached = True
            return True

        if node.subkind == "do":
            after_do = inv_st.clone()
            _exec_stmt_node(
                node.body_stmt,
                after_do,
                sink_line=None,
                at_top_unconditional=False,
                loop_sink_line=active_loop_sink,
                **ctx_kw,
            )
            state.adopt_from(after_do)
        else:
            state.adopt_from(inv_st)
        return False

    if node.kind == "TRY":
        if node.resources_m.strip():
            # Try-with-resources: if sink is inside the resource header lines, stop right there;
            # otherwise invalidate conservatively before entering body.
            body_start_ln = node.body_stmt.start_line if node.body_stmt is not None else node.start_line
            if (
                sink_line is not None
                and node.start_line <= sink_line <= body_start_ln
                and not _stmt_contains_line(node.body_stmt, sink_line)
            ):
                state.sink_reached = True
                return True
            if sink_line is not None and node.start_line == sink_line:
                state.sink_reached = True
                return True
            state.invalidate_all("try_with_resources_unmodeled")
        pre_st = state.clone()
        try_st = state.clone()
        hit_try = _exec_stmt_node(
            node.body_stmt,
            try_st,
            sink_line=sink_line,
            at_top_unconditional=False,
            loop_sink_line=loop_sink_line,
            **ctx_kw,
        )
        if hit_try or _stmt_contains_line(node.body_stmt, sink_line):
            state.adopt_from(try_st)
            state.sink_reached = True
            return True
        branch_states = [pre_st, try_st]
        for c_blk in node.catches or []:
            c_st = pre_st.clone()
            hit_c = _exec_stmt_node(
                c_blk,
                c_st,
                sink_line=sink_line,
                at_top_unconditional=False,
                loop_sink_line=loop_sink_line,
                **ctx_kw,
            )
            if hit_c or _stmt_contains_line(c_blk, sink_line):
                state.merge_from(pre_st, try_st, c_st)
                state.sink_reached = True
                return True
            branch_states.append(c_st)
        state.merge_from(*branch_states)
        if node.finally_stmt is not None:
            hit_f = _exec_stmt_node(
                node.finally_stmt,
                state,
                sink_line=sink_line,
                at_top_unconditional=False,
                loop_sink_line=loop_sink_line,
                **ctx_kw,
            )
            if hit_f or _stmt_contains_line(node.finally_stmt, sink_line):
                state.sink_reached = True
                return True
        return False

    if node.kind in ("SWITCH", "SYNCHRONIZED"):
        # Unmodeled switch/synchronized blocks conservatively invalidate all prior safety assumptions
        state.invalidate_all(f"unmodeled_{node.kind.lower()}_block")
        if _stmt_contains_line(node, sink_line):
            state.sink_reached = True
            return True
        return False

    state.invalidate_all(f"unknown_node_kind:{node.kind}")
    return False


def _build_gate_resolution_context(
    record: dict[str, Any],
    p_path: str | None,
    lines_by_no: dict[int, str],
) -> tuple[dict[str, Any], dict[str | None, set[str]], list[dict[str, Any]]]:
    """Build JLS §6.5.5.1 compilation-unit & project package-class context for scalar-parse stdlib verification."""
    jctx = record.get("java_context") if isinstance(record.get("java_context"), dict) else {}
    snaps = record.get("snapshots") if isinstance(record.get("snapshots"), dict) else {}
    verified_by_path: dict[str, dict[int, str]] = {}
    for snip in record.get("snippets") or []:
        if not isinstance(snip, dict):
            continue
        sp = snip.get("path")
        ssha = snip.get("sha256")
        snap = snaps.get(sp) if isinstance(sp, str) else None
        if not isinstance(snap, dict) or not isinstance(ssha, str) or snap.get("sha256") != ssha:
            continue
        lmap = verified_by_path.setdefault(sp, {})
        for ln in snip.get("lines") or []:
            if isinstance(ln, dict) and type(ln.get("line")) is int:
                lmap[ln["line"]] = str(ln.get("text") or "")
    if p_path and p_path not in verified_by_path and lines_by_no:
        verified_by_path[p_path] = dict(lines_by_no)

    units_by_path: dict[str, dict[str, Any]] = {}
    for fp, lmap in verified_by_path.items():
        if not lmap:
            continue
        min_ln = min(lmap)
        max_ln = max(lmap)
        virtual = [lmap.get(i, "") for i in range(1, max_ln + 1)]
        full_src = "\n".join(virtual)
        parsed = parse_java_structure_v2(full_src)
        cls_by_name = {c["name"]: c for c in (parsed.get("classes") or []) if isinstance(c.get("name"), str)}
        enc_cls = jctx.get("enclosing_class") if isinstance(jctx.get("enclosing_class"), str) else None
        fields = sorted(extract_class_field_names(full_src, structure=parsed, enclosing_class=enc_cls)) if min_ln == 1 else []
        enc_extends = cls_by_name.get(enc_cls, {}).get("extends") if enc_cls and enc_cls in cls_by_name else None
        units_by_path[fp] = {
            "path": fp,
            "min_line": min_ln,
            "has_complete_header": min_ln == 1,
            "package_name": parsed.get("package_name"),
            "imports": list(parsed.get("imports") or []),
            "type_imports": list(parsed.get("type_imports") or []),
            "static_imports": list(parsed.get("static_imports") or []),
            "classes": cls_by_name,
            "declared_class_names": list(cls_by_name.keys()),
            "enclosing_class_fields": fields,
            "enclosing_class_extends": enc_extends,
            "line_map": lmap,
        }
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
            "line_map": lines_by_no,
        }
    _merge_header_metadata_into_unit(caller_unit, record, p_path)
    proj_pkg_classes = collect_project_package_classes(
        record,
        all_units,
        primary_path=p_path,
        primary_pkg=caller_unit.get("package_name"),
    )
    return caller_unit, proj_pkg_classes, all_units


def _verify_independent_refutation_proof(
    record: dict[str, Any],
    lines_by_no: dict[int, str],
    header_line: int,
    sink_line: int,
    cited_primary_lines: set[int],
    p_path: str | None = None,
) -> tuple[bool, str]:
    """Independently prove safety on continuous verified Java lines without trusting heuristics."""
    if not (header_line <= sink_line) or not all(ln in lines_by_no for ln in range(header_line, sink_line + 1)):
        return False, "enclosing method lines between header and sink are incomplete in verified prompt evidence"

    cwes = [str(x).upper() for x in (record.get("cwe") or [])]
    primary_cwe = "CWE-22" if any("CWE-22" in c or c == "22" for c in cwes) else (
        "CWE-89" if any("CWE-89" in c or c == "89" for c in cwes) else "UNKNOWN"
    )
    if primary_cwe not in ("CWE-22", "CWE-89"):
        return False, f"unsupported CWE ({primary_cwe}) for independent safety verification"

    caller_unit, project_pkg_classes, all_units = _build_gate_resolution_context(record, p_path, lines_by_no)

    max_ln = max(lines_by_no)
    sub_lines = {ln: lines_by_no[ln] for ln in range(header_line, max_ln + 1) if ln in lines_by_no}
    keep_str, masked_str = _strip_comments_and_mask_strings(sub_lines)
    body_pos = _method_body_start_pos(masked_str, header_line, sink_line)
    if body_pos is None or body_pos[0] > sink_line:
        return False, "could not verify enclosing method header and body boundaries"
    body_start, body_col = body_pos
    if body_col > 0 and body_start in keep_str and body_start in masked_str:
        keep_str = dict(keep_str)
        masked_str = dict(masked_str)
        keep_str[body_start] = (" " * body_col) + keep_str[body_start][body_col:]
        masked_str[body_start] = (" " * body_col) + masked_str[body_start][body_col:]

    # Determine end of sink statement (up to ';' or '{' within verified lines)
    sink_end_ln = sink_line
    while sink_end_ln < max_ln and (sink_end_ln + 1) in masked_str:
        cur_m = masked_str[sink_end_ln].strip()
        if cur_m.endswith((";", "{", "}")):
            break
        sink_end_ln += 1

    parser = _JavaBodyParser(body_start, max(sink_end_ln, max_ln), keep_str, masked_str)
    stmts = parser.parse_method_body()

    # Collect all ExpressionName identifiers in scope (formal parameters, local/loop/resource declarations,
    # and enclosing class fields) so shadowed tokens like `File.separator` (param/local/field named `File`)
    # or `java.io.File.separator` (param/local/field named `java`) NEVER satisfy canonical containment!
    jctx = record.get("java_context") if isinstance(record.get("java_context"), dict) else {}
    enc_cls = jctx.get("enclosing_class") if isinstance(jctx.get("enclosing_class"), str) else None
    shadowed_expr_names: set[str] = set()
    shadowed_expr_names.update(_extract_method_param_names(record, lines_by_no, header_line, body_start))
    shadowed_expr_names.update(_collect_local_decl_names_in_ast(stmts))
    for fn in caller_unit.get("enclosing_class_fields") or ():
        if isinstance(fn, str) and fn:
            shadowed_expr_names.add(fn)
    # Also scan catch parameter names (`catch (ExType File)`) in masked_str within method body
    for ln_c in range(body_start, max(sink_end_ln, max_ln) + 1):
        txt_c = masked_str.get(ln_c, "")
        for m_cat in re.finditer(r"\bcatch\s*\(\s*(?:final\s+)?[A-Za-z0-9_.|\s]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\)", txt_c):
            if m_cat.group(1) not in _JAVA_NON_TYPE_KEYWORDS:
                shadowed_expr_names.add(m_cat.group(1))
    has_unverified_superclass = _enclosing_class_has_unverified_superclass(
        caller_unit,
        project_pkg_classes,
        all_units,
        enc_cls,
    )

    state = _IndependentFlowState(primary_cwe)
    _exec_stmt_list(
        stmts,
        state,
        sink_line=sink_line,
        at_top_unconditional=True,
        caller_unit=caller_unit,
        project_pkg_classes=project_pkg_classes,
        all_units=all_units,
        shadowed_expr_names=shadowed_expr_names,
        has_unverified_superclass=has_unverified_superclass,
    )
    if state.aborted or not state.sink_reached:
        return False, (
            f"enclosing method control flow could not be fully verified up to sink "
            f"({state.abort_reason or 'sink_not_reached_in_parsed_ast'})"
        )

    sink_k = " ".join(keep_str.get(ln, "").strip() for ln in range(sink_line, sink_end_ln + 1) if keep_str.get(ln, "").strip())
    sink_m = " ".join(masked_str.get(ln, "").strip() for ln in range(sink_line, sink_end_ln + 1) if masked_str.get(ln, "").strip())
    clean_sink_k = _clean_sink_statement(sink_k)
    clean_sink_m = _clean_sink_statement(sink_m)
    sink_span = set(range(sink_line, sink_end_ln + 1))

    # 1. CWE-89 0-arg PreparedStatement execution (`ps.executeQuery()`)
    if primary_cwe == "CWE-89":
        m_ps0 = _PREP_EXEC_ZERO_RE.match(clean_sink_k)
        if m_ps0 and m_ps0.group(1) in state.prepared_stmt_safe:
            proof_lines = set(state.prepared_stmt_safe[m_ps0.group(1)]) | sink_span
            if cited_primary_lines & proof_lines:
                return True, "CWE89_CONSTANT_PREPARED_STATEMENT"
            return False, "citations do not cover the verified PreparedStatement or sink lines"

        m_prep_sink = _PREPARE_CALL_RE.match(clean_sink_k.rstrip(";").strip())
        if m_prep_sink:
            p_args = _split_top_level(m_prep_sink.group(1), ",")
            if p_args and _eval_constant_expr(p_args[0], state.const_vars, is_cwe22=False):
                if cited_primary_lines & sink_span:
                    return True, "CWE89_CONSTANT_PREPARED_STATEMENT"
                return False, "citations do not cover the verified PreparedStatement or sink lines"

    sink_args = _extract_sink_args(clean_sink_k, clean_sink_m, primary_cwe)
    if not sink_args:
        return False, "could not extract sink arguments for independent verification"
    sink_args_m = _extract_sink_args(clean_sink_m, clean_sink_m, primary_cwe)
    if any(_has_unmodeled_expr_side_effect(arg_m) for arg_m in sink_args_m):
        return False, "sink arguments contain unmodeled embedded side effects"

    # 2. Unconditional constant-literal sink flow (all dangerous sink args proven constant across all paths)
    if all(_eval_constant_expr(arg, state.const_vars, is_cwe22=state.is_cwe22) for arg in sink_args):
        proof_lines = set(sink_span)
        for arg in sink_args:
            for tok in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", arg):
                proof_lines.update(state.const_assign_lines.get(tok, ()))
        if cited_primary_lines & proof_lines:
            return True, "UNCONDITIONAL_CONSTANT_SINK_FLOW"
        return False, "citations do not cover the constant assignment or sink lines"

    # 3. CWE-89 unconditional scalar parse (`Integer.parseInt` / `Long.parseLong` / `UUID.fromString`)
    if primary_cwe == "CWE-89" and all(
        _eval_scalar_safe_sql_expr(arg, state.const_vars, state.scalar_vars) for arg in sink_args
    ):
        proof_lines = set(sink_span)
        for arg in sink_args:
            for tok in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", arg):
                proof_lines.update(state.scalar_assign_lines.get(tok, ()))
        if cited_primary_lines & proof_lines:
            return True, "CWE89_UNCONDITIONAL_SCALAR_PARSE"
        return False, "citations do not cover the scalar parse sanitizer or sink lines"

    # 4. CWE-22 verified dominating canonical directory containment guard (checked canonical value used directly at sink!)
    if primary_cwe == "CWE-22":
        # Never allow multi-arg path joining after canonicalization (e.g. `new File(targetCanon, "child")`,
        # `Paths.get(targetCanon, "child")`, `targetReal.resolve("child")`) because appended child segments
        # were NOT resolved by the preceding canonical containment check!
        if len(sink_args) > 1 and _CWE22_PATH_JOIN_SINK_RE.search(clean_sink_k):
            return False, "CWE-22 sink appends unverified path segments after canonical containment guard"
        guarded_lines: set[int] = set()
        all_args_guarded = True
        for arg in sink_args:
            tv = _extract_cwe22_sink_target_var(arg)
            if tv and tv in state.guarded_vars:
                guarded_lines.add(state.guarded_vars[tv][0])
            elif _eval_constant_expr(arg, state.const_vars, is_cwe22=True):
                continue
            else:
                all_args_guarded = False
                break
        if all_args_guarded and guarded_lines:
            if cited_primary_lines & guarded_lines:
                return True, "CWE22_CANONICAL_CONTAINMENT_GUARD"
            return False, "citations do not cover the verified canonical containment guard line"

    return False, (
        "safety claim could not be independently proven across all reachable Java paths "
        "(arithmetic conditions, unmodeled statements/branches, dominance gaps, unverified canonical "
        "prefix/raw-path sinks, collections, try/catch fallthrough, and custom allowlists fail closed to UNDETERMINED)"
    )


def _uses_cwe22_basename_or_unverified_normalize(
    record: dict[str, Any],
    sig: dict[str, Any] | None,
    lines_by_no: dict[int, str],
    header_line: int,
    sink_line: int,
) -> bool:
    cwes = [str(x).upper() for x in (record.get("cwe") or [])]
    is_cwe22 = any("CWE-22" in x or x == "22" for x in cwes)
    if not is_cwe22:
        return False

    sans = [s for s in ((sig or {}).get("sanitizers_found") or []) if isinstance(s, dict)]
    has_canon_guard = any(s.get("name") == "getCanonicalPath_startsWith" for s in sans)
    has_scalar_san = any(
        str(s.get("name") or "") in ("SANITIZED_CWE89", "Integer.parseInt", "Long.parseLong", "UUID.fromString")
        for s in sans
    )

    for s in sans:
        sname = str(s.get("name") or "").lower()
        smech = str(s.get("mechanism") or "").lower()
        if sname == "sanitized_cwe22" or any(tok in sname or tok in smech for tok in _BASENAME_SANITIZER_NAMES):
            if not has_canon_guard:
                return True

    if not has_canon_guard and not has_scalar_san:
        for lno in sorted(lines_by_no):
            if header_line <= lno <= sink_line:
                txt = lines_by_no[lno]
                if _BASENAME_CALL_RE.search(txt) or _NORMALIZE_CALL_RE.search(txt):
                    return True
    return False


def apply_integration_gate(record: dict[str, Any], assessment: dict[str, Any]) -> dict[str, Any]:
    """Enforce single authoritative integration gate on an assessment dictionary.

    Separates four independent dimensions:
    - Gate 0 (Citation Integrity): verifies citations verbatim against locked source/prompt/SHA-256.
      Invalid or missing citations fail closed (`INVALID_CITATION`, `citation_check='NOT_VERIFIED'`).
      Verified citations (`citation_check='MATCHED'`) are NEVER overwritten to `'NOT_VERIFIED'`
      by downstream helper-flow or refutation-proof downgrades.
    - Gate 1 (Context & Flow-Dependency Validity): fails closed (`UNVERIFIED_HELPER_FLOW`) only when
      an unverified helper can actually affect the sink payload, tainted flow, or governing guard.
    - Gate 2 (Independent Refutation Proof): requires independent AST/CFG safety proof for `REFUTED`.
    - Security Verdict Boundary: keeps `security_conclusion_verified=False` and `requires_human_review=True`.
    """
    if not isinstance(assessment, dict):
        return assessment
    cur_status, status_contradiction = _resolve_effective_status(assessment)
    is_conclusive = (status_contradiction is None) and cur_status in ("SUPPORTED", "REFUTED")

    out = dict(assessment)
    if "raw_model_status" not in out:
        out["raw_model_status"] = assessment.get("status")

    # Gate 0: Independent citation integrity verification runs BEFORE ANY return path (including UNDETERMINED).
    # Never trusts caller-supplied citation_check, citation_provenance, status, validated_status, or security flags.
    cite_ok, verified_citation_check, verified_citation_prov, cite_err = _verify_citation_integrity(
        record,
        out,
        require_non_empty=is_conclusive,
        require_relevant_scope=is_conclusive,
    )
    if status_contradiction is not None:
        if not cite_ok:
            return _downgrade_assessment(
                out,
                failure_kind="INVALID_CITATION",
                reason=(
                    f"Rejected contradictory assessment ({status_contradiction}) with invalid citation: {cite_err}."
                ),
                citation_check="NOT_VERIFIED",
                citation_provenance=verified_citation_prov,
            )
        return _downgrade_assessment(
            out,
            failure_kind="INVALID_SCHEMA",
            reason=f"Blocked contradictory assessment status fields: {status_contradiction}.",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )

    if not is_conclusive:
        if not cite_ok:
            return _downgrade_assessment(
                out,
                failure_kind="INVALID_CITATION",
                reason=f"Rejected unverified citation on non-conclusive assessment: {cite_err}.",
                citation_check="NOT_VERIFIED",
                citation_provenance=verified_citation_prov,
            )
        return _finalize_gate_output(
            out,
            final_status="UNDETERMINED",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )

    if not cite_ok:
        return _downgrade_assessment(
            out,
            failure_kind="INVALID_CITATION",
            reason=f"Blocked conclusive verdict because citation verification failed: {cite_err}.",
            citation_check="NOT_VERIFIED",
            citation_provenance=verified_citation_prov,
        )
    out["citation_check"] = verified_citation_check
    out["citation_provenance"] = verified_citation_prov

    # Gate 1 (Blocker D / P0-IV): Helper ownership, package, static/instance, dispatch, AST flow-slice, and SHA-256 verification.
    dep = analyze_flow_dependencies(record)
    if dep["has_unverified_helper_dependency"]:
        detail = "; ".join(dep["reasons"]) or "unverified helper dependency"
        return _downgrade_assessment(
            out,
            failure_kind="UNVERIFIED_HELPER_FLOW",
            reason=f"Blocked conclusive verdict due to unverified helper flow dependency: {detail}.",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )

    if cur_status == "SUPPORTED":
        return _finalize_gate_output(
            out,
            final_status="SUPPORTED",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )

    # Gate 2 (Blocker C / P0-III & P0-V): Single authoritative REFUTED gate.
    # NEVER authorizes REFUTED from heuristic `recommended_status` or heuristic/Qwen agreement alone.
    if record.get("issues"):
        return _downgrade_assessment(
            out,
            failure_kind="UNVERIFIED_REFUTATION",
            reason="Rejected REFUTED because evidence record carries unresolved completeness issues.",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )

    sig = record.get("heuristic_signals")
    if not isinstance(sig, dict):
        return _downgrade_assessment(
            out,
            failure_kind="UNVERIFIED_REFUTATION",
            reason="Rejected REFUTED because structural evidence signals are unavailable.",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )

    if dep.get("unresolved_calls") or dep.get("has_unverified_helper_dependency"):
        return _downgrade_assessment(
            out,
            failure_kind="UNVERIFIED_REFUTATION",
            reason="Rejected REFUTED because flow contains unresolved method calls.",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )

    p_path, lines_by_no = _verified_primary_map(record)
    if p_path is None or not lines_by_no:
        return _downgrade_assessment(
            out,
            failure_kind="UNVERIFIED_REFUTATION",
            reason="Rejected REFUTED because verified primary source lines are missing.",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )

    citations = out.get("citations") or []
    cited_primary_lines = {
        ln
        for c in citations
        if isinstance(c, dict) and c.get("path") == p_path and type(c.get("start_line")) is int and type(c.get("end_line")) is int
        for ln in range(c["start_line"], c["end_line"] + 1)
    }
    if not cited_primary_lines:
        return _downgrade_assessment(
            out,
            failure_kind="UNVERIFIED_REFUTATION",
            reason="Rejected REFUTED because no verified primary-file citation supports the refutation.",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )

    jctx = record.get("java_context") if isinstance(record.get("java_context"), dict) else {}
    enc = jctx.get("enclosing_method") if isinstance(jctx.get("enclosing_method"), dict) else None
    if not enc or type(enc.get("header_line")) is not int:
        return _downgrade_assessment(
            out,
            failure_kind="UNVERIFIED_REFUTATION",
            reason="Rejected REFUTED because enclosing method header boundary is unavailable for independent proof.",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )
    header_line = int(enc["header_line"])
    raw_sink_ln = sig.get("sink_line") if type(sig.get("sink_line")) is int else (record.get("start") or {}).get("line")
    if type(raw_sink_ln) is not int:
        return _downgrade_assessment(
            out,
            failure_kind="UNVERIFIED_REFUTATION",
            reason="Rejected REFUTED because sink line coordinate is unavailable for independent proof.",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )
    sink_line = int(raw_sink_ln)

    if _uses_cwe22_basename_or_unverified_normalize(record, sig, lines_by_no, header_line, sink_line):
        return _downgrade_assessment(
            out,
            failure_kind="UNVERIFIED_REFUTATION",
            reason=(
                "Rejected REFUTED: bare basename extraction (FilenameUtils.getName/getFileName) or "
                "non-canonical Path.normalize() without verified canonical directory containment is insufficient for CWE-22."
            ),
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )

    ok_proof, proof_detail = _verify_independent_refutation_proof(
        record,
        lines_by_no,
        header_line,
        sink_line,
        cited_primary_lines,
        p_path=p_path,
    )
    if not ok_proof:
        return _downgrade_assessment(
            out,
            failure_kind="UNVERIFIED_REFUTATION",
            reason=f"Rejected REFUTED: {proof_detail}.",
            citation_check=verified_citation_check,
            citation_provenance=verified_citation_prov,
        )

    out["independent_refutation_proof"] = proof_detail
    return _finalize_gate_output(
        out,
        final_status="REFUTED",
        citation_check=verified_citation_check,
        citation_provenance=verified_citation_prov,
    )
