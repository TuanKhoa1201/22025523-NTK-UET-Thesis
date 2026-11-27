"""Independent raw HTTP capture verifier for v2.triage Ollama runs.

Verifies that same-call raw HTTP request/response body artifacts (`*.request.body.bin`,
`*.response.body.bin` or `*.response.incomplete.bin`) and per-call receipts
(`*.http-capture.json`) match `evidence.json` and `assessments.jsonl` byte-for-byte
and SHA-256-for-SHA-256 without mutating run artifacts when `--output` or `--no-write` is used.

Scope note & trust-boundary contract (6 separated verification levels):
1. Capture integrity (`artifact_integrity_ok`, `capture_status` in normal mode): verifies
   same-call client-sent request bytes and client-received HTTP body bytes prior to
   UTF-8/JSON decoding, lengths, SHA-256 bindings, and absence of symlinks/orphans.
2. Metadata consistency (`prompt_metadata_binding`, `canonical_request_status`): verifies
   cross-artifact consistency across `evidence.json`, `assessments.jsonl`, receipts,
   and JSON sidecars plus fail-closed post-gate downgrade and OPEN review invariants.
3. Endpoint-reported protocol shape (`endpoint_reported_protocol_ok`): verifies non-mock
   HTTP 200 Ollama-shaped response fields and bound `/api/tags` + `ollama-tags-check.json`.
   This describes what the HTTP peer reported; a local loopback fixture can synthesize
   identical artifacts.
4. Verified live runtime origin (`live_origin_verified`, `live_chat_verified`): CANNOT be
   established by offline inspection of self-declared artifacts inside `<triage_dir>`.
   Because no independent trusted external runtime attestation exists in the current
   offline verifier architecture, `live_chat_verified` and `live_origin_verified` remain
   `False`, and `require_live_chat=True` (`--require-live-chat`) fails closed.
5. Independent model execution attestation (`independently_verified_model_runtime`): always `False`.
6. Security conclusion verification (`security_conclusion_verified`): always `False`.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime
import errno
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any

from .evidence import EvidenceError, StaleSourceError, digest, strict_json
from .ollama import (
    DEFAULT_PROMPT_CONTRACT,
    HISTORICAL_MULTILINE_PROMPT_VERSIONS,
    LEGACY_STEERED_PROMPT_VERSION,
    MAX_HTTP_BODY_BYTES,
    PREVIOUS_MINIMAL_SINGLELINE_PROMPT_VERSION,
    PREVIOUS_V225_PROMPT_VERSION,
    PROMPT_CONTRACTS,
    PROMPT_VERSION,
    SCHEMA,
    STATUSES,
    CaptureWriteError,
    _classify_failure,
    _extract_raw_model_status,
    _peek_raw_model_status_from_bytes,
    _template_fingerprint,
    _validate_lexical_dir_path,
    inspect_citations_provenance,
    is_reparse_link,
    request_payload,
    request_payload_for_version,
    validate_chat_response,
    verify_safe_directory_chain,
)

MAX_METADATA_JSON_BYTES = 16 * 1024 * 1024
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_HTTP_ORIGINS = frozenset({"unverified", "mock"})
_POST_GATE_RUNTIME_KEYS = frozenset({"answer_validated", "failure_kind", "validator_downgraded"})
_GATE_GOVERNED_HISTORICAL_VERSIONS = frozenset(
    {PREVIOUS_V225_PROMPT_VERSION, PREVIOUS_MINIMAL_SINGLELINE_PROMPT_VERSION}
)
_VERIFICATION_SCOPE = "offline_artifact_integrity_and_endpoint_reported_protocol_only"
_UNVERIFIED_LIVE_ORIGIN_REASON = (
    "UNVERIFIED_LIVE_RUNTIME_ORIGIN: offline artifact inspection inside triage_dir cannot "
    "prove that the HTTP endpoint was genuine Ollama rather than a local loopback fixture; "
    "self-declared HTTP/tags/scan_provenance metadata cannot establish live runtime origin "
    "without operator-controlled external runtime evidence outside triage_dir"
)


def _strict_eq(a: Any, b: Any) -> bool:
    """Deep equality that also enforces exact scalar types (distinguishing bool vs int)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        if a.keys() != b.keys():
            return False
        return all(_strict_eq(a[k], b[k]) for k in a)
    if isinstance(a, list):
        if len(a) != len(b):
            return False
        return all(_strict_eq(x, y) for x, y in zip(a, b))
    return a == b


def _is_finite_nonneg_number(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _parse_iso_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt


def _valid_response_headers(headers: Any) -> bool:
    if not isinstance(headers, list) or not headers:
        return False
    for entry in headers:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            return False
        name, val = entry
        if not isinstance(name, str) or not name.strip() or not isinstance(val, str):
            return False
    return True


def _check_endpoint_reported_scan_provenance(sp: Any) -> tuple[bool, str | None]:
    """Check self-declared scan_provenance structure for Level-3 protocol completeness only.

    A local fixture can write identical fields into evidence.json; this helper MUST NEVER
    be treated as independent proof of live runtime origin.
    """
    if not isinstance(sp, dict):
        return False, "missing scan_provenance object"
    if sp.get("source_capture_verified") is not True:
        return False, "scan_provenance.source_capture_verified is not True"
    if sp.get("exit_capture_verified") is not True:
        return False, "scan_provenance.exit_capture_verified is not True"
    origin = sp.get("origin")
    if origin != "recorded_capture_unsigned":
        return False, f"scan_provenance.origin ({origin!r}) is not 'recorded_capture_unsigned'"
    producer = sp.get("producer")
    if not isinstance(producer, str) or not producer.strip():
        return False, "scan_provenance.producer is missing or blank"
    prod_low = producer.lower()
    if "mock" in prod_low or "unit_test" in prod_low:
        return False, f"scan_provenance.producer ({producer!r}) indicates mock/unit-test fixture"
    man_sha = sp.get("manifest_sha256")
    if not isinstance(man_sha, str) or not _HEX64_RE.fullmatch(man_sha):
        return False, f"scan_provenance.manifest_sha256 ({man_sha!r}) is not a valid SHA-256 hex digest"
    return True, None


def _safe_id(finding_id: Any) -> str:
    return re.sub(r"[^0-9a-fA-F_-]", "_", str(finding_id or "unknown"))[:80]


def _is_strict_basename(name: Any) -> bool:
    if not isinstance(name, str) or not name or name in (".", ".."):
        return False
    if "/" in name or "\\" in name or ":" in name or "\x00" in name:
        return False
    p = Path(name)
    if p.is_absolute() or bool(p.drive) or p.name != name:
        return False
    return True


def _safe_regular_child_file(
    parent_dir: Path,
    resolved_parent: Path,
    filename: Any,
    *,
    max_bytes: int | None,
    label: str,
    errors: list[str],
) -> Path | None:
    if not _is_strict_basename(filename):
        errors.append(f"{label} uses unsafe non-basename artifact path: {filename!r}")
        return None
    candidate = parent_dir / filename
    if not os.path.lexists(candidate):
        errors.append(f"missing {label}: {filename}")
        return None
    try:
        if is_reparse_link(candidate):
            errors.append(f"{label} {filename} must not be a symlink or junction")
            return None
        st = os.lstat(candidate)
        if not stat.S_ISREG(st.st_mode):
            errors.append(f"{label} {filename} is not a regular file")
            return None
        resolved = candidate.resolve(strict=True)
        if resolved.parent != resolved_parent or resolved.name != filename:
            errors.append(f"{label} {filename} resolves outside allowed capture directory: {resolved}")
            return None
        if max_bytes is not None and st.st_size > max_bytes:
            errors.append(f"{label} {filename} exceeds byte bound ({st.st_size} > {max_bytes})")
            return None
    except (OSError, CaptureWriteError, RuntimeError) as exc:
        errors.append(f"cannot verify {label} {filename}: {exc}")
        return None
    return candidate


_TAGS_RECEIPT_RE = re.compile(r"tags-\d{4}\.http-capture\.json")


_EMPTY_CITATION_PROVENANCE = {
    "citation_in_source": False,
    "citation_in_prompt": False,
    "citation_posthoc_only": False,
    "supports_security_claim_verified": False,
}

_V224_HELPER_REASON_PREFIX = "Blocked conclusive verdict due to unverified helper flow dependency: "
_V224_HELPER_COUNT_CLAUSE_RE = re.compile(r"^(?:helper_hash_mismatch|max_hop_depth_exceeded) \(([1-9][0-9]*)\)$")
_V224_HELPER_LIST_CLAUSE_RE = re.compile(
    r"^(?:dropped_same_file_helpers|unresolved_calls|unverified_decisive_calls) \(\[([^\]]+)\]\)$"
)
_V224_HELPER_IDENT_RE = re.compile(r"^'([A-Za-z_$][A-Za-z0-9_$]*|<init>)'$")


def _load_authoritative_layer1_validator():
    """Load the single authoritative Layer-1 response validator and failure classifier."""
    return validate_chat_response, _classify_failure


def _recompute_layer1_decision(
    rec: Any,
    parsed_raw: Any,
    *,
    expected_model: Any,
    prompt_version: str | None,
) -> dict[str, Any]:
    """Independently re-run authoritative Layer-1 validation (`validate_chat_response` + `_classify_failure`)
    solely from locked `evidence.json` record and SHA-256-verified raw HTTP JSON response.

    NEVER trusts self-declared sidecar or assessment metadata to decide whether Layer-1 accepted or rejected.
    NEVER bypasses `check_current(record)` or mutates `record["root"]`.
    Explicitly separates verification-time source unavailability/drift (`StaleSourceError`) from
    model/content rejection (`EvidenceError`) so environment drift is never misattributed to model output.
    """
    if not isinstance(rec, dict):
        return {
            "outcome": "UNAVAILABLE",
            "error": "missing locked evidence record for independent Layer-1 validation",
        }
    if not isinstance(expected_model, str) or not expected_model.strip():
        return {
            "outcome": "UNAVAILABLE",
            "error": "missing expected model identifier for independent Layer-1 validation",
        }
    loaded = _load_authoritative_layer1_validator()
    if (
        not isinstance(loaded, tuple)
        or len(loaded) != 2
        or not callable(loaded[0])
        or not callable(loaded[1])
    ):
        return {
            "outcome": "UNAVAILABLE",
            "error": "authoritative Layer-1 validator unavailable for independent verification",
        }
    validate_fn, classify_fn = loaded
    try:
        answer = validate_fn(
            parsed_raw,
            copy.deepcopy(rec),
            expected_model=expected_model,
            prompt_version=prompt_version,
        )
    except StaleSourceError as exc:
        return {
            "outcome": "SOURCE_UNAVAILABLE_OR_DRIFTED",
            "error": str(exc),
            "stale_source": exc.to_dict(),
        }
    except (EvidenceError, ValueError, TypeError, UnicodeError) as exc:
        try:
            fk = classify_fn(exc, http_status=200, error_body_text="")
        except Exception as c_exc:
            return {
                "outcome": "UNAVAILABLE",
                "error": f"authoritative Layer-1 failure classifier failed: {c_exc}",
            }
        return {
            "outcome": "REJECTED",
            "failure_kind": fk,
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "outcome": "UNAVAILABLE",
            "error": f"independent Layer-1 validation raised unexpected error: {exc}",
        }
    if not isinstance(answer, dict):
        return {
            "outcome": "UNAVAILABLE",
            "error": "authoritative Layer-1 validator returned non-object result",
        }
    return {
        "outcome": "ACCEPTED",
        "answer": answer,
    }


def _load_authoritative_integration_gate():
    """Load the single authoritative integration gate without creating top-level import cycles."""
    try:
        from v2.api.triage_gate import apply_integration_gate
    except Exception:
        return None
    return apply_integration_gate


def _recompute_post_gate_decision(
    rec: Any,
    *,
    raw_status: str,
    raw_expl: str,
    raw_fix: str,
    raw_cites: list[Any],
    sidecar_runtime: dict[str, Any] | None,
    prompt_version: str | None,
    citation_provenance: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Deterministically re-run apply_integration_gate from locked evidence and Layer-1-verified output."""
    if not isinstance(rec, dict):
        return None, "missing locked evidence record for independent integration gate recomputation"
    gate_fn = _load_authoritative_integration_gate()
    if gate_fn is None:
        return None, "authoritative integration gate unavailable for independent downgrade verification"
    rt_for_gate = copy.deepcopy(sidecar_runtime) if isinstance(sidecar_runtime, dict) else {}
    rt_for_gate["answer_validated"] = True
    rt_for_gate["failure_kind"] = "NONE"
    pre_gate: dict[str, Any] = {
        "status": raw_status,
        "raw_model_status": raw_status,
        "validated_status": raw_status,
        "validator_downgraded": False,
        "failure_kind": "NONE",
        "explanation": raw_expl,
        "fix_suggestion": raw_fix,
        "citations": copy.deepcopy(raw_cites),
        "citation_check": "MATCHED" if raw_cites else "NONE",
        "security_conclusion_verified": False,
        "requires_human_review": True,
        "runtime": rt_for_gate,
    }
    if isinstance(citation_provenance, dict):
        pre_gate["citation_provenance"] = copy.deepcopy(citation_provenance)
    if isinstance(prompt_version, str) and prompt_version.strip():
        pre_gate["prompt_version"] = prompt_version
    try:
        gated = gate_fn(copy.deepcopy(rec), pre_gate)
    except Exception as exc:
        return None, f"independent integration gate recomputation failed: {exc}"
    if not isinstance(gated, dict):
        return None, "independent integration gate returned non-object result"
    return gated, None


def _recompute_error_gate_decision(
    rec: Any,
    *,
    sidecar_error: str,
    raw_model_status: str | None,
    sidecar_runtime: dict[str, Any] | None,
    prompt_version: str | None,
    raw_response: Any,
    authoritative_failure_kind: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Deterministically re-run apply_integration_gate on a Layer-1 undecided() error assessment."""
    if not isinstance(rec, dict):
        return None, "missing locked evidence record for error-branch gate recomputation"
    gate_fn = _load_authoritative_integration_gate()
    if gate_fn is None:
        return None, "authoritative integration gate unavailable for error-branch downgrade verification"
    if isinstance(authoritative_failure_kind, str) and authoritative_failure_kind:
        eff_fk = authoritative_failure_kind
    else:
        s_fk = sidecar_runtime.get("failure_kind") if isinstance(sidecar_runtime, dict) else None
        eff_fk = s_fk if isinstance(s_fk, str) and s_fk else "UNDETERMINED_FALLBACK"
    rt_for_gate = copy.deepcopy(sidecar_runtime) if isinstance(sidecar_runtime, dict) else {}
    rt_for_gate["answer_validated"] = False
    rt_for_gate["failure_kind"] = eff_fk
    pre_gate_err: dict[str, Any] = {
        "status": "UNDETERMINED",
        "raw_model_status": raw_model_status,
        "validated_status": "UNDETERMINED",
        "validator_downgraded": bool(raw_model_status in STATUSES and raw_model_status != "UNDETERMINED"),
        "failure_kind": eff_fk,
        "explanation": sidecar_error,
        "citations": [],
        "fix_suggestion": "",
        "citation_check": "NOT_VERIFIED",
        "citation_provenance": dict(_EMPTY_CITATION_PROVENANCE),
        "raw_response": copy.deepcopy(raw_response),
        "security_conclusion_verified": False,
        "requires_human_review": True,
        "runtime": rt_for_gate,
    }
    if isinstance(prompt_version, str) and prompt_version.strip():
        pre_gate_err["prompt_version"] = prompt_version
    try:
        gated = gate_fn(copy.deepcopy(rec), pre_gate_err)
    except Exception as exc:
        return None, f"error-branch integration gate recomputation failed: {exc}"
    if not isinstance(gated, dict):
        return None, "error-branch integration gate returned non-object result"
    return gated, None


def _verify_historical_v224_helper_downgrade_reason(dr: Any, rec: Any) -> bool:
    """Strict formal-grammar and locked-source identifier grounding check for historical v2.2.4 UNVERIFIED_HELPER_FLOW only.

    Historical v2.2.4 captures were produced before G3 expanded the JDK/JDBC stdlib allowlist in java_context_v2.py,
    so current apply_integration_gate() no longer downgrades those stdlib calls. This helper verifies that every clause
    matches the exact closed java_context_v2.py reason grammar and that every cited Java identifier appears in the
    locked evidence snippets, preventing arbitrary free-text injection.
    """
    if not isinstance(dr, str) or not isinstance(rec, dict):
        return False
    if not (dr.startswith(_V224_HELPER_REASON_PREFIX) and dr.endswith(".")):
        return False
    body = dr[len(_V224_HELPER_REASON_PREFIX) : -1]
    if not body:
        return False
    clauses = body.split("; ")
    if not clauses or len(clauses) > 5:
        return False
    src_text = "\n".join(
        ln.get("text", "")
        for sn in (rec.get("snippets") or [])
        if isinstance(sn, dict)
        for ln in (sn.get("lines") or [])
        if isinstance(ln, dict) and isinstance(ln.get("text"), str)
    )
    if not src_text:
        return False
    for clause in clauses:
        if _V224_HELPER_COUNT_CLAUSE_RE.fullmatch(clause):
            continue
        m_list = _V224_HELPER_LIST_CLAUSE_RE.fullmatch(clause)
        if not m_list:
            return False
        raw_items = m_list.group(1).split(", ")
        if not raw_items or len(raw_items) > 4:
            return False
        for item in raw_items:
            m_ident = _V224_HELPER_IDENT_RE.fullmatch(item)
            if not m_ident:
                return False
            ident = m_ident.group(1)
            if ident == "<init>":
                if not re.search(r"\bnew\s+", src_text):
                    return False
            else:
                if not re.search(rf"\b{re.escape(ident)}\b", src_text):
                    return False
    return True


def _verify_citation_provenance_field(
    idx: int,
    assessment: dict[str, Any],
    expected_prov: dict[str, bool],
    item_errors: list[str],
) -> None:
    """Validate `assessment.citation_provenance` whenever declared against computed provenance."""
    if "citation_provenance" not in assessment:
        return
    cp = assessment.get("citation_provenance")
    if not isinstance(cp, dict):
        item_errors.append(
            f"finding[{idx}] assessment.citation_provenance must be a JSON object, got {type(cp).__name__}"
        )
        return
    for key in (
        "citation_in_source",
        "citation_in_prompt",
        "citation_posthoc_only",
        "supports_security_claim_verified",
    ):
        val = cp.get(key)
        if type(val) is not bool:
            item_errors.append(
                f"finding[{idx}] assessment.citation_provenance.{key} must be boolean, got {val!r}"
            )
            continue
        if key == "supports_security_claim_verified" and val is not False:
            item_errors.append(
                f"finding[{idx}] assessment.citation_provenance.supports_security_claim_verified must be False"
            )
        elif val is not expected_prov[key]:
            item_errors.append(
                f"finding[{idx}] assessment.citation_provenance.{key} ({val!r}) disagrees with verified citation provenance ({expected_prov[key]!r})"
            )


def _verify_citations_against_evidence(
    idx: int,
    citations: list[Any],
    rec: Any,
    *,
    prompt_version: str | None,
    require_relevant_scope: bool,
    item_errors: list[str],
) -> dict[str, bool] | None:
    """Re-verify non-empty citations against locked source/prompt snapshots using ollama.inspect_citations_provenance."""
    if not isinstance(rec, dict):
        item_errors.append(f"finding[{idx}] cannot verify citations without evidence record object")
        return None
    try:
        prov = inspect_citations_provenance(citations, rec, prompt_version=prompt_version)
    except Exception as exc:
        item_errors.append(f"finding[{idx}] citation provenance verification error: {exc}")
        return None

    if prov.get("contract_error"):
        item_errors.append(f"finding[{idx}] citation contract violation: {prov['contract_error']}")
    for c_idx, it in enumerate(prov.get("items") or []):
        if isinstance(it, dict) and it.get("error"):
            item_errors.append(f"finding[{idx}] citation[{c_idx}] failed source/prompt verification: {it['error']}")
    if prov.get("citation_in_source") is not True:
        item_errors.append(f"finding[{idx}] citations do not match locked source evidence")
    if prov.get("citation_in_prompt") is not True or prov.get("citation_posthoc_only") is True:
        item_errors.append(f"finding[{idx}] citations were not supplied in locked model prompt")
    if prov.get("all_executable_code") is not True:
        item_errors.append(f"finding[{idx}] citations must reference executable Java code")
    if prov.get("any_dead_branch") is True:
        item_errors.append(f"finding[{idx}] citations reference unreachable dead-branch code")
    if require_relevant_scope and prov.get("any_in_relevant_scope") is not True:
        item_errors.append(f"finding[{idx}] conclusive citations lie outside enclosing method and dataflow trace scope")
    return {
        "citation_in_source": bool(prov.get("citation_in_source")),
        "citation_in_prompt": bool(prov.get("citation_in_prompt")),
        "citation_posthoc_only": bool(prov.get("citation_posthoc_only")),
        "supports_security_claim_verified": False,
    }


def _verify_empty_undetermined_assessment(
    idx: int,
    assessment: dict[str, Any],
    *,
    require_v226_fields: bool,
    expected_raw_model_status: str | None,
    item_errors: list[str],
    context_label: str,
    sidecar_error: str | None = None,
    allowed_error_gate_doc: dict[str, Any] | None = None,
) -> None:
    """Enforce fail-closed UNDETERMINED assessment content invariants when no verified citations exist."""
    if assessment.get("status") != "UNDETERMINED":
        item_errors.append(
            f"finding[{idx}] ({context_label}) unvalidated/fail-closed assessment.status must be 'UNDETERMINED', got {assessment.get('status')!r}"
        )
    if require_v226_fields or "validated_status" in assessment:
        if "validated_status" not in assessment:
            item_errors.append(
                f"finding[{idx}] ({context_label}) assessment missing required validated_status field"
            )
        elif assessment.get("validated_status") != "UNDETERMINED":
            item_errors.append(
                f"finding[{idx}] ({context_label}) assessment.validated_status must be 'UNDETERMINED', got {assessment.get('validated_status')!r}"
            )
    if require_v226_fields or "raw_model_status" in assessment or expected_raw_model_status is not None:
        if "raw_model_status" not in assessment:
            item_errors.append(
                f"finding[{idx}] ({context_label}) assessment missing required raw_model_status field"
            )
        elif not _strict_eq(assessment.get("raw_model_status"), expected_raw_model_status):
            item_errors.append(
                f"finding[{idx}] ({context_label}) assessment.raw_model_status ({assessment.get('raw_model_status')!r}) "
                f"!= expected raw HTTP model status ({expected_raw_model_status!r})"
            )
    if "independent_refutation_proof" in assessment and assessment.get("independent_refutation_proof") is not None:
        item_errors.append(
            f"finding[{idx}] ({context_label}) unvalidated/fail-closed assessment must not declare independent_refutation_proof"
        )
    expected_vd = (
        True
        if (isinstance(allowed_error_gate_doc, dict) and allowed_error_gate_doc.get("validator_downgraded") is True)
        else bool(expected_raw_model_status in STATUSES and expected_raw_model_status != "UNDETERMINED")
    )
    if "validator_downgraded" in assessment:
        if type(assessment.get("validator_downgraded")) is not bool:
            item_errors.append(
                f"finding[{idx}] ({context_label}) assessment.validator_downgraded must be boolean, got {assessment.get('validator_downgraded')!r}"
            )
        elif expected_vd is False and assessment.get("validator_downgraded") is True:
            item_errors.append(
                f"finding[{idx}] ({context_label}) assessment.validator_downgraded must be False without a verifiable conclusive/gate downgrade"
            )
    if "downgrade_reason" in assessment and assessment.get("downgrade_reason") is not None:
        dr_val = assessment.get("downgrade_reason")
        allowed_l1_unref_dr = (
            assessment.get("failure_kind") == "UNVERIFIED_REFUTATION"
            and expected_raw_model_status == "REFUTED"
            and isinstance(sidecar_error, str)
            and bool(sidecar_error.strip())
            and _strict_eq(dr_val, sidecar_error.strip())
        )
        allowed_gate_err_dr = (
            isinstance(allowed_error_gate_doc, dict)
            and allowed_error_gate_doc.get("validator_downgraded") is True
            and isinstance(allowed_error_gate_doc.get("downgrade_reason"), str)
            and _strict_eq(dr_val, allowed_error_gate_doc.get("downgrade_reason"))
            and _strict_eq(assessment.get("explanation"), allowed_error_gate_doc.get("explanation"))
            and _strict_eq(assessment.get("failure_kind"), allowed_error_gate_doc.get("failure_kind"))
        )
        if not (allowed_l1_unref_dr or allowed_gate_err_dr):
            item_errors.append(
                f"finding[{idx}] ({context_label}) assessment.downgrade_reason ({dr_val!r}) is ungrounded for this unvalidated/error branch"
            )
    if require_v226_fields or "explanation" in assessment:
        expl = assessment.get("explanation")
        if not isinstance(expl, str) or not expl.strip():
            item_errors.append(
                f"finding[{idx}] ({context_label}) assessment.explanation must be a non-empty string, got {expl!r}"
            )
    if require_v226_fields or "fix_suggestion" in assessment:
        fix = assessment.get("fix_suggestion")
        if not isinstance(fix, str) or fix != "":
            item_errors.append(
                f"finding[{idx}] ({context_label}) unvalidated/fail-closed assessment.fix_suggestion must be empty string, got {fix!r}"
            )
    if require_v226_fields or "citations" in assessment:
        cites = assessment.get("citations")
        if not isinstance(cites, list) or len(cites) != 0:
            item_errors.append(
                f"finding[{idx}] ({context_label}) unvalidated/fail-closed assessment.citations must be empty list, got {cites!r}"
            )
    if require_v226_fields or "citation_check" in assessment:
        cc = assessment.get("citation_check")
        if cc != "NOT_VERIFIED":
            item_errors.append(
                f"finding[{idx}] ({context_label}) unvalidated/fail-closed assessment.citation_check must be 'NOT_VERIFIED', got {cc!r}"
            )
    _verify_citation_provenance_field(idx, assessment, _EMPTY_CITATION_PROVENANCE, item_errors)


def _is_gate_error_downgrade_transition(
    gated_doc: dict[str, Any] | None,
    sidecar_error: str | None,
) -> bool:
    """Return True when apply_integration_gate() transformed a Layer-1 error via _downgrade_assessment()."""
    if not isinstance(gated_doc, dict) or not isinstance(sidecar_error, str):
        return False
    dr = gated_doc.get("downgrade_reason")
    expl = gated_doc.get("explanation")
    return (
        gated_doc.get("validator_downgraded") is True
        and isinstance(dr, str)
        and bool(dr.strip())
        and isinstance(expl, str)
        and expl != sidecar_error
    )


def _verify_assessment_against_recomputed_gate(
    idx: int,
    rec: Any,
    assessment: dict[str, Any],
    runtime: dict[str, Any],
    expected_gated: dict[str, Any],
    *,
    raw_status: str,
    raw_expl: str,
    raw_fix: str,
    raw_cites: list[Any],
    recorded_prompt_version: str | None,
    is_historical_ver: bool,
    item_errors: list[str],
) -> tuple[str, str]:
    """Single authoritative comparator binding a Layer-1-accepted assessment to recomputed Integration Gate output.

    Enforces the exact same contract regardless of whether `assessment` claims clean (`SUPPORTED`/`REFUTED`/`UNDETERMINED`)
    or downgraded (`UNDETERMINED`): the recomputed Gate decision determines the required output state, never vice versa.
    Returns `(integration_gate_verification, post_gate_downgrade_verification)`.
    """
    pre_err_cnt = len(item_errors)
    ass_status = assessment.get("status")
    ass_val_status = assessment.get("validated_status", ass_status)
    gate_downgraded = expected_gated.get("validator_downgraded") is True
    exp_status = expected_gated.get("validated_status")
    exp_fk = expected_gated.get("failure_kind")
    exp_dr = expected_gated.get("downgrade_reason")
    exp_expl = expected_gated.get("explanation")
    exp_fix = expected_gated.get("fix_suggestion")
    exp_cites = expected_gated.get("citations") if isinstance(expected_gated.get("citations"), list) else []
    exp_cc = expected_gated.get("citation_check")
    exp_proof = expected_gated.get("independent_refutation_proof")

    if "fix_suggestion" not in assessment or not _strict_eq(assessment.get("fix_suggestion"), exp_fix):
        item_errors.append(
            f"finding[{idx}] assessment.fix_suggestion disagrees with locked raw HTTP / Integration Gate fix_suggestion"
        )

    if not gate_downgraded:
        # Gate authorized clean pass (SUPPORTED, REFUTED, or UNDETERMINED).
        if runtime.get("answer_validated") is not True:
            item_errors.append(
                f"finding[{idx}] assessment claims unvalidated/downgraded state (answer_validated={runtime.get('answer_validated')!r}), "
                f"but independent Integration Gate recomputation authorized clean validated_status={exp_status!r} (failure_kind={exp_fk!r})"
            )
        if ass_status != exp_status or ass_val_status != exp_status:
            item_errors.append(
                f"finding[{idx}] assessment status ({ass_status!r}/{assessment.get('validated_status')!r}) "
                f"!= independently recomputed Integration Gate status ({exp_status!r})"
            )
        if "validator_downgraded" in assessment and assessment.get("validator_downgraded") is not False:
            item_errors.append(
                f"finding[{idx}] assessment.validator_downgraded ({assessment.get('validator_downgraded')!r}) must be False when Gate authorizes clean {exp_status!r}"
            )
        if "validator_downgraded" in runtime and runtime.get("validator_downgraded") is not False:
            item_errors.append(
                f"finding[{idx}] assessment.runtime.validator_downgraded ({runtime.get('validator_downgraded')!r}) must be False when Gate authorizes clean {exp_status!r}"
            )
        if "failure_kind" in assessment and assessment.get("failure_kind") != "NONE":
            item_errors.append(
                f"finding[{idx}] assessment.failure_kind ({assessment.get('failure_kind')!r}) must be 'NONE' when Gate authorizes clean {exp_status!r}"
            )
        if "downgrade_reason" in assessment and assessment.get("downgrade_reason") is not None:
            item_errors.append(
                f"finding[{idx}] clean Gate-authorized assessment must not declare non-null downgrade_reason ({assessment.get('downgrade_reason')!r})"
            )
        if "explanation" not in assessment or not _strict_eq(assessment.get("explanation"), exp_expl):
            item_errors.append(
                f"finding[{idx}] clean assessment.explanation disagrees with locked raw HTTP / Gate explanation"
            )
        if exp_status == "REFUTED":
            if (not is_historical_ver) or ("independent_refutation_proof" in assessment):
                if (
                    "independent_refutation_proof" not in assessment
                    or not isinstance(exp_proof, str)
                    or not exp_proof.strip()
                    or not _strict_eq(assessment.get("independent_refutation_proof"), exp_proof)
                ):
                    item_errors.append(
                        f"finding[{idx}] clean REFUTED assessment.independent_refutation_proof "
                        f"({assessment.get('independent_refutation_proof')!r}) missing or != independently recomputed Gate proof ({exp_proof!r})"
                    )
        else:
            if "independent_refutation_proof" in assessment and assessment.get("independent_refutation_proof") is not None:
                item_errors.append(
                    f"finding[{idx}] non-REFUTED ({exp_status}) assessment must not declare independent_refutation_proof ({assessment.get('independent_refutation_proof')!r})"
                )
        ass_cites = assessment.get("citations")
        if "citations" not in assessment or not isinstance(ass_cites, list):
            item_errors.append(f"finding[{idx}] assessment.citations missing or not a list")
        elif not _strict_eq(ass_cites, exp_cites):
            item_errors.append(
                f"finding[{idx}] clean assessment.citations disagrees with locked raw HTTP / Gate citations"
            )
        if raw_status != "UNDETERMINED" and len(exp_cites) == 0:
            item_errors.append(
                f"finding[{idx}] conclusive validated assessment ({raw_status}) requires at least one citation"
            )
        if not _strict_eq(assessment.get("citation_check"), exp_cc):
            item_errors.append(
                f"finding[{idx}] clean assessment.citation_check ({assessment.get('citation_check')!r}) "
                f"!= independently recomputed Gate citation_check ({exp_cc!r})"
            )
        if isinstance(ass_cites, list) and len(ass_cites) > 0:
            exp_prov = _verify_citations_against_evidence(
                idx,
                ass_cites,
                rec,
                prompt_version=recorded_prompt_version,
                require_relevant_scope=(raw_status != "UNDETERMINED"),
                item_errors=item_errors,
            )
            if exp_prov is not None:
                _verify_citation_provenance_field(idx, assessment, exp_prov, item_errors)
        elif isinstance(ass_cites, list):
            _verify_citation_provenance_field(idx, assessment, _EMPTY_CITATION_PROVENANCE, item_errors)

        if len(item_errors) == pre_err_cnt:
            return "RECOMPUTED_EXACT_MATCH", "NOT_APPLICABLE"
        return "FAILED_RECOMPUTATION_MISMATCH", "FAILED_RECOMPUTATION_MISMATCH"

    # Gate mandated fail-closed downgrade to UNDETERMINED.
    if runtime.get("answer_validated") is not False:
        item_errors.append(
            f"finding[{idx}] assessment disagrees with independent Integration Gate recomputation: "
            f"Gate requires fail-closed downgrade to 'UNDETERMINED' (failure_kind={exp_fk!r}), "
            f"but assessment claimed status={ass_status!r}, validated_status={assessment.get('validated_status')!r}, "
            f"answer_validated={runtime.get('answer_validated')!r}"
        )
    if ass_status != "UNDETERMINED" or ass_val_status != "UNDETERMINED":
        item_errors.append(
            f"finding[{idx}] assessment status ({ass_status!r}/{assessment.get('validated_status')!r}) "
            f"must fail closed to 'UNDETERMINED' per independent Integration Gate recomputation (failure_kind={exp_fk!r})"
        )
    if assessment.get("validator_downgraded") is not True or runtime.get("validator_downgraded") is not True:
        item_errors.append(
            f"finding[{idx}] Gate-downgraded assessment must set validator_downgraded=True in both assessment and runtime"
        )
    if not _strict_eq(assessment.get("failure_kind"), exp_fk):
        item_errors.append(
            f"finding[{idx}] post-gate assessment.failure_kind ({assessment.get('failure_kind')!r}) "
            f"!= independently recomputed Gate failure_kind ({exp_fk!r})"
        )
    if not _strict_eq(assessment.get("downgrade_reason"), exp_dr):
        item_errors.append(
            f"finding[{idx}] post-gate assessment.downgrade_reason ({assessment.get('downgrade_reason')!r}) "
            f"!= independently recomputed Gate downgrade_reason ({exp_dr!r})"
        )
    if not _strict_eq(assessment.get("explanation"), exp_expl):
        item_errors.append(
            f"finding[{idx}] post-gate assessment.explanation disagrees with independently recomputed Gate explanation"
        )
    if "independent_refutation_proof" in assessment and assessment.get("independent_refutation_proof") is not None:
        item_errors.append(
            f"finding[{idx}] post-gate downgraded assessment must not declare independent_refutation_proof"
        )
    ass_cites = assessment.get("citations")
    if not isinstance(ass_cites, list):
        item_errors.append(f"finding[{idx}] post-gate downgraded assessment.citations must be a list")
        return "FAILED_RECOMPUTATION_MISMATCH", "FAILED_RECOMPUTATION_MISMATCH"
    if not _strict_eq(ass_cites, exp_cites):
        item_errors.append(
            f"finding[{idx}] post-gate downgraded assessment.citations ({exp_fk}) disagrees with independently recomputed Gate citations"
        )
    if not _strict_eq(assessment.get("citation_check"), exp_cc):
        item_errors.append(
            f"finding[{idx}] post-gate downgraded assessment.citation_check ({assessment.get('citation_check')!r}) "
            f"!= independently recomputed Gate citation_check ({exp_cc!r})"
        )
    if exp_fk == "INVALID_CITATION":
        if "raw_model_citations" in assessment and not _strict_eq(assessment.get("raw_model_citations"), raw_cites):
            item_errors.append(
                f"finding[{idx}] post-gate assessment.raw_model_citations disagrees with raw HTTP model citations"
            )
        _verify_citation_provenance_field(idx, assessment, _EMPTY_CITATION_PROVENANCE, item_errors)
    elif len(ass_cites) > 0:
        exp_prov = _verify_citations_against_evidence(
            idx,
            ass_cites,
            rec,
            prompt_version=recorded_prompt_version,
            require_relevant_scope=(raw_status != "UNDETERMINED"),
            item_errors=item_errors,
        )
        if exp_prov is not None:
            _verify_citation_provenance_field(idx, assessment, exp_prov, item_errors)
    else:
        _verify_citation_provenance_field(idx, assessment, _EMPTY_CITATION_PROVENANCE, item_errors)

    if len(item_errors) == pre_err_cnt:
        return "RECOMPUTED_EXACT_MATCH", "RECOMPUTED_EXACT_MATCH"
    return "FAILED_RECOMPUTATION_MISMATCH", "FAILED_RECOMPUTATION_MISMATCH"


def _verify_http200_parsed_assessment_content(
    idx: int,
    rec: Any,
    assessment: dict[str, Any],
    runtime: dict[str, Any],
    parsed_raw: Any,
    *,
    expected_model: Any,
    sidecar_answer_validated: bool | None,
    sidecar_runtime: dict[str, Any] | None,
    sidecar_error: str | None,
    recomputed_error_gate_doc: dict[str, Any] | None,
    recomputed_error_gate_err: str | None,
    is_legal_post_gate_downgrade: bool,
    recorded_prompt_version: str | None,
    is_historical_ver: bool,
    item_errors: list[str],
) -> tuple[str, str, str]:
    """Independently verify the full chain:
    Raw HTTP Response + Evidence -> Layer-1 Validator (`validate_chat_response` + `_classify_failure`)
    -> Sidecar Binding -> Integration Gate (`apply_integration_gate`) -> Final Assessment.

    Branch selection is governed strictly by the independently recomputed Layer-1 outcome and
    prompt-version contract, NEVER allowing self-declared `sidecar.runtime.answer_validated`,
    `sidecar.runtime.failure_kind`, `sidecar.error`, `assessment.status`, or
    `assessment.runtime.answer_validated` to opt out of Layer-1 or Integration Gate verification.

    Returns `(layer1_verification, integration_gate_verification, post_gate_downgrade_verification)`.
    """
    require_v226_fields = not is_historical_ver
    raw_content: str | None = None
    if (
        isinstance(parsed_raw, dict)
        and isinstance(parsed_raw.get("message"), dict)
        and isinstance(parsed_raw["message"].get("content"), str)
    ):
        raw_content = parsed_raw["message"]["content"]

    expected_raw_model_status = _extract_raw_model_status(raw_content)
    parsed_msg_doc: dict[str, Any] | None = None
    if isinstance(raw_content, str):
        try:
            cand_doc = strict_json(raw_content)
            if isinstance(cand_doc, dict):
                parsed_msg_doc = cand_doc
        except (ValueError, TypeError, EvidenceError):
            parsed_msg_doc = None

    ass_status = assessment.get("status")
    if not isinstance(ass_status, str) or ass_status not in STATUSES:
        item_errors.append(f"finding[{idx}] assessment.status must be one of {STATUSES}, got {ass_status!r}")
    if require_v226_fields or "validated_status" in assessment:
        val_status = assessment.get("validated_status")
        if "validated_status" not in assessment:
            item_errors.append(f"finding[{idx}] assessment missing required validated_status field")
        elif not isinstance(val_status, str) or val_status not in STATUSES:
            item_errors.append(
                f"finding[{idx}] assessment.validated_status must be one of {STATUSES}, got {val_status!r}"
            )

    if (
        require_v226_fields
        or sidecar_answer_validated is True
        or runtime.get("answer_validated") is True
        or expected_raw_model_status is not None
        or "raw_model_status" in assessment
    ):
        if "raw_model_status" not in assessment:
            item_errors.append(f"finding[{idx}] assessment missing required raw_model_status field")
        elif not _strict_eq(assessment.get("raw_model_status"), expected_raw_model_status):
            item_errors.append(
                f"finding[{idx}] assessment.raw_model_status ({assessment.get('raw_model_status')!r}) "
                f"!= raw HTTP model status ({expected_raw_model_status!r})"
            )

    # Independent authoritative Layer-1 recomputation from locked evidence.json + SHA-256-verified raw HTTP JSON.
    l1_res = _recompute_layer1_decision(
        rec,
        parsed_raw,
        expected_model=expected_model,
        prompt_version=recorded_prompt_version,
    )
    l1_outcome = l1_res.get("outcome")

    if l1_outcome == "SOURCE_UNAVAILABLE_OR_DRIFTED":
        item_errors.append(
            f"finding[{idx}] independent Layer-1 verification failed closed: source root unavailable or "
            f"drifted at verification time (environment/source-freshness limit, NOT attributed to historical model output): "
            f"{l1_res.get('error')}"
        )
        return (
            "FAILED_SOURCE_UNAVAILABLE_OR_DRIFTED",
            "FAILED_LAYER1_SOURCE_UNAVAILABLE",
            "FAILED_LAYER1_SOURCE_UNAVAILABLE",
        )

    if l1_outcome == "UNAVAILABLE":
        item_errors.append(
            f"finding[{idx}] independent Layer-1 verification unavailable (fail-closed): {l1_res.get('error')}"
        )
        return (
            "FAILED_LAYER1_UNAVAILABLE",
            "FAILED_LAYER1_UNAVAILABLE",
            "FAILED_LAYER1_UNAVAILABLE",
        )

    # Domain A: Authoritative Layer-1 validator ACCEPTED raw HTTP model response + locked source evidence.
    if l1_outcome == "ACCEPTED":
        l1_answer = l1_res["answer"]
        raw_status = str(l1_answer["status"])
        raw_expl = str(l1_answer["explanation"])
        raw_fix = str(l1_answer["fix_suggestion"])
        raw_cites = list(l1_answer["citations"])
        l1_prov = l1_answer.get("citation_provenance") if isinstance(l1_answer.get("citation_provenance"), dict) else None

        # Bind sidecar .response.json Layer-1 fields to authoritative Layer-1 acceptance.
        pre_l1_err_cnt = len(item_errors)
        s_fk = sidecar_runtime.get("failure_kind") if isinstance(sidecar_runtime, dict) else None
        if sidecar_answer_validated is not True:
            item_errors.append(
                f"finding[{idx}] independent Layer-1 validation ACCEPTED raw HTTP response (status={raw_status!r}), "
                f"but sidecar .response.json declared runtime.answer_validated={sidecar_answer_validated!r} "
                f"(failure_kind={s_fk!r}, error={sidecar_error!r})"
            )
        if sidecar_error is not None:
            item_errors.append(
                f"finding[{idx}] independent Layer-1 validation ACCEPTED raw HTTP response (status={raw_status!r}), "
                f"but sidecar .response.json declared non-null error ({sidecar_error!r})"
            )
        if isinstance(sidecar_runtime, dict):
            if "failure_kind" in sidecar_runtime:
                if s_fk != "NONE":
                    item_errors.append(
                        f"finding[{idx}] independent Layer-1 validation ACCEPTED raw HTTP response (status={raw_status!r}), "
                        f"but sidecar .response.json runtime.failure_kind={s_fk!r} (expected 'NONE')"
                    )
            elif not is_historical_ver:
                item_errors.append(
                    f"finding[{idx}] sidecar .response.json runtime missing required failure_kind='NONE' for accepted v2.2.6 Layer-1 result"
                )
            if "validator_downgraded" in sidecar_runtime and sidecar_runtime.get("validator_downgraded") is not False:
                item_errors.append(
                    f"finding[{idx}] sidecar .response.json runtime.validator_downgraded ({sidecar_runtime.get('validator_downgraded')!r}) must be False or absent for Layer-1 output"
                )
        layer1_ok = len(item_errors) == pre_l1_err_cnt
        l1_status = "RECOMPUTED_EXACT_MATCH" if layer1_ok else "FAILED_LAYER1_MISMATCH"

        # Pre-Gate historical contract (v2.2.2 P11 sealed captures and v2.1 legacy steered):
        # Integration Gate did not exist when these clean captures were generated.
        is_pre_gate_historical_clean = (
            is_historical_ver
            and recorded_prompt_version not in _GATE_GOVERNED_HISTORICAL_VERSIONS
            and runtime.get("answer_validated") is True
        )
        if is_pre_gate_historical_clean:
            if ass_status != raw_status or assessment.get("validated_status", ass_status) != raw_status:
                item_errors.append(
                    f"finding[{idx}] validated assessment status ({ass_status!r}/{assessment.get('validated_status')!r}) "
                    f"!= raw HTTP model status ({raw_status!r})"
                )
            if "validator_downgraded" in assessment and assessment.get("validator_downgraded") is not False:
                item_errors.append(
                    f"finding[{idx}] assessment.validator_downgraded ({assessment.get('validator_downgraded')!r}) must be False when answer_validated=True"
                )
            if "failure_kind" in assessment and assessment.get("failure_kind") != "NONE":
                item_errors.append(
                    f"finding[{idx}] assessment.failure_kind ({assessment.get('failure_kind')!r}) must be 'NONE' when answer_validated=True"
                )
            if "downgrade_reason" in assessment and assessment.get("downgrade_reason") is not None:
                item_errors.append(
                    f"finding[{idx}] validated assessment must not declare non-null downgrade_reason ({assessment.get('downgrade_reason')!r})"
                )
            if "independent_refutation_proof" in assessment and assessment.get("independent_refutation_proof") is not None:
                item_errors.append(
                    f"finding[{idx}] pre-Gate historical assessment must not declare independent_refutation_proof"
                )
            if "explanation" not in assessment or not _strict_eq(assessment.get("explanation"), raw_expl):
                item_errors.append(
                    f"finding[{idx}] validated assessment.explanation disagrees with raw HTTP model explanation"
                )
            if "fix_suggestion" not in assessment or not _strict_eq(assessment.get("fix_suggestion"), raw_fix):
                item_errors.append(
                    f"finding[{idx}] validated assessment.fix_suggestion disagrees with raw HTTP model fix_suggestion"
                )
            ass_cites = assessment.get("citations")
            if "citations" not in assessment or not isinstance(ass_cites, list):
                item_errors.append(f"finding[{idx}] validated assessment.citations missing or not a list")
                ass_cites = None
            elif not _strict_eq(ass_cites, raw_cites):
                item_errors.append(
                    f"finding[{idx}] validated assessment.citations disagrees with raw HTTP model citations"
                )
            if raw_status != "UNDETERMINED" and len(raw_cites) == 0:
                item_errors.append(
                    f"finding[{idx}] conclusive validated assessment ({raw_status}) requires at least one citation"
                )
            if ass_cites is not None:
                if len(ass_cites) > 0:
                    if assessment.get("citation_check") != "MATCHED":
                        item_errors.append(
                            f"finding[{idx}] validated assessment with non-empty citations must set citation_check='MATCHED', got {assessment.get('citation_check')!r}"
                        )
                    exp_prov = _verify_citations_against_evidence(
                        idx,
                        ass_cites,
                        rec,
                        prompt_version=recorded_prompt_version,
                        require_relevant_scope=(raw_status != "UNDETERMINED"),
                        item_errors=item_errors,
                    )
                    if exp_prov is not None:
                        _verify_citation_provenance_field(idx, assessment, exp_prov, item_errors)
                else:
                    if assessment.get("citation_check") != "NONE":
                        item_errors.append(
                            f"finding[{idx}] validated assessment with empty citations must set citation_check='NONE', got {assessment.get('citation_check')!r}"
                        )
                    _verify_citation_provenance_field(idx, assessment, _EMPTY_CITATION_PROVENANCE, item_errors)
            return (
                l1_status,
                ("HISTORICAL_PRE_GATE_CONTRACT" if layer1_ok else "FAILED_LAYER1_MISMATCH"),
                "NOT_APPLICABLE",
            )

        # Current (v2.2.6) and Gate-governed historical versions (v2.2.5, v2.2.4, plus any claimed downgrade):
        # ALWAYS recompute the single authoritative apply_integration_gate() from locked evidence + authoritative Layer-1 answer.
        expected_gated, gate_err = _recompute_post_gate_decision(
            rec,
            raw_status=raw_status,
            raw_expl=raw_expl,
            raw_fix=raw_fix,
            raw_cites=raw_cites,
            sidecar_runtime=sidecar_runtime,
            prompt_version=recorded_prompt_version,
            citation_provenance=l1_prov,
        )
        if expected_gated is None:
            item_errors.append(f"finding[{idx}] Integration Gate decision cannot be independently verified: {gate_err}")
            return l1_status, "FAILED_GATE_UNAVAILABLE", "FAILED_GATE_UNAVAILABLE"

        # Check explicit historical v2.2.4 pre-G3-allowlist UNVERIFIED_HELPER_FLOW downgrade compatibility
        # ONLY when Layer-1 matched, the assessment is a genuine v2.2.4 downgrade, and current Gate no longer reproduces it.
        fk = assessment.get("failure_kind")
        dr = assessment.get("downgrade_reason")
        ass_expl = assessment.get("explanation")
        is_exact_gate_downgrade_match = (
            expected_gated.get("validator_downgraded") is True
            and runtime.get("answer_validated") is False
            and _strict_eq(fk, expected_gated.get("failure_kind"))
            and _strict_eq(dr, expected_gated.get("downgrade_reason"))
            and _strict_eq(ass_expl, expected_gated.get("explanation"))
        )
        if (
            layer1_ok
            and not is_exact_gate_downgrade_match
            and is_historical_ver
            and recorded_prompt_version == PREVIOUS_MINIMAL_SINGLELINE_PROMPT_VERSION
            and runtime.get("answer_validated") is False
            and fk == "UNVERIFIED_HELPER_FLOW"
            and _verify_historical_v224_helper_downgrade_reason(dr, rec)
        ):
            if ass_status != "UNDETERMINED" or assessment.get("validated_status", ass_status) != "UNDETERMINED":
                item_errors.append(
                    f"finding[{idx}] historical v2.2.4 post-gate downgrade must fail closed to UNDETERMINED, got {ass_status!r}/{assessment.get('validated_status')!r}"
                )
            if "fix_suggestion" not in assessment or not _strict_eq(assessment.get("fix_suggestion"), raw_fix):
                item_errors.append(
                    f"finding[{idx}] historical v2.2.4 post-gate downgraded assessment.fix_suggestion disagrees with raw HTTP model fix_suggestion"
                )
            if "independent_refutation_proof" in assessment and assessment.get("independent_refutation_proof") is not None:
                item_errors.append(
                    f"finding[{idx}] historical v2.2.4 post-gate downgraded assessment must not declare independent_refutation_proof"
                )
            raw_expl_stripped = raw_expl.strip()
            expected_v224_expl = (
                f"{dr} (Model returned {raw_status}; Human Review remains OPEN. Prior note: {raw_expl_stripped})".strip()
                if raw_expl_stripped
                else f"{dr} (Model returned {raw_status}; Human Review remains OPEN.)"
            )
            hist_status = "HISTORICAL_V224_GRAMMAR_AND_EVIDENCE_GROUNDED_ONLY"
            if not _strict_eq(ass_expl, expected_v224_expl):
                hist_status = "FAILED_HISTORICAL_GROUNDING"
                item_errors.append(
                    f"finding[{idx}] historical v2.2.4 post-gate downgraded assessment.explanation does not match canonical gate wrapper for verified downgrade_reason"
                )
            ass_cites = assessment.get("citations")
            if not isinstance(ass_cites, list) or not _strict_eq(ass_cites, raw_cites):
                item_errors.append(
                    f"finding[{idx}] historical v2.2.4 post-gate downgraded assessment.citations disagrees with raw HTTP model citations"
                )
            elif len(ass_cites) > 0:
                if assessment.get("citation_check") != "MATCHED":
                    item_errors.append(
                        f"finding[{idx}] historical v2.2.4 post-gate downgraded assessment with preserved citations must set citation_check='MATCHED', got {assessment.get('citation_check')!r}"
                    )
                exp_prov = _verify_citations_against_evidence(
                    idx,
                    ass_cites,
                    rec,
                    prompt_version=recorded_prompt_version,
                    require_relevant_scope=(raw_status != "UNDETERMINED"),
                    item_errors=item_errors,
                )
                if exp_prov is not None:
                    _verify_citation_provenance_field(idx, assessment, exp_prov, item_errors)
            else:
                if assessment.get("citation_check") not in ("NONE", "NOT_VERIFIED"):
                    item_errors.append(
                        f"finding[{idx}] historical v2.2.4 post-gate downgraded assessment with empty citations has invalid citation_check={assessment.get('citation_check')!r}"
                    )
                _verify_citation_provenance_field(idx, assessment, _EMPTY_CITATION_PROVENANCE, item_errors)
            return l1_status, hist_status, hist_status

        ig_status, pg_status = _verify_assessment_against_recomputed_gate(
            idx,
            rec,
            assessment,
            runtime,
            expected_gated,
            raw_status=raw_status,
            raw_expl=raw_expl,
            raw_fix=raw_fix,
            raw_cites=raw_cites,
            recorded_prompt_version=recorded_prompt_version,
            is_historical_ver=is_historical_ver,
            item_errors=item_errors,
        )
        if not layer1_ok:
            if ig_status == "RECOMPUTED_EXACT_MATCH":
                ig_status = "FAILED_LAYER1_MISMATCH"
            if pg_status == "RECOMPUTED_EXACT_MATCH":
                pg_status = "FAILED_LAYER1_MISMATCH"
        return l1_status, ig_status, pg_status

    # Domain B: Authoritative Layer-1 validator REJECTED raw HTTP response (`l1_outcome == "REJECTED"`).
    # MUST fail closed to UNDETERMINED with exact authoritative failure_kind and error text.
    exp_l1_fk = str(l1_res["failure_kind"])
    exp_l1_err = str(l1_res["error"])

    pre_l1_err_cnt = len(item_errors)
    s_fk = sidecar_runtime.get("failure_kind") if isinstance(sidecar_runtime, dict) else None
    if sidecar_answer_validated is not False:
        item_errors.append(
            f"finding[{idx}] independent Layer-1 validation REJECTED raw HTTP response "
            f"(failure_kind={exp_l1_fk!r}, error={exp_l1_err!r}), "
            f"but sidecar .response.json declared runtime.answer_validated={sidecar_answer_validated!r}"
        )
    if not _strict_eq(sidecar_error, exp_l1_err):
        item_errors.append(
            f"finding[{idx}] sidecar .response.json error ({sidecar_error!r}) disagrees with "
            f"independently recomputed Layer-1 rejection error ({exp_l1_err!r})"
        )
    if isinstance(sidecar_runtime, dict):
        if "failure_kind" in sidecar_runtime:
            if not _strict_eq(s_fk, exp_l1_fk):
                item_errors.append(
                    f"finding[{idx}] sidecar .response.json runtime.failure_kind ({s_fk!r}) != "
                    f"independently recomputed Layer-1 failure_kind ({exp_l1_fk!r})"
                )
        elif not is_historical_ver:
            item_errors.append(
                f"finding[{idx}] sidecar .response.json runtime missing required failure_kind ({exp_l1_fk!r}) for rejected v2.2.6 Layer-1 result"
            )
        if "validator_downgraded" in sidecar_runtime and sidecar_runtime.get("validator_downgraded") is not False:
            item_errors.append(
                f"finding[{idx}] sidecar .response.json runtime.validator_downgraded ({sidecar_runtime.get('validator_downgraded')!r}) must be False or absent for Layer-1 output"
            )
    if runtime.get("answer_validated") is not False:
        item_errors.append(
            f"finding[{idx}] independent Layer-1 validation REJECTED raw HTTP response ({exp_l1_fk!r}), "
            f"but assessment.runtime.answer_validated is {runtime.get('answer_validated')!r} (must be False)"
        )
    if ass_status != "UNDETERMINED" or assessment.get("validated_status", ass_status) != "UNDETERMINED":
        item_errors.append(
            f"finding[{idx}] unvalidated assessment must fail closed to UNDETERMINED, got {ass_status!r}/{assessment.get('validated_status')!r}"
        )
    layer1_ok = len(item_errors) == pre_l1_err_cnt
    l1_status = "RECOMPUTED_EXACT_MATCH" if layer1_ok else "FAILED_LAYER1_MISMATCH"

    # Current contract (v2.2.6): ALWAYS recompute apply_integration_gate() from the AUTHORITATIVE
    # Layer-1 rejection `(exp_l1_fk, exp_l1_err)` (NEVER from untrusted sidecar metadata).
    if not is_historical_ver:
        exp_err_gated, exp_err_gate_err = _recompute_error_gate_decision(
            rec,
            sidecar_error=exp_l1_err,
            raw_model_status=expected_raw_model_status,
            sidecar_runtime=sidecar_runtime,
            prompt_version=recorded_prompt_version,
            raw_response=parsed_raw,
            authoritative_failure_kind=exp_l1_fk,
        )
        if exp_err_gated is None:
            item_errors.append(
                f"finding[{idx}] Layer-1 rejected assessment cannot be independently verified against Integration Gate: {exp_err_gate_err}"
            )
            return l1_status, "FAILED_GATE_UNAVAILABLE", "FAILED_GATE_UNAVAILABLE"

        pre_err_cnt = len(item_errors)
        err_gate_downgraded = _is_gate_error_downgrade_transition(exp_err_gated, exp_l1_err)
        exp_fk = exp_err_gated.get("failure_kind")
        exp_vd = exp_err_gated.get("validator_downgraded") is True
        exp_dr = exp_err_gated.get("downgrade_reason")
        exp_expl = exp_err_gated.get("explanation")
        exp_cites = exp_err_gated.get("citations") if isinstance(exp_err_gated.get("citations"), list) else []
        exp_cc = exp_err_gated.get("citation_check")

        if not _strict_eq(assessment.get("failure_kind"), exp_fk):
            item_errors.append(
                f"finding[{idx}] (layer1_rejected) assessment.failure_kind ({assessment.get('failure_kind')!r}) "
                f"!= independently recomputed Gate failure_kind ({exp_fk!r})"
            )
        if not _strict_eq(runtime.get("failure_kind"), exp_fk):
            item_errors.append(
                f"finding[{idx}] (layer1_rejected) assessment.runtime.failure_kind ({runtime.get('failure_kind')!r}) "
                f"!= independently recomputed Gate failure_kind ({exp_fk!r})"
            )
        if type(assessment.get("validator_downgraded")) is not bool or assessment.get("validator_downgraded") is not exp_vd:
            item_errors.append(
                f"finding[{idx}] (layer1_rejected) assessment.validator_downgraded ({assessment.get('validator_downgraded')!r}) "
                f"!= independently recomputed Gate validator_downgraded ({exp_vd!r})"
            )
        if err_gate_downgraded and runtime.get("validator_downgraded") is not True:
            item_errors.append(
                f"finding[{idx}] (layer1_rejected) Gate-downgraded assessment must set runtime.validator_downgraded=True"
            )
        elif not err_gate_downgraded and "validator_downgraded" in runtime and runtime.get("validator_downgraded") is not False:
            item_errors.append(
                f"finding[{idx}] (layer1_rejected) non-Gate-downgraded assessment must not set runtime.validator_downgraded={runtime.get('validator_downgraded')!r}"
            )
        if exp_dr is not None:
            if not _strict_eq(assessment.get("downgrade_reason"), exp_dr):
                item_errors.append(
                    f"finding[{idx}] (layer1_rejected) assessment.downgrade_reason ({assessment.get('downgrade_reason')!r}) "
                    f"!= independently recomputed Gate downgrade_reason ({exp_dr!r})"
                )
        elif "downgrade_reason" in assessment and assessment.get("downgrade_reason") is not None:
            item_errors.append(
                f"finding[{idx}] (layer1_rejected) assessment.downgrade_reason ({assessment.get('downgrade_reason')!r}) is ungrounded for this Layer-1 rejection"
            )
        if not _strict_eq(assessment.get("explanation"), exp_expl):
            item_errors.append(
                f"finding[{idx}] (layer1_rejected) assessment.explanation disagrees with independently recomputed Gate explanation"
            )
        if "independent_refutation_proof" in assessment and assessment.get("independent_refutation_proof") is not None:
            item_errors.append(
                f"finding[{idx}] (layer1_rejected) assessment must not declare independent_refutation_proof"
            )
        if not isinstance(assessment.get("fix_suggestion"), str) or assessment.get("fix_suggestion") != "":
            item_errors.append(
                f"finding[{idx}] (layer1_rejected) assessment.fix_suggestion must be empty string, got {assessment.get('fix_suggestion')!r}"
            )
        ass_cites = assessment.get("citations")
        if not isinstance(ass_cites, list) or not _strict_eq(ass_cites, exp_cites):
            item_errors.append(
                f"finding[{idx}] (layer1_rejected) assessment.citations disagrees with independently recomputed Gate citations"
            )
        if not _strict_eq(assessment.get("citation_check"), exp_cc):
            item_errors.append(
                f"finding[{idx}] (layer1_rejected) assessment.citation_check ({assessment.get('citation_check')!r}) "
                f"!= independently recomputed Gate citation_check ({exp_cc!r})"
            )
        if isinstance(ass_cites, list) and len(ass_cites) > 0:
            exp_prov = _verify_citations_against_evidence(
                idx,
                ass_cites,
                rec,
                prompt_version=recorded_prompt_version,
                require_relevant_scope=True,
                item_errors=item_errors,
            )
            if exp_prov is not None:
                _verify_citation_provenance_field(idx, assessment, exp_prov, item_errors)
        else:
            _verify_citation_provenance_field(idx, assessment, _EMPTY_CITATION_PROVENANCE, item_errors)

        gate_ok = len(item_errors) == pre_err_cnt
        if not gate_ok:
            return (
                l1_status,
                "FAILED_RECOMPUTATION_MISMATCH",
                ("FAILED_RECOMPUTATION_MISMATCH" if err_gate_downgraded else "NOT_APPLICABLE"),
            )
        if not layer1_ok:
            return (
                l1_status,
                "FAILED_LAYER1_MISMATCH",
                ("FAILED_LAYER1_MISMATCH" if err_gate_downgraded else "NOT_APPLICABLE"),
            )
        return (
            l1_status,
            "RECOMPUTED_EXACT_MATCH",
            ("RECOMPUTED_EXACT_MATCH" if err_gate_downgraded else "NOT_APPLICABLE"),
        )

    # Historical Layer-1 rejected compatibility path (preserves pre-G3 historical v2.2.4/v2.2.5/v2.2.2 error captures,
    # while binding failure_kind and explanation to the independently recomputed Layer-1 rejection).
    hist_err_gate_doc: dict[str, Any] | None = None
    if expected_raw_model_status is not None and expected_raw_model_status not in STATUSES:
        hist_err_gate_doc, _ = _recompute_error_gate_decision(
            rec,
            sidecar_error=exp_l1_err,
            raw_model_status=expected_raw_model_status,
            sidecar_runtime=sidecar_runtime,
            prompt_version=recorded_prompt_version,
            raw_response=parsed_raw,
            authoritative_failure_kind=exp_l1_fk,
        )
    allowed_hist_gate = (
        hist_err_gate_doc
        if _is_gate_error_downgrade_transition(hist_err_gate_doc, exp_l1_err)
        else None
    )
    if "failure_kind" in assessment:
        exp_hist_fk = allowed_hist_gate.get("failure_kind") if allowed_hist_gate is not None else exp_l1_fk
        if not _strict_eq(assessment.get("failure_kind"), exp_hist_fk):
            item_errors.append(
                f"finding[{idx}] (historical layer1_rejected) assessment.failure_kind ({assessment.get('failure_kind')!r}) "
                f"!= independently recomputed Layer-1 failure_kind ({exp_hist_fk!r})"
            )
    ass_cites = assessment.get("citations")
    if (
        exp_l1_fk == "UNVERIFIED_REFUTATION"
        and assessment.get("failure_kind") == "UNVERIFIED_REFUTATION"
        and expected_raw_model_status == "REFUTED"
        and isinstance(ass_cites, list)
        and len(ass_cites) > 0
    ):
        raw_cites = parsed_msg_doc.get("citations") if isinstance(parsed_msg_doc, dict) else None
        if not isinstance(raw_cites, list) or not _strict_eq(ass_cites, raw_cites):
            item_errors.append(
                f"finding[{idx}] Layer-1 UNVERIFIED_REFUTATION preserved citations disagree with raw HTTP model citations"
            )
        else:
            if assessment.get("citation_check") != "MATCHED":
                item_errors.append(
                    f"finding[{idx}] Layer-1 UNVERIFIED_REFUTATION with preserved citations must set citation_check='MATCHED', got {assessment.get('citation_check')!r}"
                )
            exp_prov = _verify_citations_against_evidence(
                idx,
                ass_cites,
                rec,
                prompt_version=recorded_prompt_version,
                require_relevant_scope=True,
                item_errors=item_errors,
            )
            if exp_prov is not None:
                _verify_citation_provenance_field(idx, assessment, exp_prov, item_errors)
        if not _strict_eq(assessment.get("explanation"), exp_l1_err):
            item_errors.append(
                f"finding[{idx}] Layer-1 UNVERIFIED_REFUTATION assessment.explanation disagrees with recomputed Layer-1 error"
            )
        if "downgrade_reason" in assessment and assessment.get("downgrade_reason") is not None:
            if not _strict_eq(assessment.get("downgrade_reason"), exp_l1_err.strip()):
                item_errors.append(
                    f"finding[{idx}] Layer-1 UNVERIFIED_REFUTATION assessment.downgrade_reason ({assessment.get('downgrade_reason')!r}) "
                    f"!= recomputed Layer-1 error ({exp_l1_err.strip()!r})"
                )
        if "independent_refutation_proof" in assessment and assessment.get("independent_refutation_proof") is not None:
            item_errors.append(
                f"finding[{idx}] Layer-1 UNVERIFIED_REFUTATION assessment must not declare independent_refutation_proof"
            )
        if not isinstance(assessment.get("fix_suggestion"), str) or assessment.get("fix_suggestion") != "":
            item_errors.append(
                f"finding[{idx}] Layer-1 UNVERIFIED_REFUTATION assessment.fix_suggestion must be empty string, got {assessment.get('fix_suggestion')!r}"
            )
        return (
            l1_status,
            ("HISTORICAL_ERROR_CONTRACT" if layer1_ok else "FAILED_LAYER1_MISMATCH"),
            "NOT_APPLICABLE",
        )

    _verify_empty_undetermined_assessment(
        idx,
        assessment,
        require_v226_fields=require_v226_fields,
        expected_raw_model_status=expected_raw_model_status,
        item_errors=item_errors,
        context_label="layer1_rejected",
        sidecar_error=exp_l1_err,
        allowed_error_gate_doc=allowed_hist_gate,
    )
    if allowed_hist_gate is not None:
        if not _strict_eq(assessment.get("explanation"), allowed_hist_gate.get("explanation")):
            item_errors.append(
                f"finding[{idx}] (historical layer1_rejected) assessment.explanation disagrees with recomputed Gate error wrapper"
            )
    elif not _strict_eq(assessment.get("explanation"), exp_l1_err):
        item_errors.append(
            f"finding[{idx}] (historical layer1_rejected) assessment.explanation disagrees with recomputed Layer-1 error"
        )
    return (
        l1_status,
        ("HISTORICAL_ERROR_CONTRACT" if layer1_ok else "FAILED_LAYER1_MISMATCH"),
        "NOT_APPLICABLE",
    )


def _failed_report(errors: list[str]) -> dict[str, Any]:
    return {
        "schema": "ntk-http-capture-verification-1",
        "capture_scope": "http_body_and_client_metadata_not_tcp_wire",
        "verification_scope": _VERIFICATION_SCOPE,
        "capture_status": "FAILED",
        "capture_integrity_ok": False,
        "artifact_integrity_ok": False,
        "endpoint_reported_protocol_ok": False,
        "live_origin_verified": False,
        "live_chat_verified": False,
        "live_origin_trust_status": "FAILED_CAPTURE_INTEGRITY",
        "independently_verified_model_runtime": False,
        "security_conclusion_verified": False,
        "endpoint_reported_protocol_errors": [],
        "live_chat_provenance_errors": [],
        "errors": errors,
        "findings": [],
        "tags_probes": [],
    }


def _verify_tags_captures(tags_dir: Path, seen_call_ids: set[str], errors: list[str]) -> list[dict[str, Any]]:
    probes: list[dict[str, Any]] = []
    try:
        raw_tags = _validate_lexical_dir_path(tags_dir, label="llm_io/_tags")
    except CaptureWriteError as exc:
        errors.append(str(exc))
        return probes
    abs_tags = Path(os.path.abspath(raw_tags))
    if not abs_tags.anchor or abs_tags == Path(abs_tags.anchor):
        errors.append(f"invalid llm_io/_tags root path: {abs_tags}")
        return probes
    anchor = Path(abs_tags.anchor)
    try:
        anchor_st = os.lstat(anchor)
        if not stat.S_ISDIR(anchor_st.st_mode):
            errors.append(f"filesystem root anchor is not a directory: {anchor}")
            return probes
        prev_resolved = anchor.resolve(strict=True)
        if os.name == "nt" and prev_resolved.drive.upper() != anchor.drive.upper():
            errors.append(f"drive root {anchor} redirects to different volume {prev_resolved}")
            return probes
        if prev_resolved != Path(os.path.abspath(prev_resolved)) or prev_resolved.parent != prev_resolved:
            errors.append(f"filesystem root redirects unexpectedly: {anchor} -> {prev_resolved}")
            return probes
    except (OSError, RuntimeError) as exc:
        errors.append(f"cannot verify filesystem root for llm_io/_tags {anchor}: {exc}")
        return probes

    rel_parts = abs_tags.relative_to(anchor).parts
    cur = anchor
    for part in rel_parts[:-1]:
        cur = cur / part
        try:
            st_anc = os.lstat(cur)
        except FileNotFoundError:
            return probes
        except OSError as exc:
            errors.append(f"cannot inspect llm_io/_tags ancestor {cur}: {exc}")
            return probes
        try:
            if is_reparse_link(cur):
                errors.append(f"llm_io/_tags ancestor must not be a symlink, junction, or reparse point: {cur}")
                return probes
            if not stat.S_ISDIR(st_anc.st_mode):
                errors.append(f"llm_io/_tags ancestor is not a directory: {cur}")
                return probes
            resolved_anc = cur.resolve(strict=True)
            res_anc_st = os.lstat(resolved_anc)
        except (OSError, CaptureWriteError, RuntimeError) as exc:
            errors.append(f"cannot verify llm_io/_tags ancestor {cur}: {exc}")
            return probes
        if resolved_anc.parent != prev_resolved or not os.path.samestat(st_anc, res_anc_st):
            errors.append(f"llm_io/_tags ancestor resolves outside lexical parent chain: {cur} -> {resolved_anc}")
            return probes
        prev_resolved = resolved_anc

    try:
        st = os.lstat(abs_tags)
    except FileNotFoundError:
        return probes
    except OSError as exc:
        errors.append(f"cannot inspect llm_io/_tags {abs_tags}: {exc}")
        return probes

    try:
        if is_reparse_link(abs_tags):
            errors.append(f"llm_io/_tags must not be a symlink, junction, or reparse point: {abs_tags}")
            return probes
        if not stat.S_ISDIR(st.st_mode):
            errors.append(f"llm_io/_tags is not a directory: {abs_tags}")
            return probes
        resolved_tags = abs_tags.resolve(strict=True)
        res_tags_st = os.lstat(resolved_tags)
        if resolved_tags.parent != prev_resolved or not os.path.samestat(st, res_tags_st):
            errors.append(f"llm_io/_tags resolves outside parent llm_io directory: {resolved_tags}")
            return probes
        dir_entries = sorted(abs_tags.iterdir(), key=lambda p: p.name)
    except (OSError, CaptureWriteError, RuntimeError) as exc:
        errors.append(f"cannot inspect llm_io/_tags {abs_tags}: {exc}")
        return probes

    receipt_files: list[Path] = []
    regular_names: list[str] = []
    for entry in dir_entries:
        try:
            if is_reparse_link(entry):
                errors.append(f"symlink or junction forbidden in llm_io/_tags: {entry.name}")
                continue
            est = os.lstat(entry)
            if stat.S_ISDIR(est.st_mode):
                errors.append(f"unexpected directory inside llm_io/_tags: {entry.name}")
                continue
            if not stat.S_ISREG(est.st_mode):
                errors.append(f"non-regular file inside llm_io/_tags: {entry.name}")
                continue
        except (OSError, CaptureWriteError) as exc:
            errors.append(f"cannot inspect llm_io/_tags entry {entry.name}: {exc}")
            continue
        regular_names.append(entry.name)
        if entry.name.endswith(".http-capture.json"):
            if not _TAGS_RECEIPT_RE.fullmatch(entry.name):
                errors.append(f"unexpected tags receipt filename format: {entry.name}")
                continue
            receipt_files.append(entry)

    expected_files: set[str] = set()
    for r_file in receipt_files:
        expected_files.add(r_file.name)
        prefix = r_file.name[: -len(".http-capture.json")]
        safe_r = _safe_regular_child_file(
            abs_tags,
            resolved_tags,
            r_file.name,
            max_bytes=1024 * 1024,
            label="tags receipt",
            errors=errors,
        )
        if safe_r is None:
            continue
        try:
            doc = strict_json(safe_r.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, EvidenceError) as exc:
            errors.append(f"unreadable tags receipt {r_file.name}: {exc}")
            continue
        if not isinstance(doc, dict) or doc.get("schema") != "ntk-ollama-http-capture-1":
            errors.append(f"invalid schema in tags receipt {r_file.name}")
            continue
        call_id = doc.get("call_id")
        if not isinstance(call_id, str) or not call_id:
            errors.append(f"missing call_id in tags receipt {r_file.name}")
        elif call_id in seen_call_ids:
            errors.append(f"duplicate call_id across HTTP receipts: {call_id}")
        else:
            seen_call_ids.add(call_id)

        if doc.get("call_kind") != "tags_probe" or doc.get("method") != "GET" or doc.get("path") != "/api/tags":
            errors.append(f"tags receipt {r_file.name} has unexpected call_kind/method/path")
        if doc.get("finding_id") is not None:
            errors.append(f"tags receipt {r_file.name} must not bind a finding_id")
        if doc.get("request_raw_file") is not None:
            errors.append(f"GET tags receipt {r_file.name} unexpectedly declares request_raw_file")
        if "runtime_origin" in doc and doc.get("runtime_origin") not in _ALLOWED_HTTP_ORIGINS:
            errors.append(f"tags receipt {r_file.name} has invalid runtime_origin: {doc.get('runtime_origin')!r}")

        completeness = doc.get("completeness")
        resp_name = doc.get("response_raw_file")
        inc_name = doc.get("response_incomplete_raw_file")
        expected_resp_name = f"{prefix}.response.body.bin"
        expected_inc_name = f"{prefix}.response.incomplete.bin"
        probe_ok = True
        models_listed: list[str] | None = None
        model_digests: dict[str, str | None] = {}
        if completeness in ("complete", "complete_http_error_body"):
            if resp_name != expected_resp_name:
                errors.append(
                    f"tags receipt {r_file.name} response_raw_file must be exact basename {expected_resp_name!r}, got {resp_name!r}"
                )
                probe_ok = False
            else:
                expected_files.add(resp_name)
                resp_path = _safe_regular_child_file(
                    abs_tags,
                    resolved_tags,
                    resp_name,
                    max_bytes=MAX_HTTP_BODY_BYTES,
                    label="tags raw response body",
                    errors=errors,
                )
                if resp_path is None:
                    probe_ok = False
                else:
                    raw = resp_path.read_bytes()
                    if len(raw) > MAX_HTTP_BODY_BYTES:
                        errors.append(f"tags raw response {resp_name} exceeds MAX_HTTP_BODY_BYTES")
                        probe_ok = False
                    if len(raw) != doc.get("response_byte_length"):
                        errors.append(f"tags raw response {resp_name} byte length mismatch")
                        probe_ok = False
                    if digest(raw) != doc.get("response_body_sha256"):
                        errors.append(f"tags raw response {resp_name} SHA-256 mismatch")
                        probe_ok = False
                    if probe_ok and completeness == "complete" and type(doc.get("http_status")) is int and doc["http_status"] == 200:
                        try:
                            tags_doc = strict_json(raw.decode("utf-8"))
                            if isinstance(tags_doc, dict) and isinstance(tags_doc.get("models"), list):
                                models_listed = []
                                for m in tags_doc["models"]:
                                    if isinstance(m, dict) and isinstance(m.get("name") or m.get("model"), str):
                                        m_name = str(m.get("name") or m.get("model"))
                                        models_listed.append(m_name)
                                        m_dig = m.get("digest")
                                        model_digests[m_name] = m_dig if isinstance(m_dig, str) else None
                        except (UnicodeError, ValueError, EvidenceError):
                            models_listed = None
                            model_digests = {}
        elif inc_name is not None:
            if inc_name != expected_inc_name:
                errors.append(
                    f"tags receipt {r_file.name} response_incomplete_raw_file must be {expected_inc_name!r}, got {inc_name!r}"
                )
                probe_ok = False
            else:
                expected_files.add(inc_name)
                inc_path = _safe_regular_child_file(
                    abs_tags,
                    resolved_tags,
                    inc_name,
                    max_bytes=MAX_HTTP_BODY_BYTES + 1024,
                    label="tags incomplete body",
                    errors=errors,
                )
                if inc_path is None:
                    probe_ok = False
                else:
                    inc_bytes = inc_path.read_bytes()
                    if len(inc_bytes) != doc.get("response_incomplete_byte_length") or digest(inc_bytes) != doc.get("response_incomplete_sha256"):
                        errors.append(f"tags incomplete body {inc_name} length/SHA-256 mismatch")
                        probe_ok = False

        probes.append({
            "receipt": f"llm_io/_tags/{r_file.name}",
            "call_id": call_id,
            "endpoint": doc.get("endpoint"),
            "requested_model": doc.get("requested_model"),
            "runtime_origin": doc.get("runtime_origin"),
            "transport_entered": doc.get("transport_entered") is True,
            "http_status": doc.get("http_status"),
            "completeness": completeness,
            "complete": doc.get("complete") is True,
            "response_byte_length": doc.get("response_byte_length"),
            "response_body_sha256": doc.get("response_body_sha256"),
            "models_listed": models_listed,
            "model_digests": model_digests,
            "verified": probe_ok,
        })

    for actual in regular_names:
        if actual not in expected_files:
            errors.append(f"orphan file in llm_io/_tags not referenced by any tags receipt: {actual}")

    return probes


def verify_run_http_captures(
    triage_dir: Path,
    *,
    require_live_chat: bool = False,
    minimum_findings: int = 0,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        raw_triage = _validate_lexical_dir_path(triage_dir, label="triage_dir")
        abs_triage = Path(os.path.abspath(raw_triage))
        resolved_triage = verify_safe_directory_chain(raw_triage, boundary_root=raw_triage, create=False)
    except (OSError, CaptureWriteError, RuntimeError) as exc:
        return _failed_report([f"unsafe or invalid triage directory {triage_dir}: {exc}"])

    finding_checks: list[dict[str, Any]] = []
    seen_call_ids: set[str] = set()

    parse_errors: list[str] = []
    evidence_path = _safe_regular_child_file(
        abs_triage,
        resolved_triage,
        "evidence.json",
        max_bytes=64 * 1024 * 1024,
        label="evidence.json",
        errors=parse_errors,
    )
    assessments_path = _safe_regular_child_file(
        abs_triage,
        resolved_triage,
        "assessments.jsonl",
        max_bytes=64 * 1024 * 1024,
        label="assessments.jsonl",
        errors=parse_errors,
    )
    if evidence_path is None or assessments_path is None:
        return _failed_report(parse_errors)

    try:
        bundle = strict_json(evidence_path.read_text(encoding="utf-8"))
        rows = [
            strict_json(line)
            for line in assessments_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError, ValueError, EvidenceError) as exc:
        return _failed_report([f"failed to parse evidence/assessments: {exc}"])

    records = bundle.get("records") if isinstance(bundle, dict) else None
    scan_sha = bundle.get("scan_sha256") if isinstance(bundle, dict) else None
    has_bundle_contract = isinstance(bundle, dict) and "prompt_contract" in bundle
    bundle_contract = bundle.get("prompt_contract") if has_bundle_contract else None
    if has_bundle_contract and (not isinstance(bundle_contract, str) or bundle_contract not in PROMPT_CONTRACTS):
        errors.append(f"evidence.json invalid top-level prompt_contract: {bundle_contract!r}")
    if not isinstance(records, list) or not isinstance(scan_sha, str):
        errors.append("evidence.json missing records list or scan_sha256")
        records = []

    if len(rows) != len(records):
        errors.append(f"finding count mismatch: evidence={len(records)} vs assessments={len(rows)}")

    io_dir = abs_triage / "llm_io"
    io_dir_exists = os.path.lexists(io_dir)
    io_dir_safe = False
    resolved_io_dir: Path | None = None
    io_regular_files: list[str] = []
    if io_dir_exists:
        try:
            if is_reparse_link(io_dir):
                errors.append(f"llm_io must not be a symlink or junction: {io_dir}")
            elif not stat.S_ISDIR(os.lstat(io_dir).st_mode):
                errors.append(f"llm_io is not a directory: {io_dir}")
            else:
                cand_resolved_io = io_dir.resolve(strict=True)
                if cand_resolved_io != resolved_triage / "llm_io":
                    errors.append(f"llm_io resolves outside triage directory: {cand_resolved_io}")
                else:
                    io_dir_safe = True
                    resolved_io_dir = cand_resolved_io
                    for entry in sorted(io_dir.iterdir(), key=lambda p: p.name):
                        if is_reparse_link(entry):
                            errors.append(f"symlink or junction forbidden inside llm_io: {entry.name}")
                            continue
                        est = os.lstat(entry)
                        if entry.name == "_tags" and stat.S_ISDIR(est.st_mode):
                            continue
                        if stat.S_ISDIR(est.st_mode):
                            errors.append(f"unexpected subdirectory in llm_io: {entry.name}")
                        elif stat.S_ISREG(est.st_mode):
                            io_regular_files.append(entry.name)
                        else:
                            errors.append(f"non-regular entry in llm_io: {entry.name}")
        except (OSError, CaptureWriteError, RuntimeError) as exc:
            errors.append(f"cannot inspect llm_io directory {io_dir}: {exc}")

    tags_probes = _verify_tags_captures(io_dir / "_tags", seen_call_ids, errors) if io_dir_safe else []
    expected_chat_files: set[str] = set()

    disabled_count = 0
    mock_method_count = 0
    complete_chat_count = 0
    endpoint_reported_non_mock_complete_count = 0
    partial_or_error_count = 0
    artifact_errors: list[str] = list(errors)
    strict_errors: list[str] = []
    endpoint_reported_protocol_errors: list[str] = []
    endpoint_expected_pairs: set[tuple[str, str]] = set()

    for idx, (rec, row) in enumerate(zip(records, rows)):
        rec_id = rec.get("id") if isinstance(rec, dict) else None
        expected_id = digest(f"{scan_sha}:{idx}".encode("utf-8")) if isinstance(scan_sha, str) else None
        raw_assessment = row.get("assessment") if isinstance(row, dict) else None
        assessment = raw_assessment if isinstance(raw_assessment, dict) else {}
        raw_runtime = assessment.get("runtime") if isinstance(assessment, dict) else None
        runtime = raw_runtime if isinstance(raw_runtime, dict) else {}
        safe_id = _safe_id(rec_id)
        item_errors: list[str] = []

        if not isinstance(row, dict) or not isinstance(raw_assessment, dict):
            item_errors.append(f"finding[{idx}] row or assessment is not a JSON object")
        if not isinstance(raw_runtime, dict):
            item_errors.append(f"finding[{idx}] assessment.runtime is missing or not a JSON object")
        if assessment.get("security_conclusion_verified") is True:
            item_errors.append(f"finding[{idx}] assessment.security_conclusion_verified must never be True")
        if "supports_security_claim_verified" in assessment and assessment.get("supports_security_claim_verified") is not False:
            item_errors.append(f"finding[{idx}] assessment.supports_security_claim_verified must be False")
        if runtime.get("model_runtime_verified") is True:
            item_errors.append(f"finding[{idx}] runtime.model_runtime_verified must never be True")

        if (
            not isinstance(rec_id, str)
            or rec_id != expected_id
            or (isinstance(row, dict) and row.get("id") != rec_id)
            or runtime.get("finding_id") not in (rec_id, None)
        ):
            item_errors.append(f"finding[{idx}] ID join mismatch across evidence/assessments/runtime")
        if isinstance(row, dict) and "evidence" in row and not _strict_eq(row.get("evidence"), rec):
            item_errors.append(f"finding[{idx}] assessments.jsonl row.evidence disagrees with evidence.json record")

        origin = runtime.get("origin")
        raw_resp_obj = assessment.get("raw_response")
        is_mock = origin == "mock" or (isinstance(raw_resp_obj, dict) and raw_resp_obj.get("mock_test_fixture") is True)
        req_attempted = runtime.get("request_attempted") is True
        cap_completeness = runtime.get("http_capture_completeness")
        failure_kind = assessment.get("failure_kind")

        if failure_kind == "EVIDENCE_CAPTURE_WRITE_FAILED" or cap_completeness == "capture_write_failed":
            item_errors.append(
                f"finding[{idx}] ({rec_id}) failed raw evidence capture write: {runtime.get('http_capture_error') or assessment.get('explanation')}"
            )

        if io_dir_exists and not io_dir_safe:
            item_errors.append(f"finding[{idx}] unsafe or escaped llm_io directory rejected")

        sidecar_stem_raw = runtime.get("sidecar_artifact_stem")
        sidecar_stem = safe_id
        if sidecar_stem_raw is not None:
            if re.fullmatch(rf"{re.escape(safe_id)}(?:\.attempt-\d{{4}})?", str(sidecar_stem_raw)):
                sidecar_stem = str(sidecar_stem_raw)
            else:
                item_errors.append(f"finding[{idx}] invalid sidecar_artifact_stem: {sidecar_stem_raw!r}")

        if origin == "disabled" and assessment.get("transport") == "disabled":
            disabled_count += 1
            if req_attempted:
                item_errors.append(f"finding[{idx}] disabled transport unexpectedly attempted HTTP request")
            if io_dir_safe:
                for suffix in (".request.body.bin", ".response.body.bin", ".response.incomplete.bin", ".http-capture.json"):
                    if os.path.lexists(io_dir / f"{safe_id}{suffix}"):
                        item_errors.append(f"finding[{idx}] disabled run unexpectedly has {safe_id}{suffix}")
            finding_artifact_ok = len(item_errors) == 0
            artifact_errors.extend(item_errors)
            strict_item_errors: list[str] = [
                f"finding[{idx}] ({rec_id}) transport is disabled",
                f"finding[{idx}] {_UNVERIFIED_LIVE_ORIGIN_REASON}",
            ]
            endpoint_reported_protocol_errors.append(f"finding[{idx}] ({rec_id}) transport is disabled")
            reported_item_errors = item_errors + (strict_item_errors if require_live_chat else [])
            if require_live_chat:
                strict_errors.extend(strict_item_errors)
            finding_checks.append({
                "finding_index": idx,
                "id": rec_id,
                "mode": "disabled",
                "mock": False,
                "artifact_integrity_ok": finding_artifact_ok,
                "endpoint_reported_protocol_ok": False,
                "live_provenance_ok": False,
                "layer1_verification": "NOT_APPLICABLE",
                "integration_gate_verification": "NOT_APPLICABLE",
                "post_gate_downgrade_verification": "NOT_APPLICABLE",
                "verified": len(reported_item_errors) == 0,
                "errors": reported_item_errors,
            })
            continue

        if isinstance(row, dict):
            if "state" in row and row.get("state") != "OPEN":
                item_errors.append(
                    f"finding[{idx}] assessments.jsonl row.state must remain 'OPEN', got {row.get('state')!r}"
                )
            if "human_review_state" in row and row.get("human_review_state") != "OPEN":
                item_errors.append(
                    f"finding[{idx}] assessments.jsonl row.human_review_state must remain 'OPEN', got {row.get('human_review_state')!r}"
                )
            if "validated_status" in row and not _strict_eq(
                row.get("validated_status"), assessment.get("validated_status", assessment.get("status"))
            ):
                item_errors.append(
                    f"finding[{idx}] assessments.jsonl row.validated_status ({row.get('validated_status')!r}) "
                    f"!= assessment validated_status ({assessment.get('validated_status', assessment.get('status'))!r})"
                )
            if "raw_model_status" in row and not _strict_eq(
                row.get("raw_model_status"), assessment.get("raw_model_status")
            ):
                item_errors.append(
                    f"finding[{idx}] assessments.jsonl row.raw_model_status ({row.get('raw_model_status')!r}) "
                    f"!= assessment.raw_model_status ({assessment.get('raw_model_status')!r})"
                )
        if "requires_human_review" in assessment and assessment.get("requires_human_review") is not True:
            item_errors.append(
                f"finding[{idx}] assessment.requires_human_review must be True, got {assessment.get('requires_human_review')!r}"
            )
        if (
            "failure_kind" in assessment
            and "failure_kind" in runtime
            and not _strict_eq(assessment.get("failure_kind"), runtime.get("failure_kind"))
        ):
            item_errors.append(
                f"finding[{idx}] assessment.failure_kind ({assessment.get('failure_kind')!r}) "
                f"!= runtime.failure_kind ({runtime.get('failure_kind')!r})"
            )

        if not req_attempted and cap_completeness == "request_method_mocked":
            mock_method_count += 1
            if io_dir_safe and resolved_io_dir is not None:
                for suffix in (".prompt.json", ".request.json", ".response.json"):
                    sname = f"{sidecar_stem}{suffix}"
                    if os.path.lexists(io_dir / sname):
                        cand = _safe_regular_child_file(
                            io_dir, resolved_io_dir, sname, max_bytes=MAX_METADATA_JSON_BYTES, label=f"finding[{idx}] sidecar", errors=item_errors
                        )
                        if cand is not None:
                            expected_chat_files.add(sname)
            finding_artifact_ok = len(item_errors) == 0
            artifact_errors.extend(item_errors)
            mock_msg = f"finding[{idx}] ({rec_id}) used in-memory mocked request() without HTTP transport capture"
            endpoint_reported_protocol_errors.append(mock_msg)
            strict_item_errors = [mock_msg, f"finding[{idx}] {_UNVERIFIED_LIVE_ORIGIN_REASON}"]
            reported_item_errors = item_errors + (strict_item_errors if require_live_chat else [])
            if require_live_chat:
                strict_errors.extend(strict_item_errors)
            finding_checks.append({
                "finding_index": idx,
                "id": rec_id,
                "mode": "request_method_mocked",
                "mock": True,
                "artifact_integrity_ok": finding_artifact_ok,
                "endpoint_reported_protocol_ok": False,
                "live_provenance_ok": False,
                "layer1_verification": "NOT_APPLICABLE",
                "integration_gate_verification": "NOT_APPLICABLE",
                "post_gate_downgrade_verification": "NOT_APPLICABLE",
                "verified": len(reported_item_errors) == 0,
                "errors": reported_item_errors,
            })
            continue

        if not req_attempted:
            # Precheck failure prior to transport (e.g. insufficient evidence or oversized prompt)
            partial_or_error_count += 1
            pre_rec_contract = rec.get("prompt_contract", DEFAULT_PROMPT_CONTRACT) if isinstance(rec, dict) else None
            if (
                has_bundle_contract
                and isinstance(bundle_contract, str)
                and isinstance(pre_rec_contract, str)
                and bundle_contract != pre_rec_contract
            ):
                item_errors.append(
                    f"finding[{idx}] evidence.json prompt_contract ({bundle_contract!r}) != record prompt_contract ({pre_rec_contract!r})"
                )
            if origin is not None and (not isinstance(origin, str) or origin not in _ALLOWED_HTTP_ORIGINS):
                item_errors.append(
                    f"finding[{idx}] precheck-aborted finding has invalid runtime.origin: {origin!r}"
                )
            if io_dir_safe and resolved_io_dir is not None:
                for suffix in (".prompt.json", ".request.json", ".response.json"):
                    sname = f"{sidecar_stem}{suffix}"
                    if os.path.lexists(io_dir / sname):
                        cand = _safe_regular_child_file(
                            io_dir, resolved_io_dir, sname, max_bytes=MAX_METADATA_JSON_BYTES, label=f"finding[{idx}] sidecar", errors=item_errors
                        )
                        if cand is not None:
                            expected_chat_files.add(sname)
                            try:
                                s_doc = strict_json(cand.read_text(encoding="utf-8"))
                                if not isinstance(s_doc, dict):
                                    item_errors.append(f"finding[{idx}] precheck sidecar {sname} is not a JSON object")
                                elif suffix == ".response.json":
                                    if s_doc.get("finding_id") != rec_id:
                                        item_errors.append(f"finding[{idx}] {sname} finding_id mismatch")
                                    if "model" not in s_doc or not _strict_eq(s_doc.get("model"), assessment.get("model")):
                                        item_errors.append(f"finding[{idx}] {sname} model mismatch")
                                    if "endpoint" not in s_doc or not _strict_eq(s_doc.get("endpoint"), assessment.get("endpoint")):
                                        item_errors.append(f"finding[{idx}] {sname} endpoint mismatch")
                                    if "raw_response" not in s_doc or s_doc.get("raw_response") is not None or assessment.get("raw_response") is not None:
                                        item_errors.append(f"finding[{idx}] {sname} precheck raw_response must be null")
                                    s_rt = s_doc.get("runtime")
                                    if not isinstance(s_rt, dict) or not _strict_eq(s_rt, runtime):
                                        item_errors.append(f"finding[{idx}] {sname} runtime disagrees with assessment.runtime")
                                    s_err = s_doc.get("error")
                                    ass_expl = assessment.get("explanation")
                                    if not isinstance(s_err, str) or not s_err.strip():
                                        item_errors.append(f"finding[{idx}] {sname} precheck error must be a non-empty string, got {s_err!r}")
                                    elif not _strict_eq(ass_expl, s_err):
                                        item_errors.append(f"finding[{idx}] {sname} precheck error contradicts assessment.explanation")
                                elif suffix == ".prompt.json":
                                    if s_doc.get("finding_id") != rec_id:
                                        item_errors.append(f"finding[{idx}] {sname} finding_id mismatch")
                                    if s_doc.get("prompt_version") != assessment.get("prompt_version"):
                                        item_errors.append(f"finding[{idx}] {sname} prompt_version mismatch")
                                    if s_doc.get("prompt_contract") != pre_rec_contract:
                                        item_errors.append(f"finding[{idx}] {sname} prompt_contract mismatch")
                                    if s_doc.get("prompt_sha256") != assessment.get("prompt_sha256"):
                                        item_errors.append(f"finding[{idx}] {sname} prompt_sha256 mismatch")
                                elif suffix == ".request.json":
                                    if not _strict_eq(s_doc.get("model"), assessment.get("model")):
                                        item_errors.append(f"finding[{idx}] {sname} model mismatch")
                                    if "stream" in s_doc and s_doc.get("stream") is not False:
                                        item_errors.append(f"finding[{idx}] {sname} stream must be False")
                                    s_msgs = s_doc.get("messages")
                                    if not isinstance(s_msgs, list) or len(s_msgs) < 2:
                                        item_errors.append(f"finding[{idx}] {sname} missing valid chat messages")
                                    elif assessment.get("prompt_sha256") is not None:
                                        s_msg_sha = digest(json.dumps(s_msgs, ensure_ascii=False).encode("utf-8"))
                                        if s_msg_sha != assessment.get("prompt_sha256"):
                                            item_errors.append(f"finding[{idx}] {sname} messages prompt_sha256 mismatch")
                            except (OSError, UnicodeError, ValueError, EvidenceError) as exc:
                                item_errors.append(f"finding[{idx}] unreadable precheck sidecar {sname}: {exc}")
                for suffix in (".request.body.bin", ".response.body.bin", ".response.incomplete.bin", ".http-capture.json"):
                    if os.path.lexists(io_dir / f"{sidecar_stem}{suffix}"):
                        item_errors.append(f"finding[{idx}] precheck-aborted finding unexpectedly has {sidecar_stem}{suffix}")
            pre_pv = assessment.get("prompt_version")
            if pre_pv == LEGACY_STEERED_PROMPT_VERSION and pre_rec_contract != "steered":
                item_errors.append(
                    f"finding[{idx}] precheck assessment.prompt_version ({pre_pv!r}) contradicts evidence prompt_contract ({pre_rec_contract!r})"
                )
            pre_require_schema_fields = not (
                pre_pv == LEGACY_STEERED_PROMPT_VERSION and pre_rec_contract == "steered"
            )
            if (
                runtime.get("answer_validated") is True
                or assessment.get("status") != "UNDETERMINED"
                or (
                    "validated_status" in assessment
                    and assessment.get("validated_status") != "UNDETERMINED"
                )
            ):
                item_errors.append(f"finding[{idx}] precheck-aborted finding must be unvalidated UNDETERMINED")
            _verify_empty_undetermined_assessment(
                idx,
                assessment,
                require_v226_fields=pre_require_schema_fields,
                expected_raw_model_status=None,
                item_errors=item_errors,
                context_label="precheck_not_attempted",
            )
            finding_artifact_ok = len(item_errors) == 0
            artifact_errors.extend(item_errors)
            pre_msg = f"finding[{idx}] ({rec_id}) did not execute live HTTP chat"
            endpoint_reported_protocol_errors.append(pre_msg)
            strict_item_errors = [pre_msg, f"finding[{idx}] {_UNVERIFIED_LIVE_ORIGIN_REASON}"]
            reported_item_errors = item_errors + (strict_item_errors if require_live_chat else [])
            if require_live_chat:
                strict_errors.extend(strict_item_errors)
            finding_checks.append({
                "finding_index": idx,
                "id": rec_id,
                "mode": "precheck_not_attempted",
                "mock": is_mock,
                "artifact_integrity_ok": finding_artifact_ok,
                "endpoint_reported_protocol_ok": False,
                "live_provenance_ok": False,
                "layer1_verification": "NOT_APPLICABLE",
                "integration_gate_verification": "NOT_APPLICABLE",
                "post_gate_downgrade_verification": "NOT_APPLICABLE",
                "verified": len(reported_item_errors) == 0,
                "errors": reported_item_errors,
            })
            continue

        # Real HTTP transport was attempted -> raw capture files, receipt, valid origin, and runtime finding_id are mandatory!
        if runtime.get("finding_id") != rec_id:
            item_errors.append(
                f"finding[{idx}] runtime.finding_id ({runtime.get('finding_id')!r}) != evidence id ({rec_id!r})"
            )
        if not isinstance(origin, str) or origin not in _ALLOWED_HTTP_ORIGINS:
            item_errors.append(
                f"finding[{idx}] invalid runtime.origin for HTTP transport: {origin!r} (expected 'unverified' or 'mock')"
            )
        if isinstance(raw_resp_obj, dict) and raw_resp_obj.get("mock_test_fixture") is True and origin != "mock":
            item_errors.append(
                f"finding[{idx}] raw_response sets mock_test_fixture=True but runtime.origin is {origin!r}, expected 'mock'"
            )
        if not io_dir_safe or resolved_io_dir is None:
            item_errors.append(f"finding[{idx}] missing or unsafe llm_io directory: {io_dir}")
            artifact_errors.extend(item_errors)
            finding_checks.append({
                "finding_index": idx,
                "id": rec_id,
                "mode": "http_transport",
                "mock": is_mock,
                "artifact_integrity_ok": False,
                "endpoint_reported_protocol_ok": False,
                "live_provenance_ok": False,
                "layer1_verification": "NOT_APPLICABLE",
                "integration_gate_verification": "NOT_APPLICABLE",
                "post_gate_downgrade_verification": "NOT_APPLICABLE",
                "verified": False,
                "errors": item_errors,
            })
            continue

        receipt_name = f"{safe_id}.http-capture.json"
        req_bin_name = f"{safe_id}.request.body.bin"
        resp_bin_name = f"{safe_id}.response.body.bin"
        inc_bin_name = f"{safe_id}.response.incomplete.bin"
        prompt_json_name = f"{safe_id}.prompt.json"
        req_json_name = f"{safe_id}.request.json"
        resp_json_name = f"{safe_id}.response.json"

        prompt_binding_errors_start = len(item_errors)

        receipt_path = _safe_regular_child_file(
            io_dir, resolved_io_dir, receipt_name, max_bytes=MAX_METADATA_JSON_BYTES, label=f"finding[{idx}] HTTP capture receipt", errors=item_errors
        )
        req_bin_path = _safe_regular_child_file(
            io_dir, resolved_io_dir, req_bin_name, max_bytes=MAX_METADATA_JSON_BYTES, label=f"finding[{idx}] raw request body", errors=item_errors
        )
        resp_bin_path = io_dir / resp_bin_name
        inc_bin_path = io_dir / inc_bin_name

        for sidecar_name in (receipt_name, req_bin_name, prompt_json_name, req_json_name, resp_json_name):
            expected_chat_files.add(sidecar_name)

        receipt_doc: dict[str, Any] = {}
        if receipt_path is not None:
            try:
                loaded = strict_json(receipt_path.read_text(encoding="utf-8"))
                if not isinstance(loaded, dict):
                    item_errors.append(f"finding[{idx}] receipt {receipt_name} is not a JSON object")
                else:
                    receipt_doc = loaded
            except (OSError, UnicodeError, ValueError, EvidenceError) as exc:
                item_errors.append(f"finding[{idx}] unreadable receipt {receipt_name}: {exc}")

        if receipt_doc:
            if receipt_doc.get("schema") != "ntk-ollama-http-capture-1":
                item_errors.append(f"finding[{idx}] unexpected receipt schema: {receipt_doc.get('schema')!r}")
            if receipt_doc.get("capture_scope") != "http_body_and_client_metadata_not_tcp_wire":
                item_errors.append(f"finding[{idx}] unexpected capture_scope: {receipt_doc.get('capture_scope')!r}")
            call_id = receipt_doc.get("call_id")
            if not isinstance(call_id, str) or not call_id:
                item_errors.append(f"finding[{idx}] missing call_id in {receipt_name}")
            elif call_id in seen_call_ids:
                item_errors.append(f"finding[{idx}] duplicate call_id {call_id}")
            else:
                seen_call_ids.add(call_id)

            if receipt_doc.get("call_kind") != "chat_analyze" or receipt_doc.get("method") != "POST" or receipt_doc.get("path") != "/api/chat":
                item_errors.append(f"finding[{idx}] receipt call_kind/method/path mismatch")
            if (
                receipt_doc.get("finding_id") != rec_id
                or receipt_doc.get("alert_id") != rec.get("alert_id")
                or receipt_doc.get("scan_sha256") != rec.get("scan_sha256")
                or type(receipt_doc.get("finding_index")) is not int
                or receipt_doc.get("finding_index") != idx
                or receipt_doc.get("rule_id") != rec.get("rule_id")
            ):
                item_errors.append(f"finding[{idx}] receipt finding metadata does not match evidence record")
            ass_model = assessment.get("model")
            ass_endpoint = assessment.get("endpoint")
            if (
                not isinstance(ass_model, str)
                or not ass_model.strip()
                or not isinstance(ass_endpoint, str)
                or not ass_endpoint.strip()
                or receipt_doc.get("requested_model") != ass_model
                or receipt_doc.get("endpoint") != ass_endpoint
            ):
                item_errors.append(f"finding[{idx}] receipt model/endpoint does not match assessment")
            if runtime.get("http_capture_receipt") != f"llm_io/{receipt_name}":
                item_errors.append(f"finding[{idx}] runtime.http_capture_receipt mismatch")
            if receipt_doc.get("request_raw_file") != req_bin_name:
                item_errors.append(
                    f"finding[{idx}] receipt request_raw_file must be {req_bin_name!r}, got {receipt_doc.get('request_raw_file')!r}"
                )
            if "request_relative_artifact" in receipt_doc and receipt_doc.get("request_relative_artifact") != f"llm_io/{req_bin_name}":
                item_errors.append(
                    f"finding[{idx}] receipt request_relative_artifact ({receipt_doc.get('request_relative_artifact')!r}) != llm_io/{req_bin_name!r}"
                )
            if runtime.get("request_raw_artifact") != f"llm_io/{req_bin_name}":
                item_errors.append(f"finding[{idx}] runtime.request_raw_artifact mismatch")
            if "transport_entered" in receipt_doc and receipt_doc.get("transport_entered") is not True:
                item_errors.append(f"finding[{idx}] receipt.transport_entered must be True, got {receipt_doc.get('transport_entered')!r}")
            if "request_attempted" in receipt_doc and receipt_doc.get("request_attempted") is not True:
                item_errors.append(f"finding[{idx}] receipt.request_attempted must be True, got {receipt_doc.get('request_attempted')!r}")
            if "http_response_received" in receipt_doc:
                rcp_hrr = receipt_doc.get("http_response_received")
                if not isinstance(rcp_hrr, bool) or ("http_response_received" in runtime and not _strict_eq(rcp_hrr, runtime.get("http_response_received"))):
                    item_errors.append(
                        f"finding[{idx}] receipt.http_response_received ({rcp_hrr!r}) mismatches runtime ({runtime.get('http_response_received')!r})"
                    )
            if "runtime_origin" in receipt_doc and not _strict_eq(receipt_doc.get("runtime_origin"), origin):
                item_errors.append(
                    f"finding[{idx}] receipt.runtime_origin ({receipt_doc.get('runtime_origin')!r}) != runtime.origin ({origin!r})"
                )
            if "origin" in receipt_doc and not _strict_eq(receipt_doc.get("origin"), origin):
                item_errors.append(
                    f"finding[{idx}] receipt.origin ({receipt_doc.get('origin')!r}) != runtime.origin ({origin!r})"
                )

        # Verify raw request payload bytes & cryptographically bind prompt metadata to raw request messages
        req_sha_verified = None
        req_len_verified = None
        canonical_request_status = "NOT_CHECKED"
        serializer_fingerprint = None
        actual_req_doc: dict[str, Any] | None = None
        actual_prompt_sha: str | None = None
        actual_template_fp: str | None = None
        recorded_prompt_version = assessment.get("prompt_version")
        pv_valid_str = (
            isinstance(recorded_prompt_version, str)
            and bool(recorded_prompt_version.strip())
            and recorded_prompt_version == recorded_prompt_version.strip()
        )
        is_historical_ver = False
        rec_contract = rec.get("prompt_contract", DEFAULT_PROMPT_CONTRACT) if isinstance(rec, dict) else None
        if not isinstance(rec_contract, str) or rec_contract not in PROMPT_CONTRACTS:
            item_errors.append(f"finding[{idx}] invalid evidence prompt_contract: {rec_contract!r}")
        elif has_bundle_contract and isinstance(bundle_contract, str) and bundle_contract != rec_contract:
            item_errors.append(
                f"finding[{idx}] evidence.json prompt_contract ({bundle_contract!r}) != record prompt_contract ({rec_contract!r})"
            )

        if req_bin_path is not None:
            req_bytes = req_bin_path.read_bytes()
            req_len_verified = len(req_bytes)
            req_sha_verified = digest(req_bytes)
            if req_sha_verified != runtime.get("request_payload_sha256"):
                item_errors.append(f"finding[{idx}] {req_bin_name} SHA-256 != runtime.request_payload_sha256")
            if req_len_verified != runtime.get("request_payload_bytes"):
                item_errors.append(f"finding[{idx}] {req_bin_name} byte length != runtime.request_payload_bytes")
            if receipt_doc:
                if req_sha_verified != receipt_doc.get("request_payload_sha256"):
                    item_errors.append(f"finding[{idx}] {req_bin_name} SHA-256 != receipt.request_payload_sha256")
                if req_len_verified != receipt_doc.get("request_byte_length"):
                    item_errors.append(f"finding[{idx}] {req_bin_name} byte length != receipt.request_byte_length")

            # Parse raw request JSON directly from verified bytes (NEVER re-serialized as raw bytes)
            try:
                parsed_req = strict_json(req_bytes.decode("utf-8"))
                if (
                    not isinstance(parsed_req, dict)
                    or not isinstance(parsed_req.get("messages"), list)
                    or len(parsed_req["messages"]) < 2
                    or not isinstance(parsed_req["messages"][0], dict)
                    or not isinstance(parsed_req["messages"][0].get("content"), str)
                    or not isinstance(parsed_req["messages"][1], dict)
                    or not isinstance(parsed_req["messages"][1].get("content"), str)
                ):
                    item_errors.append(f"finding[{idx}] {req_bin_name} lacks valid Ollama chat messages payload")
                else:
                    actual_req_doc = parsed_req
                    if actual_req_doc.get("model") != assessment.get("model"):
                        item_errors.append(
                            f"finding[{idx}] {req_bin_name} model ({actual_req_doc.get('model')!r}) != assessment.model ({assessment.get('model')!r})"
                        )
                    actual_prompt_sha = digest(
                        json.dumps(actual_req_doc["messages"], ensure_ascii=False).encode("utf-8")
                    )
                    actual_template_fp = _template_fingerprint(
                        actual_req_doc["messages"][0]["content"], actual_req_doc.get("format")
                    )
                    if assessment.get("prompt_sha256") != actual_prompt_sha:
                        item_errors.append(
                            f"finding[{idx}] assessment.prompt_sha256 mismatch against raw request messages "
                            f"(recorded={assessment.get('prompt_sha256')!r}, actual={actual_prompt_sha!r})"
                        )
                    if runtime.get("prompt_sha256") != actual_prompt_sha:
                        item_errors.append(
                            f"finding[{idx}] runtime.prompt_sha256 mismatch against raw request messages "
                            f"(recorded={runtime.get('prompt_sha256')!r}, actual={actual_prompt_sha!r})"
                        )
                    if rec_contract == "blind":
                        try:
                            user_doc = strict_json(actual_req_doc["messages"][1]["content"])
                            if isinstance(user_doc, dict) and "evidence_signals" in user_doc:
                                item_errors.append(
                                    f"finding[{idx}] raw request violates blind prompt_contract (contains evidence_signals)"
                                )
                        except (ValueError, EvidenceError):
                            pass
            except (UnicodeError, ValueError, EvidenceError) as exc:
                item_errors.append(f"finding[{idx}] {req_bin_name} failed strict JSON parse: {exc}")

            if not pv_valid_str:
                canonical_request_status = "MISSING_PROMPT_VERSION"
                item_errors.append(
                    f"finding[{idx}] missing or blank assessment.prompt_version: {recorded_prompt_version!r}"
                )
            else:
                if "prompt_version" in runtime and runtime.get("prompt_version") != recorded_prompt_version:
                    item_errors.append(
                        f"finding[{idx}] runtime.prompt_version ({runtime.get('prompt_version')!r}) != assessment.prompt_version ({recorded_prompt_version!r})"
                    )
                try:
                    expected_payload, ser_meta = request_payload_for_version(
                        rec, assessment.get("model"), prompt_version=recorded_prompt_version
                    )
                    is_historical_ver = bool(ser_meta.get("historical"))
                    serializer_fingerprint = ser_meta.get("serializer_fingerprint")
                    if "prompt_version" not in runtime and not is_historical_ver:
                        item_errors.append(
                            f"finding[{idx}] runtime missing required prompt_version for current prompt_version {recorded_prompt_version!r}"
                        )
                    if expected_payload is None:
                        canonical_request_status = "HISTORICAL_SERIALIZER_UNAVAILABLE"
                        item_errors.append(
                            f"finding[{idx}] {req_bin_name} canonical replay unavailable: no registered serializer for "
                            f"prompt_version={recorded_prompt_version!r}"
                        )
                    else:
                        expected_req_bytes = json.dumps(expected_payload).encode("utf-8")
                        if req_bytes == expected_req_bytes:
                            canonical_request_status = "HISTORICAL_MATCHED" if is_historical_ver else "MATCHED"
                        else:
                            canonical_request_status = (
                                "HISTORICAL_TEMPLATE_MISMATCH" if is_historical_ver else "CANONICAL_MISMATCH"
                            )
                            item_errors.append(
                                f"finding[{idx}] {req_bin_name} bytes differ from canonical serialized request_payload "
                                f"(prompt_version={ser_meta.get('prompt_version')!r}, status={canonical_request_status})"
                            )
                        if actual_template_fp is not None and actual_template_fp != serializer_fingerprint:
                            item_errors.append(
                                f"finding[{idx}] raw request template fingerprint ({actual_template_fp!r}) != "
                                f"expected serializer_fingerprint ({serializer_fingerprint!r}) for {recorded_prompt_version!r}"
                            )
                except (EvidenceError, KeyError, TypeError, ValueError) as exc:
                    canonical_request_status = "RECONSTRUCTION_ERROR"
                    item_errors.append(f"finding[{idx}] could not reconstruct request_payload from evidence: {exc}")

            # Verify prompt_contract metadata consistency across assessment, runtime, and receipt
            ass_contract = assessment.get("prompt_contract")
            if ass_contract is not None:
                if ass_contract not in PROMPT_CONTRACTS or ass_contract != rec_contract:
                    item_errors.append(
                        f"finding[{idx}] assessment.prompt_contract ({ass_contract!r}) != evidence prompt_contract ({rec_contract!r})"
                    )
            elif pv_valid_str and recorded_prompt_version != LEGACY_STEERED_PROMPT_VERSION:
                item_errors.append(f"finding[{idx}] assessment missing prompt_contract for {recorded_prompt_version!r}")
            if "prompt_contract" in runtime:
                if not isinstance(runtime.get("prompt_contract"), str) or runtime.get("prompt_contract") != rec_contract:
                    item_errors.append(
                        f"finding[{idx}] runtime.prompt_contract ({runtime.get('prompt_contract')!r}) != evidence prompt_contract ({rec_contract!r})"
                    )
            elif pv_valid_str and not is_historical_ver:
                item_errors.append(
                    f"finding[{idx}] runtime missing required prompt_contract for current prompt_version {recorded_prompt_version!r}"
                )
            if pv_valid_str and not is_historical_ver and assessment.get("requires_human_review") is not True:
                item_errors.append(
                    f"finding[{idx}] assessment.requires_human_review must be True for current prompt_version {recorded_prompt_version!r}"
                )
            if receipt_doc:
                if "runtime_origin" not in receipt_doc and pv_valid_str and not is_historical_ver:
                    item_errors.append(
                        f"finding[{idx}] receipt missing required runtime_origin for current prompt_version {recorded_prompt_version!r}"
                    )
                if "prompt_version" in receipt_doc:
                    if not pv_valid_str or not _strict_eq(receipt_doc.get("prompt_version"), recorded_prompt_version):
                        item_errors.append(
                            f"finding[{idx}] receipt.prompt_version ({receipt_doc.get('prompt_version')!r}) != assessment.prompt_version ({recorded_prompt_version!r})"
                        )
                elif pv_valid_str and not is_historical_ver:
                    item_errors.append(
                        f"finding[{idx}] receipt missing required prompt_version for current prompt_version {recorded_prompt_version!r}"
                    )
                if "prompt_sha256" in receipt_doc:
                    if actual_prompt_sha is None or not _strict_eq(receipt_doc.get("prompt_sha256"), actual_prompt_sha):
                        item_errors.append(
                            f"finding[{idx}] receipt.prompt_sha256 ({receipt_doc.get('prompt_sha256')!r}) != raw request prompt_sha256 ({actual_prompt_sha!r})"
                        )
                elif pv_valid_str and not is_historical_ver:
                    item_errors.append(
                        f"finding[{idx}] receipt missing required prompt_sha256 for current prompt_version {recorded_prompt_version!r}"
                    )
                if "prompt_contract" in receipt_doc:
                    if not isinstance(receipt_doc.get("prompt_contract"), str) or receipt_doc.get("prompt_contract") != rec_contract:
                        item_errors.append(
                            f"finding[{idx}] receipt.prompt_contract ({receipt_doc.get('prompt_contract')!r}) != evidence prompt_contract ({rec_contract!r})"
                        )
                elif pv_valid_str and not is_historical_ver:
                    item_errors.append(
                        f"finding[{idx}] receipt missing required prompt_contract for current prompt_version {recorded_prompt_version!r}"
                    )

            # Bind serializer_fingerprint across assessment, runtime, and receipt whenever declared (and mandatory for current version)
            for src_name, container in (
                ("assessment", assessment),
                ("runtime", runtime),
                ("receipt", receipt_doc),
            ):
                if "serializer_fingerprint" in container:
                    decl_fp = container.get("serializer_fingerprint")
                    if (
                        not isinstance(decl_fp, str)
                        or not decl_fp
                        or serializer_fingerprint is None
                        or decl_fp != serializer_fingerprint
                        or (actual_template_fp is not None and decl_fp != actual_template_fp)
                    ):
                        item_errors.append(
                            f"finding[{idx}] {src_name}.serializer_fingerprint mismatch: declared={decl_fp!r}, verified={serializer_fingerprint!r}"
                        )
                elif pv_valid_str and not is_historical_ver:
                    if src_name != "receipt" or bool(receipt_doc):
                        item_errors.append(
                            f"finding[{idx}] {src_name} missing required serializer_fingerprint for current prompt_version {recorded_prompt_version!r}"
                        )

        completeness = receipt_doc.get("completeness") if receipt_doc else None
        if receipt_doc and "http_capture_completeness" in runtime and runtime.get("http_capture_completeness") != completeness:
            item_errors.append(
                f"finding[{idx}] runtime.http_capture_completeness ({runtime.get('http_capture_completeness')!r}) != receipt.completeness ({completeness!r})"
            )
        if receipt_doc and not _strict_eq(receipt_doc.get("http_status"), runtime.get("http_status")):
            item_errors.append(
                f"finding[{idx}] receipt.http_status ({receipt_doc.get('http_status')!r}) != runtime.http_status ({runtime.get('http_status')!r})"
            )

        # Verify compatibility JSON sidecars and cryptographically bind them to raw request bytes & authoritative metadata
        prompt_sidecar_has_fp = False
        sidecar_answer_validated: bool | None = None
        sidecar_runtime_doc: dict[str, Any] | None = None
        sidecar_error_text: str | None = None
        recomputed_error_gate_doc: dict[str, Any] | None = None
        recomputed_error_gate_err: str | None = None
        is_legal_post_gate_downgrade = False
        layer1_verification = "NOT_APPLICABLE"
        integration_gate_verification = "NOT_APPLICABLE"
        post_gate_downgrade_verification = "NOT_APPLICABLE"
        for json_sidecar in (prompt_json_name, req_json_name, resp_json_name):
            sidecar_path = _safe_regular_child_file(
                io_dir,
                resolved_io_dir,
                json_sidecar,
                max_bytes=MAX_METADATA_JSON_BYTES,
                label=f"finding[{idx}] compatibility artifact",
                errors=item_errors,
            )
            if sidecar_path is not None:
                try:
                    s_doc = strict_json(sidecar_path.read_text(encoding="utf-8"))
                    if not isinstance(s_doc, dict):
                        item_errors.append(f"finding[{idx}] compatibility artifact {json_sidecar} is not a JSON object")
                        continue
                    if json_sidecar == prompt_json_name:
                        if s_doc.get("finding_id") != rec_id or s_doc.get("prompt_sha256") != assessment.get("prompt_sha256"):
                            item_errors.append(f"finding[{idx}] {prompt_json_name} finding_id/prompt_sha256 mismatch")
                        if actual_prompt_sha is not None and s_doc.get("prompt_sha256") != actual_prompt_sha:
                            item_errors.append(
                                f"finding[{idx}] {prompt_json_name} prompt_sha256 mismatch against raw request messages"
                            )
                        if pv_valid_str and s_doc.get("prompt_version") != recorded_prompt_version:
                            item_errors.append(
                                f"finding[{idx}] {prompt_json_name} prompt_version ({s_doc.get('prompt_version')!r}) != assessment.prompt_version ({recorded_prompt_version!r})"
                            )
                        s_contract = s_doc.get("prompt_contract")
                        if s_contract is not None:
                            if not isinstance(s_contract, str) or s_contract not in PROMPT_CONTRACTS or s_contract != rec_contract:
                                item_errors.append(
                                    f"finding[{idx}] {prompt_json_name} prompt_contract ({s_contract!r}) != evidence prompt_contract ({rec_contract!r})"
                                )
                        elif pv_valid_str and recorded_prompt_version != LEGACY_STEERED_PROMPT_VERSION:
                            item_errors.append(f"finding[{idx}] {prompt_json_name} missing prompt_contract")
                        if actual_req_doc is not None and s_doc.get("messages") != actual_req_doc.get("messages"):
                            item_errors.append(f"finding[{idx}] {prompt_json_name} messages differ from raw {req_bin_name}")
                        if "serializer_fingerprint" in s_doc:
                            prompt_sidecar_has_fp = True
                            p_fp = s_doc.get("serializer_fingerprint")
                            if (
                                not isinstance(p_fp, str)
                                or not p_fp
                                or serializer_fingerprint is None
                                or p_fp != serializer_fingerprint
                                or (actual_template_fp is not None and p_fp != actual_template_fp)
                            ):
                                item_errors.append(
                                    f"finding[{idx}] {prompt_json_name} serializer_fingerprint mismatch: declared={p_fp!r}, verified={serializer_fingerprint!r}"
                                )
                        elif pv_valid_str and not is_historical_ver:
                            item_errors.append(
                                f"finding[{idx}] {prompt_json_name} missing required serializer_fingerprint for current prompt_version {recorded_prompt_version!r}"
                            )
                    elif json_sidecar == req_json_name:
                        if actual_req_doc is not None and not _strict_eq(s_doc, actual_req_doc):
                            item_errors.append(f"finding[{idx}] {req_json_name} differs from raw {req_bin_name}")
                    elif json_sidecar == resp_json_name:
                        if s_doc.get("finding_id") != rec_id:
                            item_errors.append(f"finding[{idx}] {resp_json_name} finding_id mismatch")
                        if "raw_response" not in s_doc or not _strict_eq(s_doc.get("raw_response"), assessment.get("raw_response")):
                            item_errors.append(f"finding[{idx}] {resp_json_name} raw_response missing or mismatches assessment.raw_response")
                        if "model" not in s_doc or not _strict_eq(s_doc.get("model"), assessment.get("model")):
                            item_errors.append(
                                f"finding[{idx}] {resp_json_name} model ({s_doc.get('model')!r}) missing or != assessment.model ({assessment.get('model')!r})"
                            )
                        if "endpoint" not in s_doc or not _strict_eq(s_doc.get("endpoint"), assessment.get("endpoint")):
                            item_errors.append(
                                f"finding[{idx}] {resp_json_name} endpoint ({s_doc.get('endpoint')!r}) missing or != assessment.endpoint ({assessment.get('endpoint')!r})"
                            )
                        for timing_k in ("elapsed_seconds", "latency_ms"):
                            if timing_k in s_doc and not _is_finite_nonneg_number(s_doc.get(timing_k)):
                                item_errors.append(
                                    f"finding[{idx}] {resp_json_name} {timing_k} must be a finite non-negative number, got {s_doc.get(timing_k)!r}"
                                )
                        if "http_error_body" in s_doc:
                            s_heb = s_doc.get("http_error_body")
                            if s_heb is not None and not isinstance(s_heb, str):
                                item_errors.append(
                                    f"finding[{idx}] {resp_json_name} http_error_body must be string or null, got {type(s_heb).__name__}"
                                )
                            elif completeness == "complete" and s_heb is not None:
                                item_errors.append(
                                    f"finding[{idx}] {resp_json_name} sets http_error_body on HTTP 200 complete capture"
                                )
                        s_rt = s_doc.get("runtime")
                        if "runtime" not in s_doc or not isinstance(s_rt, dict):
                            item_errors.append(f"finding[{idx}] {resp_json_name} missing required runtime JSON object")
                            s_rt = None
                        else:
                            sidecar_runtime_doc = s_rt
                            # Exhaustive structural binding of ALL non-post-gate runtime keys between sidecar and assessment.runtime
                            for rt_k in sorted((set(s_rt) | set(runtime)) - _POST_GATE_RUNTIME_KEYS):
                                if rt_k not in s_rt or rt_k not in runtime or not _strict_eq(s_rt.get(rt_k), runtime.get(rt_k)):
                                    item_errors.append(
                                        f"finding[{idx}] {resp_json_name} runtime.{rt_k} mismatch with assessment.runtime "
                                        f"(sidecar={s_rt.get(rt_k)!r}, assessment={runtime.get(rt_k)!r})"
                                    )
                            # Recompute deterministic Integration Gate decision on parsed HTTP 200 Layer-1 error assessments
                            # from locked sidecar + evidence (NEVER keyed on assessment.validator_downgraded on current captures).
                            s_err_pre = s_doc.get("error")
                            s_av = s_rt.get("answer_validated")
                            r_av = runtime.get("answer_validated")
                            s_raw_obj = s_doc.get("raw_response")
                            if (
                                completeness == "complete"
                                and receipt_doc.get("response_json_parse_succeeded") is True
                                and s_av is False
                                and isinstance(s_err_pre, str)
                                and bool(s_err_pre.strip())
                                and isinstance(s_raw_obj, dict)
                            ):
                                s_raw_content = (
                                    s_raw_obj.get("message", {}).get("content")
                                    if isinstance(s_raw_obj.get("message"), dict)
                                    else None
                                )
                                s_raw_ms = _extract_raw_model_status(s_raw_content)
                                should_recompute_err_gate = (not is_historical_ver) or (
                                    s_raw_ms is not None and s_raw_ms not in STATUSES
                                )
                                if should_recompute_err_gate:
                                    recomputed_error_gate_doc, recomputed_error_gate_err = _recompute_error_gate_decision(
                                        rec,
                                        sidecar_error=s_err_pre,
                                        raw_model_status=s_raw_ms,
                                        sidecar_runtime=s_rt,
                                        prompt_version=recorded_prompt_version if pv_valid_str else None,
                                        raw_response=s_raw_obj,
                                    )
                            gate_required_error_downgrade = _is_gate_error_downgrade_transition(
                                recomputed_error_gate_doc, s_err_pre
                            )
                            # Post-call integration gate keys may ONLY transition in the fail-closed downgrade direction
                            if not isinstance(s_av, bool) or not isinstance(r_av, bool):
                                item_errors.append(
                                    f"finding[{idx}] {resp_json_name} runtime.answer_validated ({s_av!r}) / assessment.runtime.answer_validated ({r_av!r}) must be boolean"
                                )
                            else:
                                sidecar_answer_validated = s_av
                                is_legal_post_gate_downgrade = (
                                    s_av is True
                                    and r_av is False
                                    and assessment.get("validated_status") == "UNDETERMINED"
                                    and assessment.get("status") == "UNDETERMINED"
                                    and assessment.get("validator_downgraded") is True
                                    and runtime.get("validator_downgraded") is True
                                    and s_rt.get("validator_downgraded") in (None, False)
                                    and s_rt.get("failure_kind") in (None, "NONE")
                                    and isinstance(runtime.get("failure_kind"), str)
                                    and runtime.get("failure_kind") not in ("", "NONE")
                                    and _strict_eq(assessment.get("failure_kind"), runtime.get("failure_kind"))
                                    and isinstance(assessment.get("downgrade_reason"), str)
                                    and bool(assessment["downgrade_reason"].strip())
                                )
                                is_legal_error_gate_downgrade = (
                                    gate_required_error_downgrade
                                    and recomputed_error_gate_doc is not None
                                    and s_av is False
                                    and r_av is False
                                    and assessment.get("validated_status") == "UNDETERMINED"
                                    and assessment.get("status") == "UNDETERMINED"
                                    and assessment.get("validator_downgraded") is True
                                    and runtime.get("validator_downgraded") is True
                                    and s_rt.get("validator_downgraded") in (None, False)
                                    and _strict_eq(runtime.get("failure_kind"), recomputed_error_gate_doc.get("failure_kind"))
                                    and _strict_eq(assessment.get("failure_kind"), runtime.get("failure_kind"))
                                )
                                if not is_legal_post_gate_downgrade and not is_legal_error_gate_downgrade:
                                    if s_av != r_av:
                                        item_errors.append(
                                            f"finding[{idx}] {resp_json_name} runtime.answer_validated ({s_av!r}) contradicts assessment.runtime.answer_validated ({r_av!r})"
                                        )
                                    if ("failure_kind" in s_rt) != ("failure_kind" in runtime) or not _strict_eq(
                                        s_rt.get("failure_kind"), runtime.get("failure_kind")
                                    ):
                                        item_errors.append(
                                            f"finding[{idx}] {resp_json_name} runtime.failure_kind ({s_rt.get('failure_kind')!r}) != assessment.runtime.failure_kind ({runtime.get('failure_kind')!r})"
                                        )
                                    if ("validator_downgraded" in s_rt) != ("validator_downgraded" in runtime) or not _strict_eq(
                                        s_rt.get("validator_downgraded"), runtime.get("validator_downgraded")
                                    ):
                                        item_errors.append(
                                            f"finding[{idx}] {resp_json_name} runtime.validator_downgraded ({s_rt.get('validator_downgraded')!r}) != assessment.runtime.validator_downgraded ({runtime.get('validator_downgraded')!r})"
                                        )
                                    if gate_required_error_downgrade and not is_historical_ver:
                                        item_errors.append(
                                            f"finding[{idx}] Layer-1 rejected assessment requires Integration Gate downgrade "
                                            f"(failure_kind={recomputed_error_gate_doc.get('failure_kind')!r}, validator_downgraded=True), "
                                            f"but assessment did not record the required Gate downgrade transition"
                                        )
                        # Strict binding of sidecar .response.json["error"] against sidecar runtime, receipt, and assessment
                        if "error" not in s_doc:
                            item_errors.append(f"finding[{idx}] {resp_json_name} missing required 'error' field")
                        else:
                            s_err = s_doc.get("error")
                            if s_err is None:
                                if s_rt is not None:
                                    if s_rt.get("answer_validated") is not True:
                                        item_errors.append(
                                            f"finding[{idx}] {resp_json_name} error is null while runtime.answer_validated is {s_rt.get('answer_validated')!r}"
                                        )
                                    if "failure_kind" in s_rt and s_rt.get("failure_kind") != "NONE":
                                        item_errors.append(
                                            f"finding[{idx}] {resp_json_name} error is null while runtime.failure_kind is {s_rt.get('failure_kind')!r}"
                                        )
                                if receipt_doc and (
                                    completeness != "complete" or receipt_doc.get("response_json_parse_succeeded") is not True
                                ):
                                    item_errors.append(
                                        f"finding[{idx}] {resp_json_name} error is null despite incomplete/unparsed HTTP capture ({completeness!r})"
                                    )
                            elif not isinstance(s_err, str) or not s_err.strip():
                                item_errors.append(
                                    f"finding[{idx}] {resp_json_name} error must be null or non-empty string, got {s_err!r}"
                                )
                            else:
                                sidecar_error_text = s_err
                                if s_rt is not None:
                                    if s_rt.get("answer_validated") is not False:
                                        item_errors.append(
                                            f"finding[{idx}] {resp_json_name} reports error ({s_err!r}) while sidecar runtime.answer_validated is {s_rt.get('answer_validated')!r}"
                                        )
                                    if "failure_kind" in s_rt and (
                                        not isinstance(s_rt.get("failure_kind"), str)
                                        or s_rt.get("failure_kind") in ("", "NONE")
                                    ):
                                        item_errors.append(
                                            f"finding[{idx}] {resp_json_name} reports error while sidecar runtime.failure_kind is {s_rt.get('failure_kind')!r}"
                                        )
                                if runtime.get("answer_validated") is not False:
                                    item_errors.append(
                                        f"finding[{idx}] {resp_json_name} reports error while assessment.runtime.answer_validated is {runtime.get('answer_validated')!r}"
                                    )
                                if assessment.get("validated_status") != "UNDETERMINED" or assessment.get("status") != "UNDETERMINED":
                                    item_errors.append(
                                        f"finding[{idx}] {resp_json_name} reports error while assessment status is {assessment.get('validated_status')!r}/{assessment.get('status')!r}"
                                    )
                                if "failure_kind" in assessment and (
                                    not isinstance(assessment.get("failure_kind"), str)
                                    or assessment.get("failure_kind") in ("", "NONE")
                                ):
                                    item_errors.append(
                                        f"finding[{idx}] {resp_json_name} reports error while assessment.failure_kind is {assessment.get('failure_kind')!r}"
                                    )
                                ass_expl = assessment.get("explanation")
                                err_gate_active = _is_gate_error_downgrade_transition(recomputed_error_gate_doc, s_err)
                                if err_gate_active and not is_historical_ver:
                                    expl_matches_sidecar = (
                                        recomputed_error_gate_doc is not None
                                        and _strict_eq(ass_expl, recomputed_error_gate_doc.get("explanation"))
                                    )
                                else:
                                    expl_matches_sidecar = _strict_eq(ass_expl, s_err) or (
                                        err_gate_active
                                        and recomputed_error_gate_doc is not None
                                        and _strict_eq(ass_expl, recomputed_error_gate_doc.get("explanation"))
                                    )
                                if not expl_matches_sidecar:
                                    item_errors.append(
                                        f"finding[{idx}] {resp_json_name} error ({s_err!r}) contradicts assessment.explanation ({ass_expl!r})"
                                    )
                except (OSError, UnicodeError, ValueError, EvidenceError) as exc:
                    item_errors.append(f"finding[{idx}] unreadable compatibility artifact {json_sidecar}: {exc}")

        prompt_metadata_ok = (
            len(item_errors) == prompt_binding_errors_start
            and req_bin_path is not None
            and actual_req_doc is not None
            and actual_prompt_sha is not None
            and serializer_fingerprint is not None
            and canonical_request_status in ("MATCHED", "HISTORICAL_MATCHED")
        )
        if not prompt_metadata_ok:
            prompt_metadata_binding = "FAILED"
        elif (
            assessment.get("serializer_fingerprint") == serializer_fingerprint
            and runtime.get("serializer_fingerprint") == serializer_fingerprint
            and prompt_sidecar_has_fp
        ):
            prompt_metadata_binding = "VERIFIED_EXPLICIT"
        else:
            prompt_metadata_binding = "VERIFIED_HISTORICAL_RECONSTRUCTED_WITHOUT_RECORDED_FINGERPRINT"

        # Verify raw response body bytes according to completeness state
        resp_sha_verified = None
        resp_len_verified = None
        finding_endpoint_proto_ok = False
        strict_item_errors: list[str] = []
        if completeness in ("complete", "complete_http_error_body"):
            expected_chat_files.add(resp_bin_name)
            if receipt_doc.get("complete") is not True:
                item_errors.append(f"finding[{idx}] receipt completeness={completeness} must set complete=True")
            if "http_capture_complete" in runtime and runtime.get("http_capture_complete") is not True:
                item_errors.append(f"finding[{idx}] runtime.http_capture_complete must be True for completeness={completeness}")
            if "http_response_received" in runtime and runtime.get("http_response_received") is not True:
                item_errors.append(f"finding[{idx}] runtime.http_response_received must be True for completeness={completeness}")
            if receipt_doc.get("response_raw_file") != resp_bin_name:
                item_errors.append(
                    f"finding[{idx}] receipt response_raw_file must be {resp_bin_name!r}, got {receipt_doc.get('response_raw_file')!r}"
                )
            if "response_relative_artifact" in receipt_doc and receipt_doc.get("response_relative_artifact") != f"llm_io/{resp_bin_name}":
                item_errors.append(
                    f"finding[{idx}] receipt response_relative_artifact ({receipt_doc.get('response_relative_artifact')!r}) != llm_io/{resp_bin_name!r}"
                )
            if runtime.get("response_raw_artifact") != f"llm_io/{resp_bin_name}":
                item_errors.append(f"finding[{idx}] runtime.response_raw_artifact mismatch")
            if os.path.lexists(inc_bin_path):
                item_errors.append(f"finding[{idx}] unexpected {inc_bin_name} alongside complete response")
            safe_resp_path = _safe_regular_child_file(
                io_dir,
                resolved_io_dir,
                resp_bin_name,
                max_bytes=MAX_HTTP_BODY_BYTES,
                label=f"finding[{idx}] raw response body",
                errors=item_errors,
            )
            if safe_resp_path is not None:
                resp_bytes = safe_resp_path.read_bytes()
                resp_len_verified = len(resp_bytes)
                resp_sha_verified = digest(resp_bytes)
                if resp_len_verified > MAX_HTTP_BODY_BYTES:
                    item_errors.append(f"finding[{idx}] {resp_bin_name} exceeds MAX_HTTP_BODY_BYTES")
                if resp_sha_verified != runtime.get("response_body_sha256"):
                    item_errors.append(f"finding[{idx}] {resp_bin_name} SHA-256 != runtime.response_body_sha256")
                if resp_len_verified != runtime.get("response_body_bytes"):
                    item_errors.append(f"finding[{idx}] {resp_bin_name} byte length != runtime.response_body_bytes")
                if resp_sha_verified != receipt_doc.get("response_body_sha256"):
                    item_errors.append(f"finding[{idx}] {resp_bin_name} SHA-256 != receipt.response_body_sha256")
                if resp_len_verified != receipt_doc.get("response_byte_length"):
                    item_errors.append(f"finding[{idx}] {resp_bin_name} byte length != receipt.response_byte_length")
                if (
                    type(receipt_doc.get("http_status")) is not int
                    or type(runtime.get("http_status")) is not int
                    or receipt_doc.get("http_status") != runtime.get("http_status")
                    or not isinstance(receipt_doc.get("response_headers"), list)
                ):
                    item_errors.append(f"finding[{idx}] receipt http_status/response_headers mismatch")

                if completeness == "complete":
                    complete_chat_count += 1
                    if type(receipt_doc.get("http_status")) is not int or receipt_doc.get("http_status") != 200:
                        item_errors.append(f"finding[{idx}] completeness='complete' requires integer http_status 200")
                    if "transport_error" in receipt_doc and receipt_doc.get("transport_error") is not None:
                        item_errors.append(f"finding[{idx}] completeness='complete' must have null transport_error")
                    if not isinstance(receipt_doc.get("response_json_parse_succeeded"), bool):
                        item_errors.append(
                            f"finding[{idx}] completeness='complete' requires boolean response_json_parse_succeeded, got {receipt_doc.get('response_json_parse_succeeded')!r}"
                        )
                    if receipt_doc.get("response_json_parse_succeeded") is True:
                        if "parse_error" in receipt_doc and receipt_doc.get("parse_error") is not None:
                            item_errors.append(f"finding[{idx}] response_json_parse_succeeded=True must have null parse_error")
                        try:
                            parsed_raw = strict_json(resp_bytes.decode("utf-8"))
                            if not _strict_eq(parsed_raw, assessment.get("raw_response")):
                                item_errors.append(f"finding[{idx}] parsed {resp_bin_name} != assessment.raw_response")
                            canon_sha = digest(
                                json.dumps(parsed_raw, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
                            )
                            if canon_sha != runtime.get("response_json_sha256") or canon_sha != receipt_doc.get("response_json_sha256"):
                                item_errors.append(f"finding[{idx}] canonical response_json_sha256 mismatch")

                            # Bind full assessment content across Raw HTTP -> Layer-1 Validator -> Sidecar -> Integration Gate -> Assessment.
                            expected_l1_model = (
                                actual_req_doc.get("model")
                                if isinstance(actual_req_doc, dict) and isinstance(actual_req_doc.get("model"), str)
                                else assessment.get("model")
                            )
                            (
                                layer1_verification,
                                integration_gate_verification,
                                post_gate_downgrade_verification,
                            ) = _verify_http200_parsed_assessment_content(
                                idx,
                                rec,
                                assessment,
                                runtime,
                                parsed_raw,
                                expected_model=expected_l1_model,
                                sidecar_answer_validated=sidecar_answer_validated,
                                sidecar_runtime=sidecar_runtime_doc,
                                sidecar_error=sidecar_error_text,
                                recomputed_error_gate_doc=recomputed_error_gate_doc,
                                recomputed_error_gate_err=recomputed_error_gate_err,
                                is_legal_post_gate_downgrade=is_legal_post_gate_downgrade,
                                recorded_prompt_version=recorded_prompt_version if pv_valid_str else None,
                                is_historical_ver=is_historical_ver,
                                item_errors=item_errors,
                            )

                            # Level 3: Evaluate endpoint-reported protocol shape (self-reported by HTTP peer; NEVER proves live Ollama origin!)
                            f_proto_errs: list[str] = []
                            if is_mock or origin != "unverified":
                                f_proto_errs.append(f"finding[{idx}] origin ({origin!r}) / mock ({is_mock}) is not non-mock live HTTP")
                            if assessment.get("transport") != "ollama-http":
                                f_proto_errs.append(f"finding[{idx}] live chat requires transport='ollama-http', got {assessment.get('transport')!r}")
                            if assessment.get("security_conclusion_verified") is not False:
                                f_proto_errs.append(f"finding[{idx}] live chat requires security_conclusion_verified=False")
                            if runtime.get("model_runtime_verified") is not False:
                                f_proto_errs.append(f"finding[{idx}] live chat requires explicit runtime.model_runtime_verified=False")
                            sp_ok, sp_err = _check_endpoint_reported_scan_provenance(rec.get("scan_provenance") if isinstance(rec, dict) else None)
                            if not sp_ok:
                                f_proto_errs.append(f"finding[{idx}] missing verified non-mock scan provenance: {sp_err}")
                            if receipt_doc.get("transport_entered") is not True:
                                f_proto_errs.append(f"finding[{idx}] receipt missing transport_entered=True live transport marker")
                            if receipt_doc.get("request_attempted") is not True:
                                f_proto_errs.append(f"finding[{idx}] receipt missing request_attempted=True")
                            if receipt_doc.get("http_response_received") is not True:
                                f_proto_errs.append(f"finding[{idx}] receipt missing http_response_received=True")
                            if receipt_doc.get("request_relative_artifact") != f"llm_io/{req_bin_name}":
                                f_proto_errs.append(f"finding[{idx}] receipt missing request_relative_artifact")
                            if receipt_doc.get("response_relative_artifact") != f"llm_io/{resp_bin_name}":
                                f_proto_errs.append(f"finding[{idx}] receipt missing response_relative_artifact")
                            dt_start = _parse_iso_utc(receipt_doc.get("started_at_utc"))
                            dt_end = _parse_iso_utc(receipt_doc.get("finished_at_utc"))
                            if dt_start is None or dt_end is None or dt_end < dt_start:
                                f_proto_errs.append(f"finding[{idx}] receipt missing valid UTC started_at_utc/finished_at_utc timing provenance")
                            if not _is_finite_nonneg_number(receipt_doc.get("elapsed_seconds")):
                                f_proto_errs.append(f"finding[{idx}] receipt missing valid finite non-negative elapsed_seconds")
                            if not _valid_response_headers(receipt_doc.get("response_headers")):
                                f_proto_errs.append(f"finding[{idx}] receipt missing valid HTTP response_headers pairs")
                            if not isinstance(parsed_raw, dict):
                                f_proto_errs.append(f"finding[{idx}] parsed raw response is not a JSON object")
                            else:
                                if parsed_raw.get("done") is not True or parsed_raw.get("done_reason") not in (None, "stop"):
                                    f_proto_errs.append(f"finding[{idx}] raw response lacks completed Ollama done/done_reason markers")
                                if not isinstance(parsed_raw.get("model"), str) or parsed_raw.get("model") != assessment.get("model"):
                                    f_proto_errs.append(f"finding[{idx}] raw response model mismatches assessment.model")
                                if not isinstance(parsed_raw.get("created_at"), str) or not parsed_raw["created_at"].strip():
                                    f_proto_errs.append(f"finding[{idx}] raw response missing Ollama created_at timestamp")
                                ev_cnt = parsed_raw.get("eval_count")
                                ev_dur = parsed_raw.get("eval_duration")
                                if type(ev_cnt) is not int or ev_cnt <= 0 or type(ev_dur) is not int or ev_dur <= 0:
                                    f_proto_errs.append(f"finding[{idx}] raw response missing positive integer eval_count/eval_duration counters")
                                if runtime.get("response_complete") is not True:
                                    f_proto_errs.append(f"finding[{idx}] runtime missing response_complete=True")
                                if runtime.get("model_identity_matched") is not True:
                                    f_proto_errs.append(f"finding[{idx}] runtime missing model_identity_matched=True")
                                if type(runtime.get("reported_eval_count")) is not int or runtime.get("reported_eval_count") != ev_cnt:
                                    f_proto_errs.append(f"finding[{idx}] runtime.reported_eval_count missing or mismatches raw response eval_count")
                                if type(runtime.get("reported_eval_duration_ns")) is not int or runtime.get("reported_eval_duration_ns") != ev_dur:
                                    f_proto_errs.append(f"finding[{idx}] runtime.reported_eval_duration_ns missing or mismatches raw response eval_duration")
                                if runtime.get("http_capture_complete") is not True or runtime.get("http_capture_completeness") != "complete":
                                    f_proto_errs.append(f"finding[{idx}] runtime missing http_capture_complete=True / completeness='complete'")
                            if not f_proto_errs and len(item_errors) == 0:
                                finding_endpoint_proto_ok = True
                                endpoint_reported_non_mock_complete_count += 1
                                if isinstance(assessment.get("endpoint"), str) and isinstance(assessment.get("model"), str):
                                    endpoint_expected_pairs.add((assessment["endpoint"], assessment["model"]))
                            else:
                                endpoint_reported_protocol_errors.extend(f_proto_errs)
                                strict_item_errors.extend(f_proto_errs)
                        except (UnicodeError, ValueError, EvidenceError) as exc:
                            item_errors.append(f"finding[{idx}] receipt claimed JSON parse succeeded but {resp_bin_name} failed strict_json: {exc}")
                    else:
                        # Malformed JSON or invalid UTF-8 on HTTP 200: raw bytes preserved, must not validate!
                        if assessment.get("raw_response") is not None:
                            item_errors.append(f"finding[{idx}] unparseable HTTP 200 body must have raw_response=None")
                        if runtime.get("answer_validated") is True or assessment.get("validated_status") != "UNDETERMINED":
                            item_errors.append(f"finding[{idx}] unparseable HTTP 200 body must fail closed to UNDETERMINED")
                        _verify_empty_undetermined_assessment(
                            idx,
                            assessment,
                            require_v226_fields=(not is_historical_ver),
                            expected_raw_model_status=_peek_raw_model_status_from_bytes(resp_bytes),
                            item_errors=item_errors,
                            context_label="http200_parse_failed",
                            sidecar_error=sidecar_error_text,
                            allowed_error_gate_doc=(
                                recomputed_error_gate_doc
                                if _is_gate_error_downgrade_transition(recomputed_error_gate_doc, sidecar_error_text)
                                else None
                            ),
                        )
                        parse_msg = f"finding[{idx}] HTTP 200 response failed strict JSON parsing"
                        endpoint_reported_protocol_errors.append(parse_msg)
                        strict_item_errors.append(parse_msg)
                else:
                    # complete_http_error_body (e.g. HTTP 404/500)
                    partial_or_error_count += 1
                    if type(receipt_doc.get("http_status")) is not int or (200 <= receipt_doc["http_status"] < 300):
                        item_errors.append(
                            f"finding[{idx}] completeness='complete_http_error_body' requires non-2xx integer http_status, got {receipt_doc.get('http_status')!r}"
                        )
                    if receipt_doc.get("response_json_parse_succeeded") is True:
                        item_errors.append(f"finding[{idx}] complete_http_error_body must not set response_json_parse_succeeded=True")
                    if assessment.get("raw_response") is not None:
                        item_errors.append(f"finding[{idx}] HTTP error response must have raw_response=None")
                    if runtime.get("response_json_sha256") is not None or receipt_doc.get("response_json_sha256") is not None:
                        item_errors.append(f"finding[{idx}] HTTP error response must not set response_json_sha256")
                    if (
                        runtime.get("answer_validated") is True
                        or assessment.get("status") != "UNDETERMINED"
                        or assessment.get("validated_status", assessment.get("status")) != "UNDETERMINED"
                    ):
                        item_errors.append(f"finding[{idx}] HTTP error response must fail closed to UNDETERMINED")
                    _verify_empty_undetermined_assessment(
                        idx,
                        assessment,
                        require_v226_fields=(not is_historical_ver),
                        expected_raw_model_status=None,
                        item_errors=item_errors,
                        context_label="complete_http_error_body",
                        sidecar_error=sidecar_error_text,
                    )
                    err_status_msg = f"finding[{idx}] HTTP error status {receipt_doc.get('http_status')}"
                    endpoint_reported_protocol_errors.append(err_status_msg)
                    strict_item_errors.append(err_status_msg)
        elif completeness in ("partial_read_error", "exceeded_max_bytes_prefix_only"):
            partial_or_error_count += 1
            if receipt_doc.get("complete") is not False or runtime.get("http_capture_complete") is not False:
                item_errors.append(f"finding[{idx}] incomplete response must have complete=False")
            if receipt_doc.get("response_json_parse_succeeded") is True:
                item_errors.append(f"finding[{idx}] incomplete response must not set response_json_parse_succeeded=True")
            if assessment.get("raw_response") is not None:
                item_errors.append(f"finding[{idx}] incomplete response must have raw_response=None")
            if runtime.get("response_json_sha256") is not None or receipt_doc.get("response_json_sha256") is not None:
                item_errors.append(f"finding[{idx}] incomplete response must not fabricate response_json_sha256")
            if runtime.get("response_body_sha256") is not None or receipt_doc.get("response_body_sha256") is not None:
                item_errors.append(f"finding[{idx}] incomplete response must not fabricate response_body_sha256")
            if os.path.lexists(resp_bin_path):
                item_errors.append(f"finding[{idx}] incomplete response must not write {resp_bin_name}")
            if receipt_doc.get("response_incomplete_raw_file") is not None:
                if receipt_doc.get("response_incomplete_raw_file") != inc_bin_name:
                    item_errors.append(
                        f"finding[{idx}] receipt response_incomplete_raw_file must be {inc_bin_name!r}, got {receipt_doc.get('response_incomplete_raw_file')!r}"
                    )
                else:
                    expected_chat_files.add(inc_bin_name)
                    safe_inc_path = _safe_regular_child_file(
                        io_dir,
                        resolved_io_dir,
                        inc_bin_name,
                        max_bytes=MAX_HTTP_BODY_BYTES + 1024,
                        label=f"finding[{idx}] incomplete body",
                        errors=item_errors,
                    )
                    if safe_inc_path is not None:
                        inc_bytes = safe_inc_path.read_bytes()
                        if len(inc_bytes) > MAX_HTTP_BODY_BYTES:
                            item_errors.append(f"finding[{idx}] {inc_bin_name} exceeds MAX_HTTP_BODY_BYTES")
                        if len(inc_bytes) != receipt_doc.get("response_incomplete_byte_length"):
                            item_errors.append(f"finding[{idx}] {inc_bin_name} byte length mismatch")
                        if digest(inc_bytes) != receipt_doc.get("response_incomplete_sha256"):
                            item_errors.append(f"finding[{idx}] {inc_bin_name} SHA-256 mismatch")
            if (
                runtime.get("answer_validated") is True
                or assessment.get("status") != "UNDETERMINED"
                or assessment.get("validated_status", assessment.get("status")) != "UNDETERMINED"
            ):
                item_errors.append(f"finding[{idx}] incomplete response must fail closed to UNDETERMINED")
            _verify_empty_undetermined_assessment(
                idx,
                assessment,
                require_v226_fields=(not is_historical_ver),
                expected_raw_model_status=None,
                item_errors=item_errors,
                context_label=str(completeness),
                sidecar_error=sidecar_error_text,
            )
            inc_msg = f"finding[{idx}] incomplete HTTP response ({completeness})"
            endpoint_reported_protocol_errors.append(inc_msg)
            strict_item_errors.append(inc_msg)
        elif completeness in ("no_body_received", "read_error_after_headers"):
            partial_or_error_count += 1
            if receipt_doc.get("complete") is not False or runtime.get("http_capture_complete") is not False:
                item_errors.append(f"finding[{idx}] no-body transport failure must have complete=False")
            if receipt_doc.get("response_json_parse_succeeded") is True:
                item_errors.append(f"finding[{idx}] no-body transport failure must not set response_json_parse_succeeded=True")
            if assessment.get("raw_response") is not None:
                item_errors.append(f"finding[{idx}] no-body transport failure must have raw_response=None")
            if runtime.get("response_json_sha256") is not None or receipt_doc.get("response_json_sha256") is not None:
                item_errors.append(f"finding[{idx}] no-body transport failure must not set response_json_sha256")
            if completeness == "no_body_received":
                if (
                    receipt_doc.get("http_response_received") is True
                    or runtime.get("http_response_received") is True
                    or receipt_doc.get("http_status") is not None
                    or runtime.get("http_status") is not None
                ):
                    item_errors.append(
                        f"finding[{idx}] completeness='no_body_received' must not record http_response_received=True or non-null http_status"
                    )
            if runtime.get("response_body_sha256") is not None or receipt_doc.get("response_body_sha256") is not None:
                item_errors.append(f"finding[{idx}] no-body transport failure must not set response_body_sha256")
            if os.path.lexists(resp_bin_path) or os.path.lexists(inc_bin_path):
                item_errors.append(f"finding[{idx}] no-body transport failure must not fabricate response binary files")
            if (
                runtime.get("answer_validated") is True
                or assessment.get("status") != "UNDETERMINED"
                or assessment.get("validated_status", assessment.get("status")) != "UNDETERMINED"
            ):
                item_errors.append(f"finding[{idx}] no-body transport failure must fail closed to UNDETERMINED")
            _verify_empty_undetermined_assessment(
                idx,
                assessment,
                require_v226_fields=(not is_historical_ver),
                expected_raw_model_status=None,
                item_errors=item_errors,
                context_label=str(completeness),
                sidecar_error=sidecar_error_text,
            )
            nb_msg = f"finding[{idx}] HTTP transport failed before complete body ({completeness})"
            endpoint_reported_protocol_errors.append(nb_msg)
            strict_item_errors.append(nb_msg)
        else:
            item_errors.append(f"finding[{idx}] unrecognized or missing receipt completeness: {completeness!r}")

        if is_mock:
            mock_err = f"finding[{idx}] ({rec_id}) is marked mock, not real live Qwen HTTP"
            if mock_err not in endpoint_reported_protocol_errors:
                endpoint_reported_protocol_errors.append(mock_err)
            if mock_err not in strict_item_errors:
                strict_item_errors.append(mock_err)

        finding_artifact_ok = len(item_errors) == 0
        artifact_errors.extend(item_errors)
        strict_item_errors.append(f"finding[{idx}] {_UNVERIFIED_LIVE_ORIGIN_REASON}")
        reported_item_errors = item_errors + (strict_item_errors if require_live_chat else [])
        if require_live_chat:
            strict_errors.extend(strict_item_errors)

        finding_checks.append({
            "finding_index": idx,
            "id": rec_id,
            "call_id": receipt_doc.get("call_id") if receipt_doc else None,
            "mode": "http_transport",
            "mock": is_mock,
            "artifact_integrity_ok": finding_artifact_ok,
            "endpoint_reported_protocol_ok": finding_endpoint_proto_ok,
            "live_provenance_ok": False,
            "http_status": receipt_doc.get("http_status") if receipt_doc else runtime.get("http_status"),
            "completeness": completeness,
            "request_byte_length": req_len_verified,
            "request_payload_sha256": req_sha_verified,
            "prompt_version": recorded_prompt_version,
            "prompt_contract": assessment.get("prompt_contract"),
            "prompt_sha256": actual_prompt_sha,
            "canonical_request_status": canonical_request_status,
            "serializer_fingerprint": serializer_fingerprint,
            "recorded_serializer_fingerprint": assessment.get("serializer_fingerprint"),
            "actual_template_fingerprint": actual_template_fp,
            "prompt_metadata_binding": prompt_metadata_binding,
            "layer1_verification": layer1_verification,
            "integration_gate_verification": integration_gate_verification,
            "post_gate_downgrade_verification": post_gate_downgrade_verification,
            "response_byte_length": resp_len_verified,
            "response_body_sha256": resp_sha_verified,
            "response_json_sha256": runtime.get("response_json_sha256"),
            "verified": len(reported_item_errors) == 0,
            "errors": reported_item_errors,
        })

    if io_dir_safe:
        for fname in io_regular_files:
            if fname not in expected_chat_files:
                artifact_errors.append(f"orphan file in llm_io not bound to any finding in assessments.jsonl: {fname}")

    # Level 3 run-level check: endpoint-reported non-mock /api/tags capture + bound ollama-tags-check.json
    # NOTE: Self-reported HTTP /api/tags evidence can be synthesized by a loopback fixture and NEVER proves live Ollama origin.
    tags_protocol_ok = False
    if len(rows) > 0 and (endpoint_reported_non_mock_complete_count == len(rows) or require_live_chat):
        tags_errs: list[str] = []
        matching_probes = [
            p
            for p in tags_probes
            if p.get("verified") is True
            and p.get("complete") is True
            and p.get("completeness") == "complete"
            and type(p.get("http_status")) is int
            and p.get("http_status") == 200
            and p.get("transport_entered") is True
            and p.get("runtime_origin") in (None, "unverified")
            and isinstance(p.get("models_listed"), list)
        ]
        if not matching_probes:
            tags_errs.append("live chat requires at least one verified non-mock HTTP 200 /api/tags capture in llm_io/_tags")
        tags_check_errs: list[str] = []
        tags_check_path = _safe_regular_child_file(
            abs_triage,
            resolved_triage,
            "ollama-tags-check.json",
            max_bytes=MAX_METADATA_JSON_BYTES,
            label="ollama-tags-check.json",
            errors=tags_check_errs,
        )
        if tags_check_path is None:
            tags_errs.append("live chat requires ollama-tags-check.json bound to verified /api/tags capture")
        else:
            try:
                ot_doc = strict_json(tags_check_path.read_text(encoding="utf-8"))
                if not isinstance(ot_doc, dict):
                    tags_errs.append("ollama-tags-check.json is not a JSON object")
                else:
                    hc = ot_doc.get("http_capture")
                    if ot_doc.get("reachable") is not True or ot_doc.get("model_found") is not True:
                        tags_errs.append("ollama-tags-check.json must record reachable=True and model_found=True")
                    if not isinstance(ot_doc.get("model_digest"), str) or not ot_doc["model_digest"].strip():
                        tags_errs.append("ollama-tags-check.json missing non-empty model_digest")
                    if not isinstance(hc, dict):
                        tags_errs.append("ollama-tags-check.json missing http_capture binding object")
                    else:
                        matched_probe = None
                        for p in matching_probes:
                            p_digests = p.get("model_digests") if isinstance(p.get("model_digests"), dict) else {}
                            req_mdl = ot_doc.get("requested_model")
                            if (
                                hc.get("receipt") == p.get("receipt")
                                and hc.get("response_body_sha256") == p.get("response_body_sha256")
                                and hc.get("response_body_bytes") == p.get("response_byte_length")
                                and type(hc.get("http_status")) is int
                                and hc.get("http_status") == 200
                                and hc.get("complete") is True
                                and ot_doc.get("endpoint") == p.get("endpoint")
                                and req_mdl in (p.get("models_listed") or [])
                                and p_digests.get(req_mdl) == ot_doc.get("model_digest")
                            ):
                                matched_probe = p
                                break
                        if matched_probe is None:
                            tags_errs.append("ollama-tags-check.json does not match any verified non-mock HTTP 200 /api/tags probe containing requested_model")
                        else:
                            for ep, mdl in sorted(endpoint_expected_pairs):
                                if ot_doc.get("endpoint") != ep or ot_doc.get("requested_model") != mdl or mdl not in (matched_probe.get("models_listed") or []):
                                    tags_errs.append(
                                        f"ollama-tags-check.json ({ot_doc.get('endpoint')!r}, {ot_doc.get('requested_model')!r}) "
                                        f"does not match chat finding ({ep!r}, {mdl!r})"
                                    )
            except (OSError, UnicodeError, ValueError, EvidenceError) as exc:
                tags_errs.append(f"unreadable ollama-tags-check.json: {exc}")
        if tags_errs:
            endpoint_reported_protocol_errors.extend(tags_errs)
            if require_live_chat:
                strict_errors.extend(tags_errs)
        else:
            tags_protocol_ok = True

    # Explicit caller minimum_findings applies in BOTH normal and strict modes.
    if minimum_findings > 0 and len(rows) < minimum_findings:
        min_err = f"capture requires at least {minimum_findings} finding(s), found {len(rows)}"
        artifact_errors.append(min_err)
        endpoint_reported_protocol_errors.append(min_err)

    # Level 4: Trusted live runtime origin ALWAYS fails closed in offline artifact verification.
    live_provenance_errors: list[str] = []
    if len(rows) > 0 or require_live_chat:
        live_provenance_errors.append(_UNVERIFIED_LIVE_ORIGIN_REASON)
    live_provenance_errors.extend(endpoint_reported_protocol_errors)

    if require_live_chat:
        if len(rows) < max(1, minimum_findings) and not (minimum_findings > 0 and len(rows) < minimum_findings):
            strict_errors.append(f"live chat requires at least {max(1, minimum_findings)} finding(s), found {len(rows)}")
        if endpoint_reported_non_mock_complete_count < max(1, minimum_findings, len(rows)):
            strict_errors.append(
                f"live chat requires {max(1, minimum_findings, len(rows))} non-mock complete HTTP 200 chat capture(s) "
                f"with complete endpoint-reported protocol metadata, found {endpoint_reported_non_mock_complete_count}"
            )
        strict_errors.append(_UNVERIFIED_LIVE_ORIGIN_REASON)

    errors = list(artifact_errors) + (list(strict_errors) if require_live_chat else [])
    artifact_integrity_ok = len(artifact_errors) == 0
    integrity_ok = len(errors) == 0
    if not integrity_ok:
        status = "FAILED"
    elif len(rows) == 0:
        status = "NO_FINDINGS"
    elif disabled_count == len(rows):
        status = "DISABLED"
    elif mock_method_count == len(rows):
        status = "MOCKED_REQUEST_METHOD"
    elif complete_chat_count == len(rows):
        status = "VERIFIED_COMPLETE"
    else:
        status = "VERIFIED_ERROR_OR_PARTIAL_CAPTURED"

    endpoint_reported_protocol_ok = bool(
        artifact_integrity_ok
        and len(rows) >= max(1, minimum_findings)
        and endpoint_reported_non_mock_complete_count == len(rows)
        and tags_protocol_ok
        and len(endpoint_reported_protocol_errors) == 0
    )

    if not artifact_integrity_ok:
        live_origin_trust_status = "FAILED_CAPTURE_INTEGRITY"
    elif len(rows) == 0:
        live_origin_trust_status = "NO_FINDINGS"
    elif disabled_count == len(rows):
        live_origin_trust_status = "DISABLED"
    elif mock_method_count == len(rows) or any(fc.get("mock") is True for fc in finding_checks):
        live_origin_trust_status = "MOCK_OR_NON_LIVE_DECLARED"
    elif not endpoint_reported_protocol_ok:
        live_origin_trust_status = "ENDPOINT_PROTOCOL_INCOMPLETE_UNVERIFIED"
    else:
        live_origin_trust_status = "UNVERIFIED_OFFLINE_NO_TRUSTED_EXTERNAL_PROVENANCE"

    # Offline verification NEVER grants live_chat_verified=True or live_origin_verified=True
    # from self-declared artifacts inside triage_dir.
    live_chat_ok = False

    return {
        "schema": "ntk-http-capture-verification-1",
        "capture_scope": "http_body_and_client_metadata_not_tcp_wire",
        "verification_scope": _VERIFICATION_SCOPE,
        "capture_status": status,
        "capture_integrity_ok": integrity_ok,
        "artifact_integrity_ok": artifact_integrity_ok,
        "endpoint_reported_protocol_ok": endpoint_reported_protocol_ok,
        "live_origin_verified": False,
        "live_chat_verified": live_chat_ok,
        "live_origin_trust_status": live_origin_trust_status,
        "independently_verified_model_runtime": False,
        "security_conclusion_verified": False,
        "endpoint_reported_protocol_errors": endpoint_reported_protocol_errors,
        "live_chat_provenance_errors": live_provenance_errors,
        "total_findings": len(rows),
        "complete_http_200_captures": complete_chat_count,
        "endpoint_reported_non_mock_complete_captures": endpoint_reported_non_mock_complete_count,
        "live_non_mock_complete_captures": 0,
        "partial_or_error_captures": partial_or_error_count,
        "tags_probes": tags_probes,
        "findings": finding_checks,
        "errors": errors,
    }


def _write_exclusive_atomic_bytes(parent_dir: Path, target: Path, payload: bytes) -> None:
    """Write `payload` to `target` atomically without overwriting existing files and without swallowing fsync errors.

    Fails closed without falling back to non-atomic direct `open('xb')` when the target filesystem does
    not support exclusive hard-link publication.
    """
    if os.path.lexists(target):
        if is_reparse_link(target):
            raise CaptureWriteError(f"refusing symlink/junction output target: {target}")
        try:
            st = os.lstat(target)
        except OSError as exc:
            raise CaptureWriteError(f"cannot inspect existing output target {target}: {exc}") from exc
        if not stat.S_ISREG(st.st_mode):
            raise CaptureWriteError(f"refusing non-regular output target: {target}")
        raise FileExistsError(f"refusing to overwrite existing verifier report: {target}")

    tmp_path = parent_dir / f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    created_tmp = False
    try:
        with tmp_path.open("xb") as handle:
            created_tmp = True
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(tmp_path, target)
            return
        except FileExistsError:
            raise FileExistsError(f"refusing to overwrite existing verifier report: {target}")
        except OSError as exc:
            unsupported_link_errnos = {
                e for e in (getattr(errno, "EXDEV", None), getattr(errno, "EOPNOTSUPP", None), getattr(errno, "ENOSYS", None))
                if e is not None
            }
            win_err = getattr(exc, "winerror", None)
            if exc.errno in unsupported_link_errnos or win_err in (1, 50):
                raise OSError(
                    exc.errno or getattr(errno, "EOPNOTSUPP", errno.EIO),
                    f"ATOMIC_PUBLISH_UNSUPPORTED: target filesystem does not support exclusive hard-link publication for {target}: {exc}",
                ) from exc
            raise
    finally:
        if created_tmp:
            try:
                tmp_path.unlink()
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify raw same-call HTTP request/response captures in a triage directory")
    parser.add_argument("run", type=Path, help="Path to <run>/triage directory")
    parser.add_argument(
        "--require-live-chat",
        action="store_true",
        help="Strict live-origin mode (fails closed in offline verification when trusted external runtime provenance is unavailable)",
    )
    parser.add_argument("--minimum-findings", type=int, default=0, help="Minimum expected finding count")
    parser.add_argument("--output", type=Path, default=None, help="Write JSON report to this path instead of <run>/http-capture-check.json")
    parser.add_argument("--no-write", action="store_true", help="Print JSON report to stdout only without writing any file")
    args = parser.parse_args(argv)
    if args.minimum_findings < 0:
        parser.error("--minimum-findings must be >= 0")

    result = verify_run_http_captures(
        args.run,
        require_live_chat=args.require_live_chat,
        minimum_findings=args.minimum_findings,
    )
    try:
        rendered = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        safe_err_doc = {
            "schema": "ntk-http-capture-verification-1",
            "verification_scope": _VERIFICATION_SCOPE,
            "capture_status": result.get("capture_status") if isinstance(result, dict) and isinstance(result.get("capture_status"), str) else "FAILED",
            "capture_integrity_ok": bool(result.get("capture_integrity_ok")) if isinstance(result, dict) and type(result.get("capture_integrity_ok")) is bool else False,
            "artifact_integrity_ok": bool(result.get("artifact_integrity_ok")) if isinstance(result, dict) and type(result.get("artifact_integrity_ok")) is bool else False,
            "endpoint_reported_protocol_ok": bool(result.get("endpoint_reported_protocol_ok")) if isinstance(result, dict) and type(result.get("endpoint_reported_protocol_ok")) is bool else False,
            "live_origin_verified": False,
            "live_chat_verified": False,
            "independently_verified_model_runtime": False,
            "security_conclusion_verified": False,
            "verification_executed": True,
            "report_write_ok": False,
            "report_write_status": "REPORT_SERIALIZATION_ERROR",
            "report_write_error": f"REPORT_SERIALIZATION_ERROR: {type(exc).__name__}: {exc}",
            "report_output_path": str(args.output) if args.output is not None else None,
            "cli_operation_ok": False,
        }
        print(json.dumps(safe_err_doc, indent=2, ensure_ascii=False, allow_nan=False))
        return 2

    target_written: Path | None = None
    if not args.no_write:
        target = args.output if args.output is not None else (Path(args.run) / "http-capture-check.json")
        write_status: str | None = None
        write_error: str | None = None
        try:
            if args.output is None:
                safe_parent_dir = verify_safe_directory_chain(Path(args.run), boundary_root=Path(args.run), create=False)
                target = safe_parent_dir / "http-capture-check.json"
            else:
                raw_out = _validate_lexical_dir_path(target, label="verifier --output")
                if not _is_strict_basename(raw_out.name):
                    raise CaptureWriteError(f"invalid verifier --output filename: {target}")
                safe_parent_dir = verify_safe_directory_chain(raw_out.parent, boundary_root=raw_out.parent, create=True)
                target = safe_parent_dir / raw_out.name
            _write_exclusive_atomic_bytes(safe_parent_dir, target, (rendered + "\n").encode("utf-8"))
            target_written = target
        except FileExistsError as exc:
            write_status = "REFUSED_EXISTING_OUTPUT"
            write_error = f"OUTPUT_WRITE_REFUSED_EXISTING_FILE: {exc}"
        except CaptureWriteError as exc:
            write_status = "REFUSED_UNSAFE_OUTPUT_TARGET"
            write_error = f"OUTPUT_WRITE_REFUSED_UNSAFE_TARGET: refusing unsafe verifier output target {target}: {exc}"
        except (OSError, RuntimeError) as exc:
            write_status = "OUTPUT_WRITE_IO_ERROR"
            write_error = f"OUTPUT_WRITE_IO_ERROR: unable to write verifier report to {target}: {exc}"
        if write_error is not None:
            # Preserve the actual artifact/protocol verification fields untouched;
            # report output write refusal/error separately without fabricating artifact_integrity_ok=False.
            cli_result = dict(result)
            cli_result["verification_executed"] = True
            cli_result["report_write_ok"] = False
            cli_result["report_write_status"] = write_status
            cli_result["report_write_error"] = write_error
            cli_result["report_output_path"] = str(target)
            cli_result["cli_operation_ok"] = False
            print(json.dumps(cli_result, indent=2, ensure_ascii=False, allow_nan=False))
            return 2

    exit_code = (0 if result["live_chat_verified"] else 2) if args.require_live_chat else (0 if result["capture_integrity_ok"] else 2)
    cli_result = dict(result)
    cli_result["verification_executed"] = True
    cli_result["report_write_ok"] = None if args.no_write else True
    cli_result["report_write_status"] = "SKIPPED_NO_WRITE" if args.no_write else "WRITTEN"
    cli_result["report_write_error"] = None
    cli_result["report_output_path"] = None if args.no_write else str(target_written)
    cli_result["cli_operation_ok"] = exit_code == 0
    print(json.dumps(cli_result, indent=2, ensure_ascii=False, allow_nan=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
