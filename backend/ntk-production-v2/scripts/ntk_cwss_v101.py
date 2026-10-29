"""CWSS 1.0.1 scorer and conservative adapter for NTK findings.

Source: https://cwe.mitre.org/cwss/cwss_v1.0.1.html

CWSS measures weakness prioritization, NOT probability of true-positive findings.
Missing metrics use CWSS Unknown (0.5), except individual-finding
Prevalence=P:NA,1.0. CWE number alone never determines impact or attack reachability.
Pure Python 3.9+, no network or external dependencies.
"""
from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, Mapping, Optional

CWSS_VERSION = "1.0.1"
STANDARD_URL = "https://cwe.mitre.org/cwss/cwss_v1.0.1.html"
SUPPORTED_CWES = frozenset((22, 78, 79, 89))
GROUPS = {
    "base": ("TI", "AP", "AL", "IC", "FC"),
    "attack_surface": ("RP", "RL", "AV", "AS", "IN", "SC"),
    "environment": ("BI", "DI", "EX", "EC", "P"),
}
FACTOR_ORDER = GROUPS["base"] + GROUPS["attack_surface"] + GROUPS["environment"]
# Exact discrete metric weight lookup from MITRE CWSS 1.0.1 sections 2.3-2.5.
WEIGHTS: Dict[str, Dict[str, float]] = {
    "TI": {"C": 1, "H": .9, "M": .6, "L": .3, "N": 0, "D": .6, "UK": .5, "NA": 1},
    "AP": {"A": 1, "P": .9, "RU": .7, "L": .6, "N": .1, "D": .7, "UK": .5, "NA": 1},
    "AL": {"A": 1, "S": .9, "N": .7, "E": 1, "D": .9, "UK": .5, "NA": 1},
    "IC": {"N": 1, "L": .9, "M": .7, "I": .5, "B": .3, "C": 0, "D": .6, "UK": .5, "NA": 1},
    "FC": {"T": 1, "LT": .8, "F": 0, "D": .8, "UK": .5, "NA": 1},
    "RP": {"N": 1, "L": .9, "RU": .7, "P": .6, "A": .1, "D": .7, "UK": .5, "NA": 1},
    "RL": {"A": 1, "S": .9, "N": .7, "E": 1, "D": .9, "UK": .5, "NA": 1},
    "AV": {"I": 1, "R": .8, "V": .8, "A": .7, "L": .5, "P": .2, "D": .75, "U": .5, "NA": 1},
    "AS": {"S": .7, "M": .8, "W": .9, "N": 1, "D": .85, "UK": .5, "NA": 1},
    "IN": {"A": 1, "T": .9, "M": .8, "O": .3, "H": .1, "NI": 0, "D": .55, "UK": .5, "NA": 1},
    "SC": {"A": 1, "M": .9, "R": .5, "P": .1, "D": .7, "UK": .5, "NA": 1},
    "BI": {"C": 1, "H": .9, "M": .6, "L": .3, "N": 0, "D": .6, "UK": .5, "NA": 1},
    "DI": {"H": 1, "M": .6, "L": .2, "D": .6, "UK": .5, "NA": 1},
    "EX": {"H": 1, "M": .6, "L": .2, "N": 0, "D": .6, "UK": .5, "NA": 1},
    "EC": {"N": 1, "L": .9, "M": .7, "I": .5, "B": .3, "C": .1, "D": .6, "UK": .5, "NA": 1},
    "P": {"W": 1, "H": .9, "C": .8, "L": .7, "D": .85, "UK": .5, "NA": 1},
}
CWE_HINTS: Dict[int, Dict[str, str]] = {
    22: {
        "name": "Path Traversal",
        "dataflow": "Untrusted path or filename -> filesystem sink; validate path normalization AND containment guard.",
        "cwss_context": "File sensitivity, process filesystem privileges, attacker access, OS/path semantics.",
    },
    78: {
        "name": "OS Command Injection",
        "dataflow": "Untrusted command data -> process execution sink; inspect escaping/allowlists and argument formation.",
        "cwss_context": "OS identity of execution process, runtime sandbox, attacker reachability, possible command scope.",
    },
    79: {
        "name": "Cross-Site Scripting",
        "dataflow": "Untrusted content -> HTML/DOM sink; inspect output context and contextual encoding.",
        "cwss_context": "Victim interactions, session privileges, browser context, security headers and deployment.",
    },
    89: {
        "name": "SQL Injection",
        "dataflow": "Untrusted values -> SQL construction/execution; inspect parameter binding and query generation.",
        "cwss_context": "Database account permissions, data sensitivity, attacker reachability, DB controls.",
    },
}


def _cwss_decimal_score(value: float) -> float:
    return float(Decimal(str(value)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def _parse_cwe(value: Any) -> int:
    import re
    matched = re.search(r"\d+", str(value))
    if not matched:
        raise ValueError("Finding must have CWE-022/078/079/089")
    cwe = int(matched.group())
    if cwe not in SUPPORTED_CWES:
        raise ValueError("Unsupported CWE: %r" % cwe)
    return cwe


def default_metric_codes() -> Dict[str, str]:
    """No invented operational values; P:NA for an individual finding per MITRE."""
    values = {metric: ("U" if metric == "AV" else "UK") for metric in FACTOR_ORDER}
    values["P"] = "NA"
    return values


def _normalized_code(factor: str, code: str) -> str:
    code = str(code).strip().upper()
    if factor == "AV" and code == "UK":
        code = "U"  # CWSS AV uses U rather than UK in the MITRE table.
    if factor != "AV" and code == "U":
        code = "UK"
    if code not in WEIGHTS[factor]:
        raise ValueError("Invalid CWSS 1.0.1 value for %s: %s" % (factor, code))
    return code


def score_codes(codes: Mapping[str, str], *, fill_unknown: bool = True) -> Dict[str, Any]:
    """Compute CWSS 1.0.1 exactly from factor value codes.

    The official tables are the sole source of numeric metric weights.
    Q (quantified) is deliberately excluded from this strict discrete profile;
    it requires a separately documented organization-specific scheme.
    """
    if not isinstance(codes, Mapping):
        raise TypeError("codes must be a mapping")
    extras = set(codes) - set(FACTOR_ORDER)
    if extras:
        raise ValueError("Unknown CWSS metric(s): " + ", ".join(sorted(extras)))
    if not fill_unknown and set(codes) != set(FACTOR_ORDER):
        raise ValueError("All sixteen CWSS metrics required")
    mapped = default_metric_codes() if fill_unknown else {}
    for factor, value in codes.items():
        mapped[factor] = _normalized_code(factor, value)
    weights = {factor: float(WEIGHTS[factor][mapped[factor]]) for factor in FACTOR_ORDER}
    w = weights
    f_ti = 0.0 if w["TI"] == 0 else 1.0
    f_bi = 0.0 if w["BI"] == 0 else 1.0
    base = (10*w["TI"] + 5*(w["AP"] + w["AL"]) + 5*w["FC"]) * f_ti * w["IC"] * 4.0
    attack = (20*(w["RP"] + w["RL"] + w["AV"]) + 20*w["SC"] + 15*w["IN"] + 5*w["AS"]) / 100.0
    environment = ((10*w["BI"] + 3*w["DI"] + 4*w["EX"] + 3*w["P"]) * f_bi * w["EC"]) / 20.0
    unrounded = base * attack * environment
    if not (0 <= base <= 100 and 0 <= attack <= 1 and 0 <= environment <= 1 and 0 <= unrounded <= 100):
        raise AssertionError("CWSS metric score outside expected range")
    vector = "/".join(f"{factor}:{mapped[factor]},{weights[factor]:.4g}" for factor in FACTOR_ORDER)
    unknown = [key for key in FACTOR_ORDER if mapped[key] in ("UK", "U")]
    return {
        "cwss_version": CWSS_VERSION,
        "specification_url": STANDARD_URL,
        "cwss_score": _cwss_decimal_score(unrounded),
        "cwss_score_unrounded": round(unrounded, 8),
        "base_finding_subscore": round(base, 8),
        "attack_surface_subscore": round(attack, 8),
        "environment_subscore": round(environment, 8),
        "vector": vector,
        "factor_codes": mapped,
        "factor_weights": weights,
        "unknown_metrics": unknown,
        "unknown_metric_count": len(unknown),
        "assessment_status": "PROVISIONAL_MISSING_CONTEXT" if unknown else "FULL_METRIC_ASSIGNMENT",
        "score_kind": "CWSS_1_0_1_WEAKNESS_PRIORITIZATION_NOT_TP_PROBABILITY",
        "not_a_tp_probability": True,
        "not_a_cvss_score": True,
    }


def recommend_finding_confidence(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Propose an FC category; it is NOT automatically assigned as proven evidence.

    Automatic source-to-sink evidence can suggest locally true but cannot
    establish attacker reachability or a human-confirmed true positive.
    """
    review = str(finding.get("review_status", "NOT_REVIEWED")).upper()
    if review == "CONFIRMED_FALSE_POSITIVE":
        return {"suggested_code": "F", "reason": "Human review confirmed a false-positive finding"}
    if review == "CONFIRMED_TRUE_POSITIVE":
        return {"suggested_code": "LT", "reason": "Human review confirms local weakness; external reachability not established"}
    iris = finding.get("iris_evidence") or {}
    llm = finding.get("llm_api_role") or finding.get("llm_prediction") or {}
    if not isinstance(iris, Mapping):
        iris = {}
    if not isinstance(llm, Mapping):
        llm = {}
    role = str(llm.get("predicted_role") or finding.get("predicted_api_role") or "").lower()
    trace = iris.get("taint_trace_steps") or []
    strong_local = (
        iris.get("ast_parser_engine") == "OPENJDK17_JAVAC_TASK_AST"
        and iris.get("source_sink_trace_status") == "VERIFIED_TAINT_FLOW"
        and iris.get("taint_reaches_sink") is True
        and isinstance(trace, list) and len(trace) >= 2
        and role == "sink"
        and llm.get("strict_json_valid") is True
    )
    if strong_local:
        return {"suggested_code": "LT", "reason": "Machine AST/local taint + strict sink role; must validate source semantics before treating as proven"}
    if iris.get("explicit_ast_release_verified") is True:
        return {"suggested_code": "F", "reason": "Automatic AST safety release; verify all required sink args and guard semantics before claiming Proven False"}
    return {"suggested_code": "UK", "reason": "Insufficient proof of local weakness or attacker reachability"}


def score_finding(
    finding: Mapping[str, Any],
    *,
    metric_overrides: Optional[Mapping[str, Mapping[str, str]]] = None,
) -> Dict[str, Any]:
    """Generate a cautious CWSS profile for normalized SAST finding input.

    Non-Unknown metric assignments are explicit/manual and require evidence.
    This conservatism is intentional: LLM API-role predictions are not TP labels.
    """
    if not isinstance(finding, Mapping):
        raise TypeError("finding must be a mapping")
    cwe = _parse_cwe(finding.get("cwe", finding.get("cwe_id", "")))
    codes = default_metric_codes()
    sources = {factor: "UNASSESSED" for factor in FACTOR_ORDER}
    sources["P"] = "MITRE_INDIVIDUAL_FINDING_PREVALENCE_NA"
    reasons = {factor: "No verified factor-specific evidence" for factor in FACTOR_ORDER}
    reasons["P"] = "Prevalence is typically not applicable to an individual finding (CWSS 1.0.1 section 2.5.5)"
    if metric_overrides:
        extras = set(metric_overrides) - set(FACTOR_ORDER)
        if extras:
            raise ValueError("Unknown override factor(s): " + ", ".join(sorted(extras)))
        for factor, item in metric_overrides.items():
            if not isinstance(item, Mapping):
                raise TypeError("Metric override must be {code,evidence,source}")
            code = _normalized_code(factor, item.get("code", ""))
            evidence = str(item.get("evidence", "")).strip()
            source = str(item.get("source", "")).strip()
            if code not in ("UK", "U", "NA") and (len(evidence) < 12 or not source):
                raise ValueError("Non-Unknown metric %s needs evidence and source provenance" % factor)
            if code == "NA" and not evidence:
                raise ValueError("NA metric %s needs explicit scope rationale" % factor)
            codes[factor] = code
            sources[factor] = source or "MANUAL_UNSPECIFIED"
            reasons[factor] = evidence or "Unknown / pending assessment"
    scored = score_codes(codes, fill_unknown=False)
    scored["finding_id"] = str(finding.get("finding_id", ""))
    scored["cwe"] = f"CWE-{cwe:03d}"
    scored["cwe_name"] = CWE_HINTS[cwe]["name"]
    scored["source_evidence_guidance"] = CWE_HINTS[cwe]
    scored["metric_sources"] = sources
    scored["metric_evidence"] = reasons
    scored["fc_recommendation_not_proof"] = recommend_finding_confidence(finding)
    scored["existing_ntk_triage_decision_unchanged"] = finding.get("decision", "REVIEW")
    scored["existing_ntk_heuristic_for_comparison_only"] = finding.get("final_heuristic_score")
    scored["policy_note"] = (
        "This is a genuine CWSS 1.0.1 formula with versioned MITRE discrete weights. "
        "Unassessed environment metrics remain Unknown, so score is provisional and "
        "cannot establish True Positive/False Positive or severity by itself."
    )
    return scored


def unwrap_finding(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Accept either a normalized scanner finding or NTK finding detail envelope."""
    if isinstance(payload.get("finding"), Mapping):
        return dict(payload["finding"])
    return dict(payload)
