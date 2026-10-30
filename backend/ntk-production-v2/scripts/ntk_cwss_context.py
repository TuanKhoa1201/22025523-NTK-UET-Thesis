"""Evidence-anchored CWSS 1.0.1 context profiles for NTK.

Does not infer deployment, business impact, attacker privileges or reachability
from CWE IDs, Qwen roles, Spring annotations, Dockerfile text, or a scanner label.
Machine findings generate review leads only. Metric codes are promoted to
scoring only after explicit reviewer attestation and source reference.

Python stdlib only. No network, model inference or subprocesses.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ntk_cwss_v101 import FACTOR_ORDER, WEIGHTS, _normalized_code, default_metric_codes, score_finding

PROFILE_VERSION = "NTK_CWSS_CONTEXT_PROFILE_V1"
SCAN_PATTERN = re.compile(r"^SCAN-[A-Za-z0-9_-]{1,96}$")
FINDING_PATTERN = re.compile(r"^FINDING-[A-Za-z0-9_-]{1,180}$")
MAX_PROFILE_BYTES = 2 * 1024 * 1024

METRIC_GUIDANCE = {
    "TI": "Technical impact after successful exploitation: data confidentiality/integrity, remote command scope, service interruption. Verify what asset can actually be affected.",
    "AP": "Attacker's privilege AFTER exploitation (e.g. process UID / database grants), not current user or authentication required.",
    "AL": "Privilege layer reached AFTER exploit: application, host system, network, or enterprise infrastructure.",
    "IC": "Effective controls INSIDE the application. Check sanitizer, source-sink coverage, all viable call paths; a mere function name is insufficient.",
    "FC": "Is the weakness present locally and can attacker reach it? LT needs independently reviewed local evidence; T additionally needs verified attacker reachability.",
    "RP": "Privileges attacker must hold BEFORE reaching vulnerable functionality; verify route authorization and inherited security configuration.",
    "RL": "Layer where required attacker's privilege exists (application vs system vs network vs infrastructure).",
    "AV": "Attack channel in ACTUAL deployment: public Internet / intranet / private / local / physical, not merely @GetMapping.",
    "AS": "Authentication strength of the ACTUAL access path: none/password/MFA; account for alternate routes.",
    "IN": "Human victim interaction required for attack (click/link/preview vs none). Confirm flow for CWE-079.",
    "SC": "Which deployments/configurations/platforms contain vulnerable code, from versioned deployment inventory.",
    "BI": "Business or mission impact; data classification, asset criticality, business owner sign-off, not inferred from CWE.",
    "DI": "Attacker's likelihood of discovering weakness without privileged source code, not whether OpenGrep found it.",
    "EX": "Successful exploit likelihood under verified environment/access assumptions; distinguish plausibility from tested exploit.",
    "EC": "External controls: WAF, firewall, runtime sandbox, IAM, network policy; verify live enforcement and alternate paths.",
    "P": "CWSS Prevalence is generally Not Applicable (NA) for individual code findings; relevant for generalized weaknesses.",
}


def finding_anchor(finding: Mapping[str, Any]) -> str:
    """Identity fingerprint, intentionally avoiding raw code in the profile."""
    identity = {
        "id": str(finding.get("finding_id", "")),
        "cwe": str(finding.get("cwe", "")),
        "file": str(finding.get("file_path", "")),
        "line": str(finding.get("line_number", "")),
        "rule": str(finding.get("scanner_rule_id", "")),
        "code_sha256": hashlib.sha256(str(finding.get("matched_code", "")).encode("utf-8")).hexdigest(),
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def evidence_leads(finding: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Machine evidence to investigate; NEVER automatically becomes a verified CWSS metric."""
    leads: List[Dict[str, Any]] = []
    iris = finding.get("iris_evidence") or {}
    if isinstance(iris, Mapping):
        flow = iris.get("source_sink_trace_status")
        trace = iris.get("taint_trace_steps") or []
        if flow:
            leads.append({"factor_hints": ["FC", "IC", "TI"], "source": "NTK_IRIS_AST",
                          "evidence": "AST status=" + str(flow),
                          "trace_step_count": len(trace) if isinstance(trace, list) else 0,
                          "verified_factor": False})
        if iris.get("explicit_ast_release_verified"):
            leads.append({"factor_hints": ["IC", "FC"], "source": "NTK_AST_RELEASE",
                          "evidence": "Analyzer reports AST safety release; independent verification required",
                          "verified_factor": False})
    llm = finding.get("llm_api_role") or finding.get("llm_prediction") or {}
    if isinstance(llm, Mapping) and llm.get("predicted_role"):
        leads.append({"factor_hints": ["FC"], "source": "LOCAL_QWEN_LORA",
                      "evidence": "API role=" + str(llm.get("predicted_role")) + "; role is NOT a TP label",
                      "verified_factor": False})
    leads.append({"factor_hints": ["TI", "AP", "AL", "RP", "RL", "AV", "AS", "IN", "SC", "BI", "DI", "EX", "EC"],
                  "source": "DEPLOYMENT_AND_BUSINESS_EVIDENCE_REQUIRED",
                  "evidence": "Obtain verified application/host/database access and business context; no auto assignment",
                  "verified_factor": False})
    return leads


def template_for_scan(scan_id: str, findings: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    if not SCAN_PATTERN.fullmatch(scan_id):
        raise ValueError("Invalid scan ID")
    profile: Dict[str, Any] = {
        "schema_version": PROFILE_VERSION,
        "scan_id": scan_id,
        "deployment_name": "",
        "deployment_version_or_commit": "",
        "assessment_scope": "Target application and deployment actually evaluated (fill this)",
        "reviewer_guidance": "Only set code != UK/U with verified evidence, source reference, reviewer ID, review date, and verified=true. Never copy suggestions into codes without confirmation.",
        "findings": {},
    }
    for f in findings:
        fid = str(f.get("finding_id", ""))
        if not FINDING_PATTERN.fullmatch(fid):
            raise ValueError("Invalid finding ID in scan: " + fid[:50])
        if fid in profile["findings"]:
            raise ValueError("Duplicate finding ID")
        codes = default_metric_codes()
        profile["findings"][fid] = {
            "cwe": str(f.get("cwe", "")),
            "anchor_sha256": finding_anchor(f),
            "review_notes": "",
            "finding_verification": {
                "verdict": "UNREVIEWED",
                "attacker_reachability_verified": False,
                "evidence": "",
                "reference": "",
                "reviewer": "",
                "reviewed_at_utc": ""
            },
            "metric_assessments": {
                metric: {"code": codes[metric], "verified": False, "source": "", "reference": "", "evidence": "", "reviewer": "", "reviewed_at_utc": ""}
                for metric in FACTOR_ORDER if metric != "P"
            },
            "context_questions": {
                "attacker_reachability": "Evidence of authenticated/unauthenticated route and conditions?",
                "runtime_privileges": "Service identity, DB user role, container effective security context?",
                "technical_and_business_impact": "Which assets can be read, modified or disrupted; owner-confirmed impact?",
                "deployed_controls": "Which internal and external mitigations are enforced on every attack path?",
            },
        }
    return profile


def load_profile(path: Path) -> Dict[str, Any]:
    path = Path(path)
    if path.stat().st_size > MAX_PROFILE_BYTES:
        raise ValueError("CWSS profile too large")
    content = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(content, dict) or content.get("schema_version") != PROFILE_VERSION:
        raise ValueError("Unexpected CWSS context profile schema")
    if not SCAN_PATTERN.fullmatch(str(content.get("scan_id", ""))):
        raise ValueError("Invalid profile scan ID")
    if not isinstance(content.get("findings"), dict):
        raise ValueError("Missing profile findings object")
    return content


def _validate_review_date(value: str) -> None:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise ValueError("Invalid reviewed_at_utc ISO 8601 date") from exc
    if result.tzinfo is None:
        raise ValueError("Review date must include timezone")


def reviewed_metric_overrides(
    profile: Optional[Mapping[str, Any]], finding: Mapping[str, Any], scan_id: str,
) -> Tuple[Dict[str, Dict[str, str]], Dict[str, Any]]:
    """Promotes ONLY explicitly attested, evidence-anchored factor decisions.

    Rejects context for another scan/finding or version. A reviewed code cannot
    be silently inherited from other findings or from a deployment name.
    """
    accepted: Dict[str, Dict[str, str]] = {}
    meta: Dict[str, Any] = {"applied_metrics": [], "pending_metrics": [], "reviewed_metrics_count": 0}
    if profile is None:
        return accepted, meta
    if str(profile.get("schema_version", "")) != PROFILE_VERSION or profile.get("scan_id") != scan_id:
        raise ValueError("CWSS profile scan ID/schema mismatch")
    fid = str(finding.get("finding_id", ""))
    entry = (profile.get("findings") or {}).get(fid)
    if entry is None:
        return accepted, meta
    if not isinstance(entry, Mapping) or entry.get("anchor_sha256") != finding_anchor(finding) or str(entry.get("cwe")) != str(finding.get("cwe")):
        raise ValueError("CWSS profile finding identity/anchor mismatch for " + fid)
    metrics = entry.get("metric_assessments") or {}
    if not isinstance(metrics, Mapping):
        raise ValueError("metric_assessments must be object")
    for factor, rec in metrics.items():
        if factor == "P":
            raise ValueError("P automatically defaults NA for individual findings; do not override via context profile")
        if factor not in FACTOR_ORDER or not isinstance(rec, Mapping):
            raise ValueError("Invalid CWSS metric assessment: " + str(factor))
        code = _normalized_code(factor, rec.get("code", ""))
        if code in ("UK", "U"):
            continue
        if rec.get("verified") is not True:
            meta["pending_metrics"].append(factor)
            continue
        evidence = str(rec.get("evidence", "")).strip()
        source = str(rec.get("source", "")).strip()
        ref = str(rec.get("reference", "")).strip()
        reviewer = str(rec.get("reviewer", "")).strip()
        reviewed_at = str(rec.get("reviewed_at_utc", "")).strip()
        if len(evidence) < 24 or not source or len(ref) < 6 or not reviewer or not reviewed_at:
            raise ValueError("Verified CWSS %s requires detailed evidence, source, reference, reviewer, and timestamp" % factor)
        _validate_review_date(reviewed_at)
        # Stronger semantic controls for the most consequential factor claims.
        if factor == "FC" and code in ("T", "LT", "F"):
            rstatus = str(finding.get("review_status", "NOT_REVIEWED"))
            verified = entry.get("finding_verification") or {}
            if not isinstance(verified, Mapping):
                raise ValueError("finding_verification must be an object")
            expected = "CONFIRMED_FALSE_POSITIVE" if code == "F" else "CONFIRMED_TRUE_POSITIVE"
            direct_ok = rstatus == expected
            profile_ok = str(verified.get("verdict", "")) == expected
            if profile_ok:
                ver_evidence = str(verified.get("evidence", "")).strip()
                ver_ref = str(verified.get("reference", "")).strip()
                ver_reviewer = str(verified.get("reviewer", "")).strip()
                ver_time = str(verified.get("reviewed_at_utc", "")).strip()
                if len(ver_evidence) < 24 or len(ver_ref) < 6 or not ver_reviewer or not ver_time:
                    raise ValueError("FC verification requires independent finding review record with source")
                _validate_review_date(ver_time)
            if not (direct_ok or profile_ok):
                raise ValueError("FC:T/LT/F requires independently reviewed finding verdict")
            if code == "T" and not (verified.get("attacker_reachability_verified") is True and profile_ok):
                raise ValueError("FC:T additionally requires separately verified attacker reachability in profile")
        accepted[factor] = {"code": code, "source": source + ":" + ref,
                            "evidence": evidence + " [reviewer=" + reviewer + "; reviewed=" + reviewed_at + "]"}
        meta["applied_metrics"].append({"metric": factor, "code": code, "reference": ref, "source": source, "reviewer": reviewer})
    meta["reviewed_metrics_count"] = len(meta["applied_metrics"])
    return accepted, meta


def evaluate_with_context(finding: Mapping[str, Any], scan_id: str, profile: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    overrides, audit = reviewed_metric_overrides(profile, finding, scan_id)
    scored = score_finding(finding, metric_overrides=overrides)
    scored["assessment_mode"] = "CWSS_101_FACTORS_EVIDENCE_REVIEWED"
    scored["assessment_completeness"] = {
        "metrics_total": 16,
        "metrics_unknown": scored["unknown_metric_count"],
        "metrics_non_unknown": 16-scored["unknown_metric_count"],
        "reviewed_metrics": audit["reviewed_metrics_count"],
        "provisional": scored["unknown_metric_count"] > 0,
    }
    scored["profile_applied"] = bool(profile and profile.get("findings", {}).get(finding.get("finding_id")))
    scored["review_audit"] = audit
    scored["machine_evidence_leads_not_proof"] = evidence_leads(finding)
    scored["source_finding_anchor_sha256"] = finding_anchor(finding)
    return scored


def context_directory() -> Path:
    return Path(os.environ.get("NTK_CWSS_CONTEXT_DIR", str(Path.home()/"ntk-production-runtime-20261028"/"cwss-contexts"))).expanduser()


def profile_path_for_scan(scan_id: str, directory: Optional[Path] = None) -> Path:
    if not SCAN_PATTERN.fullmatch(scan_id):
        raise ValueError("Invalid scan ID")
    return (directory or context_directory()) / (scan_id + ".json")


def read_published_profile(scan_id: str, directory: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    target = profile_path_for_scan(scan_id, directory)
    if not target.is_file():
        return None
    if target.is_symlink():
        raise ValueError("Symlink CWSS context profile forbidden")
    return load_profile(target)


def publish_profile_checked(source: Path, directory: Optional[Path] = None,
                            findings: Optional[Sequence[Mapping[str, Any]]] = None) -> Path:
    """Only explicit CLI operation; atomic replace with backup, no API write endpoint."""
    profile = load_profile(Path(source))
    # Legacy operator publication uses the same attestation gate as reads.
    # Never replace a valid profile with unchecked metric records.
    originals = {str(f.get("finding_id")): f for f in (findings or [])}
    for fid, entry in profile["findings"].items():
        if not FINDING_PATTERN.fullmatch(str(fid)) or not isinstance(entry, Mapping):
            raise ValueError("Invalid profile finding")
        metrics = entry.get("metric_assessments") or {}
        if not isinstance(metrics, Mapping):
            raise ValueError("Invalid metric_assessments")
        for factor, rec in metrics.items():
            if factor not in FACTOR_ORDER or factor == "P" or not isinstance(rec, Mapping):
                raise ValueError("Invalid context metric")
            code = _normalized_code(factor, rec.get("code", ""))
            if code not in ("UK", "U") and rec.get("verified") is True and fid not in originals:
                raise ValueError("Verified legacy publication requires original finding evidence")
        if fid in originals:
            reviewed_metric_overrides(profile, originals[fid], profile["scan_id"])
    target = profile_path_for_scan(profile["scan_id"], directory)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.is_symlink():
        raise ValueError("Refusing to overwrite symlink profile")
    if target.exists():
        old = target.read_bytes()
        backup = target.with_name(target.name + ".backup-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"))
        with open(backup, "xb") as outf:
            outf.write(old)
        os.chmod(backup, 0o600)
    payload = json.dumps(profile, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    if len(payload) > MAX_PROFILE_BYTES:
        raise ValueError("Profile too large")
    fd, temporary = tempfile.mkstemp(dir=str(target.parent), prefix=".cwss-context-")
    try:
        with os.fdopen(fd, "wb") as outf:
            outf.write(payload)
            outf.flush()
            os.fsync(outf.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target
