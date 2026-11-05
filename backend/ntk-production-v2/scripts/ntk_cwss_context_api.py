"""Read-only CWSS API page for already-persisted NTK scan findings.

Nothing is written to backend scan history; context is read from private local
files published explicitly via the Stage 9 CLI. Errors fail closed.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
import ntk_cwss_workflow as workflow

from ntk_cwss_context import read_published_profile, evaluate_with_context


def cwss_findings_page(state: Any, scan_id: str, page: Any = 1, page_size: Any = 50) -> Tuple[int, Dict[str, Any]]:
    try:
        status, original = state.result_index.query_findings_page(
            scan_id=scan_id,
            page=page,
            page_size=page_size,
            include_evidence=True,
            include_partitioned_arrays=False,
        )
        if status != 200:
            return status, original
        profile = read_published_profile(scan_id)
        assessments = []
        has_published = False
        for f in original.get("findings", []):
            if not isinstance(f, dict):
                raise ValueError("Finding row not a dictionary")
            assessed = evaluate_with_context(f, scan_id, profile)
            if profile is None:
                assessed.update(workflow.evaluate(f, scan_id))
            if getattr(state, "storage_dir", None) is not None:
                store_dir = workflow.directory(state)
                if (store_dir / "cwss-assessments.sqlite3").is_file():
                    revisions = workflow.AssessmentStore(store_dir).history(scan_id, f["finding_id"])
                    published = [r for r in revisions if r["profile"]["mode"] == "ASSESSED"]
                    if published:
                        has_published = True
                        last = published[-1]
                        if (last["assessment"]["finding_anchor"] != workflow.context.finding_anchor(f)
                                or last["assessment"]["source_evidence_hash"] != workflow.evidence_hash(f)):
                            raise ValueError("Published CWSS finding anchor mismatch")
                        assessed = dict(last["assessment"], revision=last["revision"], revision_hash=last["revision_hash"])
            assessments.append({
                "finding_id": assessed["finding_id"],
                "cwe": assessed["cwe"],
                "cwss": assessed,
            })
        return 200, {
            "status": "OK",
            "scan_id": scan_id,
            "cwss_policy": "CWSS_1_0_1_EVIDENCE_CONTEXT_V1",
            "cwss_score_kind": "WEAKNESS_PRIORITY_NOT_TRUE_POSITIVE_PROBABILITY",
            "read_only": True,
            "profile_available": bool(profile) or has_published,
            "total_matching": original.get("total_matching", len(assessments)),
            "page": original.get("page", 1),
            "page_size": original.get("page_size", 50),
            "assessments": assessments,
        }
    except ValueError as exc:
        return 422, {"status": "ERROR", "error_code": "CWSS_CONTEXT_VALIDATION_ERROR", "error_message": str(exc)}
    except Exception:
        return 500, {"status": "ERROR", "error_code": "CWSS_CONTEXT_INTERNAL_ERROR",
                     "error_message": "Could not calculate CWSS profile; inspect local server logs"}
