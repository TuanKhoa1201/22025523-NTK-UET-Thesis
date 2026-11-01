"""Read-only, explicitly hypothetical CWSS V2 scenario scoring for archived scans.

Does not mutate persisted CWSS revisions, scan records, evidence, or triage.
Only the bundled and attributed synthetic-business-critical fixture is supported.
"""
from __future__ import annotations

import copy
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import quote

import ntk_cwss_auto_v2 as v2
import ntk_cwss_workflow as workflow
import ntk_cwss_complete as complete

ROUTE = re.compile(r"^/api/scans/(SCAN-[A-Za-z0-9_-]{1,96})/cwss/v2/scenario$")
FINDING_ID = re.compile(r"^FINDING-[A-Za-z0-9_-]{1,180}$")
PROFILE = "BUSINESS_CRITICAL_INTERNET_FACING"
CONTEXT_FILE = (Path(__file__).resolve().parent.parent /
                'tests/fixtures/cwss_v2/high-risk-context.json')


def _read_declared_context():
    # Bundled source-controlled fixture, not a client-supplied metric vector.
    context = v2.validate_context(json.loads(CONTEXT_FILE.read_text(encoding='utf-8')))
    if context['profile_id'] != PROFILE or context['reference'] != 'fixture:declared-domain-scenario-not-runtime-proof':
        raise ValueError('Unsupported or unattributed reference context')
    return context


def _read_complete_revision(db, scan, fid):
    cursor = db.execute(
        'SELECT envelope,checksum FROM revisions WHERE scan=? AND finding=? ORDER BY revision DESC',
        (scan, fid))
    for envelope_text, checksum in cursor:
        record = json.loads(envelope_text)
        if workflow.digest(record) != checksum:
            raise ValueError('Immutable CWSS revision checksum mismatch')
        profile = record.get('profile') or {}
        assessment = record.get('assessment') or {}
        if (profile.get('mode') == complete.MODE and
                profile.get('inference_version') == v2.VERSION and
                assessment.get('inference_version') == v2.VERSION):
            return record
    raise LookupError('No published CWSS Inference V2 complete snapshot for this finding')


def _scenario_assessment(db, scan_id, finding, context):
    fid = finding['finding_id']
    revision = _read_complete_revision(db, scan_id, fid)
    if not v2.matches(finding, revision):
        raise ValueError('Finding evidence differs from archived immutable CWSS revision')
    stored_profile = revision['profile']
    snapshot = copy.deepcopy(stored_profile['automatic_evidence'])
    original_hash = snapshot.get('finding_evidence_hashes', {}).get(fid)
    current_hash = workflow.evidence_hash(finding)
    archived_hash = workflow.evidence_hash(revision['finding_snapshot'])
    if original_hash not in (current_hash, archived_hash):
        raise ValueError('Archived evidence binding mismatch')
    snapshot['finding_evidence_hashes'][fid] = current_hash
    snapshot['declared_context_v2'] = copy.deepcopy(context)

    _, result = v2.assess(finding, scan_id, snapshot, complete.MODE)
    if (result['inference_version'] != v2.VERSION or
            result['reference_profile'] != PROFILE or
            len(result['metric_assessments']) != 16 or
            result['reference_context_hash'] is None or
            result['triage_decision'] != finding.get('decision', 'REVIEW')):
        raise ValueError('Scenario assessment invariant failed')
    return result


def handle(state, path, query):
    """Return (HTTP code, JSON) for the scenario route, or None otherwise."""
    match = ROUTE.fullmatch(path)
    if match is None:
        return None
    scan_id = match.group(1)
    requested_profile = query.get('profile', [PROFILE])[0]
    if requested_profile != PROFILE:
        return 422, {'status': 'ERROR', 'error_code': 'UNSUPPORTED_REFERENCE_SCENARIO'}
    try:
        context = _read_declared_context()
        fid = query.get('finding_id', [''])[0]
        if fid:
            if FINDING_ID.fullmatch(fid) is None:
                raise ValueError('Invalid finding ID')
            summary = state.result_index.get_scan_summary(scan_id)
            if summary is None:
                return 404, {'status': 'ERROR', 'error_code': 'SCAN_NOT_FOUND'}
            findings = [f for f in state.result_index.get_all_finding_details(scan_id)
                        if f.get('finding_id') == fid]
            if not findings:
                return 404, {'status': 'ERROR', 'error_code': 'FINDING_NOT_FOUND'}
            page, page_size = 1, 1
            total_count = 1
        else:
            page = int(query.get('page', ['1'])[0])
            page_size = int(query.get('page_size', ['50'])[0])
            if page < 1 or not 1 <= page_size <= 100:
                raise ValueError('Invalid page/page_size')
            status, payload = state.result_index.query_findings_page(
                scan_id=scan_id, page=page, page_size=page_size,
                include_evidence=True, include_partitioned_arrays=False)
            if status != 200:
                return status, payload
            findings = payload.get('findings') or []
            total_count = payload.get('total_matching', len(findings))
        db_file = workflow.directory(state) / 'complete' / 'cwss-assessments.sqlite3'
        if not db_file.is_file():
            return 404, {'status': 'ERROR', 'error_code': 'CWSS_V2_SNAPSHOT_NOT_FOUND'}
        sqlite_url = 'file:' + quote(str(db_file), safe='/') + '?mode=ro'
        with closing(sqlite3.connect(sqlite_url, uri=True, timeout=15)) as db:
            results = [{'finding_id': f['finding_id'],
                        'cwss': _scenario_assessment(db, scan_id, f, context)}
                       for f in findings]
        return 200, {
            'status': 'OK', 'scan_id': scan_id, 'page': page, 'page_size': page_size,
            'total_matching': total_count, 'scenario_id': PROFILE,
            'inference_version': v2.VERSION,
            'reference_source': context['reference'],
            'reference_profile_version': context['profile_version'],
            'reference_rationale': context['rationale'],
            'reference_context_hash': workflow.digest(context),
            'hypothetical': True, 'verified_deployment': False,
            'ground_truth_calibration': False, 'read_only': True,
            'metric_assumption_semantics': 'REFERENCE_ASSUMPTION, not VERIFIED',
            'scoring_standard': 'MITRE CWSS 1.0.1',
            'standard_url': 'https://cwe.mitre.org/cwss/cwss_v1.0.1.html',
            'assessments': results,
        }
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return 422, {'status': 'ERROR', 'error_code': 'CWSS_SCENARIO_VALIDATION_ERROR',
                     'error_message': str(exc)}
    except LookupError as exc:
        return 404, {'status': 'ERROR', 'error_code': 'CWSS_V2_SNAPSHOT_NOT_FOUND',
                     'error_message': str(exc)}
    except (OSError, sqlite3.Error, json.JSONDecodeError) as exc:
        return 500, {'status': 'ERROR', 'error_code': 'CWSS_SCENARIO_STORAGE_ERROR',
                     'error_message': type(exc).__name__}
