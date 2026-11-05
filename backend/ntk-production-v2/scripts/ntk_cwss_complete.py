"""Scenario-conditional completion; no new weights or calibrated priors.

Reference policies are NTK normative scenarios, not empirical deployment facts.
The old evidence/estimate engines and their historical replay remain unchanged.
"""
import copy
import os
import json
import hashlib
from pathlib import Path

import ntk_cwss_automatic as auto
import ntk_cwss_v101 as scoring

VERSION = 'NTK_CWSS_COMPLETE_V1'
MODE = 'CWSS_AUTO_COMPLETE'
PROFILE_VERSION = 'NTK_REFERENCE_CONTEXT_1'
SOURCE = 'NTK declared reference policy; docs/CWSS_COMPLETE_API.txt'
PROFILES = {
 'GENERAL_JAVA': {'name': 'General Java Application', 'codes': {},
    'reason': 'Neutral fallback: no deployment or business characteristics asserted; remaining metrics use MITRE D.'},
 'INTERNET_WEB': {'name': 'Internet-Facing Web Application',
    'codes': {'AV': 'I', 'RL': 'A', 'SC': 'A', 'BI': 'M'},
    'reason': 'Declared scenario: Internet-reachable application layer, broadly deployed weakness and moderate business impact; no assumed administrator privilege.'},
 'BUSINESS_CRITICAL_WEB': {'name': 'Business-Critical Web Application',
    'codes': {'AV': 'I', 'RL': 'A', 'SC': 'A', 'BI': 'C'},
    'reason': 'Declared scenario: Internet application affecting critical business assets. Privileges and external controls are not asserted.'},
 'RESTRICTED_INTERNAL': {'name': 'Restricted Internal Application',
    'codes': {'AV': 'R', 'RP': 'RU', 'RL': 'A', 'AS': 'S', 'SC': 'R', 'BI': 'M', 'EC': 'B'},
    'reason': 'Declared scenario: internal access, regular application account, strong authentication, rare deployment and best-available external controls. These are assumptions, not observed controls.'},
}


def selection():
    key = os.environ.get('NTK_CWSS_REFERENCE_PROFILE', 'GENERAL_JAVA')
    if key not in PROFILES:
        raise ValueError('Invalid NTK_CWSS_REFERENCE_PROFILE')
    return key


def collect_context(root):
    """Optional repository-authored scenario declaration, never trusted facts."""
    path = Path(root)/'ntk-cwss-reference-context.json'
    try:
        if not path.exists():
            return None
        if path.is_symlink() or path.stat().st_size > 32768:
            return {'error': 'REFERENCE_CONTEXT_REJECTED'}
        raw = path.read_bytes()
        if len(raw) > 32768:
            raise ValueError('Reference context too large')
        value = json.loads(raw)
        validate_context(value)
        return {'document': value, 'sha256': hashlib.sha256(raw).hexdigest(),
                'reference': 'repository:ntk-cwss-reference-context.json'}
    except (ValueError, OSError, TypeError, KeyError):
        return {'error': 'REFERENCE_CONTEXT_REJECTED'}


def validate_context(value):
    if not isinstance(value, dict) or set(value) != {'schema_version','profile','revision','reason','metric_assumptions'}:
        raise ValueError('Invalid declared reference context fields')
    if value['schema_version'] != PROFILE_VERSION or value['profile'] not in PROFILES:
        raise ValueError('Unsupported reference context version/profile')
    if not all(isinstance(value[k],str) and len(value[k].strip()) >= 8 for k in ('revision','reason')):
        raise ValueError('Reference context revision and rationale required')
    if not isinstance(value['metric_assumptions'],dict):
        raise ValueError('Invalid assumptions')
    for m,rec in value['metric_assumptions'].items():
        if m not in scoring.FACTOR_ORDER or m in ('FC','P') or not isinstance(rec,dict) or set(rec) != {'code','reason'}:
            raise ValueError('FC/P cannot be assumed by repository context')
        code = scoring._normalized_code(m,rec['code'])
        if code in ('U','UK','NA','D') or not isinstance(rec['reason'],str) or len(rec['reason'].strip()) < 24:
            raise ValueError('Explicit discrete value and detailed assumption rationale required')
    return value


def assess(finding, scan, snapshot, reference='GENERAL_JAVA', attestation=None):
    import ntk_cwss_workflow as w
    if reference not in PROFILES:
        raise ValueError('Unknown reference profile')
    declaration = snapshot.get('complete_reference_context')
    context_warning = None
    if declaration and 'document' in declaration:
        document = validate_context(declaration['document'])
        reference = document['profile']
    elif declaration:
        context_warning = 'Invalid repository reference context ignored; using declared server/default profile'
    spec = copy.deepcopy(PROFILES[reference])
    if declaration and 'document' in declaration:
        for m, rec in document['metric_assumptions'].items():
            spec['codes'][m] = scoring._normalized_code(m, rec['code'])
        spec['reason'] = document['reason']
        spec['declaration'] = declaration
    # Caller cannot inject metric facts. Revalidate any prior reviewed profile
    # through the original gates including independent FC verification.
    reviewed = None
    if attestation is not None:
        if attestation['profile'].get('mode') != 'ASSESSED':
            raise ValueError('Only existing assessed context can supply attestations')
        reviewed = w.evaluate(finding, scan, attestation['profile'], attestation['reviewer'])
    _, evidence = auto.assess(finding, scan, snapshot, auto.MODES[0])
    _, estimate = auto.assess(finding, scan, snapshot, auto.MODES[1])
    # Conditional impact-layer estimate from supported resolved sink capability;
    # never infer an administrator or acquired privilege level from execution.
    iris = finding.get('iris_evidence') or {}
    owner = (iris.get('target_callee_identity') or {}).get('package')
    layer = {'java.lang': 'S', 'java.nio.file': 'S', 'java.sql': 'A', 'java.io': 'A'}.get(owner)
    if layer and estimate['metric_assessments']['TI']['code'] == 'H':
        estimate['metric_assessments']['AL'] = {
            'metric': 'AL', 'code': layer, 'classification': 'MACHINE_SUGGESTED',
            'reason': 'Conditional compromise layer follows the resolved local sink capability. No privilege elevation, process identity or actual compromise is proven.',
            'source': VERSION, 'provenance': {'source_evidence_hash': w.evidence_hash(finding)},
            'evidence_sufficient': False, 'applied_to_score': True}
    records = {}
    for m in scoring.FACTOR_ORDER:
        proof = evidence['metric_assessments'][m]
        guess = estimate['metric_assessments'][m]
        human = reviewed['metric_assessments'][m] if reviewed else {}
        # Applied human context is independently validated, never machine promotion.
        if proof['classification'] in ('VERIFIED', 'NOT_APPLICABLE'):
            row = copy.deepcopy(proof)
        elif human.get('evidence_sufficient') and human.get('code') not in ('UK', 'U', 'D', 'NA'):
            row = copy.deepcopy(human)
        elif guess['code'] not in ('UK', 'U') and m != 'FC':
            row = copy.deepcopy(guess)
        else:
            code = spec['codes'].get(m, 'D')
            row = {'metric': m, 'code': code,
                'classification': 'REFERENCE_ASSUMED' if m in spec['codes'] else 'STANDARD_DEFAULT',
                'reason': (spec.get('declaration', {}).get('document', {}).get('metric_assumptions', {}).get(m, {}).get('reason', spec['reason'])) if m in spec['codes'] else 'MITRE official Default; no factor-specific evidence. D is not an attested value, including FC:D.',
                'source': SOURCE if m in spec['codes'] else scoring.STANDARD_URL,
                'reference': reference + '@' + PROFILE_VERSION if m in spec['codes'] else scoring.STANDARD_URL,
                'provenance': {'reference_profile': reference, 'version': PROFILE_VERSION, 'declaration': declaration},
                'evidence_sufficient': False, 'applied_to_score': True}
        row.update(weight=scoring.WEIGHTS[m][row['code']], metric=m,
                   inference_status=row['classification'])
        records[m] = row
    codes = {m:r['code'] for m,r in records.items()}
    result = scoring.score_codes(codes, fill_unknown=False)
    assert result['unknown_metric_count'] == 0
    profile = {'schema_version': VERSION, 'mode': MODE, 'reference_profile': reference,
               'reference_profile_version': PROFILE_VERSION, 'reference_policy': spec,
               'automatic_evidence': snapshot, 'attestation': copy.deepcopy(attestation)}
    counts = {
        'verified_metric_count': sum(r['classification']=='VERIFIED' for r in records.values()),
        'attested_metric_count': sum(r['classification']=='ANALYST_ATTESTED' for r in records.values()),
        'estimated_metric_count': sum(r['classification'] in ('MACHINE_SUGGESTED','SCENARIO_ASSUMED') for r in records.values()),
        'reference_metric_count': sum(r['classification']=='REFERENCE_ASSUMED' for r in records.values()),
        'default_metric_count': sum(r['classification']=='STANDARD_DEFAULT' for r in records.values()),
        'policy_na_count': 1}
    result.update(mode=MODE, score_mode=MODE, inference_version=VERSION,
        engine_version=w.ENGINE, engine_hash=w.ENGINE_HASH,
        scan_id=scan, finding_id=finding['finding_id'], finding_anchor=w.context.finding_anchor(finding),
        source_evidence_hash=w.evidence_hash(finding), profile_hash=w.digest(profile),
        reference_profile=reference, reference_profile_version=PROFILE_VERSION,
        reference_profile_name=spec['name'], reference_selection='REPOSITORY_DECLARED_SCENARIO' if declaration and 'document' in declaration else ('SERVER_DECLARED' if reference!='GENERAL_JAVA' else 'DEFAULT_REFERENCE_ASSUMPTION'),
        reference_context_warning=context_warning,
        assessment_status='SCENARIO-CONDITIONAL', fully_verified=False,
        metric_vector=result['vector'], metric_assessments=records, metric_provenance=records,
        three_subscores=result['subscores_exact'], **counts,
        assessment_completeness={**counts, 'unknown_count': 0, 'metric_count':16,
            'unverified_metric_count': sum(not r.get('evidence_sufficient',False) for r in records.values())},
        explanation='Complete numeric vector under declared assumptions; not verified deployment risk. '+spec['reason'],
        collection_limitations=snapshot['limitations'], triage_decision=finding.get('decision','REVIEW'),
        heuristic_evidence_score=finding.get('final_heuristic_score'))
    result['calculation_hash'] = w.digest({'version': VERSION,'profile':profile,'codes':codes,
        'finding_hash':w.evidence_hash(finding),'engine_hash':w.ENGINE_HASH,'exact':result['cwss_score_exact']})
    return profile, result
