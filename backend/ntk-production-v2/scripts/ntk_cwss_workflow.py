"""CWSS discrete targeted assessments. Sidecar revisions never mutate scan/triage.

Trust boundary: suggestions are not attestations. Only authenticated reviewers
may submit attestations; scenario assumptions are always labelled separately.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import ntk_cwss_v101 as scoring
import ntk_cwss_context as context
import ntk_cwss_automatic as automatic
import ntk_cwss_complete as complete
import ntk_cwss_auto_v2 as automatic_v2

VERSION = 'NTK_CWSS_ASSESSMENT_V2'
ENGINE = 'NTK_CWSS_DECIMAL_V1'
MODES = {'PRELIMINARY', 'SCENARIO', 'ASSESSED'}
CLASSES = {'VERIFIED', 'MACHINE_SUGGESTED', 'SCENARIO_ASSUMED', 'ANALYST_ATTESTED', 'UNKNOWN', 'NOT_APPLICABLE'}
ENGINE_HASH = hashlib.sha256(json.dumps(scoring.WEIGHTS, sort_keys=True).encode()).hexdigest()
ROUTE = re.compile(r'^/api/scans/(SCAN-[A-Za-z0-9_-]{1,96})/cwss/v1/(catalog|ranking|report|findings/(FINDING-[A-Za-z0-9_-]{1,180})/(template|preview|draft|publish|history|replay|automatic))$')

METRIC_NAMES = dict(zip(scoring.FACTOR_ORDER, (
    'Technical Impact', 'Acquired Privilege', 'Acquired Privilege Layer', 'Internal Control Effectiveness',
    'Finding Confidence', 'Required Privilege', 'Required Privilege Layer', 'Access Vector',
    'Authentication Strength', 'Level of Interaction', 'Deployment Scope', 'Business Impact',
    'Likelihood of Discovery', 'Likelihood of Exploit', 'External Control Effectiveness', 'Prevalence')))
_LABEL_ROWS = {
    'TI': 'C:Critical H:High M:Medium L:Low N:None',
    'AP': 'A:Administrator P:Partially-Privileged_User RU:Regular_User L:Limited/Guest N:None',
    'AL': 'A:Application S:System N:Network E:Enterprise_Infrastructure',
    'IC': 'N:None L:Limited M:Moderate I:Indirect B:Best-Available C:Complete',
    'FC': 'T:Proven_True LT:Proven_Locally_True F:Proven_False',
    'RP': 'N:None L:Limited/Guest RU:Regular_User P:Partially-Privileged_User A:Administrator',
    'RL': 'A:Application S:System N:Network E:Enterprise_Infrastructure',
    'AV': 'I:Internet R:Intranet V:Private_Network A:Adjacent_Network L:Local P:Physical',
    'AS': 'S:Strong M:Moderate W:Weak N:None',
    'IN': 'A:Automated T:Typical/Limited M:Moderate O:Opportunistic H:High NI:No_interaction',
    'SC': 'A:All M:Moderate R:Rare P:Potentially_Reachable',
    'BI': 'C:Critical H:High M:Medium L:Low N:None',
    'DI': 'H:High M:Medium L:Low', 'EX': 'H:High M:Medium L:Low N:None',
    'EC': 'N:None L:Limited M:Moderate I:Indirect B:Best-Available C:Complete',
    'P': 'W:Widespread H:High C:Common L:Limited'}
VALUE_LABELS = {m: {**{k: v.replace('_', ' ') for k, v in (item.split(':') for item in row.split())},
                    'D': 'Default', 'U' if m == 'AV' else 'UK': 'Unknown', 'NA': 'Not Applicable'}
                for m, row in _LABEL_ROWS.items()}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


class AuthorizationError(PermissionError):
    pass


def authorize(header):
    """Private server config: reviewer -> strong bearer token. No default token."""
    try:
        configured = json.loads(os.environ.get('NTK_CWSS_REVIEWER_TOKENS', '{}'))
    except ValueError:
        raise AuthorizationError('CWSS write authorization is not configured') from None
    if not isinstance(configured, dict):
        raise AuthorizationError('CWSS write authorization is not configured')
    candidate = header[7:] if header.startswith('Bearer ') else ''
    for reviewer, token in configured.items():
        if isinstance(token, str) and len(token) >= 32 and isinstance(reviewer, str) and reviewer.strip():
            if hmac.compare_digest(candidate.encode(), token.encode()):
                return reviewer
    raise AuthorizationError('Valid CWSS reviewer authorization required')


def catalog():
    return {'schema_version': VERSION, 'engine_version': ENGINE, 'engine_hash': ENGINE_HASH,
            'standard_url': scoring.STANDARD_URL, 'profile': 'DISCRETE_TARGETED', 'quantified_supported': False,
            'metrics': [{'metric': m, 'name': METRIC_NAMES[m], 'values': scoring.WEIGHTS[m],
                         'value_labels': VALUE_LABELS[m], 'meaning': context.METRIC_GUIDANCE[m]}
                        for m in scoring.FACTOR_ORDER], 'classifications': sorted(CLASSES),
            'priority_policy': 'CWSS_0_100_WITH_ASSESSMENT_STATE', 'mitre_severity_thresholds': None, 'automatic_modes': [*automatic.MODES, complete.MODE], 'reference_profiles': complete.PROFILES, 'reference_profile_version': complete.PROFILE_VERSION,
            'inference_version': automatic.VERSION, 'v2_inference_version': automatic_v2.VERSION,
            'v2_policy_hash': automatic_v2.policy_hash(), 'v2_metric_policy': automatic_v2.POLICY, 'automatic_scope': 'LOCAL_STATIC_SOURCE_ONLY'}


def suggestions(finding):
    """Bounded review leads, never deployment facts or automatically scored values."""
    fc = scoring.recommend_finding_confidence(finding)
    cwe = scoring._parse_cwe(finding.get('cwe', ''))
    iris = finding.get('iris_evidence') or {}
    source_ref = 'finding:' + str(finding.get('finding_id', ''))
    leads = []
    for metric in scoring.FACTOR_ORDER:
        code = 'U' if metric == 'AV' else 'UK'
        reason = context.METRIC_GUIDANCE[metric]
        evidence = []
        if metric == 'FC':
            code, reason = fc['suggested_code'], fc['reason']
            evidence = [source_ref + '#iris_evidence', source_ref + '#llm_api_role']
        elif metric == 'TI' and (iris.get('source_sink_trace_status') == 'VERIFIED_TAINT_FLOW'
                                and iris.get('taint_reaches_sink') is True):
            identity = iris.get('target_callee_identity') or finding.get('target_callee_identity') or {}
            sink = (identity.get('class'), identity.get('method'))
            roles = finding.get('llm_api_role') or {}
            supported = {22: {('Files', 'readAllBytes'), ('Files', 'readString')},
                         78: {('Runtime', 'exec'), ('ProcessBuilder', 'start')},
                         79: {('PrintWriter', 'println'), ('PrintWriter', 'write')},
                         89: {('Statement', 'executeQuery'), ('PreparedStatement', 'executeQuery')}}
            if (sink in supported.get(cwe, set()) and roles.get('strict_json_valid') is True
                    and roles.get('predicted_role') == 'sink' and finding.get('matched_code')):
                code = 'H'
                reason = 'Review potential significant technical impact of the observed %s.%s sink and local flow. Asset scope and privileges are not established.' % sink
            evidence = [source_ref + '#iris_evidence', source_ref + '#matched_code']
        elif metric == 'IC' and iris.get('explicit_ast_release_verified') is True:
            code = 'C'
            reason = 'Analyzer reports a safety release; review full sink coverage and all relevant call paths before attesting complete internal control.'
            evidence = [source_ref + '#iris_evidence']
        elif metric in ('TI', 'IC') and iris:
            reason += ' Inspect CWE-%03d and actual sink/control evidence; no impact/control value is verified.' % cwe
            evidence = [source_ref + '#iris_evidence']
        elif metric in ('DI', 'EX'):
            reason += ' Static detection is not evidence of attacker discovery or exploit reliability.'
        leads.append({'metric': metric, 'code': code, 'classification': 'MACHINE_SUGGESTED',
                      'reason': reason, 'references': evidence, 'source': 'NTK_STATIC_REVIEW_LEAD',
                      'suggested_weight': scoring.WEIGHTS[metric][code],
                      'verified': False, 'applied_to_score': False})
    return leads


def evidence_hash(finding):
    return digest({key: finding.get(key) for key in (
        'finding_id', 'cwe', 'file_path', 'line_number', 'scanner_rule_id', 'matched_code',
        'iris_evidence', 'llm_api_role', 'source_provenance_record', 'review_status')})


def template(finding, scan_id):
    return {'schema_version': VERSION, 'mode': 'ASSESSED', 'scan_id': scan_id,
            'finding_id': finding['finding_id'], 'finding_anchor': context.finding_anchor(finding),
            'source_evidence_hash': evidence_hash(finding),
            'context': {'deployment_name': '', 'deployment_version_or_commit': '', 'assessment_scope': ''},
            'scenario_name': '', 'finding_verification': {}, 'metrics': {}}


def evaluate(finding, scan_id, profile=None, actor=None):
    """Single validation/preview/publication/replay path, shared across all modes."""
    p = copy.deepcopy(profile) if profile is not None else template(finding, scan_id)
    if profile is None:
        p['mode'] = 'PRELIMINARY'
    if not isinstance(p, dict) or set(p) - set(template(finding, scan_id)):
        raise ValueError('Invalid assessment profile fields')
    if (p.get('schema_version') != VERSION or p.get('scan_id') != scan_id
            or p.get('finding_id') != finding['finding_id'] or p.get('finding_anchor') != context.finding_anchor(finding)
            or p.get('source_evidence_hash') != evidence_hash(finding)):
        raise ValueError('Profile schema/scan/finding/anchor mismatch')
    mode = p.get('mode')
    if mode not in MODES:
        raise ValueError('Invalid assessment mode')
    ctx = p.get('context')
    if not isinstance(ctx, dict) or set(ctx) != {'deployment_name', 'deployment_version_or_commit', 'assessment_scope'}:
        raise ValueError('Versioned deployment context required')
    if mode != 'PRELIMINARY' and not all(isinstance(v, str) and v.strip() for v in ctx.values()):
        raise ValueError('Deployment name, revision and assessment scope required')
    if not isinstance(p.get('scenario_name', ''), str) or len(p.get('scenario_name', '')) > 256:
        raise ValueError('Invalid scenario name')
    if not isinstance(p.get('finding_verification'), dict):
        raise ValueError('finding_verification must be an object')
    if mode == 'SCENARIO' and not p.get('scenario_name', '').strip():
        raise ValueError('Named scenario required')
    if mode != 'SCENARIO' and p.get('scenario_name'):
        raise ValueError('Scenario name only valid in SCENARIO mode')
    metrics = p.get('metrics')
    if not isinstance(metrics, dict) or set(metrics) - set(scoring.FACTOR_ORDER):
        raise ValueError('Unknown metric or invalid metrics object')
    codes = scoring.default_metric_codes()
    records = {}
    old_profile = context.template_for_scan(scan_id, [finding])
    entry = old_profile['findings'][finding['finding_id']]
    entry['finding_verification'] = p.get('finding_verification') or {}
    for metric in scoring.FACTOR_ORDER:
        rec = metrics.get(metric)
        row = {'metric': metric, 'code': codes[metric], 'classification': 'UNKNOWN',
               'meaning': context.METRIC_GUIDANCE[metric], 'reason': 'Factor-specific evidence missing',
               'source': 'UNASSESSED', 'reference': '', 'reviewer': '', 'reviewed_at_utc': '',
               'evidence_sufficient': False, 'applied_to_score': False}
        if metric == 'P':
            if rec is not None:
                raise ValueError('P:NA is fixed by targeted scoring policy')
            row.update(classification='NOT_APPLICABLE', reason='Targeted individual finding: prevalence intentionally excluded',
                       source='MITRE_2_5_5_TARGETED_POLICY', reference=scoring.STANDARD_URL + '#prevalence',
                       evidence_sufficient=True, applied_to_score=True)
        elif rec is not None:
            if not isinstance(rec, dict) or set(rec) - {'code', 'classification', 'reason', 'source', 'reference', 'reviewer', 'reviewed_at_utc', 'verified'}:
                raise ValueError('Invalid metric record')
            code = scoring._normalized_code(metric, rec.get('code', ''))
            cls = rec.get('classification')
            if cls not in CLASSES or cls == 'VERIFIED':
                raise ValueError('VERIFIED is reserved for registered server evidence producers; none configured')
            row.update({k: rec[k] for k in rec if k not in ('code', 'verified')})
            row['proposed_code'] = code
            if code in ('UK', 'U') and cls != 'MACHINE_SUGGESTED':
                row['classification'] = 'UNKNOWN'
            if cls == 'UNKNOWN' and code not in ('UK', 'U'):
                raise ValueError('UNKNOWN must use official Unknown code')
            apply = code not in ('UK', 'U') and cls != 'MACHINE_SUGGESTED'
            if apply:
                if mode == 'PRELIMINARY':
                    raise ValueError('Preliminary mode cannot apply user assumptions/attestations')
                for key in ('reason', 'source', 'reference'):
                    if not isinstance(rec.get(key), str) or len(rec[key].strip()) < (24 if key == 'reason' else 6):
                        raise ValueError('Applied metric requires detailed reason/source/reference')
                if mode == 'SCENARIO':
                    if cls != 'SCENARIO_ASSUMED' or rec.get('verified') is True:
                        raise ValueError('Scenario must use explicit unverified assumptions')
                else:
                    if cls not in ('ANALYST_ATTESTED', 'NOT_APPLICABLE') or rec.get('verified') is not True:
                        raise ValueError('Assessed metric requires explicit analyst attestation')
                    if not actor or rec.get('reviewer') != actor:
                        raise ValueError('Reviewer must match authenticated principal')
                    context._validate_review_date(str(rec.get('reviewed_at_utc', '')))
                    if (cls == 'NOT_APPLICABLE') != (code == 'NA'):
                        raise ValueError('NA requires NOT_APPLICABLE classification')
                    entry['metric_assessments'][metric] = {
                        'code': code, 'verified': True, 'evidence': rec['reason'], 'source': rec['source'],
                        'reference': rec['reference'], 'reviewer': actor, 'reviewed_at_utc': rec['reviewed_at_utc']}
                codes[metric] = code
                row.update(code=code, evidence_sufficient=mode == 'ASSESSED', applied_to_score=True)
        row['name'] = METRIC_NAMES[metric]
        row['value_meaning'] = VALUE_LABELS[metric][row['code']]
        row['weight'] = scoring.WEIGHTS[metric][row['code']]
        row['missing_evidence_reason'] = '' if row['evidence_sufficient'] else row['reason']
        records[metric] = row
    if mode == 'ASSESSED':
        verification = entry['finding_verification']
        if verification and verification.get('reviewer') != actor:
            raise ValueError('Finding verification reviewer must match authenticated principal')
        # Reuse proven-local/proven-true/reachability and evidence/date gates.
        context.reviewed_metric_overrides(old_profile, finding, scan_id)
    scored = scoring.score_codes(codes, fill_unknown=False)
    complete = scored['unknown_metric_count'] == 0
    limited = [m for m in scoring.FACTOR_ORDER if m != 'P' and codes[m] in ('D', 'NA')]
    scored.update(cwe="CWE-%03d" % scoring._parse_cwe(finding.get("cwe", "")),
                  schema_version=VERSION, engine_version=ENGINE, engine_hash=ENGINE_HASH,
                  mode=mode, assessment_status='COMPLETE' if complete else 'INCOMPLETE',
                  fully_verified=mode == 'ASSESSED' and complete and not limited,
                  verification_scope_limited_metrics=limited,
                  assessment_completeness={'unknown_ratio': scored['unknown_metric_count']/16, 'metric_count': 16,
                      'unknown_count': scored['unknown_metric_count'], 'policy_na_count': 1},
                  risk_interpretation='SCENARIO_ONLY' if mode == 'SCENARIO' else ('ASSESSED_CONTEXT' if complete and mode == 'ASSESSED' else 'INSUFFICIENT_CONTEXT_NOT_VERIFIED_LOW_RISK'),
                  scan_id=scan_id, finding_id=finding['finding_id'], scenario_name=p.get('scenario_name', ''),
                  finding_anchor=p['finding_anchor'], source_evidence_hash=p['source_evidence_hash'], context=ctx, profile_hash=digest(p),
                  metric_assessments=records, machine_suggestions=suggestions(finding),
                  triage_decision=finding.get('decision', 'REVIEW'),
                  heuristic_evidence_score=finding.get('final_heuristic_score'),
                  priority_policy='CWSS_0_100_WITH_ASSESSMENT_STATE')
    # One-at-a-time sensitivity, not hypothetical attestation or new weights.
    scored['metric_sensitivity_not_proof'] = {
        m: {code: scoring.score_codes({**codes, m: code}, fill_unknown=False)['cwss_score']
            for code in scoring.WEIGHTS[m]} for m in scoring.FACTOR_ORDER if m != 'P'}
    return scored


class Conflict(ValueError):
    pass


class AssessmentStore:
    """SQLite transaction gives atomic immutable revisions and optimistic locking."""
    def __init__(self, directory):
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path, 0o700)
        self.path = path / 'cwss-assessments.sqlite3'
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS revisions (scan TEXT, finding TEXT, revision INTEGER, envelope TEXT NOT NULL, checksum TEXT NOT NULL, PRIMARY KEY(scan,finding,revision))')
            db.execute('CREATE TABLE IF NOT EXISTS drafts (scan TEXT, finding TEXT, actor TEXT, profile TEXT NOT NULL, PRIMARY KEY(scan,finding,actor))')
        os.chmod(self.path, 0o600)

    def connect(self):
        return sqlite3.connect(str(self.path), timeout=20)

    def save_draft(self, finding, scan, profile, actor):
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError('Authenticated reviewer required')
        profile = copy.deepcopy(profile)
        preview = evaluate(finding, scan, profile, actor)
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO drafts VALUES (?,?,?,?)', (scan, finding['finding_id'], actor, canonical(profile)))
        return preview

    def draft(self, scan, fid, actor):
        with self.connect() as db:
            row = db.execute('SELECT profile FROM drafts WHERE scan=? AND finding=? AND actor=?', (scan, fid, actor)).fetchone()
        return json.loads(row[0]) if row else None

    def publish(self, finding, scan, profile, actor, expected_revision):
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError('expected_revision must be a nonnegative integer')
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError('Authenticated reviewer required')
        profile, finding = copy.deepcopy(profile), copy.deepcopy(finding)
        result = evaluate(finding, scan, profile, actor)
        if profile['mode'] == 'PRELIMINARY':
            raise ValueError('Publish a scenario or assessed profile; preliminary is reproducible from scan evidence')
        envelope = {'scan_id': scan, 'finding_id': finding['finding_id'], 'revision': expected_revision + 1,
                    'reviewer': actor, 'published_at_utc': now(), 'profile': copy.deepcopy(profile),
                    'finding_snapshot': copy.deepcopy(finding), 'assessment': result}
        checksum = digest(envelope)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            latest = db.execute('SELECT COALESCE(MAX(revision),0) FROM revisions WHERE scan=? AND finding=?', (scan, finding['finding_id'])).fetchone()[0]
            if latest != expected_revision:
                raise Conflict('Assessment revision changed; reload history')
            db.execute('INSERT INTO revisions VALUES (?,?,?,?,?)', (scan, finding['finding_id'], latest+1, canonical(envelope), checksum))
        return {**envelope, 'revision_hash': checksum}

    def publish_automatic(self, finding, scan, snapshot):
        """Server-only, idempotent atomic pair. No client metric/profile promotion."""
        if snapshot.get('inference_version') == automatic_v2.graph.VERSION:
            pairs = [automatic_v2.assess(finding, scan, snapshot, mode) for mode in automatic.MODES]
            return self._publish_generated(copy.deepcopy(finding), scan, pairs)
        finding, snapshot = copy.deepcopy(finding), copy.deepcopy(snapshot)
        pairs = [automatic.assess(finding, scan, snapshot, mode) for mode in automatic.MODES]
        return self._publish_generated(finding, scan, pairs)

    def publish_complete(self, finding, scan, snapshot, reference='GENERAL_JAVA', attestation=None):
        if snapshot.get('inference_version') == automatic_v2.graph.VERSION:
            pair = automatic_v2.assess(finding, scan, snapshot, complete.MODE, reference, attestation)
            return self._publish_generated(copy.deepcopy(finding), scan, [pair])[0]
        finding, snapshot, attestation = copy.deepcopy((finding, snapshot, attestation))
        pairs = [complete.assess(finding, scan, snapshot, reference, attestation)]
        return self._publish_generated(copy.deepcopy(finding), scan, pairs)[0]

    def _publish_generated(self, finding, scan, pairs):
        modes = [profile['mode'] for profile, _ in pairs]
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            raw = db.execute('SELECT envelope,checksum FROM revisions WHERE scan=? AND finding=? ORDER BY revision',
                             (scan, finding['finding_id'])).fetchall()
            previous = []
            for encoded, checksum in raw:
                rec = json.loads(encoded)
                if digest(rec) != checksum:
                    raise ValueError('Assessment storage checksum mismatch')
                previous.append(rec)
            latest = {r['profile']['mode']: r for r in previous}
            if all(mode in latest and latest[mode]['assessment'] == result
                   for mode, (_, result) in zip(modes, pairs)):
                return [{**latest[mode], 'revision_hash': digest(latest[mode])} for mode in modes]
            revision = max((r['revision'] for r in previous), default=0)
            saved = []
            for profile, result in pairs:
                revision += 1
                envelope = {'scan_id': scan, 'finding_id': finding['finding_id'], 'revision': revision,
                            'reviewer': 'NTK_AUTOMATIC_EVIDENCE_COLLECTOR', 'published_at_utc': now(),
                            'profile': profile, 'finding_snapshot': finding, 'assessment': result}
                checksum = digest(envelope)
                db.execute('INSERT INTO revisions VALUES (?,?,?,?,?)',
                           (scan, finding['finding_id'], revision, canonical(envelope), checksum))
                saved.append({**envelope, 'revision_hash': checksum})
        return saved

    def history(self, scan, fid):
        with self.connect() as db:
            rows = db.execute('SELECT envelope,checksum FROM revisions WHERE scan=? AND finding=? ORDER BY revision', (scan, fid)).fetchall()
        result = []
        for raw, checksum in rows:
            envelope = json.loads(raw)
            if digest(envelope) != checksum:
                raise ValueError('Assessment storage checksum mismatch')
            result.append({**envelope, 'revision_hash': checksum})
        return result

    def replay(self, scan, fid, revision):
        selected = next((r for r in self.history(scan, fid) if r['revision'] == revision), None)
        if selected is None:
            raise LookupError('Assessment revision not found')
        if (selected['assessment']['engine_version'] != ENGINE or selected['assessment']['engine_hash'] != ENGINE_HASH):
            raise Conflict('Replay requires the recorded scoring engine/weights')
        if selected['profile'].get('inference_version') == automatic_v2.VERSION:
            p = selected['profile']
            regenerated, result = automatic_v2.assess(selected['finding_snapshot'], scan,
                p['automatic_evidence'], p['mode'], p.get('reference_profile', 'GENERAL_JAVA'), p.get('attestation'))
            if canonical(regenerated) != canonical(p):
                raise Conflict('Replay requires recorded V2 policy')
        elif selected['profile']['mode'] == complete.MODE:
            profile = selected['profile']
            if selected['assessment'].get('inference_version') != complete.VERSION:
                raise Conflict('Replay requires recorded completion engine')
            regenerated, result = complete.assess(selected['finding_snapshot'], scan,
                profile['automatic_evidence'], profile['reference_profile'], profile['attestation'])
            if canonical(regenerated) != canonical(profile):
                raise Conflict('Replay requires recorded reference policy')
        elif selected['profile']['mode'] in automatic.MODES:
            if selected['assessment'].get('inference_version') != automatic.VERSION:
                raise Conflict('Replay requires the recorded inference engine')
            _, result = automatic.assess(selected['finding_snapshot'], scan,
                selected['profile']['automatic_evidence'], selected['profile']['mode'])
        else:
            result = evaluate(selected['finding_snapshot'], scan, selected['profile'], selected['reviewer'])
        if canonical(result) != canonical(selected['assessment']):
            raise Conflict('Assessment replay differs from recorded result')
        return {**selected, 'replay_verified': True}


def directory(state):
    return Path(os.environ.get('NTK_CWSS_ASSESSMENT_DIR', str(Path(state.storage_dir) / 'cwss-assessments')))


def ranking(findings, scan, store, mode='ASSESSED', scenario_name='', decision=''):
    if mode in automatic_v2.MODES:
        return automatic_v2.ranking(findings, scan, store, mode, decision)
    if mode not in MODES | set(automatic.MODES) | {complete.MODE} or (mode == 'SCENARIO' and not scenario_name):
        raise ValueError('Select a valid mode and named scenario')
    if decision and decision not in ('REPORT', 'REVIEW', 'SUPPRESS'):
        raise ValueError('Invalid decision filter')
    results = []
    for finding in findings:
        if decision and finding.get('decision') != decision:
            continue
        selected_store = AssessmentStore(store.path.parent / 'complete') if mode == complete.MODE else store
        candidates = [r for r in selected_store.history(scan, finding['finding_id']) if r['profile']['mode'] == mode
                      and (mode != 'SCENARIO' or r['profile']['scenario_name'] == scenario_name)]
        if candidates:
            latest = candidates[-1]
            if (latest['assessment']['finding_anchor'] != context.finding_anchor(finding)
                    or latest['assessment']['source_evidence_hash'] != evidence_hash(finding)):
                raise Conflict('Published assessment does not match current finding')
            row = {**latest['assessment'], 'revision': latest['revision'], 'revision_hash': latest['revision_hash']}
        else:
            fallback = (complete.assess(finding, scan, automatic.collect(None, [finding]))[1] if mode == complete.MODE else automatic.assess(finding, scan, automatic.collect(None, [finding]), mode)[1]
                        if mode in (*automatic.MODES, complete.MODE) else evaluate(finding, scan))
            row = {**fallback, 'revision': None, 'revision_hash': None}
        results.append(row)
    results.sort(key=lambda r: (-Decimal(r['cwss_score_exact']), r['finding_id']))
    return results


def handle(state, method, path, query, body=None, authorization=''):
    """Called by HTTP handler; return None only for a different route."""
    matched = ROUTE.fullmatch(path)
    if not matched:
        return None
    scan, endpoint, fid, action = matched.groups()
    def param(key, default=''):
        return query.get(key, [default])[0]
    try:
        actor = authorize(authorization) if method == 'POST' or action == 'draft' else None
        if endpoint == 'catalog' and method == 'GET':
            return 200, catalog()
        findings = state.result_index.get_all_finding_details(scan)
        summary = state.result_index.get_scan_summary(scan)
        if summary is None:
            return 404, {'error_code': 'SCAN_NOT_FOUND'}
        store = AssessmentStore(directory(state))
        if endpoint in ('ranking', 'report') and method == 'GET':
            rows = ranking(findings, scan, store, param('mode', 'ASSESSED'), param('scenario_name'), param('decision'))
            if endpoint == 'report':
                return 200, {'schema_version': VERSION, 'scan_id': scan, 'export_kind': 'CWSS_ASSESSMENT_REPORT',
                             'archive_unchanged': True, 'requested_mode': param('mode', 'ASSESSED'),
                             'findings': rows, 'metric_catalog': catalog()}
            page, size = int(param('page', '1')), int(param('page_size', '50'))
            if page < 1 or not 1 <= size <= 200:
                raise ValueError('Invalid page/page_size')
            return 200, {'scan_id': scan, 'priority_policy': 'CWSS_0_100_WITH_ASSESSMENT_STATE',
                         'requested_mode': param('mode', 'ASSESSED'), 'scenario_name': param('scenario_name'),
                         'total_matching': len(rows), 'page': page, 'page_size': size,
                         'findings': rows[(page-1)*size:page*size]}
        finding = next((f for f in findings if f['finding_id'] == fid), None)
        if finding is None:
            raise LookupError('Finding not found in this scan')
        if method == 'GET':
            if action == 'automatic':
                rows = {mode: ranking([finding], scan, store, mode)[0] for mode in automatic.MODES}
                return 200, {'scan_id': scan, 'finding_id': fid, 'automatic_scores': rows,
                             'inference_version': automatic.VERSION,
                             'auto_complete': ranking([finding], scan, store, complete.MODE)[0]}
            if action == 'template':
                return 200, {'profile': template(finding, scan), 'preliminary': evaluate(finding, scan), 'catalog': catalog()}
            if action == 'history':
                return 200, {'scan_id': scan, 'finding_id': fid, 'revisions': store.history(scan, fid),
                    'complete_revisions': AssessmentStore(directory(state)/'complete').history(scan, fid)}
            if action == 'draft':
                return 200, {'profile': store.draft(scan, fid, actor)}
            if action == 'replay':
                return 200, (AssessmentStore(directory(state)/'complete') if param('mode') == complete.MODE else store).replay(scan, fid, int(param('revision')))
        elif method == 'POST' and action in ('preview', 'draft', 'publish'):
            if not isinstance(body, dict) or set(body) - {'profile', 'expected_revision'} or not isinstance(body.get('profile'), dict):
                raise ValueError('Body must contain profile and optional expected_revision')
            p = body['profile']
            if action == 'preview':
                return 200, evaluate(finding, scan, p, actor)
            if action == 'draft':
                return 200, store.save_draft(finding, scan, p, actor)
            return 201, store.publish(finding, scan, p, actor, body.get('expected_revision'))
        return 405, {'error_code': 'METHOD_NOT_ALLOWED'}
    except AuthorizationError as exc:
        return 401, {'error_code': 'CWSS_AUTH_REQUIRED', 'error_message': str(exc)}
    except Conflict as exc:
        return 409, {'error_code': 'CWSS_REVISION_CONFLICT', 'error_message': str(exc)}
    except LookupError as exc:
        return 404, {'error_code': 'CWSS_NOT_FOUND', 'error_message': str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return 422, {'error_code': 'CWSS_VALIDATION_ERROR', 'error_message': str(exc)}

    except (OSError, sqlite3.Error):
        return 500, {'error_code': 'CWSS_STORAGE_ERROR', 'error_message': 'Assessment storage unavailable'}
