"""Per-metric CWSS V2. V1 engines remain immutable for historical replay."""
import copy
from datetime import datetime
from decimal import Decimal
import ntk_cwss_evidence_graph as graph
import ntk_cwss_v101 as score
import ntk_cwss_automatic as old
import ntk_cwss_complete as completion

VERSION='NTK_CWSS_INFERENCE_V2'
CONTEXT_VERSION='NTK_CWSS_DECLARED_CONTEXT_V2'
MODES=(*old.MODES,completion.MODE)
POLICY={m:{'metric':m,'version':VERSION,'allowed':list(score.WEIGHTS[m]),
    'rule':{'TI':'LOCAL_CAPABILITY','AL':'COMPROMISE_LAYER_ESTIMATE','IC':'VERIFIED_CONTROL',
            'IN':'LOCAL_INTERACTION','RP':'DECLARED_AUTH_OR_METHOD_SECURITY','AS':'DECLARED_AUTH',
            'FC':'EXISTING_ATTESTATION_GATE_ONLY','P':'TARGETED_POLICY'}.get(m,'DECLARED_CONTEXT_OR_OFFICIAL_FALLBACK')}
    for m in score.FACTOR_ORDER}
_REQUIRED={
 'TI':['source hash','resolved scoped sink','IRIS local flow or exact safe proof','execution/output semantics'],
 'AP':['declared service-account privilege or independent attestation; never inferred from CWE'],
 'AL':['proven local sink capability','conditional compromise layer'],
 'IC':['exact-slot safe control proof; absence of sanitizer is not absence of control'],
 'FC':['original independent reviewer verdict and reachability gates only'],
 'RP':['active-context declaration or method authorization annotation (estimate only)'],
 'RL':['declared access privilege layer'], 'AV':['declared deployment exposure'],
 'AS':['declared authentication model'], 'IN':['observed HTTP entry','proven server flow or HTML victim estimate'],
 'SC':['declared deployment inventory scope'], 'BI':['declared asset criticality and rationale'],
 'DI':['declared discovery assumption; no measured attacker prior'],
 'EX':['declared exploit reliability assumption; no measured exploit rate'],
 'EC':['declared external control assumption or independent attestation'], 'P':['targeted policy']}
for _metric,_row in POLICY.items():
    _row.update(required_inputs=_REQUIRED[_metric], conflict_policy='retain raw graph conflict; do not promote UNKNOWN',
                fallback='UK/U in audit modes, official D in Complete')

# This policy is defined in domain terms, not as an injected 16-metric vector.
CONTEXT_CODES={
 'asset_criticality':{'CRITICAL':{'BI':'C'},'MODERATE':{'BI':'M'},'LOW':{'BI':'L'}},
 'exposure':{'INTERNET':{'AV':'I'},'INTRANET':{'AV':'R'},'LOCAL':{'AV':'L'}},
 'authentication':{'NONE':{'RP':'N','RL':'A','AS':'N'},'REGULAR_PASSWORD':{'RP':'RU','RL':'A','AS':'M'},'PRIVILEGED_MFA':{'RP':'P','RL':'A','AS':'S'}},
 'external_controls':{'NONE':{'EC':'N'},'BEST_AVAILABLE':{'EC':'B'},'COMPLETE':{'EC':'C'}},
 'internal_controls':{'NONE':{'IC':'N'},'PARTIAL':{'IC':'M'}},
 'deployment_scope':{'ALL':{'SC':'A'},'RARE':{'SC':'R'}},
 'service_privilege':{'REGULAR':{'AP':'RU'},'LIMITED':{'AP':'L'}},
 'discovery':{'DOCUMENTED_EXPOSED':{'DI':'H'},'RESTRICTED':{'DI':'L'}},
 'exploitability':{'DIRECT_UNMITIGATED':{'EX':'H'},'RESTRICTED':{'EX':'L'}}}


def validate_context(ctx):
    keys={'schema_version','profile_id','profile_version','declared_by','declared_at','reference','rationale',*CONTEXT_CODES}
    if not isinstance(ctx,dict) or set(ctx)!=keys:
        raise ValueError('Complete typed context declaration required')
    if ctx['schema_version']!=CONTEXT_VERSION or ctx['profile_id'] not in ('BUSINESS_CRITICAL_INTERNET_FACING','USER_DECLARED_DEPLOYMENT'):
        raise ValueError('Unknown context schema/profile')
    for key in ('profile_version','declared_by','reference','rationale'):
        if not isinstance(ctx[key],str) or len(ctx[key].strip())<(24 if key=='rationale' else 6):
            raise ValueError('Context attribution/reference/rationale missing')
    date=datetime.fromisoformat(str(ctx['declared_at']).replace('Z','+00:00'))
    if date.tzinfo is None:raise ValueError('Context timezone required')
    for key,options in CONTEXT_CODES.items():
        if ctx[key] not in options:raise ValueError('Unsupported context choice:'+key)
    if ctx['profile_id']=='BUSINESS_CRITICAL_INTERNET_FACING' and (ctx['asset_criticality']!='CRITICAL' or ctx['exposure']!='INTERNET'):
        raise ValueError('Context profile and declared properties conflict')
    return ctx


def policy_hash():
    import ntk_cwss_workflow as w
    return w.digest({'rules':POLICY,'registry':{':'.join(k):sorted(v) for k,v in graph.REGISTRY.items()},'context':CONTEXT_CODES,'cwe_applicability':graph.CWE_APPLICABILITY,'version':VERSION})


def assess(finding,scan,snapshot,mode,reference='GENERAL_JAVA',attestation=None):
    import ntk_cwss_workflow as w
    if mode not in MODES:raise ValueError('Unsupported automatic mode')
    g=graph.normalize(finding,snapshot)
    if snapshot.get('finding_evidence_hashes',{}).get(finding['finding_id'])!=w.evidence_hash(finding):
        raise ValueError('Snapshot/finding evidence mismatch')
    ctx=snapshot.get('declared_context_v2')
    if ctx:validate_context(ctx)
    contextual={}
    if ctx:
        for key,options in CONTEXT_CODES.items():
            for m,code in options[ctx[key]].items():contextual[m]=(code,key)
    reviewed=w.evaluate(finding,scan,attestation['profile'],attestation['reviewer']) if attestation else None
    if attestation and attestation['profile']['mode']!='ASSESSED':raise ValueError('Only validated attestation')
    rows={}
    owner=g['identity'];package=owner.get('package');cls=owner.get('class');method=owner.get('method')
    server=package in ('java.lang','java.sql','java.nio.file')
    xss=package=='java.io' and cls=='PrintWriter'
    shell=bool(g['local_taint_proven'] and package=='java.lang' and any('"-c"' in step and re_shell(step) for step in g['source_to_sink_steps']))
    for m in score.FACTOR_ORDER:
        code='U' if m=='AV' else 'UK';status='UNKNOWN';reason='No factor-specific evidence';rule='NO_SUFFICIENT_EVIDENCE';origin=[]
        def choose(c,s,r,why,source):
            nonlocal code,status,rule,reason,origin
            code,status,rule,reason,origin=c,s,r,why,source
        # Independent guards: controls, effect, interaction, privilege layer and auth.
        if m=='P':choose('NA','NOT_APPLICABLE','TARGETED_POLICY','Prevalence excluded for targeted individual finding',[score.STANDARD_URL])
        elif m=='TI' and g['local_safe_proven']:
            choose('N','VERIFIED','EXACT_CANDIDATE_NO_INJECTION','IRIS safe proof covers the resolved candidate sink; not an application-wide safety claim',[g['evidence_hash']])
        elif m=='IC' and g['local_safe_proven'] and str(g['control']['proof_node']).startswith('SANITIZER_CALL:'):
            choose('C','VERIFIED','IRIS_COMPLETE_LOCAL_CONTROL','Existing semantic release and exact sink-slot control proof',[g['evidence_hash']])
        elif m=='TI' and g['local_taint_proven'] and (server or xss):
            if not xss or g['control']['context'] in ('HTML_BODY','HTML_ATTRIBUTE_QUOTED','SERVLET_HTML_RESPONSE'):
                choose('H','VERIFIED' if shell else 'ESTIMATED','SHELL_CAPABILITY' if shell else 'RESOLVED_SINK_CAPABILITY',
                    'Explicit shell command capability' if shell else 'Conditional significant impact of covered local sink capability; runtime scope remains unverified',[g['evidence_hash']])
        elif m=='AL' and g['local_taint_proven'] and (server or xss):
            choose('S' if package in ('java.lang','java.nio.file') else 'A','ESTIMATED','LOCAL_COMPROMISE_LAYER',
                'Conditional compromise layer from sink semantics, not acquired privilege level',[g['evidence_hash']])
        elif m=='IN' and g['local_taint_proven'] and g['entry_point']['observed'] and server:
            choose('A','VERIFIED','SYNCHRONOUS_HTTP_SERVER_EFFECT','Local request-to-server-sink flow is automatable; no deployed reachability claim',[g['evidence_hash']])
        elif m=='IN' and g['local_taint_proven'] and xss and g['control']['context'] in ('HTML_BODY','HTML_ATTRIBUTE_QUOTED','SERVLET_HTML_RESPONSE'):
            choose('T','ESTIMATED','HTML_VICTIM_INTERACTION','Assumes victim renders the vulnerable HTML response',[g['evidence_hash']])
        elif m=='RP' and g['entry_point'].get('method_security_observed'):
            choose('P','ESTIMATED','METHOD_SECURITY_REQUIREMENT','Method authorization annotation observed; active enforcement not established',[g['evidence_hash']])
        human=reviewed['metric_assessments'][m] if reviewed else {}
        if status not in ('VERIFIED','NOT_APPLICABLE') and human.get('evidence_sufficient') and human.get('code') not in ('UK','U','D','NA'):
            choose(human['code'],'ANALYST_ATTESTED','V2_REVIEWER_GATE',human['reason'],[human.get('reference')])
        # Declared deployment context is never emitted into audit Evidence.
        if mode!=old.MODES[0] and status not in ('VERIFIED','NOT_APPLICABLE','ANALYST_ATTESTED') and m in contextual:
            value,field=contextual[m]
            choose(value,'REFERENCE_ASSUMPTION','DECLARED_'+field.upper(),ctx['rationale'],[ctx['reference']])
        if mode==old.MODES[0] and status not in ('VERIFIED','NOT_APPLICABLE','ANALYST_ATTESTED'):
            code='U' if m=='AV' else 'UK';status='UNKNOWN'
        if mode==completion.MODE and code in ('UK','U'):
            # Legacy references stay available with explicit provenance, FC never assumed.
            spec=completion.PROFILES.get(reference)
            if spec is None:raise ValueError('Unknown reference profile')
            if m in spec['codes']:
                choose(spec['codes'][m],'REFERENCE_ASSUMPTION','LEGACY_REFERENCE_PROFILE',spec['reason'],[reference+'@'+completion.PROFILE_VERSION])
            else:choose('D','MITRE_DEFAULT','OFFICIAL_DISCRETE_DEFAULT','Official Default is not proof, including FC:D',[score.STANDARD_URL])
        rows[m]={'metric':m,'code':code,'weight':score.WEIGHTS[m][code],'classification':status,'inference_status':status,
            'reason':reason,'rule_id':rule,'evidence':origin,'assumption':status in ('ESTIMATED','REFERENCE_ASSUMPTION','MITRE_DEFAULT'),
            'confidence':'LOCAL_PROOF' if status=='VERIFIED' else ('UNVERIFIED' if status!='NOT_APPLICABLE' else 'POLICY'),
            'input_evidence_status':g['status'] if m in ('TI','AL','IC','IN') else status,
            'conflicts':g['conflicts'] if m in ('TI','AL','IC','IN') else [],
            'rejection_reasons':g['blocked_rules'] if code in ('UK','U','D') else [],'evidence_sufficient':status in ('VERIFIED','ANALYST_ATTESTED','NOT_APPLICABLE'),
            'provenance':{'inference_version':VERSION,'graph_hash':g['evidence_hash'],'policy_hash':policy_hash()},'applied_to_score':code not in ('UK','U')}
    codes={m:r['code'] for m,r in rows.items()}
    result=score.score_codes(codes,fill_unknown=False)
    profile={'mode':mode,'inference_version':VERSION,'automatic_evidence':copy.deepcopy(snapshot),
             'reference_profile':reference,'attestation':copy.deepcopy(attestation),'policy_hash':policy_hash()}
    counts={name:sum(r['classification'] in kinds for r in rows.values()) for name,kinds in {
      'verified_metric_count':('VERIFIED',),'estimated_metric_count':('ESTIMATED',),'reference_metric_count':('REFERENCE_ASSUMPTION',),
      'default_metric_count':('MITRE_DEFAULT',),'attested_metric_count':('ANALYST_ATTESTED',)}.items()}
    result.update(mode=mode,score_mode=mode,inference_version=VERSION,engine_version=w.ENGINE,engine_hash=w.ENGINE_HASH,
        finding_id=finding['finding_id'],scan_id=scan,finding_anchor=w.context.finding_anchor(finding),source_evidence_hash=w.evidence_hash(finding),
        metric_assessments=rows,metric_provenance=rows,metric_vector=result['vector'],normalized_evidence=g,
        reference_profile=ctx['profile_id'] if ctx else reference,reference_profile_version=ctx['profile_version'] if ctx else completion.PROFILE_VERSION,
        reference_context_hash=w.digest(ctx) if ctx else None,profile_hash=w.digest(profile),fully_verified=False,
        assessment_status='SCENARIO-CONDITIONAL' if ctx or mode==completion.MODE else 'INCOMPLETE',
        three_subscores=result['subscores_exact'],triage_decision=finding.get('decision','REVIEW'),heuristic_evidence_score=finding.get('final_heuristic_score'),
        explanation='Versioned per-metric rules. Local proof is not deployed exploitability; declared context is conditional.',**counts,
        assessment_completeness={**counts,'unknown_count':result['unknown_metric_count'],'metric_count':16,'policy_na_count':1})
    result['calculation_hash']=w.digest({'profile':profile,'codes':codes,'graph':g,'exact':result['cwss_score_exact'],'engine_hash':w.ENGINE_HASH})
    return profile,result


def re_shell(step):
    import re
    return bool(re.search(r'"(?:/bin/)?(?:sh|bash)"',step))


def matches(finding,revision):
    from ntk_cwss_provenance import equivalent
    return equivalent(finding,revision)


def ranking(findings,scan,store,mode,decision=''):
    import ntk_cwss_workflow as w
    if decision and decision not in ('REPORT','REVIEW','SUPPRESS'):raise ValueError('Invalid decision filter')
    selected=w.AssessmentStore(store.path.parent/'complete') if mode==completion.MODE else store
    rows=[]
    for f in findings:
        if decision and f.get('decision')!=decision:continue
        revisions=[r for r in selected.history(scan,f['finding_id']) if r['profile']['mode']==mode]
        if revisions:
            latest=revisions[-1]
            if not matches(f,latest):raise w.Conflict('Published assessment does not match current finding/source')
            row={**latest['assessment'],'revision':latest['revision'],'revision_hash':latest['revision_hash']}
        else:
            snapshot=old.collect(None,[f]);snapshot['inference_version']=graph.VERSION
            row={**assess(f,scan,snapshot,mode)[1],'revision':None,'revision_hash':None}
        rows.append(row)
    return sorted(rows,key=lambda r:(-Decimal(r['cwss_score_exact']),r['finding_id']))
