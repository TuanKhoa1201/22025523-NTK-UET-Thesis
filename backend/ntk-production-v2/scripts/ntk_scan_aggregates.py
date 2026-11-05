"""Whole persisted-scan aggregates, independent of API pagination and triage."""
from collections import Counter,defaultdict
import math
import statistics

METRICS={'TI','AP','AL','IC','FC','RP','RL','AV','AS','IN','SC','BI','DI','EX','EC','P'}


def summarize(findings):
    findings=list(findings);profiles=defaultdict(list);complete=0;priorities=[]
    for finding in findings:
        assessment=finding.get('cwss') or {}
        metrics=assessment.get('metric_assessments') or {}
        valid_metrics=set(metrics)==METRICS and all(isinstance(m,dict) and m.get('provenance') for m in metrics.values())
        complete+=bool(valid_metrics)
        score=assessment.get('cwss_score')
        if type(score) not in (int,float) or not math.isfinite(score) or not 0<=score<=100:continue
        profile=assessment.get('reference_profile') or 'UNDECLARED_PROFILE'
        profiles[profile].append(score)
        priorities.append({'finding_id':finding.get('finding_id'),'cwss_score':score,
                           'profile':profile,'decision':finding.get('decision','REVIEW')})
    return {'scope':'ALL_PERSISTED_FINDINGS_NOT_CURRENT_PAGE','finding_count':len(findings),
        'decisions':dict(Counter(f.get('decision','REVIEW') for f in findings)),
        'by_cwe':dict(Counter(str(f.get('cwe_id') or f.get('cwe') or 'UNKNOWN') for f in findings)),
        'by_severity':dict(Counter(str(f.get('severity') or 'UNKNOWN') for f in findings)),
        'cwss_complete_16_metric_provenance_count':complete,
        'cwss_missing_or_incomplete_metric_provenance_count':len(findings)-complete,
        'cwss_by_profile':{profile:{'count':len(scores),'mean':statistics.mean(scores),
            'median':statistics.median(scores),'min':min(scores),'max':max(scores),
            'score_distribution':dict(Counter(str(score) for score in scores))} for profile,scores in profiles.items()},
        'top_priority_findings':sorted(priorities,key=lambda p:(-p['cwss_score'],str(p['finding_id'])))[:10],
        'cwss_semantics':'PRIORITY_NOT_TP_PROBABILITY_NO_TRIAGE_MUTATION'}
