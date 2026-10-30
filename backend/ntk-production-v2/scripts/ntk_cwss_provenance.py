"""Persisted-index enrichment compatibility without changing historical hashes."""
import copy


def equivalent(current, revision):
    import ntk_cwss_workflow as w
    original = revision['finding_snapshot']
    if w.context.finding_anchor(current) != w.context.finding_anchor(original):
        return False
    if current.get('decision') != original.get('decision'):
        return False
    candidate = copy.deepcopy(current)
    if (current.get('review_status') or 'NOT_REVIEWED') == (original.get('review_status') or 'NOT_REVIEWED'):
        candidate['review_status'] = original.get('review_status')
    incoming = current.get('source_provenance_record')
    if original.get('source_provenance_record') is None and incoming is not None:
        snapshot = revision['profile'].get('automatic_evidence') or {}
        expected = snapshot.get('analysis_source_bindings', {}).get(current['finding_id'])
        if not expected or incoming.get('verified') is not True or incoming.get('file_sha256') != expected:
            return False
        if incoming.get('finding_id', current['finding_id']) != current['finding_id']:
            return False
        candidate['source_provenance_record'] = None
    return w.evidence_hash(candidate) == w.evidence_hash(original)
