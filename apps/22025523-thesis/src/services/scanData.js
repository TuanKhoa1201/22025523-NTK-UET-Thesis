import {classifyDataOrigin, normCwe} from './findingPresentation';

export {classifyDataOrigin};

const MAX_RECORDS = 20;
// In-memory only: scan records belong to the active auth session and must not survive reload
// or cross-session credential switches via browser disk/sessionStorage.
let memoryScanRecords = [];

const firstValue = (object, keys) => {
  if (!object || typeof object !== 'object') return undefined;
  for (const key of keys) {
    if (object[key] !== undefined && object[key] !== null && object[key] !== '') return object[key];
  }
  return undefined;
};

const EXPLICIT_VALIDATED_SET = new Set(['SUPPORTED', 'REFUTED', 'UNDETERMINED']);
const EXPLICIT_HUMAN_SET = new Set(['OPEN', 'CONFIRMED_TRUE', 'CONFIRMED_FALSE']);

export function normalizeFinding(item) {
  const safe = item && typeof item === 'object' && !Array.isArray(item) ? item : {};
  const location = safe.location || safe.source_location || safe.start || {};
  const start = safe.start || {};
  const end = safe.end || {};
  const ass = safe.assessment && typeof safe.assessment === 'object' ? safe.assessment : {};
  const rawValidated = firstValue(safe, ['validated_status']) ?? ass.validated_status ?? ass.status;
  const normalizedValidated = typeof rawValidated === 'string' ? rawValidated.trim().toUpperCase() : '';
  const explicitValidatedStatus = EXPLICIT_VALIDATED_SET.has(normalizedValidated) ? normalizedValidated : '';
  const rawHuman = firstValue(safe, ['human_review_state', 'state']);
  const normalizedHuman = typeof rawHuman === 'string' ? rawHuman.trim().toUpperCase() : '';
  const explicitHumanReviewState = EXPLICIT_HUMAN_SET.has(normalizedHuman) ? normalizedHuman : '';

  return {
    id: firstValue(safe, ['finding_id', 'id', 'alert_id']) ?? '',
    alertId: firstValue(safe, ['alert_id', 'finding_id', 'id']) ?? '',
    scanId: firstValue(safe, ['scan_id']) ?? '',
    ruleId: firstValue(safe, ['rule_id', 'scanner_rule_id']) ?? '',
    title: firstValue(safe, ['message', 'title', 'rule_id']) ?? '',
    cwe: normCwe(firstValue(safe, ['cwe', 'cwe_list', 'cwe_id']) ?? ''),
    cweList: Array.isArray(safe.cwe_list) ? safe.cwe_list : [],
    file: firstValue(safe, ['file_path', 'path', 'raw_path']) ?? location.file ?? location.path ?? '',
    line: firstValue(safe, ['start_line', 'line_number', 'line']) ?? start.line ?? location.line ?? '',
    endLine: firstValue(safe, ['end_line']) ?? end.line ?? '',
    severity: firstValue(safe, ['severity', 'priority']) ?? 'WARNING',
    validatedStatus: explicitValidatedStatus || String(rawValidated ?? 'UNDETERMINED').toUpperCase(),
    explicitValidatedStatus,
    rawModelStatus: firstValue(safe, ['raw_model_status']) ?? ass.raw_model_status ?? null,
    validatorDowngraded: Boolean(safe.validator_downgraded ?? ass.validator_downgraded),
    failureKind: firstValue(safe, ['failure_kind']) ?? ass.failure_kind ?? null,
    citationCheck: String(firstValue(safe, ['citation_check']) ?? ass.citation_check ?? 'NOT_VERIFIED').toUpperCase(),
    citationsCount: Number(safe.citations_count ?? (Array.isArray(ass.citations) ? ass.citations.length : 0)),
    humanReviewState: explicitHumanReviewState || String(rawHuman ?? 'OPEN').toUpperCase(),
    explicitHumanReviewState,
    requiresHumanReview: safe.requires_human_review !== false && ass.requires_human_review !== false,
    securityConclusionVerified: Boolean(safe.security_conclusion_verified ?? ass.security_conclusion_verified),
    hasDataflowTrace: Boolean(safe.has_dataflow_trace),
    evidenceIssuesCount: Number(safe.evidence_issues_count ?? 0),
    explanationPreview: firstValue(safe, ['explanation_preview']) ?? ass.explanation ?? '',
    detailUrl: firstValue(safe, ['detail_url']),
    raw: safe,
  };
}

export function readScanHistory() {
  return memoryScanRecords.map((item) => ({...item}));
}

export function saveScanRecord(record) {
  memoryScanRecords = [record, ...memoryScanRecords.filter((item) => item.sessionKey !== record.sessionKey)].slice(0, MAX_RECORDS);
  return readScanHistory();
}

export function removeScanRecord(scanId, apiOrigin, sessionScope) {
  const sameRecord = (item) => (item?.scanId === scanId || item?.sessionKey === scanId)
    && (apiOrigin === undefined || (item?.apiOrigin || '') === apiOrigin)
    && (sessionScope === undefined || (item?.sessionScope || '') === sessionScope);
  memoryScanRecords = memoryScanRecords.filter((item) => !sameRecord(item));
  return readScanHistory();
}

export function clearScanRecords() {
  memoryScanRecords = [];
}
