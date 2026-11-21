import {classifyDataOrigin, clearScanRecords, readScanHistory, removeScanRecord} from './scanData';

// In-memory (RAM-only) scan history scoped by API origin AND active Auth Session Scope.
//
// Provenance & session-isolation rules:
// - Credential-dependent history is kept strictly in RAM (never read from or written to localStorage),
//   so page reloads lose the RAM token AND never resurface private history from an earlier auth session.
// - Every cached record carries BOTH `apiOrigin` (normalized scheme://host:port) and `sessionScope`
//   (an opaque RAM-only session id rotated on every origin change, token change, or token clear;
//   never derived from the raw token or a token hash).
// - Switching API origin or Bearer Token wipes the RAM history cache via `clearHistoryCache()`,
//   preventing cross-origin, cross-session, or return-to-prior-session cache leaks.
// - Records returned by the currently selected API are authoritative and are NEVER back-filled with
//   fields from the browser cache (repo URL, commit, timestamps, ...). Missing fields stay missing.
// - Cache-only records stay labelled as browser cache (`backendConfirmed: false`).

const ACTIVE_SCAN_KEY = '22025523-scan-id';
const MAX = 50;
const KEEP_FIRST = ['startedAt', 'completedAt', 'repoUrl', 'inputMode'];
const INTERNAL_FIELDS = new Set(['backendConfirmed', 'sourceOrigin', 'apiOrigin', 'sessionScope', 'hiddenAt']);

let memoryHistoryRecords = [];
let memoryHiddenMap = {};

export function normalizeApiOrigin(value) {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed.origin : '';
  } catch {
    return '';
  }
}

export function normalizeSessionScope(value, origin = '') {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (raw) return raw;
  return normalizeApiOrigin(origin);
}

export const historyKey = (record) => record?.scanId || record?.jobId || '';

const recordOrigin = (record) => normalizeApiOrigin(record?.apiOrigin);
const recordSession = (record) => normalizeSessionScope(record?.sessionScope, record?.apiOrigin);

export function scopedHistoryKey(record, origin, sessionScope) {
  const k = historyKey(record);
  if (!k) return '';
  const orig = origin === undefined ? recordOrigin(record) : normalizeApiOrigin(origin);
  const sess = sessionScope === undefined
    ? (origin === undefined ? recordSession(record) : normalizeSessionScope('', orig))
    : normalizeSessionScope(sessionScope, orig);
  return `${sess}|${orig}|${k}`;
}

export function clearHistoryCache() {
  memoryHistoryRecords = [];
  memoryHiddenMap = {};
  clearScanRecords();
}

const stamp = (record) => Date.parse(record.completedAt || record.startedAt || record.savedAt || '') || 0;

function definedFields(record) {
  return Object.fromEntries(
    Object.entries(record).filter(([key, value]) => !INTERNAL_FIELDS.has(key) && value !== undefined),
  );
}

export function readHiddenHistory(origin = '', {sessionScope} = {}) {
  const orig = normalizeApiOrigin(origin);
  const sess = normalizeSessionScope(sessionScope, orig);
  return Object.values(memoryHiddenMap)
    .filter((record) => record && typeof record === 'object' && recordOrigin(record) === orig && recordSession(record) === sess)
    .sort((a, b) => stamp(b) - stamp(a));
}

export function readHistory(origin = '', {sessionScope} = {}) {
  const orig = normalizeApiOrigin(origin);
  const sess = normalizeSessionScope(sessionScope, orig);
  const stored = memoryHistoryRecords
    .filter((item) => recordOrigin(item) === orig && recordSession(item) === sess)
    .map((item) => ({
      ...item,
      apiOrigin: orig,
      sessionScope: sess,
      backendConfirmed: false,
      sourceOrigin: 'BROWSER_CACHE',
    }));
  const known = new Set(stored.map(historyKey).filter(Boolean));
  const legacy = readScanHistory()
    .filter((item) => (
      item?.scanId &&
      normalizeApiOrigin(item.apiOrigin) === orig &&
      normalizeSessionScope(item.sessionScope, item.apiOrigin) === sess &&
      !known.has(item.scanId)
    ))
    .map((item) => ({
      scanId: item.scanId,
      savedAt: item.savedAt,
      status: 'COMPLETED',
      apiOrigin: orig,
      sessionScope: sess,
      backendConfirmed: false,
      sourceOrigin: 'BROWSER_CACHE',
    }));
  return [...stored, ...legacy]
    .filter((item) => {
      const k = scopedHistoryKey(item);
      return Boolean(historyKey(item)) && !memoryHiddenMap[k] && !item.isTestOrMock;
    })
    .sort((a, b) => stamp(b) - stamp(a));
}

// Merge RAM browser-cache rows with rows returned by the current API within the same auth session.
// Rows belonging to any other origin or auth session scope are discarded.
// A remote row fully replaces a cached row with the same scoped key: cache fields are never used to
// fill gaps in API data, so the row's provenance badge always describes every field it shows.
export function mergeHistoryRecords(cached, remote, hidden = [], {origin, sessionScope} = {}) {
  const origFilter = origin === undefined ? undefined : normalizeApiOrigin(origin);
  const sessFilter = sessionScope === undefined
    ? (origin === undefined ? undefined : normalizeSessionScope('', origFilter))
    : normalizeSessionScope(sessionScope, origFilter || '');
  const inScope = (record) => (
    (origFilter === undefined || recordOrigin(record) === origFilter) &&
    (sessFilter === undefined || recordSession(record) === sessFilter)
  );

  const byKey = new Map();
  for (const record of cached || []) {
    const k = scopedHistoryKey(record);
    if (!historyKey(record) || record.isTestOrMock || !inScope(record)) continue;
    byKey.set(k, {
      ...definedFields(record),
      apiOrigin: recordOrigin(record),
      sessionScope: recordSession(record),
      backendConfirmed: false,
      sourceOrigin: 'BROWSER_CACHE',
    });
  }
  for (const record of remote || []) {
    const k = scopedHistoryKey(record);
    if (!historyKey(record) || record.isTestOrMock || !inScope(record)) continue;
    // Several endpoints of the SAME API & session (scan-jobs + scans) may describe one scan;
    // combine those, but never inherit fields from a browser-cache row.
    const previous = byKey.get(k);
    const base = previous?.backendConfirmed ? previous : {};
    byKey.set(k, {
      ...base,
      ...definedFields(record),
      apiOrigin: recordOrigin(record),
      sessionScope: recordSession(record),
      backendConfirmed: true,
      sourceOrigin: 'BACKEND',
    });
  }
  const hiddenKeys = new Set((hidden || []).map((record) => scopedHistoryKey(record)).filter(Boolean));
  return [...byKey.values()]
    .filter((record) => !hiddenKeys.has(scopedHistoryKey(record)) && !record.isTestOrMock)
    .sort((a, b) => stamp(b) - stamp(a));
}

function isPlainObj(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export function historyRecordFromBackend(item, {origin = '', sessionScope} = {}) {
  if (!isPlainObj(item)) return null;
  const byValidated = isPlainObj(item.by_validated_status) ? item.by_validated_status : {};
  const byHuman = isPlainObj(item.by_human_review_state) ? item.by_human_review_state : {};
  const stageStatuses = isPlainObj(item.stage_statuses) ? item.stage_statuses : {};
  const rawState = String(item.job_state ?? item.state ?? item.job_status ?? item.status ?? '').toUpperCase();
  const rawScanId = item.scan_id ?? (item.scan_sha256 && !item.job_id ? item.id : undefined);
  const scanId = typeof rawScanId === 'string' && rawScanId.trim() ? rawScanId.trim() : null;
  const rawJobId = item.job_id;
  const jobId = typeof rawJobId === 'string' && rawJobId.trim() ? rawJobId.trim() : null;
  if (!scanId && !jobId) return null;
  const status = ['COMPLETED', 'FAILED', 'RUNNING', 'QUEUED'].includes(rawState)
    ? rawState
    : scanId
      ? 'COMPLETED'
      : undefined;
  const orig = normalizeApiOrigin(origin);
  const originInfo = classifyDataOrigin(item);
  return {
    scanId: scanId || undefined,
    jobId: jobId || undefined,
    repoUrl: item.repository_url ?? item.repo_url ?? undefined,
    fileName: item.file_name ?? undefined,
    inputMode: item.input_mode ?? (String(item.source_mode || '').includes('ZIP') ? 'ZIP' : undefined),
    commit: item.resolved_commit ?? item.resolved_commit_sha ?? undefined,
    status,
    startedAt: item.started_at_utc ?? item.started_at ?? item.created_at_utc ?? item.created_at ?? undefined,
    completedAt: item.finished_at_utc ?? item.completed_at ?? item.collected_at ?? item.finished_at ?? undefined,
    backendMs: item.total_e2e_duration_ms ?? undefined,
    javaFilesScanned: item.java_files_scanned ?? undefined,
    candidates: item.total_findings ?? undefined,
    supported: byValidated.SUPPORTED ?? undefined,
    refuted: byValidated.REFUTED ?? undefined,
    undetermined: byValidated.UNDETERMINED ?? undefined,
    openCount: byHuman.OPEN ?? undefined,
    confirmedTrue: byHuman.CONFIRMED_TRUE ?? undefined,
    confirmedFalse: byHuman.CONFIRMED_FALSE ?? undefined,
    qwenInferenceStatus: stageStatuses.qwen_inference_status ?? undefined,
    scanIssuesCount: Array.isArray(item.scan_issues) ? item.scan_issues.length : undefined,
    errorCode: item.error_code ?? undefined,
    errorMessage: item.error_message ?? undefined,
    dataOrigin: item.data_origin !== undefined ? originInfo.code : undefined,
    isTestOrMock: originInfo.isMockOrTest,
    apiOrigin: orig,
    sessionScope: normalizeSessionScope(sessionScope, orig),
    backendConfirmed: true,
    sourceOrigin: 'BACKEND',
  };
}

export function upsertHistory(partial, {authoritative = false, origin = '', sessionScope} = {}) {
  const orig = normalizeApiOrigin(origin);
  const sess = normalizeSessionScope(sessionScope, orig);
  const k = historyKey(partial);
  if (!k || partial?.isTestOrMock) return;
  const scoped = `${sess}|${orig}|${k}`;
  if (memoryHiddenMap[scoped]) return;
  const old = memoryHistoryRecords.find((item) => scopedHistoryKey(item) === scoped) || {};
  const defined = Object.fromEntries(
    Object.entries(partial).filter(([key, value]) => {
      if (INTERNAL_FIELDS.has(key)) return false;
      return value !== undefined && value !== null && value !== '';
    }),
  );
  KEEP_FIRST.forEach((key) => {
    if (old[key] && !authoritative) delete defined[key];
  });
  const next = {
    savedAt: new Date().toISOString(),
    ...old,
    ...defined,
    apiOrigin: orig,
    sessionScope: sess,
  };
  memoryHistoryRecords = [
    next,
    ...memoryHistoryRecords.filter((item) => scopedHistoryKey(item) !== scoped),
  ].slice(0, MAX);
}

export function hideHistoryRecord(record) {
  const scoped = scopedHistoryKey(record);
  if (!scoped) return;
  const orig = recordOrigin(record);
  const sess = recordSession(record);
  const {backendConfirmed: _bc, sourceOrigin: _so, ...persisted} = record;
  memoryHiddenMap = {
    ...memoryHiddenMap,
    [scoped]: {...persisted, apiOrigin: orig, sessionScope: sess, hiddenAt: new Date().toISOString()},
  };
  memoryHistoryRecords = memoryHistoryRecords.filter((item) => scopedHistoryKey(item) !== scoped);
  if (record.scanId) {
    try {
      if (typeof window !== 'undefined' && window.sessionStorage?.getItem(ACTIVE_SCAN_KEY) === record.scanId) {
        window.sessionStorage.removeItem(ACTIVE_SCAN_KEY);
      }
    } catch {
      /* non-destructive */
    }
    removeScanRecord(record.scanId, orig, sess);
  }
}

export function restoreHistoryRecord(scopedKey) {
  const record = memoryHiddenMap[scopedKey];
  if (!record) return;
  const nextHidden = {...memoryHiddenMap};
  delete nextHidden[scopedKey];
  memoryHiddenMap = nextHidden;
  const {hiddenAt: _hiddenAt, backendConfirmed: _bc, sourceOrigin: _so, ...visibleRecord} = record;
  const restored = {...visibleRecord, apiOrigin: recordOrigin(record), sessionScope: recordSession(record)};
  memoryHistoryRecords = [
    restored,
    ...memoryHistoryRecords.filter((item) => scopedHistoryKey(item) !== scopedKey),
  ].slice(0, MAX);
}

export const pick = (object, keys) => {
  if (!object || typeof object !== 'object') return undefined;
  for (const key of keys) {
    if (typeof object[key] === 'string' && object[key]) return object[key];
  }
  return undefined;
};
