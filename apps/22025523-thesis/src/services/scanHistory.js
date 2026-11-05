import {readScanHistory, removeScanRecord} from './scanData';

const KEY = '22025523-scan-history-v1';
const HIDDEN_KEY = '22025523-hidden-scan-history-v1';
const CACHE_PREFIX = '22025523-live-dataset:';
const MAX = 50;
const KEEP_FIRST = ['startedAt', 'completedAt', 'repoUrl', 'inputMode'];

function readStored() {
  try {
    const list = JSON.parse(window.localStorage.getItem(KEY) || '[]');
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function readHiddenMap() {
  try {
    const value = JSON.parse(window.localStorage.getItem(HIDDEN_KEY) || '{}');
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  } catch {
    return {};
  }
}

const stamp = (record) => Date.parse(record.startedAt || record.savedAt || '') || 0;

export function readHiddenHistory() {
  return Object.values(readHiddenMap()).sort((a, b) => stamp(b) - stamp(a));
}

export function readHistory() {
  const hidden = readHiddenMap();
  const stored = readStored();
  const known = new Set(stored.map((item) => item.scanId));
  const legacy = readScanHistory()
    .filter((item) => item?.scanId && !known.has(item.scanId))
    .map((item) => ({scanId: item.scanId, savedAt: item.savedAt, status: 'COMPLETED', inputMode: 'GITHUB'}));
  return [...stored, ...legacy]
    .filter((item) => item.scanId && !hidden[item.scanId])
    .sort((a, b) => stamp(b) - stamp(a));
}

// The browser cache stays bounded. Rendering the authoritative backend history
// must not silently inherit that cache's 50-record retention limit.
export function mergeHistoryRecords(cached, remote, hidden = []) {
  const byId=new Map();
  for(const record of [...cached,...remote]){
    if(!record?.scanId)continue;
    const defined=Object.fromEntries(Object.entries(record).filter(([,value])=>value!==undefined));
    byId.set(record.scanId,{...byId.get(record.scanId),...defined});
  }
  const hiddenIds=new Set(hidden.map(record=>record.scanId));
  return [...byId.values()].filter(record=>!hiddenIds.has(record.scanId)).sort((a,b)=>stamp(b)-stamp(a));
}

export function historyRecordFromBackend(item) {
  const totals = item.triage_totals || {};
  // Transport status OK is not the job lifecycle state.
  const state = String(item.job_state ?? item.state ?? item.job_status ?? item.status ?? '').toUpperCase();
  return {
    scanId: item.scan_id ?? item.id,
    jobId: item.job_id,
    repoUrl: item.repository_url ?? item.repo_url,
    fileName: item.file_name,
    inputMode: item.input_mode ?? (String(item.source_mode || '').includes('ZIP') ? 'ZIP' : undefined),
    commit: item.resolved_commit ?? item.resolved_commit_sha,
    status: ['COMPLETED','FAILED','RUNNING','QUEUED'].includes(state) ? state : undefined,
    startedAt: item.started_at_utc ?? item.started_at ?? item.created_at_utc ?? item.created_at,
    completedAt: item.finished_at_utc ?? item.completed_at ?? item.finished_at,
    backendMs: item.total_e2e_duration_ms,
    candidates: totals.total_candidates,
    report: totals.report_count,
    review: totals.review_count,
    suppress: totals.suppress_count,
    restoration: item.restoration_type ?? item.restoration_status,
  };
}

export function upsertHistory(partial, {authoritative = false} = {}) {
  if (!partial?.scanId || readHiddenMap()[partial.scanId]) return;
  const list = readStored();
  const old = list.find((item) => item.scanId === partial.scanId) || {};
  const defined = Object.fromEntries(Object.entries(partial).filter(([, value]) => value !== undefined && value !== null && value !== ''));
  KEEP_FIRST.forEach((key) => {
    if (old[key] && !authoritative) delete defined[key];
  });
  const next = {savedAt: new Date().toISOString(), ...old, ...defined};
  const records = [next, ...list.filter((item) => item.scanId !== partial.scanId)].slice(0, MAX);
  try {
    window.localStorage.setItem(KEY, JSON.stringify(records));
  } catch {
    /* storage unavailable or full */
  }
}

export function hideHistoryRecord(record) {
  if (!record?.scanId) return;
  const hidden = readHiddenMap();
  hidden[record.scanId] = {...record, hiddenAt: new Date().toISOString()};
  const stored = readStored().filter((item) => item.scanId !== record.scanId);
  try {
    window.localStorage.setItem(HIDDEN_KEY, JSON.stringify(hidden));
    window.localStorage.setItem(KEY, JSON.stringify(stored));
    window.sessionStorage.removeItem(`${CACHE_PREFIX}${record.scanId}`);
    if (window.sessionStorage.getItem('22025523-scan-id') === record.scanId) {
      window.sessionStorage.removeItem('22025523-scan-id');
    }
    removeScanRecord(record.scanId);
  } catch {
    /* Browser history remains non-destructive if storage is unavailable. */
  }
}

export function restoreHistoryRecord(scanId) {
  const hidden = readHiddenMap();
  const record = hidden[scanId];
  if (!record) return;
  delete hidden[scanId];
  const {hiddenAt, ...visibleRecord} = record;
  const records = [visibleRecord, ...readStored().filter((item) => item.scanId !== scanId)].slice(0, MAX);
  try {
    window.localStorage.setItem(HIDDEN_KEY, JSON.stringify(hidden));
    window.localStorage.setItem(KEY, JSON.stringify(records));
  } catch {
    /* storage unavailable */
  }
}

export const pick = (object, keys) => {
  if (!object || typeof object !== 'object') return undefined;
  for (const key of keys) {
    if (typeof object[key] === 'string' && object[key]) return object[key];
  }
  return undefined;
};