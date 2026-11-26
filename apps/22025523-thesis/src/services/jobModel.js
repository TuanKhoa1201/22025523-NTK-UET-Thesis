const WIRE_INTEGRITY_REGISTRY_SYM = Symbol.for('22025523.restJsonWireIntegrity.v1');

function getWireRegistry() {
  return globalThis[WIRE_INTEGRITY_REGISTRY_SYM] || null;
}

function getWireObject(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const reg = getWireRegistry();
  if (typeof reg?.getWireObjectIntegrity === 'function') return reg.getWireObjectIntegrity(obj);
  return reg?.objects?.get(obj) || null;
}

function getWireDup(obj, key) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const reg = getWireRegistry();
  if (typeof reg?.getWireDuplicateKeyInfo === 'function') return reg.getWireDuplicateKeyInfo(obj, key);
  const w = reg?.objects?.get(obj);
  if (w?.scannerError) return {count: 2, conflicting: true, scannerError: true};
  return w?.duplicateKeys?.get(key) || null;
}

function isWireInvalidObj(val) {
  return Boolean(val && typeof val === 'object' && !Array.isArray(val) && val.__wireInvalid === true);
}

function fallbackMaterializeTelemetry(value, depth = 0) {
  const reg = getWireRegistry();
  if (typeof reg?.materializeNormalizedTelemetry === 'function') {
    return reg.materializeNormalizedTelemetry(value, depth);
  }
  return {value, hasConflict: false, hasMalformed: false, duplicateKeys: [], invalidFields: []};
}

function buildStageWireIntegrity(job, rawStage, materializedSummary) {
  const jobWire = getWireObject(job);
  const rawWire = getWireObject(rawStage);
  const reasons = [];
  const duplicateKeys = [];
  let hasConflict = Boolean(materializedSummary?.hasConflict);
  let hasMalformed = Boolean(materializedSummary?.hasMalformed);
  let scannerError = Boolean(jobWire?.scannerError || rawWire?.scannerError);
  let duplicateStagesContainer = false;
  let conflictingStagesContainer = false;
  let duplicateSummaryMetadata = false;
  let conflictingSummaryMetadata = false;

  if (scannerError) {
    hasMalformed = true;
    reasons.push('Phản hồi JSON công việc gặp lỗi quét toàn vẹn tại biên REST.');
  }

  for (const jobKey of ['stages', 'state', 'status', 'active_stage', 'scan_id', 'job_id']) {
    const dup = getWireDup(job, jobKey);
    if (dup) {
      duplicateKeys.push(`job.${jobKey}`);
      if (jobKey === 'stages') {
        duplicateStagesContainer = true;
        if (dup.conflicting) conflictingStagesContainer = true;
      }
      if (dup.conflicting) hasConflict = true;
      else hasMalformed = true;
      reasons.push(`Đối tượng job chứa khóa trùng lặp tại biên REST (${jobKey}).`);
    }
  }

  for (const stageKey of ['summary_metadata', 'status', 'state', 'stage_no', 'stage_number', 'stage_id', 'stage_key', 'duration_ms']) {
    const dup = getWireDup(rawStage, stageKey);
    if (dup) {
      duplicateKeys.push(`stage.${stageKey}`);
      if (stageKey === 'summary_metadata') {
        duplicateSummaryMetadata = true;
        if (dup.conflicting) conflictingSummaryMetadata = true;
      }
      if (dup.conflicting) hasConflict = true;
      else hasMalformed = true;
      reasons.push(`Đối tượng stage chứa khóa trùng lặp tại biên REST (${stageKey}).`);
    }
  }

  if (materializedSummary?.duplicateKeys?.length) {
    for (const k of materializedSummary.duplicateKeys) duplicateKeys.push(`summary.${k}`);
  }
  const invalidFields = Array.isArray(materializedSummary?.invalidFields) ? [...materializedSummary.invalidFields] : [];

  if (!scannerError && !hasConflict && !hasMalformed && duplicateKeys.length === 0 && invalidFields.length === 0) {
    return null;
  }

  return {
    scannerError,
    hasConflict,
    hasMalformed,
    duplicateStagesContainer,
    conflictingStagesContainer,
    duplicateSummaryMetadata,
    conflictingSummaryMetadata,
    duplicateKeys: [...new Set(duplicateKeys)],
    invalidFields: [...new Set(invalidFields)],
    reasons: [...new Set(reasons)],
  };
}

export const STAGES = [
  ['INTAKE_VALIDATION', 'Tiếp nhận & kiểm tra an toàn mã nguồn Java'],
  ['OPENGREP_SCAN', 'Phân tích tĩnh OpenGrep & ghi biên nhận băm nguồn'],
  ['EVIDENCE_COLLECTION', 'Trích xuất bằng chứng & ngữ cảnh phương thức Java'],
  ['QWEN_INFERENCE', 'Suy luận Qwen3.5-9B cục bộ qua Ollama (hợp đồng blind)'],
  ['CITATION_VALIDATION', 'Kiểm chứng trích dẫn dòng mã thật & SHA-256'],
  ['REVIEW_STORE_COMMIT', 'Khởi tạo hàng đợi Human Review trên SQLite'],
];

export const CAT_LABEL = {
  COMPLETED: 'Hoàn thành',
  DEGRADED: 'Hoàn tất (có hạ cấp)',
  SKIPPED: 'Bỏ qua',
  FAILED: 'Thất bại',
  CANCELLED: 'Đã hủy',
  RUNNING: 'Đang thực thi',
  PENDING: 'Chưa bắt đầu',
  NOT_RUN: 'Không chạy (job đã dừng)',
  UNKNOWN: 'Chưa có telemetry',
};

export function fmtMs(value, {emptyLabel = 'Chưa có số liệu thời lượng', compact = false} = {}) {
  if (value === null || value === undefined || value === '' || typeof value === 'boolean') return emptyLabel;
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) return emptyLabel;
  if (numeric === 0) return '0 ms';
  if (numeric < 1000) {
    if (numeric < 10 && !Number.isInteger(numeric)) {
      return `${numeric.toLocaleString('vi-VN', {minimumFractionDigits: 1, maximumFractionDigits: 1})} ms`;
    }
    return `${Math.round(numeric)} ms`;
  }
  const sec = numeric / 1000;
  if (sec < 60) {
    return `${sec.toLocaleString('vi-VN', {minimumFractionDigits: 1, maximumFractionDigits: 1})} giây`;
  }
  const totalSec = Math.round(sec);
  const mins = Math.floor(totalSec / 60);
  const rem = totalSec % 60;
  if (compact) {
    return `${mins}p ${String(rem).padStart(2, '0')}s`;
  }
  return rem === 0 ? `${mins} phút` : `${mins} phút ${rem} giây`;
}

export function findKey(object, key, depth = 0) {
  if (!object || typeof object !== 'object' || depth > 6) return undefined;
  if (!Array.isArray(object) && object[key] !== undefined && object[key] !== null) return object[key];
  for (const value of Object.values(object)) {
    const found = findKey(value, key, depth + 1);
    if (found !== undefined) return found;
  }
  return undefined;
}

export function findKeyLike(object, pattern, depth = 0) {
  if (!object || typeof object !== 'object' || depth > 6) return undefined;
  if (!Array.isArray(object)) {
    for (const [key, value] of Object.entries(object)) {
      if (pattern.test(key) && value !== null && value !== undefined && typeof value !== 'object') return {key, value};
    }
  }
  for (const value of Object.values(object)) {
    const found = findKeyLike(value, pattern, depth + 1);
    if (found) return found;
  }
  return undefined;
}

function category(raw) {
  const text = String(raw || '').toUpperCase();
  if (text.includes('SKIP')) return 'SKIPPED';
  if (text.includes('CANCEL')) return 'CANCELLED';
  if (text.includes('FAIL') || text === 'ERROR') return 'FAILED';
  if (text === 'DEGRADED' || text === 'PARTIAL') return 'DEGRADED';
  if (['COMPLETED', 'COMPLETE', 'SUCCESS', 'SUCCEEDED', 'DONE', 'PASSED'].includes(text)) return 'COMPLETED';
  if (['RUNNING', 'IN_PROGRESS', 'ACTIVE'].includes(text)) return 'RUNNING';
  if (['QUEUED', 'PENDING', 'NOT_STARTED'].includes(text)) return 'PENDING';
  return 'UNKNOWN';
}

function toStageNumber(value) {
  if (value && typeof value === 'object') return toStageNumber(value.stage_number ?? value.stage_key ?? value.key);
  if (Number.isInteger(value) && value >= 1 && value <= STAGES.length) return value;
  if (typeof value === 'string' && value) {
    const index = STAGES.findIndex(([key]) => key === value.toUpperCase());
    if (index >= 0) return index + 1;
    const digits = parseInt(value, 10);
    if (Number.isInteger(digits) && digits >= 1 && digits <= STAGES.length) return digits;
  }
  return null;
}

function rawStageNumber(stage, index) {
  return toStageNumber(stage?.stage_number ?? stage?.stage_no ?? stage?.number)
    ?? toStageNumber(stage?.stage_key ?? stage?.key ?? stage?.stage_id)
    ?? index + 1;
}

function failedStageNumber(job, byNumber) {
  const candidates = [job?.failed_stage, job?.failure_stage, job?.error?.stage, job?.error?.failed_stage];
  for (const item of candidates) {
    const number = toStageNumber(item);
    if (number) return number;
  }
  for (const [number, stage] of byNumber) {
    if (category(stage?.state ?? stage?.status) === 'FAILED') return number;
  }
  return toStageNumber(Number(job?.active_stage));
}

export function jobState(job) {
  const raw = String(job?.state || '').toUpperCase();
  return raw === 'CANCELED' ? 'CANCELLED' : raw;
}

export function resolveStages(job) {
  const list = Array.isArray(job?.stages) ? job.stages : [];
  const byNumber = new Map(list.map((stage, index) => [rawStageNumber(stage, index), stage]));
  const state = jobState(job);
  const failedAt = state === 'FAILED' ? failedStageNumber(job, byNumber) : null;
  const active = Number(job?.active_stage);
  return STAGES.map(([key, name], index) => {
    const number = index + 1;
    const raw = byNumber.get(number);
    let cat = category(raw?.state ?? raw?.status);
    if (state === 'FAILED') {
      if (number === failedAt) cat = 'FAILED';
      else if (failedAt && number > failedAt && ['PENDING', 'UNKNOWN', 'RUNNING'].includes(cat)) cat = 'NOT_RUN';
      else if (cat === 'RUNNING') cat = 'UNKNOWN';
    } else if (state === 'CANCELLED') {
      if (cat === 'RUNNING' || (number === active && ['PENDING', 'UNKNOWN'].includes(cat))) cat = 'CANCELLED';
      else if (['PENDING', 'UNKNOWN'].includes(cat)) cat = 'NOT_RUN';
    } else if (state === 'RUNNING' && number === active && ['PENDING', 'UNKNOWN'].includes(cat)) {
      cat = 'RUNNING';
    }
    const rawDuration = raw?.duration_ms;
    const duration = (rawDuration === null || rawDuration === undefined || rawDuration === '' || typeof rawDuration === 'boolean' || isWireInvalidObj(rawDuration))
      ? null
      : Number(rawDuration);
    const materializedSummary = raw?.summary_metadata !== undefined && raw?.summary_metadata !== null
      ? fallbackMaterializeTelemetry(raw.summary_metadata)
      : {value: null, hasConflict: false, hasMalformed: false, duplicateKeys: [], invalidFields: []};
    const wireIntegrity = buildStageWireIntegrity(job, raw, materializedSummary);
    const resolvedStage = {
      number,
      key,
      name: raw?.stage_name || name,
      cat,
      label: CAT_LABEL[cat],
      duration: Number.isFinite(duration) && duration >= 0 ? duration : null,
      reason: raw?.reason ?? raw?.skip_reason ?? raw?.skipped_reason ?? null,
      summary: materializedSummary.value ?? null,
      elapsed: raw?.running_elapsed_ms,
      error: raw?.error ?? raw?.error_message ?? null,
      ...(wireIntegrity ? {wireIntegrity} : {}),
    };
    return resolvedStage;
  });
}

export function currentStageIndex(job) {
  const state = jobState(job);
  const stages = resolveStages(job);
  if (state === 'FAILED') {
    const failed = stages.find((stage) => stage.cat === 'FAILED');
    return failed ? failed.number - 1 : null;
  }
  if (state === 'CANCELLED') {
    const cancelled = stages.find((stage) => stage.cat === 'CANCELLED');
    if (cancelled) return cancelled.number - 1;
    const active = Number(job?.active_stage);
    return Number.isInteger(active) && active >= 1 && active <= STAGES.length ? active - 1 : null;
  }
  if (state === 'COMPLETED') return STAGES.length - 1;
  if (state === 'RUNNING') {
    const active = Number(job?.active_stage);
    return Number.isInteger(active) && active >= 1 && active <= STAGES.length ? active - 1 : null;
  }
  return null;
}

export function errorInfo(job) {
  const raw = job?.error;
  const object = raw && typeof raw === 'object' ? raw : {};
  const steps = job?.next_steps ?? job?.actionable_steps ?? object.next_steps ?? object.actionable_steps ?? job?.hint ?? object.hint;
  return {
    code: job?.error_code ?? object.code ?? object.error_code ?? null,
    message: job?.error_message ?? object.message ?? object.error_message ?? (typeof raw === 'string' ? raw : null) ?? job?.message ?? null,
    limits: job?.resource_limits ?? job?.limits ?? object.resource_limits ?? object.limits ?? object.details ?? null,
    steps: steps ? (Array.isArray(steps) ? steps : [steps]) : [],
  };
}

export function skipNote(stage) {
  if (stage.cat !== 'SKIPPED') return stage.reason || null;
  if (stage.summary && typeof stage.summary === 'object' && stage.summary.reason) {
    return String(stage.summary.reason);
  }
  return stage.reason || null;
}

const TERMINAL_JOB_STATES = new Set(['COMPLETED', 'FAILED', 'CANCELLED']);

function jobLifecycleRank(state) {
  const norm = state === 'CANCELED' ? 'CANCELLED' : String(state || '').toUpperCase();
  if (norm === 'QUEUED') return 1;
  if (norm === 'RUNNING') return 2;
  if (TERMINAL_JOB_STATES.has(norm)) return 3;
  return 0;
}

/**
 * Extracts an explicit monotonic revision/sequence integer if provided by backend.
 * Never fabricates a sequence number when the API omits one.
 */
export function extractJobSnapshotRevision(job) {
  if (!job || typeof job !== 'object' || Array.isArray(job)) return null;
  for (const key of ['revision', 'snapshot_revision', 'version', 'sequence', 'seq', 'event_seq']) {
    const val = job[key];
    if (typeof val === 'number' && Number.isInteger(val) && val >= 0) {
      return val;
    }
  }
  return null;
}

/**
 * Extracts a valid epoch-ms timestamp from `updated_at` (or known aliases) if provided by backend.
 */
export function extractJobUpdatedAtMs(job) {
  if (!job || typeof job !== 'object' || Array.isArray(job)) return null;
  for (const key of ['updated_at', 'updated_at_utc', 'last_updated_at', 'snapshot_at', 'timestamp']) {
    const val = job[key];
    if (typeof val === 'string' && val.trim()) {
      const parsed = Date.parse(val.trim());
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return null;
}

function extractProgressVector(job) {
  const state = jobState(job);
  const rank = jobLifecycleRank(state);
  const stages = resolveStages(job);
  const completedCount = stages.filter((s) => ['COMPLETED', 'DEGRADED', 'SKIPPED'].includes(s.cat)).length;
  const activeStageIdx = currentStageIndex(job);
  const activeStageNum = activeStageIdx !== null ? activeStageIdx + 1 : (Number.isInteger(Number(job?.active_stage)) ? Number(job.active_stage) : 0);
  const rawProcessed = job?.progress?.processed_findings;
  const processedFindings = typeof rawProcessed === 'number' && Number.isInteger(rawProcessed) && rawProcessed >= 0
    ? rawProcessed
    : null;
  return {state, rank, activeStageNum, completedCount, processedFindings};
}

/**
 * Decides whether a polled snapshot for a scan job should replace the latest accepted snapshot.
 * Guarantees:
 * - Strict job_id verification (different job_id resets/accepts cleanly on job switch).
 * - Terminal snapshots (COMPLETED / FAILED / CANCELLED) are never overwritten by older non-terminal snapshots.
 * - Valid terminal transitions (FAILED / CANCELLED / COMPLETED) are never masked by clock skew on updated_at.
 * - Monotonic acceptance for same-job polling using backend revision/sequence first, then updated_at,
 *   then defensive stage/progress ordering so out-of-order/stale snapshots never move the timeline backward.
 */
export function shouldAcceptJobSnapshot(previousJob, candidateJob, {expectedJobId} = {}) {
  if (!candidateJob || typeof candidateJob !== 'object' || Array.isArray(candidateJob)) {
    return {accept: false, reason: 'INVALID_CANDIDATE'};
  }
  const candId = typeof candidateJob.job_id === 'string' ? candidateJob.job_id.trim() : '';
  const wantId = typeof expectedJobId === 'string' ? expectedJobId.trim() : '';
  if (!candId || (wantId && candId !== wantId)) {
    return {accept: false, reason: 'JOB_ID_MISMATCH'};
  }
  if (!previousJob || typeof previousJob !== 'object' || Array.isArray(previousJob)) {
    return {accept: true, reason: 'INITIAL_SNAPSHOT'};
  }
  const prevId = typeof previousJob.job_id === 'string' ? previousJob.job_id.trim() : '';
  if (!prevId || prevId !== candId) {
    return {accept: true, reason: 'NEW_JOB_IDENTITY'};
  }

  const prevVec = extractProgressVector(previousJob);
  const nextVec = extractProgressVector(candidateJob);
  const prevRev = extractJobSnapshotRevision(previousJob);
  const nextRev = extractJobSnapshotRevision(candidateJob);
  const prevTs = extractJobUpdatedAtMs(previousJob);
  const nextTs = extractJobUpdatedAtMs(candidateJob);

  const prevTerminal = TERMINAL_JOB_STATES.has(prevVec.state);
  const nextTerminal = TERMINAL_JOB_STATES.has(nextVec.state);

  // 1. Once a job is terminal (COMPLETED / FAILED / CANCELLED), never regress to non-terminal.
  if (prevTerminal && !nextTerminal) {
    return {accept: false, reason: 'TERMINAL_STATE_IMMUTABLE'};
  }

  // 2. Both terminal: only accept if strictly newer revision/timestamp or enriching missing metadata on same state.
  if (prevTerminal && nextTerminal) {
    if (prevRev !== null && nextRev !== null) {
      return nextRev > prevRev
        ? {accept: true, reason: 'NEWER_TERMINAL_REVISION'}
        : {accept: false, reason: 'STALE_TERMINAL_REVISION'};
    }
    if (prevTs !== null && nextTs !== null && nextTs < prevTs) {
      return {accept: false, reason: 'OLDER_TERMINAL_TIMESTAMP'};
    }
    if (prevVec.state !== nextVec.state) {
      return {accept: false, reason: 'CONFLICTING_TERMINAL_STATE'};
    }
    const addsScanId = !previousJob.scan_id && Boolean(candidateJob.scan_id);
    const addsE2e = (previousJob.total_e2e_duration_ms == null) && (candidateJob.total_e2e_duration_ms != null);
    if (addsScanId || addsE2e || (prevTs !== null && nextTs !== null && nextTs > prevTs)) {
      return {accept: true, reason: 'TERMINAL_METADATA_UPDATE'};
    }
    return {accept: false, reason: 'ALREADY_TERMINAL'};
  }

  // 3. Non-terminal -> Terminal (COMPLETED / FAILED / CANCELLED):
  // Never hide terminal states unless an explicit backend revision proves this snapshot is strictly older.
  if (!prevTerminal && nextTerminal) {
    if (prevRev !== null && nextRev !== null && nextRev < prevRev) {
      return {accept: false, reason: 'OLDER_REVISION'};
    }
    return {accept: true, reason: 'TERMINAL_TRANSITION'};
  }

  // 4. Both non-terminal: prefer explicit monotonic revision/sequence if backend provides it.
  if (prevRev !== null && nextRev !== null) {
    if (nextRev < prevRev) {
      return {accept: false, reason: 'OLDER_REVISION'};
    }
    if (nextRev > prevRev) {
      return {accept: true, reason: 'NEWER_REVISION'};
    }
  }

  // 5. Reject strictly older updated_at timestamp for the same active job.
  if (prevTs !== null && nextTs !== null && nextTs < prevTs) {
    return {accept: false, reason: 'OLDER_TIMESTAMP'};
  }

  // 6. Defensive monotonicity when revision/timestamp are absent or equal (prevents backward jumps).
  if (nextVec.rank < prevVec.rank) {
    return {accept: false, reason: 'STATE_REGRESSION'};
  }
  if (nextVec.rank === prevVec.rank) {
    if (nextVec.activeStageNum > 0 && prevVec.activeStageNum > 0 && nextVec.activeStageNum < prevVec.activeStageNum) {
      return {accept: false, reason: 'STAGE_REGRESSION'};
    }
    if (nextVec.activeStageNum === prevVec.activeStageNum && nextVec.completedCount < prevVec.completedCount) {
      return {accept: false, reason: 'STAGE_COMPLETION_REGRESSION'};
    }
    if (
      nextVec.activeStageNum === prevVec.activeStageNum
      && nextVec.completedCount === prevVec.completedCount
      && prevVec.processedFindings !== null
      && nextVec.processedFindings !== null
      && nextVec.processedFindings < prevVec.processedFindings
    ) {
      return {accept: false, reason: 'FINDING_PROGRESS_REGRESSION'};
    }
  }

  return {accept: true, reason: 'MONOTONIC_ADVANCE'};
}
