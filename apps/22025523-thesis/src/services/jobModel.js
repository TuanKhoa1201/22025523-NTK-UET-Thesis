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
  SKIPPED: 'Bỏ qua',
  FAILED: 'Thất bại',
  RUNNING: 'Đang thực thi',
  PENDING: 'Chưa bắt đầu',
  NOT_RUN: 'Không chạy (job đã FAILED)',
  UNKNOWN: 'Chưa có telemetry',
};

export function fmtMs(value) {
  if (value === null || value === undefined || value === '') return '-';
  const number = Number(value);
  return Number.isFinite(number)
    ? `${number.toLocaleString('vi-VN', {minimumFractionDigits: 3, maximumFractionDigits: 3})} ms`
    : '-';
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
  if (text.includes('FAIL') || text === 'ERROR') return 'FAILED';
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
  return String(job?.state || '').toUpperCase();
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
    } else if (state === 'RUNNING' && number === active && ['PENDING', 'UNKNOWN'].includes(cat)) {
      cat = 'RUNNING';
    }
    const duration = raw?.duration_ms === null || raw?.duration_ms === undefined ? null : Number(raw.duration_ms);
    return {
      number,
      key,
      name: raw?.stage_name || name,
      cat,
      label: CAT_LABEL[cat],
      duration: Number.isFinite(duration) ? duration : null,
      reason: raw?.reason ?? raw?.skip_reason ?? raw?.skipped_reason ?? null,
      summary: raw?.summary_metadata ?? null,
      elapsed: raw?.running_elapsed_ms,
      error: raw?.error ?? raw?.error_message ?? null,
    };
  });
}

export function currentStageIndex(job) {
  const state = jobState(job);
  const stages = resolveStages(job);
  if (state === 'FAILED') {
    const failed = stages.find((stage) => stage.cat === 'FAILED');
    return failed ? failed.number - 1 : null;
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
