import {TIMELINE_MODES, formatDurationMs} from './remotionEngine';

const WIRE_INTEGRITY_REGISTRY_SYM = Symbol.for('22025523.restJsonWireIntegrity.v1');

function isWireInvalidSentinel(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) && value.__wireInvalid === true);
}

const FALLBACK_STRICT_INT_KEY_RE = /(?:^|_)(?:count|total|checked|findings|files|scanned|ignored|inventory|matched|invalid|not_verified|unverified|open|pages|page|page_size|limit|citations_matched|citations_invalid|citations_not_verified|citations_total)$/i;

function isWireInvalidIntAnomaly(key, wireIntErr, rawVal) {
  if (!wireIntErr) return false;
  const reg = globalThis[WIRE_INTEGRITY_REGISTRY_SYM];
  if (typeof reg?.isWireInvalidIntAnomaly === 'function') {
    return reg.isWireInvalidIntAnomaly(key, wireIntErr, rawVal);
  }
  if (FALLBACK_STRICT_INT_KEY_RE.test(key)) return true;
  if (wireIntErr.reason === 'UNSAFE_INTEGER_WIRE_NUMBER') return true;
  if (wireIntErr.reason === 'NON_INTEGER_WIRE_NUMBER' && typeof rawVal === 'number' && Number.isSafeInteger(rawVal)) {
    return true;
  }
  return false;
}

function getWireMaxScanDepth() {
  const max = globalThis[WIRE_INTEGRITY_REGISTRY_SYM]?.WIRE_MAX_SCAN_DEPTH;
  return Number.isSafeInteger(max) && max > 0 ? max : 128;
}

function inspectRawSummaryWireSubtree(root, depth = 0, seen = new Set()) {
  const res = {scannerError: false, hasConflict: false, hasMalformed: false};
  if (!root || typeof root !== 'object') return res;
  if (depth > getWireMaxScanDepth()) {
    return {scannerError: true, hasConflict: false, hasMalformed: true};
  }
  if (seen.has(root)) return res;
  seen.add(root);
  if (isWireInvalidSentinel(root)) {
    if (root.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY') res.hasConflict = true;
    else res.hasMalformed = true;
    return res;
  }
  const integ = getWireObjectIntegrity(root);
  if (integ) {
    if (integ.scannerError || integ.depthExceeded || integ.hasDepthExceededSubtree) {
      res.scannerError = true;
      res.hasMalformed = true;
    }
    if (integ.hasConflictingDuplicateKeyInSubtree) res.hasConflict = true;
    else if (integ.hasDuplicateKeyInSubtree) res.hasMalformed = true;
    if (integ.duplicateKeys instanceof Map) {
      for (const info of integ.duplicateKeys.values()) {
        if (info?.conflicting) res.hasConflict = true;
        else res.hasMalformed = true;
      }
    }
    if (integ.invalidIntFields instanceof Map) {
      for (const [k, err] of integ.invalidIntFields.entries()) {
        if (isWireInvalidIntAnomaly(k, err, root[k])) res.hasMalformed = true;
      }
    }
    const mat = integ.materialized;
    if (mat && typeof mat === 'object') {
      if (mat.scannerError === true) res.scannerError = true;
      if (mat.hasConflict === true) res.hasConflict = true;
      if (mat.hasMalformed === true) res.hasMalformed = true;
    }
  }
  if (Array.isArray(root)) {
    for (let i = 0; i < root.length; i += 1) {
      const child = inspectRawSummaryWireSubtree(root[i], depth + 1, seen);
      if (child.scannerError) res.scannerError = true;
      if (child.hasConflict) res.hasConflict = true;
      if (child.hasMalformed) res.hasMalformed = true;
    }
    return res;
  }
  const keys = Object.keys(root);
  for (let i = 0; i < keys.length; i += 1) {
    const k = keys[i];
    if (k === '__wireIntegrity') continue;
    const child = inspectRawSummaryWireSubtree(root[k], depth + 1, seen);
    if (child.scannerError) res.scannerError = true;
    if (child.hasConflict) res.hasConflict = true;
    if (child.hasMalformed) res.hasMalformed = true;
  }
  return res;
}

function getWireObjectIntegrity(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const reg = globalThis[WIRE_INTEGRITY_REGISTRY_SYM];
  if (typeof reg?.getWireObjectIntegrity === 'function') return reg.getWireObjectIntegrity(obj);
  const weak = reg?.objects?.get(obj) || null;
  const mat = !Array.isArray(obj) && obj.__wireIntegrity && typeof obj.__wireIntegrity === 'object' ? obj.__wireIntegrity : null;
  if (!weak && !mat) return null;
  return {
    scannerError: Boolean(weak?.scannerError || mat?.scannerError),
    depthExceeded: Boolean(weak?.depthExceeded),
    hasDepthExceededSubtree: Boolean(weak?.hasDepthExceededSubtree || weak?.depthExceeded),
    duplicateKeys: weak?.duplicateKeys || null,
    invalidIntFields: weak?.invalidIntFields || null,
    materialized: mat,
    hasDuplicateKeyInSubtree: Boolean(weak?.hasDuplicateKeyInSubtree || mat?.hasConflict),
    hasConflictingDuplicateKeyInSubtree: Boolean(weak?.hasConflictingDuplicateKeyInSubtree || mat?.hasConflict),
  };
}

function getWireStageAnomaly(stage) {
  if (!stage || typeof stage !== 'object') return null;
  const fromWeak = globalThis[WIRE_INTEGRITY_REGISTRY_SYM]?.stages?.get(stage) || null;
  const fromMat = stage.wireIntegrity && typeof stage.wireIntegrity === 'object' ? stage.wireIntegrity : null;
  if (!fromWeak && !fromMat) return null;
  return {
    scannerError: Boolean(fromWeak?.scannerError || fromMat?.scannerError),
    hasConflict: Boolean(fromWeak?.conflictingSummaryMetadata || fromMat?.hasConflict),
    hasMalformed: Boolean(fromWeak?.duplicateSummaryMetadata || fromMat?.hasMalformed),
    duplicateStagesContainer: Boolean(fromMat?.duplicateStagesContainer),
    conflictingStagesContainer: Boolean(fromMat?.conflictingStagesContainer),
    duplicateSummaryMetadata: Boolean(fromWeak?.duplicateSummaryMetadata || fromMat?.duplicateSummaryMetadata),
    conflictingSummaryMetadata: Boolean(fromWeak?.conflictingSummaryMetadata || fromMat?.conflictingSummaryMetadata),
    reasons: Array.isArray(fromMat?.reasons) ? fromMat.reasons : [],
  };
}

function getWireDuplicateKeyInfo(obj, key) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const reg = globalThis[WIRE_INTEGRITY_REGISTRY_SYM];
  if (typeof reg?.getWireDuplicateKeyInfo === 'function') return reg.getWireDuplicateKeyInfo(obj, key);
  const meta = reg?.objects?.get(obj);
  if (meta?.scannerError) return {count: 2, conflicting: true, scannerError: true};
  if (meta?.duplicateKeys?.get(key)) return meta.duplicateKeys.get(key);
  const mat = obj.__wireIntegrity && typeof obj.__wireIntegrity === 'object' ? obj.__wireIntegrity : null;
  if (mat?.scannerError) return {count: 2, conflicting: true, scannerError: true};
  if (mat?.duplicateKeys && typeof mat.duplicateKeys === 'object' && !Array.isArray(mat.duplicateKeys) && Object.hasOwn(mat.duplicateKeys, key)) {
    return {count: Number(mat.duplicateKeys[key]?.count) || 2, conflicting: Boolean(mat.duplicateKeys[key]?.conflicting)};
  }
  const val = Object.hasOwn(obj, key) ? obj[key] : undefined;
  if (isWireInvalidSentinel(val) && (val.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY' || val.kind === 'DUPLICATE_WIRE_KEY')) {
    return {count: 2, conflicting: val.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY'};
  }
  return null;
}

function readStrictWireSafeInt(obj, key) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return {present: false, valid: true, value: null, conflict: false, malformed: false, reason: ''};
  }
  if (isWireInvalidSentinel(obj)) {
    const isConflict = obj.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY';
    return {present: true, valid: false, value: null, conflict: isConflict, malformed: !isConflict, reason: String(obj.reason || obj.kind || 'WIRE_INVALID_CONTAINER')};
  }
  const reg = globalThis[WIRE_INTEGRITY_REGISTRY_SYM];
  if (typeof reg?.readStrictWireSafeInt === 'function') return reg.readStrictWireSafeInt(obj, key);
  const wire = reg?.objects?.get(obj);
  const mat = obj.__wireIntegrity && typeof obj.__wireIntegrity === 'object' ? obj.__wireIntegrity : null;
  if (wire?.scannerError || wire?.depthExceeded || mat?.scannerError) {
    return {present: true, valid: false, value: null, conflict: false, malformed: true, reason: 'WIRE_SCANNER_ERROR'};
  }
  const dup = getWireDuplicateKeyInfo(obj, key);
  if (dup) {
    return {
      present: true,
      valid: false,
      value: null,
      conflict: Boolean(dup.conflicting),
      malformed: !dup.conflicting,
      reason: dup.conflicting ? 'DUPLICATE_CONFLICTING_WIRE_KEY' : 'DUPLICATE_WIRE_KEY',
    };
  }
  const wireInvalid = wire?.invalidIntFields?.get(key);
  if (wireInvalid) {
    return {present: true, valid: false, value: null, conflict: false, malformed: true, reason: wireInvalid.reason, raw: wireInvalid.raw};
  }
  if (!Object.hasOwn(obj, key)) {
    return {present: false, valid: true, value: null, conflict: false, malformed: false, reason: ''};
  }
  const value = obj[key];
  if (isWireInvalidSentinel(value)) {
    const isConflict = value.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY';
    return {
      present: true,
      valid: false,
      value: null,
      conflict: isConflict,
      malformed: !isConflict,
      reason: String(value.reason || value.kind || 'INVALID_WIRE_NUMBER'),
      ...(value.raw !== undefined ? {raw: String(value.raw)} : {}),
    };
  }
  if (value === undefined || value === null) {
    return {present: false, valid: true, value: null, conflict: false, malformed: false, reason: ''};
  }
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
    return {present: true, valid: false, value: null, conflict: false, malformed: true, reason: 'INVALID_SAFE_INTEGER'};
  }
  return {present: true, valid: true, value, conflict: false, malformed: false, reason: ''};
}

const DONE = new Set(['COMPLETED', 'COMPLETE', 'SUCCESS', 'SUCCEEDED', 'DONE']);
const DEGRADED = new Set(['DEGRADED', 'PARTIAL']);
const ACTIVE = new Set(['RUNNING', 'IN_PROGRESS', 'ACTIVE']);
const TOTAL_STAGES = 6;

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

function strictNonNegativeInt(value) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) return null;
  return value === 0 ? 0 : value;
}

export function isLiveSessionReady(live) {
  return Boolean(
    live?.resultsReady === true &&
    String(live?.stage || '').toUpperCase() === 'COMPLETED' &&
    String(live?.state || '').toUpperCase() === 'COMPLETED',
  );
}

export function backendStageStatus(index, live) {
  const stages = Array.isArray(live?.stages) ? live.stages : [];
  const stage = stages.find((item, itemIndex) => {
    const value = Number(item?.stage_number ?? item?.stage_no ?? item?.number);
    return Number.isInteger(value) ? value === index + 1 : itemIndex === index;
  });
  const status = String(stage?.state ?? stage?.status ?? '').toUpperCase();
  const jobState = String(live?.state || '').toUpperCase();
  const progress = String(live?.stage || '').toUpperCase();
  const hasDuration = typeof stage?.duration_ms === 'number' && Number.isFinite(stage.duration_ms) && stage.duration_ms >= 0;
  const measured = hasDuration
    ? ` · ${formatDurationMs(stage.duration_ms, {compact: true})}`
    : '';

  if (status.includes('FAIL')) return `Thất bại${measured}`;
  if (status.includes('CANCEL')) return `Đã hủy${measured}`;
  if (jobState === 'FAILED') {
    const failedAt = Number(live?.activeStage);
    if (index + 1 === failedAt) return `Thất bại${measured}`;
    if (index === TOTAL_STAGES - 1 && !isLiveSessionReady(live)) return 'Phiên không hoàn tất';
    if (index + 1 > failedAt && !status.includes('SKIP') && !DONE.has(status) && !DEGRADED.has(status)) return 'Không chạy (phiên đã thất bại)';
  }
  if (jobState === 'CANCELLED' || jobState === 'CANCELED') {
    const cancelledAt = Number(live?.activeStage);
    if (index + 1 === cancelledAt && !DONE.has(status) && !DEGRADED.has(status)) return `Đã hủy${measured}`;
    if (!DONE.has(status) && !DEGRADED.has(status) && !status.includes('SKIP')) return 'Không chạy (phiên đã hủy)';
  }
  if (status.includes('SKIP')) {
    const reason = stage?.reason ?? stage?.summary_metadata?.reason;
    return `Bỏ qua${reason ? ` · ${reason}` : ''}`;
  }

  if (index === TOTAL_STAGES - 1 && !isLiveSessionReady(live)) {
    if (progress === 'RESULTS_ERROR') return 'Chưa thể xác nhận kết quả';
    if (progress === 'LOADING_RESULTS' || jobState === 'COMPLETED') return 'Đang xác nhận kết quả';
    if (ACTIVE.has(status) || Number(live?.activeStage) === TOTAL_STAGES) return 'Đang ghi nhận SQLite';
    return 'Chưa bắt đầu';
  }

  if (DEGRADED.has(status)) {
    return hasDuration ? `Hoàn tất (có hạ cấp)${measured}` : 'Hoàn tất (có hạ cấp)';
  }
  if (DONE.has(status)) return `Hoàn thành${measured}`;
  if (index === TOTAL_STAGES - 1 && isLiveSessionReady(live)) return `Hoàn thành${measured}`;
  if (ACTIVE.has(status) || (jobState === 'RUNNING' && Number(live?.activeStage) === index + 1)) return 'Đang thực thi';
  if (['QUEUED', 'PENDING', 'NOT_STARTED'].includes(status) || jobState === 'QUEUED') return 'Chưa bắt đầu';
  return 'Chưa có telemetry';
}

const CITATION_CHECK_SPECS = Object.freeze([
  {key: 'path', label: 'PATH', y: 74},
  {key: 'line', label: 'LINE', y: 104},
  {key: 'quote', label: 'QUOTE', y: 134},
  {key: 'sha256', label: 'SHA-256', y: 164},
]);

function normalizeSingleCheckEvidence(raw, {allowBoolean = true} = {}) {
  if (raw === undefined || raw === null) return null;
  if (typeof raw === 'boolean') {
    return allowBoolean ? (raw ? 'MATCHED' : 'INVALID') : null;
  }
  if (typeof raw !== 'string') return null;
  const code = raw.trim().toUpperCase();
  if (!code) return null;
  if (['MATCHED', 'MATCH', 'PASS', 'PASSED', 'VERIFIED', 'VALID', 'OK'].includes(code)) return 'MATCHED';
  if (['INVALID', 'MISMATCH', 'FAILED', 'FAIL', 'ERROR'].includes(code)) return 'INVALID';
  if (['MIXED', 'PARTIAL', 'DEGRADED'].includes(code)) return 'MIXED';
  if (['NOT_VERIFIED', 'NONE', 'UNVERIFIED', 'MISSING'].includes(code)) return 'NOT_VERIFIED';
  if (['CHECKING', 'RUNNING', 'IN_PROGRESS', 'PENDING'].includes(code)) return 'CHECKING';
  if (['SKIPPED'].includes(code)) return 'SKIPPED';
  return null;
}

function resolveStrictCountGroup(candidates) {
  const validValues = [];
  const invalidFields = [];
  let hasAnyPresent = false;
  let hasWireConflict = false;
  for (let i = 0; i < candidates.length; i += 1) {
    const {name, value, sourceObj, sourceKey} = candidates[i];
    if (sourceObj && sourceKey) {
      const wireCheck = readStrictWireSafeInt(sourceObj, sourceKey);
      if (!wireCheck.present) continue;
      hasAnyPresent = true;
      if (wireCheck.valid && wireCheck.value !== null) {
        validValues.push({name, value: wireCheck.value});
      } else {
        if (wireCheck.conflict) hasWireConflict = true;
        invalidFields.push(name);
      }
      continue;
    }
    if (value === undefined || value === null) continue;
    hasAnyPresent = true;
    const parsed = strictNonNegativeInt(value);
    if (parsed !== null) {
      validValues.push({name, value: parsed});
    } else {
      invalidFields.push(name);
    }
  }
  if (hasWireConflict) {
    return {
      value: null,
      hasAnyPresent,
      conflict: true,
      malformed: invalidFields.length > 0,
      invalidFields,
    };
  }
  if (validValues.length === 0) {
    return {
      value: null,
      hasAnyPresent,
      conflict: false,
      malformed: invalidFields.length > 0,
      invalidFields,
    };
  }
  const unique = [...new Set(validValues.map((entry) => entry.value))];
  if (unique.length > 1) {
    return {
      value: null,
      hasAnyPresent,
      conflict: true,
      malformed: invalidFields.length > 0,
      invalidFields,
    };
  }
  return {
    value: unique[0],
    hasAnyPresent,
    conflict: false,
    malformed: invalidFields.length > 0,
    invalidFields,
  };
}

function resolveStrictOverallGroup(candidates) {
  const validValues = [];
  const invalidFields = [];
  let hasAnyPresent = false;
  let hasWireConflict = false;
  for (let i = 0; i < candidates.length; i += 1) {
    const {name, value, sourceObj, sourceKey} = candidates[i];
    if (sourceObj && sourceKey) {
      const dup = getWireDuplicateKeyInfo(sourceObj, sourceKey);
      if (dup) {
        hasAnyPresent = true;
        if (dup.conflicting) hasWireConflict = true;
        invalidFields.push(name);
        continue;
      }
    }
    if (value === undefined || value === null) continue;
    hasAnyPresent = true;
    const parsed = normalizeSingleCheckEvidence(value, {allowBoolean: false});
    if (parsed) {
      validValues.push({name, value: parsed});
    } else {
      invalidFields.push(name);
    }
  }
  if (hasWireConflict) {
    return {
      value: null,
      hasAnyPresent,
      conflict: true,
      malformed: invalidFields.length > 0,
      invalidFields,
    };
  }
  if (validValues.length === 0) {
    return {
      value: null,
      hasAnyPresent,
      conflict: false,
      malformed: invalidFields.length > 0,
      invalidFields,
    };
  }
  const unique = [...new Set(validValues.map((entry) => entry.value))];
  if (unique.length > 1) {
    return {
      value: null,
      hasAnyPresent,
      conflict: true,
      malformed: invalidFields.length > 0,
      invalidFields,
    };
  }
  return {
    value: unique[0],
    hasAnyPresent,
    conflict: false,
    malformed: invalidFields.length > 0,
    invalidFields,
  };
}

function checkPresentationFromStatus(status) {
  switch (status) {
    case 'PREVIEW':
      return {status, badgeText: 'MINH HỌA', tone: 'neutral', isVerifiedMatch: false};
    case 'MATCHED':
      return {status, badgeText: 'MATCH ✓', tone: 'green', isVerifiedMatch: true};
    case 'INVALID':
      return {status, badgeText: 'INVALID ✕', tone: 'red', isVerifiedMatch: false};
    case 'CONFLICT':
      return {status, badgeText: 'MÂU THUẪN', tone: 'red', isVerifiedMatch: false};
    case 'MALFORMED':
      return {status, badgeText: 'DỮ LIỆU LỖI', tone: 'amber', isVerifiedMatch: false};
    case 'MIXED':
      return {status, badgeText: 'HỖN HỢP', tone: 'amber', isVerifiedMatch: false};
    case 'NOT_VERIFIED':
      return {status, badgeText: 'CHƯA XÁC MINH', tone: 'amber', isVerifiedMatch: false};
    case 'CHECKING':
      return {status, badgeText: 'ĐANG KIỂM TRA', tone: 'blue', isVerifiedMatch: false};
    case 'SKIPPED':
      return {status, badgeText: 'BỎ QUA', tone: 'neutral', isVerifiedMatch: false};
    case 'CANCELLED':
      return {status, badgeText: 'ĐÃ HỦY', tone: 'neutral', isVerifiedMatch: false};
    case 'FAILED':
      return {status, badgeText: 'THẤT BẠI', tone: 'red', isVerifiedMatch: false};
    case 'AGGREGATE_MATCHED':
      return {status, badgeText: 'ĐÃ ĐỐI CHIẾU', tone: 'green', isVerifiedMatch: false};
    default:
      return {status: 'NO_DATA', badgeText: 'CHƯA CÓ DỮ LIỆU', tone: 'neutral', isVerifiedMatch: false};
  }
}

/**
 * Resolves fail-closed Stage 05 citation validation telemetry strictly from backend evidence.
 * - PREVIEW mode is explicitly marked illustrative and never presents verified MATCH ✓ badges.
 * - LIVE and PLAYBACK modes never infer MATCH ✓ or ALL_MATCHED from animation state,
 *   reducedMotion, stage COMPLETED, partial counts, or contradictory signals.
 * - Cross-checks per-layer checks, aggregate counts, and overall status together:
 *   - INVALID / NOT_VERIFIED evidence is never masked by an aggregate MATCHED claim.
 *   - Missing required aggregate fields (matched, invalid, not_verified, total) are NEVER
 *     defaulted to 0 or promoted to ALL_MATCHED.
 *   - Missing layers inside a partial `checks` / `citation_checks` map stay NO_DATA instead of
 *     being filled with AGGREGATE_MATCHED.
 */
export function resolveStage05CitationTelemetry({
  mode = TIMELINE_MODES.PREVIEW,
  stage = null,
  liveCounts = null,
} = {}) {
  if (mode === TIMELINE_MODES.PREVIEW) {
    return {
      mode: TIMELINE_MODES.PREVIEW,
      isIllustrative: true,
      hasBackendEvidence: false,
      aggregateStatus: 'PREVIEW',
      aggregateLabel: 'Minh họa quy trình kiểm chứng trích dẫn (PREVIEW)',
      aggregateNote: 'Sơ đồ minh họa các lớp đối chiếu PATH / LINE / QUOTE / SHA-256 — chưa phải kết quả kiểm chứng thực tế.',
      counts: null,
      checks: CITATION_CHECK_SPECS.map((spec) => ({
        ...spec,
        ...checkPresentationFromStatus('PREVIEW'),
      })),
    };
  }

  const rawSummary = stage?.summary;
  const stageWireAnomaly = getWireStageAnomaly(stage);
  const stageRootWire = getWireObjectIntegrity(stage);
  const metaWire = isPlainObject(rawSummary) ? getWireObjectIntegrity(rawSummary) : null;
  const rawSummaryTree = isPlainObject(rawSummary) ? inspectRawSummaryWireSubtree(rawSummary) : null;
  const rawSummaryIsWireInvalid = isWireInvalidSentinel(rawSummary);
  const summaryWireConflict = Boolean(
    stageWireAnomaly?.hasConflict
    || stageWireAnomaly?.conflictingSummaryMetadata
    || stageWireAnomaly?.conflictingStagesContainer
    || metaWire?.materialized?.hasConflict
    || rawSummaryTree?.hasConflict
    || (rawSummaryIsWireInvalid && rawSummary.kind === 'DUPLICATE_CONFLICTING_WIRE_KEY'),
  );
  const summaryMalformed = Boolean(
    (rawSummary !== undefined && rawSummary !== null && (!isPlainObject(rawSummary) || rawSummaryIsWireInvalid))
    || stageWireAnomaly?.scannerError
    || stageRootWire?.scannerError
    || metaWire?.scannerError
    || rawSummaryTree?.scannerError
    || (stageWireAnomaly?.hasMalformed && !stageWireAnomaly?.hasConflict)
    || (stageWireAnomaly?.duplicateSummaryMetadata && !stageWireAnomaly?.conflictingSummaryMetadata)
    || (stageWireAnomaly?.duplicateStagesContainer && !stageWireAnomaly?.conflictingStagesContainer)
    || (metaWire?.materialized?.hasMalformed && !metaWire?.materialized?.hasConflict)
    || (rawSummaryTree?.hasMalformed && !rawSummaryTree?.hasConflict),
  );
  const meta = isPlainObject(rawSummary) && !rawSummaryIsWireInvalid ? rawSummary : {};

  // 1. Parse per-layer checks from `checks` and/or `citation_checks` without hiding mismatches, bad types, or duplicate wire keys.
  const rawChecksA = Object.hasOwn(meta, 'checks') ? meta.checks : undefined;
  const rawChecksB = Object.hasOwn(meta, 'citation_checks') ? meta.citation_checks : undefined;
  const dupChecksA = getWireDuplicateKeyInfo(meta, 'checks');
  const dupChecksB = getWireDuplicateKeyInfo(meta, 'citation_checks');
  const checksContainerWireConflict = Boolean(dupChecksA?.conflicting || dupChecksB?.conflicting);
  const malformedChecksContainer = Boolean(
    (rawChecksA !== undefined && rawChecksA !== null && !isPlainObject(rawChecksA))
    || (rawChecksB !== undefined && rawChecksB !== null && !isPlainObject(rawChecksB))
    || (dupChecksA && !dupChecksA.conflicting)
    || (dupChecksB && !dupChecksB.conflicting),
  );
  const checkSources = [rawChecksA, rawChecksB].filter(isPlainObject);

  const explicitCheckMap = {};
  const malformedCheckLayers = [];
  const conflictingCheckLayers = [];
  let hasExplicitPerCheck = false;

  for (const spec of CITATION_CHECK_SPECS) {
    const keys = spec.key === 'sha256' ? ['sha256', 'sha-256', 'hash', 'integrity'] : [spec.key];
    const parsedValues = [];
    let sawMalformed = false;
    let sawWireConflict = false;
    for (const src of checkSources) {
      for (const k of keys) {
        const dupLayer = getWireDuplicateKeyInfo(src, k);
        if (dupLayer) {
          if (dupLayer.conflicting) sawWireConflict = true;
          else sawMalformed = true;
          continue;
        }
        if (!Object.hasOwn(src, k)) continue;
        const rawVal = src[k];
        if (rawVal === undefined || rawVal === null) continue;
        const norm = normalizeSingleCheckEvidence(rawVal, {allowBoolean: true});
        if (norm) {
          parsedValues.push(norm);
        } else {
          sawMalformed = true;
        }
      }
    }
    const uniqueVals = [...new Set(parsedValues)];
    if (sawWireConflict || uniqueVals.length > 1) {
      explicitCheckMap[spec.key] = 'CONFLICT';
      conflictingCheckLayers.push(spec.label);
      hasExplicitPerCheck = true;
    } else if (sawMalformed && uniqueVals.length === 0) {
      explicitCheckMap[spec.key] = 'MALFORMED';
      malformedCheckLayers.push(spec.label);
      hasExplicitPerCheck = true;
    } else if (sawMalformed && uniqueVals.length === 1) {
      explicitCheckMap[spec.key] = uniqueVals[0] === 'INVALID' ? 'INVALID' : 'MALFORMED';
      malformedCheckLayers.push(spec.label);
      hasExplicitPerCheck = true;
    } else if (uniqueVals.length === 1) {
      explicitCheckMap[spec.key] = uniqueVals[0];
      hasExplicitPerCheck = true;
    }
  }

  // 2. Parse aggregate counts strictly (enforcing REST-boundary wire precision & duplicate-key checks;
  //    never defaulting missing or malformed fields to 0).
  const hasLiveCitationCounts = isPlainObject(liveCounts) && (
    liveCounts.matchedCitations !== undefined
    || liveCounts.invalidCitations !== undefined
    || liveCounts.notVerifiedCitations !== undefined
  );
  const matchedGroup = resolveStrictCountGroup([
    {name: 'matched_count', value: meta.matched_count, sourceObj: meta, sourceKey: 'matched_count'},
    {name: 'matched_citation_count', value: meta.matched_citation_count, sourceObj: meta, sourceKey: 'matched_citation_count'},
    {name: 'citations_matched', value: meta.citations_matched, sourceObj: meta, sourceKey: 'citations_matched'},
    ...(hasLiveCitationCounts ? [{name: 'liveCounts.matchedCitations', value: liveCounts.matchedCitations, sourceObj: liveCounts, sourceKey: 'matchedCitations'}] : []),
  ]);
  const invalidGroup = resolveStrictCountGroup([
    {name: 'invalid_count', value: meta.invalid_count, sourceObj: meta, sourceKey: 'invalid_count'},
    {name: 'invalid_citation_count', value: meta.invalid_citation_count, sourceObj: meta, sourceKey: 'invalid_citation_count'},
    {name: 'citations_invalid', value: meta.citations_invalid, sourceObj: meta, sourceKey: 'citations_invalid'},
    ...(hasLiveCitationCounts ? [{name: 'liveCounts.invalidCitations', value: liveCounts.invalidCitations, sourceObj: liveCounts, sourceKey: 'invalidCitations'}] : []),
  ]);
  const notVerifiedGroup = resolveStrictCountGroup([
    {name: 'not_verified_count', value: meta.not_verified_count, sourceObj: meta, sourceKey: 'not_verified_count'},
    {name: 'unverified_citation_count', value: meta.unverified_citation_count, sourceObj: meta, sourceKey: 'unverified_citation_count'},
    {name: 'citations_not_verified', value: meta.citations_not_verified, sourceObj: meta, sourceKey: 'citations_not_verified'},
    ...(hasLiveCitationCounts ? [{name: 'liveCounts.notVerifiedCitations', value: liveCounts.notVerifiedCitations, sourceObj: liveCounts, sourceKey: 'notVerifiedCitations'}] : []),
  ]);
  const totalGroup = resolveStrictCountGroup([
    {name: 'total_checked', value: meta.total_checked, sourceObj: meta, sourceKey: 'total_checked'},
    {name: 'total_findings', value: meta.total_findings, sourceObj: meta, sourceKey: 'total_findings'},
    {name: 'citations_total', value: meta.citations_total, sourceObj: meta, sourceKey: 'citations_total'},
    ...(hasLiveCitationCounts ? [{name: 'liveCounts.total', value: liveCounts.total, sourceObj: liveCounts, sourceKey: 'total'}] : []),
  ]);

  const matchedCount = matchedGroup.value;
  const invalidCount = invalidGroup.value;
  const notVerifiedCount = notVerifiedGroup.value;
  const totalChecked = totalGroup.value;
  const hasAnyCountSignal = (
    matchedGroup.hasAnyPresent
    || invalidGroup.hasAnyPresent
    || notVerifiedGroup.hasAnyPresent
    || totalGroup.hasAnyPresent
  );
  const hasValidCounts = (
    matchedCount !== null
    || invalidCount !== null
    || notVerifiedCount !== null
    || totalChecked !== null
  );
  const malformedCountFields = [
    ...matchedGroup.invalidFields,
    ...invalidGroup.invalidFields,
    ...notVerifiedGroup.invalidFields,
    ...totalGroup.invalidFields,
  ];
  const hasMalformedCounts = malformedCountFields.length > 0;
  const hasCountAliasConflict = (
    matchedGroup.conflict
    || invalidGroup.conflict
    || notVerifiedGroup.conflict
    || totalGroup.conflict
  );

  let hasCountMathConflict = false;
  let hasCountSumOverflow = false;
  if (hasValidCounts) {
    const knownSumBig = BigInt(matchedCount ?? 0) + BigInt(invalidCount ?? 0) + BigInt(notVerifiedCount ?? 0);
    if (knownSumBig > MAX_SAFE_BIGINT) {
      hasCountSumOverflow = true;
    }
    if (totalChecked !== null) {
      const totalBig = BigInt(totalChecked);
      if (knownSumBig > totalBig) {
        hasCountMathConflict = true;
      } else if (
        matchedCount !== null
        && invalidCount !== null
        && notVerifiedCount !== null
        && knownSumBig !== totalBig
      ) {
        hasCountMathConflict = true;
      } else if (totalChecked === 0 && knownSumBig > 0n) {
        hasCountMathConflict = true;
      }
    }
  }

  const effectiveMalformedCounts = hasMalformedCounts || hasCountSumOverflow;

  let countsStatus = null;
  if (hasAnyCountSignal) {
    if (hasCountAliasConflict || hasCountMathConflict) {
      countsStatus = 'CONFLICT';
    } else if (effectiveMalformedCounts) {
      countsStatus = 'MALFORMED';
    } else if ((invalidCount ?? 0) > 0 && (matchedCount ?? 0) > 0) {
      countsStatus = 'MIXED';
    } else if ((invalidCount ?? 0) > 0) {
      countsStatus = 'INVALID';
    } else if ((matchedCount ?? 0) > 0 && (notVerifiedCount ?? 0) > 0) {
      countsStatus = 'MIXED';
    } else if ((matchedCount ?? 0) > 0 && totalChecked !== null && matchedCount < totalChecked) {
      countsStatus = 'MIXED';
    } else if (
      matchedCount !== null
      && matchedCount > 0
      && invalidCount === 0
      && notVerifiedCount === 0
      && totalChecked !== null
      && matchedCount === totalChecked
    ) {
      countsStatus = 'ALL_MATCHED';
    } else if ((matchedCount ?? 0) > 0) {
      countsStatus = 'PARTIAL';
    } else if ((notVerifiedCount ?? 0) > 0) {
      countsStatus = 'NOT_VERIFIED';
    } else if (totalChecked === 0) {
      countsStatus = 'NO_FINDINGS';
    } else {
      countsStatus = 'PARTIAL';
    }
  }

  // 3. Parse overall status strictly.
  const overallGroup = resolveStrictOverallGroup([
    {name: 'citation_status', value: meta.citation_status, sourceObj: meta, sourceKey: 'citation_status'},
    {name: 'citation_check', value: meta.citation_check, sourceObj: meta, sourceKey: 'citation_check'},
    {name: 'overall_status', value: meta.overall_status, sourceObj: meta, sourceKey: 'overall_status'},
  ]);
  const explicitOverall = overallGroup.value;

  // 4. Cross-check ALL signals together (fail-closed against contradictions, malformed data, and partial gaps).
  const layerValues = Object.values(explicitCheckMap);
  const perLayerHasInvalid = layerValues.includes('INVALID');
  const perLayerHasNotVerified = layerValues.includes('NOT_VERIFIED');
  const perLayerHasMixed = layerValues.includes('MIXED');
  const perLayerHasChecking = layerValues.includes('CHECKING');
  const perLayerHasSkipped = layerValues.includes('SKIPPED');
  const perLayerHasMatched = layerValues.includes('MATCHED');
  const perLayerHasConflict = conflictingCheckLayers.length > 0;
  const perLayerHasMalformed = malformedChecksContainer || malformedCheckLayers.length > 0;
  const perLayerCompleteAllMatched = (
    !perLayerHasMalformed
    && !perLayerHasConflict
    && layerValues.length === CITATION_CHECK_SPECS.length
    && layerValues.every((st) => st === 'MATCHED')
  );
  const perLayerHasMissing = hasExplicitPerCheck && Object.keys(explicitCheckMap).length < CITATION_CHECK_SPECS.length;

  const overallClaimsMatched = explicitOverall === 'MATCHED';
  const countsClaimAllMatched = countsStatus === 'ALL_MATCHED';
  const countsClaimZeroInvalid = invalidCount === 0;
  const countsClaimZeroNotVerified = notVerifiedCount === 0;
  const countsClaimNoFindings = countsStatus === 'NO_FINDINGS';

  const conflictReasons = [];
  if (summaryWireConflict || checksContainerWireConflict) {
    conflictReasons.push('Phản hồi JSON chứa khóa trùng lặp gây mâu thuẫn tại biên REST.');
  }
  if (perLayerHasConflict) {
    conflictReasons.push(`Các trường lớp đối chiếu mâu thuẫn nhau (${conflictingCheckLayers.join(', ')}).`);
  }
  if (hasCountAliasConflict || hasCountMathConflict) {
    conflictReasons.push('Các số liệu tổng hợp kiểm chứng trích dẫn mâu thuẫn nhau về mặt số học.');
  }
  if (overallGroup.conflict) {
    conflictReasons.push('Các trường trạng thái tổng hợp trích dẫn (citation_status / overall_status) mâu thuẫn nhau.');
  }
  if (overallClaimsMatched && (perLayerHasInvalid || perLayerHasNotVerified || perLayerHasMixed || perLayerHasChecking || perLayerHasSkipped || perLayerHasMalformed)) {
    conflictReasons.push('Trạng thái tổng hợp báo MATCHED nhưng bằng chứng từng lớp có mục không khớp hoặc chưa hợp lệ.');
  }
  if (overallClaimsMatched && (['INVALID', 'MIXED', 'NOT_VERIFIED', 'NO_FINDINGS', 'CONFLICT', 'MALFORMED'].includes(countsStatus) || matchedCount === 0)) {
    conflictReasons.push('Trạng thái tổng hợp báo MATCHED nhưng số liệu tổng hợp không khớp toàn bộ.');
  }
  if (countsClaimAllMatched && (perLayerHasInvalid || perLayerHasNotVerified || perLayerHasMixed || perLayerHasChecking || perLayerHasSkipped || perLayerHasMalformed)) {
    conflictReasons.push('Số liệu tổng hợp báo toàn bộ MATCHED nhưng bằng chứng từng lớp có mục không khớp hoặc chưa hợp lệ.');
  }
  if (countsClaimAllMatched && ((explicitOverall && explicitOverall !== 'MATCHED') || overallGroup.malformed)) {
    conflictReasons.push('Số liệu tổng hợp báo toàn bộ MATCHED nhưng trạng thái tổng hợp từ API không đồng nhất.');
  }
  if (perLayerCompleteAllMatched && (['INVALID', 'MIXED', 'NOT_VERIFIED', 'NO_FINDINGS', 'CONFLICT', 'MALFORMED'].includes(countsStatus) || (explicitOverall && explicitOverall !== 'MATCHED') || overallGroup.malformed)) {
    conflictReasons.push('Bằng chứng từng lớp báo MATCHED nhưng số liệu hoặc trạng thái tổng hợp từ API mâu thuẫn.');
  }
  if (perLayerHasInvalid && countsClaimZeroInvalid) {
    conflictReasons.push('Có lớp đối chiếu ở trạng thái INVALID trong khi invalid_count báo 0.');
  }
  if (perLayerHasNotVerified && countsClaimZeroNotVerified) {
    conflictReasons.push('Có lớp đối chiếu ở trạng thái NOT_VERIFIED trong khi not_verified_count báo 0.');
  }
  if ((perLayerHasMatched || perLayerHasInvalid) && countsClaimNoFindings) {
    conflictReasons.push('Số liệu tổng hợp báo 0 cảnh báo nhưng vẫn có bằng chứng lớp đối chiếu.');
  }
  if (explicitOverall === 'INVALID' && (perLayerCompleteAllMatched || countsClaimAllMatched || countsClaimZeroInvalid || countsClaimNoFindings)) {
    conflictReasons.push('Trạng thái tổng hợp báo INVALID nhưng số liệu/lớp chi tiết mâu thuẫn.');
  }
  if (explicitOverall === 'NOT_VERIFIED' && (perLayerCompleteAllMatched || countsClaimAllMatched || perLayerHasInvalid || countsStatus === 'INVALID' || countsClaimZeroNotVerified || countsClaimNoFindings)) {
    conflictReasons.push('Trạng thái tổng hợp báo NOT_VERIFIED nhưng số liệu/lớp chi tiết mâu thuẫn.');
  }
  if (explicitOverall === 'MIXED' && (perLayerCompleteAllMatched || countsClaimAllMatched || countsClaimNoFindings)) {
    conflictReasons.push('Trạng thái tổng hợp báo MIXED nhưng số liệu/lớp chi tiết mâu thuẫn.');
  }
  if (explicitOverall === 'CHECKING' && (perLayerCompleteAllMatched || countsClaimAllMatched || perLayerHasInvalid || countsStatus === 'INVALID' || countsStatus === 'MIXED' || countsClaimNoFindings)) {
    conflictReasons.push('Trạng thái tổng hợp báo đang kiểm tra nhưng đã có kết quả tổng hợp/lớp mâu thuẫn.');
  }
  if (explicitOverall === 'SKIPPED' && (perLayerHasMatched || perLayerHasInvalid || (matchedCount ?? 0) > 0 || (invalidCount ?? 0) > 0)) {
    conflictReasons.push('Trạng thái tổng hợp báo bỏ qua nhưng có dữ liệu đối chiếu trích dẫn.');
  }

  const hasAnyMalformed = summaryMalformed || perLayerHasMalformed || effectiveMalformedCounts || overallGroup.malformed;
  const hasAnyEvidenceSignal = hasAnyCountSignal || hasExplicitPerCheck || malformedChecksContainer || overallGroup.hasAnyPresent || summaryMalformed || summaryWireConflict || checksContainerWireConflict;
  const stageCat = String(stage?.cat || 'UNKNOWN').toUpperCase();

  let aggregateStatus = 'NO_DATA';
  let aggregateLabel = 'Chưa có dữ liệu kiểm chứng trích dẫn từ API';
  let aggregateNote = 'Trạng thái giai đoạn hoàn tất không đồng nghĩa mọi trích dẫn đều MATCHED; xem kết quả từng finding trong Danh sách cảnh báo.';

  if (conflictReasons.length > 0) {
    aggregateStatus = 'CONFLICT';
    aggregateLabel = 'Mâu thuẫn dữ liệu kiểm chứng trích dẫn từ API';
    aggregateNote = `${conflictReasons.join(' ')} Hệ thống fail-closed và không đánh dấu ALL_MATCHED.`;
  } else if (hasAnyMalformed) {
    if (perLayerHasInvalid || countsStatus === 'INVALID' || (invalidCount ?? 0) > 0 || explicitOverall === 'INVALID') {
      aggregateStatus = (perLayerHasMatched || (matchedCount ?? 0) > 0) ? 'MIXED' : 'INVALID';
      aggregateLabel = aggregateStatus === 'MIXED'
        ? 'Kết quả hỗn hợp kèm trường dữ liệu sai kiểu'
        : 'Phát hiện trích dẫn không khớp (INVALID) kèm trường sai kiểu';
      aggregateNote = 'API có bằng chứng trích dẫn không khớp và một số trường telemetry sai kiểu; không đánh dấu ALL_MATCHED.';
    } else {
      aggregateStatus = 'MALFORMED';
      aggregateLabel = 'Dữ liệu telemetry kiểm chứng trích dẫn sai kiểu';
      aggregateNote = 'Một hoặc nhiều trường kiểm chứng trích dẫn từ API sai định dạng hoặc vượt miền số nguyên an toàn; không mặc định thành 0 hay ALL_MATCHED.';
    }
  } else if (hasAnyEvidenceSignal) {
    const hasMixedSignals = (
      countsStatus === 'MIXED'
      || perLayerHasMixed
      || explicitOverall === 'MIXED'
      || (perLayerHasMatched && (perLayerHasInvalid || perLayerHasNotVerified || perLayerHasChecking || perLayerHasSkipped))
      || ((matchedCount ?? 0) > 0 && (perLayerHasInvalid || perLayerHasNotVerified || explicitOverall === 'INVALID' || explicitOverall === 'NOT_VERIFIED'))
    );
    if (hasMixedSignals) {
      aggregateStatus = 'MIXED';
      if (hasValidCounts && (invalidCount ?? 0) > 0 && (matchedCount ?? 0) > 0) {
        aggregateLabel = `Kết quả hỗn hợp (${matchedCount} MATCHED · ${invalidCount} INVALID${(notVerifiedCount ?? 0) > 0 ? ` · ${notVerifiedCount} NOT_VERIFIED` : ''})`;
        aggregateNote = 'Tổng hợp mức giai đoạn có cả trích dẫn khớp và trích dẫn không khớp; không đánh dấu toàn bộ là MATCHED.';
      } else if (hasValidCounts && (matchedCount ?? 0) > 0 && (notVerifiedCount ?? 0) > 0) {
        aggregateLabel = `Kết quả hỗn hợp (${matchedCount} MATCHED · ${notVerifiedCount} NOT_VERIFIED)`;
        aggregateNote = 'Chỉ một phần cảnh báo có trích dẫn khớp mã nguồn; các cảnh báo còn lại chưa được xác minh trích dẫn.';
      } else if (hasValidCounts && (matchedCount ?? 0) > 0 && totalChecked !== null && matchedCount < totalChecked) {
        aggregateLabel = `Khớp một phần (${matchedCount}/${totalChecked} cảnh báo MATCHED)`;
        aggregateNote = 'Chưa phải toàn bộ cảnh báo trong phiên đều đạt MATCHED; đối chiếu chi tiết từng cảnh báo.';
      } else if (hasExplicitPerCheck) {
        aggregateLabel = 'Kết quả đối chiếu từng lớp không đồng nhất';
        aggregateNote = 'Dựa trực tiếp trên dữ liệu kiểm chứng từng lớp do API cung cấp; không đánh dấu toàn bộ là MATCHED.';
      } else {
        aggregateLabel = 'Backend báo kết quả kiểm chứng hỗn hợp (MIXED)';
        aggregateNote = 'Có sự khác nhau giữa các cảnh báo; xem chi tiết từng finding.';
      }
    } else if (perLayerHasInvalid || countsStatus === 'INVALID' || explicitOverall === 'INVALID') {
      aggregateStatus = 'INVALID';
      if (hasValidCounts && (invalidCount ?? 0) > 0) {
        aggregateLabel = `Trích dẫn không khớp (${invalidCount} INVALID${(notVerifiedCount ?? 0) > 0 ? ` · ${notVerifiedCount} NOT_VERIFIED` : ''})`;
        aggregateNote = 'Các trích dẫn không khớp tệp/dòng/nội dung/SHA-256 nguồn lúc quét và bị hạ cấp về UNDETERMINED.';
      } else if (perLayerHasInvalid) {
        aggregateLabel = 'Phát hiện lớp đối chiếu trích dẫn không khớp (INVALID)';
        aggregateNote = 'Ít nhất một lớp kiểm chứng trích dẫn không khớp mã nguồn gốc; giữ fail-closed.';
      } else {
        aggregateLabel = 'Backend báo trích dẫn không hợp lệ (INVALID)';
        aggregateNote = 'Trích dẫn không khớp mã nguồn hoặc SHA-256 gốc.';
      }
    } else if (perLayerHasNotVerified || countsStatus === 'NOT_VERIFIED' || explicitOverall === 'NOT_VERIFIED') {
      aggregateStatus = 'NOT_VERIFIED';
      if (hasValidCounts && (notVerifiedCount ?? 0) > 0) {
        aggregateLabel = `Chưa xác minh trích dẫn (${notVerifiedCount} NOT_VERIFIED)`;
      } else {
        aggregateLabel = 'Chưa xác minh trích dẫn (NOT_VERIFIED)';
      }
      aggregateNote = 'Chưa có trích dẫn đạt MATCHED; giữ nguyên cảnh báo để kiểm tra thủ công.';
    } else if (perLayerHasChecking || explicitOverall === 'CHECKING') {
      aggregateStatus = 'CHECKING';
      aggregateLabel = 'Đang kiểm tra trích dẫn trên backend…';
      aggregateNote = 'Chưa có kết quả cuối cùng từ bước đối chiếu trích dẫn.';
    } else if (countsStatus === 'NO_FINDINGS') {
      aggregateStatus = 'NO_FINDINGS';
      aggregateLabel = 'Không có cảnh báo cần đối chiếu trích dẫn (0)';
      aggregateNote = 'Không phát sinh cảnh báo hoặc trích dẫn để đối chiếu trong giai đoạn này (không đánh dấu ALL_MATCHED).';
    } else if (perLayerHasSkipped || explicitOverall === 'SKIPPED') {
      aggregateStatus = 'SKIPPED';
      aggregateLabel = 'Giai đoạn kiểm chứng trích dẫn được bỏ qua';
      aggregateNote = 'Không thực hiện đối chiếu trích dẫn trong chế độ hiện tại.';
    } else if (
      (perLayerCompleteAllMatched || countsClaimAllMatched)
      && !perLayerHasMissing
      && countsStatus !== 'PARTIAL'
    ) {
      aggregateStatus = 'ALL_MATCHED';
      if (countsClaimAllMatched && perLayerCompleteAllMatched) {
        aggregateLabel = `Đủ 4 lớp đối chiếu và ${matchedCount}/${totalChecked} trích dẫn MATCHED`;
      } else if (countsClaimAllMatched) {
        aggregateLabel = `Tổng hợp giai đoạn: ${matchedCount}/${totalChecked} cảnh báo MATCHED (0 INVALID · 0 NOT_VERIFIED)`;
      } else {
        aggregateLabel = 'Backend xác nhận đủ 4 lớp đối chiếu trích dẫn';
      }
      aggregateNote = 'MATCHED chỉ chứng thực trích dẫn khớp mã nguồn lúc quét, không đồng nghĩa xác nhận lỗ hổng cuối cùng.';
    } else {
      aggregateStatus = 'PARTIAL';
      if (hasValidCounts && (matchedCount ?? 0) > 0) {
        const missingParts = [];
        if (totalChecked === null) missingParts.push('total');
        if (invalidCount === null) missingParts.push('invalid_count');
        if (notVerifiedCount === null) missingParts.push('not_verified_count');
        aggregateLabel = `Ghi nhận ${matchedCount} MATCHED (chưa đủ bằng chứng tổng hợp: thiếu ${missingParts.join(', ') || 'chi tiết lớp'})`;
        aggregateNote = 'API chưa cung cấp đủ các trường bắt buộc (matched, invalid, not_verified, total) nên không mặc định thành 0 và không khẳng định ALL_MATCHED.';
      } else if (perLayerHasMissing) {
        aggregateLabel = 'Mới nhận bằng chứng cho một phần lớp đối chiếu trích dẫn';
        aggregateNote = 'Các lớp thiếu dữ liệu giữ trạng thái CHƯA CÓ DỮ LIỆU; không công nhận ALL_MATCHED khi thiếu lớp bắt buộc.';
      } else if (overallClaimsMatched) {
        aggregateLabel = 'API chỉ báo tổng hợp MATCHED (chưa đủ số liệu hoặc bằng chứng 4 lớp)';
        aggregateNote = 'Thiếu số liệu đầy đủ (matched/invalid/not_verified/total) và bằng chứng từng lớp nên chưa đủ căn cứ công nhận ALL_MATCHED.';
      } else {
        aggregateLabel = 'Chưa đủ dữ liệu kiểm chứng trích dẫn để kết luận';
        aggregateNote = 'Số liệu kiểm chứng từ API chưa đầy đủ; không tự suy diễn 0 hoặc ALL_MATCHED.';
      }
    }
  } else if (stageCat === 'RUNNING') {
    aggregateStatus = 'CHECKING';
    aggregateLabel = 'Đang kiểm tra trích dẫn trên backend…';
    aggregateNote = 'Backend đang chạy giai đoạn 05 và chưa trả telemetry chi tiết cho từng lớp đối chiếu.';
  } else if (stageCat === 'SKIPPED') {
    aggregateStatus = 'SKIPPED';
    aggregateLabel = 'Giai đoạn kiểm chứng trích dẫn được bỏ qua';
    aggregateNote = 'Không thực hiện đối chiếu trích dẫn trong chế độ hiện tại.';
  } else if (stageCat === 'CANCELLED') {
    aggregateStatus = 'CANCELLED';
    aggregateLabel = 'Giai đoạn kiểm chứng trích dẫn đã hủy';
    aggregateNote = 'Phiên phân tích đã bị hủy trước khi hoàn tất đối chiếu trích dẫn.';
  } else if (stageCat === 'FAILED') {
    aggregateStatus = 'FAILED';
    aggregateLabel = 'Giai đoạn kiểm chứng trích dẫn thất bại';
    aggregateNote = 'Không có kết quả kiểm chứng trích dẫn hợp lệ do giai đoạn gặp lỗi.';
  }

  // Missing layers inside an explicit per-layer container NEVER inherit an aggregate badge;
  // they strictly stay NO_DATA so unverified layers never look verified.
  const fallbackPillStatus = (() => {
    if (hasExplicitPerCheck) return 'NO_DATA';
    if (aggregateStatus === 'CONFLICT') return 'CONFLICT';
    if (aggregateStatus === 'MALFORMED') return 'MALFORMED';
    if (aggregateStatus === 'PARTIAL') return 'NO_DATA';
    if (aggregateStatus === 'NO_FINDINGS') return 'NO_DATA';
    if (aggregateStatus === 'CHECKING') return 'CHECKING';
    if (aggregateStatus === 'INVALID') return 'INVALID';
    if (aggregateStatus === 'MIXED') return 'MIXED';
    if (aggregateStatus === 'NOT_VERIFIED') return 'NOT_VERIFIED';
    if (aggregateStatus === 'SKIPPED') return 'SKIPPED';
    if (aggregateStatus === 'CANCELLED') return 'CANCELLED';
    if (aggregateStatus === 'FAILED') return 'FAILED';
    // Even when complete stage aggregate counts prove ALL_MATCHED, without explicit per-layer
    // `checks`, never claim per-field `MATCH ✓` pills; show stage-level verified cue instead.
    if (aggregateStatus === 'ALL_MATCHED') return 'AGGREGATE_MATCHED';
    return 'NO_DATA';
  })();

  const checks = CITATION_CHECK_SPECS.map((spec) => {
    const resolvedStatus = explicitCheckMap[spec.key] || fallbackPillStatus;
    return {
      ...spec,
      ...checkPresentationFromStatus(resolvedStatus),
    };
  });

  return {
    mode,
    isIllustrative: false,
    hasBackendEvidence: hasAnyEvidenceSignal,
    aggregateStatus,
    aggregateLabel,
    aggregateNote,
    conflictReasons,
    counts: hasValidCounts
      ? {
          matched: matchedCount,
          invalid: invalidCount,
          notVerified: notVerifiedCount,
          total: totalChecked,
          isComplete: (
            matchedCount !== null
            && invalidCount !== null
            && notVerifiedCount !== null
            && totalChecked !== null
            && !hasCountAliasConflict
            && !hasCountMathConflict
            && !effectiveMalformedCounts
          ),
        }
      : null,
    checks,
  };
}
