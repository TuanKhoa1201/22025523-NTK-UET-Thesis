// Bounded, single-flight, session-isolated, TTL-aware /api/health monitor for active OpenGrep health probes.
// Prevents stale/out-of-order responses, duplicate concurrent polls, infinite retry loops,
// older server snapshots overwriting fresher valid probes, reload resurrection of expired proofs,
// false TTL extension from replayed snapshots, malformed payload render crashes,
// or self-promotion to VERIFIED when backend has not verified OpenGrep.
import {
  api,
  getApiBaseUrl,
  getApiOrigin,
  getAuthSessionScope,
  getHealthPersistenceScopeKey,
  getWireDuplicateKeyInfo,
  getWireObjectIntegrity,
  HEALTH_PROOF_LEDGER_STORAGE_KEY,
} from './api';
import {
  describeOpengrepHealth,
  normalizeDegradedReasons,
  normalizeHealthArchitecture,
  parseOpengrepTimestampMs,
  parseStrictBoolean,
  resolveOpengrepExpiresAtMs,
  resolveOpengrepExpiryEvidence,
} from './findingPresentation';

export const DEFAULT_PROBE_RETRY_DELAYS_MS = Object.freeze([800, 1200, 1800, 2500, 3500, 5000]);
const MAX_SAFE_TIMER_DELAY_MS = 2147483647;
const MAX_SEEN_PROOF_SIGNATURES = 64;
const MAX_PERSISTED_SCOPES = 16;
const MAX_FUTURE_OBSERVATION_SKEW_MS = 30000;
const CLOCK_ROLLBACK_TOLERANCE_MS = 250;
const HEALTH_LEDGER_SCHEMA_VERSION = 1;
const SHA256_HEX_RE = /^[a-f0-9]{64}$/i;
const HEALTH_LEDGER_WRITE_PROBE_KEY = '22025523-health-ledger-write-probe-v1';
const UNANCHORED_LEDGER_REASON = 'Trình duyệt không cho đọc/ghi sổ chống phát lại (sessionStorage) và phản hồi thiếu checked_at của máy chủ; không đủ căn cứ xác minh độ mới của probe.';

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function stableIdentityText(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function finitePositiveNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : null;
}

function nonNegativeFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

function positiveSafeInt(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 ? value : null;
}

function nonNegativeSafeInt(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

// Separates monotonic elapsed-time measurement from wall-clock epoch timestamps.
// - In production (no custom clocks), reads `performance.now()` wrapped in a non-decreasing ratchet.
// - When tests inject `monotonicNow`, reads that clock wrapped in a non-decreasing ratchet.
// - When legacy tests inject only a custom wall clock `now` (without `monotonicNow`), derives a
//   monotonic elapsed ratchet from positive wall-clock increments so rollback steps never move
//   monotonic time backward while preserving deterministic fake-clock tests.
function createMonotonicClock({wallNow, customMonotonicNow, hasCustomWallNow}) {
  if (typeof customMonotonicNow === 'function') {
    let last = null;
    return () => {
      const raw = Number(customMonotonicNow());
      if (!Number.isFinite(raw)) return last ?? 0;
      if (last === null || raw > last) last = raw;
      return last;
    };
  }
  if (hasCustomWallNow) {
    let prevWall = null;
    let mono = 0;
    return () => {
      const raw = Number(wallNow());
      if (!Number.isFinite(raw)) return mono;
      if (prevWall === null) {
        prevWall = raw;
        return mono;
      }
      if (raw > prevWall) {
        mono += (raw - prevWall);
      }
      prevWall = raw;
      return mono;
    };
  }
  const hasPerfNow = typeof globalThis.performance?.now === 'function';
  let last = null;
  return () => {
    const raw = hasPerfNow ? globalThis.performance.now() : Date.now();
    if (!Number.isFinite(raw)) return last ?? 0;
    if (last === null || raw > last) last = raw;
    return last;
  };
}

function minOptionalFinite(a, b) {
  const na = finitePositiveNumber(a);
  const nb = finitePositiveNumber(b);
  if (na !== null && nb !== null) return Math.min(na, nb);
  return na ?? nb;
}

function minOptionalNonNegative(a, b) {
  const na = nonNegativeFiniteNumber(a);
  const nb = nonNegativeFiniteNumber(b);
  if (na !== null && nb !== null) return Math.min(na, nb);
  return na ?? nb;
}

function maxOptionalFinite(a, b) {
  const na = finitePositiveNumber(a);
  const nb = finitePositiveNumber(b);
  if (na !== null && nb !== null) return Math.max(na, nb);
  return na ?? nb;
}

// Deterministic strict partial order over observation tuples (firstSeenSeq, firstSeenAtMs).
// Monotonic per-scope logical sequence `firstSeenSeq` takes precedence over wall-clock
// `firstSeenAtMs` so backward or forward client clock steps (NTP adjustments) can NEVER invert
// observation order or let an older probe displace a newer probe before or after reload.
// Legacy schema-v1 entries lacking `firstSeenSeq` strictly predate any sequenced entry and
// fall back to `firstSeenAtMs` when compared against another legacy entry.
function compareObservationOrder(a, b) {
  if (!a || !b) return null;
  const sa = positiveSafeInt(a.firstSeenSeq);
  const sb = positiveSafeInt(b.firstSeenSeq);
  if (sa !== null && sb !== null) {
    if (sa < sb) return -1;
    if (sa > sb) return 1;
    if (a.firstSeenAtMs < b.firstSeenAtMs) return -1;
    if (a.firstSeenAtMs > b.firstSeenAtMs) return 1;
    return 0;
  }
  if (sa === null && sb !== null) return -1;
  if (sa !== null && sb === null) return 1;
  if (a.firstSeenAtMs < b.firstSeenAtMs) return -1;
  if (a.firstSeenAtMs > b.firstSeenAtMs) return 1;
  return null;
}

// Monotonically merges two observations of the SAME proof signature: preserves the tightest
// wall/server/monotonic deadlines, sticky expiry & rollback flags, tightest reload checkpoint
// remaining budget, and earliest deterministic observation tuple.
function mergeProofRecord(prev, next) {
  const expiresAtMs = Math.min(prev.expiresAtMs, next.expiresAtMs);
  const expired = Boolean(prev.expired || next.expired);
  const rollbackObserved = Boolean(prev.rollbackObserved || next.rollbackObserved);
  const serverExpiresAtMs = minOptionalFinite(prev.serverExpiresAtMs, next.serverExpiresAtMs);
  const lastServerCheckedAtMs = maxOptionalFinite(prev.lastServerCheckedAtMs, next.lastServerCheckedAtMs);
  const checkpointRemainingMs = minOptionalNonNegative(prev.checkpointRemainingMs, next.checkpointRemainingMs);
  const checkpointWallMs = maxOptionalFinite(prev.checkpointWallMs, next.checkpointWallMs);
  const monoExpiresAtMs = minOptionalNonNegative(prev.monoExpiresAtMs, next.monoExpiresAtMs);
  const firstSeenMonoMs = nonNegativeFiniteNumber(prev.firstSeenMonoMs) ?? nonNegativeFiniteNumber(next.firstSeenMonoMs);
  const shared = {
    expiresAtMs,
    expired,
    rollbackObserved,
    serverExpiresAtMs,
    lastServerCheckedAtMs,
    checkpointRemainingMs,
    checkpointWallMs,
    monoExpiresAtMs,
    firstSeenMonoMs,
  };
  const sp = positiveSafeInt(prev.firstSeenSeq);
  const sn = positiveSafeInt(next.firstSeenSeq);
  if (sp !== null && sn !== null) {
    if (sp < sn) return {...shared, firstSeenAtMs: prev.firstSeenAtMs, firstSeenSeq: sp};
    if (sn < sp) return {...shared, firstSeenAtMs: next.firstSeenAtMs, firstSeenSeq: sn};
    return {...shared, firstSeenAtMs: Math.min(prev.firstSeenAtMs, next.firstSeenAtMs), firstSeenSeq: sp};
  }
  return {...shared, firstSeenAtMs: Math.min(prev.firstSeenAtMs, next.firstSeenAtMs), firstSeenSeq: null};
}

function sortObservationCompare(a, b) {
  const cmp = compareObservationOrder(a, b);
  if (cmp !== null && cmp !== 0) return cmp;
  return 0;
}

function validateScopeEntrySchema(entry) {
  if (!isPlainObject(entry)) return false;
  if (entry.latestProbedAtMs !== null && entry.latestProbedAtMs !== undefined && finitePositiveNumber(entry.latestProbedAtMs) === null) {
    return false;
  }
  if (entry.latestServerExpiresAtMs !== null && entry.latestServerExpiresAtMs !== undefined && finitePositiveNumber(entry.latestServerExpiresAtMs) === null) {
    return false;
  }
  if (entry.latestProcessInstanceId !== undefined && entry.latestProcessInstanceId !== null && typeof entry.latestProcessInstanceId !== 'string') {
    return false;
  }
  if (entry.latestProofSig !== undefined && entry.latestProofSig !== null && typeof entry.latestProofSig !== 'string') {
    return false;
  }
  if (entry.nextOrderSeq !== undefined && nonNegativeSafeInt(entry.nextOrderSeq) === null) {
    return false;
  }
  if (entry.updatedAtMs !== undefined && finitePositiveNumber(entry.updatedAtMs) === null) {
    return false;
  }
  if (entry.maxWallClockMs !== undefined && finitePositiveNumber(entry.maxWallClockMs) === null) {
    return false;
  }
  if (entry.latestAcceptedProof !== undefined && entry.latestAcceptedProof !== null) {
    const lap = entry.latestAcceptedProof;
    if (
      !isPlainObject(lap)
      || typeof lap.sig !== 'string'
      || !lap.sig.trim()
      || finitePositiveNumber(lap.firstSeenAtMs) === null
      || (Object.hasOwn(lap, 'firstSeenSeq') && lap.firstSeenSeq !== null && positiveSafeInt(lap.firstSeenSeq) === null)
    ) {
      return false;
    }
  }
  if (entry.proofs !== undefined) {
    if (!isPlainObject(entry.proofs)) return false;
    for (const [sig, meta] of Object.entries(entry.proofs)) {
      if (!sig || !isPlainObject(meta)) return false;
      if (finitePositiveNumber(meta.expiresAtMs) === null || finitePositiveNumber(meta.firstSeenAtMs) === null) {
        return false;
      }
      // Legacy schema-v1 entries may omit optional monotonic/checkpoint fields, but if present they MUST be valid.
      if (Object.hasOwn(meta, 'firstSeenSeq') && positiveSafeInt(meta.firstSeenSeq) === null) {
        return false;
      }
      if (Object.hasOwn(meta, 'expired') && typeof meta.expired !== 'boolean') {
        return false;
      }
      if (Object.hasOwn(meta, 'rollbackObserved') && typeof meta.rollbackObserved !== 'boolean') {
        return false;
      }
      if (Object.hasOwn(meta, 'serverExpiresAtMs') && finitePositiveNumber(meta.serverExpiresAtMs) === null) {
        return false;
      }
      if (Object.hasOwn(meta, 'lastServerCheckedAtMs') && finitePositiveNumber(meta.lastServerCheckedAtMs) === null) {
        return false;
      }
      if (Object.hasOwn(meta, 'checkpointWallMs') && finitePositiveNumber(meta.checkpointWallMs) === null) {
        return false;
      }
      if (Object.hasOwn(meta, 'checkpointRemainingMs') && nonNegativeFiniteNumber(meta.checkpointRemainingMs) === null) {
        return false;
      }
    }
  }
  return true;
}

function validateLedgerRootSchema(parsed) {
  if (!isPlainObject(parsed) || parsed.v !== HEALTH_LEDGER_SCHEMA_VERSION || !isPlainObject(parsed.scopes)) {
    return false;
  }
  for (const [scopeKey, entry] of Object.entries(parsed.scopes)) {
    if (!scopeKey || !validateScopeEntrySchema(entry)) return false;
  }
  return true;
}

function sanitizeBooleanFields(sourceObj, fieldNames, prefix, schemaWarnings, invalidFields) {
  if (!isPlainObject(sourceObj)) return sourceObj;
  let next = null;
  for (const field of fieldNames) {
    if (!Object.hasOwn(sourceObj, field)) continue;
    const parsed = parseStrictBoolean(sourceObj[field]);
    if (parsed.malformed) {
      if (!next) next = {...sourceObj};
      next[field] = null;
      const fullKey = prefix ? `${prefix}.${field}` : field;
      invalidFields.push(fullKey);
      schemaWarnings.push(`Trường ${fullKey} từ /api/health sai kiểu boolean.`);
    }
  }
  return next || sourceObj;
}

/**
 * Stable identity of one OpenGrep probe execution. Deadline attributes (`expires_at`,
 * `ttl_seconds`, `checked_at`, receive time) are deliberately excluded: changing them on the same
 * probe must never look like a new probe. `probed_at` anchors identity. Without `probed_at` there
 * is no evidence of a distinct run except the backend execution identity digests, so the anchor
 * is a constant `u:` and a later or longer deadline alone never yields a new identity.
 */
export function buildProbeProofSignature(og, evidence) {
  if (!isPlainObject(og) || !evidence || !evidence.hasVerifiableBasis) return '';
  const anchor = evidence.probedAtMs !== null && evidence.probedAtMs !== undefined
    ? `p:${evidence.probedAtMs}`
    : 'u:';
  return [
    anchor,
    stableIdentityText(og.process_instance_id),
    stableIdentityText(og.probe_execution_identity_sha256),
    stableIdentityText(og.binary_identity_sha256),
    stableIdentityText(og.rules_sha256),
  ].join('|');
}

/**
 * Returns true only when an OpenGrep probe carries strong execution-identifying metadata
 * (both a non-empty `process_instance_id` without delimiter ambiguity and a valid 64-hex
 * `probe_execution_identity_sha256`). Neither `process_instance_id` alone nor static binary/rules
 * digests are treated as reliable proof of the same execution when `probed_at` is omitted.
 */
export function hasReliableProbeExecutionIdentity(og, evidence = null) {
  if (!isPlainObject(og)) return false;
  if (evidence && (!evidence.hasVerifiableBasis || evidence.malformed || evidence.contradictory)) {
    return false;
  }
  const procId = stableIdentityText(og.process_instance_id);
  const execSha = stableIdentityText(og.probe_execution_identity_sha256);
  return Boolean(procId && !procId.includes('|') && SHA256_HEX_RE.test(execSha));
}

function hasReliableUnanchoredProofSignature(sig) {
  if (typeof sig !== 'string' || !sig.startsWith('u:|')) return false;
  const parts = sig.split('|');
  if (parts.length !== 5) return false;
  const [, procId, execSha] = parts;
  return Boolean(procId && SHA256_HEX_RE.test(execSha));
}

/**
 * Extracts structured server probe ordering metadata from a structurally valid, verifiable
 * OpenGrep probe snapshot. Returns null for malformed/contradictory/unanchored snapshots so
 * invalid payloads can never advance or poison freshness watermarks.
 */
export function extractProbeOrderMeta(og, evidence) {
  if (!isPlainObject(og) || !evidence || !evidence.hasVerifiableBasis || evidence.malformed || evidence.contradictory) {
    return null;
  }
  return {
    probedAtMs: evidence.probedAtMs ?? null,
    explicitExpiresMs: evidence.explicitExpiresMs ?? null,
    serverExpiresAtMs: evidence.serverExpiresAtMs ?? evidence.explicitExpiresMs ?? null,
    processInstanceId: stableIdentityText(og.process_instance_id),
    proofSig: buildProbeProofSignature(og, evidence),
  };
}

/**
 * Compares the server-side evidence freshness of an incoming valid probe snapshot against
 * a reference watermark/accepted probe in the same API & auth scope.
 * Returns one of: 'OLDER', 'SAME', 'NEWER', 'INCOMPARABLE_PROCESS', 'UNANCHORED_DROP_PROBED_AT', 'INCOMPARABLE'.
 */
export function compareProbeEvidenceOrder(incoming, reference) {
  if (!incoming || !reference) return 'INCOMPARABLE';
  if (incoming.processInstanceId && reference.processInstanceId && incoming.processInstanceId !== reference.processInstanceId) {
    return 'INCOMPARABLE_PROCESS';
  }
  if (incoming.probedAtMs !== null && reference.probedAtMs !== null) {
    if (incoming.probedAtMs < reference.probedAtMs) return 'OLDER';
    if (incoming.probedAtMs > reference.probedAtMs) return 'NEWER';
    // Same probe execution: a different expires_at / ttl_seconds is not a newer probe.
    return 'SAME';
  }
  if (
    incoming.probedAtMs === null
    && reference.probedAtMs === null
    && incoming.proofSig
    && reference.proofSig
    && incoming.proofSig === reference.proofSig
    && hasReliableUnanchoredProofSignature(incoming.proofSig)
  ) {
    // Reliably identified same unanchored execution (matching full proof signature containing both
    // `process_instance_id` and a valid 64-hex `probe_execution_identity_sha256`): a tightened
    // deadline or EXPIRED status update belongs to this exact execution and must flow through
    // monotonic clamping (`recordAndClampProbeDeadline`) rather than being dropped as OLDER.
    return 'SAME';
  }
  if (incoming.probedAtMs === null && incoming.serverExpiresAtMs !== null && reference.serverExpiresAtMs !== null) {
    if (incoming.serverExpiresAtMs < reference.serverExpiresAtMs) return 'OLDER';
    if (incoming.serverExpiresAtMs === reference.serverExpiresAtMs) return 'SAME';
    // A later deadline without a run timestamp is not evidence of a newer probe run.
    return reference.probedAtMs === null ? 'SAME' : 'UNANCHORED_DROP_PROBED_AT';
  }
  if (incoming.probedAtMs !== null && reference.probedAtMs === null && incoming.serverExpiresAtMs !== null && reference.serverExpiresAtMs !== null) {
    if (incoming.serverExpiresAtMs < reference.serverExpiresAtMs) return 'OLDER';
    if (incoming.serverExpiresAtMs > reference.serverExpiresAtMs) return 'NEWER';
    return 'SAME';
  }
  return 'INCOMPARABLE';
}

function shouldReplaceWatermark(candidate, current, {allowIncomparableProcess = false, preferredProofSig = ''} = {}) {
  if (!candidate) return false;
  if (!current) return true;
  const cmp = compareProbeEvidenceOrder(candidate, current);
  if (cmp === 'NEWER' || (allowIncomparableProcess && cmp === 'INCOMPARABLE_PROCESS')) {
    return true;
  }
  if (
    cmp === 'SAME'
    && candidate.probedAtMs === null
    && current.probedAtMs === null
    && candidate.serverExpiresAtMs !== null
    && current.serverExpiresAtMs !== null
    && candidate.proofSig
    && candidate.proofSig !== current.proofSig
  ) {
    if (candidate.serverExpiresAtMs > current.serverExpiresAtMs) return true;
    if (candidate.serverExpiresAtMs === current.serverExpiresAtMs && preferredProofSig && candidate.proofSig === preferredProofSig) {
      return true;
    }
  }
  return false;
}

function readValidatedLedgerRoot(storage) {
  if (!storage || typeof storage.getItem !== 'function') return {root: null, corrupted: false};
  let raw = null;
  try {
    raw = storage.getItem(HEALTH_PROOF_LEDGER_STORAGE_KEY);
  } catch {
    return {root: null, corrupted: false};
  }
  if (raw === null || raw === undefined || raw === '') {
    return {root: {v: HEALTH_LEDGER_SCHEMA_VERSION, scopes: {}}, corrupted: false};
  }
  if (typeof raw !== 'string') {
    try {
      storage.removeItem?.(HEALTH_PROOF_LEDGER_STORAGE_KEY);
    } catch {
      /* ignore */
    }
    return {root: {v: HEALTH_LEDGER_SCHEMA_VERSION, scopes: {}}, corrupted: true};
  }
  try {
    const parsed = JSON.parse(raw);
    if (!validateLedgerRootSchema(parsed)) {
      try {
        storage.removeItem?.(HEALTH_PROOF_LEDGER_STORAGE_KEY);
      } catch {
        /* ignore */
      }
      return {root: {v: HEALTH_LEDGER_SCHEMA_VERSION, scopes: {}}, corrupted: true};
    }
    return {root: parsed, corrupted: false};
  } catch {
    try {
      storage.removeItem?.(HEALTH_PROOF_LEDGER_STORAGE_KEY);
    } catch {
      /* ignore */
    }
    return {root: {v: HEALTH_LEDGER_SCHEMA_VERSION, scopes: {}}, corrupted: true};
  }
}

function loadValidatedScopeLedger(storage, persistKey, currentNow) {
  if (!storage || !persistKey) return null;
  const {root, corrupted} = readValidatedLedgerRoot(storage);
  if (corrupted) return {corrupted: true, watermarkOrder: null, proofs: new Map(), nextOrderSeq: 0, latestAcceptedProof: null};
  if (!root || !Object.hasOwn(root.scopes, persistKey)) return null;
  const entry = root.scopes[persistKey];
  if (!validateScopeEntrySchema(entry)) {
    return {corrupted: true, watermarkOrder: null, proofs: new Map(), nextOrderSeq: 0, latestAcceptedProof: null};
  }

  const latestProbedAtMs = entry.latestProbedAtMs === null || entry.latestProbedAtMs === undefined
    ? null
    : finitePositiveNumber(entry.latestProbedAtMs);
  const latestServerExpiresAtMs = entry.latestServerExpiresAtMs === null || entry.latestServerExpiresAtMs === undefined
    ? null
    : finitePositiveNumber(entry.latestServerExpiresAtMs);
  const latestProcessInstanceId = stableIdentityText(entry.latestProcessInstanceId);
  const latestProofSig = stableIdentityText(entry.latestProofSig);
  let maxOrderSeq = nonNegativeSafeInt(entry.nextOrderSeq) ?? 0;

  const proofs = new Map();
  if (isPlainObject(entry.proofs)) {
    for (const [sig, meta] of Object.entries(entry.proofs)) {
      if (!sig || !isPlainObject(meta)) continue;
      const expiresAtMs = finitePositiveNumber(meta.expiresAtMs);
      const rawFirstSeenAtMs = finitePositiveNumber(meta.firstSeenAtMs);
      if (expiresAtMs === null || rawFirstSeenAtMs === null) continue;
      // Detect wall-clock rollback against persisted timestamps before clamping future timestamps:
      // dropping a record would erase its tombstone, while silently clamping without recording
      // `rollbackObserved` would conceal clock discontinuity across document reload.
      const rawCheckpointWallMs = Object.hasOwn(meta, 'checkpointWallMs') ? finitePositiveNumber(meta.checkpointWallMs) : null;
      const rolledBackAgainstStoredWall = Boolean(
        Number.isFinite(currentNow) && (
          rawFirstSeenAtMs > currentNow + CLOCK_ROLLBACK_TOLERANCE_MS
          || (rawCheckpointWallMs !== null && rawCheckpointWallMs > currentNow + CLOCK_ROLLBACK_TOLERANCE_MS)
        ),
      );
      const firstSeenAtMs = (Number.isFinite(currentNow) && rawFirstSeenAtMs > currentNow + MAX_FUTURE_OBSERVATION_SKEW_MS)
        ? currentNow
        : rawFirstSeenAtMs;
      const firstSeenSeq = Object.hasOwn(meta, 'firstSeenSeq') ? positiveSafeInt(meta.firstSeenSeq) : null;
      if (firstSeenSeq !== null && firstSeenSeq > maxOrderSeq) {
        maxOrderSeq = firstSeenSeq;
      }
      proofs.set(sig, {
        expiresAtMs,
        firstSeenAtMs,
        firstSeenSeq,
        expired: meta.expired === true,
        rollbackObserved: Boolean(meta.rollbackObserved === true || rolledBackAgainstStoredWall),
        serverExpiresAtMs: Object.hasOwn(meta, 'serverExpiresAtMs') ? finitePositiveNumber(meta.serverExpiresAtMs) : null,
        lastServerCheckedAtMs: Object.hasOwn(meta, 'lastServerCheckedAtMs') ? finitePositiveNumber(meta.lastServerCheckedAtMs) : null,
        checkpointWallMs: rawCheckpointWallMs,
        checkpointRemainingMs: Object.hasOwn(meta, 'checkpointRemainingMs') ? nonNegativeFiniteNumber(meta.checkpointRemainingMs) : null,
        monoExpiresAtMs: null,
        firstSeenMonoMs: null,
      });
    }
  }

  let latestAcceptedProof = null;
  if (isPlainObject(entry.latestAcceptedProof)) {
    const lap = entry.latestAcceptedProof;
    const rawLapAt = finitePositiveNumber(lap.firstSeenAtMs);
    const lapSeq = Object.hasOwn(lap, 'firstSeenSeq') && lap.firstSeenSeq !== null ? positiveSafeInt(lap.firstSeenSeq) : null;
    if (typeof lap.sig === 'string' && lap.sig.trim() && rawLapAt !== null) {
      const lapAt = (Number.isFinite(currentNow) && rawLapAt > currentNow + MAX_FUTURE_OBSERVATION_SKEW_MS)
        ? currentNow
        : rawLapAt;
      if (lapSeq !== null && lapSeq > maxOrderSeq) {
        maxOrderSeq = lapSeq;
      }
      latestAcceptedProof = {sig: lap.sig, firstSeenAtMs: lapAt, firstSeenSeq: lapSeq};
    }
  }

  const watermarkOrder = (latestProbedAtMs !== null || latestServerExpiresAtMs !== null)
    ? {
        probedAtMs: latestProbedAtMs,
        explicitExpiresMs: latestServerExpiresAtMs,
        serverExpiresAtMs: latestServerExpiresAtMs,
        processInstanceId: latestProcessInstanceId,
        proofSig: latestProofSig,
      }
    : null;

  const maxWallClockMs = maxOptionalFinite(entry.maxWallClockMs, entry.updatedAtMs);
  return {corrupted: false, watermarkOrder, proofs, nextOrderSeq: maxOrderSeq, latestAcceptedProof, maxWallClockMs};
}

function writeValidatedScopeLedger(storage, persistKey, watermarkOrder, proofsMap, currentNow, {nextOrderSeq = 0, latestAcceptedProof = null, activeProofSig = ''} = {}) {
  if (!storage || !persistKey || typeof storage.setItem !== 'function') return false;
  // Never overwrite or clobber a scope ledger with empty state (e.g. during AUTH_REQUIRED).
  if (!watermarkOrder && (!proofsMap || proofsMap.size === 0)) return true;
  try {
    const {root} = readValidatedLedgerRoot(storage);
    const safeRoot = root || {v: HEALTH_LEDGER_SCHEMA_VERSION, scopes: {}};
    const nextScopes = isPlainObject(safeRoot.scopes) ? {...safeRoot.scopes} : {};
    const existingScope = loadValidatedScopeLedger(storage, persistKey, currentNow);
    const validExisting = existingScope && !existingScope.corrupted ? existingScope : null;

    // Strictly monotonic merge: never discard or extend previously recorded deadlines/watermarks,
    // and deterministically preserve observation sequence numbers across reloads.
    const mergedProofs = new Map();
    let mergedNextOrderSeq = Math.max(
      nonNegativeSafeInt(validExisting?.nextOrderSeq) ?? 0,
      nonNegativeSafeInt(nextOrderSeq) ?? 0,
    );
    if (validExisting?.proofs) {
      for (const [sig, meta] of validExisting.proofs.entries()) {
        mergedProofs.set(sig, {
          expiresAtMs: meta.expiresAtMs,
          firstSeenAtMs: meta.firstSeenAtMs,
          firstSeenSeq: positiveSafeInt(meta.firstSeenSeq),
          expired: Boolean(meta.expired),
          rollbackObserved: Boolean(meta.rollbackObserved),
          serverExpiresAtMs: finitePositiveNumber(meta.serverExpiresAtMs),
          lastServerCheckedAtMs: finitePositiveNumber(meta.lastServerCheckedAtMs),
          checkpointWallMs: finitePositiveNumber(meta.checkpointWallMs),
          checkpointRemainingMs: nonNegativeFiniteNumber(meta.checkpointRemainingMs),
          monoExpiresAtMs: null,
          firstSeenMonoMs: null,
        });
        if (meta.firstSeenSeq !== null && meta.firstSeenSeq > mergedNextOrderSeq) {
          mergedNextOrderSeq = meta.firstSeenSeq;
        }
      }
    }
    if (proofsMap) {
      for (const [sig, meta] of proofsMap.entries()) {
        if (finitePositiveNumber(meta?.expiresAtMs) === null) continue;
        const firstSeenAtMs = finitePositiveNumber(meta?.firstSeenAtMs) ?? currentNow;
        const firstSeenSeq = positiveSafeInt(meta?.firstSeenSeq);
        if (firstSeenSeq !== null && firstSeenSeq > mergedNextOrderSeq) {
          mergedNextOrderSeq = firstSeenSeq;
        }
        const incomingRec = {
          expiresAtMs: meta.expiresAtMs,
          firstSeenAtMs,
          firstSeenSeq,
          expired: Boolean(meta?.expired),
          rollbackObserved: Boolean(meta?.rollbackObserved),
          serverExpiresAtMs: finitePositiveNumber(meta?.serverExpiresAtMs),
          lastServerCheckedAtMs: finitePositiveNumber(meta?.lastServerCheckedAtMs),
          checkpointWallMs: finitePositiveNumber(meta?.checkpointWallMs),
          checkpointRemainingMs: nonNegativeFiniteNumber(meta?.checkpointRemainingMs),
          monoExpiresAtMs: null,
          firstSeenMonoMs: null,
        };
        const prev = mergedProofs.get(sig);
        mergedProofs.set(sig, prev ? mergeProofRecord(prev, incomingRec) : incomingRec);
      }
    }

    let mergedLatestAccepted = validExisting?.latestAcceptedProof || null;
    if (latestAcceptedProof && typeof latestAcceptedProof.sig === 'string' && finitePositiveNumber(latestAcceptedProof.firstSeenAtMs) !== null) {
      const lapSeq = positiveSafeInt(latestAcceptedProof.firstSeenSeq);
      if (lapSeq !== null && lapSeq > mergedNextOrderSeq) {
        mergedNextOrderSeq = lapSeq;
      }
      const candidateLap = {
        sig: latestAcceptedProof.sig,
        firstSeenAtMs: latestAcceptedProof.firstSeenAtMs,
        firstSeenSeq: lapSeq,
      };
      if (!mergedLatestAccepted) {
        mergedLatestAccepted = candidateLap;
      } else {
        const lapCmp = compareObservationOrder(mergedLatestAccepted, candidateLap);
        if (lapCmp === -1 || (lapCmp === 0 && candidateLap.sig === mergedLatestAccepted.sig)) {
          mergedLatestAccepted = candidateLap;
        }
      }
    }

    let mergedWatermark = validExisting?.watermarkOrder || null;
    if (watermarkOrder) {
      if (shouldReplaceWatermark(watermarkOrder, mergedWatermark, {
        allowIncomparableProcess: true,
        preferredProofSig: mergedLatestAccepted?.sig || activeProofSig || '',
      })) {
        mergedWatermark = watermarkOrder;
      } else if (mergedWatermark && !mergedWatermark.proofSig && watermarkOrder.proofSig && compareProbeEvidenceOrder(watermarkOrder, mergedWatermark) === 'SAME') {
        mergedWatermark = {...mergedWatermark, proofSig: watermarkOrder.proofSig};
      }
    }

    // Deterministically bound per-scope entries to MAX_SEEN_PROOF_SIGNATURES while ALWAYS
    // protecting the active accepted proof and `latestAcceptedProof` from eviction so their
    // clamped deadlines and ordering tuples can never be dropped across reloads.
    const validEntries = [...mergedProofs.entries()]
      .filter(([, meta]) => finitePositiveNumber(meta?.expiresAtMs) !== null);
    const protectedSigs = new Set([activeProofSig, latestAcceptedProof?.sig, mergedLatestAccepted?.sig].filter(Boolean));
    let entries;
    if (validEntries.length <= MAX_SEEN_PROOF_SIGNATURES) {
      entries = validEntries.sort((a, b) => sortObservationCompare(a[1], b[1]) || a[0].localeCompare(b[0]));
    } else {
      const protectedEntries = validEntries.filter(([sig]) => protectedSigs.has(sig));
      const otherEntries = validEntries
        .filter(([sig]) => !protectedSigs.has(sig))
        .sort((a, b) => sortObservationCompare(a[1], b[1]) || a[0].localeCompare(b[0]));
      const keepOthers = Math.max(0, MAX_SEEN_PROOF_SIGNATURES - protectedEntries.length);
      entries = [...protectedEntries, ...otherEntries.slice(otherEntries.length - keepOthers)]
        .sort((a, b) => sortObservationCompare(a[1], b[1]) || a[0].localeCompare(b[0]));
    }
    const serializedProofs = {};
    for (const [sig, meta] of entries) {
      const rec = {
        expiresAtMs: meta.expiresAtMs,
        firstSeenAtMs: finitePositiveNumber(meta.firstSeenAtMs) ?? currentNow,
      };
      const seqVal = positiveSafeInt(meta.firstSeenSeq);
      if (seqVal !== null) rec.firstSeenSeq = seqVal;
      if (meta.expired === true) rec.expired = true;
      if (meta.rollbackObserved === true) rec.rollbackObserved = true;
      const srvExp = finitePositiveNumber(meta.serverExpiresAtMs);
      if (srvExp !== null) rec.serverExpiresAtMs = srvExp;
      const lastSrvChk = finitePositiveNumber(meta.lastServerCheckedAtMs);
      if (lastSrvChk !== null) rec.lastServerCheckedAtMs = lastSrvChk;
      const cpWall = finitePositiveNumber(meta.checkpointWallMs);
      if (cpWall !== null) rec.checkpointWallMs = cpWall;
      const cpRem = nonNegativeFiniteNumber(meta.checkpointRemainingMs);
      if (cpRem !== null) rec.checkpointRemainingMs = cpRem;
      serializedProofs[sig] = rec;
    }

    const mergedMaxWallClockMs = maxOptionalFinite(validExisting?.maxWallClockMs, currentNow) ?? currentNow;
    nextScopes[persistKey] = {
      latestProbedAtMs: mergedWatermark?.probedAtMs ?? null,
      latestServerExpiresAtMs: mergedWatermark?.serverExpiresAtMs ?? null,
      latestProcessInstanceId: mergedWatermark?.processInstanceId || '',
      ...(mergedWatermark?.proofSig ? {latestProofSig: mergedWatermark.proofSig} : {}),
      nextOrderSeq: mergedNextOrderSeq,
      latestAcceptedProof: mergedLatestAccepted,
      updatedAtMs: currentNow,
      maxWallClockMs: mergedMaxWallClockMs,
      proofs: serializedProofs,
    };

    const scopeKeys = Object.keys(nextScopes);
    if (scopeKeys.length > MAX_PERSISTED_SCOPES) {
      scopeKeys
        .sort((a, b) => (Number(nextScopes[a]?.updatedAtMs) || 0) - (Number(nextScopes[b]?.updatedAtMs) || 0))
        .slice(0, scopeKeys.length - MAX_PERSISTED_SCOPES)
        .forEach((oldKey) => {
          if (oldKey !== persistKey) delete nextScopes[oldKey];
        });
    }

    storage.setItem(
      HEALTH_PROOF_LEDGER_STORAGE_KEY,
      JSON.stringify({v: HEALTH_LEDGER_SCHEMA_VERSION, scopes: nextScopes}),
    );
    return true;
  } catch {
    /* Storage unavailable, quota exceeded, or blocked: continue safely in RAM. */
    return false;
  }
}

/**
 * Validates and normalizes a raw /api/health response at the API boundary so malformed field
 * types (such as non-array `degraded_reasons`, non-object `opengrep`/`rules`/`ollama`/`architecture`,
 * or non-boolean nested flags like `{toString: null, valueOf: null}`) never throw runtime
 * exceptions in AppShell or StatusPage and never coerce invalid strings via truthiness.
 */
export function sanitizeHealthPayload(rawHealth) {
  if (!isPlainObject(rawHealth)) {
    return {
      valid: false,
      health: null,
      schemaWarnings: ['Phản hồi /api/health không phải đối tượng JSON hợp lệ.'],
      architectureInvalidFields: [],
      architectureMalformed: false,
      invalidBooleanFields: [],
      serverCheckedAtMalformed: false,
      healthWireMalformed: false,
    };
  }
  const schemaWarnings = [];
  const invalidBooleanFields = [];

  // Inspect root & opengrep wire integrity BEFORE shallow-spreading into `sanitized`.
  const rootWire = getWireObjectIntegrity(rawHealth);
  const dupRootKeys = ['status', 'opengrep', 'checked_at', 'authenticated', 'auth_required', 'write_auth_configured', 'degraded_reasons', 'ollama', 'rules', 'architecture']
    .filter((k) => Boolean(getWireDuplicateKeyInfo(rawHealth, k)));
  const healthWireMalformed = Boolean(rootWire?.scannerError || dupRootKeys.length > 0);
  if (healthWireMalformed) {
    schemaWarnings.push(`Phản hồi /api/health chứa khóa trùng lặp hoặc lỗi toàn vẹn JSON (${dupRootKeys.join(', ') || 'wire'}).`);
  }
  const hasCheckedAtField = rawHealth.checked_at !== undefined && rawHealth.checked_at !== null;
  const parsedCheckedAt = hasCheckedAtField ? parseOpengrepTimestampMs(rawHealth.checked_at) : null;
  const serverCheckedAtMalformed = Boolean(
    (hasCheckedAtField && parsedCheckedAt === null)
    || getWireDuplicateKeyInfo(rawHealth, 'checked_at')
    || getWireDuplicateKeyInfo(rawHealth, 'opengrep')
    || getWireDuplicateKeyInfo(rawHealth, 'status')
    || rootWire?.scannerError,
  );
  if (hasCheckedAtField && parsedCheckedAt === null) {
    schemaWarnings.push('Trường checked_at từ /api/health không đúng định dạng thời gian hợp lệ.');
  }

  const reasonsCheck = normalizeDegradedReasons(rawHealth.degraded_reasons);
  if (reasonsCheck.malformed) {
    schemaWarnings.push('Trường degraded_reasons từ /api/health không đúng định dạng mảng.');
  }

  let safeOpengrep = rawHealth.opengrep;
  if (safeOpengrep !== undefined && safeOpengrep !== null && !isPlainObject(safeOpengrep)) {
    schemaWarnings.push('Trường opengrep từ /api/health không đúng định dạng đối tượng.');
    safeOpengrep = {probe_status: 'NOT_VERIFIED', available: false, malformed: true};
  } else if (isPlainObject(safeOpengrep)) {
    const ogInfoCheck = describeOpengrepHealth(safeOpengrep, null, {
      serverCheckedAtMs: parsedCheckedAt,
      serverCheckedAtMalformed,
      rootHealthObj: rawHealth,
    });
    if (ogInfoCheck.malformed || healthWireMalformed) {
      schemaWarnings.push('Một hoặc nhiều trường trong opengrep từ /api/health sai kiểu dữ liệu hoặc trùng khóa tại biên REST.');
      safeOpengrep = {...safeOpengrep, malformed: true};
    }
  }

  let safeOllama = rawHealth.ollama;
  if (safeOllama !== undefined && safeOllama !== null && !isPlainObject(safeOllama)) {
    schemaWarnings.push('Trường ollama từ /api/health không đúng định dạng đối tượng.');
    safeOllama = {};
  } else if (isPlainObject(safeOllama)) {
    safeOllama = sanitizeBooleanFields(safeOllama, ['reachable', 'model_installed'], 'ollama', schemaWarnings, invalidBooleanFields);
  }

  let safeRules = rawHealth.rules;
  if (safeRules !== undefined && safeRules !== null && !isPlainObject(safeRules)) {
    schemaWarnings.push('Trường rules từ /api/health không đúng định dạng đối tượng.');
    safeRules = {};
  } else if (isPlainObject(safeRules)) {
    safeRules = sanitizeBooleanFields(safeRules, ['available'], 'rules', schemaWarnings, invalidBooleanFields);
    if (safeRules.priority_cwes !== undefined && safeRules.priority_cwes !== null && !Array.isArray(safeRules.priority_cwes)) {
      schemaWarnings.push('Trường rules.priority_cwes từ /api/health không đúng định dạng mảng.');
      safeRules = {...safeRules, priority_cwes: null};
    }
  }

  const archNorm = normalizeHealthArchitecture(rawHealth.architecture);
  if (archNorm.schemaWarnings.length > 0) {
    schemaWarnings.push(...archNorm.schemaWarnings);
  }

  let safeTop = sanitizeBooleanFields(
    rawHealth,
    ['auth_required', 'authenticated', 'write_auth_configured', 'write_auth_required', 'git_available'],
    '',
    schemaWarnings,
    invalidBooleanFields,
  );

  const sanitized = {
    ...safeTop,
    degraded_reasons: reasonsCheck.reasons,
    ...(safeOpengrep !== undefined ? {opengrep: safeOpengrep} : {}),
    ...(safeOllama !== undefined ? {ollama: safeOllama} : {}),
    ...(safeRules !== undefined ? {rules: safeRules} : {}),
    ...(rawHealth.architecture !== undefined ? {architecture: archNorm.sanitized} : {}),
  };

  return {
    valid: true,
    health: sanitized,
    schemaWarnings: [...new Set(schemaWarnings)],
    architectureInvalidFields: archNorm.invalidFields,
    architectureMalformed: archNorm.malformed,
    invalidBooleanFields,
    serverCheckedAtMalformed,
    healthWireMalformed,
  };
}

/**
 * Determines whether the frontend should schedule a bounded follow-up /api/health check.
 * Only returns true while backend explicitly reports probe_in_progress === true and
 * OpenGrep is not yet VERIFIED. Never polls when probe_in_progress is false or deferred.
 */
export function shouldAutoRecheckHealth(health, options = {}) {
  if (!isPlainObject(health)) return false;
  const rawStatus = typeof health.status === 'string' ? health.status.trim().toUpperCase() : '';
  if (rawStatus === 'AUTH_REQUIRED') return false;
  const og = isPlainObject(health.opengrep) ? health.opengrep : null;
  if (!og || og.probe_in_progress !== true) return false;
  const ogInfo = describeOpengrepHealth(og, null, options);
  return !ogInfo.isVerified;
}

function buildExpiredBackendSnapshot(backend, expiresAtMs) {
  const prevHealth = isPlainObject(backend?.health) ? backend.health : {};
  const prevOg = isPlainObject(prevHealth.opengrep) ? prevHealth.opengrep : {};
  const prevExpiresMs = parseOpengrepTimestampMs(prevOg.expires_at);
  const clampedExpiresIso = (
    typeof expiresAtMs === 'number'
    && Number.isFinite(expiresAtMs)
    && (prevExpiresMs === null || prevExpiresMs > expiresAtMs)
  )
    ? new Date(expiresAtMs).toISOString()
    : prevOg.expires_at;
  const reasonsCheck = normalizeDegradedReasons(prevHealth.degraded_reasons);
  const nextReasons = reasonsCheck.reasons.includes('OPENGREP_PROBE_EXPIRED')
    ? reasonsCheck.reasons
    : [...reasonsCheck.reasons, 'OPENGREP_PROBE_EXPIRED'];
  return {
    ...backend,
    status: 'DEGRADED',
    ttlExpired: true,
    expiresAtMs,
    opengrepVerified: false,
    health: {
      ...prevHealth,
      degraded_reasons: nextReasons,
      opengrep: {
        ...prevOg,
        available: false,
        runtime_verified: false,
        probe_status: 'EXPIRED',
        health_state: 'EXPIRED',
        ...(clampedExpiresIso !== undefined ? {expires_at: clampedExpiresIso} : {}),
        ttl_expired_locally: true,
      },
    },
  };
}

function buildUnverifiedBackendSnapshot(backend, detailReason) {
  const prevHealth = isPlainObject(backend?.health) ? backend.health : {};
  const prevOg = isPlainObject(prevHealth.opengrep) ? prevHealth.opengrep : {};
  const reasonsCheck = normalizeDegradedReasons(prevHealth.degraded_reasons);
  const nextReasons = reasonsCheck.reasons.includes('OPENGREP_NOT_VERIFIED')
    ? reasonsCheck.reasons
    : [...reasonsCheck.reasons, 'OPENGREP_NOT_VERIFIED'];
  return {
    ...backend,
    status: 'DEGRADED',
    ttlExpired: false,
    expiresAtMs: null,
    opengrepVerified: false,
    health: {
      ...prevHealth,
      degraded_reasons: nextReasons,
      opengrep: {
        ...prevOg,
        available: false,
        runtime_verified: false,
        probe_status: 'NOT_VERIFIED',
        health_state: 'NOT_VERIFIED',
        error: detailReason || prevOg.error || null,
      },
    },
  };
}

function hasVerifiedOpengrepProbe(backend, nowMs) {
  if (!backend || (backend.status !== 'CONNECTED' && backend.status !== 'DEGRADED')) return false;
  if (backend.ttlExpired || backend.serverCheckedAtMalformed || backend.healthWireMalformed) return false;
  const og = isPlainObject(backend.health?.opengrep) ? backend.health.opengrep : null;
  if (!og) return false;
  const ogInfo = describeOpengrepHealth(og, null, {
    nowMs,
    snapshotReceivedAtMs: backend.receivedAtMs ?? null,
    expiresAtMs: backend.expiresAtMs ?? null,
    serverCheckedAtMs: backend.serverCheckedAtMs ?? null,
    serverCheckedAtMalformed: Boolean(backend.serverCheckedAtMalformed),
    forceExpired: Boolean(backend.ttlExpired),
  });
  return ogInfo.isVerified;
}

/**
 * Classifies a raw /api/health payload into backend status without ever self-promoting
 * OpenGrep to VERIFIED if the payload lacks explicit verification proof, contradicts verification,
 * has malformed fields, or carries an already-expired TTL snapshot.
 * Tracks OpenGrep verification & TTL independently from overall API OK/DEGRADED status.
 */
export function classifyHealthResponse(rawHealth, {nowMs = Date.now(), receivedAtMs = null, serverCheckedAtMs = null} = {}) {
  const sanitizedRes = sanitizeHealthPayload(rawHealth);
  if (!sanitizedRes.valid || !sanitizedRes.health) {
    return {
      status: 'ERROR',
      health: null,
      error: 'Phản hồi /api/health không hợp lệ.',
      schemaWarnings: sanitizedRes.schemaWarnings,
      architectureInvalidFields: [],
      architectureMalformed: false,
      invalidBooleanFields: [],
      serverCheckedAtMalformed: false,
      healthWireMalformed: false,
      expiresAtMs: null,
      receivedAtMs: null,
      serverCheckedAtMs: null,
      ttlExpired: false,
      opengrepVerified: false,
    };
  }
  const health = sanitizedRes.health;
  const schemaWarnings = sanitizedRes.schemaWarnings;
  const validationMeta = {
    architectureInvalidFields: sanitizedRes.architectureInvalidFields,
    architectureMalformed: sanitizedRes.architectureMalformed,
    invalidBooleanFields: sanitizedRes.invalidBooleanFields,
    serverCheckedAtMalformed: Boolean(sanitizedRes.serverCheckedAtMalformed),
    healthWireMalformed: Boolean(sanitizedRes.healthWireMalformed),
  };
  const rawStatus = typeof health.status === 'string' ? health.status.trim().toUpperCase() : '';
  const effectiveReceivedAt = typeof receivedAtMs === 'number' && Number.isFinite(receivedAtMs) ? receivedAtMs : nowMs;
  const effectiveServerCheckedAt = validationMeta.serverCheckedAtMalformed
    ? null
    : ((typeof serverCheckedAtMs === 'number' && Number.isFinite(serverCheckedAtMs))
        ? serverCheckedAtMs
        : parseOpengrepTimestampMs(health.checked_at));

  if (rawStatus === 'AUTH_REQUIRED') {
    return {
      status: 'AUTH_REQUIRED',
      health,
      error: '',
      schemaWarnings,
      ...validationMeta,
      expiresAtMs: null,
      receivedAtMs: effectiveReceivedAt,
      serverCheckedAtMs: effectiveServerCheckedAt,
      ttlExpired: false,
      opengrepVerified: false,
    };
  }

  const hasOpengrep = Object.hasOwn(health, 'opengrep') && health.opengrep !== null && health.opengrep !== undefined;
  const og = isPlainObject(health.opengrep) ? health.opengrep : null;
  const ogInfo = hasOpengrep
    ? describeOpengrepHealth(health.opengrep, null, {
        nowMs,
        snapshotReceivedAtMs: effectiveReceivedAt,
        serverCheckedAtMs: effectiveServerCheckedAt,
        serverCheckedAtMalformed: validationMeta.serverCheckedAtMalformed,
        rootHealthObj: rawHealth,
      })
    : null;
  const expiresAtMs = og
    ? resolveOpengrepExpiresAtMs(og, effectiveReceivedAt, {
        serverCheckedAtMs: effectiveServerCheckedAt,
        serverCheckedAtMalformed: validationMeta.serverCheckedAtMalformed,
        rootHealthObj: rawHealth,
      })
    : null;
  const opengrepVerified = Boolean(ogInfo?.isVerified && !validationMeta.healthWireMalformed && !validationMeta.serverCheckedAtMalformed);

  if (rawStatus === 'OK') {
    if (ogInfo && ogInfo.ttlExpired) {
      return buildExpiredBackendSnapshot(
        {
          status: 'DEGRADED',
          health,
          error: '',
          schemaWarnings,
          ...validationMeta,
          expiresAtMs,
          receivedAtMs: effectiveReceivedAt,
          serverCheckedAtMs: effectiveServerCheckedAt,
          ttlExpired: true,
          opengrepVerified: false,
        },
        expiresAtMs,
      );
    }
    if ((hasOpengrep && !opengrepVerified) || schemaWarnings.length > 0) {
      return {
        status: 'DEGRADED',
        health,
        error: '',
        schemaWarnings,
        ...validationMeta,
        expiresAtMs: opengrepVerified ? expiresAtMs : null,
        receivedAtMs: effectiveReceivedAt,
        serverCheckedAtMs: effectiveServerCheckedAt,
        ttlExpired: false,
        opengrepVerified,
      };
    }
    return {
      status: 'CONNECTED',
      health,
      error: '',
      schemaWarnings,
      ...validationMeta,
      expiresAtMs: opengrepVerified ? expiresAtMs : null,
      receivedAtMs: effectiveReceivedAt,
      serverCheckedAtMs: effectiveServerCheckedAt,
      ttlExpired: false,
      opengrepVerified,
    };
  }

  if (rawStatus === 'DEGRADED') {
    if (ogInfo && ogInfo.ttlExpired && og?.probe_status !== 'EXPIRED') {
      return buildExpiredBackendSnapshot(
        {
          status: 'DEGRADED',
          health,
          error: '',
          schemaWarnings,
          ...validationMeta,
          expiresAtMs,
          receivedAtMs: effectiveReceivedAt,
          serverCheckedAtMs: effectiveServerCheckedAt,
          ttlExpired: true,
          opengrepVerified: false,
        },
        expiresAtMs,
      );
    }
    return {
      status: 'DEGRADED',
      health,
      error: '',
      schemaWarnings,
      ...validationMeta,
      expiresAtMs: opengrepVerified ? expiresAtMs : null,
      receivedAtMs: effectiveReceivedAt,
      serverCheckedAtMs: effectiveServerCheckedAt,
      ttlExpired: Boolean(ogInfo?.ttlExpired),
      opengrepVerified,
    };
  }

  return {
    status: 'ERROR',
    health: null,
    error: 'Phản hồi /api/health không hợp lệ.',
    schemaWarnings,
    ...validationMeta,
    expiresAtMs: null,
    receivedAtMs: effectiveReceivedAt,
    serverCheckedAtMs: effectiveServerCheckedAt,
    ttlExpired: false,
    opengrepVerified: false,
  };
}

export function createHealthMonitor(options = {}) {
  const hasCustomScopeKey = typeof options.getScopeKey === 'function';
  const hasCustomStorage = Object.hasOwn(options, 'storage');
  const hasCustomWallNow = typeof options.now === 'function';
  const {
    fetchHealth = (opts) => api.health(opts),
    getScopeKey = () => `${getApiBaseUrl()}|${getApiOrigin()}|${getAuthSessionScope()}`,
    onStateChange = () => {},
    retryDelaysMs = DEFAULT_PROBE_RETRY_DELAYS_MS,
    timeoutMs = 5000,
    setTimer = (fn, ms) => globalThis.setTimeout(fn, ms),
    clearTimer = (id) => globalThis.clearTimeout(id),
    now = () => Date.now(),
    monotonicNow: customMonotonicNow,
    storage: customStorage,
  } = options;
  const monoNow = createMonotonicClock({wallNow: now, customMonotonicNow, hasCustomWallNow});

  const schedule = Array.isArray(retryDelaysMs) ? retryDelaysMs.filter((n) => Number.isFinite(n) && n >= 0) : [];
  let disposed = false;
  let seq = 0;
  let ttlGeneration = 0;
  let activeController = null;
  let activePromise = null;
  let activeScopeKey = null;
  let retryTimerId = null;
  let ttlTimerId = null;
  let retryCount = 0;
  let activeVerifiedExpiresAtMs = null;
  let activeVerifiedMonoExpiresAtMs = null;
  let activeVerifiedProofSig = '';
  let activeSnapshotScopeKey = null;
  let lastAcceptedVerified = null; // { scopeKey, backend, expiresAtMs, monoExpiresAtMs, serverExpiresAtMs, orderMeta, proofSig }
  let seenVerifiedDeadlinesBySig = new Map(); // sig -> monotonic proof ledger record
  let seenProofOrderSeq = 0;
  let latestAcceptedProof = null; // { sig, firstSeenAtMs, firstSeenSeq }
  let watermarkOrder = null; // { probedAtMs, explicitExpiresMs, serverExpiresAtMs, processInstanceId }
  let hydratedPersistKey = null;
  let ledgerUntrusted = false;

  let snapshot = {
    backend: {
      status: 'CHECKING',
      health: null,
      error: '',
      schemaWarnings: [],
      architectureInvalidFields: [],
      architectureMalformed: false,
      invalidBooleanFields: [],
      expiresAtMs: null,
      receivedAtMs: null,
      serverCheckedAtMs: null,
      ttlExpired: false,
      opengrepVerified: false,
    },
    meta: {
      autoRechecking: false,
      retryAttempt: 0,
      maxRetries: schedule.length,
      retryExhausted: false,
      lastCheckedAt: null,
      inFlight: false,
      expiresAtMs: null,
      ttlExpired: false,
      staleSnapshotIgnored: false,
      scopeKey: '',
    },
  };

  function resolveStorage() {
    if (hasCustomStorage) return customStorage || null;
    if (hasCustomScopeKey) return null;
    try {
      return typeof window !== 'undefined' && window.sessionStorage ? window.sessionStorage : null;
    } catch {
      return null;
    }
  }

  function resolvePersistenceKey(scopeKey) {
    if (hasCustomStorage) {
      return typeof scopeKey === 'string' && scopeKey.trim() ? `custom|${scopeKey.trim()}` : null;
    }
    if (hasCustomScopeKey) return null;
    return getHealthPersistenceScopeKey();
  }

  function hydrateScopeLedger(scopeKey, currentNow) {
    const storage = resolveStorage();
    const persistKey = resolvePersistenceKey(scopeKey);
    if (!storage || !persistKey) return;
    if (hydratedPersistKey === persistKey) return;
    hydratedPersistKey = persistKey;
    const loaded = loadValidatedScopeLedger(storage, persistKey, currentNow);
    if (!loaded) return;
    if (loaded.corrupted) {
      if (isDefaultPersistence()) ledgerUntrusted = true;
      return;
    }

    // Strictly monotonic tightening: storage can NEVER promote VERIFIED; it only restores
    // previously clamped deadlines (preventing reload resurrection / TTL extension),
    // deterministic observation sequence numbers (preserving same-millisecond ordering across reload),
    // and server freshness watermarks (preventing older-snapshot resurrection across reload).
    if (loaded.nextOrderSeq > seenProofOrderSeq) {
      seenProofOrderSeq = loaded.nextOrderSeq;
    }
    for (const [sig, entry] of loaded.proofs.entries()) {
      const existing = seenVerifiedDeadlinesBySig.get(sig);
      const merged = existing ? mergeProofRecord(existing, entry) : {
        expiresAtMs: entry.expiresAtMs,
        firstSeenAtMs: entry.firstSeenAtMs,
        firstSeenSeq: positiveSafeInt(entry.firstSeenSeq),
        expired: Boolean(entry.expired),
        rollbackObserved: Boolean(entry.rollbackObserved),
        serverExpiresAtMs: finitePositiveNumber(entry.serverExpiresAtMs),
        lastServerCheckedAtMs: finitePositiveNumber(entry.lastServerCheckedAtMs),
        checkpointWallMs: finitePositiveNumber(entry.checkpointWallMs),
        checkpointRemainingMs: nonNegativeFiniteNumber(entry.checkpointRemainingMs),
        monoExpiresAtMs: null,
        firstSeenMonoMs: null,
      };
      if (merged.firstSeenSeq !== null && merged.firstSeenSeq > seenProofOrderSeq) {
        seenProofOrderSeq = merged.firstSeenSeq;
      }
      seenVerifiedDeadlinesBySig.set(sig, merged);
    }
    if (loaded.latestAcceptedProof) {
      if (!latestAcceptedProof || compareObservationOrder(latestAcceptedProof, loaded.latestAcceptedProof) === -1) {
        latestAcceptedProof = loaded.latestAcceptedProof;
      }
      if (loaded.latestAcceptedProof.firstSeenSeq !== null && loaded.latestAcceptedProof.firstSeenSeq > seenProofOrderSeq) {
        seenProofOrderSeq = loaded.latestAcceptedProof.firstSeenSeq;
      }
    }
    if (loaded.watermarkOrder) {
      if (shouldReplaceWatermark(loaded.watermarkOrder, watermarkOrder, {
        allowIncomparableProcess: false,
        preferredProofSig: latestAcceptedProof?.sig || '',
      })) {
        watermarkOrder = loaded.watermarkOrder;
      }
    }
  }

  function persistScopeLedger(scopeKey, currentNow) {
    const storage = resolveStorage();
    const persistKey = resolvePersistenceKey(scopeKey);
    if (!storage || !persistKey) return;
    const written = writeValidatedScopeLedger(
      storage,
      persistKey,
      watermarkOrder,
      seenVerifiedDeadlinesBySig,
      currentNow,
      {
        nextOrderSeq: seenProofOrderSeq,
        latestAcceptedProof,
        activeProofSig: lastAcceptedVerified?.proofSig || '',
      },
    );
    if (!written && isDefaultPersistence()) ledgerUntrusted = true;
  }

  function isDefaultPersistence() {
    return !hasCustomStorage && !hasCustomScopeKey;
  }

  // In the default browser path the anti-replay ledger lives in sessionStorage. If that storage is
  // missing, throws on read/write/remove, or holds a corrupted ledger, the ledger cannot be trusted
  // to remember expired proofs across reloads. This flag is sticky for the monitor lifetime and
  // makes verification conservative (server-clock anchoring via checked_at becomes mandatory).
  // Write capability is probed BEFORE the verification decision so the very first response is
  // already gated; a later persist failure re-applies the gate in the same check (see runCheck).
  function checkLedgerAvailability(storage) {
    if (!isDefaultPersistence() || ledgerUntrusted) return;
    if (!storage) {
      ledgerUntrusted = true;
      return;
    }
    try {
      const raw = storage.getItem(HEALTH_PROOF_LEDGER_STORAGE_KEY);
      if (raw !== null && raw !== undefined && raw !== '') {
        let ok = false;
        try {
          const parsed = JSON.parse(raw);
          ok = validateLedgerRootSchema(parsed);
        } catch {
          ok = false;
        }
        if (!ok) ledgerUntrusted = true;
      }
      storage.setItem(HEALTH_LEDGER_WRITE_PROBE_KEY, '1');
      storage.removeItem(HEALTH_LEDGER_WRITE_PROBE_KEY);
    } catch {
      ledgerUntrusted = true;
    }
  }

  function emit(nextBackend, nextMetaPatch = {}) {
    if (disposed) return;
    snapshot = {
      backend: nextBackend,
      meta: {
        ...snapshot.meta,
        ...nextMetaPatch,
      },
    };
    onStateChange(snapshot);
  }

  function clearRetryTimer() {
    if (retryTimerId !== null) {
      clearTimer(retryTimerId);
      retryTimerId = null;
    }
  }

  function clearTtlTimer() {
    if (ttlTimerId !== null) {
      clearTimer(ttlTimerId);
      ttlTimerId = null;
    }
  }

  function clearAllTimers() {
    clearRetryTimer();
    clearTtlTimer();
  }

  function resetScopeProofMemory() {
    activeVerifiedExpiresAtMs = null;
    activeVerifiedMonoExpiresAtMs = null;
    activeVerifiedProofSig = '';
    lastAcceptedVerified = null;
    seenVerifiedDeadlinesBySig.clear();
    seenProofOrderSeq = 0;
    latestAcceptedProof = null;
    watermarkOrder = null;
    hydratedPersistKey = null;
  }

  function abortActiveRequest() {
    if (activeController) {
      try {
        activeController.abort();
      } catch {
        // Ignore already-aborted controllers.
      }
      activeController = null;
    }
    activePromise = null;
    activeScopeKey = null;
  }

  function isProofFresh(wallDeadlineMs, monoDeadlineMs, currentWall, currentMono) {
    if (wallDeadlineMs === null || wallDeadlineMs === undefined || !Number.isFinite(wallDeadlineMs)) return false;
    if (currentWall >= wallDeadlineMs) return false;
    if (monoDeadlineMs !== null && monoDeadlineMs !== undefined && Number.isFinite(monoDeadlineMs) && currentMono >= monoDeadlineMs) {
      return false;
    }
    return true;
  }

  function markProofExpiredInLedger(proofSig, expiredAtMs, currentWall, currentMono = null) {
    if (!proofSig) return;
    const prev = seenVerifiedDeadlinesBySig.get(proofSig);
    if (!prev) return;
    const clampedWall = (typeof expiredAtMs === 'number' && Number.isFinite(expiredAtMs) && expiredAtMs > 0)
      ? Math.min(prev.expiresAtMs, expiredAtMs)
      : prev.expiresAtMs;
    const clampedMono = (
      currentMono !== null && Number.isFinite(currentMono)
        ? minOptionalNonNegative(prev.monoExpiresAtMs, currentMono)
        : prev.monoExpiresAtMs
    );
    seenVerifiedDeadlinesBySig.set(proofSig, {
      ...prev,
      expiresAtMs: clampedWall,
      monoExpiresAtMs: clampedMono,
      checkpointRemainingMs: 0,
      checkpointWallMs: finitePositiveNumber(currentWall) ?? prev.checkpointWallMs,
      expired: true,
    });
    if (activeSnapshotScopeKey) {
      persistScopeLedger(activeSnapshotScopeKey, currentWall);
    }
  }

  // Persists the active verified probe's monotonic remaining budget and wall-vs-monotonic
  // rollback detection into sessionStorage before document teardown (pagehide / dispose) so
  // reload never grants extra elapsed time after a client wall-clock rollback.
  function checkpointActiveProofToLedger() {
    if (!activeVerifiedProofSig || activeVerifiedMonoExpiresAtMs === null || !activeSnapshotScopeKey) return;
    const prev = seenVerifiedDeadlinesBySig.get(activeVerifiedProofSig);
    if (!prev) return;
    const currentWall = now();
    const currentMono = monoNow();
    const remainingMonoMs = Math.max(0, activeVerifiedMonoExpiresAtMs - currentMono);
    if (remainingMonoMs <= 0) {
      markProofExpiredInLedger(activeVerifiedProofSig, prev.expiresAtMs, currentWall, currentMono);
      return;
    }
    const wallAtRemaining = currentWall + remainingMonoMs;
    const nextWallDeadline = Number.isFinite(wallAtRemaining) && wallAtRemaining > 0
      ? Math.min(prev.expiresAtMs, wallAtRemaining)
      : prev.expiresAtMs;
    const wallWentBackward = Boolean(
      (prev.checkpointWallMs !== null && currentWall < prev.checkpointWallMs - CLOCK_ROLLBACK_TOLERANCE_MS)
      || currentWall < prev.firstSeenAtMs - CLOCK_ROLLBACK_TOLERANCE_MS,
    );
    const wallElapsed = currentWall - prev.firstSeenAtMs;
    const wallLaggedMonoWhileMoving = Boolean(
      prev.firstSeenMonoMs !== null
      && Number.isFinite(prev.firstSeenMonoMs)
      && wallElapsed > 0
      && ((currentMono - prev.firstSeenMonoMs) - wallElapsed) > CLOCK_ROLLBACK_TOLERANCE_MS,
    );
    const rollbackDetected = Boolean(prev.rollbackObserved || wallWentBackward || wallLaggedMonoWhileMoving);
    seenVerifiedDeadlinesBySig.set(activeVerifiedProofSig, {
      ...prev,
      expiresAtMs: nextWallDeadline,
      checkpointRemainingMs: minOptionalNonNegative(prev.checkpointRemainingMs, remainingMonoMs),
      checkpointWallMs: finitePositiveNumber(currentWall) ?? prev.checkpointWallMs,
      rollbackObserved: rollbackDetected,
    });
    persistScopeLedger(activeSnapshotScopeKey, currentWall);
  }

  const handlePageHide = () => {
    if (!disposed) checkpointActiveProofToLedger();
  };
  if (!hasCustomScopeKey && !hasCustomStorage && typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
    window.addEventListener('pagehide', handlePageHide);
  }

  function expireCurrentSnapshotIfNeeded(currentWall = now(), currentMono = monoNow()) {
    const expiringSig = lastAcceptedVerified?.proofSig || activeVerifiedProofSig || '';
    if (
      lastAcceptedVerified
      && !isProofFresh(lastAcceptedVerified.expiresAtMs, lastAcceptedVerified.monoExpiresAtMs, currentWall, currentMono)
    ) {
      markProofExpiredInLedger(lastAcceptedVerified.proofSig, lastAcceptedVerified.expiresAtMs, currentWall, currentMono);
      lastAcceptedVerified = null;
    }
    const activeExpired = (
      (activeVerifiedExpiresAtMs !== null && currentWall >= activeVerifiedExpiresAtMs)
      || (activeVerifiedMonoExpiresAtMs !== null && currentMono >= activeVerifiedMonoExpiresAtMs)
    );
    if (
      activeExpired
      && (snapshot.backend.status === 'CONNECTED' || snapshot.backend.status === 'DEGRADED' || snapshot.backend.status === 'CHECKING')
      && !snapshot.backend.ttlExpired
    ) {
      const expiredAt = activeVerifiedExpiresAtMs ?? snapshot.backend.expiresAtMs ?? currentWall;
      if (expiringSig) markProofExpiredInLedger(expiringSig, expiredAt, currentWall, currentMono);
      activeVerifiedExpiresAtMs = null;
      activeVerifiedMonoExpiresAtMs = null;
      activeVerifiedProofSig = '';
      lastAcceptedVerified = null;
      ttlGeneration += 1;
      clearTtlTimer();
      const downgraded = buildExpiredBackendSnapshot(snapshot.backend, expiredAt);
      const nextBackend = snapshot.backend.status === 'CHECKING'
        ? {...downgraded, status: 'CHECKING'}
        : downgraded;
      emit(nextBackend, {
        ttlExpired: true,
        expiresAtMs: expiredAt,
        autoRechecking: false,
        staleSnapshotIgnored: false,
      });
    }
  }

  function armTtlTimer(wallDeadlineMs, monoDeadlineMs, proofSig, scopeKey, generation) {
    clearTtlTimer();
    const currentWall = now();
    const currentMono = monoNow();
    const remainingWallMs = wallDeadlineMs - currentWall;
    const remainingMonoMs = monoDeadlineMs - currentMono;
    const remainingMs = Math.min(remainingWallMs, remainingMonoMs);
    if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
      expireCurrentSnapshotIfNeeded(currentWall, Math.max(currentMono, monoDeadlineMs));
      return;
    }
    const delayMs = Math.max(1, Math.min(remainingMs, MAX_SAFE_TIMER_DELAY_MS));
    const isFinalHop = remainingMs <= MAX_SAFE_TIMER_DELAY_MS;
    let scheduledId = null;
    scheduledId = setTimer(() => {
      if (disposed || generation !== ttlGeneration || getScopeKey() !== scopeKey || activeVerifiedProofSig !== proofSig) {
        return;
      }
      if (ttlTimerId === scheduledId) {
        ttlTimerId = null;
      }
      const firedWall = now();
      const firedMono = monoNow();
      if (isFinalHop || firedMono >= monoDeadlineMs || firedWall >= wallDeadlineMs) {
        expireCurrentSnapshotIfNeeded(firedWall, Math.max(firedMono, monoDeadlineMs));
      } else {
        armTtlTimer(wallDeadlineMs, monoDeadlineMs, proofSig, scopeKey, generation);
      }
    }, delayMs);
    ttlTimerId = scheduledId;
  }

  // Enforces the monotonic TTL timer invariant per probe identity:
  // - Same active probe with equal or looser monotonic deadline: keep exact active timer untouched.
  // - Same active probe with strictly tighter monotonic deadline: re-arm strictly earlier.
  // - New distinct valid probe: replace timer with the new probe's monotonic deadline.
  // - Unverified / expired / error state: clear timer and active tracking.
  function syncActiveTtlTimer({verified, proofSig, wallDeadlineMs, monoDeadlineMs, scopeKey, checkedAtWall, checkedAtMono}) {
    if (
      !verified
      || !proofSig
      || !isProofFresh(wallDeadlineMs, monoDeadlineMs, checkedAtWall, checkedAtMono)
    ) {
      if (ttlTimerId !== null || activeVerifiedProofSig || activeVerifiedExpiresAtMs !== null || activeVerifiedMonoExpiresAtMs !== null) {
        ttlGeneration += 1;
        clearTtlTimer();
      }
      activeVerifiedExpiresAtMs = null;
      activeVerifiedMonoExpiresAtMs = null;
      activeVerifiedProofSig = '';
      return;
    }
    if (
      ttlTimerId !== null
      && activeVerifiedProofSig === proofSig
      && activeVerifiedMonoExpiresAtMs !== null
      && monoDeadlineMs >= activeVerifiedMonoExpiresAtMs
    ) {
      // Keep the existing active timer untouched; never cancel or extend on same-probe replay.
      activeVerifiedExpiresAtMs = activeVerifiedExpiresAtMs !== null
        ? Math.min(activeVerifiedExpiresAtMs, wallDeadlineMs)
        : wallDeadlineMs;
      return;
    }
    ttlGeneration += 1;
    clearTtlTimer();
    activeVerifiedExpiresAtMs = wallDeadlineMs;
    activeVerifiedMonoExpiresAtMs = monoDeadlineMs;
    activeVerifiedProofSig = proofSig;
    armTtlTimer(wallDeadlineMs, monoDeadlineMs, proofSig, scopeKey, ttlGeneration);
  }

  // Records and monotonically clamps the tightest observed wall, server, and monotonic deadlines
  // for a structurally valid, identifiable probe execution — decoupled from VERIFIED promotion so
  // proofs first observed expired, replayed after a client wall-clock rollback, tightened after a
  // rollback, or replayed across reload with broken time continuity can NEVER gain elapsed TTL.
  function recordAndClampProbeDeadline(og, evidence, checkedAtWall, checkedAtMono, {expired = false, serverCheckedAtMs = null} = {}) {
    if (!isPlainObject(og) || !evidence || !evidence.hasVerifiableBasis || evidence.contradictory || evidence.malformed || evidence.expiresAtMs === null) {
      return {expiresAtMs: null, monoExpiresAtMs: null, serverExpiresAtMs: null, proofSig: '', expired: false};
    }
    const proofSig = buildProbeProofSignature(og, evidence);
    if (!proofSig) return {expiresAtMs: null, monoExpiresAtMs: null, serverExpiresAtMs: null, proofSig: '', expired: false};
    const rawWallDeadline = expired ? Math.min(evidence.expiresAtMs, checkedAtWall) : evidence.expiresAtMs;
    if (!Number.isFinite(rawWallDeadline) || rawWallDeadline <= 0) {
      return {expiresAtMs: null, monoExpiresAtMs: null, serverExpiresAtMs: null, proofSig: '', expired: false};
    }
    const incomingServerExpiresAtMs = finitePositiveNumber(evidence.serverExpiresAtMs);
    const incomingServerCheckedAtMs = finitePositiveNumber(serverCheckedAtMs);
    const incomingRemainingMs = expired ? 0 : Math.max(0, rawWallDeadline - checkedAtWall);

    if (seenVerifiedDeadlinesBySig.has(proofSig)) {
      const prev = seenVerifiedDeadlinesBySig.get(proofSig);
      const clampedWall = Math.min(rawWallDeadline, prev.expiresAtMs);
      const prevServerExp = finitePositiveNumber(prev.serverExpiresAtMs);
      const clampedServerExp = minOptionalFinite(prevServerExp, incomingServerExpiresAtMs);
      const serverTightenDeltaMs = (
        prevServerExp !== null
        && incomingServerExpiresAtMs !== null
        && incomingServerExpiresAtMs < prevServerExp
      ) ? (prevServerExp - incomingServerExpiresAtMs) : 0;
      const monoCapFromIncoming = checkedAtMono + incomingRemainingMs;

      let clampedMono;
      let isExpired;
      let rollbackObserved = Boolean(prev.rollbackObserved);

      if (prev.monoExpiresAtMs !== null && Number.isFinite(prev.monoExpiresAtMs)) {
        // Same-document observation: monotonic deadline can only stay equal or move strictly earlier.
        const monoCapFromPrev = prev.monoExpiresAtMs - serverTightenDeltaMs;
        clampedMono = expired
          ? Math.min(prev.monoExpiresAtMs, checkedAtMono)
          : Math.min(prev.monoExpiresAtMs, monoCapFromPrev, monoCapFromIncoming);
        const wallWentBackward = Boolean(
          (prev.checkpointWallMs !== null && checkedAtWall < prev.checkpointWallMs - CLOCK_ROLLBACK_TOLERANCE_MS)
          || checkedAtWall < prev.firstSeenAtMs - CLOCK_ROLLBACK_TOLERANCE_MS,
        );
        const wallElapsed = checkedAtWall - prev.firstSeenAtMs;
        const wallLaggedMonoWhileMoving = Boolean(
          prev.firstSeenMonoMs !== null
          && Number.isFinite(prev.firstSeenMonoMs)
          && wallElapsed > 0
          && ((checkedAtMono - prev.firstSeenMonoMs) - wallElapsed) > CLOCK_ROLLBACK_TOLERANCE_MS,
        );
        if (wallWentBackward || wallLaggedMonoWhileMoving) {
          rollbackObserved = true;
        }
        isExpired = Boolean(prev.expired || expired || clampedWall <= checkedAtWall || clampedMono <= checkedAtMono);
      } else {
        // Hydrated from sessionStorage across document reload (new monotonic origin).
        const prevCheckpointWall = finitePositiveNumber(prev.checkpointWallMs);
        const prevCheckpointRem = nonNegativeFiniteNumber(prev.checkpointRemainingMs);
        const rollbackAcrossReload = Boolean(
          prev.rollbackObserved
          || checkedAtWall < prev.firstSeenAtMs - CLOCK_ROLLBACK_TOLERANCE_MS
          || (prevCheckpointWall !== null && checkedAtWall < prevCheckpointWall - CLOCK_ROLLBACK_TOLERANCE_MS),
        );
        if (rollbackAcrossReload) rollbackObserved = true;
        const prevSrvChecked = finitePositiveNumber(prev.lastServerCheckedAtMs);
        const serverClockAdvanced = Boolean(
          incomingServerCheckedAtMs !== null
          && prevSrvChecked !== null
          && incomingServerCheckedAtMs > prevSrvChecked
          && clampedServerExp !== null
          && incomingServerCheckedAtMs < clampedServerExp,
        );
        if (rollbackAcrossReload && !serverClockAdvanced) {
          // Wall-clock rollback across reload without a fresher server checked_at: cannot prove
          // monotonic time continuity across documents, so fail closed conservatively.
          clampedMono = checkedAtMono;
          isExpired = true;
        } else {
          let reloadBudgetMs = Math.min(Math.max(0, clampedWall - checkedAtWall), incomingRemainingMs);
          if (prevCheckpointRem !== null) {
            const reloadGapMs = prevCheckpointWall !== null ? Math.max(0, checkedAtWall - prevCheckpointWall) : 0;
            const checkpointBudget = Math.max(0, prevCheckpointRem - reloadGapMs - serverTightenDeltaMs);
            reloadBudgetMs = Math.min(reloadBudgetMs, checkpointBudget);
          }
          clampedMono = expired ? checkedAtMono : checkedAtMono + reloadBudgetMs;
          isExpired = Boolean(prev.expired || expired || clampedWall <= checkedAtWall || clampedMono <= checkedAtMono);
        }
      }

      const remainingAfterClamp = isExpired ? 0 : Math.max(0, clampedMono - checkedAtMono);
      seenVerifiedDeadlinesBySig.set(proofSig, {
        expiresAtMs: clampedWall,
        monoExpiresAtMs: clampedMono,
        firstSeenAtMs: prev.firstSeenAtMs,
        firstSeenMonoMs: prev.firstSeenMonoMs ?? checkedAtMono,
        firstSeenSeq: positiveSafeInt(prev.firstSeenSeq),
        serverExpiresAtMs: clampedServerExp,
        lastServerCheckedAtMs: maxOptionalFinite(prev.lastServerCheckedAtMs, incomingServerCheckedAtMs),
        checkpointWallMs: finitePositiveNumber(checkedAtWall) ?? prev.checkpointWallMs,
        checkpointRemainingMs: minOptionalNonNegative(prev.checkpointRemainingMs, remainingAfterClamp),
        rollbackObserved,
        expired: isExpired,
      });
      return {
        expiresAtMs: clampedWall,
        monoExpiresAtMs: clampedMono,
        serverExpiresAtMs: clampedServerExp,
        proofSig,
        expired: isExpired,
      };
    }

    if (seenVerifiedDeadlinesBySig.size >= MAX_SEEN_PROOF_SIGNATURES) {
      let evictKey = null;
      let evictMeta = null;
      for (const [k, meta] of seenVerifiedDeadlinesBySig.entries()) {
        if (k === lastAcceptedVerified?.proofSig || k === latestAcceptedProof?.sig || k === activeVerifiedProofSig) continue;
        if (!evictMeta || compareObservationOrder(meta, evictMeta) === -1) {
          evictKey = k;
          evictMeta = meta;
        }
      }
      if (evictKey === null) evictKey = seenVerifiedDeadlinesBySig.keys().next().value;
      if (evictKey !== undefined && evictKey !== null) seenVerifiedDeadlinesBySig.delete(evictKey);
    }
    seenProofOrderSeq += 1;
    const monoDeadline = expired ? checkedAtMono : checkedAtMono + incomingRemainingMs;
    const isExpired = Boolean(expired || rawWallDeadline <= checkedAtWall || monoDeadline <= checkedAtMono);
    seenVerifiedDeadlinesBySig.set(proofSig, {
      expiresAtMs: rawWallDeadline,
      monoExpiresAtMs: monoDeadline,
      firstSeenAtMs: checkedAtWall,
      firstSeenMonoMs: checkedAtMono,
      firstSeenSeq: seenProofOrderSeq,
      serverExpiresAtMs: incomingServerExpiresAtMs,
      lastServerCheckedAtMs: incomingServerCheckedAtMs,
      checkpointWallMs: finitePositiveNumber(checkedAtWall),
      checkpointRemainingMs: isExpired ? 0 : incomingRemainingMs,
      rollbackObserved: false,
      expired: isExpired,
    });
    return {
      expiresAtMs: rawWallDeadline,
      monoExpiresAtMs: monoDeadline,
      serverExpiresAtMs: incomingServerExpiresAtMs,
      proofSig,
      expired: isExpired,
    };
  }

  function runCheck({force = false, isRetry = false, preserveStatus = false} = {}) {
    if (disposed) return Promise.resolve(snapshot);
    const scopeKey = getScopeKey();

    // Single-flight guard: coalesce duplicate non-forced requests for the same scope.
    if (!force && activePromise && activeScopeKey === scopeKey) {
      return activePromise;
    }

    const scopeChanged = activeSnapshotScopeKey !== null && activeSnapshotScopeKey !== scopeKey;
    if (scopeChanged) {
      ttlGeneration += 1;
      clearAllTimers();
      resetScopeProofMemory();
    } else {
      // Preserve an active TTL timer handle and `lastAcceptedVerified` across same-scope
      // refreshes so: (a) a probe still expires passively if a refresh stalls past deadline,
      // and (b) if an older server snapshot arrives, the exact active TTL timer handle and
      // accepted probe continue running completely uninterrupted.
      clearRetryTimer();
    }

    if (activeController) {
      abortActiveRequest();
    }

    if (!isRetry) {
      retryCount = 0;
    }

    seq += 1;
    const requestSeq = seq;
    const controller = new AbortController();
    activeController = controller;
    activeScopeKey = scopeKey;

    if (!preserveStatus) {
      emit(
        {
          ...snapshot.backend,
          status: 'CHECKING',
          error: '',
          ...(activeSnapshotScopeKey !== scopeKey
            ? {
                health: null,
                schemaWarnings: [],
                architectureInvalidFields: [],
                architectureMalformed: false,
                invalidBooleanFields: [],
                expiresAtMs: null,
                serverCheckedAtMs: null,
                ttlExpired: false,
                opengrepVerified: false,
              }
            : {}),
        },
        {
          inFlight: true,
          autoRechecking: isRetry,
          retryAttempt: retryCount,
          retryExhausted: false,
          staleSnapshotIgnored: false,
          scopeKey,
        },
      );
    } else {
      emit(snapshot.backend, {
        inFlight: true,
        autoRechecking: isRetry,
        retryAttempt: retryCount,
        staleSnapshotIgnored: false,
        scopeKey,
      });
    }

    const isStale = () => (
      disposed
      || requestSeq !== seq
      || controller.signal.aborted
      || getScopeKey() !== scopeKey
    );

    let initialPromise;
    try {
      initialPromise = Promise.resolve(fetchHealth({signal: controller.signal, timeoutMs}));
    } catch (syncError) {
      initialPromise = Promise.reject(syncError);
    }

    const promise = initialPromise
      .then((rawHealth) => {
        if (isStale()) return snapshot;
        activeController = null;
        activePromise = null;
        activeScopeKey = null;

        const checkedAt = now();
        const checkedAtMono = monoNow();
        if (activeSnapshotScopeKey !== null && activeSnapshotScopeKey !== scopeKey) {
          resetScopeProofMemory();
        }
        activeSnapshotScopeKey = scopeKey;
        checkLedgerAvailability(resolveStorage());
        hydrateScopeLedger(scopeKey, checkedAt);

        // Verify whether any previously accepted verified probe for this scope is STILL fresh
        // against BOTH wall clock and monotonic clock right now.
        const hasFreshAcceptedVerified = Boolean(
          lastAcceptedVerified
          && lastAcceptedVerified.scopeKey === scopeKey
          && isProofFresh(lastAcceptedVerified.expiresAtMs, lastAcceptedVerified.monoExpiresAtMs, checkedAt, checkedAtMono),
        );
        if (lastAcceptedVerified && !hasFreshAcceptedVerified) {
          markProofExpiredInLedger(lastAcceptedVerified.proofSig, lastAcceptedVerified.expiresAtMs, checkedAt, checkedAtMono);
          lastAcceptedVerified = null;
        }

        const serverCheckedAtMs = isPlainObject(rawHealth) ? parseOpengrepTimestampMs(rawHealth.checked_at) : null;
        let nextBackend = classifyHealthResponse(rawHealth, {
          nowMs: checkedAt,
          receivedAtMs: checkedAt,
          serverCheckedAtMs,
        });
        const og = isPlainObject(nextBackend.health?.opengrep) ? nextBackend.health.opengrep : null;
        const rawOg = isPlainObject(rawHealth?.opengrep) ? rawHealth.opengrep : og;
        const anchoredServerCheckedAt = nextBackend.serverCheckedAtMs ?? serverCheckedAtMs;
        const incomingExpiry = rawOg
          ? resolveOpengrepExpiryEvidence(rawOg, checkedAt, {
              serverCheckedAtMs: anchoredServerCheckedAt,
              serverCheckedAtMalformed: Boolean(nextBackend.serverCheckedAtMalformed),
              rootHealthObj: rawHealth,
            })
          : null;
        const incomingOgInfo = og
          ? describeOpengrepHealth(og, null, {
              nowMs: checkedAt,
              snapshotReceivedAtMs: checkedAt,
              expiresAtMs: nextBackend.expiresAtMs ?? null,
              serverCheckedAtMs: anchoredServerCheckedAt,
              serverCheckedAtMalformed: Boolean(nextBackend.serverCheckedAtMalformed),
              rootHealthObj: rawHealth,
              forceExpired: Boolean(nextBackend.ttlExpired),
            })
          : null;
        const hasValidStructuredProofEvidence = Boolean(
          (nextBackend.status === 'CONNECTED' || nextBackend.status === 'DEGRADED')
          && !nextBackend.healthWireMalformed
          && !nextBackend.serverCheckedAtMalformed
          && og
          && og.malformed !== true
          && incomingOgInfo
          && !incomingOgInfo.malformed
          && incomingExpiry
          && incomingExpiry.hasVerifiableBasis
          && !incomingExpiry.malformed
          && !incomingExpiry.contradictory
          && incomingExpiry.expiresAtMs !== null
          && Number.isFinite(incomingExpiry.expiresAtMs),
        );
        const incomingOrder = hasValidStructuredProofEvidence
          ? extractProbeOrderMeta(og, incomingExpiry)
          : null;
        const initiallyVerifiedBeforeLedgerGate = hasVerifiedOpengrepProbe(nextBackend, checkedAt);
        let opengrepIsVerified = initiallyVerifiedBeforeLedgerGate;
        if (opengrepIsVerified && ledgerUntrusted && (anchoredServerCheckedAt === null || anchoredServerCheckedAt === undefined)) {
          nextBackend = buildUnverifiedBackendSnapshot(nextBackend, UNANCHORED_LEDGER_REASON);
          opengrepIsVerified = false;
        }
        const isExpiredProbeEvidence = Boolean(
          hasValidStructuredProofEvidence
          && (nextBackend.ttlExpired || incomingOgInfo.ttlExpired),
        );
        const shouldAdvanceWatermark = Boolean(
          hasValidStructuredProofEvidence
          && (opengrepIsVerified || isExpiredProbeEvidence),
        );
        const shouldRecordProofDeadline = Boolean(
          hasValidStructuredProofEvidence
          && (initiallyVerifiedBeforeLedgerGate || opengrepIsVerified || isExpiredProbeEvidence),
        );

        const orderVsWatermark = incomingOrder && watermarkOrder
          ? compareProbeEvidenceOrder(incomingOrder, watermarkOrder)
          : 'NONE';
        const orderVsAccepted = incomingOrder && hasFreshAcceptedVerified && lastAcceptedVerified.orderMeta
          ? compareProbeEvidenceOrder(incomingOrder, lastAcceptedVerified.orderMeta)
          : 'NONE';
        const isOlderByOrder = orderVsWatermark === 'OLDER' || orderVsAccepted === 'OLDER';
        // Without probed_at, deadlines cannot order two runs. A proof whose identity was already seen
        // BEFORE the currently accepted fresh proof is an older run re-sent by the server and must not
        // displace (or expire) the accepted proof.
        const incomingSig = hasValidStructuredProofEvidence ? buildProbeProofSignature(og, incomingExpiry) : '';
        const incomingSeen = incomingSig ? seenVerifiedDeadlinesBySig.get(incomingSig) : null;
        const acceptedSeen = hasFreshAcceptedVerified && lastAcceptedVerified.proofSig
          ? seenVerifiedDeadlinesBySig.get(lastAcceptedVerified.proofSig)
          : null;
        const isKnownOlderThanActive = Boolean(
          hasFreshAcceptedVerified
          && incomingSig
          && incomingSig !== lastAcceptedVerified.proofSig
          && incomingSeen
          && acceptedSeen
          && compareObservationOrder(incomingSeen, acceptedSeen) === -1,
        );
        const isKnownOlderThanLatestAccepted = Boolean(
          !hasFreshAcceptedVerified
          && incomingSig
          && latestAcceptedProof
          && incomingSig !== latestAcceptedProof.sig
          && incomingSeen
          && compareObservationOrder(incomingSeen, latestAcceptedProof) === -1,
        );
        const isKnownOlderProof = isKnownOlderThanActive || isKnownOlderThanLatestAccepted;
        const isOlderServerSnapshot = isOlderByOrder || isKnownOlderProof;

        // Invariant F02.1: An older server snapshot MUST NEVER overwrite a still-fresh accepted
        // probe in the same URL/session scope — preserve the fresher probe, its exact deadline,
        // its exact presentation across Header/Sidebar/StatusPage, and its exact active TTL timer handle.
        if (isOlderServerSnapshot && hasFreshAcceptedVerified) {
          const preserved = lastAcceptedVerified;
          syncActiveTtlTimer({
            verified: true,
            proofSig: preserved.proofSig,
            wallDeadlineMs: preserved.expiresAtMs,
            monoDeadlineMs: preserved.monoExpiresAtMs,
            scopeKey,
            checkedAtWall: checkedAt,
            checkedAtMono,
          });
          emit(preserved.backend, {
            inFlight: false,
            autoRechecking: false,
            retryAttempt: retryCount,
            maxRetries: schedule.length,
            retryExhausted: false,
            lastCheckedAt: checkedAt,
            expiresAtMs: activeVerifiedExpiresAtMs,
            ttlExpired: false,
            staleSnapshotIgnored: true,
            scopeKey,
          });
          return snapshot;
        }

        if (opengrepIsVerified && orderVsWatermark === 'UNANCHORED_DROP_PROBED_AT' && hasFreshAcceptedVerified) {
          const preserved = lastAcceptedVerified;
          syncActiveTtlTimer({
            verified: true,
            proofSig: preserved.proofSig,
            wallDeadlineMs: preserved.expiresAtMs,
            monoDeadlineMs: preserved.monoExpiresAtMs,
            scopeKey,
            checkedAtWall: checkedAt,
            checkedAtMono,
          });
          emit(preserved.backend, {
            inFlight: false,
            autoRechecking: false,
            retryAttempt: retryCount,
            maxRetries: schedule.length,
            retryExhausted: false,
            lastCheckedAt: checkedAt,
            expiresAtMs: activeVerifiedExpiresAtMs,
            ttlExpired: false,
            staleSnapshotIgnored: true,
            scopeKey,
          });
          return snapshot;
        }

        let nextVerifiedProofSig = '';
        let nextVerifiedMonoDeadline = null;

        // Anti-resurrection when no fresh probe is active (e.g. newer probe already expired or after reload):
        // an older server snapshot must NEVER resurrect VERIFIED.
        if (isOlderServerSnapshot) {
          lastAcceptedVerified = null;
          let clampedStaleDeadline = null;
          if (shouldRecordProofDeadline) {
            clampedStaleDeadline = recordAndClampProbeDeadline(og, incomingExpiry, checkedAt, checkedAtMono, {
              expired: true,
              serverCheckedAtMs: anchoredServerCheckedAt,
            }).expiresAtMs;
          }
          if (opengrepIsVerified) {
            const staleDeadline = clampedStaleDeadline ?? (incomingExpiry?.expiresAtMs ?? checkedAt);
            nextBackend = buildExpiredBackendSnapshot(nextBackend, Math.min(staleDeadline, checkedAt));
            opengrepIsVerified = false;
          }
          if (nextBackend.status !== 'AUTH_REQUIRED') {
            persistScopeLedger(scopeKey, checkedAt);
          }
        } else if (opengrepIsVerified && orderVsWatermark === 'UNANCHORED_DROP_PROBED_AT') {
          if (incomingSeen && (incomingSeen.expired || incomingSeen.expiresAtMs <= checkedAt)) {
            const clampedRes = recordAndClampProbeDeadline(og, incomingExpiry, checkedAt, checkedAtMono, {
              expired: true,
              serverCheckedAtMs: anchoredServerCheckedAt,
            });
            const clampedDeadline = clampedRes.expiresAtMs ?? incomingSeen.expiresAtMs;
            nextBackend = buildExpiredBackendSnapshot(nextBackend, clampedDeadline);
            opengrepIsVerified = false;
            lastAcceptedVerified = null;
            if (nextBackend.status !== 'AUTH_REQUIRED') {
              persistScopeLedger(scopeKey, checkedAt);
            }
          } else {
            nextBackend = buildUnverifiedBackendSnapshot(
              nextBackend,
              'Snapshot OpenGrep thiếu probed_at nên không thể xác định thứ tự mới hơn so với bằng chứng trước đó; giữ trạng thái chưa xác minh.',
            );
            opengrepIsVerified = false;
            lastAcceptedVerified = null;
          }
        } else {
          // Advance freshness watermark strictly from structurally valid, verifiable probe proofs
          // that were accepted as VERIFIED or observed EXPIRED (never malformed payloads and never
          // unverified snapshots rejected by the untrusted-storage ledger gate).
          if (incomingOrder && shouldAdvanceWatermark) {
            if (!watermarkOrder || orderVsWatermark === 'NEWER' || orderVsWatermark === 'INCOMPARABLE_PROCESS') {
              watermarkOrder = incomingOrder;
            }
          }

          // OpenGrep TTL lifecycle is decoupled from VERIFIED promotion and from overall API
          // OK/DEGRADED status: any structurally valid, identifiable probe evidence (whether
          // verified, initially observed already expired, or gated by untrusted storage) has its
          // tightest observed wall, server, and monotonic deadlines recorded and clamped across
          // refresh/reload.
          const deadlineRes = shouldRecordProofDeadline
            ? recordAndClampProbeDeadline(og, incomingExpiry, checkedAt, checkedAtMono, {
                expired: isExpiredProbeEvidence,
                serverCheckedAtMs: anchoredServerCheckedAt,
              })
            : {expiresAtMs: null, monoExpiresAtMs: null, serverExpiresAtMs: null, proofSig: '', expired: false};
          const effectiveDeadline = deadlineRes.expiresAtMs;
          const effectiveMonoDeadline = deadlineRes.monoExpiresAtMs;

          const prevLatestAcceptedProof = latestAcceptedProof;
          if (opengrepIsVerified && (effectiveDeadline === null || effectiveMonoDeadline === null)) {
            nextBackend = {
              ...nextBackend,
              status: 'DEGRADED',
              expiresAtMs: null,
              opengrepVerified: false,
            };
            opengrepIsVerified = false;
            lastAcceptedVerified = null;
          } else if (opengrepIsVerified && (deadlineRes.expired || !isProofFresh(effectiveDeadline, effectiveMonoDeadline, checkedAt, checkedAtMono))) {
            nextBackend = buildExpiredBackendSnapshot(nextBackend, effectiveDeadline);
            opengrepIsVerified = false;
            lastAcceptedVerified = null;
          } else if (opengrepIsVerified && effectiveDeadline !== null && effectiveMonoDeadline !== null) {
            nextBackend = {
              ...nextBackend,
              expiresAtMs: effectiveDeadline,
              serverCheckedAtMs: nextBackend.serverCheckedAtMs ?? serverCheckedAtMs,
            };
            const clampedOrderMeta = incomingOrder
              ? {
                  ...incomingOrder,
                  explicitExpiresMs: deadlineRes.serverExpiresAtMs ?? incomingOrder.explicitExpiresMs,
                  serverExpiresAtMs: deadlineRes.serverExpiresAtMs ?? incomingOrder.serverExpiresAtMs,
                }
              : incomingOrder;
            if (
              clampedOrderMeta
              && shouldReplaceWatermark(clampedOrderMeta, watermarkOrder, {
                allowIncomparableProcess: true,
                preferredProofSig: deadlineRes.proofSig,
              })
            ) {
              watermarkOrder = clampedOrderMeta;
            }
            nextVerifiedProofSig = deadlineRes.proofSig;
            nextVerifiedMonoDeadline = effectiveMonoDeadline;
            lastAcceptedVerified = {
              scopeKey,
              backend: nextBackend,
              expiresAtMs: effectiveDeadline,
              monoExpiresAtMs: effectiveMonoDeadline,
              serverExpiresAtMs: deadlineRes.serverExpiresAtMs,
              orderMeta: clampedOrderMeta,
              proofSig: deadlineRes.proofSig,
            };
            const acceptedRecord = deadlineRes.proofSig ? seenVerifiedDeadlinesBySig.get(deadlineRes.proofSig) : null;
            if (acceptedRecord) {
              const candidateLap = {
                sig: deadlineRes.proofSig,
                firstSeenAtMs: acceptedRecord.firstSeenAtMs,
                firstSeenSeq: positiveSafeInt(acceptedRecord.firstSeenSeq),
              };
              if (!latestAcceptedProof || compareObservationOrder(latestAcceptedProof, candidateLap) === -1) {
                latestAcceptedProof = candidateLap;
              }
            }
          } else {
            if (
              isExpiredProbeEvidence
              && effectiveDeadline !== null
              && (nextBackend.expiresAtMs === null || nextBackend.expiresAtMs > effectiveDeadline)
            ) {
              nextBackend = buildExpiredBackendSnapshot(nextBackend, effectiveDeadline);
            }
            lastAcceptedVerified = null;
          }

          if (nextBackend.status !== 'AUTH_REQUIRED') {
            persistScopeLedger(scopeKey, checkedAt);
          }
          // Re-apply the ledger gate in this same check if persisting just revealed a write failure.
          if (opengrepIsVerified && ledgerUntrusted && (anchoredServerCheckedAt === null || anchoredServerCheckedAt === undefined)) {
            nextBackend = buildUnverifiedBackendSnapshot(nextBackend, UNANCHORED_LEDGER_REASON);
            opengrepIsVerified = false;
            nextVerifiedProofSig = '';
            nextVerifiedMonoDeadline = null;
            lastAcceptedVerified = null;
            latestAcceptedProof = prevLatestAcceptedProof;
          }
        }

        const needsRecheck = shouldAutoRecheckHealth(nextBackend.health, {
          nowMs: checkedAt,
          snapshotReceivedAtMs: checkedAt,
          expiresAtMs: nextBackend.expiresAtMs ?? null,
          serverCheckedAtMs: nextBackend.serverCheckedAtMs ?? serverCheckedAtMs,
          serverCheckedAtMalformed: Boolean(nextBackend.serverCheckedAtMalformed),
          rootHealthObj: rawHealth,
          forceExpired: Boolean(nextBackend.ttlExpired),
        });

        syncActiveTtlTimer({
          verified: opengrepIsVerified,
          proofSig: nextVerifiedProofSig,
          wallDeadlineMs: opengrepIsVerified ? nextBackend.expiresAtMs : null,
          monoDeadlineMs: opengrepIsVerified ? nextVerifiedMonoDeadline : null,
          scopeKey,
          checkedAtWall: checkedAt,
          checkedAtMono,
        });

        if (needsRecheck && retryCount < schedule.length) {
          const delayMs = schedule[retryCount];
          const scheduledSeq = requestSeq;
          const nextAttempt = retryCount + 1;
          emit(nextBackend, {
            inFlight: false,
            autoRechecking: true,
            retryAttempt: nextAttempt,
            maxRetries: schedule.length,
            retryExhausted: false,
            lastCheckedAt: checkedAt,
            expiresAtMs: activeVerifiedExpiresAtMs ?? nextBackend.expiresAtMs ?? null,
            ttlExpired: Boolean(nextBackend.ttlExpired),
            staleSnapshotIgnored: false,
            scopeKey,
          });
          let scheduledRetryId = null;
          scheduledRetryId = setTimer(() => {
            if (disposed || scheduledSeq !== seq || getScopeKey() !== scopeKey) return;
            if (retryTimerId === scheduledRetryId) retryTimerId = null;
            retryCount += 1;
            runCheck({force: true, isRetry: true, preserveStatus: true});
          }, delayMs);
          retryTimerId = scheduledRetryId;
        } else {
          emit(nextBackend, {
            inFlight: false,
            autoRechecking: false,
            retryAttempt: retryCount,
            maxRetries: schedule.length,
            retryExhausted: Boolean(needsRecheck && retryCount >= schedule.length),
            lastCheckedAt: checkedAt,
            expiresAtMs: activeVerifiedExpiresAtMs ?? nextBackend.expiresAtMs ?? null,
            ttlExpired: Boolean(nextBackend.ttlExpired),
            staleSnapshotIgnored: false,
            scopeKey,
          });
        }
        return snapshot;
      })
      .catch((error) => {
        if (isStale() || error?.abortedByConfigChange || error?.name === 'AbortError') {
          return snapshot;
        }
        activeController = null;
        activePromise = null;
        activeScopeKey = null;
        activeVerifiedExpiresAtMs = null;
        activeVerifiedMonoExpiresAtMs = null;
        activeVerifiedProofSig = '';
        lastAcceptedVerified = null;
        ttlGeneration += 1;
        clearTtlTimer();

        const checkedAt = now();
        activeSnapshotScopeKey = scopeKey;
        const nextBackend = error?.status === 401
          ? {
              status: 'AUTH_REQUIRED',
              health: null,
              error: error?.message || 'Yêu cầu Bearer Token hợp lệ (HTTP 401).',
              schemaWarnings: [],
              architectureInvalidFields: [],
              architectureMalformed: false,
              invalidBooleanFields: [],
              expiresAtMs: null,
              receivedAtMs: checkedAt,
              serverCheckedAtMs: null,
              ttlExpired: false,
              opengrepVerified: false,
            }
          : {
              status: 'ERROR',
              health: null,
              error: error?.message || 'Không thể kết nối máy chủ API.',
              schemaWarnings: [],
              architectureInvalidFields: [],
              architectureMalformed: false,
              invalidBooleanFields: [],
              expiresAtMs: null,
              receivedAtMs: checkedAt,
              serverCheckedAtMs: null,
              ttlExpired: false,
              opengrepVerified: false,
            };
        emit(nextBackend, {
          inFlight: false,
          autoRechecking: false,
          retryAttempt: retryCount,
          maxRetries: schedule.length,
          retryExhausted: false,
          lastCheckedAt: checkedAt,
          expiresAtMs: null,
          ttlExpired: false,
          staleSnapshotIgnored: false,
          scopeKey,
        });
        return snapshot;
      });

    activePromise = promise;
    return promise;
  }

  return {
    checkNow(opts = {}) {
      return runCheck({force: Boolean(opts.force), isRetry: false, preserveStatus: Boolean(opts.preserveStatus)});
    },
    cancel() {
      seq += 1;
      ttlGeneration += 1;
      resetScopeProofMemory();
      clearAllTimers();
      abortActiveRequest();
    },
    dispose() {
      if (!disposed) {
        checkpointActiveProofToLedger();
      }
      disposed = true;
      if (!hasCustomScopeKey && !hasCustomStorage && typeof window !== 'undefined' && typeof window.removeEventListener === 'function') {
        window.removeEventListener('pagehide', handlePageHide);
      }
      seq += 1;
      ttlGeneration += 1;
      // Clear RAM-only state and timers; preserve non-sensitive anti-replay ledger in sessionStorage
      // across reload/remount within the same scope (cleared on URL/origin/token change in api.js).
      resetScopeProofMemory();
      clearAllTimers();
      abortActiveRequest();
    },
    getSnapshot() {
      expireCurrentSnapshotIfNeeded(now(), monoNow());
      return snapshot;
    },
    hasPendingTimer() {
      return retryTimerId !== null || ttlTimerId !== null;
    },
    hasPendingRetryTimer() {
      return retryTimerId !== null;
    },
    hasPendingTtlTimer() {
      return ttlTimerId !== null;
    },
  };
}
