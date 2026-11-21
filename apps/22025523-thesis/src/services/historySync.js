import {api as defaultApi, getApiOrigin, getAuthSessionScope, subscribeApiConfig} from './api';
import {
  clearHistoryCache,
  historyKey,
  historyRecordFromBackend,
  mergeHistoryRecords,
  normalizeApiOrigin,
  readHiddenHistory,
  readHistory,
  upsertHistory,
} from './scanHistory';

// Invalidate all RAM history cache immediately whenever API origin or auth credential changes.
subscribeApiConfig((event) => {
  if (event?.sessionChanged) {
    clearHistoryCache();
  }
});

// Loads the scan history of ONE API origin + active Auth Session Scope.
// - Every remote record is stamped with both `origin` and `sessionScope`; cache rows of any
//   other origin or auth session are never read or merged.
// - If the request is aborted, the API configuration/session changed (`abortedByConfigChange`),
//   or the active origin/auth session scope no longer matches, returns `{stale: true}` and
//   NOTHING is written to cache.
// - Only GET endpoints are used; no scan or review action is ever triggered from here.
export async function syncHistoryFromApi({
  origin,
  sessionScope = getAuthSessionScope(),
  signal,
  apiClient = defaultApi,
  isCurrent = () => getApiOrigin() === normalizeApiOrigin(origin) && getAuthSessionScope() === sessionScope,
} = {}) {
  const scopeOrigin = normalizeApiOrigin(origin);
  const scopeSession = sessionScope || getAuthSessionScope();
  const stale = () => Boolean(signal?.aborted) || !isCurrent();
  let lastError = '';
  let anyEndpointSucceededOrPartial = false;
  const received = [];
  const incompleteEndpoints = [];
  const incompleteReasons = [];
  const endpointStatuses = {};

  // Both /api/scan-jobs and /api/scans are required sources under v2/api contract:
  // /api/scan-jobs covers QUEUED/RUNNING/FAILED jobs; /api/scans covers persisted completed scans.
  const endpoints = [
    {name: '/api/scan-jobs', required: true, load: apiClient?.listScanJobs},
    {name: '/api/scans', required: true, load: apiClient?.listScans},
  ];

  for (const {name, required, load} of endpoints) {
    if (typeof load !== 'function') {
      endpointStatuses[name] = {status: 'UNSUPPORTED', required, reason: 'ENDPOINT_CLIENT_MISSING'};
      if (required) {
        incompleteEndpoints.push({endpoint: name, status: 'UNSUPPORTED', reason: 'ENDPOINT_CLIENT_MISSING', receivedCount: 0, declaredTotalCount: null});
        if (!incompleteReasons.includes('ENDPOINT_CLIENT_MISSING')) incompleteReasons.push('ENDPOINT_CLIENT_MISSING');
      }
      continue;
    }

    let result;
    try {
      result = await load({signal});
    } catch (err) {
      if (stale() || err?.abortedByConfigChange) return {stale: true};
      const errMsg = err?.message || 'Lỗi kết nối API';
      lastError = errMsg;
      const reason = err?.code || (err?.status ? `HTTP_${err.status}` : 'FETCH_ERROR');
      endpointStatuses[name] = {status: 'ERROR', required, reason, error: errMsg};
      if (required) {
        incompleteEndpoints.push({endpoint: name, status: 'ERROR', reason, receivedCount: 0, declaredTotalCount: null});
        if (!incompleteReasons.includes(reason)) incompleteReasons.push(reason);
      }
      continue;
    }
    if (stale()) return {stale: true};

    if (!result || typeof result !== 'object' || !result.supported) {
      const reason = result?.invalidReason || 'UNSUPPORTED_OR_INVALID_RESPONSE';
      const statusKind = result?.endpointStatus === 'UNSUPPORTED' || /^HTTP_(404|405|501)$/.test(reason)
        ? 'UNSUPPORTED'
        : 'ERROR';
      endpointStatuses[name] = {status: statusKind, required, reason};
      if (required) {
        incompleteEndpoints.push({endpoint: name, status: statusKind, reason, receivedCount: 0, declaredTotalCount: null});
        if (!incompleteReasons.includes(reason)) incompleteReasons.push(reason);
      }
      continue;
    }

    anyEndpointSucceededOrPartial = true;
    const rawItems = Array.isArray(result.items) ? result.items : [];
    const declaredTotal = Number.isInteger(result.declaredTotalCount) ? result.declaredTotalCount : null;
    const parserInvalidCount = Number.isInteger(result.invalidItemCount) ? result.invalidItemCount : 0;
    const parserDuplicateCount = Number.isInteger(result.duplicateKeyCount) ? result.duplicateKeyCount : 0;

    // Validate and convert each received item safely (never throw on null / malformed entries, never fabricate missing rows).
    let validKeptCount = 0;
    let droppedMalformedCount = 0;
    for (let i = 0; i < rawItems.length; i += 1) {
      const record = historyRecordFromBackend(rawItems[i], {origin: scopeOrigin, sessionScope: scopeSession});
      if (!record || !historyKey(record)) {
        droppedMalformedCount += 1;
        continue;
      }
      if (record.isTestOrMock) {
        validKeptCount += 1;
        continue;
      }
      validKeptCount += 1;
      received.push(record);
    }

    const totalInvalidItems = parserInvalidCount + droppedMalformedCount;
    const countMismatch = (
      (declaredTotal !== null && declaredTotal !== (result.rawItemCount ?? rawItems.length)) ||
      (declaredTotal !== null && declaredTotal !== validKeptCount)
    );
    const endpointIncomplete = Boolean(
      result.valid === false ||
      result.truncated === true ||
      result.countConsistent === false ||
      result.invalidReason ||
      totalInvalidItems > 0 ||
      parserDuplicateCount > 0 ||
      countMismatch,
    );

    if (endpointIncomplete) {
      const reason = result.invalidReason
        || (totalInvalidItems > 0 ? 'INVALID_LIST_ITEMS'
          : parserDuplicateCount > 0 ? 'DUPLICATE_LIST_ITEMS'
            : result.truncated ? 'TRUNCATED_LIST'
              : countMismatch ? 'COUNT_MISMATCH'
                : 'INCOMPLETE_LIST');
      endpointStatuses[name] = {
        status: 'INCOMPLETE',
        required,
        reason,
        receivedCount: validKeptCount,
        declaredTotalCount: declaredTotal,
        invalidItemCount: totalInvalidItems,
      };
      incompleteEndpoints.push({
        endpoint: name,
        status: 'INCOMPLETE',
        reason,
        receivedCount: validKeptCount,
        declaredTotalCount: declaredTotal,
        invalidItemCount: totalInvalidItems,
      });
      if (!incompleteReasons.includes(reason)) incompleteReasons.push(reason);
    } else {
      endpointStatuses[name] = {
        status: 'COMPLETE',
        required,
        reason: '',
        receivedCount: validKeptCount,
        declaredTotalCount: declaredTotal,
        invalidItemCount: 0,
      };
    }
  }

  if (stale()) return {stale: true};

  const allRequiredComplete = endpoints
    .filter((ep) => ep.required)
    .every((ep) => endpointStatuses[ep.name]?.status === 'COMPLETE');
  // Never confirm supported: true as a complete sync while any required source failed,
  // returned 404/unsupported, had COUNT_MISMATCH/truncation, or dropped invalid/empty items.
  const supported = allRequiredComplete;
  const incomplete = !allRequiredComplete && anyEndpointSucceededOrPartial;
  const incompleteNotice = incomplete
    ? `Danh sách lịch sử từ API chưa đầy đủ (${incompleteEndpoints.map((ep) => {
      if (ep.status === 'UNSUPPORTED') return `${ep.endpoint}: không hỗ trợ [${ep.reason}]`;
      if (ep.status === 'ERROR') return `${ep.endpoint}: lỗi tải [${ep.reason}]`;
      return ep.declaredTotalCount !== null
        ? `${ep.endpoint}: nhận hợp lệ ${ep.receivedCount}/${ep.declaredTotalCount} [${ep.reason}]`
        : `${ep.endpoint} [${ep.reason}]`;
    }).join('; ')}). Đang hiển thị các bản ghi hợp lệ đã nhận mà không tự tạo bản ghi bù.`
    : '';

  received
    .filter((record) => record.scanId && record.status === 'COMPLETED')
    .forEach((record) => upsertHistory(record, {authoritative: true, origin: scopeOrigin, sessionScope: scopeSession}));

  const cached = readHistory(scopeOrigin, {sessionScope: scopeSession});
  const hidden = readHiddenHistory(scopeOrigin, {sessionScope: scopeSession});
  return {
    stale: false,
    origin: scopeOrigin,
    sessionScope: scopeSession,
    supported,
    incomplete,
    endpointStatuses,
    incompleteReasons,
    incompleteEndpoints,
    incompleteNotice,
    lastError: lastError || incompleteNotice,
    backendRecords: received,
    records: mergeHistoryRecords(cached, received, hidden, {origin: scopeOrigin, sessionScope: scopeSession}),
    hidden,
  };
}
