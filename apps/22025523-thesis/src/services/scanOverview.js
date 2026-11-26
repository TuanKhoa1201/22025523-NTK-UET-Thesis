import {useCallback, useEffect, useState} from 'react';
import {api, getApiOrigin, getAuthSessionScope, safeSessionSet} from './api';
import {
  ACTIVE_KEY,
  clearStaleActiveScanId,
  isConfirmedScanNotFoundError,
  validateScanCountersAndPagination,
} from './liveScan';
import {normalizeFinding} from './scanData';
import {classifyDataOrigin, VALIDATED_STATUSES, HUMAN_REVIEW_STATES} from './findingPresentation';

export const PRIORITY_CWES = ['CWE-22', 'CWE-89'];

const tally = (rows, pick) => {
  const map = new Map();
  rows.forEach((row) => {
    const key = pick(row);
    map.set(key, (map.get(key) || 0) + 1);
  });
  return [...map.entries()];
};

export function buildAggregates(rows) {
  return {
    byCwe: tally(rows, (row) => row.cwe).sort((a, b) => b[1] - a[1]),
    byValidatedStatus: VALIDATED_STATUSES.map((status) => [
      status,
      rows.filter((row) => row.validatedStatus === status).length,
    ]),
    byHumanReviewState: HUMAN_REVIEW_STATES.map((state) => [
      state,
      rows.filter((row) => row.humanReviewState === state).length,
    ]),
    byCitationCheck: tally(rows, (row) => row.citationCheck || 'NOT_VERIFIED'),
  };
}

const numOrNull = (v) => (v === undefined || v === null || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
const fail = (rows, reason) => ({complete: false, rows, reason});

export function verifyCompleteness(summary, items, found) {
  const safeItems = Array.isArray(items) ? items : [];
  const rows = safeItems.map(normalizeFinding);
  if (found?.hasFindingsArray === false) {
    return fail(rows, 'Phản hồi API thiếu danh sách findings hợp lệ.');
  }
  if (found?.paginationInconsistent === true || found?.invalidItemsInPages === true) {
    return fail(rows, 'Siêu dữ liệu phân trang hoặc danh sách cảnh báo từ API có mâu thuẫn/trùng lặp.');
  }
  if (!found?.complete) return fail(rows, '');
  if (rows.some((row) => !row.id)) {
    return fail(rows, 'Có cảnh báo thiếu finding_id; không thể xác minh dữ liệu đầy đủ.');
  }
  const ids = new Set(rows.map((row) => row.id));
  if (ids.size !== rows.length) {
    return fail(rows, 'Phát hiện finding_id trùng lặp giữa các trang.');
  }
  const expected = numOrNull(summary?.total_findings);
  const foundTotal = numOrNull(found?.totalMatching) ?? numOrNull(found?.total);
  if (expected === null && foundTotal === null) {
    return fail(rows, 'Phản hồi API thiếu tổng số cảnh báo hợp lệ; không thể xác minh dữ liệu đầy đủ.');
  }
  if (expected !== null && expected !== ids.size) {
    return fail(rows, `Summary báo ${expected.toLocaleString()} cảnh báo nhưng danh sách phân trang có ${ids.size.toLocaleString()}.`);
  }
  const pageMeta = found?.meta && typeof found.meta === 'object'
    ? {...found.meta, findings: safeItems}
    : {total_count: foundTotal ?? expected, findings: safeItems};
  const consistency = validateScanCountersAndPagination(summary, pageMeta, {isAggregatedAllPages: true});
  if (!consistency.valid) {
    return fail(rows, `Dữ liệu summary/phân trang mâu thuẫn (${consistency.reason}); không thể xác minh đầy đủ.`);
  }
  return {complete: true, rows, reason: ''};
}

export function useScanOverview(scanId, apiRevision = 0) {
  const [state, setState] = useState({status: 'loading', progress: null, data: null, error: '', statusCode: null, errorCode: null});
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!scanId) {
      setState({status: 'idle', progress: null, data: null, error: '', statusCode: null, errorCode: null});
      return undefined;
    }
    const controller = new AbortController();
    const {signal} = controller;
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    let summaryConfirmed = false;
    const isStale = () => !active || signal.aborted || getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession;
    setState({status: 'loading', progress: null, data: null, error: '', statusCode: null, errorCode: null});
    (async () => {
      const summary = await api.scanSummary(scanId, {signal});
      if (isStale()) return;
      if (summary?.scan_id !== scanId) {
        throw new Error('Phản hồi summary không khớp scan_id đã chọn.');
      }
      if (classifyDataOrigin(summary).isMockOrTest) {
        throw new Error('Dữ liệu kiểm thử mô phỏng (mock) bị cách ly khỏi luồng hiển thị vận hành thực.');
      }
      summaryConfirmed = true;
      const found = await api.allFindingsPages(scanId, {includeConfirmedFalse: true}, {
        signal,
        onProgress: (progress) => {
          if (!isStale()) {
            setState((s) => ({...s, progress}));
          }
        },
      });
      if (isStale()) return;
      try {
        safeSessionSet(ACTIVE_KEY, scanId);
      } catch {
        /* optional sessionStorage update */
      }
      const check = verifyCompleteness(summary, found.items, found);
      setState({
        status: 'success',
        progress: null,
        error: '',
        statusCode: null,
        errorCode: null,
        data: {
          summary,
          rows: check.rows,
          complete: check.complete,
          reason: check.reason,
          total: found.total ?? summary.total_findings ?? check.rows.length,
        },
      });
    })().catch((error) => {
      if (isStale() || error?.abortedByConfigChange) return;
      if (!summaryConfirmed && isConfirmedScanNotFoundError(error)) {
        clearStaleActiveScanId(scanId, requestSession);
      }
      setState({
        status: 'error',
        progress: null,
        data: null,
        error: error?.message || 'Không thể tải dữ liệu từ API.',
        statusCode: error?.status ?? null,
        errorCode: error?.code ?? error?.payload?.error_code ?? null,
      });
    });
    return () => {
      active = false;
      controller.abort();
    };
  }, [scanId, apiRevision, attempt]);

  const retry = useCallback(() => setAttempt((value) => value + 1), []);
  return [state, retry];
}
