import {useEffect, useMemo, useState} from 'react';
import {useSearchParams} from 'react-router-dom';
import {
  api,
  ApiError,
  getApiOrigin,
  getAuthSessionScope,
  getWireDuplicateKeyInfo,
  getWireObjectIntegrity,
  readStrictWireSafeInt,
  subscribeApiConfig,
  safeSessionGet,
  safeSessionSet,
  safeSessionRemove,
  getSessionStorageSafe,
} from './api';
import {classifyDataOrigin} from './findingPresentation';
import {normalizeFinding, saveScanRecord} from './scanData';
import {clearHistoryCache, upsertHistory} from './scanHistory';

export const ACTIVE_KEY = '22025523-scan-id';
// RAM-only dataset cache keyed by active Auth Session Scope + scanId.
const liveDatasetCache = new Map();

export function isConfirmedScanNotFoundError(error) {
  if (!error || error.status !== 404) return false;
  const code = String(error.code || error.payload?.error_code || '').trim().toUpperCase();
  return code === 'SCAN_NOT_FOUND';
}

export function clearStaleActiveScanId(failedScanId, sessionScope = getAuthSessionScope()) {
  const target = typeof failedScanId === 'string' ? failedScanId.trim() : '';
  if (!target) return false;
  liveDatasetCache.delete(`${sessionScope}|${target}`);
  if (!getSessionStorageSafe()) return false;
  try {
    if (safeSessionGet(ACTIVE_KEY) === target) {
      safeSessionRemove(ACTIVE_KEY);
      return true;
    }
  } catch {
    /* optional sessionStorage cleanup */
  }
  return false;
}

subscribeApiConfig((event) => {
  if (event?.sessionChanged) {
    liveDatasetCache.clear();
    clearHistoryCache();
  }
});

const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

function nonNegativeIntOrNull(value, obj = null, key = '') {
  if (obj && key) {
    const check = readStrictWireSafeInt(obj, key);
    return check.present && check.valid ? check.value : null;
  }
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) return null;
  return value === 0 ? 0 : value;
}

function positiveIntOrNull(value, obj = null, key = '') {
  const n = nonNegativeIntOrNull(value, obj, key);
  return n !== null && n >= 1 ? n : null;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

const EXPLICIT_VALIDATED_STATUSES = new Set(['SUPPORTED', 'REFUTED', 'UNDETERMINED']);
const EXPLICIT_HUMAN_STATES = new Set(['OPEN', 'CONFIRMED_TRUE', 'CONFIRMED_FALSE']);

function inspectCountMap(mapObj, resolvedTotal, requiredKeys = []) {
  if (mapObj === undefined || mapObj === null) {
    return {valid: true, sum: null, reason: ''};
  }
  if (!isPlainObject(mapObj)) {
    return {valid: false, sum: null, reason: 'INVALID_STATUS_COUNTER_MAP'};
  }
  const mapWire = getWireObjectIntegrity(mapObj);
  if (
    mapWire?.scannerError
    || (mapWire?.duplicateKeys && mapWire.duplicateKeys.size > 0)
    || (mapWire?.materialized?.duplicateKeys && Object.keys(mapWire.materialized.duplicateKeys).length > 0)
  ) {
    return {valid: false, sum: null, reason: 'DUPLICATE_WIRE_KEY'};
  }
  const entries = Object.entries(mapObj).filter(([k]) => k !== '__wireIntegrity');
  if (entries.length === 0) {
    return {valid: true, sum: 0, reason: ''};
  }
  let sumBig = 0n;
  for (const [entryKey, rawVal] of entries) {
    if (getWireDuplicateKeyInfo(mapObj, entryKey)) {
      return {valid: false, sum: null, reason: 'DUPLICATE_WIRE_KEY'};
    }
    const n = nonNegativeIntOrNull(rawVal, mapObj, entryKey);
    if (n === null) {
      return {valid: false, sum: null, reason: 'INVALID_STATUS_COUNTER'};
    }
    sumBig += BigInt(n);
    if (sumBig > MAX_SAFE_BIGINT) {
      return {valid: false, sum: null, reason: 'STATUS_COUNTS_OVERFLOW'};
    }
  }
  const sum = Number(sumBig);
  if (resolvedTotal !== null) {
    if (resolvedTotal === 0 && sum > 0) {
      return {valid: false, sum, reason: 'NONZERO_COUNTER_WITH_ZERO_TOTAL'};
    }
    if (sum > resolvedTotal) {
      return {valid: false, sum, reason: 'STATUS_COUNTS_EXCEED_TOTAL'};
    }
    if (requiredKeys.length > 0 && requiredKeys.every((k) => Object.hasOwn(mapObj, k)) && sum !== resolvedTotal) {
      return {valid: false, sum, reason: 'STATUS_COUNTS_MISMATCH_TOTAL'};
    }
  }
  return {valid: true, sum, reason: ''};
}

function isNonEmptyMarker(value) {
  return value !== undefined && value !== null && value !== false && value !== '';
}

function readFindingId(item) {
  if (!isPlainObject(item)) return '';
  const rawId = item.finding_id ?? item.id;
  if (typeof rawId === 'string') return rawId.trim();
  if (typeof rawId === 'number' && Number.isFinite(rawId)) return String(rawId);
  return '';
}

export function inspectFindingsForRefutedOpen(rawFindings) {
  if (!Array.isArray(rawFindings)) {
    return {
      validIds: false,
      hasInvalidItem: true,
      hasDuplicates: false,
      hasMissingId: false,
      hasAllExplicitStatuses: false,
      obsRefOpen: 0,
      obsNonRefOpen: 0,
      obsRefNonOpen: 0,
      obsOpenNonRef: 0,
      validatedCounts: {SUPPORTED: 0, REFUTED: 0, UNDETERMINED: 0},
      humanCounts: {OPEN: 0, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
      reason: 'MISSING_FINDINGS_LIST',
    };
  }
  const seenIds = new Set();
  let hasInvalidItem = false;
  let hasMissingId = false;
  let hasDuplicates = false;
  let hasAllExplicitStatuses = true;
  let obsRefOpen = 0;
  let obsNonRefOpen = 0;
  let obsRefNonOpen = 0;
  let obsOpenNonRef = 0;
  const validatedCounts = {SUPPORTED: 0, REFUTED: 0, UNDETERMINED: 0};
  const humanCounts = {OPEN: 0, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0};

  for (let i = 0; i < rawFindings.length; i += 1) {
    const item = rawFindings[i];
    if (!isPlainObject(item)) {
      hasInvalidItem = true;
      hasAllExplicitStatuses = false;
      continue;
    }
    const id = readFindingId(item);
    if (!id) {
      hasMissingId = true;
    } else if (seenIds.has(id)) {
      hasDuplicates = true;
    } else {
      seenIds.add(id);
    }

    const ass = isPlainObject(item.assessment) ? item.assessment : {};
    const rawVal = item.validated_status ?? ass.validated_status ?? ass.status;
    const validated = typeof rawVal === 'string' ? rawVal.trim().toUpperCase() : '';
    const hasVal = EXPLICIT_VALIDATED_STATUSES.has(validated);
    if (hasVal) {
      validatedCounts[validated] += 1;
    } else {
      hasAllExplicitStatuses = false;
    }

    const rawHuman = item.human_review_state ?? item.state;
    const human = typeof rawHuman === 'string' ? rawHuman.trim().toUpperCase() : '';
    const hasHuman = EXPLICIT_HUMAN_STATES.has(human);
    if (hasHuman) {
      humanCounts[human] += 1;
    } else {
      hasAllExplicitStatuses = false;
    }

    if (hasVal && hasHuman) {
      if (validated === 'REFUTED' && human === 'OPEN') {
        obsRefOpen += 1;
      } else {
        obsNonRefOpen += 1;
        if (validated === 'REFUTED') obsRefNonOpen += 1;
        if (human === 'OPEN') obsOpenNonRef += 1;
      }
    } else if (hasVal && validated !== 'REFUTED') {
      obsNonRefOpen += 1;
      if (hasHuman && human === 'OPEN') obsOpenNonRef += 1;
    } else if (hasHuman && human !== 'OPEN') {
      obsNonRefOpen += 1;
      if (hasVal && validated === 'REFUTED') obsRefNonOpen += 1;
    }
  }

  const reason = hasInvalidItem
    ? 'INVALID_FINDING_ITEM'
    : hasMissingId
      ? 'MISSING_FINDING_ID'
      : hasDuplicates
        ? 'DUPLICATE_FINDING_ID'
        : !hasAllExplicitStatuses
          ? 'MISSING_EXPLICIT_STATUS'
          : '';

  return {
    validIds: !hasInvalidItem && !hasMissingId && !hasDuplicates,
    hasInvalidItem,
    hasDuplicates,
    hasMissingId,
    hasAllExplicitStatuses,
    obsRefOpen,
    obsNonRefOpen,
    obsRefNonOpen,
    obsOpenNonRef,
    validatedCounts,
    humanCounts,
    reason,
  };
}

export function computeRefutedOpenFromFindings(rawFindings, {expectedTotal = null} = {}) {
  const inspection = inspectFindingsForRefutedOpen(rawFindings);
  if (!Array.isArray(rawFindings)) {
    return {valid: false, value: null, reason: 'MISSING_FINDINGS_LIST', hasDuplicates: false};
  }
  if (expectedTotal === null || rawFindings.length !== expectedTotal) {
    return {
      valid: false,
      value: null,
      reason: 'INCOMPLETE_FINDINGS_FOR_INTERSECTION',
      hasDuplicates: inspection.hasDuplicates,
    };
  }
  if (!inspection.validIds || !inspection.hasAllExplicitStatuses) {
    return {
      valid: false,
      value: null,
      reason: inspection.reason || 'MISSING_EXPLICIT_HUMAN_REVIEW_STATE',
      hasDuplicates: inspection.hasDuplicates,
    };
  }
  return {valid: true, value: inspection.obsRefOpen, reason: '', hasDuplicates: false};
}

export function validateScanCountersAndPagination(summary, pagePayload, {isAggregatedAllPages = false} = {}) {
  const hasSummaryWireAnomaly = Boolean(
    isPlainObject(summary) && (
      getWireObjectIntegrity(summary)?.scannerError
      || [
        'scan_id',
        'total_findings',
        'by_validated_status',
        'by_human_review_state',
        'by_cwe',
        'counts',
        'data_origin',
        'findings_with_trace',
        'validator_downgraded_count',
        'matched_citation_count',
        'proposed_refuted_open_count',
      ].some((k) => Boolean(getWireDuplicateKeyInfo(summary, k)))
      || (isPlainObject(summary.counts) && (
        getWireObjectIntegrity(summary.counts)?.scannerError
        || ['open_count', 'proposed_refuted_open_count'].some((k) => Boolean(getWireDuplicateKeyInfo(summary.counts, k)))
      ))
    ),
  );
  const hasPageWireAnomaly = Boolean(
    isPlainObject(pagePayload) && (
      getWireObjectIntegrity(pagePayload)?.scannerError
      || [
        'scan_id',
        'findings',
        'total_count',
        'total_matching',
        'total_pages',
        'page',
        'page_size',
        'has_more',
        'truncated',
        'next_page',
        'next_cursor',
        'data_origin',
      ].some((k) => Boolean(getWireDuplicateKeyInfo(pagePayload, k)))
    ),
  );
  if (hasSummaryWireAnomaly || hasPageWireAnomaly) {
    return {valid: false, reason: 'DUPLICATE_WIRE_KEY', resolvedTotal: null};
  }
  const hasFindingsArray = Array.isArray(pagePayload?.findings);
  const rawList = hasFindingsArray ? pagePayload.findings : [];

  const summaryTotalRaw = summary?.total_findings;
  const pageTotalRaw = pagePayload?.total_count;
  const pageMatchingRaw = pagePayload?.total_matching;
  const summaryTotal = nonNegativeIntOrNull(summaryTotalRaw, summary, 'total_findings');
  const pageTotal = nonNegativeIntOrNull(pageTotalRaw, pagePayload, 'total_count');
  const pageMatching = nonNegativeIntOrNull(pageMatchingRaw, pagePayload, 'total_matching');

  if (summaryTotalRaw !== undefined && summaryTotalRaw !== null && summaryTotal === null) {
    return {valid: false, reason: 'INVALID_TOTAL_FINDINGS', resolvedTotal: null};
  }
  if (pageTotalRaw !== undefined && pageTotalRaw !== null && pageTotal === null) {
    return {valid: false, reason: 'INVALID_PAGE_TOTAL_COUNT', resolvedTotal: null};
  }
  if (pageMatchingRaw !== undefined && pageMatchingRaw !== null && pageMatching === null) {
    return {valid: false, reason: 'INVALID_TOTAL_MATCHING', resolvedTotal: null};
  }
  if (summaryTotal !== null && pageTotal !== null && summaryTotal !== pageTotal) {
    return {valid: false, reason: 'TOTAL_COUNT_CONFLICT', resolvedTotal: null};
  }
  const resolvedTotal = summaryTotal ?? pageTotal;
  if (!isAggregatedAllPages && !hasFindingsArray && resolvedTotal === null) {
    return {valid: false, reason: 'MISSING_FINDINGS_AND_TOTAL', resolvedTotal: null};
  }
  if (!isAggregatedAllPages && !hasFindingsArray) {
    return {valid: false, reason: 'MISSING_FINDINGS_LIST', resolvedTotal};
  }
  if (resolvedTotal === null) {
    return {valid: false, reason: 'MISSING_TOTAL_COUNT', resolvedTotal: null};
  }
  if (pageMatching !== null && pageMatching !== resolvedTotal) {
    return {valid: false, reason: 'TOTAL_MATCHING_CONFLICT', resolvedTotal: null};
  }

  // Validate status breakdown and CWE counters against resolvedTotal
  const valCheck = inspectCountMap(summary?.by_validated_status, resolvedTotal, ['SUPPORTED', 'REFUTED', 'UNDETERMINED']);
  if (!valCheck.valid) return {valid: false, reason: valCheck.reason, resolvedTotal: null};

  const humCheck = inspectCountMap(summary?.by_human_review_state, resolvedTotal, ['OPEN', 'CONFIRMED_TRUE', 'CONFIRMED_FALSE']);
  if (!humCheck.valid) return {valid: false, reason: humCheck.reason, resolvedTotal: null};

  const cweCheck = inspectCountMap(summary?.by_cwe, resolvedTotal);
  if (!cweCheck.valid) return {valid: false, reason: cweCheck.reason, resolvedTotal: null};

  if (isPlainObject(summary?.counts) && summary.counts.open_count !== undefined && summary.counts.open_count !== null) {
    const openCount = nonNegativeIntOrNull(summary.counts.open_count, summary.counts, 'open_count');
    if (openCount === null || openCount > resolvedTotal) {
      return {valid: false, reason: 'INVALID_OPEN_COUNT', resolvedTotal: null};
    }
  }

  let findingsInspection = null;
  if (hasFindingsArray) {
    findingsInspection = inspectFindingsForRefutedOpen(rawList);
    if (findingsInspection.hasInvalidItem) {
      return {valid: false, reason: 'INVALID_FINDING_ITEM', resolvedTotal: null};
    }
    if (findingsInspection.hasMissingId) {
      return {valid: false, reason: 'MISSING_FINDING_ID', resolvedTotal: null};
    }
    if (findingsInspection.hasDuplicates) {
      return {valid: false, reason: 'DUPLICATE_FINDING_ID', resolvedTotal: null};
    }
    const remainingUnseen = Math.max(0, resolvedTotal - rawList.length);
    const byValidated = isPlainObject(summary?.by_validated_status) ? summary.by_validated_status : null;
    if (byValidated) {
      for (const statusKey of ['SUPPORTED', 'REFUTED', 'UNDETERMINED']) {
        const declared = nonNegativeIntOrNull(byValidated[statusKey]);
        if (declared !== null) {
          const observed = findingsInspection.validatedCounts[statusKey];
          if (observed > declared || observed + remainingUnseen < declared) {
            return {valid: false, reason: 'FINDINGS_CONTRADICT_SUMMARY_STATUS', resolvedTotal: null};
          }
        }
      }
    }
    const byHuman = isPlainObject(summary?.by_human_review_state) ? summary.by_human_review_state : null;
    if (byHuman) {
      for (const humanKey of ['OPEN', 'CONFIRMED_TRUE', 'CONFIRMED_FALSE']) {
        const declared = nonNegativeIntOrNull(byHuman[humanKey]);
        if (declared !== null) {
          const observed = findingsInspection.humanCounts[humanKey];
          if (observed > declared || observed + remainingUnseen < declared) {
            return {valid: false, reason: 'FINDINGS_CONTRADICT_HUMAN_REVIEW_STATE', resolvedTotal: null};
          }
        }
      }
    }
  }

  for (const [field, reason] of [
    ['findings_with_trace', 'INVALID_TRACE_COUNT'],
    ['validator_downgraded_count', 'INVALID_DOWNGRADED_COUNT'],
    ['matched_citation_count', 'INVALID_CITATION_COUNT'],
  ]) {
    const raw = summary?.[field];
    if (raw !== undefined && raw !== null) {
      const n = nonNegativeIntOrNull(raw, summary, field);
      if (n === null || n > resolvedTotal) {
        return {valid: false, reason, resolvedTotal: null};
      }
    }
  }

  // Validate pagination invariants on pagePayload
  if (isPlainObject(pagePayload)) {
    const rawPage = pagePayload.page;
    const rawPageSize = pagePayload.page_size;
    const rawTotalPages = pagePayload.total_pages;
    const pageNum = rawPage !== undefined && rawPage !== null ? positiveIntOrNull(rawPage, pagePayload, 'page') : null;
    const pageSize = rawPageSize !== undefined && rawPageSize !== null ? positiveIntOrNull(rawPageSize, pagePayload, 'page_size') : null;
    const totalPages = rawTotalPages !== undefined && rawTotalPages !== null ? nonNegativeIntOrNull(rawTotalPages, pagePayload, 'total_pages') : null;

    if (rawPage !== undefined && rawPage !== null && pageNum === null) {
      return {valid: false, reason: 'INVALID_PAGE_NUMBER', resolvedTotal: null};
    }
    if (rawPageSize !== undefined && rawPageSize !== null && pageSize === null) {
      return {valid: false, reason: 'INVALID_PAGE_SIZE', resolvedTotal: null};
    }
    if (rawTotalPages !== undefined && rawTotalPages !== null && totalPages === null) {
      return {valid: false, reason: 'INVALID_TOTAL_PAGES', resolvedTotal: null};
    }

    if (pagePayload.truncated === true) {
      return {valid: false, reason: 'PAGINATION_TRUNCATED', resolvedTotal: null};
    }

    const hasNextPage = isNonEmptyMarker(pagePayload.next_page);
    const hasNextCursor = isNonEmptyMarker(pagePayload.next_cursor);
    const hasContinuation = Boolean(pagePayload.has_more === true || hasNextPage || hasNextCursor);
    const effectivePage = pageNum ?? 1;

    if (hasNextPage) {
      const nextNum = typeof pagePayload.next_page === 'number'
        ? pagePayload.next_page
        : typeof pagePayload.next_page === 'string' && /^\d+$/.test(pagePayload.next_page.trim())
          ? Number(pagePayload.next_page.trim())
          : null;
      if (nextNum !== null && (nextNum <= effectivePage || (totalPages !== null && nextNum > totalPages))) {
        return {valid: false, reason: 'PAGINATION_INVALID_NEXT_PAGE', resolvedTotal: null};
      }
    }

    if (resolvedTotal === 0) {
      if ((totalPages !== null && totalPages > 1) || (pageNum !== null && pageNum > 1) || hasContinuation) {
        return {valid: false, reason: 'PAGINATION_INCONSISTENT_WITH_ZERO_TOTAL', resolvedTotal: null};
      }
      if (!isAggregatedAllPages && rawList.length > 0) {
        return {valid: false, reason: 'NONEMPTY_FINDINGS_FOR_ZERO_TOTAL', resolvedTotal: null};
      }
    } else {
      if (totalPages !== null && totalPages < 1) {
        return {valid: false, reason: 'PAGINATION_ZERO_PAGES_FOR_NONZERO_TOTAL', resolvedTotal: null};
      }
      if (pageNum !== null && totalPages !== null && pageNum > totalPages) {
        return {valid: false, reason: 'PAGINATION_PAGE_OUT_OF_RANGE', resolvedTotal: null};
      }
      if (pageSize !== null && totalPages !== null && totalPages !== Math.ceil(resolvedTotal / pageSize)) {
        return {valid: false, reason: 'PAGINATION_TOTAL_PAGES_MISMATCH', resolvedTotal: null};
      }
      if (isAggregatedAllPages) {
        if (hasContinuation) {
          return {valid: false, reason: 'PAGINATION_INCONSISTENT_FINAL_PAGE', resolvedTotal: null};
        }
        if (pageNum !== null && totalPages !== null && pageNum !== totalPages) {
          return {valid: false, reason: 'PAGINATION_INCOMPLETE_FINAL_PAGE', resolvedTotal: null};
        }
      } else {
        if (totalPages !== null && effectivePage >= totalPages && hasContinuation) {
          return {valid: false, reason: 'PAGINATION_HAS_MORE_AT_END', resolvedTotal: null};
        }
        if (effectivePage === 1 && rawList.length >= resolvedTotal && hasContinuation) {
          return {valid: false, reason: 'PAGINATION_HAS_MORE_EXCEEDS_TOTAL', resolvedTotal: null};
        }
        if (totalPages !== null && effectivePage < totalPages && pagePayload.has_more === false) {
          return {valid: false, reason: 'PAGINATION_HAS_MORE_FALSE_BEFORE_END', resolvedTotal: null};
        }
        if (rawList.length > resolvedTotal) {
          return {valid: false, reason: 'FINDINGS_EXCEED_TOTAL', resolvedTotal: null};
        }
        if (effectivePage === 1 && rawList.length === 0) {
          return {valid: false, reason: 'EMPTY_FINDINGS_FOR_NONZERO_TOTAL', resolvedTotal: null};
        }
        if (totalPages !== null && effectivePage < totalPages && rawList.length === 0) {
          return {valid: false, reason: 'EMPTY_INTERMEDIATE_PAGE', resolvedTotal: null};
        }
        if (effectivePage === 1 && pageSize !== null && rawList.length < Math.min(resolvedTotal, pageSize)) {
          return {valid: false, reason: 'PAGE_UNDERFLOW_INCOMPLETE', resolvedTotal: null};
        }
      }
    }
  }

  return {valid: true, reason: '', resolvedTotal, findingsInspection};
}

export function buildDataset(scanId, summary, findingsPagePayload) {
  const hasFindingsArray = Array.isArray(findingsPagePayload?.findings);
  const list = hasFindingsArray ? findingsPagePayload.findings : [];
  const rows = list.map((item) => normalizeFinding(item));
  const byValidated = isPlainObject(summary?.by_validated_status) ? summary.by_validated_status : {};
  const byHuman = isPlainObject(summary?.by_human_review_state) ? summary.by_human_review_state : {};

  const consistency = validateScanCountersAndPagination(summary, findingsPagePayload);
  let incompleteReason = consistency.valid ? '' : consistency.reason;
  let resolvedTotal = consistency.valid ? consistency.resolvedTotal : null;

  const hasAllRows = (
    consistency.valid &&
    hasFindingsArray &&
    resolvedTotal !== null &&
    rows.length === resolvedTotal &&
    !(findingsPagePayload?.has_more === true || findingsPagePayload?.truncated === true || (nonNegativeIntOrNull(findingsPagePayload?.total_pages) ?? 1) > 1)
  );

  const inspection = consistency.findingsInspection || inspectFindingsForRefutedOpen(list);
  const allUniqueIds = hasAllRows && inspection.validIds;
  const canDeriveValidatedFromRows = allUniqueIds && rows.every((r) => Boolean(r.explicitValidatedStatus));
  const canDeriveHumanFromRows = allUniqueIds && rows.every((r) => Boolean(r.explicitHumanReviewState));

  const countOrNull = (summaryVal, canDerive, rowFilter) => {
    const parsed = nonNegativeIntOrNull(summaryVal);
    if (parsed !== null) return parsed;
    if (canDerive) return rows.filter(rowFilter).length;
    return null;
  };

  const supported = consistency.valid ? countOrNull(byValidated.SUPPORTED, canDeriveValidatedFromRows, (r) => r.explicitValidatedStatus === 'SUPPORTED') : null;
  const refuted = consistency.valid ? countOrNull(byValidated.REFUTED, canDeriveValidatedFromRows, (r) => r.explicitValidatedStatus === 'REFUTED') : null;
  const undetermined = consistency.valid ? countOrNull(byValidated.UNDETERMINED, canDeriveValidatedFromRows, (r) => r.explicitValidatedStatus === 'UNDETERMINED') : null;
  const open = consistency.valid ? countOrNull(byHuman.OPEN, canDeriveHumanFromRows, (r) => r.explicitHumanReviewState === 'OPEN') : null;
  const confirmedTrue = consistency.valid ? countOrNull(byHuman.CONFIRMED_TRUE, canDeriveHumanFromRows, (r) => r.explicitHumanReviewState === 'CONFIRMED_TRUE') : null;
  const confirmedFalse = consistency.valid ? countOrNull(byHuman.CONFIRMED_FALSE, canDeriveHumanFromRows, (r) => r.explicitHumanReviewState === 'CONFIRMED_FALSE') : null;

  // Strict two-axis intersection: Qwen validated_status === REFUTED AND explicit human_review_state === OPEN.
  // Enforce unique IDs on ALL pages (full or partial), pigeonhole mathematical bounds against both axes & observed rows,
  // and exact equality when all rows are present.
  const rawExplicitRefutedOpen = summary?.proposed_refuted_open_count ?? summary?.counts?.proposed_refuted_open_count;
  const hasExplicitRefutedOpen = rawExplicitRefutedOpen !== undefined && rawExplicitRefutedOpen !== null;
  const explicitRefutedOpen = hasExplicitRefutedOpen
    ? (summary?.proposed_refuted_open_count !== undefined && summary?.proposed_refuted_open_count !== null
      ? nonNegativeIntOrNull(summary.proposed_refuted_open_count, summary, 'proposed_refuted_open_count')
      : nonNegativeIntOrNull(summary?.counts?.proposed_refuted_open_count, summary?.counts, 'proposed_refuted_open_count'))
    : null;
  const computedFromRows = hasAllRows
    ? computeRefutedOpenFromFindings(list, {expectedTotal: resolvedTotal})
    : {valid: false, value: null, reason: 'NOT_ALL_ROWS', hasDuplicates: inspection.hasDuplicates};

  let refutedOpen = null;
  if (consistency.valid) {
    if (hasExplicitRefutedOpen) {
      const upperBound = Math.min(
        resolvedTotal,
        refuted !== null ? Math.max(0, refuted - inspection.obsRefNonOpen) : resolvedTotal,
        open !== null ? Math.max(0, open - inspection.obsOpenNonRef) : resolvedTotal,
        Math.max(0, resolvedTotal - inspection.obsNonRefOpen),
      );
      const lowerBound = Math.max(
        0,
        (refuted !== null && open !== null) ? Math.max(0, refuted + open - resolvedTotal) : 0,
        inspection.obsRefOpen,
      );
      if (
        !inspection.validIds ||
        explicitRefutedOpen === null ||
        explicitRefutedOpen > upperBound ||
        explicitRefutedOpen < lowerBound ||
        (computedFromRows.valid && explicitRefutedOpen !== computedFromRows.value)
      ) {
        incompleteReason = !inspection.validIds
          ? (inspection.reason || 'DUPLICATE_FINDING_ID')
          : 'REFUTED_OPEN_COUNT_INCONSISTENT';
        resolvedTotal = null;
        refutedOpen = null;
      } else {
        refutedOpen = explicitRefutedOpen;
      }
    } else if (computedFromRows.valid) {
      refutedOpen = computedFromRows.value;
    } else if (inspection.validIds && (resolvedTotal === 0 || refuted === 0 || open === 0)) {
      refutedOpen = 0;
    } else {
      refutedOpen = null;
    }
  }

  const incomplete = incompleteReason !== '';
  const confirmedNoFindings = (
    !incomplete &&
    resolvedTotal === 0 &&
    hasFindingsArray &&
    rows.length === 0 &&
    (refutedOpen === 0 || refutedOpen === null)
  );

  return {
    scanId,
    scan: summary,
    findingsPayload: findingsPagePayload,
    rows,
    incomplete,
    incompleteReason,
    pagination: {
      loaded: rows.length,
      total: resolvedTotal,
      page: Number(findingsPagePayload?.page ?? 1),
      pageSize: Number(findingsPagePayload?.page_size ?? 50),
    },
    counts: {
      total: resolvedTotal,
      supported: incomplete ? null : supported,
      refuted: incomplete ? null : refuted,
      refutedOpen: incomplete ? null : refutedOpen,
      undetermined: incomplete ? null : undetermined,
      open: incomplete ? null : open,
      confirmedTrue: incomplete ? null : confirmedTrue,
      confirmedFalse: incomplete ? null : confirmedFalse,
      hasFindingsList: hasFindingsArray,
      hasValidTotal: !incomplete && resolvedTotal !== null,
      confirmedNoFindings,
      incomplete,
      incompleteReason,
    },
  };
}

function cacheKeyFor(scanId, sessionScope = getAuthSessionScope()) {
  return `${sessionScope}|${scanId}`;
}

function writeCache(scanId, scan, findingsPayload, sessionScope = getAuthSessionScope()) {
  liveDatasetCache.set(cacheKeyFor(scanId, sessionScope), {scan, findingsPayload});
}

function readCache(scanId, sessionScope = getAuthSessionScope()) {
  const cached = liveDatasetCache.get(cacheKeyFor(scanId, sessionScope));
  return cached ? buildDataset(scanId, cached.scan, cached.findingsPayload) : null;
}

function recordHistory(dataset, origin, sessionScope) {
  const {scanId, scan, counts} = dataset;
  const backendDuration = scan?.total_e2e_duration_ms;
  const backendMs = backendDuration === null || backendDuration === undefined ? undefined : Number(backendDuration);
  upsertHistory({
    scanId,
    jobId: scan?.job_id,
    status: 'COMPLETED',
    inputMode: scan?.input_mode,
    fileName: scan?.file_name,
    repoUrl: scan?.repo_url,
    commit: scan?.resolved_commit,
    startedAt: scan?.started_at,
    completedAt: scan?.completed_at ?? scan?.collected_at,
    candidates: counts.total,
    supported: counts.supported,
    refuted: counts.refuted,
    undetermined: counts.undetermined,
    openCount: counts.open,
    backendMs: Number.isFinite(backendMs) ? backendMs : undefined,
  }, {authoritative: true, origin, sessionScope});
}

export async function loadLiveScan(scanId, signal) {
  const requestOrigin = getApiOrigin();
  const requestSession = getAuthSessionScope();
  const options = {signal, timeoutMs: 60000};
  const [summaryRes, pageRes] = await Promise.allSettled([
    api.scanSummary(scanId, options),
    api.findingsPage(scanId, {page: 1, pageSize: 50}, options),
  ]);
  if (summaryRes.status === 'rejected') {
    if (
      isConfirmedScanNotFoundError(summaryRes.reason) &&
      getApiOrigin() === requestOrigin &&
      getAuthSessionScope() === requestSession
    ) {
      clearStaleActiveScanId(scanId, requestSession);
    }
    throw summaryRes.reason;
  }
  if (pageRes.status === 'rejected') {
    // Summary already succeeded (scan exists); never erase active scan_id when a secondary endpoint fails or is blocked by proxy.
    throw pageRes.reason;
  }
  const summary = summaryRes.value;
  const page = pageRes.value;
  if (getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession) {
    throw new ApiError('Cấu hình kết nối hoặc phiên xác thực API đã thay đổi khi yêu cầu đang thực thi.', {abortedByConfigChange: true});
  }
  if (summary?.scan_id !== scanId) throw new Error('Phản hồi summary không khớp scan_id đã chọn.');
  if (page?.scan_id !== scanId) throw new Error('Phản hồi findings không khớp scan_id đã chọn.');
  if (classifyDataOrigin(summary).isMockOrTest || classifyDataOrigin(page).isMockOrTest) {
    throw new Error('Phiên dữ liệu mô phỏng (mock) bị cách ly khỏi giao diện vận hành thực.');
  }

  const dataset = buildDataset(scanId, summary, page);
  if (dataset.incomplete) {
    throw new ApiError(
      `Dữ liệu kết quả phiên quét chưa đầy đủ (${dataset.incompleteReason}); không thể xác nhận số cảnh báo hoặc kết luận không có cảnh báo.`,
      {payload: {error_code: dataset.incompleteReason || 'INCOMPLETE_SCAN_RESULTS'}},
    );
  }

  writeCache(scanId, summary, page, requestSession);
  safeSessionSet(ACTIVE_KEY, scanId);
  saveScanRecord({
    sessionKey: `${requestSession}|${scanId}`,
    scanId,
    apiOrigin: requestOrigin,
    sessionScope: requestSession,
    raw: summary,
    findingsPayload: page,
    savedAt: new Date().toISOString(),
  });
  recordHistory(dataset, requestOrigin, requestSession);
  return dataset;
}

function describe(error) {
  if (error instanceof ApiError && error.status === 404) {
    return 'Phiên quét không còn tồn tại trên máy chủ API (HTTP 404).';
  }
  if (error instanceof ApiError && error.timedOut) {
    return 'Máy chủ API không phản hồi trong thời gian cho phép.';
  }
  return error?.message || 'Không thể tải dữ liệu phiên quét từ máy chủ API.';
}

export function useScanSelection(apiRevision = 0) {
  const [params] = useSearchParams();
  const queryId = params.get('scan_id') || '';
  const currentSession = getAuthSessionScope();
  const storedId = useMemo(
    () => (queryId ? '' : (getSessionStorageSafe() ? safeSessionGet(ACTIVE_KEY) || '' : '')),
    [queryId, currentSession, apiRevision],
  );
  const scanId = queryId || storedId;
  const mode = scanId ? 'live' : 'none';
  const selectionKey = `${currentSession}:${scanId}`;
  const [state, setState] = useState({key: '', status: 'idle', data: null, error: '', statusCode: null});

  useEffect(() => {
    if (!scanId) return undefined;
    const requestOrigin = getApiOrigin();
    const requestSession = getAuthSessionScope();
    let active = true;
    const isStale = () => !active || getApiOrigin() !== requestOrigin || getAuthSessionScope() !== requestSession;
    const cached = readCache(scanId, requestSession);
    if (cached) {
      setState({key: selectionKey, status: 'ready', data: cached, error: '', statusCode: null});
    }
    const controller = new AbortController();
    if (!cached) setState({key: selectionKey, status: 'loading', data: null, error: '', statusCode: null});
    loadLiveScan(scanId, controller.signal)
      .then((data) => {
        if (controller.signal.aborted || isStale()) return;
        setState({key: selectionKey, status: 'ready', data, error: '', statusCode: null});
      })
      .catch((error) => {
        if (controller.signal.aborted || error?.abortedByConfigChange || isStale()) return;
        if (isConfirmedScanNotFoundError(error)) {
          clearStaleActiveScanId(scanId, requestSession);
        }
        setState({key: selectionKey, status: 'error', data: null, error: describe(error), statusCode: error?.status ?? null});
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [scanId, selectionKey, apiRevision]);

  const current = state.key === selectionKey
    ? state
    : {status: scanId ? 'loading' : 'idle', data: null, error: '', statusCode: null};
  return {mode, scanId, status: current.status, data: current.data, error: current.error, statusCode: current.statusCode};
}

export const scanQuery = (scanId) => (scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '');

export function evidenceText(row) {
  const preview = row?.explanationPreview;
  if (preview) return preview.length > 240 ? `${preview.slice(0, 240)}…` : preview;
  if (row?.ruleId) return `Rule: ${row.ruleId}`;
  return 'Mở chi tiết để xem trích dẫn mã nguồn và SHA-256.';
}
