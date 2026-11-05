import {useCallback, useEffect, useState} from 'react';
import {api} from './api';
import {normalizeFinding} from './scanData';
import {readIrisTraceStatus} from './scanStatus';
import {IRIS_PROOF_STATES} from './findingPresentation';

export const IN_SCOPE_CWES = ['CWE-22', 'CWE-78', 'CWE-79', 'CWE-89'];
export const SOURCE_LABELS = {
  OG: 'Chỉ OpenGrep',
  IRIS: 'Chỉ IRIS',
  BOTH: 'OpenGrep + IRIS',
  UNKNOWN: 'Backend chưa báo nguồn'
};
const SOURCE_KEYS = ['detection_source', 'detected_by', 'candidate_source', 'source', 'origin', 'detection_sources', 'sources'];

export const normCwe = (value) => {
  const match = String(value ?? '').match(/(\d+)/);
  return match ? `CWE-${parseInt(match[1], 10)}` : 'Không rõ';
};

function sourceOf(item) {
  const key = SOURCE_KEYS.find((name) => item?.[name] !== undefined && item?.[name] !== null && item?.[name] !== '');
  if (!key) return 'UNKNOWN';
  const text = JSON.stringify(item[key]).toLowerCase();
  const og = text.includes('opengrep') || text.includes('semgrep');
  const iris = text.includes('iris') || text.includes('codeql');
  if (og && iris) return 'BOTH';
  if (og) return 'OG';
  if (iris) return 'IRIS';
  return 'UNKNOWN';
}

export function toRow(item) {
  const source = item?.finding && typeof item.finding === 'object' ? {...item.finding, ...item} : item;
  const row = normalizeFinding(source);
  return {
    id: row.id,
    cwe: normCwe(row.cwe),
    decision: String(row.decision || '').toUpperCase() || 'UNKNOWN',
    irisProofState: row.irisProofState,
    file: String(row.file || ''),
    line: row.line,
    source: sourceOf(source),
    detailUrl: source?.detail_url
  };
}

const tally = (rows, pick) => {
  const map = new Map();
  rows.forEach((row) => {
    const key = pick(row);
    map.set(key, (map.get(key) || 0) + 1);
  });
  return [...map.entries()];
};

export const SCORE_BINS = [
  ['0-19', 0, 20], ['20-39', 20, 40], ['40-59', 40, 60], ['60-79', 60, 80], ['80-100', 80, 100.0001]
];

export function buildAggregates(rows, scores) {
  const scoreCounts = SCORE_BINS.map(([label, lo, hi]) => [
    label, rows.filter((row) => scores.has(row.id) && scores.get(row.id) >= lo && scores.get(row.id) < hi).length
  ]);
  const missing = rows.filter((row) => !scores.has(row.id)).length;
  return {
    byCwe: tally(rows, (row) => row.cwe).sort((a, b) => b[1] - a[1]),
    byDecision: tally(rows, (row) => row.decision),
    byFlowProof: IRIS_PROOF_STATES.map((state) => [
      state, rows.filter((row) => row.irisProofState === state).length
    ]),
    bySource: tally(rows, (row) => row.source),
    byScore: missing ? [...scoreCounts, ['Chưa có CWSS', missing]] : scoreCounts
  };
}

const numOrNull = (v) => (v === undefined || v === null || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
const fail = (rows, reason) => ({complete: false, rows, reason});

// Verifies the loaded list is the whole scan. COMPLETE only when ALL hold:
// every page loaded (backend paging total reached), every row has a finding_id,
// no duplicate finding_id, unique IDs == backend total_matching == summary total,
// and REPORT/REVIEW/SUPPRESS counts equal summary triage_totals when provided.
export function verifyCompleteness(summary, items, found) {
  const rows = items.map(toRow);
  if (!found.complete) return fail(rows, '');
  if (rows.some((row) => !row.id)) return fail(rows, 'Có finding thiếu finding_id; không thể xác minh dữ liệu đầy đủ.');
  const ids = new Set(rows.map((row) => row.id));
  if (ids.size !== rows.length) return fail(rows, 'Phát hiện finding_id trùng lặp giữa các trang; dữ liệu không được coi là đầy đủ.');
  if (found.total !== null && found.total !== ids.size) {
    return fail(rows, `Backend báo ${found.total.toLocaleString()} findings nhưng chỉ có ${ids.size.toLocaleString()} finding_id duy nhất.`);
  }
  const expected = numOrNull(summary?.total_findings ?? summary?.triage_totals?.total_candidates);
  if (expected !== null && expected !== ids.size) {
    return fail(rows, `Summary báo ${expected.toLocaleString()} findings nhưng danh sách phân trang có ${ids.size.toLocaleString()}. Hãy kiểm tra backend.`);
  }
  const totals = summary?.triage_totals || {};
  for (const decision of ['REPORT', 'REVIEW', 'SUPPRESS']) {
    const reported = numOrNull(totals[`${decision.toLowerCase()}_count`]);
    const counted = rows.filter((row) => row.decision === decision).length;
    if (reported !== null && reported !== counted) {
      return fail(rows, `Summary báo ${reported.toLocaleString()} ${decision} nhưng danh sách có ${counted.toLocaleString()}.`);
    }
  }
  return {complete: true, rows, reason: ''};
}

// Loads whole-scan data: summary (lightweight) + every /findings/page page + CWSS
// score map. Charts are only rendered when the finding list is verified complete.
export function useScanOverview(scanId) {
  const [state, setState] = useState({status: 'loading', progress: null, data: null, error: ''});
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    const {signal} = controller;
    setState({status: 'loading', progress: null, data: null, error: ''});
    (async () => {
      const summary = await api.scanSummary(scanId, {signal});
      if (summary?.scan_id !== scanId) throw new Error('Phản hồi summary không khớp scan_id đã chọn.');
      const found = await api.allFindingsPages(scanId, {
        signal,
        onProgress: (progress) => { if (!signal.aborted) setState((s) => ({...s, progress})); }
      });
      const check = verifyCompleteness(summary, found.items, found);
      let scores = new Map();
      let scoreStatus = 'ok';
      let scoreProfile = 'BUSINESS_CRITICAL_INTERNET_FACING';
      try {
        const result = await api.cwssScenarioScoreMap(scanId, {signal});
        scores = result.scores;
        scoreProfile = result.scoreProfile;
        scoreStatus = result.complete && check.complete && result.scores.size === check.rows.length &&
          check.rows.every((row) => result.scores.has(row.id)) ? 'ok' : 'partial';
      } catch (error) {
        if (signal.aborted) throw error;
        scoreStatus = 'error';
      }
      // An optional read-only trace gives Stage 05's ORIGINAL IRIS status when
      // the summary does not expose it. Failure never invalidates findings/CWSS.
      let irisTrace = null;
      if (!summary.iris_status && !summary.iris_analysis_status && !summary.iris_run_status) {
        try {
          const trace = await api.pipelineTrace(scanId, {signal});
          irisTrace = readIrisTraceStatus(trace, scanId);
        } catch (error) {
          if (signal.aborted) throw error;
        }
      }
      setState({status: 'success', progress: null, error: '',
        data: {summary, rows: check.rows, scores, scoreStatus, scoreProfile, irisTrace, complete: check.complete, reason: check.reason, total: found.total}});
    })().catch((error) => {
      if (!signal.aborted) setState({status: 'error', progress: null, data: null, error: error?.message || 'Không thể tải dữ liệu từ backend.'});
    });
    return () => controller.abort();
  }, [scanId, attempt]);
  const retry = useCallback(() => setAttempt((value) => value + 1), []);
  return [state, retry];
}