// Regression tests for the 7 Codex pre-E2E audit findings:
//   1 — Commit SHA validation & API contract label (Scanner.jsx, api.js)
//   2 — Restored active job recovery & locking new scan creation (Scanner.jsx)
//   3 — Report A/B scan_id isolation, late-response discard, download guard (ReportsPage.jsx, reportModel.js)
//   4 — Human Review (scan_id, finding_id) identity & source drift preconditions (ReviewPage.jsx, Results.jsx, HumanReviewPanel.jsx, reviewModel.js)
//   5 — Strict GitHub URL, ZIP signature/limits, write-auth & read-only proxy guards (Scanner.jsx, api.js)
//   6 — 404 recovery navigation to /history & selective sessionStorage cleanup (ReviewPage.jsx, LiveFindings.jsx, Results.jsx, ReportsPage.jsx, liveScan.js)
//   7 — Preservation of citations, SHA-256 hashes, Human Review audit trail, and approved UI provenance
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const {spawn} = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '../../..');
const APP_ROOT = path.join(__dirname, '..');
const SRC_ROOT = path.join(APP_ROOT, 'src');
const ORIGIN = 'http://127.0.0.1:19101';

function mkStorage() {
  return {
    _map: new Map(),
    get length() { return this._map.size; },
    key(i) { return [...this._map.keys()][i] ?? null; },
    getItem(k) { return this._map.has(k) ? this._map.get(k) : null; },
    setItem(k, v) { this._map.set(k, String(v)); },
    removeItem(k) { this._map.delete(k); },
  };
}

function setupDomGlobals() {
  global.window = {
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    sessionStorage: mkStorage(),
    localStorage: mkStorage(),
    location: {hash: ''},
  };
}

function esmUrl(rel, replacements = []) {
  let src = fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8');
  src = src.replace(/import\.meta\.env\?\.VITE_API_BASE_URL/g, '""');
  src = src.replace(/import\.meta\.env\.VITE_API_BASE_URL/g, '""');
  for (const [from, to] of replacements) src = src.replace(from, to);
  return `data:text/javascript;base64,${Buffer.from(`${src}\n// ${Math.random()}`).toString('base64')}`;
}

function bundleEntry(entryCode, virtualName = 'codex-test-bundle.jsx') {
  const esbuild = require(path.join(APP_ROOT, 'node_modules', 'esbuild'));
  const out = esbuild.buildSync({
    stdin: {contents: entryCode, resolveDir: APP_ROOT, loader: 'jsx', sourcefile: virtualName},
    bundle: true,
    platform: 'node',
    format: 'cjs',
    jsx: 'automatic',
    loader: {'.css': 'empty'},
    write: false,
    logLevel: 'silent',
    define: {'import.meta.env': '{}', 'process.env.NODE_ENV': '"production"'},
  });
  const m = new Module(virtualName, module);
  m.paths = module.paths;
  m._compile(out.outputFiles[0].text, path.join(APP_ROOT, `${virtualName}.cjs`));
  return m.exports;
}

function loadUiBundle() {
  const entry = `
    import {createElement as h} from 'react';
    import {renderToStaticMarkup} from 'react-dom/server';
    import {MemoryRouter, Outlet, Route, Routes} from 'react-router-dom';
    import * as apiMod from './src/services/api.js';
    import * as liveScanMod from './src/services/liveScan.js';
    import * as reportModelMod from './src/services/reportModel.js';
    import * as reviewModelMod from './src/services/reviewModel.js';
    import Scanner, {
      classifyJobPollError,
      classifyJobPollResponse,
      detectReadOnlyHealth,
      evaluateWritePermission,
      isJobBlockingNewScan,
      isJobDiscoveryBlocking,
      isReadOnlyWriteError,
      isValidGithubRepoUrl,
      runGuardedZipSubmission,
      validateCommitSha,
      validateGithubRepoUrl,
      validateScanJobsListResponse,
      validateZipSelection,
      validateZipSignature,
    } from './src/pages/Scanner.jsx';
    import ReportsPage, {
      createReportLoadRunner,
      selectEffectiveReportState,
    } from './src/pages/ReportsPage.jsx';
    import HumanReviewPanel from './src/components/review/HumanReviewPanel.jsx';

    function renderWithOutlet(element, outletContext, initialEntry = '/') {
      function Layout() {
        return h(Outlet, {context: outletContext});
      }
      return renderToStaticMarkup(
        h(MemoryRouter, {initialEntries: [initialEntry]},
          h(Routes, null,
            h(Route, {element: h(Layout)},
              h(Route, {path: '*', element}),
            ),
          ),
        ),
      );
    }

    export {
      apiMod,
      liveScanMod,
      reportModelMod,
      reviewModelMod,
      classifyJobPollError,
      classifyJobPollResponse,
      detectReadOnlyHealth,
      evaluateWritePermission,
      isJobBlockingNewScan,
      isJobDiscoveryBlocking,
      isReadOnlyWriteError,
      isValidGithubRepoUrl,
      runGuardedZipSubmission,
      validateCommitSha,
      validateGithubRepoUrl,
      validateScanJobsListResponse,
      validateZipSelection,
      validateZipSignature,
      createReportLoadRunner,
      selectEffectiveReportState,
    };

    export function renderScanner(outletContext) {
      return renderWithOutlet(h(Scanner), outletContext, '/scanner');
    }

    export function renderReports(outletContext, url = '/reports') {
      return renderWithOutlet(h(ReportsPage), outletContext, url);
    }

    export function renderReviewPanel(props, outletContext = {}) {
      return renderWithOutlet(h(HumanReviewPanel, props), outletContext, '/review');
    }
  `;
  return bundleEntry(entry, 'codex-pre-e2e-ui.jsx');
}

function makeZipFile(name, bytes, declaredSize = null) {
  const buf = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  return {
    name,
    size: declaredSize === null ? buf.byteLength : declaredSize,
    slice(start, end) {
      const sub = buf.slice(start, end);
      return {
        async arrayBuffer() {
          return sub.buffer.slice(sub.byteOffset, sub.byteOffset + sub.byteLength);
        },
      };
    },
  };
}

function makeReportDoc(scanId, {extraFindings = [], isMock = false} = {}) {
  const sha = 'a'.repeat(64);
  return {
    report_schema: 'ntk-report-v1',
    generated_at: '2026-11-20T10:00:00Z',
    data_origin: isMock ? 'MOCK_SYNTHETIC_TEST' : 'REAL_SCAN',
    contains_mock_or_test_data: isMock,
    scan_summary: {
      scan_id: scanId,
      scan_sha256: sha,
      input_mode: 'GITHUB',
      repo_url: `https://github.com/example/${scanId}`,
      java_files_scanned: 3,
      opengrep_version: '1.25.0',
      rules_sha256: 'b'.repeat(64),
      total_findings: 1 + extraFindings.length,
      findings_with_trace: 1,
      validator_downgraded_count: 0,
      matched_citation_count: 1,
      by_cwe: {'CWE-22': 1},
      by_validated_status: {SUPPORTED: 0, REFUTED: 1, UNDETERMINED: 0},
      by_human_review_state: {OPEN: 1, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
      scan_issues: [],
      known_analysis_limits: ['Bounded to OpenGrep rules'],
    },
    audit_trail: {events_count: 0, rejected_decisions_count: 0, events: [], rejected_decisions: []},
    findings: [
      {
        finding_id: `f-${scanId}-1`,
        scan_id: scanId,
        cwe: 'CWE-22',
        validated_status: 'REFUTED',
        human_review_state: 'OPEN',
        citation_check: 'MATCHED',
        evidence: {snapshots: {'src/Demo.java': {sha256: sha, size: 120}}},
        assessment: {citations: [{path: 'src/Demo.java', start_line: 10, end_line: 10, quote: 'new File(p);', sha256: sha}]},
      },
      ...extraFindings,
    ],
  };
}

function makeFindingDetail(scanId, findingId, overrides = {}) {
  const sha = 'c'.repeat(64);
  return {
    scan_id: scanId,
    finding_id: findingId,
    id: findingId,
    cwe: 'CWE-89',
    validated_status: 'REFUTED',
    human_review_state: 'OPEN',
    citation_check: 'MATCHED',
    writable: true,
    data_origin: 'REAL_SCAN',
    evidence: {
      id: findingId,
      path: 'src/SqlDemo.java',
      issues: [],
      scan_provenance: {source_capture_verified: true, exit_capture_verified: true},
      snapshots: {'src/SqlDemo.java': {sha256: sha, size: 256}},
      snippets: [{role: 'finding', path: 'src/SqlDemo.java', start: {line: 5}, end: {line: 5}, sha256: sha}],
    },
    assessment: {
      validated_status: 'REFUTED',
      citation_check: 'MATCHED',
      citations: [{path: 'src/SqlDemo.java', start_line: 5, end_line: 5, quote: 'ps.executeQuery()', sha256: sha}],
    },
    review_events: [],
    rejected_decisions: [],
    ...overrides,
  };
}

// ------------------------------------------------------------------------------------------------
// Finding 1 — Commit SHA validation & API contract labels
// ------------------------------------------------------------------------------------------------

test('Issue 1: Commit SHA validator enforces 7–40 hex chars, rejects branch names like main, allows empty default branch, and Scanner uses exact contract label', async () => {
  setupDomGlobals();
  const prevFetch = global.fetch;
  const fetchCalls = [];
  global.fetch = async (url, options = {}) => {
    fetchCalls.push({url, method: options.method || 'GET', body: options.body});
    return new Response(JSON.stringify({job_id: 'job-ok-1', state: 'QUEUED'}), {status: 202});
  };
  try {
    const apiUrl = esmUrl('services/api.js');
    const apiMod = await import(apiUrl);
    apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'mock-token-123456'});

    // Empty / whitespace -> uses repository default branch (commit_sha omitted)
    assert.deepEqual(apiMod.validateCommitSha(''), {valid: true, normalized: undefined, error: ''});
    assert.deepEqual(apiMod.validateCommitSha('   '), {valid: true, normalized: undefined, error: ''});
    assert.deepEqual(apiMod.validateCommitSha(undefined), {valid: true, normalized: undefined, error: ''});

    // Valid 7-char, 40-char, uppercase hex normalized to lowercase
    assert.equal(apiMod.validateCommitSha('7F6B76C').valid, true);
    assert.equal(apiMod.validateCommitSha('7F6B76C').normalized, '7f6b76c');
    assert.equal(apiMod.validateCommitSha('7f6b76c5056a82292a87cafa78f922077a211feb').valid, true);

    // Invalid branch names, short/long/non-hex SHAs -> rejected cleanly
    for (const bad of ['main', 'master', 'develop', 'origin/main', 'v1.0.0', 'HEAD', '123456', 'a'.repeat(41), 'zzzzzzz', '7f6b76c main']) {
      const res = apiMod.validateCommitSha(bad);
      assert.equal(res.valid, false, `must reject invalid commit SHA: ${bad}`);
      assert.match(res.error, /7–40/);
    }

    // api.createScanJob rejects branch name 'main' BEFORE sending any HTTP request
    await assert.rejects(
      () => apiMod.api.createScanJob('https://github.com/org/repo', 'main'),
      (err) => err instanceof apiMod.ApiError && err.code === 'INVALID_COMMIT_SHA',
    );
    assert.equal(fetchCalls.length, 0, 'invalid commit SHA must emit zero HTTP requests');

    // Empty commit SHA omits commit_sha field so backend clones default branch
    await apiMod.api.createScanJob('https://github.com/org/repo', '   ');
    assert.equal(fetchCalls.length, 1);
    const bodyDefault = JSON.parse(fetchCalls[0].body);
    assert.equal(bodyDefault.repo_url, 'https://github.com/org/repo');
    assert.equal(Object.hasOwn(bodyDefault, 'commit_sha'), false);

    // Valid uppercase SHA is normalized to lowercase; .git suffix is preserved for single-place backend canonicalization
    await apiMod.api.createScanJob('https://github.com/org/repo.git', '7F6B76C');
    assert.equal(fetchCalls.length, 2);
    const bodyPinned = JSON.parse(fetchCalls[1].body);
    assert.equal(bodyPinned.repo_url, 'https://github.com/org/repo.git');
    assert.equal(bodyPinned.commit_sha, '7f6b76c');

    // Scanner.jsx contract labels
    const scannerSrc = fs.readFileSync(path.join(SRC_ROOT, 'pages/Scanner.jsx'), 'utf8');
    assert.match(scannerSrc, /Commit SHA \(không bắt buộc\)/);
    assert.doesNotMatch(scannerSrc, /Nhánh hoặc Commit SHA/);
    assert.doesNotMatch(scannerSrc, /Ví dụ:\s*main/);
  } finally {
    global.fetch = prevFetch;
  }
});

// ------------------------------------------------------------------------------------------------
// Finding 2 — Restored active job recovery & preventing duplicate job creation
// ------------------------------------------------------------------------------------------------

test('Issue 2: restored active jobId locks Scanner until API confirms terminal/404, keeps JOB_KEY across transient failures, and unlocks when finished or 404', () => {
  setupDomGlobals();
  const ui = loadUiBundle();

  // Persisted jobId in sessionStorage when user returns to Scanner
  window.sessionStorage.setItem('22025523-active-job', 'job-active-999');
  const html = ui.renderScanner({
    apiOrigin: ORIGIN,
    authSessionScope: `${ORIGIN}#s1`,
    apiRevision: 1,
    backend: {status: 'CONNECTED', health: {status: 'OK', write_auth_required: true, write_auth_configured: true, authenticated: true}},
  });
  assert.match(html, /Đang xác minh job…/, 'restored jobId must immediately lock submit button on initial render');
  assert.match(html, /<button[^>]*type="submit"[^>]*disabled=""/, 'submit button must be disabled while verifying restored job');
  assert.equal(
    window.sessionStorage.getItem('22025523-active-job'),
    'job-active-999',
    'restored jobId must NOT be deleted before API verifies its status',
  );

  // Blocking matrix
  for (const locked of ['VERIFYING', 'SUBMITTING', 'WAITING_FOR_RESPONSE', 'QUEUED', 'RUNNING', 'LOADING_RESULTS', 'INTERRUPTED', 'UNKNOWN']) {
    assert.equal(ui.isJobBlockingNewScan(locked), true, `${locked} must block creating a new scan`);
  }
  for (const unlocked of ['IDLE', 'COMPLETED', 'FAILED', 'RESULTS_ERROR', 'NOT_FOUND']) {
    assert.equal(ui.isJobBlockingNewScan(unlocked), false, `${unlocked} must allow creating a new scan`);
  }

  // Poll response classification
  const queued = ui.classifyJobPollResponse({job_id: 'job-1', state: 'QUEUED'}, 'job-1');
  assert.equal(queued.clearStoredJob, false);
  assert.equal(ui.isJobBlockingNewScan(queued.trackingState), true);

  const running = ui.classifyJobPollResponse({job_id: 'job-1', state: 'RUNNING', active_stage: 4}, 'job-1');
  assert.equal(running.clearStoredJob, false);
  assert.equal(ui.isJobBlockingNewScan(running.trackingState), true);

  const mismatched = ui.classifyJobPollResponse({job_id: 'job-other', state: 'COMPLETED'}, 'job-1');
  assert.equal(mismatched.kind, 'MISMATCH');
  assert.equal(mismatched.clearStoredJob, false);
  assert.equal(ui.isJobBlockingNewScan(mismatched.trackingState), true);

  const completed = ui.classifyJobPollResponse({job_id: 'job-1', state: 'COMPLETED', scan_id: 'scan-1'}, 'job-1');
  assert.equal(completed.kind, 'COMPLETED');
  assert.equal(completed.clearStoredJob, true);

  const failed = ui.classifyJobPollResponse({job_id: 'job-1', state: 'FAILED'}, 'job-1');
  assert.equal(failed.kind, 'FAILED');
  assert.equal(failed.clearStoredJob, true);
  assert.equal(ui.isJobBlockingNewScan(failed.trackingState), false);

  // Poll error classification: transient errors NEVER mark job finished or clear JOB_KEY
  const netErr = ui.classifyJobPollError(new TypeError('Failed to fetch'));
  assert.equal(netErr.kind, 'TRANSIENT');
  assert.equal(netErr.clearStoredJob, false);
  assert.equal(netErr.retryPoll, true);
  assert.equal(ui.isJobBlockingNewScan(netErr.trackingState), true);

  const err503 = ui.classifyJobPollError({status: 503, message: 'Service Unavailable'});
  assert.equal(err503.clearStoredJob, false);
  assert.equal(ui.isJobBlockingNewScan(err503.trackingState), true);

  const err401 = ui.classifyJobPollError({status: 401, code: 'UNAUTHORIZED'});
  assert.equal(err401.kind, 'AUTH_ERROR');
  assert.equal(err401.clearStoredJob, false);
  assert.equal(err401.retryPoll, false);
  assert.equal(ui.isJobBlockingNewScan(err401.trackingState), true);

  // Confirmed 404 JOB_NOT_FOUND clears JOB_KEY and unlocks; ROUTE_NOT_FOUND stays fail-closed
  const err404Job = ui.classifyJobPollError({status: 404, code: 'JOB_NOT_FOUND'});
  assert.equal(err404Job.kind, 'NOT_FOUND');
  assert.equal(err404Job.clearStoredJob, true);
  assert.equal(ui.isJobBlockingNewScan(err404Job.trackingState), false);

  const err404Route = ui.classifyJobPollError({status: 404, code: 'ROUTE_NOT_FOUND'});
  assert.equal(err404Route.clearStoredJob, false);
  assert.equal(ui.isJobBlockingNewScan(err404Route.trackingState), true);
});

// ------------------------------------------------------------------------------------------------
// Finding 3 — ReportsPage A/B scan_id binding, stale-state clearing & late-response protection
// ------------------------------------------------------------------------------------------------

test('Issue 3: switching ReportsPage A -> B drops A synchronously, discards late A responses, and blocks mismatched scan_id reports from display/download', async () => {
  setupDomGlobals();
  const ui = loadUiBundle();

  const reportA = makeReportDoc('scan-A');
  const reportB = makeReportDoc('scan-B');

  // 1. Synchronous render guard when URL switches A -> B before effect runs
  const stateHoldingA = {
    key: `${ORIGIN}#s1|${ORIGIN}|1|scan-A`,
    scanId: 'scan-A',
    status: 'ready',
    data: reportA,
    error: '',
    statusCode: null,
  };
  const effectiveForB = ui.selectEffectiveReportState(stateHoldingA, {
    reportKey: `${ORIGIN}#s1|${ORIGIN}|1|scan-B`,
    scanId: 'scan-B',
  });
  assert.equal(effectiveForB.status, 'loading', 'Report A state must not bleed into Scan B on transition');
  assert.equal(effectiveForB.data, null);
  assert.equal(effectiveForB.scanId, 'scan-B');

  // 2. Late API response for A (even ignoring AbortSignal) must NEVER overwrite B
  let resolveA;
  let resolveB;
  const states = [];
  const runner = ui.createReportLoadRunner({
    apiClient: {
      report: (scanId) => new Promise((resolve) => {
        if (scanId === 'scan-A') resolveA = resolve;
        else resolveB = resolve;
      }),
    },
    getOrigin: () => ORIGIN,
    getSession: () => `${ORIGIN}#s1`,
    onState: (s) => states.push(s),
  });

  const taskA = runner.load('scan-A', 'k-A');
  const taskB = runner.load('scan-B', 'k-B');
  resolveB(reportB);
  const resB = await taskB.promise;
  assert.equal(resB.status, 'ready');
  assert.equal(resB.data.scan_summary.scan_id, 'scan-B');

  // Slow response A arrives AFTER B finished -> must be discarded!
  resolveA(reportA);
  const resA = await taskA.promise;
  assert.deepEqual(resA, {stale: true});
  assert.equal(states.at(-1).scanId, 'scan-B');
  assert.equal(states.at(-1).data.scan_summary.scan_id, 'scan-B');

  // 3. Backend/proxy returns Report A payload for a Scan B request -> rejected, data=null
  const mismatchStates = [];
  const mismatchRunner = ui.createReportLoadRunner({
    apiClient: {report: async () => reportA},
    getOrigin: () => ORIGIN,
    getSession: () => `${ORIGIN}#s1`,
    onState: (s) => mismatchStates.push(s),
  });
  const mismatchRes = await mismatchRunner.load('scan-B', 'k-B').promise;
  assert.equal(mismatchRes.status, 'error');
  assert.equal(mismatchRes.data, null);
  assert.match(mismatchRes.error, /scan-A.*scan-B/);

  // 4. Validator rejects missing scan_id and foreign finding scan_id, while preserving valid report citations/hashes
  assert.equal(ui.reportModelMod.validateReportForScan({scan_summary: {}}, 'scan-B').valid, false);
  const mixedFindingReport = makeReportDoc('scan-B', {
    extraFindings: [{finding_id: 'f-leak', scan_id: 'scan-A', cwe: 'CWE-89'}],
  });
  assert.equal(ui.reportModelMod.validateReportForScan(mixedFindingReport, 'scan-B').valid, false);
  assert.equal(ui.reportModelMod.buildReportViewModel(reportA, {expectedScanId: 'scan-B'}), null);

  const vmB = ui.reportModelMod.buildReportViewModel(reportB, {expectedScanId: 'scan-B'});
  assert.equal(vmB.canExportReport, true);
  assert.equal(vmB.scanInfo.scanId, 'scan-B');
  assert.equal(vmB.qwenStats.refuted, 1);
  assert.equal(vmB.humanReviewStats.confirmedFalse, 0);
  assert.equal(vmB.humanReviewStats.refutedStillOpen, 1);
  assert.equal(vmB.findingRows[0].citations.length, 1);
  assert.equal(vmB.findingRows[0].snapshots[0].sha256, 'a'.repeat(64));
});

// ------------------------------------------------------------------------------------------------
// Finding 4 — Human Review (scan_id, finding_id) identity & source drift preconditions
// ------------------------------------------------------------------------------------------------

test('Issue 4: Human Review enforces both scan_id and finding_id, blocks confirm-false without source drift preconditions, and preserves valid review/audit flow', async () => {
  setupDomGlobals();
  const ui = loadUiBundle();

  const validDetail = makeFindingDetail('scan-A', 'finding-1');
  const wrongScanDetail = makeFindingDetail('scan-B', 'finding-1');
  const wrongFindingDetail = makeFindingDetail('scan-A', 'finding-2');
  const missingScanDetail = {...validDetail, scan_id: ''};
  const unverifiedCaptureDetail = makeFindingDetail('scan-A', 'finding-1', {
    evidence: {
      ...validDetail.evidence,
      scan_provenance: {source_capture_verified: false},
    },
  });
  const missingSnapshotsDetail = makeFindingDetail('scan-A', 'finding-1', {
    evidence: {
      ...validDetail.evidence,
      snapshots: {},
    },
  });
  const issuesDetail = makeFindingDetail('scan-A', 'finding-1', {
    evidence: {
      ...validDetail.evidence,
      issues: ['missing source snippet'],
    },
  });

  // Identity validator checks BOTH scan_id and finding_id
  assert.equal(ui.reviewModelMod.verifyFindingIdentity(validDetail, 'scan-A', 'finding-1').valid, true);
  assert.equal(ui.reviewModelMod.verifyFindingIdentity(wrongScanDetail, 'scan-A', 'finding-1').valid, false);
  assert.equal(ui.reviewModelMod.verifyFindingIdentity(wrongFindingDetail, 'scan-A', 'finding-1').valid, false);
  assert.equal(ui.reviewModelMod.verifyFindingIdentity(missingScanDetail, 'scan-A', 'finding-1').valid, false);

  // Queue / review-history scan_id validator
  assert.equal(ui.reviewModelMod.verifyScanPayloadIdentity({scan_id: 'scan-A', warnings: [{scan_id: 'scan-A', finding_id: 'f-1'}]}, 'scan-A', {itemsKey: 'warnings'}).valid, true);
  assert.equal(ui.reviewModelMod.verifyScanPayloadIdentity({scan_id: 'scan-B', warnings: []}, 'scan-A', {itemsKey: 'warnings'}).valid, false);
  assert.equal(ui.reviewModelMod.verifyScanPayloadIdentity({scan_id: 'scan-A', warnings: [{scan_id: 'scan-B', finding_id: 'f-1'}]}, 'scan-A', {itemsKey: 'warnings'}).valid, false);

  // Source drift readiness preconditions
  assert.equal(ui.reviewModelMod.evaluateSourceDriftReadiness(validDetail).canConfirmFalse, true);
  assert.equal(ui.reviewModelMod.evaluateSourceDriftReadiness(unverifiedCaptureDetail).canConfirmFalse, false);
  assert.equal(ui.reviewModelMod.evaluateSourceDriftReadiness(missingSnapshotsDetail).canConfirmFalse, false);
  assert.equal(ui.reviewModelMod.evaluateSourceDriftReadiness(issuesDetail).canConfirmFalse, false);
  assert.equal(ui.reviewModelMod.evaluateSourceDriftReadiness(validDetail, {hashConflict: true}).canConfirmFalse, false);

  // submitReviewDecision stops BEFORE calling API on identity mismatch or missing source drift preconditions
  let postCount = 0;
  const mockApi = {
    confirmTrue: async () => { postCount += 1; return validDetail; },
    confirmFalse: async () => { postCount += 1; return validDetail; },
    reopenFinding: async () => { postCount += 1; return validDetail; },
    findingDetail: async () => validDetail,
    findingHistory: async () => ({}),
  };

  const mismatchSubmit = await ui.reviewModelMod.submitReviewDecision({
    scanId: 'scan-A',
    findingId: 'finding-1',
    action: 'confirm-true',
    actor: 'reviewer-uet',
    reason: 'Checking identity block',
    detail: wrongScanDetail,
    apiClient: mockApi,
  });
  assert.equal(mismatchSubmit.ok, false);
  assert.equal(mismatchSubmit.errorCode, 'SCAN_ID_MISMATCH');
  assert.equal(postCount, 0, 'identity mismatch must never send POST');

  const noDriftSubmit = await ui.reviewModelMod.submitReviewDecision({
    scanId: 'scan-A',
    findingId: 'finding-1',
    action: 'confirm-false',
    actor: 'reviewer-uet',
    reason: 'Attempting confirm-false without source_capture_verified',
    detail: unverifiedCaptureDetail,
    apiClient: mockApi,
  });
  assert.equal(noDriftSubmit.ok, false);
  assert.equal(noDriftSubmit.errorCode, 'SOURCE_DRIFT_PRECONDITION_UNMET');
  assert.equal(postCount, 0, 'unmet source drift precondition must block confirm-false before POST');

  // Post-mutation refresh returning wrong scan_id is rejected
  const wrongRefreshApi = {
    ...mockApi,
    findingDetail: async () => wrongScanDetail,
  };
  const badRefreshRes = await ui.reviewModelMod.submitReviewDecision({
    scanId: 'scan-A',
    findingId: 'finding-1',
    action: 'confirm-true',
    actor: 'reviewer-uet',
    reason: 'Confirm true then detect wrong refresh scan_id',
    detail: validDetail,
    apiClient: wrongRefreshApi,
  });
  assert.equal(badRefreshRes.ok, false);
  assert.equal(badRefreshRes.errorCode, 'SCAN_ID_MISMATCH');

  // Rendered HumanReviewPanel UI guards
  const htmlWrongId = ui.renderReviewPanel({
    scanId: 'scan-A',
    findingId: 'finding-1',
    detail: wrongScanDetail,
    writable: true,
    validatedStatus: 'REFUTED',
    humanReviewState: 'OPEN',
  });
  assert.match(htmlWrongId, /không khớp phiên đang chọn/);
  assert.match(htmlWrongId, /<button[^>]*disabled=""[^>]*>.*Xác nhận cảnh báo thật/);
  assert.match(htmlWrongId, /<button[^>]*disabled=""[^>]*>.*Xác nhận cảnh báo giả/);

  const htmlNoDrift = ui.renderReviewPanel({
    scanId: 'scan-A',
    findingId: 'finding-1',
    detail: unverifiedCaptureDetail,
    writable: true,
    validatedStatus: 'REFUTED',
    humanReviewState: 'OPEN',
  });
  assert.match(htmlNoDrift, /source drift/i);
  // confirm-false button is disabled while confirm-true button remains enabled
  const buttonsNoDrift = [...htmlNoDrift.matchAll(/<button[^>]*>[\s\S]*?<\/button>/g)].map((m) => m[0]);
  const confirmTrueBtn = buttonsNoDrift.find((b) => b.includes('Xác nhận cảnh báo thật'));
  const confirmFalseBtn = buttonsNoDrift.find((b) => b.includes('Xác nhận cảnh báo giả'));
  assert(confirmTrueBtn && !confirmTrueBtn.includes('disabled=""'), 'confirm-true remains allowed when only confirm-false drift precondition is unmet');
  assert(confirmFalseBtn && confirmFalseBtn.includes('disabled=""'), 'confirm-false must be disabled when source drift preconditions are unmet');

  // api.findingDetail ignores stale detailUrl pointing to a different scan/finding
  const prevFetch = global.fetch;
  const seenUrls = [];
  global.fetch = async (url) => {
    seenUrls.push(url);
    return new Response(JSON.stringify(validDetail), {status: 200});
  };
  try {
    ui.apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'tok-1234567890'});
    await ui.apiMod.api.findingDetail('scan-A', 'finding-1', '/api/scans/scan-OTHER/findings/finding-OTHER');
    assert.equal(seenUrls.at(-1), `${ORIGIN}/api/scans/scan-A/findings/finding-1`);
  } finally {
    global.fetch = prevFetch;
  }
});

// ------------------------------------------------------------------------------------------------
// Finding 5 — Strict GitHub URL, ZIP magic signature/limits & write authorization
// ------------------------------------------------------------------------------------------------

test('Issue 5: strict GitHub URL validator, ZIP magic-byte signature, write-auth token requirement, and read-only proxy guards match backend contract', async () => {
  setupDomGlobals();
  const ui = loadUiBundle();

  // Valid GitHub URLs
  for (const okUrl of [
    'https://github.com/owner/repo',
    'https://github.com/owner/repo/',
    'https://github.com/owner/repo.git',
    'https://github.com/Org-01/java_app.v2',
  ]) {
    const r = ui.validateGithubRepoUrl(okUrl);
    assert.equal(r.valid, true, `should accept valid GitHub URL: ${okUrl}`);
    assert.equal(ui.isValidGithubRepoUrl(okUrl), true);
  }

  // Invalid GitHub URLs matching v2/api/intake.py rejections
  for (const badUrl of [
    '',
    'http://github.com/owner/repo',
    'https://www.github.com/owner/repo',
    'https://github.com:443/owner/repo',
    'https://user:pass@github.com/owner/repo',
    'https://github.com/owner/repo?tab=readme',
    'https://github.com/owner/repo#readme',
    'https://github.com/owner/repo/tree/main',
    'https://github.com/-owner/repo',
    'https://github.com/_owner/repo',
    'https://github.com/owner/-repo',
    'https://github.com/owner/.git',
    'https://github.com/owner/..',
    'https://github.com/owner//repo',
    'https://github.com/owner\\repo',
    `https://github.com/${'a'.repeat(101)}/repo`,
    `https://github.com/owner/${'b'.repeat(290)}`,
    'https://github.com/owner/re po',
  ]) {
    assert.equal(ui.validateGithubRepoUrl(badUrl).valid, false, `must reject invalid GitHub URL: ${badUrl}`);
  }

  // ZIP limits + magic-byte signature
  const validZip = makeZipFile('project.zip', [0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]);
  const emptyArchiveZip = makeZipFile('empty-eocd.zip', [0x50, 0x4b, 0x05, 0x06, 0x00, 0x00]);
  const fakeRenamedZip = makeZipFile('fake.zip', [0x4d, 0x5a, 0x90, 0x00, 0x03]); // MZ executable renamed to .zip
  const tinyZip = makeZipFile('tiny.zip', [0x50, 0x4b]);
  const oversizedZip = makeZipFile('huge.zip', [0x50, 0x4b, 0x03, 0x04], 26 * 1024 * 1024);
  const wrongExt = makeZipFile('project.tar.gz', [0x50, 0x4b, 0x03, 0x04]);

  assert.equal(ui.validateZipSelection(validZip, 25 * 1024 * 1024).valid, true);
  assert.equal(ui.validateZipSelection(oversizedZip, 25 * 1024 * 1024).valid, false);
  assert.equal(ui.validateZipSelection(wrongExt, 25 * 1024 * 1024).valid, false);
  assert.equal((await ui.validateZipSignature(validZip)).valid, true);
  assert.equal((await ui.validateZipSignature(emptyArchiveZip)).valid, true);
  const fakeSig = await ui.validateZipSignature(fakeRenamedZip);
  assert.equal(fakeSig.valid, false);
  assert.match(fakeSig.error, /INVALID_ZIP_ARCHIVE/);
  assert.equal((await ui.validateZipSignature(tinyZip)).valid, false);

  // Write permission checks: write-only API requiring Bearer token without token -> BLOCKED!
  const missingTokenWriteOnly = ui.evaluateWritePermission({
    backend: {
      status: 'CONNECTED',
      health: {status: 'OK', auth_required: false, write_auth_required: true, write_auth_configured: true, authenticated: false},
    },
    hasToken: false,
  });
  assert.equal(missingTokenWriteOnly.allowed, false);
  assert.equal(missingTokenWriteOnly.kind, 'MISSING_BEARER_TOKEN');

  // Wrong token in write-only mode -> BLOCKED!
  const invalidTokenWriteOnly = ui.evaluateWritePermission({
    backend: {
      status: 'CONNECTED',
      health: {status: 'OK', auth_required: false, write_auth_required: true, write_auth_configured: true, authenticated: false},
    },
    hasToken: true,
  });
  assert.equal(invalidTokenWriteOnly.allowed, false);
  assert.equal(invalidTokenWriteOnly.kind, 'MISSING_BEARER_TOKEN');

  // Server has no NTK_API_TOKEN configured -> BLOCKED!
  const unconfiguredServer = ui.evaluateWritePermission({
    backend: {
      status: 'DEGRADED',
      health: {status: 'DEGRADED', write_auth_required: true, write_auth_configured: false, degraded_reasons: ['WRITE_AUTH_TOKEN_NOT_CONFIGURED']},
    },
    hasToken: false,
  });
  assert.equal(unconfiguredServer.allowed, false);
  assert.equal(unconfiguredServer.kind, 'AUTH_TOKEN_NOT_CONFIGURED');

  // Read-only proxy -> BLOCKED!
  const roProxy = ui.evaluateWritePermission({
    backend: {status: 'CONNECTED', health: {status: 'OK', proxy_mode: 'read-only'}},
    hasToken: true,
  });
  assert.equal(roProxy.allowed, false);
  assert.equal(roProxy.kind, 'READ_ONLY_PROXY');
  assert.equal(ui.isReadOnlyWriteError({status: 403, code: 'READ_ONLY_PROXY'}), true);
  assert.equal(ui.isReadOnlyWriteError({status: 405}), true);

  // Authenticated connected server -> ALLOWED!
  const allowedWrite = ui.evaluateWritePermission({
    backend: {
      status: 'CONNECTED',
      health: {status: 'OK', write_auth_required: true, write_auth_configured: true, authenticated: true},
    },
    hasToken: true,
  });
  assert.equal(allowedWrite.allowed, true);

  // Rendered Scanner UI surfaces missing Bearer Token warning and disables submit button
  const htmlNeedToken = ui.renderScanner({
    apiOrigin: ORIGIN,
    authSessionScope: `${ORIGIN}#s1`,
    apiRevision: 1,
    openConnectionPanel: () => {},
    backend: {
      status: 'CONNECTED',
      health: {status: 'OK', auth_required: false, write_auth_required: true, write_auth_configured: true, authenticated: false},
    },
  });
  assert.match(htmlNeedToken, /Bearer Token/);
  assert.match(htmlNeedToken, /Nhập Bearer Token phiên/);
  assert.match(htmlNeedToken, /<button[^>]*type="submit"[^>]*disabled=""/);
});

// ------------------------------------------------------------------------------------------------
// Finding 6 — 404 recovery navigates to /history and never deletes another valid scan_id
// ------------------------------------------------------------------------------------------------

test('Issue 6: 404 clears only the dead scan_id from sessionStorage, preserves any other valid scan_id, and wires 404 buttons to /history', async () => {
  setupDomGlobals();
  const ui = loadUiBundle();
  const prevFetch = global.fetch;

  try {
    ui.apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'tok-valid-123456'});

    // 1. If sessionStorage holds dead-404, clearStaleActiveScanId removes it
    window.sessionStorage.setItem(ui.liveScanMod.ACTIVE_KEY, 'dead-scan-404');
    assert.equal(ui.liveScanMod.clearStaleActiveScanId('dead-scan-404'), true);
    assert.equal(window.sessionStorage.getItem(ui.liveScanMod.ACTIVE_KEY), null);

    // 2. If sessionStorage holds valid-scan-keep, a 404 for dead-scan-404 MUST NOT delete valid-scan-keep
    window.sessionStorage.setItem(ui.liveScanMod.ACTIVE_KEY, 'valid-scan-keep');
    assert.equal(ui.liveScanMod.clearStaleActiveScanId('dead-scan-404'), false);
    assert.equal(window.sessionStorage.getItem(ui.liveScanMod.ACTIVE_KEY), 'valid-scan-keep');

    // 3. loadLiveScan returning 404 removes dead-scan-404 if stored, but preserves valid-scan-keep
    global.fetch = async () => new Response(JSON.stringify({error_code: 'SCAN_NOT_FOUND', error_message: 'missing'}), {status: 404});
    await assert.rejects(() => ui.liveScanMod.loadLiveScan('dead-scan-404'), (e) => e.status === 404);
    assert.equal(window.sessionStorage.getItem(ui.liveScanMod.ACTIVE_KEY), 'valid-scan-keep');

    window.sessionStorage.setItem(ui.liveScanMod.ACTIVE_KEY, 'dead-scan-404');
    await assert.rejects(() => ui.liveScanMod.loadLiveScan('dead-scan-404'), (e) => e.status === 404);
    assert.equal(window.sessionStorage.getItem(ui.liveScanMod.ACTIVE_KEY), null);

    // 4. createReportLoadRunner returning 404 clears only matching dead scan_id
    window.sessionStorage.setItem(ui.liveScanMod.ACTIVE_KEY, 'valid-scan-keep');
    const runner = ui.createReportLoadRunner({
      apiClient: {report: async () => { throw new ui.apiMod.ApiError('Not found', {status: 404}); }},
      getOrigin: () => ORIGIN,
      getSession: () => ui.apiMod.getAuthSessionScope(),
      onNotFound: ui.liveScanMod.clearStaleActiveScanId,
      onState: () => {},
    });
    const res404 = await runner.load('dead-scan-404', 'k-404').promise;
    assert.equal(res404.status, 'error');
    assert.equal(res404.statusCode, 404);
    assert.equal(window.sessionStorage.getItem(ui.liveScanMod.ACTIVE_KEY), 'valid-scan-keep');

    // 5. All affected pages wire 404 navigation to /history (never reloading stale /review or /findings)
    for (const rel of ['pages/ReviewPage.jsx', 'pages/LiveFindings.jsx', 'pages/Results.jsx', 'pages/ReportsPage.jsx']) {
      const code = fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8');
      assert(code.includes("navigate('/history', {replace: true})"), `${rel} must navigate to /history on 404`);
      assert(code.includes('clearStaleActiveScanId'), `${rel} must clear stale 404 scan_id selectively`);
    }
    const reviewCode = fs.readFileSync(path.join(SRC_ROOT, 'pages/ReviewPage.jsx'), 'utf8');
    assert.doesNotMatch(reviewCode, /navigate\('\/review'/);
    const liveFindingsCode = fs.readFileSync(path.join(SRC_ROOT, 'pages/LiveFindings.jsx'), 'utf8');
    assert.doesNotMatch(liveFindingsCode, /navigate\('\/findings'/);
  } finally {
    global.fetch = prevFetch;
  }
});

// ------------------------------------------------------------------------------------------------
// Ephemeral ThesisApiServer verification (no live SQLite, no OpenGrep/Qwen) — citations, source hash,
// Human Review, and report identity end-to-end against real API contract
// ------------------------------------------------------------------------------------------------

function startTempContractServer(tmpRoot) {
  const pyCode = `
import json, pathlib, sys
from v2.api.config import ApiConfig
from v2.api.server import ThesisApiServer
from v2.triage import evidence, store

root = pathlib.Path(sys.argv[1])
token = "codex-pre-e2e-temp-token-20261120"

def make_scan(name, *, verified_capture=True, include_trace=True):
    sub = root / name
    src_dir = sub / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    jf = src_dir / "Demo.java"
    code = (
        "package demo;\\n"
        "public class Demo {\\n"
        "    public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\\n"
        '        String id = req.getParameter("id");\\n'
        '        st.executeQuery("SELECT * FROM u WHERE id=" + id);\\n'
        "    }\\n"
        "}\\n"
        f"// {name}\\n"
    )
    jf.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("id")'
    sink = 'st.executeQuery("SELECT * FROM u WHERE id=" + id)'
    col_s = lines[3].index(src_txt) + 1
    col = lines[4].index(sink) + 1
    src_loc = {"path": "Demo.java", "start": {"line": 4, "col": col_s}, "end": {"line": 4, "col": col_s + len(src_txt)}}
    loc = {"path": "Demo.java", "start": {"line": 5, "col": col}, "end": {"line": 5, "col": col + len(sink)}}
    extra = {
        "severity": "ERROR",
        "message": f"SQLi {name}",
        "metadata": {"cwe": ["CWE-89: SQL Injection"]},
    }
    if include_trace:
        extra["dataflow_trace"] = {
            "taint_source": ["CliLoc", [src_loc, src_txt]],
            "taint_sink": ["CliLoc", [loc, sink]],
            "intermediate_vars": [],
        }
    finding = {
        "check_id": "v2.g1.java.cwe89.sqli",
        **loc,
        "extra": extra,
    }
    raw_bytes = json.dumps({"results": [finding], "errors": []}).encode("utf-8")
    sha = evidence.digest(jf.read_bytes())
    prov = {
        "origin": "recorded_capture_unsigned",
        "source_capture_verified": verified_capture,
        "exit_capture_verified": verified_capture,
        "recorded_engine_exit": 0,
        "source_hashes": {"Demo.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"Demo.java": sha}
    ass = {
        "status": "REFUTED",
        "raw_model_status": "REFUTED",
        "validated_status": "REFUTED",
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "Model proposes REFUTED with citation.",
        "fix_suggestion": "Use PreparedStatement.",
        "citations": [{"path": "Demo.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}],
        "citation_check": "MATCHED",
        "requires_human_review": True,
        "security_conclusion_verified": False,
        "analyzed_at": evidence.now(),
        "runtime": {"origin": "unverified", "model_runtime_verified": False},
    }
    scan_dir = sub / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "input.opengrep.json").write_bytes(raw_bytes)
    (scan_dir / "evidence.json").write_text(json.dumps(bundle), encoding="utf-8")
    rs = store.ReviewStore(scan_dir / "review.sqlite")
    try:
        rs.add(bundle, [ass])
    finally:
        rs.close()
    return scan_dir, bundle["scan_sha256"], bundle["records"][0]["id"], sha

dir_a, scan_a, finding_a, sha_a = make_scan("scan_a", verified_capture=True, include_trace=True)
dir_b, scan_b, finding_b, sha_b = make_scan("scan_b", verified_capture=False, include_trace=True)
dir_c, scan_c, finding_c, sha_c = make_scan("scan_c", verified_capture=True, include_trace=False)

cfg = ApiConfig(
    host="127.0.0.1",
    port=0,
    data_dir=root / "api_data",
    reviewable_scan_dirs=(dir_a, dir_b, dir_c),
    api_token=token,
    read_auth_mode="write-only",
)
srv = ThesisApiServer(cfg)
host, port = srv.server_address[:2]
print(json.dumps({
    "baseUrl": f"http://{host}:{port}",
    "token": token,
    "scanA": scan_a,
    "findingA": finding_a,
    "shaA": sha_a,
    "scanB": scan_b,
    "findingB": finding_b,
    "scanC": scan_c,
    "findingC": finding_c,
}), flush=True)
srv.serve_forever()
`;
  return new Promise((resolve, reject) => {
    const proc = spawn('python', ['-X', 'utf8', '-B', '-c', pyCode, tmpRoot], {
      cwd: REPO_ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error(`Timeout starting temp server: ${err}`));
    }, 15000);
    proc.stdout.on('data', (chunk) => {
      out += chunk.toString('utf8');
      const nl = out.indexOf('\n');
      if (nl !== -1) {
        clearTimeout(timer);
        resolve({proc, info: JSON.parse(out.slice(0, nl))});
      }
    });
    proc.stderr.on('data', (chunk) => { err += chunk.toString('utf8'); });
    proc.on('exit', (code) => {
      if (code !== null) {
        clearTimeout(timer);
        reject(new Error(`Temp server exited early (${code}): ${err}`));
      }
    });
  });
}

test('Temp ThesisApiServer contract check: write-only health auth check, citations & SHA-256 preserved, unverified capture blocks confirm-false, and 404 handled cleanly', async () => {
  setupDomGlobals();
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ntk-codex-pre-e2e-'));
  const {proc, info} = await startTempContractServer(tmpRoot);
  try {
    const ui = loadUiBundle();

    // 1. Write-only server without token: /api/health returns 200 OK with write_auth_required=true, authenticated=false
    ui.apiMod.configureApiConnection({baseUrl: info.baseUrl, token: ''});
    const healthNoTok = await ui.apiMod.api.health();
    const permNoTok = ui.evaluateWritePermission({
      backend: {status: healthNoTok.status === 'OK' ? 'CONNECTED' : 'DEGRADED', health: healthNoTok},
      hasToken: ui.apiMod.hasSessionToken(),
    });
    assert.equal(permNoTok.allowed, false);
    assert.equal(permNoTok.kind, 'MISSING_BEARER_TOKEN');

    // 2. With valid token: write permission allowed; real /api/scan-jobs matches strict schema; citations & SHA-256 verified
    ui.apiMod.configureApiConnection({baseUrl: info.baseUrl, token: info.token});
    const healthWithTok = await ui.apiMod.api.health();
    const permWithTok = ui.evaluateWritePermission({
      backend: {status: healthWithTok.status === 'OK' ? 'CONNECTED' : 'DEGRADED', health: healthWithTok},
      hasToken: ui.apiMod.hasSessionToken(),
    });
    assert.equal(permWithTok.allowed, true);
    const liveJobsRes = await ui.apiMod.api.listScanJobs();
    assert.equal(liveJobsRes.supported, true);
    assert.equal(liveJobsRes.valid, true);
    assert.equal(liveJobsRes.declaredTotalCount, 0);
    assert.equal(ui.validateScanJobsListResponse(liveJobsRes).valid, true);

    const detailA = await ui.apiMod.api.findingDetail(info.scanA, info.findingA);
    assert.equal(ui.reviewModelMod.verifyFindingIdentity(detailA, info.scanA, info.findingA).valid, true);
    assert.equal(detailA.assessment.citations[0].sha256, info.shaA);
    assert.equal(detailA.evidence.snapshots['Demo.java'].sha256, info.shaA);
    assert.equal(ui.reviewModelMod.evaluateSourceDriftReadiness(detailA).canConfirmFalse, true);

    // 3. Scan B has source_capture_verified=false -> frontend blocks confirm-false BEFORE sending POST!
    const detailB = await ui.apiMod.api.findingDetail(info.scanB, info.findingB);
    assert.equal(ui.reviewModelMod.verifyFindingIdentity(detailB, info.scanB, info.findingB).valid, true);
    assert.equal(ui.reviewModelMod.evaluateSourceDriftReadiness(detailB).canConfirmFalse, false);
    const blockedB = await ui.reviewModelMod.submitReviewDecision({
      scanId: info.scanB,
      findingId: info.findingB,
      action: 'confirm-false',
      actor: 'reviewer-uet',
      reason: 'Should be blocked by frontend drift check',
      detail: detailB,
      apiClient: ui.apiMod.api,
    });
    assert.equal(blockedB.ok, false);
    assert.equal(blockedB.errorCode, 'SOURCE_DRIFT_PRECONDITION_UNMET');
    const stillOpenB = await ui.apiMod.api.findingDetail(info.scanB, info.findingB);
    assert.equal(stillOpenB.human_review_state, 'OPEN');

    // 3b. Scan C has incomplete evidence (evidence.issues non-empty) -> frontend also blocks confirm-false BEFORE POST!
    const detailC = await ui.apiMod.api.findingDetail(info.scanC, info.findingC);
    assert.equal(ui.reviewModelMod.evaluateSourceDriftReadiness(detailC).canConfirmFalse, false);
    const blockedC = await ui.reviewModelMod.submitReviewDecision({
      scanId: info.scanC,
      findingId: info.findingC,
      action: 'confirm-false',
      actor: 'reviewer-uet',
      reason: 'Should be blocked when evidence.issues is non-empty',
      detail: detailC,
      apiClient: ui.apiMod.api,
    });
    assert.equal(blockedC.ok, false);
    assert.equal(blockedC.errorCode, 'SOURCE_DRIFT_PRECONDITION_UNMET');

    // 4. Scan A confirm-false succeeds and report A strictly matches scanA (and never matches scanB)
    const okA = await ui.reviewModelMod.submitReviewDecision({
      scanId: info.scanA,
      findingId: info.findingA,
      action: 'confirm-false',
      actor: 'reviewer-uet',
      reason: 'Verified with intact SHA-256',
      detail: detailA,
      apiClient: ui.apiMod.api,
    });
    assert.equal(okA.ok, true);
    assert.equal(okA.detail.human_review_state, 'CONFIRMED_FALSE');
    assert.equal(okA.detail.assessment.citations[0].sha256, info.shaA);

    const reportA = await ui.apiMod.api.report(info.scanA);
    assert.equal(ui.reportModelMod.validateReportForScan(reportA, info.scanA).valid, true);
    assert.equal(ui.reportModelMod.validateReportForScan(reportA, info.scanB).valid, false);
    assert.equal(reportA.scan_summary.by_human_review_state.CONFIRMED_FALSE, 1);

    // 5. Missing scan returns 404 and clears only dead scan_id without harming valid scanA
    window.sessionStorage.setItem(ui.liveScanMod.ACTIVE_KEY, info.scanA);
    await assert.rejects(() => ui.liveScanMod.loadLiveScan('nonexistent-scan-404'), (e) => e.status === 404);
    assert.equal(window.sessionStorage.getItem(ui.liveScanMod.ACTIVE_KEY), info.scanA);
  } finally {
    proc.kill();
    fs.rmSync(tmpRoot, {recursive: true, force: true});
  }
});

// ------------------------------------------------------------------------------------------------
// Codex re-audit counterexamples (5 blocking issues A–E)
// ------------------------------------------------------------------------------------------------

test('Counterexample A1 + A2: proxy 404 Not allowed and COMPLETED missing job_id or scan_id must NOT clear JOB_KEY or unlock new scan', () => {
  setupDomGlobals();
  const ui = loadUiBundle();

  // A1: Proxy returns plain-text 404 "Not allowed" (no JOB_NOT_FOUND error_code)
  const proxy404 = ui.classifyJobPollError({status: 404, message: 'Not allowed'});
  assert.notEqual(proxy404.kind, 'NOT_FOUND', 'generic/proxy 404 must not be classified as JOB_NOT_FOUND');
  assert.equal(proxy404.clearStoredJob, false, 'proxy 404 must never delete stored JOB_KEY');
  assert.equal(ui.isJobBlockingNewScan(proxy404.trackingState), true, 'proxy 404 must keep new scan creation locked');

  const genericNotFound = ui.classifyJobPollError({status: 404, code: 'NOT_FOUND', message: 'Not found'});
  assert.equal(genericNotFound.clearStoredJob, false);
  assert.equal(ui.isJobBlockingNewScan(genericNotFound.trackingState), true);

  // Only explicit backend 404 JOB_NOT_FOUND unlocks
  const confirmedJob404 = ui.classifyJobPollError({status: 404, code: 'JOB_NOT_FOUND', payload: {error_code: 'JOB_NOT_FOUND'}});
  assert.equal(confirmedJob404.kind, 'NOT_FOUND');
  assert.equal(confirmedJob404.clearStoredJob, true);
  assert.equal(ui.isJobBlockingNewScan(confirmedJob404.trackingState), false);

  // A2: Terminal COMPLETED/FAILED without job_id, wrong job_id, or COMPLETED without scan_id must stay locked
  const completedNoJobId = ui.classifyJobPollResponse({state: 'COMPLETED', scan_id: 'scan-1'}, 'job-1');
  assert.equal(completedNoJobId.kind, 'MISMATCH');
  assert.equal(completedNoJobId.clearStoredJob, false);
  assert.equal(ui.isJobBlockingNewScan(completedNoJobId.trackingState), true);

  const failedNoJobId = ui.classifyJobPollResponse({state: 'FAILED'}, 'job-1');
  assert.equal(failedNoJobId.kind, 'MISMATCH');
  assert.equal(failedNoJobId.clearStoredJob, false);
  assert.equal(ui.isJobBlockingNewScan(failedNoJobId.trackingState), true);

  const completedNoScanId = ui.classifyJobPollResponse({job_id: 'job-1', state: 'COMPLETED'}, 'job-1');
  assert.equal(completedNoScanId.kind, 'MISMATCH');
  assert.equal(completedNoScanId.clearStoredJob, false);
  assert.equal(ui.isJobBlockingNewScan(completedNoScanId.trackingState), true);
});

test('Counterexample A3: Scanner locks scan creation during async active-job discovery until backend confirms no active job', () => {
  setupDomGlobals();
  const ui = loadUiBundle();

  // Even when sessionStorage has NO JOB_KEY, initial render on CONNECTED backend must lock submit while checking active jobs
  ui.apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'valid-token-123456'});
  const htmlInitial = ui.renderScanner({
    apiOrigin: ORIGIN,
    authSessionScope: ui.apiMod.getAuthSessionScope(),
    apiRevision: 1,
    backend: {
      status: 'CONNECTED',
      health: {status: 'OK', write_auth_required: true, write_auth_configured: true, authenticated: true},
    },
  });
  assert.match(htmlInitial, /<button[^>]*type="submit"[^>]*disabled=""/, 'submit button must stay disabled while async job discovery has not completed');
  assert.equal(typeof ui.isJobDiscoveryBlocking, 'function', 'Scanner must export job discovery lock evaluator');
  const scope = `${ui.apiMod.getAuthSessionScope()}|${ORIGIN}|1`;
  assert.equal(ui.isJobDiscoveryBlocking({jobId: '', backendStatus: 'CONNECTED', trackingState: 'IDLE', discoveryScope: scope, jobDiscovery: {scope: '', status: 'PENDING'}}), true);
  assert.equal(ui.isJobDiscoveryBlocking({jobId: '', backendStatus: 'CONNECTED', trackingState: 'IDLE', discoveryScope: scope, jobDiscovery: {scope, status: 'CHECKING'}}), true);
  assert.equal(ui.isJobDiscoveryBlocking({jobId: '', backendStatus: 'CONNECTED', trackingState: 'IDLE', discoveryScope: scope, jobDiscovery: {scope, status: 'ERROR'}}), true);
  assert.equal(ui.isJobDiscoveryBlocking({jobId: '', backendStatus: 'CONNECTED', trackingState: 'IDLE', discoveryScope: scope, jobDiscovery: {scope, status: 'DONE'}}), false);
});

test('Counterexample B: report validator strictly requires scan_summary.scan_id and valid string finding.scan_id for every finding', () => {
  setupDomGlobals();
  const ui = loadUiBundle();

  // Missing scan_summary.scan_id even when top-level scan_id is present -> REJECTED
  const missingSummaryId = {
    scan_id: 'scan-A',
    scan_summary: {data_origin: 'REAL_SCAN'},
    findings: [{finding_id: 'f-1', scan_id: 'scan-A'}],
  };
  const r1 = ui.reportModelMod.validateReportForScan(missingSummaryId, 'scan-A');
  assert.equal(r1.valid, false, 'report missing scan_summary.scan_id must be rejected');
  assert.notEqual(r1.reason, '');

  // Missing finding.scan_id -> REJECTED
  const missingFindingScanId = makeReportDoc('scan-A', {
    extraFindings: [{finding_id: 'f-missing-scan'}],
  });
  const r2 = ui.reportModelMod.validateReportForScan(missingFindingScanId, 'scan-A');
  assert.equal(r2.valid, false, 'finding missing scan_id must be rejected');
  assert.notEqual(r2.reason, '');

  // Malformed finding.scan_id (number / null / object / empty string) -> REJECTED
  for (const badScanId of [12345, null, '', '   ', {id: 'scan-A'}, ['scan-A']]) {
    const malformed = makeReportDoc('scan-A', {
      extraFindings: [{finding_id: 'f-malformed', scan_id: badScanId}],
    });
    const r3 = ui.reportModelMod.validateReportForScan(malformed, 'scan-A');
    assert.equal(r3.valid, false, `malformed finding scan_id (${JSON.stringify(badScanId)}) must be rejected`);
    assert.notEqual(r3.reason, '');
  }

  // Non-array findings -> REJECTED
  const nonArrayFindings = {...makeReportDoc('scan-A'), findings: null};
  assert.equal(ui.reportModelMod.validateReportForScan(nonArrayFindings, 'scan-A').valid, false);
});

test('Counterexample C: direct submitReviewDecision confirm-false without detail emits ZERO POST writes', async () => {
  setupDomGlobals();
  const ui = loadUiBundle();

  let writes = 0;
  let detailCalls = 0;
  const mockApi = {
    confirmFalse: async () => { writes += 1; return {scan_id: 'scan-A', finding_id: 'f-1', human_review_state: 'CONFIRMED_FALSE'}; },
    confirmTrue: async () => { writes += 1; return {scan_id: 'scan-A', finding_id: 'f-1', human_review_state: 'CONFIRMED_TRUE'}; },
    reopenFinding: async () => { writes += 1; return {scan_id: 'scan-A', finding_id: 'f-1', human_review_state: 'OPEN'}; },
    findingDetail: async () => { detailCalls += 1; return makeFindingDetail('scan-A', 'f-1'); },
    findingHistory: async () => ({scan_id: 'scan-A', finding_id: 'f-1', events: [], rejected_decisions: []}),
  };

  const res = await ui.reviewModelMod.submitReviewDecision({
    scanId: 'scan-A',
    findingId: 'f-1',
    action: 'confirm-false',
    actor: 'reviewer-uet',
    reason: 'Direct service call without detail',
    apiClient: mockApi,
  });
  assert.equal(res.ok, false, 'confirm-false without detail must be refused at service layer');
  assert.equal(writes, 0, 'confirm-false without detail must issue zero write calls');
  assert.equal(detailCalls, 0, 'confirm-false without detail must fail closed immediately');
});

test('Counterexample D1 + D2: GitHub URL is not double-stripped (.git.git) and async ZIP submit aborts on origin/token/permission change', async () => {
  setupDomGlobals();
  const prevFetch = global.fetch;
  const sentRequests = [];
  global.fetch = async (url, options = {}) => {
    sentRequests.push({url, method: options.method || 'GET', body: options.body, auth: options.headers?.Authorization});
    return new Response(JSON.stringify({job_id: 'job-d-1', state: 'QUEUED'}), {status: 202});
  };
  try {
    const ui = loadUiBundle();
    ui.apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'tok-d-123456'});

    // D1: https://github.com/org/repo.git.git must NOT be stripped twice into https://github.com/org/repo
    const rawDoubleGit = 'https://github.com/org/repo.git.git';
    const scannerCheck = ui.validateGithubRepoUrl(rawDoubleGit);
    assert.equal(scannerCheck.valid, true);
    await ui.apiMod.api.createScanJob(scannerCheck.canonicalUrl);
    const sentBody = JSON.parse(sentRequests.at(-1).body);
    assert.equal(sentBody.repo_url, scannerCheck.canonicalUrl, 'adapter must not strip .git a second time');
    assert.notEqual(sentBody.repo_url, 'https://github.com/org/repo', 'must never silently mutate repo.git.git into repo');

    // Scanner.jsx must not pass double-normalized URL or strip .git twice
    const scannerSrc = fs.readFileSync(path.join(SRC_ROOT, 'pages/Scanner.jsx'), 'utf8');
    assert.doesNotMatch(scannerSrc, /createScanJob\(\s*githubCheck\.canonicalUrl/);

    // D2: Changing origin or token while async ZIP signature read is in-flight must abort and emit ZERO POSTs
    assert.equal(typeof ui.runGuardedZipSubmission, 'function', 'Scanner must export guarded async ZIP submission helper');
    let releaseSlice;
    const slowZip = {
      name: 'project.zip',
      size: 16,
      slice() {
        return {
          arrayBuffer: () => new Promise((resolve) => {
            releaseSlice = () => resolve(Uint8Array.from([0x50, 0x4b, 0x03, 0x04]).buffer);
          }),
        };
      },
    };
    let zipPosts = 0;
    const backendState = {
      status: 'CONNECTED',
      health: {status: 'OK', write_auth_required: true, write_auth_configured: true, authenticated: true},
    };
    const pendingZip = ui.runGuardedZipSubmission({
      file: slowZip,
      getOrigin: ui.apiMod.getApiOrigin,
      getSession: ui.apiMod.getAuthSessionScope,
      getHasToken: ui.apiMod.hasSessionToken,
      getBackend: () => backendState,
      getReadOnlyDetected: () => false,
      isCancelled: () => false,
      submitZip: async () => { zipPosts += 1; return {job_id: 'should-not-run'}; },
    });

    // Switch origin / token while ZIP header read is still awaiting
    ui.apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19102', token: 'tok-other-999999'});
    releaseSlice();
    const zipOutcome = await pendingZip;
    assert.equal(zipOutcome.aborted, true, 'ZIP submission must abort when origin/session changed during async read');
    assert.equal(zipPosts, 0, 'ZIP from old session must never be sent to new origin/session');

    // Also test same-origin token change during async ZIP read
    const pendingZip2 = ui.runGuardedZipSubmission({
      file: slowZip,
      getOrigin: ui.apiMod.getApiOrigin,
      getSession: ui.apiMod.getAuthSessionScope,
      getHasToken: ui.apiMod.hasSessionToken,
      getBackend: () => backendState,
      getReadOnlyDetected: () => false,
      isCancelled: () => false,
      submitZip: async () => { zipPosts += 1; return {job_id: 'should-not-run-2'}; },
    });
    ui.apiMod.clearSessionToken();
    releaseSlice();
    const zipOutcome2 = await pendingZip2;
    assert.equal(zipOutcome2.aborted, true, 'ZIP submission must abort when Bearer token cleared during async read');
    assert.equal(zipPosts, 0, 'ZIP must not be sent after token cleared');
  } finally {
    global.fetch = prevFetch;
  }
});

test('Counterexample E: proxy 404 Not allowed on findings endpoint when summary returns 200 preserves valid scan_id in sessionStorage', async () => {
  setupDomGlobals();
  const prevFetch = global.fetch;
  try {
    const ui = loadUiBundle();
    ui.apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'tok-e-123456'});

    // Pre-existing valid scan_id in sessionStorage
    window.sessionStorage.setItem(ui.liveScanMod.ACTIVE_KEY, 'scan-valid-1');
    global.fetch = async (url) => {
      const pathname = new URL(url).pathname;
      if (pathname === '/api/scans/scan-valid-1') {
        return new Response(JSON.stringify({scan_id: 'scan-valid-1', data_origin: 'REAL_SCAN', total_findings: 2}), {status: 200});
      }
      if (pathname === '/api/scans/scan-valid-1/findings') {
        return new Response('Not allowed', {status: 404, headers: {'Content-Type': 'text/plain'}});
      }
      return new Response(JSON.stringify({error_code: 'SCAN_NOT_FOUND', error_message: 'missing'}), {status: 404});
    };

    await assert.rejects(() => ui.liveScanMod.loadLiveScan('scan-valid-1'), (err) => err.status === 404);
    assert.equal(
      window.sessionStorage.getItem(ui.liveScanMod.ACTIVE_KEY),
      'scan-valid-1',
      'proxy 404 Not allowed on findings endpoint must NOT delete valid scan_id from sessionStorage',
    );

    // Proxy 404 Not allowed on /report must also preserve valid scan_id in sessionStorage
    const reportRunner = ui.createReportLoadRunner({
      apiClient: {report: async () => { throw new ui.apiMod.ApiError('Not allowed', {status: 404}); }},
      getOrigin: () => ORIGIN,
      getSession: ui.apiMod.getAuthSessionScope,
      onNotFound: ui.liveScanMod.clearStaleActiveScanId,
      onState: () => {},
    });
    await reportRunner.load('scan-valid-1', 'k-valid').promise;
    assert.equal(
      window.sessionStorage.getItem(ui.liveScanMod.ACTIVE_KEY),
      'scan-valid-1',
      'proxy 404 Not allowed on /report must NOT delete valid scan_id from sessionStorage',
    );

    // Confirmed backend 404 SCAN_NOT_FOUND DOES remove the dead scan_id (and only that dead scan_id)
    window.sessionStorage.setItem(ui.liveScanMod.ACTIVE_KEY, 'scan-truly-gone');
    await assert.rejects(() => ui.liveScanMod.loadLiveScan('scan-truly-gone'), (err) => err.status === 404 && err.code === 'SCAN_NOT_FOUND');
    assert.equal(
      window.sessionStorage.getItem(ui.liveScanMod.ACTIVE_KEY),
      null,
      'backend-confirmed 404 SCAN_NOT_FOUND must clear the dead scan_id from sessionStorage',
    );
  } finally {
    global.fetch = prevFetch;
  }
});

// ------------------------------------------------------------------------------------------------
// Mounted React 18 + StrictMode test harness (zero external DOM dependencies, dev-mode StrictMode)
// ------------------------------------------------------------------------------------------------

function createZipBlobFile(name, bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  if (typeof File === 'function') {
    return new File([buf], name, {type: 'application/zip'});
  }
  const blob = new Blob([buf], {type: 'application/zip'});
  Object.defineProperty(blob, 'name', {value: name, configurable: true});
  return blob;
}

function installMiniDom() {
  const prev = {
    window: global.window,
    document: global.document,
    Node: global.Node,
    Element: global.Element,
    HTMLElement: global.HTMLElement,
    HTMLInputElement: global.HTMLInputElement,
    HTMLIFrameElement: global.HTMLIFrameElement,
    HTMLTextAreaElement: global.HTMLTextAreaElement,
    HTMLSelectElement: global.HTMLSelectElement,
    HTMLFormElement: global.HTMLFormElement,
    HTMLButtonElement: global.HTMLButtonElement,
    ShadowRoot: global.ShadowRoot,
    SVGElement: global.SVGElement,
    Text: global.Text,
    Comment: global.Comment,
    Document: global.Document,
    Event: global.Event,
    CustomEvent: global.CustomEvent,
    navigator: global.navigator,
    requestAnimationFrame: global.requestAnimationFrame,
    cancelAnimationFrame: global.cancelAnimationFrame,
    MessageChannel: global.MessageChannel,
    IS_REACT_ACT_ENVIRONMENT: global.IS_REACT_ACT_ENVIRONMENT,
  };
  const NativeMessageChannel = global.MessageChannel;
  if (typeof NativeMessageChannel === 'function') {
    global.MessageChannel = class UnrefMessageChannel {
      constructor() {
        const ch = new NativeMessageChannel();
        const protoDesc = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(ch.port1), 'onmessage');
        if (protoDesc && protoDesc.set) {
          Object.defineProperty(ch.port1, 'onmessage', {
            configurable: true,
            get() { return protoDesc.get.call(ch.port1); },
            set(fn) {
              protoDesc.set.call(ch.port1, fn);
              ch.port1.unref?.();
              ch.port2.unref?.();
            },
          });
        }
        ch.port1?.unref?.();
        ch.port2?.unref?.();
        this.port1 = ch.port1;
        this.port2 = ch.port2;
      }
    };
  }

  class MiniEvent {
    constructor(type, init = {}) {
      this.type = String(type);
      this.bubbles = Boolean(init.bubbles);
      this.cancelable = Boolean(init.cancelable);
      this.defaultPrevented = false;
      this.cancelBubble = false;
      this.target = null;
      this.currentTarget = null;
      this.srcElement = null;
      this.eventPhase = 0;
      this.timeStamp = Date.now();
      this.detail = init.detail ?? null;
    }
    initEvent(type, bubbles = false, cancelable = false) {
      this.type = String(type);
      this.bubbles = Boolean(bubbles);
      this.cancelable = Boolean(cancelable);
    }
    preventDefault() {
      if (this.cancelable) this.defaultPrevented = true;
    }
    stopPropagation() {
      this.cancelBubble = true;
    }
    stopImmediatePropagation() {
      this.cancelBubble = true;
    }
  }

  class MiniNode {
    constructor(nodeType, nodeName, ownerDocument) {
      this.nodeType = nodeType;
      this.nodeName = nodeName;
      this.ownerDocument = ownerDocument;
      this.parentNode = null;
      this.childNodes = [];
      this._listeners = new Map();
    }
    get firstChild() { return this.childNodes[0] || null; }
    get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
    get nextSibling() {
      if (!this.parentNode) return null;
      const idx = this.parentNode.childNodes.indexOf(this);
      return idx >= 0 && idx + 1 < this.parentNode.childNodes.length ? this.parentNode.childNodes[idx + 1] : null;
    }
    get previousSibling() {
      if (!this.parentNode) return null;
      const idx = this.parentNode.childNodes.indexOf(this);
      return idx > 0 ? this.parentNode.childNodes[idx - 1] : null;
    }
    get parentElement() {
      return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null;
    }
    appendChild(child) {
      if (child.nodeType === 11) {
        const moved = [...child.childNodes];
        for (const c of moved) this.appendChild(c);
        return child;
      }
      if (child.parentNode) child.parentNode.removeChild(child);
      child.parentNode = this;
      this.childNodes.push(child);
      return child;
    }
    insertBefore(child, before) {
      if (!before) return this.appendChild(child);
      if (child.nodeType === 11) {
        const moved = [...child.childNodes];
        for (const c of moved) this.insertBefore(c, before);
        return child;
      }
      if (child.parentNode) child.parentNode.removeChild(child);
      const idx = this.childNodes.indexOf(before);
      child.parentNode = this;
      if (idx === -1) this.childNodes.push(child);
      else this.childNodes.splice(idx, 0, child);
      return child;
    }
    removeChild(child) {
      const idx = this.childNodes.indexOf(child);
      if (idx >= 0) {
        this.childNodes.splice(idx, 1);
        child.parentNode = null;
      }
      return child;
    }
    contains(other) {
      let cur = other;
      while (cur) {
        if (cur === this) return true;
        cur = cur.parentNode;
      }
      return false;
    }
    getRootNode() {
      let cur = this;
      while (cur.parentNode) cur = cur.parentNode;
      return cur;
    }
    addEventListener(type, fn, options) {
      const capture = typeof options === 'boolean' ? options : Boolean(options?.capture);
      const key = `${type}:${capture ? 'c' : 'b'}`;
      if (!this._listeners.has(key)) this._listeners.set(key, []);
      const list = this._listeners.get(key);
      if (!list.includes(fn)) list.push(fn);
    }
    removeEventListener(type, fn, options) {
      const capture = typeof options === 'boolean' ? options : Boolean(options?.capture);
      const key = `${type}:${capture ? 'c' : 'b'}`;
      const list = this._listeners.get(key);
      if (!list) return;
      const idx = list.indexOf(fn);
      if (idx >= 0) list.splice(idx, 1);
    }
    dispatchEvent(event) {
      event.target = this;
      event.srcElement = this;
      const path = [];
      let cur = this;
      while (cur) {
        path.push(cur);
        cur = cur.parentNode;
      }
      if (this.ownerDocument && path[path.length - 1] !== this.ownerDocument) {
        path.push(this.ownerDocument);
      }
      const win = this.ownerDocument?.defaultView;
      if (win) path.push(win);
      // Capture phase
      for (let i = path.length - 1; i >= 0; i -= 1) {
        const node = path[i];
        event.currentTarget = node;
        const listeners = node._listeners?.get(`${event.type}:c`);
        if (listeners) {
          for (const fn of [...listeners]) fn.call(node, event);
        }
        if (event.cancelBubble) return !event.defaultPrevented;
      }
      // Target + bubble phase
      for (let i = 0; i < path.length; i += 1) {
        if (i > 0 && !event.bubbles) break;
        const node = path[i];
        event.currentTarget = node;
        const listeners = node._listeners?.get(`${event.type}:b`);
        if (listeners) {
          for (const fn of [...listeners]) fn.call(node, event);
        }
        if (event.cancelBubble) break;
      }
      return !event.defaultPrevented;
    }
    get textContent() {
      if (this.nodeType === 3 || this.nodeType === 8) return this._data || '';
      return this.childNodes.map((c) => c.textContent).join('');
    }
    set textContent(val) {
      const str = val === null || val === undefined ? '' : String(val);
      if (this.nodeType === 3 || this.nodeType === 8) {
        this._data = str;
        return;
      }
      for (const c of [...this.childNodes]) this.removeChild(c);
      if (str) this.appendChild(this.ownerDocument.createTextNode(str));
    }
  }

  class MiniText extends MiniNode {
    constructor(data, ownerDocument) {
      super(3, '#text', ownerDocument);
      this._data = String(data ?? '');
    }
    get nodeValue() { return this._data; }
    set nodeValue(v) { this._data = String(v ?? ''); }
    get data() { return this._data; }
    set data(v) { this._data = String(v ?? ''); }
  }

  class MiniComment extends MiniNode {
    constructor(data, ownerDocument) {
      super(8, '#comment', ownerDocument);
      this._data = String(data ?? '');
    }
    get nodeValue() { return this._data; }
    set nodeValue(v) { this._data = String(v ?? ''); }
    get data() { return this._data; }
    set data(v) { this._data = String(v ?? ''); }
  }

  class MiniFragment extends MiniNode {
    constructor(ownerDocument) {
      super(11, '#document-fragment', ownerDocument);
    }
  }

  class MiniElement extends MiniNode {
    constructor(tagName, ownerDocument, namespaceURI = 'http://www.w3.org/1999/xhtml') {
      const normalized = namespaceURI === 'http://www.w3.org/1999/xhtml' ? String(tagName).toUpperCase() : String(tagName);
      super(1, normalized, ownerDocument);
      this.tagName = normalized;
      this.namespaceURI = namespaceURI;
      this._attrs = new Map();
      this._value = '';
      this._checked = false;
      this.files = [];
      this.oninput = null;
      this.onchange = null;
      this.onclick = null;
      this.onsubmit = null;
      this.onblur = null;
      this.onfocus = null;
      this.style = {
        setProperty(k, v) { this[k] = v; },
        removeProperty(k) { delete this[k]; },
      };
    }
    get value() { return this._value; }
    set value(v) { this._value = v === null || v === undefined ? '' : String(v); }
    get defaultValue() { return this._attrs.get('value') || ''; }
    set defaultValue(v) { this._attrs.set('value', String(v ?? '')); }
    get checked() { return this._checked; }
    set checked(v) { this._checked = Boolean(v); }
    get disabled() { return this._attrs.has('disabled'); }
    set disabled(v) {
      if (v) this._attrs.set('disabled', '');
      else this._attrs.delete('disabled');
    }
    get id() { return this._attrs.get('id') || ''; }
    set id(v) { this._attrs.set('id', String(v ?? '')); }
    get type() { return this._attrs.get('type') || ''; }
    set type(v) { this._attrs.set('type', String(v ?? '')); }
    get name() { return this._attrs.get('name') || ''; }
    set name(v) { this._attrs.set('name', String(v ?? '')); }
    get className() { return this._attrs.get('class') || ''; }
    set className(v) { this._attrs.set('class', String(v ?? '')); }
    get innerHTML() { return ''; }
    set innerHTML(v) {
      for (const c of [...this.childNodes]) this.removeChild(c);
      if (v) this.appendChild(this.ownerDocument.createTextNode(String(v)));
    }
    setAttribute(k, v) {
      const key = String(k).toLowerCase();
      this._attrs.set(key, String(v ?? ''));
      if (key === 'value') this._value = String(v ?? '');
    }
    setAttributeNS(_ns, k, v) { this.setAttribute(k, v); }
    getAttribute(k) {
      const key = String(k).toLowerCase();
      return this._attrs.has(key) ? this._attrs.get(key) : null;
    }
    hasAttribute(k) { return this._attrs.has(String(k).toLowerCase()); }
    removeAttribute(k) { this._attrs.delete(String(k).toLowerCase()); }
    focus() { if (this.ownerDocument) this.ownerDocument.activeElement = this; }
    blur() { if (this.ownerDocument && this.ownerDocument.activeElement === this) this.ownerDocument.activeElement = this.ownerDocument.body; }
    scrollIntoView() {}
    click() {
      if (this.disabled) return;
      this.dispatchEvent(new MiniEvent('click', {bubbles: true, cancelable: true}));
    }
    _walkElements(acc = []) {
      for (const child of this.childNodes) {
        if (child.nodeType === 1) {
          acc.push(child);
          child._walkElements(acc);
        }
      }
      return acc;
    }
    matchesSelector(selector) {
      const s = String(selector || '').trim();
      if (!s) return false;
      if (s.startsWith('#')) return this.id === s.slice(1);
      const attrMatch = s.match(/^([a-z0-9_-]*)\[([a-z0-9_-]+)(?:="([^"]*)")?\]$/i);
      if (attrMatch) {
        const [, tag, attr, val] = attrMatch;
        if (tag && this.tagName.toLowerCase() !== tag.toLowerCase()) return false;
        if (val === undefined) return this.hasAttribute(attr);
        return this.getAttribute(attr) === val;
      }
      return this.tagName.toLowerCase() === s.toLowerCase();
    }
    querySelectorAll(selector) {
      return this._walkElements().filter((el) => el.matchesSelector(selector));
    }
    querySelector(selector) {
      return this.querySelectorAll(selector)[0] || null;
    }
  }

  class MiniDocument extends MiniNode {
    constructor() {
      super(9, '#document', null);
      this.ownerDocument = this;
      this.defaultView = null;
      this.documentElement = new MiniElement('html', this);
      this.head = new MiniElement('head', this);
      this.body = new MiniElement('body', this);
      this.documentElement.appendChild(this.head);
      this.documentElement.appendChild(this.body);
      this.appendChild(this.documentElement);
      this.activeElement = this.body;
      this.oninput = null;
      this.onchange = null;
      this.onclick = null;
      this.onsubmit = null;
    }
    createElement(tag) { return new MiniElement(tag, this); }
    createElementNS(ns, tag) { return new MiniElement(tag, this, ns); }
    createTextNode(text) { return new MiniText(text, this); }
    createComment(text) { return new MiniComment(text, this); }
    createDocumentFragment() { return new MiniFragment(this); }
    createEvent() { return new MiniEvent(''); }
    querySelectorAll(selector) { return this.documentElement.querySelectorAll(selector); }
    querySelector(selector) { return this.documentElement.querySelector(selector); }
  }

  class MiniIFrameElement extends MiniElement {}
  class MiniShadowRoot extends MiniNode {}

  const doc = new MiniDocument();
  const winListeners = new Map();
  const win = {
    document: doc,
    Node: MiniNode,
    Element: MiniElement,
    HTMLElement: MiniElement,
    HTMLInputElement: MiniElement,
    HTMLIFrameElement: MiniIFrameElement,
    HTMLTextAreaElement: MiniElement,
    HTMLSelectElement: MiniElement,
    HTMLFormElement: MiniElement,
    HTMLButtonElement: MiniElement,
    ShadowRoot: MiniShadowRoot,
    SVGElement: MiniElement,
    Text: MiniText,
    Comment: MiniComment,
    Document: MiniDocument,
    Event: MiniEvent,
    CustomEvent: MiniEvent,
    navigator: {userAgent: 'node-test'},
    location: {hash: '', href: 'http://127.0.0.1:5173/scanner', origin: 'http://127.0.0.1:5173', pathname: '/scanner', search: ''},
    history: {pushState() {}, replaceState() {}, state: null},
    sessionStorage: mkStorage(),
    localStorage: mkStorage(),
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    requestAnimationFrame: (cb) => setTimeout(() => cb(Date.now()), 0),
    cancelAnimationFrame: (id) => clearTimeout(id),
    _listeners: winListeners,
    addEventListener(type, fn, options) {
      const capture = typeof options === 'boolean' ? options : Boolean(options?.capture);
      const key = `${type}:${capture ? 'c' : 'b'}`;
      if (!winListeners.has(key)) winListeners.set(key, []);
      const list = winListeners.get(key);
      if (!list.includes(fn)) list.push(fn);
    },
    removeEventListener(type, fn, options) {
      const capture = typeof options === 'boolean' ? options : Boolean(options?.capture);
      const key = `${type}:${capture ? 'c' : 'b'}`;
      const list = winListeners.get(key);
      if (!list) return;
      const idx = list.indexOf(fn);
      if (idx >= 0) list.splice(idx, 1);
    },
    dispatchEvent(event) {
      event.target = event.target || win;
      event.currentTarget = win;
      const listeners = winListeners.get(`${event.type}:b`);
      if (listeners) {
        for (const fn of [...listeners]) fn.call(win, event);
      }
      return !event.defaultPrevented;
    },
    matchMedia: (q) => ({matches: String(q || '').includes('prefers-reduced-motion'), addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}}),
    getComputedStyle: () => ({}),
  };
  doc.defaultView = win;

  global.window = win;
  global.document = doc;
  global.Node = MiniNode;
  global.Element = MiniElement;
  global.HTMLElement = MiniElement;
  global.HTMLInputElement = MiniElement;
  global.HTMLIFrameElement = MiniIFrameElement;
  global.HTMLTextAreaElement = MiniElement;
  global.HTMLSelectElement = MiniElement;
  global.HTMLFormElement = MiniElement;
  global.HTMLButtonElement = MiniElement;
  global.ShadowRoot = MiniShadowRoot;
  global.SVGElement = MiniElement;
  global.Text = MiniText;
  global.Comment = MiniComment;
  global.Document = MiniDocument;
  global.Event = MiniEvent;
  global.CustomEvent = MiniEvent;
  global.requestAnimationFrame = win.requestAnimationFrame;
  global.cancelAnimationFrame = win.cancelAnimationFrame;
  global.IS_REACT_ACT_ENVIRONMENT = true;

  const setInputValue = (inputEl, nextVal) => {
    const protoDesc = Object.getOwnPropertyDescriptor(MiniElement.prototype, 'value');
    protoDesc.set.call(inputEl, nextVal);
    inputEl.dispatchEvent(new MiniEvent('input', {bubbles: true}));
    inputEl.dispatchEvent(new MiniEvent('change', {bubbles: true}));
  };

  const setInputFiles = (inputEl, files) => {
    inputEl.files = files;
    inputEl.dispatchEvent(new MiniEvent('change', {bubbles: true}));
  };

  return {
    window: win,
    document: doc,
    Event: MiniEvent,
    setInputValue,
    setInputFiles,
    restore() {
      for (const [k, v] of Object.entries(prev)) {
        if (v === undefined) delete global[k];
        else global[k] = v;
      }
    },
  };
}

function loadDevMountedScannerBundle() {
  const esbuild = require(path.join(APP_ROOT, 'node_modules', 'esbuild'));
  const entry = `
    import React, {StrictMode, act, createElement as h, useEffect} from 'react';
    import {createRoot} from 'react-dom/client';
    import {MemoryRouter, Outlet, Route, Routes} from 'react-router-dom';
    import * as apiMod from './src/services/api.js';
    import Scanner, {
      classifyJobPollError,
      classifyJobPollResponse,
      isJobBlockingNewScan,
      isJobDiscoveryBlocking,
      runGuardedZipSubmission,
    } from './src/pages/Scanner.jsx';

    export {
      React,
      StrictMode,
      act,
      createRoot,
      apiMod,
      classifyJobPollError,
      classifyJobPollResponse,
      isJobBlockingNewScan,
      isJobDiscoveryBlocking,
      runGuardedZipSubmission,
    };

    export function mountScanner({outletContext, strictMode = false, onStrictProbe} = {}) {
      const container = document.createElement('div');
      document.body.appendChild(container);
      const root = createRoot(container);
      function Probe() {
        useEffect(() => {
          onStrictProbe?.('mount');
          return () => onStrictProbe?.('cleanup');
        }, []);
        return null;
      }
      function Layout() {
        return h(Outlet, {context: outletContext});
      }
      const tree = h(
        MemoryRouter,
        {initialEntries: ['/scanner']},
        h(Probe),
        h(Routes, null,
          h(Route, {element: h(Layout)},
            h(Route, {path: '/scanner', element: h(Scanner)}),
            h(Route, {path: '*', element: h('div')}),
          ),
        ),
      );
      const wrapped = strictMode ? h(StrictMode, null, tree) : tree;
      return {
        container,
        async render() {
          await act(async () => {
            root.render(wrapped);
          });
        },
        async flush(rounds = 4) {
          for (let i = 0; i < rounds; i += 1) {
            await act(async () => {
              await new Promise((r) => setTimeout(r, 0));
            });
          }
        },
        async unmount() {
          await act(async () => {
            root.unmount();
          });
          if (container.parentNode) container.parentNode.removeChild(container);
        },
      };
    }
  `;
  const out = esbuild.buildSync({
    stdin: {contents: entry, resolveDir: APP_ROOT, loader: 'jsx', sourcefile: 'codex-mounted-scanner-dev.jsx'},
    bundle: true,
    platform: 'node',
    format: 'cjs',
    jsx: 'automatic',
    loader: {'.css': 'empty'},
    write: false,
    logLevel: 'silent',
    define: {'import.meta.env': '{}', 'process.env.NODE_ENV': '"development"'},
  });
  const m = new Module('codex-mounted-scanner-dev.jsx', module);
  m.paths = module.paths;
  m._compile(out.outputFiles[0].text, path.join(APP_ROOT, 'codex-mounted-scanner-dev.cjs'));
  return m.exports;
}

test('Counterexample A4 (mounted React): malformed-200 and count-mismatch job list responses must NEVER unlock Scanner, while valid backend schema unlocks', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;
  try {
    const dev = loadDevMountedScannerBundle();
    dev.apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'tok-a4-123456'});
    const okOutlet = () => ({
      apiOrigin: ORIGIN,
      authSessionScope: dev.apiMod.getAuthSessionScope(),
      apiRevision: 1,
      backend: {
        status: 'CONNECTED',
        health: {status: 'OK', write_auth_required: true, write_auth_configured: true, authenticated: true},
      },
    });

    const invalidResponses = [
      {label: 'malformed-200 error payload', body: {error: 'upstream returned no job list'}},
      {label: 'count-mismatch jobs=[] total_count=1', body: {jobs: [], total_count: 1}},
      {label: 'missing total_count jobs=[]', body: {jobs: []}},
      {label: 'count-mismatch jobs.length > total_count', body: {jobs: [{job_id: 'j1', state: 'COMPLETED'}], total_count: 0}},
      {label: 'invalid total_count type', body: {jobs: [], total_count: '0'}},
      {label: 'malformed job item missing state', body: {jobs: [{job_id: 'j1'}], total_count: 1}},
    ];

    for (const scenario of invalidResponses) {
      let postCount = 0;
      global.fetch = async (url, opts = {}) => {
        if ((opts.method || 'GET') === 'POST') {
          postCount += 1;
          return new Response(JSON.stringify({job_id: 'should-not-post', state: 'QUEUED'}), {status: 202});
        }
        return new Response(JSON.stringify(scenario.body), {status: 200});
      };

      const mounted = dev.mountScanner({outletContext: okOutlet(), strictMode: false});
      try {
        await mounted.render();
        await mounted.flush(4);
        const urlInput = mounted.container.querySelector('#repo-url');
        assert(urlInput, 'repo-url input must exist');
        await dev.act(async () => {
          dom.setInputValue(urlInput, 'https://github.com/org/repo');
        });
        await mounted.flush(2);
        const submitBtn = mounted.container.querySelector('button[type="submit"]');
        assert.equal(submitBtn.disabled, true, `${scenario.label}: submit button MUST stay disabled`);
        const form = mounted.container.querySelector('form');
        await dev.act(async () => {
          form.dispatchEvent(new dom.Event('submit', {bubbles: true, cancelable: true}));
        });
        await mounted.flush(2);
        assert.equal(postCount, 0, `${scenario.label}: must emit 0 POST requests`);
      } finally {
        await mounted.unmount();
      }
    }

    // Valid backend schema: 200 {"jobs": [], "total_count": 0} -> unlocks valid GitHub form
    global.fetch = async () => new Response(JSON.stringify({jobs: [], total_count: 0}), {status: 200});
    const mountedValid = dev.mountScanner({outletContext: okOutlet(), strictMode: false});
    try {
      await mountedValid.render();
      await mountedValid.flush(4);
      const urlInput = mountedValid.container.querySelector('#repo-url');
      await dev.act(async () => {
        dom.setInputValue(urlInput, 'https://github.com/org/repo');
      });
      await mountedValid.flush(2);
      const submitBtn = mountedValid.container.querySelector('button[type="submit"]');
      assert.equal(submitBtn.disabled, false, 'valid backend schema {jobs:[], total_count:0} must unlock valid form');
    } finally {
      await mountedValid.unmount();
    }

    // Valid backend schema with active RUNNING job -> attaches JOB_KEY and keeps submit locked
    global.fetch = async (url) => {
      const p = new URL(url).pathname;
      if (p === '/api/scan-jobs') {
        return new Response(JSON.stringify({
          total_count: 1,
          jobs: [{job_id: 'job-running-1', state: 'RUNNING', active_stage: 2}],
        }), {status: 200});
      }
      return new Response(JSON.stringify({job_id: 'job-running-1', state: 'RUNNING', active_stage: 2}), {status: 200});
    };
    const mountedActive = dev.mountScanner({outletContext: okOutlet(), strictMode: false});
    try {
      await mountedActive.render();
      await mountedActive.flush(4);
      assert.equal(window.sessionStorage.getItem('22025523-active-job'), 'job-running-1');
      const submitBtn = mountedActive.container.querySelector('button[type="submit"]');
      assert.equal(submitBtn.disabled, true, 'discovered RUNNING job must lock submit button');
    } finally {
      await mountedActive.unmount();
    }
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

test('Counterexample D3 (mounted React StrictMode): valid ZIP passes signature and submits once after StrictMode replay, while config/token change still aborts with 0 POSTs', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;
  try {
    const dev = loadDevMountedScannerBundle();
    dev.apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'tok-d3-123456'});
    const probeEvents = [];
    const postCalls = [];
    const pollCalls = [];
    global.fetch = async (url, opts = {}) => {
      const pathname = new URL(url).pathname;
      const method = (opts.method || 'GET').toUpperCase();
      if (method === 'GET' && pathname === '/api/scan-jobs') {
        return new Response(JSON.stringify({jobs: [], total_count: 0}), {status: 200});
      }
      if (method === 'POST' && pathname === '/api/scan-jobs') {
        postCalls.push({url, method, body: opts.body});
        return new Response(JSON.stringify({job_id: 'job-zip-strict-1', state: 'QUEUED'}), {status: 202});
      }
      if (method === 'GET' && pathname === '/api/scan-jobs/job-zip-strict-1') {
        pollCalls.push(pathname);
        return new Response(JSON.stringify({job_id: 'job-zip-strict-1', state: 'QUEUED'}), {status: 200});
      }
      return new Response(JSON.stringify({error_code: 'ROUTE_NOT_FOUND'}), {status: 404});
    };

    const mounted = dev.mountScanner({
      strictMode: true,
      onStrictProbe: (ev) => probeEvents.push(ev),
      outletContext: {
        apiOrigin: ORIGIN,
        authSessionScope: dev.apiMod.getAuthSessionScope(),
        apiRevision: 1,
        backend: {
          status: 'CONNECTED',
          health: {status: 'OK', write_auth_required: true, write_auth_configured: true, authenticated: true},
        },
      },
    });
    try {
      await mounted.render();
      await mounted.flush(4);
      // Prove React 18 StrictMode actually replayed mount -> cleanup -> mount!
      assert.deepEqual(probeEvents, ['mount', 'cleanup', 'mount'], 'test must actually run React 18 StrictMode double-effect replay');

      // Switch to ZIP tab and select a valid PK\x03\x04 ZIP file
      const zipTab = mounted.container.querySelector('#scan-tab-zip');
      assert(zipTab, 'ZIP tab button must exist');
      await dev.act(async () => { zipTab.click(); });
      const fileInput = mounted.container.querySelector('#zip-file-input');
      assert(fileInput, 'ZIP file input must exist');
      const validZip = createZipBlobFile('demo-java.zip', [0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
      await dev.act(async () => {
        dom.setInputFiles(fileInput, [validZip]);
      });
      await mounted.flush(6);

      const submitBtn = mounted.container.querySelector('button[type="submit"]');
      assert.equal(submitBtn.disabled, false, 'valid ZIP must unlock submit button after StrictMode effect replay');

      const form = mounted.container.querySelector('form');
      // Rapid double submit must emit ONLY 1 POST (no duplicate POST)
      await dev.act(async () => {
        form.dispatchEvent(new dom.Event('submit', {bubbles: true, cancelable: true}));
        form.dispatchEvent(new dom.Event('submit', {bubbles: true, cancelable: true}));
      });
      await mounted.flush(6);

      assert.equal(postCalls.length, 1, 'ZIP submit under StrictMode must send exactly 1 POST');
      assert.equal(window.sessionStorage.getItem('22025523-active-job'), 'job-zip-strict-1');
      assert.equal(pollCalls.length, 1, 'acknowledged ZIP job must start single bounded poll without duplicate polling loop');
    } finally {
      await mounted.unmount();
    }

    // Mounted StrictMode: changing origin/token during slow async ZIP signature check inside submit aborts with 0 POSTs
    window.sessionStorage.removeItem('22025523-active-job');
    let deferredZipPosts = 0;
    global.fetch = async (url, opts = {}) => {
      const pathname = new URL(url).pathname;
      const method = (opts.method || 'GET').toUpperCase();
      if (method === 'GET' && pathname === '/api/scan-jobs') {
        return new Response(JSON.stringify({jobs: [], total_count: 0}), {status: 200});
      }
      if (method === 'POST' && pathname === '/api/scan-jobs') {
        deferredZipPosts += 1;
        return new Response(JSON.stringify({job_id: 'should-not-post', state: 'QUEUED'}), {status: 202});
      }
      return new Response(JSON.stringify({error_code: 'ROUTE_NOT_FOUND'}), {status: 404});
    };
    const mountedRace = dev.mountScanner({
      strictMode: true,
      outletContext: {
        apiOrigin: ORIGIN,
        authSessionScope: dev.apiMod.getAuthSessionScope(),
        apiRevision: 1,
        backend: {
          status: 'CONNECTED',
          health: {status: 'OK', write_auth_required: true, write_auth_configured: true, authenticated: true},
        },
      },
    });
    try {
      await mountedRace.render();
      await mountedRace.flush(4);
      const zipTab2 = mountedRace.container.querySelector('#scan-tab-zip');
      await dev.act(async () => { zipTab2.click(); });
      const fileInput2 = mountedRace.container.querySelector('#zip-file-input');
      let sliceCount = 0;
      let releaseSubmitSlice;
      const twoPhaseZip = {
        name: 'race-java.zip',
        size: 16,
        slice() {
          sliceCount += 1;
          if (sliceCount === 1) {
            return {async arrayBuffer() { return Uint8Array.from([0x50, 0x4b, 0x03, 0x04]).buffer; }};
          }
          return {
            arrayBuffer: () => new Promise((resolve) => {
              releaseSubmitSlice = () => resolve(Uint8Array.from([0x50, 0x4b, 0x03, 0x04]).buffer);
            }),
          };
        },
      };
      await dev.act(async () => { dom.setInputFiles(fileInput2, [twoPhaseZip]); });
      await mountedRace.flush(6);
      const submitBtn2 = mountedRace.container.querySelector('button[type="submit"]');
      assert.equal(submitBtn2.disabled, false);

      const form2 = mountedRace.container.querySelector('form');
      await dev.act(async () => {
        form2.dispatchEvent(new dom.Event('submit', {bubbles: true, cancelable: true}));
      });
      await mountedRace.flush(2);
      // Change origin & token while submit-time validateZipSignature is in-flight!
      dev.apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19199', token: 'tok-other-origin-999'});
      releaseSubmitSlice?.();
      await mountedRace.flush(4);
      assert.equal(deferredZipPosts, 0, 'mounted StrictMode ZIP submit must abort with 0 POSTs when origin/token changed mid-read');
      assert.equal(window.sessionStorage.getItem('22025523-active-job'), null);
    } finally {
      await mountedRace.unmount();
    }
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

test('Counterexample D4 (mounted React StrictMode): GitHub 202 saves job_id, tracks polling without duplicate POSTs, and discards late 202 on real unmount', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;
  try {
    const dev = loadDevMountedScannerBundle();
    dev.apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'tok-d4-123456'});
    const probeEvents = [];
    const postCalls = [];
    const pollCalls = [];
    global.fetch = async (url, opts = {}) => {
      const pathname = new URL(url).pathname;
      const method = (opts.method || 'GET').toUpperCase();
      if (method === 'GET' && pathname === '/api/scan-jobs') {
        return new Response(JSON.stringify({jobs: [], total_count: 0}), {status: 200});
      }
      if (method === 'POST' && pathname === '/api/scan-jobs') {
        postCalls.push({url, body: JSON.parse(opts.body)});
        return new Response(JSON.stringify({job_id: 'job-gh-strict-1', state: 'QUEUED'}), {status: 202});
      }
      if (method === 'GET' && pathname === '/api/scan-jobs/job-gh-strict-1') {
        pollCalls.push(pathname);
        return new Response(JSON.stringify({job_id: 'job-gh-strict-1', state: 'QUEUED'}), {status: 200});
      }
      return new Response(JSON.stringify({error_code: 'ROUTE_NOT_FOUND'}), {status: 404});
    };

    const mounted = dev.mountScanner({
      strictMode: true,
      onStrictProbe: (ev) => probeEvents.push(ev),
      outletContext: {
        apiOrigin: ORIGIN,
        authSessionScope: dev.apiMod.getAuthSessionScope(),
        apiRevision: 1,
        backend: {
          status: 'CONNECTED',
          health: {status: 'OK', write_auth_required: true, write_auth_configured: true, authenticated: true},
        },
      },
    });
    try {
      await mounted.render();
      await mounted.flush(4);
      assert.deepEqual(probeEvents, ['mount', 'cleanup', 'mount']);

      const urlInput = mounted.container.querySelector('#repo-url');
      await dev.act(async () => {
        dom.setInputValue(urlInput, 'https://github.com/org/repo.git');
      });
      await mounted.flush(2);
      const submitBtn = mounted.container.querySelector('button[type="submit"]');
      assert.equal(submitBtn.disabled, false);

      const form = mounted.container.querySelector('form');
      // Rapid double submit must emit ONLY 1 POST
      await dev.act(async () => {
        form.dispatchEvent(new dom.Event('submit', {bubbles: true, cancelable: true}));
        form.dispatchEvent(new dom.Event('submit', {bubbles: true, cancelable: true}));
      });
      await mounted.flush(6);

      assert.equal(postCalls.length, 1, 'GitHub submit under StrictMode must emit exactly 1 POST');
      assert.equal(postCalls[0].body.repo_url, 'https://github.com/org/repo.git');
      assert.equal(
        window.sessionStorage.getItem('22025523-active-job'),
        'job-gh-strict-1',
        'StrictMode must save acknowledged GitHub job_id to sessionStorage',
      );
      assert.equal(pollCalls.length, 1, 'acknowledged GitHub job must start single bounded poll without duplicate polling loop');
    } finally {
      await mounted.unmount();
    }

    // Real unmount while POST is in-flight must discard late 202 response and NOT store stale job_id
    window.sessionStorage.removeItem('22025523-active-job');
    let resolveLatePost;
    global.fetch = async (url, opts = {}) => {
      const pathname = new URL(url).pathname;
      const method = (opts.method || 'GET').toUpperCase();
      if (method === 'GET' && pathname === '/api/scan-jobs') {
        return new Response(JSON.stringify({jobs: [], total_count: 0}), {status: 200});
      }
      if (method === 'POST' && pathname === '/api/scan-jobs') {
        return new Promise((resolve) => {
          resolveLatePost = () => resolve(new Response(JSON.stringify({job_id: 'job-late-unmounted', state: 'QUEUED'}), {status: 202}));
        });
      }
      return new Response(JSON.stringify({error_code: 'ROUTE_NOT_FOUND'}), {status: 404});
    };
    const mountedLate = dev.mountScanner({
      strictMode: true,
      outletContext: {
        apiOrigin: ORIGIN,
        authSessionScope: dev.apiMod.getAuthSessionScope(),
        apiRevision: 1,
        backend: {
          status: 'CONNECTED',
          health: {status: 'OK', write_auth_required: true, write_auth_configured: true, authenticated: true},
        },
      },
    });
    await mountedLate.render();
    await mountedLate.flush(4);
    const urlInput2 = mountedLate.container.querySelector('#repo-url');
    await dev.act(async () => { dom.setInputValue(urlInput2, 'https://github.com/org/repo'); });
    await mountedLate.flush(2);
    const form2 = mountedLate.container.querySelector('form');
    await dev.act(async () => { form2.dispatchEvent(new dom.Event('submit', {bubbles: true, cancelable: true})); });
    await mountedLate.flush(2);
    await mountedLate.unmount();
    resolveLatePost?.();
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(
      window.sessionStorage.getItem('22025523-active-job'),
      null,
      'late 202 response resolving after real unmount must be discarded',
    );
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

test('Counterexample A5 (mounted React): COMPLETED job missing scan_id and duplicate job_id lock Scanner with 0 POSTs, while valid terminal jobs unlock', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;
  try {
    const dev = loadDevMountedScannerBundle();
    dev.apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'tok-a5-123456'});
    const okOutlet = () => ({
      apiOrigin: ORIGIN,
      authSessionScope: dev.apiMod.getAuthSessionScope(),
      apiRevision: 1,
      backend: {
        status: 'CONNECTED',
        health: {status: 'OK', write_auth_required: true, write_auth_configured: true, authenticated: true},
      },
    });

    const rejectedPayloads = [
      {label: 'COMPLETED missing scan_id', body: {jobs: [{job_id: 'j', state: 'COMPLETED'}], total_count: 1}},
      {label: 'COMPLETED blank scan_id', body: {jobs: [{job_id: 'j', state: 'COMPLETED', scan_id: '   '}], total_count: 1}},
      {label: 'COMPLETED non-string scan_id', body: {jobs: [{job_id: 'j', state: 'COMPLETED', scan_id: 123}], total_count: 1}},
      {label: 'duplicate FAILED job_id', body: {jobs: [{job_id: 'j', state: 'FAILED'}, {job_id: 'j', state: 'FAILED'}], total_count: 2}},
      {label: 'duplicate trimmed job_id', body: {jobs: [{job_id: 'j', state: 'COMPLETED', scan_id: 's1'}, {job_id: ' j ', state: 'FAILED'}], total_count: 2}},
    ];

    for (const scenario of rejectedPayloads) {
      let postCount = 0;
      global.fetch = async (url, opts = {}) => {
        if ((opts.method || 'GET') === 'POST') {
          postCount += 1;
          return new Response(JSON.stringify({job_id: 'should-not-post', state: 'QUEUED'}), {status: 202});
        }
        return new Response(JSON.stringify(scenario.body), {status: 200});
      };

      const mounted = dev.mountScanner({outletContext: okOutlet(), strictMode: false});
      try {
        await mounted.render();
        await mounted.flush(4);
        const urlInput = mounted.container.querySelector('#repo-url');
        await dev.act(async () => {
          dom.setInputValue(urlInput, 'https://github.com/org/repo');
        });
        await mounted.flush(2);
        const submitBtn = mounted.container.querySelector('button[type="submit"]');
        assert.equal(submitBtn.disabled, true, `${scenario.label}: submit button MUST remain disabled`);
        const form = mounted.container.querySelector('form');
        await dev.act(async () => {
          form.dispatchEvent(new dom.Event('submit', {bubbles: true, cancelable: true}));
        });
        await mounted.flush(2);
        assert.equal(postCount, 0, `${scenario.label}: must emit 0 POST requests`);
      } finally {
        await mounted.unmount();
      }
    }

    // Valid distinct terminal jobs (COMPLETED with scan_id + FAILED) must unlock valid form
    global.fetch = async () => new Response(JSON.stringify({
      jobs: [
        {job_id: 'j-1', state: 'COMPLETED', scan_id: 'scan-1'},
        {job_id: 'j-2', state: 'FAILED'},
      ],
      total_count: 2,
    }), {status: 200});
    const mountedOk = dev.mountScanner({outletContext: okOutlet(), strictMode: false});
    try {
      await mountedOk.render();
      await mountedOk.flush(4);
      const urlInput = mountedOk.container.querySelector('#repo-url');
      await dev.act(async () => {
        dom.setInputValue(urlInput, 'https://github.com/org/repo');
      });
      await mountedOk.flush(2);
      const submitBtn = mountedOk.container.querySelector('button[type="submit"]');
      assert.equal(submitBtn.disabled, false, 'valid distinct COMPLETED(with scan_id) + FAILED jobs must unlock valid form');
    } finally {
      await mountedOk.unmount();
    }
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

test('Counterexample A6: listScans preserves legacy direct-array and {items} compatibility while listScanJobs stays strict', async () => {
  setupDomGlobals();
  const prevFetch = global.fetch;
  try {
    const ui = loadUiBundle();
    ui.apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'tok-a6-123456'});

    // 1. listScans accepts canonical {scans}, legacy direct array [...], and legacy {items: [...]}
    for (const [label, payload] of Object.entries({
      contract: {scans: [{scan_id: 's'}], total_count: 1},
      legacyArray: [{scan_id: 's'}],
      legacyItems: {items: [{scan_id: 's'}], total_count: 1},
    })) {
      global.fetch = async () => new Response(JSON.stringify(payload), {status: 200});
      const out = await ui.apiMod.api.listScans();
      assert.equal(out.supported, true, `listScans must support ${label}`);
      assert.equal(out.items.length, 1, `listScans must preserve items for ${label}`);
      assert.equal(out.items[0]?.scan_id, 's', `listScans must read scan_id for ${label}`);
    }

    // 2. listScans still rejects error/malformed payloads rather than fabricating empty lists
    for (const bad of [{error: 'upstream error'}, {}, null, 'not-json']) {
      global.fetch = async () => new Response(typeof bad === 'string' ? bad : JSON.stringify(bad), {status: 200});
      const out = await ui.apiMod.api.listScans();
      assert.equal(out.supported, false, `listScans must reject malformed payload ${JSON.stringify(bad)}`);
      assert.deepEqual(out.items, []);
    }

    // 3. listScanJobs MUST NOT apply history leniency: direct array and {items} stay rejected!
    for (const [label, payload] of Object.entries({
      directArray: [{job_id: 'j', state: 'COMPLETED', scan_id: 's'}],
      legacyItems: {items: [{job_id: 'j', state: 'COMPLETED', scan_id: 's'}], total_count: 1},
      errorPayload: {error: 'upstream returned no job list'},
    })) {
      global.fetch = async () => new Response(JSON.stringify(payload), {status: 200});
      const out = await ui.apiMod.api.listScanJobs();
      assert.equal(out.supported, false, `listScanJobs must reject ${label}`);
      assert.equal(out.valid, false, `listScanJobs must mark ${label} invalid`);
      assert.deepEqual(out.items, []);
      assert.equal(ui.validateScanJobsListResponse(out).valid, false);
    }

    // 4. listScanJobs accepts canonical {jobs, total_count}
    global.fetch = async () => new Response(JSON.stringify({jobs: [], total_count: 0}), {status: 200});
    const validJobs = await ui.apiMod.api.listScanJobs();
    assert.equal(validJobs.supported, true);
    assert.equal(validJobs.valid, true);
    assert.equal(ui.validateScanJobsListResponse(validJobs).valid, true);
  } finally {
    global.fetch = prevFetch;
  }
});



