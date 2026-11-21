// Regression tests for Codex FRONTEND_ABC_FINAL_REAUDIT counterexamples:
//   B — scan history provenance must be isolated per API origin (B1–B6)
//   C — Dataflow step identity, file identity and SHA-256 attribution (C1–C8)
// These tests execute the real frontend modules (api.js, scanHistory.js, historySync.js,
// historyPresentation.js, findingPresentation.js) and render the real HistoryRow / HistoryPage
// components with react-dom/server. Network traffic goes to an in-process fetch mock that models two
// independent API origins; no real API, token or scan is used.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const APP_ROOT = path.join(__dirname, '..');
const SRC_ROOT = path.join(APP_ROOT, 'src');
const ORIGIN_A = 'http://127.0.0.1:19001';
const ORIGIN_B = 'http://127.0.0.1:19002';
const TOKEN_A = 'MOCK_HISTORY_TOKEN_A';
const TOKEN_B = 'MOCK_HISTORY_TOKEN_B';

function mkStorage() {
  return {
    _map: new Map(),
    get length() { return this._map.size; },
    key(i) { return [...this._map.keys()][i] ?? null; },
    getItem(k) { return this._map.has(k) ? this._map.get(k) : null; },
    setItem(k, v) { this._map.set(k, String(v)); },
    removeItem(k) { this._map.delete(k); },
    dump() { return [...this._map.entries()].map(([k, v]) => `${k}=${v}`).join('\n'); },
  };
}

function setupDomGlobals() {
  global.window = {setTimeout, clearTimeout, sessionStorage: mkStorage(), localStorage: mkStorage()};
}

function esmUrl(rel, replacements = []) {
  let src = fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8');
  src = src.replace(/import\.meta\.env\?\.VITE_API_BASE_URL/g, '""');
  for (const [from, to] of replacements) src = src.replace(from, to);
  return `data:text/javascript;base64,${Buffer.from(`${src}\n// ${Math.random()}`).toString('base64')}`;
}

// Load a consistent module graph so historySync uses the SAME api/scanHistory instances as the test.
async function loadHistoryGraph() {
  const apiUrl = esmUrl('services/api.js');
  const fpUrl = esmUrl('services/findingPresentation.js');
  const sdUrl = esmUrl('services/scanData.js', [["'./findingPresentation'", `'${fpUrl}'`]]);
  const shUrl = esmUrl('services/scanHistory.js', [["'./scanData'", `'${sdUrl}'`]]);
  const hsUrl = esmUrl('services/historySync.js', [["'./api'", `'${apiUrl}'`], ["'./scanHistory'", `'${shUrl}'`]]);
  const hpUrl = esmUrl('services/historyPresentation.js');
  return {
    api: await import(apiUrl),
    sh: await import(shUrl),
    hs: await import(hsUrl),
    hp: await import(hpUrl),
  };
}

// Bundle the real HistoryPage.jsx (and its HistoryRow) for server-side rendering.
function loadHistoryRenderer() {
  const esbuild = require(path.join(APP_ROOT, 'node_modules', 'esbuild'));
  const entry = `
    import {createElement as h} from 'react';
    import {renderToStaticMarkup} from 'react-dom/server';
    import {MemoryRouter} from 'react-router-dom';
    import HistoryPage, {HistoryRow} from './src/pages/HistoryPage.jsx';
    export function renderRows(records) {
      return renderToStaticMarkup(h(MemoryRouter, null,
        records.map((record, i) => h(HistoryRow, {key: i, record, availability: undefined, onDelete() {}}))));
    }
    export function renderPage() {
      return renderToStaticMarkup(h(MemoryRouter, null, h(HistoryPage)));
    }
  `;
  const out = esbuild.buildSync({
    stdin: {contents: entry, resolveDir: APP_ROOT, loader: 'jsx', sourcefile: 'history-render-entry.jsx'},
    bundle: true,
    platform: 'node',
    format: 'cjs',
    jsx: 'automatic',
    loader: {'.css': 'empty'},
    write: false,
    logLevel: 'silent',
    define: {'import.meta.env': '{}', 'process.env.NODE_ENV': '"production"'},
  });
  const m = new Module('history-render-bundle', module);
  m.paths = module.paths;
  m._compile(out.outputFiles[0].text, path.join(APP_ROOT, 'history-render-bundle.cjs'));
  return m.exports;
}

function json(status, body) {
  return new Response(JSON.stringify(body), {status, headers: {'Content-Type': 'application/json'}});
}

// Two independent API origins behind one fetch mock. Each origin has its own route table.
function installTwoOriginFetch() {
  const requests = [];
  const routes = {[ORIGIN_A]: {}, [ORIGIN_B]: {}};
  const prev = global.fetch;
  global.fetch = async (url, options = {}) => {
    const u = new URL(url);
    const entry = {
      origin: u.origin,
      path: u.pathname,
      method: options.method || 'GET',
      auth: (options.headers || {}).Authorization,
    };
    requests.push(entry);
    const handler = routes[u.origin]?.[u.pathname];
    if (!handler) return json(404, {error_code: 'NOT_FOUND', error_message: 'not found'});
    return handler(options);
  };
  return {requests, routes, restore: () => { global.fetch = prev; }};
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    Object.values(value).forEach(deepFreeze);
  }
  return value;
}

// ------------------------------------------------------------------------------------------------
// B — History provenance per API origin
// ------------------------------------------------------------------------------------------------

test('B1 + B4: repo URL/commit cached on origin A (or typed on B) never appear on an API-B row and are never labelled as API data', async () => {
  setupDomGlobals();
  const net = installTwoOriginFetch();
  try {
    const {api, sh, hs, hp} = await loadHistoryGraph();

    // Origin A: API A returns scan-001 with repo-A; it is cached in RAM for origin A's auth session only.
    net.routes[ORIGIN_A]['/api/scans'] = async () => json(200, {scans: [{
      scan_id: 'scan-001', data_origin: 'REAL_SCAN', repo_url: 'https://github.com/example/repo-A',
      resolved_commit: 'aaaaaaa1111111', input_mode: 'GITHUB', total_findings: 3, completed_at: '2026-11-18T10:00:00Z',
    }]});
    api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_A});
    const syncA = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.equal(syncA.stale, false);
    assert.equal(syncA.records.find((r) => r.scanId === 'scan-001').repoUrl, 'https://github.com/example/repo-A');
    assert.deepEqual(
      sh.readHistory(ORIGIN_A, {sessionScope: syncA.sessionScope}).map((r) => r.repoUrl),
      ['https://github.com/example/repo-A'],
      'precondition: active RAM session cache on origin A holds repo-A',
    );
    assert.equal(window.localStorage.dump(), '', 'auth-session history must never be persisted to localStorage');

    // Switch to origin B; API B returns the same scan id WITHOUT repo_url/commit, and scan-002 without source.
    net.routes[ORIGIN_B]['/api/scans'] = async () => json(200, {scans: [
      {scan_id: 'scan-001', data_origin: 'REAL_SCAN', total_findings: 1},
      {scan_id: 'scan-002', data_origin: 'REAL_SCAN', input_mode: 'GITHUB', total_findings: 0},
    ]});
    const cfgB = api.configureApiConnection({baseUrl: ORIGIN_B, token: TOKEN_B});
    // B4 precondition: the user typed a URL in Scanner during B's active session (browser cache only).
    sh.upsertHistory(
      {scanId: 'scan-002', repoUrl: 'https://github.com/example/typed-on-B', inputMode: 'GITHUB', status: 'QUEUED'},
      {origin: ORIGIN_B, sessionScope: cfgB.sessionScope},
    );
    const before = net.requests.length;
    const syncB = await hs.syncHistoryFromApi({origin: ORIGIN_B});
    assert.equal(syncB.stale, false);

    const row1 = syncB.records.find((r) => r.scanId === 'scan-001');
    assert.equal(row1.backendConfirmed, true);
    assert.equal(row1.apiOrigin, ORIGIN_B);
    assert.equal(row1.repoUrl, undefined, 'B1: repo URL cached for origin A must not fill the API-B row');
    assert.equal(row1.commit, undefined, 'B4: commit must not be back-filled');
    assert.equal(hp.displaySource(row1).value, 'Chưa có thông tin nguồn từ API hiện tại');
    assert.equal(hp.historyProvenanceLabel(row1).label, 'Thông tin từ API hiện tại');

    const row2 = syncB.records.find((r) => r.scanId === 'scan-002');
    assert.equal(row2.backendConfirmed, true);
    assert.equal(row2.repoUrl, undefined, 'B4: URL typed earlier must not be presented as API data');
    assert.equal(hp.displaySource(row2).value, 'Chưa có đường dẫn repository từ API hiện tại');
    assert.doesNotMatch(JSON.stringify(syncB.records), /repo-A|typed-on-B|aaaaaaa1111111/);

    // Rendered output of the real HistoryRow component.
    const {renderRows} = loadHistoryRenderer();
    const html = renderRows(syncB.records);
    assert.doesNotMatch(html, /repo-A/, 'B1: repo-A must not be rendered on origin B');
    assert.doesNotMatch(html, /typed-on-B/, 'B4: typed URL must not be rendered as API source');
    assert.doesNotMatch(html, /Xác nhận từ API/);
    assert.match(html, /Chưa có thông tin nguồn từ API hiện tại/);
    assert.match(html, /Chưa có đường dẫn repository từ API hiện tại/);
    assert.doesNotMatch(
      html,
      /Bộ nhớ tạm trình duyệt · chưa xác nhận lại với API/,
      'backend-confirmed rows must not render the browser-cache provenance badge',
    );
    assert.doesNotMatch(
      html,
      /Thông tin từ API hiện tại/,
      'approved HistoryRow omits redundant API provenance badge on backend-confirmed rows',
    );
    assert.match(html, /Chưa có mốc hoàn tất/, 'rows without completedAt must not display cache savedAt as completion time');

    // Requests issued for B went only to B, carried only token B, and were GET.
    const bRequests = net.requests.slice(before);
    assert(bRequests.length >= 2);
    assert(bRequests.every((r) => r.origin === ORIGIN_B && r.method === 'GET'));
    assert(bRequests.every((r) => r.auth === `Bearer ${TOKEN_B}`));
  } finally {
    net.restore();
  }
});

test('B2: identical scan id on two origins keeps each origin\'s own repository; caches are isolated by origin and session', async () => {
  setupDomGlobals();
  const net = installTwoOriginFetch();
  try {
    const {api, sh, hs} = await loadHistoryGraph();
    net.routes[ORIGIN_A]['/api/scans'] = async () => json(200, {scans: [{scan_id: 'scan-001', repo_url: 'https://github.com/example/repo-A', input_mode: 'GITHUB'}]});
    net.routes[ORIGIN_B]['/api/scans'] = async () => json(200, {scans: [{scan_id: 'scan-001', repo_url: 'https://github.com/example/repo-B', input_mode: 'GITHUB'}]});

    api.configureApiConnection({baseUrl: ORIGIN_A, token: ''});
    const a = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.deepEqual(a.records.map((r) => r.repoUrl), ['https://github.com/example/repo-A']);
    assert.deepEqual(sh.readHistory(ORIGIN_A, {sessionScope: a.sessionScope}).map((r) => r.repoUrl), ['https://github.com/example/repo-A']);

    api.configureApiConnection({baseUrl: ORIGIN_B, token: ''});
    const b = await hs.syncHistoryFromApi({origin: ORIGIN_B});

    assert.deepEqual(b.records.map((r) => r.repoUrl), ['https://github.com/example/repo-B']);
    assert.deepEqual(sh.readHistory(ORIGIN_B, {sessionScope: b.sessionScope}).map((r) => r.repoUrl), ['https://github.com/example/repo-B']);
    assert.equal(sh.readHistory(ORIGIN_A, {sessionScope: a.sessionScope}).length, 0, 'switching origin clears prior session RAM cache');
    assert.notEqual(sh.scopedHistoryKey(a.records[0]), sh.scopedHistoryKey(b.records[0]));

    // Hiding scan-001 on B only affects B's active session.
    sh.hideHistoryRecord(b.records[0]);
    assert.equal(sh.readHistory(ORIGIN_B, {sessionScope: b.sessionScope}).length, 0);
    assert.equal(sh.readHiddenHistory(ORIGIN_B, {sessionScope: b.sessionScope}).length, 1);
    assert.equal(sh.readHiddenHistory(ORIGIN_A, {sessionScope: a.sessionScope}).length, 0);
  } finally {
    net.restore();
  }
});

test('B3: a late history response from origin A after switching to B is discarded and never written to any cache', async () => {
  setupDomGlobals();
  const net = installTwoOriginFetch();
  try {
    const {api, sh, hs} = await loadHistoryGraph();
    let releaseA;
    // Transport that ignores AbortSignal and resolves late (worst case).
    net.routes[ORIGIN_A]['/api/scan-jobs'] = () => new Promise((resolve) => {
      releaseA = () => resolve(json(200, {jobs: [{job_id: 'job-late', scan_id: 'scan-late', state: 'COMPLETED', repo_url: 'https://github.com/example/repo-A-late'}]}));
    });
    net.routes[ORIGIN_B]['/api/scans'] = async () => json(200, {scans: [{scan_id: 'scan-b', repo_url: 'https://github.com/example/repo-B', input_mode: 'GITHUB'}]});

    api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_A});
    const pendingA = hs.syncHistoryFromApi({origin: ORIGIN_A});
    await new Promise((r) => setImmediate(r));

    api.configureApiConnection({baseUrl: ORIGIN_B, token: TOKEN_B});
    const b = await hs.syncHistoryFromApi({origin: ORIGIN_B});
    releaseA();
    const lateA = await pendingA;

    assert.deepEqual(lateA, {stale: true}, 'late origin-A result must be reported stale, not as an error or data');
    assert.deepEqual(b.records.map((r) => r.scanId), ['scan-b']);
    assert.doesNotMatch(window.localStorage.dump(), /repo-A-late|scan-late/, 'late A data must not be persisted');
    assert.deepEqual(sh.readHistory(ORIGIN_B, {sessionScope: b.sessionScope}).map((r) => r.scanId), ['scan-b']);
    assert.equal(sh.readHistory(ORIGIN_A).length, 0);
  } finally {
    net.restore();
  }
});

test('B3b: historySync\'s own staleness guard drops a late result even if the transport layer did not flag it', async () => {
  setupDomGlobals();
  const {api, sh, hs} = await loadHistoryGraph();
  api.configureApiConnection({baseUrl: ORIGIN_A, token: ''});
  let release;
  const lateClient = {
    // Resolves AFTER the origin switch and is NOT marked abortedByConfigChange (adapter bypassed).
    listScanJobs: () => new Promise((resolve) => {
      release = () => resolve({supported: true, items: [{job_id: 'job-late', scan_id: 'scan-late', state: 'COMPLETED', repo_url: 'https://github.com/example/repo-A-late'}]});
    }),
    listScans: async () => ({supported: true, items: []}),
  };
  const pending = hs.syncHistoryFromApi({origin: ORIGIN_A, apiClient: lateClient});
  api.configureApiConnection({baseUrl: ORIGIN_B, token: ''});
  release();
  assert.deepEqual(await pending, {stale: true});
  assert.equal(window.localStorage.dump(), '');
  assert.equal(sh.readHistory(ORIGIN_A).length, 0);
  assert.equal(sh.readHistory(ORIGIN_B).length, 0);
});

test('B5 + B6: active-session cache fallback stays labelled as cache, returning A->B->A never resurrects old session cache, and zero write requests occur', async () => {
  setupDomGlobals();
  const net = installTwoOriginFetch();
  try {
    const {api, sh, hs, hp} = await loadHistoryGraph();
    net.routes[ORIGIN_A]['/api/scans'] = async () => json(200, {scans: [{scan_id: 'scan-a', repo_url: 'https://github.com/example/repo-A', input_mode: 'GITHUB'}]});
    net.routes[ORIGIN_B]['/api/scans'] = async () => json(200, {scans: [{scan_id: 'scan-b', repo_url: 'https://github.com/example/repo-B', input_mode: 'GITHUB'}]});

    // Active session on A: loads scan-a into RAM cache, then A temporarily drops offline WITHIN the same session.
    api.configureApiConnection({baseUrl: ORIGIN_A, token: ''});
    const firstA = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.deepEqual(firstA.records.map((r) => r.scanId), ['scan-a']);

    net.routes[ORIGIN_A]['/api/scans'] = async () => { throw new TypeError('Failed to fetch'); };
    const sameSessionOffline = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.equal(sameSessionOffline.supported, false);
    assert.deepEqual(sameSessionOffline.records.map((r) => r.scanId), ['scan-a']);
    assert.equal(sameSessionOffline.records[0].backendConfirmed, false);
    assert.equal(
      hp.historyProvenanceLabel(sameSessionOffline.records[0]).label,
      'Bộ nhớ tạm trình duyệt · chưa xác nhận lại với API',
    );
    const {renderRows} = loadHistoryRenderer();
    const offlineRowsHtml = renderRows(sameSessionOffline.records);
    assert.match(offlineRowsHtml, /Bộ nhớ tạm trình duyệt · chưa xác nhận lại với API/);
    assert.doesNotMatch(offlineRowsHtml, /Thông tin từ API hiện tại/);

    // Switch A -> B (creates new auth session scope, clears A RAM cache) and browse Findings/Review.
    api.configureApiConnection({baseUrl: ORIGIN_B, token: ''});
    const onB = await hs.syncHistoryFromApi({origin: ORIGIN_B});
    assert.deepEqual(onB.records.map((r) => r.scanId), ['scan-b']);
    net.routes[ORIGIN_B]['/api/scans/scan-b/review-queue'] = async () => json(200, {warnings: [], counts: {}});
    net.routes[ORIGIN_B]['/api/scans/scan-b/findings/f-1'] = async () => json(200, {finding_id: 'f-1'});
    await api.api.reviewQueue('scan-b');
    await api.api.findingDetail('scan-b', 'f-1');

    // Return B -> A while A is offline: MUST NOT leak B data and MUST NOT resurrect old session A cache.
    const returnedCfg = api.configureApiConnection({baseUrl: ORIGIN_A, token: ''});
    assert.notEqual(returnedCfg.sessionScope, firstA.sessionScope);
    const backOnA = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.equal(backOnA.supported, false);
    assert.deepEqual(backOnA.records, [], 'returning to prior origin in a new session must not resurrect old session cache');
    assert.equal(sh.readHistory(ORIGIN_A, {sessionScope: returnedCfg.sessionScope}).length, 0);
    assert.equal(sh.readHistory(ORIGIN_B, {sessionScope: onB.sessionScope}).length, 0);

    // B6: whole session issued zero non-GET requests.
    assert.equal(net.requests.filter((r) => r.method !== 'GET').length, 0);
    assert(net.requests.some((r) => r.origin === ORIGIN_B && r.path === '/api/scans/scan-b/review-queue'));
  } finally {
    net.restore();
  }
});

test('B (legacy data + timestamp honesty): localStorage legacy entries are ignored and missing completedAt is never mislabelled', async () => {
  setupDomGlobals();
  window.localStorage.setItem('22025523-scan-history-v1', JSON.stringify([
    {scanId: 'legacy-001', repoUrl: 'https://github.com/example/legacy', status: 'COMPLETED'},
  ]));
  const {sh, hp} = await loadHistoryGraph();
  assert.equal(sh.readHistory(ORIGIN_A).length, 0);
  assert.equal(sh.readHistory(ORIGIN_B).length, 0);
  const remoteNoTimestamp = sh.historyRecordFromBackend({scan_id: 'legacy-001'}, {origin: ORIGIN_B});
  const merged = sh.mergeHistoryRecords(sh.readHistory(ORIGIN_B), [remoteNoTimestamp], [], {origin: ORIGIN_B});
  assert.equal(merged.length, 1);
  assert.equal(merged[0].repoUrl, undefined);

  // Timestamp label honesty (Codex finding at HistoryPage.jsx:97):
  assert.deepEqual(hp.displayHistoryTimestamp(remoteNoTimestamp), {
    label: 'Thời điểm hoàn tất',
    value: 'Chưa có mốc hoàn tất',
  });
  const startedOnly = sh.historyRecordFromBackend(
    {job_id: 'job-run-1', state: 'RUNNING', started_at: '2026-11-19T08:30:00Z'},
    {origin: ORIGIN_B},
  );
  assert.equal(hp.displayHistoryTimestamp(startedOnly).label, 'Thời điểm bắt đầu');
  assert.notEqual(hp.displayHistoryTimestamp(startedOnly).value, '-');

  const {renderRows} = loadHistoryRenderer();
  const html = renderRows([remoteNoTimestamp, startedOnly]);
  assert.match(html, /Chưa có mốc hoàn tất/);
  assert.match(html, /Thời điểm bắt đầu/);
});

// ------------------------------------------------------------------------------------------------
// B7–B12 — Auth Session Scope isolation across same-origin token switches & reload
// ------------------------------------------------------------------------------------------------

test('B7: changing Bearer Token on the SAME API origin clears previous session cache when new session returns []', async () => {
  setupDomGlobals();
  const net = installTwoOriginFetch();
  try {
    const {api, sh, hs} = await loadHistoryGraph();
    net.routes[ORIGIN_A]['/api/scans'] = async (opts) => {
      if ((opts.headers || {}).Authorization === `Bearer ${TOKEN_A}`) {
        return json(200, {scans: [{
          scan_id: 'scan-session-a',
          repo_url: 'https://github.com/example/repo-A',
          resolved_commit: 'aaaa1111',
          input_mode: 'GITHUB',
          data_origin: 'REAL_SCAN',
        }]});
      }
      return json(200, {scans: []});
    };

    const cfgA = api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_A});
    const syncA = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.deepEqual(syncA.records.map((r) => r.repoUrl), ['https://github.com/example/repo-A']);
    assert.equal(syncA.sessionScope, cfgA.sessionScope);

    // Switch to TOKEN_B on the EXACT SAME API origin.
    const beforeB = net.requests.length;
    const cfgB = api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_B});
    assert.equal(cfgB.originChanged, false);
    assert.equal(cfgB.tokenChanged, true);
    assert.equal(cfgB.sessionChanged, true);
    assert.notEqual(cfgB.sessionScope, cfgA.sessionScope);
    assert(!cfgB.sessionScope.includes(TOKEN_A) && !cfgB.sessionScope.includes(TOKEN_B), 'sessionScope must be opaque (never token)');

    const syncB = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.equal(syncB.stale, false);
    assert.deepEqual(syncB.records, [], 'B7: new auth session receiving [] must display zero records');
    assert.equal(sh.readHistory(ORIGIN_A, {sessionScope: cfgB.sessionScope}).length, 0);
    assert.equal(sh.readHistory(ORIGIN_A, {sessionScope: cfgA.sessionScope}).length, 0);
    assert.doesNotMatch(JSON.stringify(syncB.records), /repo-A/);

    // Rendered HistoryPage / HistoryRow for session B contains zero repo-A.
    const {renderRows} = loadHistoryRenderer();
    assert.equal(renderRows(syncB.records), '');

    // Storage never contains token or session A history.
    assert.doesNotMatch(window.localStorage.dump(), /repo-A|MOCK_HISTORY_TOKEN/);
    assert.doesNotMatch(window.sessionStorage.dump(), /MOCK_HISTORY_TOKEN/);

    // Requests for B carried ONLY TOKEN_B.
    const bReqs = net.requests.slice(beforeB);
    assert(bReqs.length >= 2);
    assert(bReqs.every((r) => r.origin === ORIGIN_A && r.auth === `Bearer ${TOKEN_B}` && r.method === 'GET'));
  } finally {
    net.restore();
  }
});

test('B8: same scan ID across two auth sessions on the SAME origin never mixes metadata', async () => {
  setupDomGlobals();
  const net = installTwoOriginFetch();
  try {
    const {api, hs, hp} = await loadHistoryGraph();
    let bMode = 'with-repo';
    net.routes[ORIGIN_A]['/api/scans'] = async (opts) => {
      if ((opts.headers || {}).Authorization === `Bearer ${TOKEN_A}`) {
        return json(200, {scans: [{
          scan_id: 'scan-shared-001',
          repo_url: 'https://github.com/example/session-A-repo',
          resolved_commit: 'aaaa0001',
          input_mode: 'GITHUB',
          data_origin: 'REAL_SCAN',
        }]});
      }
      if (bMode === 'with-repo') {
        return json(200, {scans: [{
          scan_id: 'scan-shared-001',
          repo_url: 'https://github.com/example/session-B-repo',
          resolved_commit: 'bbbb0002',
          input_mode: 'GITHUB',
          data_origin: 'REAL_SCAN',
        }]});
      }
      return json(200, {scans: [{scan_id: 'scan-shared-001', data_origin: 'REAL_SCAN'}]});
    };

    api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_A});
    const syncA = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.equal(syncA.records[0].repoUrl, 'https://github.com/example/session-A-repo');
    assert.equal(syncA.records[0].commit, 'aaaa0001');

    // Token B returns same scan_id with B's metadata.
    api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_B});
    const syncB = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.equal(syncB.records.length, 1);
    assert.equal(syncB.records[0].repoUrl, 'https://github.com/example/session-B-repo');
    assert.equal(syncB.records[0].commit, 'bbbb0002');
    assert.doesNotMatch(JSON.stringify(syncB.records), /session-A-repo|aaaa0001/);

    // Token C returns same scan_id with missing repo_url & commit -> never inherits A or B metadata.
    bMode = 'missing-source';
    api.configureApiConnection({baseUrl: ORIGIN_A, token: 'MOCK_HISTORY_TOKEN_C'});
    const syncC = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.equal(syncC.records.length, 1);
    assert.equal(syncC.records[0].repoUrl, undefined);
    assert.equal(syncC.records[0].commit, undefined);
    assert.equal(hp.displaySource(syncC.records[0]).value, 'Chưa có thông tin nguồn từ API hiện tại');
    assert.doesNotMatch(JSON.stringify(syncC.records), /session-A-repo|session-B-repo|aaaa0001|bbbb0002/);
  } finally {
    net.restore();
  }
});

test('B9: late responses from Token A after switching to Token B on the SAME origin are discarded (adapter + historySync)', async () => {
  setupDomGlobals();
  const net = installTwoOriginFetch();
  try {
    const {api, sh, hs} = await loadHistoryGraph();
    let releaseLateHistoryA;
    let releaseLateFindingA;

    net.routes[ORIGIN_A]['/api/scan-jobs'] = (opts) => {
      if ((opts.headers || {}).Authorization === `Bearer ${TOKEN_A}`) {
        return new Promise((resolve) => {
          releaseLateHistoryA = () => resolve(json(200, {
            jobs: [{job_id: 'job-a-late', scan_id: 'scan-a-late', state: 'COMPLETED', repo_url: 'https://github.com/example/late-token-A'}],
          }));
        });
      }
      return json(200, {jobs: []});
    };
    net.routes[ORIGIN_A]['/api/scans'] = async (opts) => {
      if ((opts.headers || {}).Authorization === `Bearer ${TOKEN_B}`) {
        return json(200, {scans: [{scan_id: 'scan-b-live', repo_url: 'https://github.com/example/live-token-B', input_mode: 'GITHUB'}]});
      }
      return json(200, {scans: []});
    };
    net.routes[ORIGIN_A]['/api/scans/scan-1/findings/f-1'] = (opts) => {
      if ((opts.headers || {}).Authorization === `Bearer ${TOKEN_A}`) {
        return new Promise((resolve) => {
          releaseLateFindingA = () => resolve(json(200, {finding_id: 'f-1', message: 'STALE_FROM_TOKEN_A'}));
        });
      }
      return json(200, {finding_id: 'f-1', message: 'LIVE_FROM_TOKEN_B'});
    };

    api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_A});
    const pendingHistoryA = hs.syncHistoryFromApi({origin: ORIGIN_A});
    const pendingFindingA = api.api.findingDetail('scan-1', 'f-1');
    await new Promise((r) => setImmediate(r));

    // Switch to Token B on SAME origin; B loads cleanly.
    const cfgB = api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_B});
    const historyB = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    const findingB = await api.api.findingDetail('scan-1', 'f-1');
    assert.deepEqual(historyB.records.map((r) => r.scanId), ['scan-b-live']);
    assert.equal(findingB.message, 'LIVE_FROM_TOKEN_B');

    // Now release Token A's late responses (transport ignored AbortSignal).
    releaseLateHistoryA();
    releaseLateFindingA();
    assert.deepEqual(await pendingHistoryA, {stale: true});
    await assert.rejects(
      () => pendingFindingA,
      (err) => err instanceof api.ApiError && err.abortedByConfigChange === true,
    );

    // B's cache and data remain untouched; late Token A data never entered cache.
    assert.deepEqual(sh.readHistory(ORIGIN_A, {sessionScope: cfgB.sessionScope}).map((r) => r.scanId), ['scan-b-live']);
    assert.doesNotMatch(JSON.stringify(sh.readHistory(ORIGIN_A, {sessionScope: cfgB.sessionScope})), /late-token-A|scan-a-late/);

    // Also test historySync's own session-scope staleness guard bypassing adapter.
    let releaseBypass;
    const bypassClient = {
      listScanJobs: () => new Promise((resolve) => {
        releaseBypass = () => resolve({supported: true, items: [{job_id: 'j-byp', scan_id: 'scan-byp', state: 'COMPLETED', repo_url: 'https://github.com/example/bypass-A'}]});
      }),
      listScans: async () => ({supported: true, items: []}),
    };
    const pendingBypass = hs.syncHistoryFromApi({origin: ORIGIN_A, apiClient: bypassClient});
    api.setSessionToken('MOCK_HISTORY_TOKEN_D');
    releaseBypass();
    assert.deepEqual(await pendingBypass, {stale: true});
    assert.equal(sh.readHistory(ORIGIN_A, {sessionScope: api.getAuthSessionScope()}).length, 0);
  } finally {
    net.restore();
  }
});

test('B10: A -> B -> A never restores old session A cache, while re-applying unchanged URL + credential keeps valid session state', async () => {
  setupDomGlobals();
  const net = installTwoOriginFetch();
  try {
    const {api, sh, hs} = await loadHistoryGraph();
    let allowAToRespond = true;
    net.routes[ORIGIN_A]['/api/scans'] = async (opts) => {
      if ((opts.headers || {}).Authorization === `Bearer ${TOKEN_A}`) {
        if (!allowAToRespond) return json(200, {scans: []});
        return json(200, {scans: [{scan_id: 'scan-a1', repo_url: 'https://github.com/example/repo-A', input_mode: 'GITHUB'}]});
      }
      return json(200, {scans: [{scan_id: 'scan-b1', repo_url: 'https://github.com/example/repo-B', input_mode: 'GITHUB'}]});
    };

    const cfgA1 = api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_A});
    const syncA1 = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.deepEqual(syncA1.records.map((r) => r.scanId), ['scan-a1']);

    // Re-applying SAME URL + empty token (keeping TOKEN_A) OR SAME URL + SAME TOKEN_A keeps valid session scope & cache.
    const sameKeep = api.configureApiConnection({baseUrl: `${ORIGIN_A}/`, token: ''});
    assert.equal(sameKeep.sessionChanged, false);
    assert.equal(sameKeep.sessionScope, cfgA1.sessionScope);
    assert.equal(sh.readHistory(ORIGIN_A, {sessionScope: cfgA1.sessionScope}).length, 1);

    const sameExplicit = api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_A});
    assert.equal(sameExplicit.sessionChanged, false);
    assert.equal(sameExplicit.sessionScope, cfgA1.sessionScope);
    assert.equal(sh.readHistory(ORIGIN_A, {sessionScope: cfgA1.sessionScope}).length, 1);

    // Switch A -> B -> A: old A1 cache must NEVER be resurrected.
    const cfgB = api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_B});
    assert.equal(cfgB.sessionChanged, true);
    await hs.syncHistoryFromApi({origin: ORIGIN_A});

    allowAToRespond = false;
    const cfgA2 = api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_A});
    assert.equal(cfgA2.sessionChanged, true);
    assert.notEqual(cfgA2.sessionScope, cfgA1.sessionScope);
    assert.equal(sh.readHistory(ORIGIN_A, {sessionScope: cfgA2.sessionScope}).length, 0);

    const syncA2 = await hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.deepEqual(syncA2.records, [], 'B10: returning to Token A must not resurrect old session A1 cache');

    // Clearing token also rotates session scope and clears cache.
    api.clearSessionToken();
    assert.equal(api.hasSessionToken(), false);
    assert.notEqual(api.getAuthSessionScope(), cfgA2.sessionScope);
    assert.equal(sh.readHistory(ORIGIN_A, {sessionScope: api.getAuthSessionScope()}).length, 0);
  } finally {
    net.restore();
  }
});

test('B11 + B12: reload loses RAM token and prior auth-session history; switching tokens and reading pages issues zero POST calls', async () => {
  const sharedLocalStorage = mkStorage();
  const sharedSessionStorage = mkStorage();
  global.window = {setTimeout, clearTimeout, sessionStorage: sharedSessionStorage, localStorage: sharedLocalStorage};

  const net = installTwoOriginFetch();
  try {
    net.routes[ORIGIN_A]['/api/scans'] = async (opts) => {
      if ((opts.headers || {}).Authorization === `Bearer ${TOKEN_A}`) {
        return json(200, {scans: [{scan_id: 'scan-priv-a', repo_url: 'https://github.com/example/private-A', input_mode: 'GITHUB'}]});
      }
      return json(401, {error_code: 'UNAUTHORIZED', error_message: 'Missing token'});
    };
    net.routes[ORIGIN_A]['/api/scans/scan-priv-a'] = async () => json(200, {scan_id: 'scan-priv-a', data_origin: 'REAL_SCAN'});
    net.routes[ORIGIN_A]['/api/scans/scan-priv-a/findings/f-1'] = async () => json(200, {finding_id: 'f-1'});
    net.routes[ORIGIN_A]['/api/scans/scan-priv-a/review-queue'] = async () => json(200, {warnings: [], counts: {}});
    net.routes[ORIGIN_A]['/api/scans/scan-priv-a/report'] = async () => json(200, {data_origin: 'REAL_SCAN', scan_summary: {scan_id: 'scan-priv-a'}, findings: []});

    // Session before reload: authenticated as TOKEN_A, loads history & browses Findings/Review/Reports.
    const beforeReload = await loadHistoryGraph();
    beforeReload.api.configureApiConnection({baseUrl: ORIGIN_A, token: TOKEN_A});
    const loaded = await beforeReload.hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.deepEqual(loaded.records.map((r) => r.scanId), ['scan-priv-a']);
    sharedSessionStorage.setItem('22025523-scan-id', 'scan-priv-a');
    await beforeReload.api.api.scanSummary('scan-priv-a');
    await beforeReload.api.api.findingDetail('scan-priv-a', 'f-1');
    await beforeReload.api.api.reviewQueue('scan-priv-a');
    await beforeReload.api.api.report('scan-priv-a');

    // Simulate page reload: fresh module graph sharing the SAME browser localStorage + sessionStorage!
    const afterReload = await loadHistoryGraph();
    assert.equal(afterReload.api.hasSessionToken(), false, 'B11: RAM token must be cleared on reload');
    assert.equal(sharedSessionStorage.getItem('22025523-scan-id'), null, 'B11: stale active scan id cleared on reload');
    assert.equal(
      afterReload.sh.readHistory(ORIGIN_A, {sessionScope: afterReload.api.getAuthSessionScope()}).length,
      0,
      'B11: reloaded page must not show private history from previous auth session',
    );
    const syncAfterReload = await afterReload.hs.syncHistoryFromApi({origin: ORIGIN_A});
    assert.equal(syncAfterReload.supported, false);
    assert.deepEqual(syncAfterReload.records, []);
    assert.match(syncAfterReload.lastError, /401/);
    assert(!syncAfterReload.lastError.includes(TOKEN_A));

    // Real HistoryPage render after reload shows empty state, never private-A.
    const {renderPage} = loadHistoryRenderer();
    const reloadHtml = renderPage();
    assert.doesNotMatch(reloadHtml, /private-A|scan-priv-a/);
    assert.match(reloadHtml, /Chưa có phiên phân tích nào/);

    // B12: zero POST (or any non-GET) requests across the entire token-switch & browsing sequence.
    assert.equal(net.requests.filter((r) => r.method !== 'GET').length, 0);
  } finally {
    net.restore();
  }
});

// ------------------------------------------------------------------------------------------------
// C — Dataflow identity, file identity and SHA-256 attribution
// ------------------------------------------------------------------------------------------------

async function loadFp() {
  return import(esmUrl('services/findingPresentation.js'));
}

const ROOT = 'C:/runtime/job-x/source';
const REL = 'src/main/java/FileServlet.java';
const SHA_FS = '6fa58b5e65bb48522136529a7c613dc0b129dea8c4cf2b972a38b276578d932d';
const loc = (p, l1, c1, l2, c2) => ({path: p, start: {line: l1, col: c1}, end: {line: l2, col: c2}});

function fileServletEvidence({endpointOnlySnippets = false} = {}) {
  const abs = `${ROOT}/${REL}`;
  const snip = (role, l1, c1, l2, c2, matched) => ({role, path: REL, raw_path: abs, start: {line: l1, col: c1}, end: {line: l2, col: c2}, matched, sha256: SHA_FS});
  const snippets = [
    snip('finding', 46, 43, 46, 68, 'new FileInputStream(file)'),
    snip('source', 28, 27, 28, 55, 'request.getParameter("file")'),
    ...(endpointOnlySnippets ? [] : [snip('intermediate', 28, 16, 28, 24, 'fileName'), snip('intermediate', 33, 18, 33, 22, 'file')]),
    snip('sink', 46, 43, 46, 68, 'new FileInputStream(file)'),
  ];
  return {
    path: REL,
    raw_path: abs,
    snapshots: {[REL]: {sha256: SHA_FS, size: 2048}},
    snippets,
    raw_trace: {
      taint_source: ['CliLoc', [loc(abs, 28, 27, 28, 55), 'request.getParameter("file")']],
      intermediate_vars: [
        {location: loc(abs, 28, 16, 28, 24), content: 'fileName'},
        {location: loc(abs, 33, 18, 33, 22), content: 'file'},
      ],
      taint_sink: ['CliLoc', [loc(abs, 46, 43, 46, 68), 'new FileInputStream(file)']],
    },
  };
}

test('C1: real CWE-22 FileServlet flow (absolute OpenGrep paths + proven root) keeps Source 28 → Intermediate 28/33 → Sink 46', async () => {
  const fp = await loadFp();
  for (const endpointOnlySnippets of [false, true]) {
    const ev = deepFreeze(fileServletEvidence({endpointOnlySnippets}));
    const r = fp.analyzeDataflow(ev);
    assert.equal(r.completeness, 'COMPLETE');
    assert.equal(r.ambiguousStepCount, 0);
    assert.deepEqual(
      r.steps.map((s) => [s.tag, s.path, s.startLine, s.startCol, s.endCol]),
      [
        ['SOURCE', REL, 28, 27, 55],
        ['INTERMEDIATE', REL, 28, 16, 24],
        ['INTERMEDIATE', REL, 33, 18, 22],
        ['SINK', REL, 46, 43, 68],
      ],
      `endpointOnlySnippets=${endpointOnlySnippets}`,
    );
    assert(r.steps.every((s) => s.fileIdentity === 'REPOSITORY_RELATIVE'));
    // Hashes only where a snippet is proven to be the same location.
    assert.equal(r.steps[0].sha256, SHA_FS);
    assert.equal(r.steps[3].sha256, SHA_FS);
    if (endpointOnlySnippets) {
      assert.equal(r.source, 'raw_trace');
      assert.equal(r.steps[1].sha256, '');
      assert.equal(r.steps[2].sha256, '');
      assert.deepEqual(r.steps[2].evidenceSources, ['raw_trace']);
    } else {
      assert.equal(r.source, 'snippets');
      assert.deepEqual(r.steps[2].evidenceSources, ['raw_trace', 'snippets']);
    }
  }
});

test('C2: two different files with the same basename never exchange SHA-256 or merge steps', async () => {
  const fp = await loadFp();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const relA = 'module-a/src/main/java/FileServlet.java';
  const relB = 'module-b/src/main/java/FileServlet.java';
  const ev = deepFreeze({
    path: relA,
    raw_path: `${ROOT}/${relA}`,
    snapshots: {[relA]: {sha256: shaA}, [relB]: {sha256: shaB}},
    snippets: [
      {role: 'source', path: relB, raw_path: `${ROOT}/${relB}`, start: {line: 28, col: 27}, end: {line: 28, col: 55}, matched: 'request.getParameter("file")', sha256: shaB},
    ],
    raw_trace: {
      taint_source: ['CliLoc', [loc(`${ROOT}/${relA}`, 28, 27, 28, 55), 'request.getParameter("file")']],
      intermediate_vars: [{location: loc(`${ROOT}/${relA}`, 33, 18, 33, 22), content: 'file'}],
      taint_sink: ['CliLoc', [loc(`${ROOT}/${relA}`, 46, 43, 46, 68), 'new FileInputStream(file)']],
    },
  });
  const r = fp.analyzeDataflow(ev);
  const stepsA = r.steps.filter((s) => s.path === relA);
  const stepsB = r.steps.filter((s) => s.path === relB);
  assert.deepEqual(stepsA.map((s) => s.tag), ['SOURCE', 'INTERMEDIATE', 'SINK']);
  assert.deepEqual(stepsB.map((s) => s.tag), ['SOURCE']);
  assert(stepsA.every((s) => s.sha256 !== shaB), 'hash of module-b must never be attached to module-a steps');
  assert.equal(stepsB[0].sha256, shaB);
  assert.equal(r.source, 'merged');

  // A snippet whose hash contradicts the snapshot of its own file loses the hash (flagged, not guessed).
  const conflict = fp.analyzeDataflow(deepFreeze({
    snapshots: {[relA]: {sha256: shaA}},
    snippets: [{role: 'source', path: relA, start: {line: 28, col: 1}, end: {line: 28, col: 5}, matched: 'x', sha256: shaB}],
  }));
  assert.equal(conflict.steps[0].sha256, '');
  assert.equal(conflict.steps[0].shaConflict, true);
});

test('C3: paths that only share a suffix are not the same file without a proven source root', async () => {
  const fp = await loadFp();
  const shaA = 'c'.repeat(64);
  // Codex counterexample: snippet declares raw_path in workspace-A; raw trace lives in workspace-B.
  const codex = fp.analyzeDataflow(deepFreeze({
    snippets: [{role: 'source', path: 'src/FileServlet.java', raw_path: 'C:/workspace-A/src/FileServlet.java', start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaA}],
    raw_trace: {
      taint_source: ['CliLoc', [loc('C:/workspace-B/src/FileServlet.java', 28, 5, 28, 30), 'request.getParameter("file")']],
      intermediate_vars: [{location: loc('C:/workspace-B/src/FileServlet.java', 33, 5, 33, 9), content: 'file'}],
      taint_sink: ['CliLoc', [loc('C:/workspace-B/src/FileServlet.java', 46, 5, 46, 30), 'new FileInputStream(file)']],
    },
  }));
  const wsB = codex.steps.filter((s) => s.path === 'C:/workspace-B/src/FileServlet.java');
  assert.deepEqual(wsB.map((s) => s.tag), ['SOURCE', 'INTERMEDIATE', 'SINK']);
  assert(wsB.every((s) => s.sha256 === '' && s.fileIdentity === 'UNMAPPED_RAW_PATH'));
  const wsA = codex.steps.filter((s) => s.path === 'src/FileServlet.java');
  assert.equal(wsA.length, 1);
  assert.equal(wsA[0].sha256, shaA);

  // Relative suffix: 'other/src/FileServlet.java' is not 'src/FileServlet.java'.
  const rel = fp.analyzeDataflow(deepFreeze({
    snippets: [{role: 'sink', path: 'src/FileServlet.java', start: {line: 46}, end: {line: 46}, matched: 'new File(p)', sha256: shaA}],
    raw_trace: {taint_sink: ['CliLoc', [{path: 'other/src/FileServlet.java', start: {line: 46}, end: {line: 46}}, 'new File(p)']]},
  }));
  assert.equal(rel.steps.length, 2);
  assert.equal(rel.steps.find((s) => s.path === 'other/src/FileServlet.java').sha256, '');

  // Conflicting root declarations -> no root translation at all.
  const conflictingRoots = fp.analyzeDataflow(deepFreeze({
    path: 'src/A.java', raw_path: '/root-1/src/A.java',
    snippets: [{role: 'source', path: 'src/B.java', raw_path: '/root-2/src/B.java', start: {line: 1}, end: {line: 1}, matched: 'a'}],
    raw_trace: {taint_sink: ['CliLoc', [{path: '/root-1/src/C.java', start: {line: 9}, end: {line: 9}}, 'sink()']]},
  }));
  assert.equal(conflictingRoots.steps.find((s) => s.tag === 'SINK').path, '/root-1/src/C.java');
  assert.equal(conflictingRoots.steps.find((s) => s.tag === 'SINK').fileIdentity, 'UNMAPPED_RAW_PATH');
});

test('C4: two Intermediates on the same line with different columns are both kept; column-less evidence is never merged ambiguously', async () => {
  const fp = await loadFp();
  const twoCols = {
    taint_source: ['CliLoc', [loc('src/A.java', 28, 5, 28, 20), 'req.getParameter("x")']],
    intermediate_vars: [
      {location: loc('src/A.java', 33, 10, 33, 20), content: 'id'},
      {location: loc('src/A.java', 33, 30, 33, 40), content: 'id'},
    ],
    taint_sink: ['CliLoc', [loc('src/A.java', 46, 5, 46, 30), 'st.executeQuery(id)']],
  };
  const r = fp.analyzeDataflow(deepFreeze({snippets: [], raw_trace: twoCols}));
  assert.deepEqual(
    r.steps.filter((s) => s.tag === 'INTERMEDIATE').map((s) => [s.startLine, s.startCol, s.endCol]),
    [[33, 10, 20], [33, 30, 40]],
  );

  // Snippet with the same code but WITHOUT columns matches two raw candidates -> ambiguous, not merged.
  const sha = 'd'.repeat(64);
  const amb = fp.analyzeDataflow(deepFreeze({
    snippets: [{role: 'intermediate', path: 'src/A.java', start: {line: 33}, end: {line: 33}, matched: 'id', sha256: sha}],
    raw_trace: twoCols,
  }));
  const inter = amb.steps.filter((s) => s.tag === 'INTERMEDIATE');
  assert.equal(inter.length, 3, 'both raw locations kept and the unresolved snippet kept separately');
  assert(amb.ambiguousStepCount >= 3);
  assert(inter.filter((s) => s.startCol !== null).every((s) => s.sha256 === ''), 'no hash transferred to an arbitrary candidate');

  // Snippet with explicit columns matches exactly one of the two.
  const exact = fp.analyzeDataflow(deepFreeze({
    snippets: [{role: 'intermediate', path: 'src/A.java', start: {line: 33, col: 30}, end: {line: 33, col: 40}, matched: 'id', sha256: sha}],
    raw_trace: twoCols,
  }));
  const ex = exact.steps.filter((s) => s.tag === 'INTERMEDIATE');
  assert.equal(ex.length, 2);
  assert.equal(ex.find((s) => s.startCol === 30).sha256, sha);
  assert.equal(ex.find((s) => s.startCol === 10).sha256, '');
});

test('C5: a genuinely identical step in snippets and raw_trace is kept once', async () => {
  const fp = await loadFp();
  const r = fp.analyzeDataflow(deepFreeze({
    snippets: [{role: 'sink', path: 'src/A.java', raw_path: 'src/A.java', start: {line: 46, col: 5}, end: {line: 46, col: 30}, matched: 'st.executeQuery(id)', sha256: 'e'.repeat(64)}],
    raw_trace: {
      taint_sink: ['CliLoc', [loc('src/A.java', 46, 5, 46, 30), 'st.executeQuery(id)']],
      intermediate_vars: [
        {location: loc('src/A.java', 40, 1, 40, 3), content: 'id'},
        {location: loc('src/A.java', 40, 1, 40, 3), content: 'id'},
      ],
    },
  }));
  assert.deepEqual(r.steps.map((s) => [s.tag, s.startLine]), [['INTERMEDIATE', 40], ['SINK', 46]]);
  assert.deepEqual(r.steps[1].evidenceSources, ['raw_trace', 'snippets']);
  assert.equal(r.steps[1].sha256, 'e'.repeat(64));
  assert.equal(r.completeness, 'PARTIAL');
});

test('C6: a genuine direct Source → Sink flow stays COMPLETE without a fabricated Intermediate', async () => {
  const fp = await loadFp();
  const r = fp.analyzeDataflow(deepFreeze({
    snippets: [
      {role: 'source', path: 'src/A.java', start: {line: 10, col: 3}, end: {line: 10, col: 20}, matched: 'req.getParameter("id")'},
      {role: 'sink', path: 'src/A.java', start: {line: 11, col: 3}, end: {line: 11, col: 40}, matched: 'st.executeQuery(req.getParameter("id"))'},
    ],
    raw_trace: {
      taint_source: ['CliLoc', [loc('src/A.java', 10, 3, 10, 20), 'req.getParameter("id")']],
      intermediate_vars: [],
      taint_sink: ['CliLoc', [loc('src/A.java', 11, 3, 11, 40), 'st.executeQuery(req.getParameter("id"))']],
    },
  }));
  assert.equal(r.completeness, 'COMPLETE');
  assert.equal(r.hasIntermediate, false);
  assert.deepEqual(r.steps.map((s) => s.tag), ['SOURCE', 'SINK']);
});

test('C7: missing/invalid locations, empty traces and mismatched snapshots never yield verified hashes or steps', async () => {
  const fp = await loadFp();
  const bad = fp.analyzeDataflow(deepFreeze({
    snippets: [
      {role: 'source', start: {line: 1}, end: {line: 1}, matched: 'no path', sha256: 'f'.repeat(64)},
      {role: 'source', path: 'src/A.java', start: {line: 0}, end: {line: 0}, sha256: 'f'.repeat(64)},
      {role: 'source', path: 'src/A.java', start: {line: 5, col: 0}, end: {line: 5, col: 4}},
      {role: 'source', path: 'src/A.java', start: {line: 5, col: -2}, end: {line: 5, col: 4}},
      {role: 'sink', path: 'src/A.java', start: {line: 5, col: 9}, end: {line: 5, col: 4}},
      {role: 'sink', path: 'src/A.java', start: {line: 5.5}, end: {line: 6}},
    ],
    raw_trace: {taint_source: ['CliLoc', [{path: 'src/A.java', start: {line: 3, col: 0}}, 'x']], intermediate_vars: 'oops', taint_sink: ['CliLoc', []]},
  }));
  assert.deepEqual(bad.steps, []);
  assert.equal(bad.completeness, 'NONE');
  assert.equal(bad.hadInvalidInput, true);

  const empty = fp.analyzeDataflow(deepFreeze({snippets: [], raw_trace: {}}));
  assert.deepEqual(empty.steps, []);
  assert.equal(empty.completeness, 'NONE');

  const mismatch = fp.analyzeDataflow(deepFreeze({
    snapshots: {'src/A.java': {sha256: '1'.repeat(64)}},
    snippets: [{role: 'source', path: 'src/A.java', start: {line: 2, col: 1}, end: {line: 2, col: 9}, matched: 'src', sha256: '2'.repeat(64)}],
  }));
  assert.equal(mismatch.steps[0].sha256, '');
  assert.equal(mismatch.steps[0].shaConflict, true);
  assert.equal(mismatch.completeness, 'PARTIAL');
});

test('C8: analyzers never mutate deep-frozen evidence and return fresh presentation objects', async () => {
  const fp = await loadFp();
  const ev = deepFreeze(fileServletEvidence({endpointOnlySnippets: true}));
  const snapshot = JSON.stringify(ev);
  const r1 = fp.analyzeDataflow(ev);
  const r2 = fp.extractDataflowSteps(ev);
  assert.equal(JSON.stringify(ev), snapshot);
  assert.deepEqual(r1.steps, r2);
  assert.notEqual(r1.steps[0], r2[0]);
  r1.steps[0].path = 'mutated-by-consumer';
  assert.equal(fp.analyzeDataflow(ev).steps[0].path, REL);
});

// ------------------------------------------------------------------------------------------------
// C9–C16 — Grounded File Identity across multiple roots, path mappings, and hash conflict honesty
// ------------------------------------------------------------------------------------------------

test('C9: two different absolute source roots sharing the same relative path stay separate with their own SHA-256', async () => {
  const fp = await loadFp();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const absA = 'C:/workspace-A/src/main/java/FileServlet.java';
  const absB = 'C:/workspace-B/src/main/java/FileServlet.java';

  // Codex counterexample: two snippets with identical relative path, role, line, col, code, but distinct roots & hashes.
  const ev = deepFreeze({
    snippets: [
      {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaA},
      {role: 'source', path: REL, raw_path: absB, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaB},
    ],
    raw_trace: {
      taint_source: ['CliLoc', [loc(absA, 28, 5, 28, 30), 'request.getParameter("file")']],
      intermediate_vars: [{location: loc(absA, 33, 5, 33, 9), content: 'file'}],
      taint_sink: ['CliLoc', [loc(absA, 46, 5, 46, 30), 'new FileInputStream(file)']],
    },
  });

  const r = fp.analyzeDataflow(ev);
  const sources = r.steps.filter((s) => s.tag === 'SOURCE');
  assert.equal(sources.length, 2, 'C9: steps from workspace-A and workspace-B must never collapse');
  const srcA = sources.find((s) => s.path === absA);
  const srcB = sources.find((s) => s.path === absB);
  assert(srcA && srcB, 'both roots must keep their distinct absolute paths');
  assert.notEqual(srcA.fileIdentityKey, srcB.fileIdentityKey);
  assert.equal(srcA.root, 'C:/workspace-A');
  assert.equal(srcB.root, 'C:/workspace-B');
  assert.equal(srcA.sha256, shaA);
  assert.equal(srcB.sha256, shaB);
  assert.equal(srcA.fileIdentity, 'SCOPED_ABSOLUTE_ROOT');
  assert.equal(srcB.fileIdentity, 'SCOPED_ABSOLUTE_ROOT');
  assert.deepEqual(srcA.evidenceSources, ['raw_trace', 'snippets'], 'raw_trace at workspace-A pairs only with workspace-A snippet');
  assert.deepEqual(srcB.evidenceSources, ['snippets'], 'workspace-B snippet stays untouched and separate');

  // Explicit `root` metadata on snippets without `raw_path` also preserves separate File Identities.
  const viaRoot = fp.analyzeDataflow(deepFreeze({
    snippets: [
      {role: 'source', root: 'C:/workspace-A', path: REL, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaA},
      {role: 'source', root: 'C:/workspace-B', path: REL, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaB},
    ],
  }));
  assert.equal(viaRoot.steps.length, 2);
  assert.notEqual(viaRoot.steps[0].fileIdentityKey, viaRoot.steps[1].fileIdentityKey);
});

test('C10: two different roots with identical role, relative path, line, column, code, AND identical SHA-256 are still NOT deduplicated', async () => {
  const fp = await loadFp();
  const sameHash = '9'.repeat(64);
  const ev = deepFreeze({
    snippets: [
      {role: 'intermediate', path: REL, raw_path: 'C:/workspace-A/src/main/java/FileServlet.java', start: {line: 33, col: 18}, end: {line: 33, col: 22}, matched: 'file', sha256: sameHash},
      {role: 'intermediate', path: REL, raw_path: 'C:/workspace-B/src/main/java/FileServlet.java', start: {line: 33, col: 18}, end: {line: 33, col: 22}, matched: 'file', sha256: sameHash},
    ],
    raw_trace: null,
  });
  const r = fp.analyzeDataflow(ev);
  assert.equal(r.steps.length, 2, 'C10: identical content hash across two different roots must never be treated as the same file');
  assert.deepEqual(
    r.steps.map((s) => s.path),
    ['C:/workspace-A/src/main/java/FileServlet.java', 'C:/workspace-B/src/main/java/FileServlet.java'],
  );
  assert.equal(r.steps[0].sha256, sameHash);
  assert.equal(r.steps[1].sha256, sameHash);
});

test('C11: trustworthy backend root + path_mappings allow merging matching absolute/relative steps, while conflicting mappings are rejected', async () => {
  const fp = await loadFp();
  const sha = '1'.repeat(64);
  const mappedEv = deepFreeze({
    root: 'C:\\work\\repo',
    path_mappings: [{from: '/mnt/c/work/repo', to: 'C:\\work\\repo'}],
    path: REL,
    raw_path: 'C:/work/repo/src/main/java/FileServlet.java',
    snapshots: {[REL]: {sha256: sha}},
    snippets: [
      {role: 'source', path: REL, raw_path: 'C:/work/repo/src/main/java/FileServlet.java', start: {line: 28, col: 27}, end: {line: 28, col: 55}, matched: 'request.getParameter("file")', sha256: sha},
      {role: 'sink', path: REL, raw_path: 'C:/work/repo/src/main/java/FileServlet.java', start: {line: 46, col: 43}, end: {line: 46, col: 68}, matched: 'new FileInputStream(file)', sha256: sha},
    ],
    raw_trace: {
      taint_source: ['CliLoc', [loc('/mnt/c/work/repo/src/main/java/FileServlet.java', 28, 27, 28, 55), 'request.getParameter("file")']],
      intermediate_vars: [{location: loc('/mnt/c/work/repo/src/main/java/FileServlet.java', 33, 18, 33, 22), content: 'file'}],
      taint_sink: ['CliLoc', [loc('/mnt/c/work/repo/src/main/java/FileServlet.java', 46, 43, 46, 68), 'new FileInputStream(file)']],
    },
  });
  const r = fp.analyzeDataflow(mappedEv);
  assert.equal(r.completeness, 'COMPLETE');
  assert.equal(r.source, 'raw_trace');
  assert.deepEqual(r.steps.map((s) => [s.tag, s.path, s.startLine]), [
    ['SOURCE', REL, 28],
    ['INTERMEDIATE', REL, 33],
    ['SINK', REL, 46],
  ]);
  assert(r.steps.every((s) => s.fileIdentity === 'REPOSITORY_RELATIVE'));
  assert.equal(r.steps[0].sha256, sha);
  assert.equal(r.steps[1].sha256, '');
  assert.equal(r.steps[2].sha256, sha);

  // Conflicting path_mappings for the same `from` prefix must NOT be applied.
  const badMap = fp.analyzeDataflow(deepFreeze({
    root: 'C:/work/repo',
    path_mappings: [
      {from: '/mnt/shared', to: 'C:/work/repo'},
      {from: '/mnt/shared', to: 'C:/other/repo'},
    ],
    snippets: [{role: 'source', path: REL, raw_path: 'C:/work/repo/src/main/java/FileServlet.java', start: {line: 28, col: 1}, end: {line: 28, col: 10}, matched: 'src', sha256: sha}],
    raw_trace: {taint_source: ['CliLoc', [loc('/mnt/shared/src/main/java/FileServlet.java', 28, 1, 28, 10), 'src']]},
  }));
  assert.equal(badMap.steps.length, 2, 'conflicting mapping must not merge paths');
  assert.equal(badMap.steps.find((s) => s.path.startsWith('/mnt/shared')).fileIdentity, 'UNMAPPED_RAW_PATH');
  assert.equal(badMap.steps.find((s) => s.path.startsWith('/mnt/shared')).sha256, '');
});

test('C12: unknown root / unscoped relative path in multi-root bundle never guesses by suffix or basename and never transfers hash', async () => {
  const fp = await loadFp();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  // Multi-root bundle with an unscoped bare relative raw_trace step: cannot guess whether it belongs to A or B.
  const multiWithBareRel = fp.analyzeDataflow(deepFreeze({
    snippets: [
      {role: 'source', path: REL, raw_path: 'C:/workspace-A/src/main/java/FileServlet.java', start: {line: 28, col: 5}, end: {line: 28, col: 20}, matched: 'src', sha256: shaA},
      {role: 'sink', path: REL, raw_path: 'C:/workspace-B/src/main/java/FileServlet.java', start: {line: 46, col: 5}, end: {line: 46, col: 20}, matched: 'sink', sha256: shaB},
    ],
    raw_trace: {
      taint_source: ['CliLoc', [loc(REL, 28, 5, 28, 20), 'src']],
    },
  }));
  const rawBare = multiWithBareRel.steps.find((s) => s.path === REL);
  assert(rawBare, 'unscoped relative raw step kept separately');
  assert.equal(rawBare.fileIdentity, 'UNMAPPED_RAW_PATH');
  assert.equal(rawBare.sha256, '', 'must never borrow hash from workspace-A or workspace-B');
});

test('C13: conflicting SHA-256 on a PROVEN same file/span keeps 1 step with explicit shaConflict and empty sha256', async () => {
  const fp = await loadFp();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const absA = 'C:/workspace-A/src/main/java/FileServlet.java';

  // Two snippets for the EXACT same proven file + span disagreeing on SHA-256.
  const conflictEv = deepFreeze({
    root: 'C:/workspace-A',
    snippets: [
      {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaA},
      {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaB},
    ],
    raw_trace: {
      taint_source: ['CliLoc', [loc(absA, 28, 5, 28, 30), 'request.getParameter("file")']],
    },
  });
  const r = fp.analyzeDataflow(conflictEv);
  assert.equal(r.steps.length, 1, 'C13: hash conflict on proven same file/span must not fabricate an extra step');
  assert.equal(r.steps[0].sha256, '', 'conflicting hash must not silently keep A over B');
  assert.equal(r.steps[0].shaConflict, true);
  assert.deepEqual(r.steps[0].conflictingHashes, [shaA, shaB]);
});

test('C14 + C15 + C16: archive FileServlet (28/28/33/46), same-line different-column intermediates, and deep-freeze immutability all hold together', async () => {
  const fp = await loadFp();
  // C14: archive FileServlet with root + path_mappings
  const archiveLike = deepFreeze({
    ...fileServletEvidence({endpointOnlySnippets: true}),
    root: ROOT,
    path_mappings: [{from: '/mnt/c/runtime/job-x/source', to: ROOT}],
  });
  const frozenBefore = JSON.stringify(archiveLike);
  const r14 = fp.analyzeDataflow(archiveLike);
  assert.equal(r14.completeness, 'COMPLETE');
  assert.deepEqual(
    r14.steps.map((s) => [s.tag, s.startLine, s.startCol, s.endCol]),
    [
      ['SOURCE', 28, 27, 55],
      ['INTERMEDIATE', 28, 16, 24],
      ['INTERMEDIATE', 33, 18, 22],
      ['SINK', 46, 43, 68],
    ],
  );
  // C16: deep-frozen input untouched and returned arrays are independent copies
  assert.equal(JSON.stringify(archiveLike), frozenBefore);
  r14.steps[0].evidenceSources.push('mutated');
  assert.deepEqual(fp.analyzeDataflow(archiveLike).steps[0].evidenceSources, ['raw_trace', 'snippets']);

  // C15: same-line different-column intermediates remain two distinct steps even when paired with multi-root snippets
  const r15 = fp.analyzeDataflow(deepFreeze({
    root: 'C:/workspace-A',
    snippets: [
      {role: 'intermediate', path: REL, raw_path: 'C:/workspace-A/src/main/java/FileServlet.java', start: {line: 33, col: 10}, end: {line: 33, col: 20}, matched: 'id', sha256: SHA_FS},
    ],
    raw_trace: {
      taint_source: ['CliLoc', [loc('C:/workspace-A/src/main/java/FileServlet.java', 28, 1, 28, 20), 'src']],
      intermediate_vars: [
        {location: loc('C:/workspace-A/src/main/java/FileServlet.java', 33, 10, 33, 20), content: 'id'},
        {location: loc('C:/workspace-A/src/main/java/FileServlet.java', 33, 30, 33, 40), content: 'id'},
      ],
      taint_sink: ['CliLoc', [loc('C:/workspace-A/src/main/java/FileServlet.java', 46, 1, 46, 20), 'sink']],
    },
  }));
  const mids = r15.steps.filter((s) => s.tag === 'INTERMEDIATE');
  assert.deepEqual(mids.map((s) => [s.startLine, s.startCol, s.endCol, Boolean(s.sha256)]), [
    [33, 10, 20, true],
    [33, 30, 40, false],
  ]);
});

// ------------------------------------------------------------------------------------------------
// C17–C21 — Codex FRONTEND_AUTH_ROOT_FINAL_REAUDIT three counterexamples & invariants
//   Fail 1: Finding Detail primary SHA-256 must match the finding's grounded File Identity
//   Fail 2: Different code text on same file/version must NOT hide SHA-256 conflict
//   Fail 3: Conflicting child path_mappings must block fallback to parent mapping
// ------------------------------------------------------------------------------------------------

function loadResultsRenderer() {
  const esbuild = require(path.join(APP_ROOT, 'node_modules', 'esbuild'));
  const entry = `
    import {createElement as h} from 'react';
    import {renderToStaticMarkup} from 'react-dom/server';
    import {MemoryRouter} from 'react-router-dom';
    import {FindingPrimaryHashField, SnippetViewer, DataflowTraceSection} from './src/pages/Results.jsx';
    import {resolveFindingSourceHash, analyzeDataflow} from './src/services/findingPresentation.js';
    export function renderPrimaryHash(detail) {
      const primaryHash = resolveFindingSourceHash(detail);
      return {
        primaryHash,
        html: renderToStaticMarkup(h(MemoryRouter, null, h(FindingPrimaryHashField, {primaryHash}))),
      };
    }
    export function renderSnippet(snippet, evidence) {
      return renderToStaticMarkup(h(MemoryRouter, null, h(SnippetViewer, {snippet, evidence})));
    }
    export function renderDataflow(evidence) {
      const dataflow = analyzeDataflow(evidence);
      return {
        dataflow,
        html: renderToStaticMarkup(h(MemoryRouter, null, h(DataflowTraceSection, {dataflow}))),
      };
    }
  `;
  const out = esbuild.buildSync({
    stdin: {contents: entry, resolveDir: APP_ROOT, loader: 'jsx', sourcefile: 'results-render-entry.jsx'},
    bundle: true,
    platform: 'node',
    format: 'cjs',
    jsx: 'automatic',
    loader: {'.css': 'empty'},
    write: false,
    logLevel: 'silent',
    define: {'import.meta.env': '{}', 'process.env.NODE_ENV': '"production"'},
  });
  const m = new Module('results-render-bundle', module);
  m.paths = module.paths;
  m._compile(out.outputFiles[0].text, path.join(APP_ROOT, 'results-render-bundle.cjs'));
  return m.exports;
}

test('C17 (Fail 1): multi-root finding at root-a NEVER displays root-b hash from ambiguous relative snapshot or reversed/ungrounded snippets', async () => {
  const fp = await loadFp();
  const renderer = loadResultsRenderer();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const absA = `C:/root-a/${REL}`;
  const absB = `C:/root-b/${REL}`;
  const snipA = {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaA};
  const snipB = {role: 'source', path: REL, raw_path: absB, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaB};

  // Exact Codex Fail 1 fixture: finding at root-a, snippets A & B, snapshots ONLY has unscoped relative key with SHA_B.
  const makeDetail = (snippets, snapshots) => deepFreeze({
    finding_id: 'f-root-a',
    scan_id: 'scan-multi',
    file_path: REL,
    evidence: {path: REL, raw_path: absA, snapshots, snippets, raw_trace: null},
  });

  const forward = renderer.renderPrimaryHash(makeDetail([snipA, snipB], {[REL]: {sha256: shaB, size: 120}}));
  const reversed = renderer.renderPrimaryHash(makeDetail([snipB, snipA], {[REL]: {sha256: shaB, size: 120}}));
  for (const [label, res] of [['forward', forward], ['reversed', reversed]]) {
    assert.equal(res.primaryHash.status, 'AMBIGUOUS_SNAPSHOT', `${label}: ambiguous relative snapshot must not be picked`);
    assert.equal(res.primaryHash.sha256, '', `${label}: primary sha256 must be empty when relative snapshot is ambiguous`);
    assert.equal(res.primaryHash.verifiedAgainstSnapshot, false);
    assert(!res.html.includes('bbbbbbbb'), `${label}: root-b hash must NOT appear in Finding A primary hash DOM`);
    assert(!res.html.includes('Sao chép'), `${label}: Copy button must NOT render when primary hash is unverified`);
    assert(res.html.includes('data-hash-status="AMBIGUOUS_SNAPSHOT"'));
  }

  // Root B's independent snippet card may still render B's own declared hash with explicit provenance label & absolute path.
  const bSnippetHtml = renderer.renderSnippet(snipB, {path: REL, raw_path: absA, snapshots: {[REL]: {sha256: shaB}}, snippets: [snipA, snipB]});
  assert(bSnippetHtml.includes(absB), 'SnippetViewer must show root-b absolute path to distinguish roots');
  assert(bSnippetHtml.includes('Khai báo snippet · snapshot mơ hồ'), 'SnippetViewer must label snippet-declared hash provenance separately from citation');

  // Without ambiguous snapshot: reversing snippets [A, B] vs [B, A] yields the EXACT SAME declared hash for root-a (SHA_A).
  const noSnapFwd = fp.resolveFindingSourceHash(makeDetail([snipA, snipB], {}));
  const noSnapRev = fp.resolveFindingSourceHash(makeDetail([snipB, snipA], {}));
  assert.equal(noSnapFwd.status, 'DECLARED_BY_SNIPPET');
  assert.equal(noSnapFwd.sha256, shaA);
  assert.equal(noSnapFwd.verifiedAgainstSnapshot, false);
  assert.deepEqual(noSnapRev, noSnapFwd, 'Reversing snippet order must not change root-a primary hash');

  // Snippet missing raw_path when finding explicitly declares raw_path MUST NOT pass fallback even in single-root evidence.
  const ungroundedSnip = fp.resolveFindingSourceHash(deepFreeze({
    finding_id: 'f-ungrounded',
    file_path: REL,
    evidence: {
      path: REL,
      raw_path: absA,
      snapshots: {},
      snippets: [{role: 'finding', path: REL, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaB}],
    },
  }));
  assert.equal(ungroundedSnip.status, 'UNVERIFIED');
  assert.equal(ungroundedSnip.sha256, '', 'Snippet omitting raw_path must not supply primary hash when finding declares raw_path');

  // Finding in FileA.java (no hash) must never borrow SHA-256 from a Dataflow step in FileB.java.
  const otherFileFlow = fp.resolveFindingSourceHash(deepFreeze({
    finding_id: 'f-other',
    file_path: 'src/main/java/FileA.java',
    evidence: {
      path: 'src/main/java/FileA.java',
      raw_path: 'C:/root-a/src/main/java/FileA.java',
      snapshots: {},
      snippets: [{role: 'source', path: 'src/main/java/FileB.java', raw_path: 'C:/root-a/src/main/java/FileB.java', start: {line: 10}, end: {line: 10}, matched: 'x', sha256: shaB}],
    },
  }));
  assert.equal(otherFileFlow.status, 'UNVERIFIED');
  assert.equal(otherFileFlow.sha256, '');
});

test('C18 (Fail 1 positive & conflict): unique root-a snapshot displays SHA_A; single-root archive works; conflict on root-a displays conflict without verified hash', async () => {
  const renderer = loadResultsRenderer();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const absA = `C:/root-a/${REL}`;
  const absB = `C:/root-b/${REL}`;

  // Unique absolute snapshot for root-a in multi-root bundle (even when snippets are ordered [B, A])
  const uniqueSnap = renderer.renderPrimaryHash(deepFreeze({
    finding_id: 'f-uniq',
    file_path: REL,
    evidence: {
      path: REL,
      raw_path: absA,
      snapshots: {[absA]: {sha256: shaA, size: 120}, [absB]: {sha256: shaB, size: 140}},
      snippets: [
        {role: 'source', path: REL, raw_path: absB, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaB},
        {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaA},
      ],
    },
  }));
  assert.equal(uniqueSnap.primaryHash.status, 'SNAPSHOT_MATCHED');
  assert.equal(uniqueSnap.primaryHash.sha256, shaA);
  assert.equal(uniqueSnap.primaryHash.verifiedAgainstSnapshot, true);
  assert(uniqueSnap.html.includes(shaA), 'Unique root-a snapshot must display SHA_A in title');
  assert(uniqueSnap.html.includes('Sao chép'), 'Unique root-a snapshot must render Copy button');
  assert(uniqueSnap.html.includes('Khớp snapshot tệp nguồn'));

  // Single-root real FileServlet archive continues displaying SHA_FS normally
  const singleRoot = renderer.renderPrimaryHash(deepFreeze({
    finding_id: 'f-single',
    file_path: REL,
    evidence: fileServletEvidence({endpointOnlySnippets: true}),
  }));
  assert.equal(singleRoot.primaryHash.status, 'SNAPSHOT_MATCHED');
  assert.equal(singleRoot.primaryHash.sha256, SHA_FS);
  assert(singleRoot.html.includes(SHA_FS));

  // Self-conflict on root-a itself (different code text 'value' vs 'variant' with SHA_A vs SHA_B)
  const conflictEv = deepFreeze({
    root: 'C:/root-a',
    path: REL,
    raw_path: absA,
    snapshots: {},
    snippets: [
      {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 3}, end: {line: 28, col: 9}, matched: 'value', sha256: shaA},
      {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 3}, end: {line: 28, col: 9}, matched: 'variant', sha256: shaB},
    ],
  });
  const selfConflict = renderer.renderPrimaryHash(deepFreeze({finding_id: 'f-conf', file_path: REL, evidence: conflictEv}));
  assert.equal(selfConflict.primaryHash.status, 'CONFLICT');
  assert.equal(selfConflict.primaryHash.sha256, '');
  assert.deepEqual(selfConflict.primaryHash.conflictingHashes, [shaA, shaB]);
  assert(selfConflict.html.includes('Xung đột SHA-256'));
  assert(!selfConflict.html.includes('Sao chép'), 'Conflicting primary hash must never render a Copy button as verified');

  const conflictSnippetHtml = renderer.renderSnippet(conflictEv.snippets[0], conflictEv);
  assert(conflictSnippetHtml.includes('Xung đột SHA-256'));
  assert(!conflictSnippetHtml.includes('Sao chép'), 'Conflicting snippet must not render a single verified hash Copy button');

  // Malformed SHA-256 is rejected as INVALID_FORMAT
  const badFmt = renderer.renderPrimaryHash(deepFreeze({
    finding_id: 'f-badfmt',
    file_path: REL,
    evidence: {path: REL, snapshots: {[REL]: {sha256: 'not-a-64-hex-hash'}}, snippets: []},
  }));
  assert.equal(badFmt.primaryHash.status, 'INVALID_FORMAT');
  assert.equal(badFmt.primaryHash.sha256, '');
  assert(!badFmt.html.includes('Sao chép'));
});

test('C19 (Fail 2): different code text on same file/version NEVER hides SHA-256 conflict (order-independent, A-B-A sticky, merge-safe)', async () => {
  const fp = await loadFp();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const absA = `C:/root-a/${REL}`;
  const sVal = {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 3}, end: {line: 28, col: 9}, matched: 'value', sha256: shaA};
  const sVar = {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 3}, end: {line: 28, col: 9}, matched: 'variant', sha256: shaB};
  const sVal2 = {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 3}, end: {line: 28, col: 9}, matched: 'value_third', sha256: shaA};

  // Forward [value/A, variant/B] & Reversed [variant/B, value/A]
  const fwd = fp.analyzeDataflow(deepFreeze({root: 'C:/root-a', path: REL, raw_path: absA, snippets: [sVal, sVar], raw_trace: null}));
  const rev = fp.analyzeDataflow(deepFreeze({root: 'C:/root-a', path: REL, raw_path: absA, snippets: [sVar, sVal], raw_trace: null}));
  for (const [name, res] of [['forward', fwd], ['reversed', rev]]) {
    assert.equal(res.steps.length, 2, `${name}: both distinct code text variants must be kept`);
    assert(res.steps.every((s) => s.shaConflict === true && s.sha256 === '' && s.hashStatus === 'CONFLICT'), `${name}: both steps must flag shaConflict and empty sha256`);
    assert(res.steps.every((s) => JSON.stringify(s.conflictingHashes) === JSON.stringify([shaA, shaB])), `${name}: conflictingHashes must preserve both sorted values`);
  }

  // Three entries [A, B, A]: third record re-asserting A must NOT clear conflict
  const aba = fp.analyzeDataflow(deepFreeze({root: 'C:/root-a', path: REL, raw_path: absA, snippets: [sVal, sVar, sVal2], raw_trace: null}));
  assert.equal(aba.steps.length, 3);
  assert(aba.steps.every((s) => s.shaConflict === true && s.sha256 === '' && JSON.stringify(s.conflictingHashes) === JSON.stringify([shaA, shaB])));

  // Downstream raw_trace merge/enrichment must NEVER restore a single hash onto any step of a conflicted file
  const withRawTrace = fp.analyzeDataflow(deepFreeze({
    root: 'C:/root-a',
    path: REL,
    raw_path: absA,
    snippets: [sVal, sVar],
    raw_trace: {
      taint_source: ['CliLoc', [loc(absA, 28, 3, 28, 9), 'value']],
      intermediate_vars: [{location: loc(absA, 33, 5, 33, 10), content: 'mid'}],
      taint_sink: ['CliLoc', [loc(absA, 46, 5, 46, 20), 'sink(mid)']],
    },
  }));
  assert(withRawTrace.steps.every((s) => s.sha256 === '' && s.shaConflict === true), 'Merge/enrichment must never restore a hash onto a conflicted file');

  // Conflict between role='finding' snippet and role='source' snippet on same file/version is also caught
  const findingVsSource = fp.analyzeDataflow(deepFreeze({
    root: 'C:/root-a',
    path: REL,
    raw_path: absA,
    snippets: [
      {role: 'finding', path: REL, raw_path: absA, start: {line: 46, col: 5}, end: {line: 46, col: 20}, matched: 'sink()', sha256: shaB},
      sVal,
    ],
  }));
  assert.equal(findingVsSource.steps.length, 1);
  assert.equal(findingVsSource.steps[0].shaConflict, true);
  assert.equal(findingVsSource.steps[0].sha256, '');
  assert.deepEqual(findingVsSource.steps[0].conflictingHashes, [shaA, shaB]);
});

test('C20 (Fail 2 boundaries): different roots/files/versions/hash-scopes never false-conflict; missing/malformed hashes never verify', async () => {
  const fp = await loadFp();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const absA = `C:/root-a/${REL}`;
  const absB = `C:/root-b/${REL}`;

  // Two different roots sharing relative path -> NOT a conflict
  const multiRoot = fp.analyzeDataflow(deepFreeze({
    snippets: [
      {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 3}, end: {line: 28, col: 9}, matched: 'value', sha256: shaA},
      {role: 'source', path: REL, raw_path: absB, start: {line: 28, col: 3}, end: {line: 28, col: 9}, matched: 'variant', sha256: shaB},
    ],
  }));
  assert.equal(multiRoot.steps.length, 2);
  assert(multiRoot.steps.every((s) => s.shaConflict === false));
  assert.equal(multiRoot.steps.find((s) => s.path === absA).sha256, shaA);
  assert.equal(multiRoot.steps.find((s) => s.path === absB).sha256, shaB);

  // Two different files sharing the SAME hash -> NOT merged
  const sameHashTwoFiles = fp.analyzeDataflow(deepFreeze({
    snippets: [
      {role: 'source', path: 'src/FileA.java', start: {line: 10, col: 1}, end: {line: 10, col: 8}, matched: 'x', sha256: shaA},
      {role: 'source', path: 'src/FileB.java', start: {line: 10, col: 1}, end: {line: 10, col: 8}, matched: 'x', sha256: shaA},
    ],
  }));
  assert.equal(sameHashTwoFiles.steps.length, 2);
  assert.notEqual(sameHashTwoFiles.steps[0].fileIdentityKey, sameHashTwoFiles.steps[1].fileIdentityKey);

  // Different source versions of the same file -> NOT a conflict
  const diffVersion = fp.analyzeDataflow(deepFreeze({
    root: 'C:/root-a',
    snippets: [
      {role: 'source', path: REL, raw_path: absA, source_version: 'rev-1', start: {line: 28, col: 3}, end: {line: 28, col: 9}, matched: 'value', sha256: shaA},
      {role: 'source', path: REL, raw_path: absA, source_version: 'rev-2', start: {line: 28, col: 3}, end: {line: 28, col: 9}, matched: 'variant', sha256: shaB},
    ],
  }));
  assert.equal(diffVersion.steps.length, 2);
  assert(diffVersion.steps.every((s) => s.shaConflict === false));

  // Different hash scopes ('file' vs 'snippet') -> NOT a false conflict, and 'snippet' hash never becomes full-file primary hash
  const diffScopeEv = deepFreeze({
    root: 'C:/root-a',
    path: REL,
    raw_path: absA,
    snapshots: {[REL]: {sha256: shaA}},
    snippets: [
      {role: 'source', path: REL, raw_path: absA, hash_scope: 'file', start: {line: 28, col: 3}, end: {line: 28, col: 9}, matched: 'value', sha256: shaA},
      {role: 'sink', path: REL, raw_path: absA, hash_scope: 'snippet', start: {line: 46, col: 3}, end: {line: 46, col: 9}, matched: 'sink', sha256: shaB},
    ],
  });
  const diffScopeDf = fp.analyzeDataflow(diffScopeEv);
  assert(diffScopeDf.steps.every((s) => s.shaConflict === false));
  assert.equal(diffScopeDf.steps.find((s) => s.tag === 'SOURCE').hashStatus, 'SNAPSHOT_MATCHED');
  assert.equal(diffScopeDf.steps.find((s) => s.tag === 'SINK').hashStatus, 'DECLARED_NON_FILE_SCOPE');
  const snippetOnlyFinding = fp.resolveFindingSourceHash(deepFreeze({
    finding_id: 'f-excerpt',
    file_path: REL,
    evidence: {path: REL, snapshots: {}, snippets: [{role: 'finding', path: REL, hash_scope: 'snippet', start: {line: 46}, end: {line: 46}, sha256: shaB}]},
  }));
  assert.equal(snippetOnlyFinding.sha256, '', 'Snippet-scoped hash must never be promoted to full-file finding SHA-256');

  // Missing or malformed hashes are never treated as verified
  const badHashes = fp.analyzeDataflow(deepFreeze({
    snippets: [
      {role: 'source', path: 'src/A.java', start: {line: 10, col: 1}, end: {line: 10, col: 5}, matched: 'a', sha256: ''},
      {role: 'sink', path: 'src/B.java', start: {line: 20, col: 1}, end: {line: 20, col: 5}, matched: 'b', sha256: 'not-valid-hex-1234'},
    ],
  }));
  assert.equal(badHashes.steps[0].sha256, '');
  assert.equal(badHashes.steps[0].hashStatus, 'UNVERIFIED');
  assert.equal(badHashes.steps[1].sha256, '');
  assert.equal(badHashes.steps[1].hashStatus, 'INVALID_FORMAT');
});

test('C21 (Fail 3): conflicting child path_mappings blocks parent fallback while preserving valid sibling/boundary/child mappings & order invariance', async () => {
  const fp = await loadFp();
  const renderer = loadResultsRenderer();
  const parentAndConflictingChild = [
    {from: '/mnt/shared', to: 'C:/mount'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-A'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-B'},
    {from: '/mnt/shared/valid-sub', to: 'C:/sub-checkout'},
  ];

  const runWithMappings = (pathMappings) => fp.analyzeDataflow(deepFreeze({
    root: 'C:/mount',
    path_mappings: pathMappings,
    snippets: [],
    raw_trace: {
      taint_source: ['CliLoc', [loc(`/mnt/shared/branch/${REL}`, 28, 5, 28, 30), 'inConflictChild()']],
      intermediate_vars: [
        {location: loc(`/mnt/shared/other/${REL}`, 31, 5, 31, 20), content: 'inValidParent()'},
        {location: loc(`/mnt/shared/branch-other/${REL}`, 33, 5, 33, 25), content: 'partialPrefixName()'},
        {location: loc(`/mnt/shared/valid-sub/${REL}`, 35, 5, 35, 22), content: 'inValidChild()'},
      ],
      taint_sink: ['CliLoc', [loc(`/mnt/shared/branch/${REL}`, 46, 5, 46, 30), 'sinkInConflict()']],
    },
  }));

  const fwd = runWithMappings(parentAndConflictingChild);
  const rev = runWithMappings([...parentAndConflictingChild].reverse());

  for (const [label, res] of [['forward', fwd], ['reversed', rev]]) {
    // 1) Inside conflicting child prefix: MUST stay unmapped, NOT rewritten via parent /mnt/shared -> C:/mount
    const src = res.steps.find((s) => s.code === 'inConflictChild()');
    assert.equal(src.path, `/mnt/shared/branch/${REL}`, `${label}: path inside conflicting child must keep original path`);
    assert.equal(src.fileIdentity, 'UNMAPPED_RAW_PATH');
    assert.equal(src.mappingConflict, true);
    assert.deepEqual(src.conflictingMappingTargets, ['C:/checkout-A', 'C:/checkout-B']);
    assert.equal(src.sha256, '');
    assert(!src.path.startsWith('C:/mount'), `${label}: must never fall back to parent mapping`);

    // 2) Outside conflicting child prefix: valid parent mapping still works
    const outside = res.steps.find((s) => s.code === 'inValidParent()');
    assert.equal(outside.absolutePath, `C:/mount/other/${REL}`, `${label}: sibling path outside conflicting child must still use valid parent mapping`);
    assert.equal(outside.fileIdentity, 'REPOSITORY_RELATIVE');
    assert.equal(outside.mappingConflict, false);

    // 3) Partial directory name `/mnt/shared/branch-other/...` MUST NOT match `/mnt/shared/branch` (component boundary!)
    const partial = res.steps.find((s) => s.code === 'partialPrefixName()');
    assert.equal(partial.absolutePath, `C:/mount/branch-other/${REL}`, `${label}: partial folder name must not be blocked by sibling child prefix`);
    assert.equal(partial.fileIdentity, 'REPOSITORY_RELATIVE');
    assert.equal(partial.mappingConflict, false);

    // 4) Valid more-specific child mapping overrides parent mapping cleanly
    const validChild = res.steps.find((s) => s.code === 'inValidChild()');
    assert.equal(validChild.absolutePath, `C:/sub-checkout/${REL}`, `${label}: valid more-specific child mapping must win over parent`);
    assert.equal(validChild.mappingConflict, false);
  }

  // Rendered DataflowTraceSection explicitly reports conflicting mapping without fabricating a hash
  const rendered = renderer.renderDataflow(deepFreeze({
    root: 'C:/mount',
    path_mappings: parentAndConflictingChild,
    snippets: [],
    raw_trace: {taint_source: ['CliLoc', [loc(`/mnt/shared/branch/${REL}`, 28, 5, 28, 30), 'inConflictChild()']]},
  }));
  assert(rendered.html.includes('path_mappings có nhiều thư mục đích mâu thuẫn'));
  assert(rendered.html.includes(`/mnt/shared/branch/${REL}`));
});

// ------------------------------------------------------------------------------------------------
// C22–C23 — Codex FRONTEND_SOURCE_IDENTITY_SHA_MAPPING_REAUDIT two remaining variants & matrices
//   Variant 1: Absolute path in `path` field (and contradictory path/raw_path pairs)
//   Variant 2: Parent root + relative path must evaluate path_mappings on the FULL unmapped path
// ------------------------------------------------------------------------------------------------

test('C22 (Variant 1 matrix): absolute path in `path` field, consistent/contradictory pairs, reversed order, and positive absolute snapshot', async () => {
  const fp = await loadFp();
  const renderer = loadResultsRenderer();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const absA = `C:/root-a/${REL}`;
  const absB = `C:/root-b/${REL}`;
  const relSnapB = {[REL]: {sha256: shaB, size: 120}};

  const snipANoSha = {role: 'source', path: REL, raw_path: absA, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")'};
  const snipAWithSha = {...snipANoSha, sha256: shaA};

  // All representations of root B snippet where relative snapshot for A is ambiguous:
  const bRepresentations = [
    ['B abs in path only', {role: 'source', path: absB, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaB}],
    ['B abs in raw_path + rel path', {role: 'source', path: REL, raw_path: absB, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaB}],
    ['B consistent abs in both path & raw_path', {role: 'source', path: absB, raw_path: absB, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaB}],
    ['B contradictory abs path vs raw_path', {role: 'source', path: absB, raw_path: absA, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaB}],
    ['B contradictory rel path vs abs raw_path', {role: 'source', path: 'src/main/java/Other.java', raw_path: absB, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'request.getParameter("file")', sha256: shaB}],
  ];

  for (const [label, snipB] of bRepresentations) {
    for (const [aLabel, snipA] of [['A without SHA', snipANoSha], ['A with SHA_A', snipAWithSha]]) {
      const fwdDetail = deepFreeze({
        finding_id: 'f-v1',
        scan_id: 'scan-v1',
        file_path: REL,
        evidence: {path: REL, raw_path: absA, snapshots: relSnapB, snippets: [snipA, snipB], raw_trace: null},
      });
      const revDetail = deepFreeze({
        finding_id: 'f-v1',
        scan_id: 'scan-v1',
        file_path: REL,
        evidence: {path: REL, raw_path: absA, snapshots: relSnapB, snippets: [snipB, snipA], raw_trace: null},
      });
      const fwd = renderer.renderPrimaryHash(fwdDetail);
      const rev = renderer.renderPrimaryHash(revDetail);

      assert.equal(fwd.primaryHash.status, 'AMBIGUOUS_SNAPSHOT', `${label} / ${aLabel}: must be AMBIGUOUS_SNAPSHOT (not SNAPSHOT_MATCHED or false CONFLICT)`);
      assert.equal(fwd.primaryHash.sha256, '', `${label} / ${aLabel}: must not assign SHA_B to root A`);
      assert.equal(fwd.primaryHash.verifiedAgainstSnapshot, false);
      assert.deepEqual(rev.primaryHash, fwd.primaryHash, `${label} / ${aLabel}: reversed snippet order must yield identical primary hash result`);
      assert(!fwd.html.includes('bbbbbbbb'), `${label} / ${aLabel}: root-b hash must not render in primary hash DOM`);
      assert(!fwd.html.includes('Sao chép'), `${label} / ${aLabel}: Copy button must not render when snapshot is ambiguous`);

      // When A has SHA_A, the ambiguous relative snapshot must NOT create a false SHA conflict on A's Dataflow step
      if (aLabel === 'A with SHA_A') {
        const df = fp.analyzeDataflow(fwdDetail.evidence);
        const stepA = df.steps.find((s) => s.absolutePath === absA);
        assert(stepA, `${label}: step A must exist in Dataflow`);
        assert.equal(stepA.shaConflict, false, `${label}: ambiguous relative snapshot must not trigger false conflict on A`);
        assert.equal(stepA.sha256, shaA);
      }
    }
  }

  // Contradictory snippet renders explicit path conflict label with no Copy button
  const badSnip = {role: 'source', path: absB, raw_path: absA, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaB};
  const badSnipEv = deepFreeze({path: REL, raw_path: absA, snapshots: relSnapB, snippets: [snipANoSha, badSnip]});
  const badSnipDf = fp.analyzeDataflow(badSnipEv);
  const badStep = badSnipDf.steps.find((s) => s.pathConflict === true);
  assert(badStep && badStep.sha256 === '' && badStep.hashStatus === 'PATH_CONFLICT');
  const badSnipHtml = renderer.renderSnippet(badSnip, badSnipEv);
  assert(badSnipHtml.includes('Đường dẫn mâu thuẫn'));
  assert(!badSnipHtml.includes('Sao chép'));

  // Contradictory finding-level (path vs raw_path) never picks a convenient field
  const badFinding = renderer.renderPrimaryHash(deepFreeze({
    finding_id: 'f-bad-pair',
    file_path: REL,
    evidence: {path: absB, raw_path: absA, snapshots: {[absA]: {sha256: shaA}}, snippets: []},
  }));
  assert.equal(badFinding.primaryHash.status, 'PATH_CONFLICT');
  assert.equal(badFinding.primaryHash.sha256, '');
  assert(!badFinding.html.includes('Sao chép'));

  // External absolute path in raw_trace alone also blocks binding relative snapshot to root A
  const externalTrace = fp.resolveFindingSourceHash(deepFreeze({
    finding_id: 'f-ext-trace',
    file_path: REL,
    evidence: {
      path: REL,
      raw_path: absA,
      snapshots: relSnapB,
      snippets: [snipANoSha],
      raw_trace: {taint_source: ['CliLoc', [loc(absB, 28, 5, 28, 30), 'req.getParameter("file")']]},
    },
  }));
  assert.equal(externalTrace.status, 'AMBIGUOUS_SNAPSHOT');
  assert.equal(externalTrace.sha256, '');

  // Positive control: explicit absolute snapshot for root A still succeeds as SNAPSHOT_MATCHED with SHA_A
  const posFwd = renderer.renderPrimaryHash(deepFreeze({
    finding_id: 'f-pos',
    file_path: REL,
    evidence: {
      path: REL,
      raw_path: absA,
      snapshots: {[absA]: {sha256: shaA, size: 120}},
      snippets: [snipAWithSha, bRepresentations[0][1]],
    },
  }));
  const posRev = renderer.renderPrimaryHash(deepFreeze({
    finding_id: 'f-pos',
    file_path: REL,
    evidence: {
      path: REL,
      raw_path: absA,
      snapshots: {[absA]: {sha256: shaA, size: 120}},
      snippets: [bRepresentations[0][1], snipAWithSha],
    },
  }));
  assert.equal(posFwd.primaryHash.status, 'SNAPSHOT_MATCHED');
  assert.equal(posFwd.primaryHash.sha256, shaA);
  assert.equal(posFwd.primaryHash.verifiedAgainstSnapshot, true);
  assert.deepEqual(posRev.primaryHash, posFwd.primaryHash);
  assert(posFwd.html.includes(shaA) && posFwd.html.includes('Sao chép'));
});

test('C23 (Variant 2 matrix): parent root + relative path evaluates path_mappings on FULL original path (matching full-path behavior across conflict, sibling, boundary, valid child, and reversed mappings)', async () => {
  const fp = await loadFp();
  const renderer = loadResultsRenderer();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const mappings = [
    {from: '/mnt/shared', to: 'C:/mount'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-A'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-B'},
    {from: '/mnt/shared/valid-sub', to: 'C:/sub-checkout'},
  ];

  for (const [orderLabel, mapList] of [['forward mappings', mappings], ['reversed mappings', [...mappings].reverse()]]) {
    // 1) Inside conflicting child: compare BOTH full original path AND root + relative path
    const branchRel = `branch/${REL}`;
    const branchFull = `/mnt/shared/${branchRel}`;

    const viaRootAndRel = deepFreeze({
      finding_id: 'f-v2-rel',
      file_path: branchRel,
      evidence: {
        root: '/mnt/shared',
        path: branchRel,
        path_mappings: mapList,
        snapshots: {[branchRel]: {sha256: shaB, size: 120}},
        snippets: [{role: 'source', path: branchRel, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'req.getParameter("file")', sha256: shaB}],
        raw_trace: null,
      },
    });
    const viaFullPath = deepFreeze({
      finding_id: 'f-v2-full',
      file_path: branchFull,
      evidence: {
        root: '/mnt/shared',
        path: branchFull,
        path_mappings: mapList,
        snapshots: {[branchFull]: {sha256: shaB, size: 120}},
        snippets: [{role: 'source', path: branchFull, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'req.getParameter("file")', sha256: shaB}],
        raw_trace: null,
      },
    });

    const pRel = renderer.renderPrimaryHash(viaRootAndRel);
    const pFull = renderer.renderPrimaryHash(viaFullPath);
    const dRel = renderer.renderDataflow(viaRootAndRel.evidence);
    const dFull = renderer.renderDataflow(viaFullPath.evidence);

    for (const [repLabel, pRes, dRes] of [['root+rel', pRel, dRel], ['full-path', pFull, dFull]]) {
      assert.equal(pRes.primaryHash.status, 'MAPPING_CONFLICT', `${orderLabel} / ${repLabel}: must reject conflicting child mapping`);
      assert.equal(pRes.primaryHash.sha256, '');
      assert.equal(pRes.primaryHash.verifiedAgainstSnapshot, false);
      assert.equal(pRes.primaryHash.resolvedPath, branchFull);
      assert(!pRes.html.includes('bbbbbbbb') && !pRes.html.includes('Sao chép'));
      assert.equal(dRes.dataflow.steps[0].mappingConflict, true, `${orderLabel} / ${repLabel}: Dataflow step must flag mappingConflict`);
      assert.equal(dRes.dataflow.steps[0].fileIdentity, 'UNMAPPED_RAW_PATH');
      assert.equal(dRes.dataflow.steps[0].path, branchFull);
      assert.equal(dRes.dataflow.steps[0].sha256, '');
      assert(dRes.html.includes('path_mappings có nhiều thư mục đích mâu thuẫn'));
    }
    // Exact identity equivalence between full path and root+rel
    assert.equal(pRel.primaryHash.fileIdentityKey, pFull.primaryHash.fileIdentityKey);
    assert.equal(dRel.dataflow.steps[0].fileIdentityKey, dFull.dataflow.steps[0].fileIdentityKey);

    // Snippet-level `root: '/mnt/shared'` without evidence.root also catches the conflicting child
    const snipRootOnly = fp.resolveFindingSourceHash(deepFreeze({
      finding_id: 'f-snip-root',
      file_path: branchRel,
      evidence: {
        path: branchRel,
        path_mappings: mapList,
        snapshots: {[branchRel]: {sha256: shaB, size: 120}},
        snippets: [{role: 'source', root: '/mnt/shared', path: branchRel, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaB}],
      },
    }));
    assert.equal(snipRootOnly.status, 'MAPPING_CONFLICT');
    assert.equal(snipRootOnly.sha256, '');

    // 2) Outside conflicting child (sibling `other/...`): valid parent mapping works cleanly with SNAPSHOT_MATCHED
    const sibRel = `other/${REL}`;
    const sibRes = renderer.renderPrimaryHash(deepFreeze({
      finding_id: 'f-sib',
      file_path: sibRel,
      evidence: {
        root: '/mnt/shared',
        path: sibRel,
        path_mappings: mapList,
        snapshots: {[sibRel]: {sha256: shaA, size: 120}},
        snippets: [{role: 'source', path: sibRel, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaA}],
      },
    }));
    assert.equal(sibRes.primaryHash.status, 'SNAPSHOT_MATCHED', `${orderLabel}: sibling path outside conflict must still verify`);
    assert.equal(sibRes.primaryHash.sha256, shaA);
    assert(sibRes.html.includes(shaA) && sibRes.html.includes('Sao chép'));

    // 3) Partial directory prefix (`branch-other/...`): NOT blocked by `/mnt/shared/branch` (component boundary)
    const partialRel = `branch-other/${REL}`;
    const partialDf = fp.analyzeDataflow(deepFreeze({
      root: '/mnt/shared',
      path: partialRel,
      path_mappings: mapList,
      snippets: [{role: 'source', path: partialRel, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaA}],
    }));
    assert.equal(partialDf.steps[0].mappingConflict, false, `${orderLabel}: partial folder name must not collide with child prefix`);
    assert.equal(partialDf.steps[0].absolutePath, `C:/mount/${partialRel}`);
    assert.equal(partialDf.steps[0].fileIdentity, 'REPOSITORY_RELATIVE');

    // 4) Valid more-specific child mapping (`/mnt/shared/valid-sub -> C:/sub-checkout`):
    //    root+rel AND full-path resolve identically and pair cleanly!
    const validChildRel = `valid-sub/${REL}`;
    const validChildFull = `/mnt/shared/${validChildRel}`;
    const childDf = fp.analyzeDataflow(deepFreeze({
      root: '/mnt/shared',
      path: validChildRel,
      path_mappings: mapList,
      snapshots: {[validChildRel]: {sha256: shaA, size: 120}},
      snippets: [{role: 'source', path: validChildRel, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaA}],
      raw_trace: {taint_source: ['CliLoc', [loc(validChildFull, 28, 5, 28, 30), 'x']]},
    }));
    assert.equal(childDf.steps.length, 1, `${orderLabel}: root+rel snippet and full-path raw_trace under valid child mapping must pair into 1 step`);
    assert.equal(childDf.steps[0].mappingConflict, false);
    assert.equal(childDf.steps[0].absolutePath, `C:/sub-checkout/${REL}`);
    assert.equal(childDf.steps[0].sha256, shaA);
    assert.equal(childDf.steps[0].hashStatus, 'SNAPSHOT_MATCHED');
  }
});

// ------------------------------------------------------------------------------------------------
// C24 — Codex FRONTEND_PATH_INPUT_MAPPING_VARIANTS_REAUDIT P2 blocker:
//   Adding `raw_path` (parent-mapped OR pointing to one conflicting child target) + snapshot at
//   `raw_path` MUST NEVER override a mapping conflict detected from `root + path`.
// ------------------------------------------------------------------------------------------------

test('C24 (Round 7 P2 blocker matrix): raw_path + snapshot at raw_path NEVER overrides root+path mapping conflict; positive controls stay SNAPSHOT_MATCHED', async () => {
  const fp = await loadFp();
  const renderer = loadResultsRenderer();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const branchRel = `branch/${REL}`;
  const branchSourceFull = `/mnt/shared/${branchRel}`;
  const rawParentMapped = `C:/mount/${branchRel}`;
  const rawChildTargetASub = `C:/checkout-A/${branchRel}`;
  const rawChildTargetAShort = `C:/checkout-A/${REL}`;
  const siblingRel = `other/${REL}`;
  const rawSibling = `C:/mount/${siblingRel}`;
  const validChildRel = `valid-sub/${REL}`;
  const rawValidChild = `C:/sub-checkout/${REL}`;

  const mappings = [
    {from: '/mnt/shared', to: 'C:/mount'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-A'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-B'},
    {from: '/mnt/shared/valid-sub', to: 'C:/sub-checkout'},
  ];

  for (const [orderLabel, mapList] of [['forward mappings', mappings], ['reversed mappings', [...mappings].reverse()]]) {
    const snipParent = {role: 'source', path: branchRel, raw_path: rawParentMapped, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'req.getParameter("file")', sha256: shaB};
    const snipUnrelated = {role: 'intermediate', path: siblingRel, raw_path: rawSibling, start: {line: 33, col: 5}, end: {line: 33, col: 15}, matched: 'mid', sha256: shaA};

    // Matrix rows 1–5 (all MUST block SNAPSHOT_MATCHED, return empty sha256, render no Copy button)
    const conflictCases = [
      [
        'Row 1: root + path conflict, no raw_path',
        {root: '/mnt/shared', path: branchRel, path_mappings: mapList, snapshots: {[branchRel]: {sha256: shaB}}, snippets: [{role: 'source', path: branchRel, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaB}]},
      ],
      [
        'Row 2: root + path conflict + parent-mapped raw_path, NO snapshot',
        {root: '/mnt/shared', path: branchRel, raw_path: rawParentMapped, path_mappings: mapList, snapshots: {}, snippets: [snipParent]},
      ],
      [
        'Row 3 (Codex exact P2 blocker): root + path conflict + parent-mapped raw_path + snapshot at raw_path',
        {root: '/mnt/shared', path: branchRel, raw_path: rawParentMapped, path_mappings: mapList, snapshots: {[rawParentMapped]: {sha256: shaB, size: 120}}, snippets: [snipParent]},
      ],
      [
        'Row 4: reversed snippet order with sibling + conflicting parent-mapped raw_path + snapshot',
        {root: '/mnt/shared', path: branchRel, raw_path: rawParentMapped, path_mappings: mapList, snapshots: {[rawParentMapped]: {sha256: shaB, size: 120}}, snippets: [snipUnrelated, snipParent]},
      ],
      [
        'Row 5a: raw_path pointing to one conflicting child target (C:/checkout-A/branch/...) + snapshot',
        {root: '/mnt/shared', path: branchRel, raw_path: rawChildTargetASub, path_mappings: mapList, snapshots: {[rawChildTargetASub]: {sha256: shaB, size: 120}}, snippets: [{role: 'source', path: branchRel, raw_path: rawChildTargetASub, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaB}]},
      ],
      [
        'Row 5b: raw_path pointing to one conflicting child target (C:/checkout-A/src/...) + snapshot',
        {root: '/mnt/shared', path: branchRel, raw_path: rawChildTargetAShort, path_mappings: mapList, snapshots: {[rawChildTargetAShort]: {sha256: shaB, size: 120}}, snippets: [{role: 'source', path: branchRel, raw_path: rawChildTargetAShort, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaB}]},
      ],
    ];

    for (const [caseLabel, ev] of conflictCases) {
      const detail = deepFreeze({finding_id: 'f-r7', file_path: branchRel, evidence: ev});
      const rendered = renderer.renderPrimaryHash(detail);
      assert.equal(rendered.primaryHash.status, 'MAPPING_CONFLICT', `${orderLabel} / ${caseLabel}: must stay MAPPING_CONFLICT`);
      assert.equal(rendered.primaryHash.sha256, '', `${orderLabel} / ${caseLabel}: sha256 must be empty`);
      assert.equal(rendered.primaryHash.verifiedAgainstSnapshot, false);
      assert.equal(rendered.primaryHash.resolvedPath, branchSourceFull);
      assert(!rendered.html.includes('bbbbbbbb'), `${orderLabel} / ${caseLabel}: must not render SHA_B in primary hash DOM`);
      assert(!rendered.html.includes('Sao chép'), `${orderLabel} / ${caseLabel}: must not render Copy button`);

      const df = fp.analyzeDataflow(detail.evidence);
      const branchStep = df.steps.find((s) => s.role === 'source');
      assert(branchStep && branchStep.mappingConflict === true && branchStep.sha256 === '', `${orderLabel} / ${caseLabel}: conflicting Dataflow step must retain mappingConflict & empty sha256`);

      const snipHtml = renderer.renderSnippet(detail.evidence.snippets.find((s) => s.role === 'source'), detail.evidence);
      assert(snipHtml.includes('Mapping mâu thuẫn') && !snipHtml.includes('Sao chép'), `${orderLabel} / ${caseLabel}: conflicting snippet card must not show verified Copy button`);
    }

    // Positive control 1: consistent root + path + raw_path OUTSIDE conflicting child (even if an unrelated snippet hits branch conflict!)
    const posSibling = renderer.renderPrimaryHash(deepFreeze({
      finding_id: 'f-pos-sib',
      file_path: siblingRel,
      evidence: {
        root: '/mnt/shared',
        path: siblingRel,
        raw_path: rawSibling,
        path_mappings: mapList,
        snapshots: {[rawSibling]: {sha256: shaA, size: 120}},
        snippets: [
          {role: 'source', path: siblingRel, raw_path: rawSibling, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaA},
          {role: 'intermediate', path: branchRel, raw_path: rawParentMapped, start: {line: 33, col: 5}, end: {line: 33, col: 15}, matched: 'unrelated', sha256: shaB},
        ],
      },
    }));
    assert.equal(posSibling.primaryHash.status, 'SNAPSHOT_MATCHED', `${orderLabel}: valid sibling must not be poisoned by unrelated branch conflict`);
    assert.equal(posSibling.primaryHash.sha256, shaA);
    assert.equal(posSibling.primaryHash.verifiedAgainstSnapshot, true);
    assert(posSibling.html.includes(shaA) && posSibling.html.includes('Sao chép'));

    // Positive control 2: consistent root + path + raw_path under VALID more-specific child mapping
    const posValidChild = renderer.renderPrimaryHash(deepFreeze({
      finding_id: 'f-pos-child',
      file_path: validChildRel,
      evidence: {
        root: '/mnt/shared',
        path: validChildRel,
        raw_path: rawValidChild,
        path_mappings: mapList,
        snapshots: {[rawValidChild]: {sha256: shaA, size: 120}},
        snippets: [{role: 'source', path: validChildRel, raw_path: rawValidChild, start: {line: 28, col: 5}, end: {line: 28, col: 30}, matched: 'x', sha256: shaA}],
      },
    }));
    assert.equal(posValidChild.primaryHash.status, 'SNAPSHOT_MATCHED', `${orderLabel}: valid child mapping with matching raw_path must verify`);
    assert.equal(posValidChild.primaryHash.sha256, shaA);
  }

  // Positive control 3: absolute raw_path ONLY with unique snapshot and no conflicting source description
  const rawOnly = renderer.renderPrimaryHash(deepFreeze({
    finding_id: 'f-raw-only',
    file_path: '',
    evidence: {
      raw_path: `C:/root-a/${REL}`,
      snapshots: {[`C:/root-a/${REL}`]: {sha256: shaA, size: 120}},
      snippets: [],
    },
  }));
  assert.equal(rawOnly.primaryHash.status, 'SNAPSHOT_MATCHED');
  assert.equal(rawOnly.primaryHash.sha256, shaA);
  assert(rawOnly.html.includes(shaA) && rawOnly.html.includes('Sao chép'));
});

// ------------------------------------------------------------------------------------------------
// C25 — Codex Round 7 Ca C P2 blocker:
//   When a finding hits a `root + relativePath` mapping conflict while also declaring an explicit
//   absolute candidate (`evidence.raw_path`, e.g. `C:/checkout-A/...`), absolute-only snippets
//   (role `finding` / `source`), snapshots, and `raw_trace` CliLoc entries matching that exact
//   disputed candidate MUST preserve `MAPPING_CONFLICT` instead of restoring verified SHA-256.
// ------------------------------------------------------------------------------------------------

test('C25 (Round 8 Ca C matrix): absolute-only snippets/raw_trace matching disputed finding raw_path keep MAPPING_CONFLICT while positive controls & A-B-A isolation stay intact', async () => {
  const fp = await loadFp();
  const renderer = loadResultsRenderer();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const branchRel = `branch/${REL}`;
  const branchFull = `/mnt/shared/${branchRel}`;
  const childAbs = `C:/checkout-A/${REL}`;
  const parentAbs = `C:/mount/${branchRel}`;
  const siblingRel = `other/${REL}`;
  const siblingAbs = `C:/mount/${siblingRel}`;
  const rootAAbs = `C:/root-a/${REL}`;
  const rootBAbs = `C:/root-b/${REL}`;
  const sameBaseOtherDir = 'C:/checkout-A/other/FileServlet.java';
  const span = {start: {line: 28, col: 3}, end: {line: 28, col: 9}};

  // Exact 4 mappings from Codex Round 7 harness
  const mappings = [
    {from: '/mnt/shared', to: 'C:/mount'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-A'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-B'},
    {from: '/mnt/shared/custom', to: 'C:/specific'},
  ];

  const makeCaseC = ({
    withSnapshot = true,
    reverseMappings = false,
    reverseSnippets = false,
    duplicateRawPath = false,
    snippetsOverride = null,
  } = {}) => {
    const baseSnips = [
      {...span, role: 'finding', path: childAbs, ...(duplicateRawPath ? {raw_path: childAbs} : {}), matched: 'value', sha256: shaB},
      {...span, role: 'source', path: childAbs, ...(duplicateRawPath ? {raw_path: childAbs} : {}), matched: 'value', sha256: shaB},
    ];
    const snips = snippetsOverride !== null ? snippetsOverride : (reverseSnippets ? [...baseSnips].reverse() : baseSnips);
    return deepFreeze({
      finding_id: 'f-case-c',
      file_path: branchRel,
      evidence: {
        root: '/mnt/shared',
        path: branchRel,
        raw_path: childAbs,
        path_mappings: reverseMappings ? [...mappings].reverse() : mappings,
        snapshots: withSnapshot ? {[childAbs]: {sha256: shaB, size: 120}} : {},
        snippets: snips,
        raw_trace: {taint_source: ['CliLoc', [loc(childAbs, 28, 3, 28, 9), 'value']]},
      },
    });
  };

  // A. Exact Ca C (with snapshot) + B. Direct variants (without snapshot, duplicate raw_path, reversed mappings/snippets)
  const caseCVariants = [
    ['A_exact_with_snapshot', makeCaseC({withSnapshot: true})],
    ['B1_without_snapshot', makeCaseC({withSnapshot: false})],
    ['B2_duplicate_path_and_raw_path', makeCaseC({withSnapshot: true, duplicateRawPath: true})],
    ['B4_reversed_mappings', makeCaseC({withSnapshot: true, reverseMappings: true})],
    ['B4_reversed_snippets', makeCaseC({withSnapshot: true, reverseSnippets: true})],
    ['B4_reversed_both', makeCaseC({withSnapshot: true, reverseMappings: true, reverseSnippets: true})],
    [
      'B5_same_finding_root_on_abs_snippet',
      makeCaseC({
        withSnapshot: true,
        snippetsOverride: [
          {...span, role: 'finding', root: '/mnt/shared', path: childAbs, matched: 'value', sha256: shaB},
          {...span, role: 'source', root: '/mnt/shared', path: childAbs, matched: 'value', sha256: shaB},
        ],
      }),
    ],
    [
      'B6_relative_only_snippet_on_disputed_branch',
      makeCaseC({
        withSnapshot: true,
        snippetsOverride: [
          {...span, role: 'finding', path: branchRel, matched: 'value', sha256: shaB},
          {...span, role: 'source', path: branchRel, matched: 'value', sha256: shaB},
        ],
      }),
    ],
  ];

  for (const [label, detail] of caseCVariants) {
    const primaryRendered = renderer.renderPrimaryHash(detail);
    assert.equal(primaryRendered.primaryHash.status, 'MAPPING_CONFLICT', `${label}: primary hash must be MAPPING_CONFLICT`);
    assert.equal(primaryRendered.primaryHash.sha256, '', `${label}: primary sha256 must be empty`);
    assert.equal(primaryRendered.primaryHash.verifiedAgainstSnapshot, false);
    assert.equal(primaryRendered.primaryHash.resolvedPath, branchFull);
    assert(!primaryRendered.html.includes('bbbbbbbb') && !primaryRendered.html.includes('Sao chép'), `${label}: primary DOM must not leak hash B or Copy button`);

    for (const snip of detail.evidence.snippets) {
      const card = fp.resolveSnippetHashStatus(snip, detail.evidence);
      assert.equal(card.status, 'MAPPING_CONFLICT', `${label} / ${snip.role}: snippet status must stay MAPPING_CONFLICT`);
      assert.equal(card.sha256, '', `${label} / ${snip.role}: snippet sha256 must be empty`);
      const snipHtml = renderer.renderSnippet(snip, detail.evidence);
      assert(snipHtml.includes('Mapping mâu thuẫn'), `${label} / ${snip.role}: snippet SSR must show Mapping mâu thuẫn`);
      assert(!snipHtml.includes('Khớp snapshot'), `${label} / ${snip.role}: snippet SSR must NOT show Khớp snapshot`);
      assert(!snipHtml.includes('bbbbbbbb') && !snipHtml.includes('Sao chép'), `${label} / ${snip.role}: snippet SSR must NOT show hash B or Copy button`);
    }

    const dfRendered = renderer.renderDataflow(detail.evidence);
    assert(dfRendered.dataflow.steps.length >= 1, `${label}: Dataflow must preserve trace steps`);
    for (const step of dfRendered.dataflow.steps) {
      assert.equal(step.mappingConflict, true, `${label}: Dataflow step must flag mappingConflict`);
      assert.equal(step.hashStatus, 'MAPPING_CONFLICT', `${label}: Dataflow step hashStatus must be MAPPING_CONFLICT`);
      assert.equal(step.sha256, '', `${label}: Dataflow step must not leak SHA_B`);
      assert.deepEqual([step.startLine, step.startCol, step.endLine, step.endCol], [28, 3, 28, 9], `${label}: Dataflow must preserve exact line/col`);
    }
    assert(dfRendered.html.includes('path_mappings có nhiều thư mục đích mâu thuẫn'), `${label}: Dataflow SSR must show mapping conflict notice`);
  }

  // B3. Raw trace absolute-only without any snippets
  const rawOnlyCaseC = makeCaseC({withSnapshot: true, snippetsOverride: []});
  assert.equal(fp.resolveFindingSourceHash(rawOnlyCaseC).status, 'MAPPING_CONFLICT');
  const rawOnlyDf = fp.analyzeDataflow(rawOnlyCaseC.evidence);
  assert.equal(rawOnlyDf.steps.length, 1);
  assert.equal(rawOnlyDf.steps[0].mappingConflict, true);
  assert.equal(rawOnlyDf.steps[0].hashStatus, 'MAPPING_CONFLICT');
  assert.equal(rawOnlyDf.steps[0].sha256, '');
  assert.deepEqual([rawOnlyDf.steps[0].startLine, rawOnlyDf.steps[0].startCol, rawOnlyDf.steps[0].endLine, rawOnlyDf.steps[0].endCol], [28, 3, 28, 9]);

  // C1. Codex positive control 1: sibling outside conflict despite unrelated conflicting snippet
  const posSibling = renderer.renderPrimaryHash(deepFreeze({
    finding_id: 'f-c25-sib',
    file_path: siblingRel,
    evidence: {
      root: '/mnt/shared',
      path: siblingRel,
      raw_path: siblingAbs,
      path_mappings: mappings,
      snapshots: {[parentAbs]: {sha256: shaB}, [siblingAbs]: {sha256: shaA}},
      snippets: [
        {...span, role: 'source', path: branchRel, raw_path: parentAbs, matched: 'value', sha256: shaB},
        {...span, role: 'finding', path: siblingRel, raw_path: siblingAbs, matched: 'value', sha256: shaA},
      ],
    },
  }));
  assert.equal(posSibling.primaryHash.status, 'SNAPSHOT_MATCHED');
  assert.equal(posSibling.primaryHash.sha256, shaA);
  assert.equal(posSibling.primaryHash.verifiedAgainstSnapshot, true);
  assert(posSibling.html.includes(shaA) && posSibling.html.includes('Sao chép'));

  // C2. Codex positive control 2: root A explicit absolute snapshot alongside root B & ambiguous relative snapshot
  const posRootA = renderer.renderPrimaryHash(deepFreeze({
    finding_id: 'f-c25-root-a',
    file_path: REL,
    evidence: {
      path: REL,
      raw_path: rootAAbs,
      snapshots: {[REL]: {sha256: shaB}, [rootAAbs]: {sha256: shaA}},
      snippets: [
        {...span, role: 'source', path: REL, raw_path: rootBAbs, matched: 'value', sha256: shaB},
        {...span, role: 'finding', path: REL, raw_path: rootAAbs, matched: 'value', sha256: shaA},
      ],
    },
  }));
  assert.equal(posRootA.primaryHash.status, 'SNAPSHOT_MATCHED');
  assert.equal(posRootA.primaryHash.sha256, shaA);
  assert.equal(posRootA.primaryHash.verifiedAgainstSnapshot, true);
  assert(posRootA.html.includes(shaA) && posRootA.html.includes('Sao chép'));

  // C3. Standalone absolute-only finding at exact `C:/checkout-A/...` (without conflicting root+path) still verifies
  const standaloneClean = deepFreeze({
    finding_id: 'f-c25-standalone',
    file_path: childAbs,
    evidence: {
      raw_path: childAbs,
      path_mappings: mappings,
      snapshots: {[childAbs]: {sha256: shaA}},
      snippets: [
        {...span, role: 'finding', path: childAbs, matched: 'value', sha256: shaA},
        {...span, role: 'source', path: childAbs, matched: 'value', sha256: shaA},
      ],
      raw_trace: {taint_source: ['CliLoc', [loc(childAbs, 28, 3, 28, 9), 'value']]},
    },
  });
  const standalonePrimary = renderer.renderPrimaryHash(standaloneClean);
  assert.equal(standalonePrimary.primaryHash.status, 'SNAPSHOT_MATCHED');
  assert.equal(standalonePrimary.primaryHash.sha256, shaA);
  assert.equal(fp.resolveSnippetHashStatus(standaloneClean.evidence.snippets[0], standaloneClean.evidence).status, 'SNAPSHOT_MATCHED');
  const standaloneDf = fp.analyzeDataflow(standaloneClean.evidence);
  assert.equal(standaloneDf.steps.length, 1);
  assert.equal(standaloneDf.steps[0].mappingConflict, false);
  assert.equal(standaloneDf.steps[0].hashStatus, 'SNAPSHOT_MATCHED');
  assert.equal(standaloneDf.steps[0].sha256, shaA);

  // C4. Other files/roots sharing basename or relative path in the same conflicting evidence are NOT poisoned
  const siblingSnip = {start: {line: 33, col: 2}, end: {line: 33, col: 5}, role: 'intermediate', path: siblingRel, raw_path: siblingAbs, matched: 'sib', sha256: shaA};
  const sameBaseSnip = {start: {line: 34, col: 2}, end: {line: 34, col: 8}, role: 'intermediate', path: sameBaseOtherDir, matched: 'sameBase', sha256: shaA};
  const sameRelOtherRootSnip = {start: {line: 40, col: 2}, end: {line: 40, col: 9}, role: 'sink', path: rootBAbs, matched: 'otherRoot', sha256: shaA};
  const mixedEv = deepFreeze({
    root: '/mnt/shared',
    path: branchRel,
    raw_path: childAbs,
    path_mappings: mappings,
    snapshots: {
      [childAbs]: {sha256: shaB},
      [siblingAbs]: {sha256: shaA},
      [sameBaseOtherDir]: {sha256: shaA},
      [rootBAbs]: {sha256: shaA},
    },
    snippets: [
      {...span, role: 'finding', path: childAbs, matched: 'value', sha256: shaB},
      siblingSnip,
      sameBaseSnip,
      sameRelOtherRootSnip,
    ],
  });
  assert.equal(fp.resolveFindingSourceHash({file_path: branchRel, evidence: mixedEv}).status, 'MAPPING_CONFLICT');
  assert.equal(fp.resolveSnippetHashStatus(mixedEv.snippets[0], mixedEv).status, 'MAPPING_CONFLICT');
  assert.deepEqual([fp.resolveSnippetHashStatus(siblingSnip, mixedEv).status, fp.resolveSnippetHashStatus(siblingSnip, mixedEv).sha256], ['SNAPSHOT_MATCHED', shaA]);
  assert.deepEqual([fp.resolveSnippetHashStatus(sameBaseSnip, mixedEv).status, fp.resolveSnippetHashStatus(sameBaseSnip, mixedEv).sha256], ['SNAPSHOT_MATCHED', shaA]);
  assert.deepEqual([fp.resolveSnippetHashStatus(sameRelOtherRootSnip, mixedEv).status, fp.resolveSnippetHashStatus(sameRelOtherRootSnip, mixedEv).sha256], ['SNAPSHOT_MATCHED', shaA]);

  // C5. A-B-A isolation: resolving conflicted finding A must NEVER leak state into clean finding B on the same path
  const conflictedA = makeCaseC({withSnapshot: true});
  assert.equal(fp.resolveFindingSourceHash(conflictedA).status, 'MAPPING_CONFLICT');
  assert.equal(fp.resolveSnippetHashStatus(conflictedA.evidence.snippets[0], conflictedA.evidence).status, 'MAPPING_CONFLICT');
  assert.equal(fp.resolveFindingSourceHash(standaloneClean).status, 'SNAPSHOT_MATCHED');
  assert.equal(fp.resolveSnippetHashStatus(standaloneClean.evidence.snippets[0], standaloneClean.evidence).status, 'SNAPSHOT_MATCHED');
  assert.equal(fp.resolveFindingSourceHash(conflictedA).status, 'MAPPING_CONFLICT');
  assert.equal(fp.resolveSnippetHashStatus(conflictedA.evidence.snippets[0], conflictedA.evidence).status, 'MAPPING_CONFLICT');
});

// ------------------------------------------------------------------------------------------------
// C26 — Round 9 Metamorphic Source Identity Canonicalization & Provenance Invariants (Groups A–E):
//   Equivalent filesystem representations (internal/repeated `.` segments, `/` vs `\`, repeated
//   slashes, drive casing, UNC roots, mapped aliases, and all conflicting target branches) MUST
//   resolve to identical canonical source identities across conflict registry, snapshot ledger,
//   finding hash, snippet cards, and Dataflow — while preserving positive controls, case-distinct
//   files, A-B-A isolation, and escalating contradictory provenance/SHA or unsafe `..` traversal.
// ------------------------------------------------------------------------------------------------

test('C26 (Round 9 metamorphic & counter-provenance invariants): canonical path equivalence across conflict registry, snapshot ledger, snippet cards & Dataflow', async () => {
  const fp = await loadFp();
  const renderer = loadResultsRenderer();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const branchRel = `branch/${REL}`;
  const branchFull = `/mnt/shared/${branchRel}`;
  const childA = `C:/checkout-A/${REL}`;
  const childB = `C:/checkout-B/${REL}`;
  const parentAbs = `C:/mount/${branchRel}`;
  const siblingRel = `other/${REL}`;
  const siblingAbs = `C:/mount/${siblingRel}`;
  const validChildRel = `custom/${REL}`;
  const validChildAbs = `C:/specific/${REL}`;
  const rootAAbs = `C:/root-a/${REL}`;
  const rootBAbs = `C:/root-b/${REL}`;
  const span = {start: {line: 28, col: 3}, end: {line: 28, col: 9}};

  const mappings = [
    {from: '/mnt/shared', to: 'C:/mount'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-A'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-B'},
    {from: '/mnt/shared/custom', to: 'C:/specific'},
  ];

  const assertFullConflictConsistency = (label, detail) => {
    const primaryRes = renderer.renderPrimaryHash(detail);
    assert.equal(primaryRes.primaryHash.status, 'MAPPING_CONFLICT', `${label}: primary status`);
    assert.equal(primaryRes.primaryHash.sha256, '', `${label}: primary sha256`);
    assert.equal(primaryRes.primaryHash.verifiedAgainstSnapshot, false);
    assert(!primaryRes.html.includes('bbbbbbbb') && !primaryRes.html.includes('Sao chép'), `${label}: primary SSR must have no hash B or Copy`);

    for (const snip of detail.evidence.snippets) {
      const card = fp.resolveSnippetHashStatus(snip, detail.evidence);
      assert.equal(card.status, 'MAPPING_CONFLICT', `${label}/${snip.role}: snippet status`);
      assert.equal(card.sha256, '', `${label}/${snip.role}: snippet sha256`);
      const cardFromDetail = fp.resolveSnippetHashStatus(snip, detail);
      assert.equal(cardFromDetail.status, 'MAPPING_CONFLICT', `${label}/${snip.role}: snippet status via detail`);
      assert.equal(cardFromDetail.sha256, '', `${label}/${snip.role}: snippet sha256 via detail`);
      const snipHtml = renderer.renderSnippet(snip, detail.evidence);
      assert(snipHtml.includes('Mapping mâu thuẫn'), `${label}/${snip.role}: snippet SSR label`);
      assert(!snipHtml.includes('Khớp snapshot') && !snipHtml.includes('bbbbbbbb') && !snipHtml.includes('Sao chép'), `${label}/${snip.role}: snippet SSR must not leak SHA_B or Copy`);
    }

    const dfRes = renderer.renderDataflow(detail.evidence);
    assert(dfRes.dataflow.steps.length >= 1, `${label}: Dataflow must retain steps`);
    for (const st of dfRes.dataflow.steps) {
      assert.equal(st.mappingConflict, true, `${label}: step mappingConflict`);
      assert.equal(st.hashStatus, 'MAPPING_CONFLICT', `${label}: step hashStatus`);
      assert.equal(st.sha256, '', `${label}: step sha256`);
      assert.deepEqual([st.startLine, st.startCol, st.endLine, st.endCol], [28, 3, 28, 9], `${label}: step coordinates`);
    }
    assert(dfRes.html.includes('path_mappings có nhiều thư mục đích mâu thuẫn') && !dfRes.html.includes('/./'), `${label}: Dataflow SSR must render conflict notice without raw /./`);
  };

  // Group E: Exact Codex Round 8 C4 fixture (`/./` in snippet, snapshot key, and raw_trace)
  const codexC4Alias = 'C:/checkout-A/src/main/java/./FileServlet.java';
  const codexC4Detail = deepFreeze({
    finding_id: 'f-c26-c4',
    file_path: branchRel,
    evidence: {
      root: '/mnt/shared',
      path: branchRel,
      raw_path: childA,
      path_mappings: mappings,
      snapshots: {[codexC4Alias]: {sha256: shaB}},
      snippets: [
        {...span, role: 'finding', path: codexC4Alias, matched: 'value', sha256: shaB},
        {...span, role: 'source', path: codexC4Alias, matched: 'value', sha256: shaB},
      ],
      raw_trace: {taint_source: ['CliLoc', [loc(codexC4Alias, 28, 3, 28, 9), 'value']]},
    },
  });
  assertFullConflictConsistency('GroupE_Codex_C4_exact', codexC4Detail);
  // Raw input keys/paths must remain untouched on frozen input
  assert.equal(codexC4Detail.evidence.snapshots[codexC4Alias].sha256, shaB);

  // Group A & C: Metamorphic path-representation & permutation invariance across all surfaces
  const checkoutAVariants = [
    childA,
    codexC4Alias,
    'C:/./checkout-A/./src/./main/./java/./FileServlet.java/.',
    'c:\\checkout-A\\.\\src\\\\main\\./java\\FileServlet.java',
    'C:///checkout-A//./src///main//./java//FileServlet.java',
  ];
  for (let i = 0; i < checkoutAVariants.length; i++) {
    const fVar = checkoutAVariants[i];
    const sVar = checkoutAVariants[(i + 1) % checkoutAVariants.length];
    const tVar = checkoutAVariants[(i + 2) % checkoutAVariants.length];
    assertFullConflictConsistency(`GroupA_skew_${i}`, deepFreeze({
      finding_id: `f-c26-a-${i}`,
      file_path: `./branch/./${REL}`,
      evidence: {
        root: '/mnt/./shared/',
        path: `./branch/./${REL}`,
        raw_path: fVar,
        path_mappings: i % 2 === 0 ? mappings : [...mappings].reverse(),
        snapshots: {[sVar]: {sha256: shaB}},
        snippets: (i % 2 === 0 ? [
          {...span, role: 'finding', path: sVar, matched: 'value', sha256: shaB},
          {...span, role: 'source', path: tVar, matched: 'value', sha256: shaB},
        ] : [
          {...span, role: 'source', path: tVar, matched: 'value', sha256: shaB},
          {...span, role: 'finding', path: sVar, matched: 'value', sha256: shaB},
        ]),
        raw_trace: {taint_source: ['CliLoc', [loc(tVar, 28, 3, 28, 9), 'value']]},
      },
    }));
  }

  // Unmapped POSIX source with `/./` and `///`, plus other conflicting branch target (`checkout-B`) even when finding omits `raw_path`
  for (const [label, fRaw, cand] of [
    ['GroupA_posix_dot', undefined, '///mnt/./shared//./branch/./src/main/java/./FileServlet.java'],
    ['GroupA_checkoutB_no_raw', undefined, 'c:\\checkout-B\\.\\src\\main\\java\\./FileServlet.java'],
    ['GroupA_checkoutB_vs_rawA', childA, `${childB.slice(0, 14)}./${REL}`],
    ['GroupA_parent_dot', undefined, `C:/mount/./branch/./${REL}`],
  ]) {
    const det = deepFreeze({
      finding_id: `f-${label}`,
      file_path: branchRel,
      evidence: {
        root: '/mnt/shared',
        path: branchRel,
        ...(fRaw ? {raw_path: fRaw} : {}),
        path_mappings: mappings,
        snapshots: {[cand]: {sha256: shaB}},
        snippets: [
          {...span, role: 'finding', path: cand, matched: 'value', sha256: shaB},
          {...span, role: 'source', path: cand, matched: 'value', sha256: shaB},
        ],
        raw_trace: {taint_source: ['CliLoc', [loc(cand, 28, 3, 28, 9), 'value']]},
      },
    });
    assertFullConflictConsistency(label, det);
    assert.equal(fp.resolveFindingSourceHash(det).resolvedPath, branchFull);
  }

  // Asymmetric `..` safety: `..` targeting disputed file keeps MAPPING_CONFLICT; escaping root yields PATH_CONFLICT (never SNAPSHOT_MATCHED)
  const dotDotDisputed = 'C:/checkout-A/src/main/java/sub/../FileServlet.java';
  assertFullConflictConsistency('GroupA_dotdot_disputed', deepFreeze({
    finding_id: 'f-dotdot',
    file_path: branchRel,
    evidence: {
      root: '/mnt/shared',
      path: branchRel,
      raw_path: childA,
      path_mappings: mappings,
      snapshots: {[childA]: {sha256: shaB}},
      snippets: [
        {...span, role: 'finding', path: dotDotDisputed, matched: 'value', sha256: shaB},
        {...span, role: 'source', path: dotDotDisputed, matched: 'value', sha256: shaB},
      ],
      raw_trace: {taint_source: ['CliLoc', [loc(dotDotDisputed, 28, 3, 28, 9), 'value']]},
    },
  }));
  const escapedRoot = fp.resolveFindingSourceHash(deepFreeze({
    file_path: '../FileServlet.java',
    evidence: {path: '../FileServlet.java', snapshots: {'../FileServlet.java': {sha256: shaA}}, snippets: []},
  }));
  assert.equal(escapedRoot.status, 'PATH_CONFLICT');
  assert.equal(escapedRoot.sha256, '');

  // Group B: Positive controls (sibling, valid unique child mapping without snippet root, distinct basename/root, UNC, standalone + A-B-A)
  for (const [label, relP, absP, snapAlias] of [
    ['GroupB_sibling_dots', `./${siblingRel}`, siblingAbs, 'c:\\mount\\.\\other\\src\\main\\java\\./FileServlet.java'],
    ['GroupB_valid_child_dots', `./${validChildRel}`, validChildAbs, 'C:/specific/./src//main/java/./FileServlet.java'],
  ]) {
    const posDetail = deepFreeze({
      finding_id: `f-${label}`,
      file_path: relP,
      evidence: {
        root: '/mnt/./shared/',
        path: relP,
        raw_path: absP,
        path_mappings: mappings,
        snapshots: {[snapAlias]: {sha256: shaA}, [parentAbs]: {sha256: shaB}},
        snippets: [
          {...span, role: 'finding', path: relP, raw_path: snapAlias, matched: 'value', sha256: shaA},
          {...span, role: 'source', path: relP, raw_path: absP, matched: 'value', sha256: shaA},
        ],
        raw_trace: {taint_source: ['CliLoc', [loc(snapAlias, 28, 3, 28, 9), 'value']]},
      },
    });
    const pRes = renderer.renderPrimaryHash(posDetail);
    assert.equal(pRes.primaryHash.status, 'SNAPSHOT_MATCHED', `${label}: primary status`);
    assert.equal(pRes.primaryHash.sha256, shaA);
    assert(pRes.html.includes(shaA) && pRes.html.includes('Sao chép'));
    const sRes = fp.resolveSnippetHashStatus(posDetail.evidence.snippets[0], posDetail);
    assert.deepEqual([sRes.status, sRes.sha256], ['SNAPSHOT_MATCHED', shaA], `${label}: snippet without own root must verify under valid mapping`);
    const df = fp.analyzeDataflow(posDetail);
    assert.equal(df.steps.length, 1);
    assert.deepEqual([df.steps[0].mappingConflict, df.steps[0].hashStatus, df.steps[0].sha256], [false, 'SNAPSHOT_MATCHED', shaA]);
  }

  // Standalone equivalent `./` snapshot + A-B-A isolation
  const cleanDotStandalone = deepFreeze({
    finding_id: 'f-clean-dot',
    file_path: childA,
    evidence: {
      path: childA,
      raw_path: childA,
      snapshots: {[codexC4Alias]: {sha256: shaA}},
      snippets: [{...span, role: 'finding', path: childA, matched: 'value', sha256: shaA}],
    },
  });
  assert.equal(fp.resolveFindingSourceHash(codexC4Detail).status, 'MAPPING_CONFLICT');
  assert.deepEqual([fp.resolveFindingSourceHash(cleanDotStandalone).status, fp.resolveFindingSourceHash(cleanDotStandalone).sha256], ['SNAPSHOT_MATCHED', shaA]);
  assert.deepEqual([fp.resolveSnippetHashStatus(cleanDotStandalone.evidence.snippets[0], cleanDotStandalone).status, fp.resolveSnippetHashStatus(cleanDotStandalone.evidence.snippets[0], cleanDotStandalone).sha256], ['SNAPSHOT_MATCHED', shaA]);
  assert.equal(fp.resolveFindingSourceHash(codexC4Detail).status, 'MAPPING_CONFLICT');

  // Group D: Counter-provenance & contradictory SHA/provenance escalation
  // D1) Case-distinct filenames are NOT merged
  const caseLower = 'C:/root-a/src/main/java/fileservlet.java';
  const caseDf = fp.analyzeDataflow(deepFreeze({
    path: rootAAbs,
    raw_path: rootAAbs,
    snapshots: {[rootAAbs]: {sha256: shaA}, [caseLower]: {sha256: shaB}},
    snippets: [
      {...span, role: 'source', path: rootAAbs, matched: 'v1', sha256: shaA},
      {start: {line: 40, col: 2}, end: {line: 40, col: 8}, role: 'sink', path: caseLower, matched: 'v2', sha256: shaB},
    ],
  }));
  assert.equal(caseDf.steps.length, 2);
  assert(caseDf.steps.every((s) => !s.shaConflict));

  // D2) Two equivalent snapshot keys with opposing SHAs escalate to CONFLICT
  const eqSnapConflict = fp.resolveFindingSourceHash(deepFreeze({
    file_path: rootAAbs,
    evidence: {
      path: rootAAbs,
      raw_path: rootAAbs,
      snapshots: {[rootAAbs]: {sha256: shaA}, ['C:/root-a/src/main/java/./FileServlet.java']: {sha256: shaB}},
      snippets: [{...span, role: 'finding', path: rootAAbs, matched: 'v', sha256: shaA}],
    },
  }));
  assert.equal(eqSnapConflict.status, 'CONFLICT');
  assert.equal(eqSnapConflict.sha256, '');
  assert.deepEqual(eqSnapConflict.conflictingHashes, [shaA, shaB]);

  // D3) Two equivalent snapshot keys where one has malformed SHA escalate to INVALID_FORMAT (never silently pick valid one)
  const eqSnapInvalid = fp.resolveFindingSourceHash(deepFreeze({
    file_path: rootAAbs,
    evidence: {
      path: rootAAbs,
      raw_path: rootAAbs,
      snapshots: {[rootAAbs]: {sha256: shaA}, ['C:/root-a/src/main/java/./FileServlet.java']: {sha256: 'MALFORMED_HEX'}},
      snippets: [{...span, role: 'finding', path: rootAAbs, matched: 'v', sha256: shaA}],
    },
  }));
  assert.equal(eqSnapInvalid.status, 'INVALID_FORMAT');
  assert.equal(eqSnapInvalid.sha256, '');

  // D4) Equivalent canonical file with contradictory relative provenance escalates to PATH_CONFLICT
  const contraProv = fp.resolveFindingSourceHash(deepFreeze({
    file_path: 'sub/FileServlet.java',
    evidence: {
      path: 'sub/FileServlet.java',
      raw_path: 'C:/root-a/sub/FileServlet.java',
      snapshots: {['C:/root-a/sub/FileServlet.java']: {sha256: shaA}},
      snippets: [
        {...span, role: 'finding', path: 'sub/FileServlet.java', raw_path: 'C:/root-a/sub/FileServlet.java', matched: 'v', sha256: shaA},
        {...span, role: 'source', path: './FileServlet.java', raw_path: 'C:/root-a/./sub/FileServlet.java', matched: 'v', sha256: shaA},
      ],
    },
  }));
  assert.equal(contraProv.status, 'PATH_CONFLICT');
  assert.equal(contraProv.sha256, '');

  // D5) Multi-root ambiguous relative snapshot with `/./` must stay AMBIGUOUS_SNAPSHOT (no fallback to DECLARED_BY_SNIPPET)
  const dotRelAmb = fp.resolveFindingSourceHash(deepFreeze({
    file_path: REL,
    evidence: {
      path: REL,
      raw_path: rootAAbs,
      snapshots: {[`./src/main/java/./FileServlet.java`]: {sha256: shaB}},
      snippets: [
        {...span, role: 'source', path: REL, raw_path: rootAAbs, matched: 'v', sha256: shaA},
        {...span, role: 'source', path: REL, raw_path: rootBAbs, matched: 'v', sha256: shaB},
      ],
    },
  }));
  assert.equal(dotRelAmb.status, 'AMBIGUOUS_SNAPSHOT');
  assert.equal(dotRelAmb.sha256, '');
});

test('C27 (Round 10 provenance consistency): root-vs-absolute validation, redundant raw_path invariance, and drive-relative prefix safety', async () => {
  const fp = await loadFp();
  const renderer = loadResultsRenderer();
  const shaA = 'a'.repeat(64);
  const shaB = 'b'.repeat(64);
  const span = {start: {line: 28, col: 3}, end: {line: 28, col: 9}};
  const span2 = {start: {line: 40, col: 4}, end: {line: 40, col: 14}};
  const mappings = [
    {from: '/mnt/shared', to: 'C:/mount'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-A'},
    {from: '/mnt/shared/branch', to: 'C:/checkout-B'},
    {from: '/mnt/shared/custom', to: 'C:/specific'},
  ];

  // 1) Codex E1: absolute path outside declared root (no valid mapping) MUST return PATH_CONFLICT across primary, snippet, Dataflow & SSR
  const outsideB = `C:/checkout-B/${REL}`;
  const e1Detail = deepFreeze({
    finding_id: 'f-r10-e1',
    file_path: outsideB,
    evidence: {
      root: 'C:/checkout-A',
      path: outsideB,
      snapshots: {[outsideB]: {sha256: shaB}},
      snippets: [
        {...span, role: 'finding', root: 'C:/checkout-A', path: outsideB, matched: 'v', sha256: shaB},
        {...span, role: 'source', root: 'C:/checkout-A', path: outsideB, matched: 'v', sha256: shaB},
      ],
      raw_trace: {taint_source: ['CliLoc', [loc(outsideB, 28, 3, 28, 9), 'v']]},
    },
  });
  const e1Main = renderer.renderPrimaryHash(e1Detail);
  assert.equal(e1Main.primaryHash.status, 'PATH_CONFLICT');
  assert.equal(e1Main.primaryHash.sha256, '');
  assert.equal(e1Main.primaryHash.verifiedAgainstSnapshot, false);
  assert(!e1Main.html.includes(shaB) && !e1Main.html.includes('Sao chép'));
  for (const s of e1Detail.evidence.snippets) {
    const st = fp.resolveSnippetHashStatus(s, e1Detail);
    assert.deepEqual([st.status, st.sha256], ['PATH_CONFLICT', '']);
    const html = renderer.renderSnippet(s, e1Detail);
    assert(html.includes('Đường dẫn mâu thuẫn') && !html.includes('Sao chép'));
  }
  const e1Df = fp.analyzeDataflow(e1Detail);
  assert(e1Df.steps.length > 0 && e1Df.steps.every((st) => st.pathConflict && st.hashStatus === 'PATH_CONFLICT' && st.sha256 === ''));

  // E1 without snapshots & with unrooted snippet/raw_trace & segment-prefix trap & shadowed parent mapping
  for (const badEv of [
    deepFreeze({...e1Detail.evidence, snapshots: {}}),
    deepFreeze({root: 'C:/checkout-A', path: outsideB, snapshots: {[outsideB]: {sha256: shaB}}, snippets: [{...span, role: 'source', path: outsideB, matched: 'v', sha256: shaB}], raw_trace: e1Detail.evidence.raw_trace}),
    deepFreeze({root: 'C:/checkout-A', path: `C:/checkout-A-evil/${REL}`, snapshots: {[`C:/checkout-A-evil/${REL}`]: {sha256: shaB}}, snippets: [{...span, role: 'source', root: 'C:/checkout-A', path: `C:/checkout-A-evil/${REL}`, matched: 'v', sha256: shaB}]}),
    deepFreeze({root: '/mnt/shared', path: `C:/mount/custom/${REL}`, path_mappings: mappings, snapshots: {[`C:/mount/custom/${REL}`]: {sha256: shaB}}, snippets: [{...span, role: 'source', root: '/mnt/shared', path: `C:/mount/custom/${REL}`, matched: 'v', sha256: shaB}]}),
  ]) {
    const m = fp.resolveFindingSourceHash(badEv);
    assert.deepEqual([m.status, m.sha256, m.verifiedAgainstSnapshot], ['PATH_CONFLICT', '', false]);
    for (const s of badEv.snippets) {
      assert.deepEqual([fp.resolveSnippetHashStatus(s, badEv).status, fp.resolveSnippetHashStatus(s, badEv).sha256], ['PATH_CONFLICT', '']);
    }
  }

  // 2) Codex E2: removing redundant raw_path MUST NOT flip PATH_CONFLICT to SNAPSHOT_MATCHED
  const pSub = 'C:/root-a/sub/FileServlet.java';
  const e2SnipsNoRaw = [
    {...span, role: 'finding', root: 'C:/root-a', path: 'sub/FileServlet.java', matched: 'v', sha256: shaA},
    {...span, role: 'source', root: 'C:/root-a/sub', path: './FileServlet.java', matched: 'v', sha256: shaA},
  ];
  const e2WithRaw = deepFreeze({
    finding_id: 'f-r10-e2-raw',
    file_path: 'sub/FileServlet.java',
    evidence: {
      root: 'C:/root-a',
      path: 'sub/FileServlet.java',
      raw_path: pSub,
      snapshots: {[pSub]: {sha256: shaA}},
      snippets: e2SnipsNoRaw.map((s) => ({...s, raw_path: pSub})),
      raw_trace: {taint_source: ['CliLoc', [loc(pSub, 28, 3, 28, 9), 'v']]},
    },
  });
  const e2WithoutRaw = deepFreeze({
    finding_id: 'f-r10-e2-noraw',
    file_path: 'sub/FileServlet.java',
    evidence: {
      root: 'C:/root-a',
      path: 'sub/FileServlet.java',
      snapshots: {[pSub]: {sha256: shaA}},
      snippets: e2SnipsNoRaw,
      raw_trace: {taint_source: ['CliLoc', [loc(pSub, 28, 3, 28, 9), 'v']]},
    },
  });
  const e2Reversed = deepFreeze({
    ...e2WithoutRaw,
    evidence: {...e2WithoutRaw.evidence, snippets: [e2SnipsNoRaw[1], e2SnipsNoRaw[0]]},
  });
  const e2StaleSnipRaw = deepFreeze({
    ...e2WithoutRaw,
    evidence: {
      ...e2WithoutRaw.evidence,
      snippets: e2SnipsNoRaw.map((s) => ({...s, raw_path: `C:/root-a/${REL}`})),
    },
  });
  for (const variant of [e2WithRaw, e2WithoutRaw, e2Reversed, e2StaleSnipRaw]) {
    const rendered = renderer.renderPrimaryHash(variant);
    assert.deepEqual(
      [rendered.primaryHash.status, rendered.primaryHash.sha256, rendered.primaryHash.verifiedAgainstSnapshot],
      ['PATH_CONFLICT', '', false],
    );
    assert(!rendered.html.includes(shaA) && !rendered.html.includes('Sao chép'));
    for (const s of variant.evidence.snippets) {
      const st = fp.resolveSnippetHashStatus(s, variant);
      assert.deepEqual([st.status, st.sha256], ['PATH_CONFLICT', '']);
    }
    const df = fp.analyzeDataflow(variant);
    assert(df.steps.length > 0 && df.steps.every((st) => st.pathConflict && st.hashStatus === 'PATH_CONFLICT' && st.sha256 === ''));
  }

  // 3) Codex C7: `./C:relative/File.java` and `./C:/...` consistently return PATH_CONFLICT across all surfaces
  for (const driveRel of ['./C:relative/File.java', './C:/checkout-A/File.java']) {
    const ev = deepFreeze({
      root: 'C:/root',
      path: driveRel,
      raw_path: driveRel,
      snapshots: {[driveRel]: {sha256: shaA}},
      snippets: [{...span, role: 'source', path: driveRel, matched: 'v', sha256: shaA}],
      raw_trace: {taint_source: ['CliLoc', [loc(driveRel, 28, 3, 28, 9), 'v']]},
    });
    assert.deepEqual([fp.resolveFindingSourceHash(ev).status, fp.resolveFindingSourceHash(ev).sha256], ['PATH_CONFLICT', '']);
    assert.deepEqual([fp.resolveSnippetHashStatus(ev.snippets[0], ev).status, fp.resolveSnippetHashStatus(ev.snippets[0], ev).sha256], ['PATH_CONFLICT', '']);
    const df = fp.analyzeDataflow(ev);
    assert(df.steps.length > 0 && df.steps.every((st) => st.pathConflict && st.hashStatus === 'PATH_CONFLICT' && st.sha256 === ''));
  }

  // 4) Positive controls: valid parent/child mappings, equivalent mapped roots, sibling outside conflict, and A-B-A isolation
  const mappedParentAbs = `C:/mount/other/${REL}`;
  const validParentEv = deepFreeze({
    finding_id: 'f-r10-pos-parent',
    file_path: mappedParentAbs,
    evidence: {
      root: '/mnt/shared',
      path: mappedParentAbs,
      path_mappings: mappings,
      snapshots: {[mappedParentAbs]: {sha256: shaA}},
      snippets: [
        {...span, role: 'finding', root: '/mnt/shared', path: mappedParentAbs, matched: 'v', sha256: shaA},
        {...span, role: 'source', root: 'C:/mount', path: `other/${REL}`, matched: 'v', sha256: shaA},
      ],
      raw_trace: {taint_source: ['CliLoc', [loc(mappedParentAbs, 28, 3, 28, 9), 'v']]},
    },
  });
  const posParentRender = renderer.renderPrimaryHash(validParentEv);
  assert.deepEqual([posParentRender.primaryHash.status, posParentRender.primaryHash.sha256, posParentRender.primaryHash.verifiedAgainstSnapshot], ['SNAPSHOT_MATCHED', shaA, true]);
  assert(posParentRender.html.includes(shaA) && posParentRender.html.includes('Sao chép'));
  for (const s of validParentEv.evidence.snippets) {
    assert.deepEqual([fp.resolveSnippetHashStatus(s, validParentEv).status, fp.resolveSnippetHashStatus(s, validParentEv).sha256], ['SNAPSHOT_MATCHED', shaA]);
  }

  const mappedChildAbs = `C:/specific/${REL}`;
  const validChildEv = deepFreeze({
    root: '/mnt/shared',
    path: mappedChildAbs,
    path_mappings: mappings,
    snapshots: {[mappedChildAbs]: {sha256: shaA}},
    snippets: [
      {...span, role: 'finding', root: '/mnt/shared', path: mappedChildAbs, matched: 'v', sha256: shaA},
      {...span, role: 'source', root: 'C:/specific', path: REL, matched: 'v', sha256: shaA},
    ],
    raw_trace: {taint_source: ['CliLoc', [loc(mappedChildAbs, 28, 3, 28, 9), 'v']]},
  });
  assert.deepEqual([fp.resolveFindingSourceHash(validChildEv).status, fp.resolveFindingSourceHash(validChildEv).sha256], ['SNAPSHOT_MATCHED', shaA]);
  for (const s of validChildEv.snippets) {
    assert.deepEqual([fp.resolveSnippetHashStatus(s, validChildEv).status, fp.resolveSnippetHashStatus(s, validChildEv).sha256], ['SNAPSHOT_MATCHED', shaA]);
  }

  // Sibling outside E2 conflict stays SNAPSHOT_MATCHED
  const cleanSibling = 'C:/root-a/other/Safe.java';
  const e2SiblingEv = deepFreeze({
    root: 'C:/root-a',
    path: 'sub/FileServlet.java',
    snapshots: {[pSub]: {sha256: shaA}, [cleanSibling]: {sha256: shaB}},
    snippets: [
      ...e2SnipsNoRaw,
      {...span2, role: 'sink', root: 'C:/root-a', path: 'other/Safe.java', matched: 'ok', sha256: shaB},
    ],
  });
  assert.equal(fp.resolveFindingSourceHash(e2SiblingEv).status, 'PATH_CONFLICT');
  assert.deepEqual(
    e2SiblingEv.snippets.map((s) => [fp.resolveSnippetHashStatus(s, e2SiblingEv).status, fp.resolveSnippetHashStatus(s, e2SiblingEv).sha256]),
    [['PATH_CONFLICT', ''], ['PATH_CONFLICT', ''], ['SNAPSHOT_MATCHED', shaB]],
  );

  // A-B-A isolation: standalone independent finding on same path stays SNAPSHOT_MATCHED between E1/E2 checks
  const standaloneOutside = deepFreeze({
    path: outsideB,
    raw_path: outsideB,
    snapshots: {[outsideB]: {sha256: shaA}},
    snippets: [{...span, role: 'source', path: outsideB, matched: 'v', sha256: shaA}],
  });
  assert.equal(fp.resolveFindingSourceHash(e1Detail).status, 'PATH_CONFLICT');
  assert.deepEqual([fp.resolveFindingSourceHash(standaloneOutside).status, fp.resolveFindingSourceHash(standaloneOutside).sha256], ['SNAPSHOT_MATCHED', shaA]);
  assert.equal(fp.resolveFindingSourceHash(e1Detail).status, 'PATH_CONFLICT');
});
