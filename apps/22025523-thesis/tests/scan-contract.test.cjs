/** Contract regression for the browser scan loader. Runs with Node.js >= 20, no npm dependencies. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

function loadFrontendContract(apiStub) {
  const file = path.join(__dirname, '..', 'src', 'services', 'liveScan.js');
  const source = fs.readFileSync(file, 'utf8');
  // Isolate the pure data + fetch contract without loading React or a browser.
  const code = source.replace(/^import [^\n]+\n/gm, '').replace(/^export /gm, '')
    + '\n;globalThis.__tested = {buildDataset, loadLiveScan};';
  const storage = new Map();
  const saves = [];
  const sandbox = {
    api: apiStub,
    ApiError: class ApiError extends Error {},
    normalizeFinding: (item) => ({id: item.finding_id || '', decision: item.decision || ''}),
    saveScanRecord: (record) => saves.push(record),
    pick: () => '',
    upsertHistory: () => {},
    window: {sessionStorage: {
      setItem: (key, value) => storage.set(key, value),
      getItem: (key) => storage.get(key) || null,
      removeItem: (key) => storage.delete(key)
    }}
  };
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox, {filename: file});
  return {tested: sandbox.__tested, saves, storage};
}

test('large Java scan fetches only summary and 50 rows, without replacing global totals', async () => {
  const scanId = 'SCAN-TEST-LARGE';
  const summary = {
    scan_id: scanId,
    total_findings: 5251,
    has_full_scan_findings_payload: true,
    triage_totals: {total_candidates: 5251, report_count: 500, review_count: 3744, suppress_count: 1007}
  };
  const findings = Array.from({length: 50}, (_, i) => ({finding_id: `F-${i}`, decision: 'REPORT'}));
  const calls = [];
  const apiStub = {
    scanSummary: async (sid) => {calls.push('summary'); assert.equal(sid, scanId); return summary;},
    findingsPage: async (sid, page, size) => {
      calls.push('page'); assert.equal(sid, scanId); assert.equal(page, 1);
      assert.equal(size, 50); return {scan_id: scanId, findings, total_count: 5251};
    },
    cwssV2ForFindingIds: async (sid, ids) => {
      calls.push('cwss');
      assert.equal(sid, scanId);
      assert.equal(ids.length, 50);
      assert.equal(ids[0], "F-0");
      assert.equal(ids[49], "F-49");
      return {status: 'UNAVAILABLE', assessments: []};
    },
    cwssV2ScenarioPage: async (sid, page, size) => { calls.push('scenario'); assert.equal(sid, scanId); assert.equal(page, 1); assert.equal(size, 50); return {status:'UNAVAILABLE', assessments: []}; },
    scan: async () => {throw Error('must never fetch full scan');},
    findings: async () => {throw Error('must never fetch full findings');}
  };
  const {tested, saves} = loadFrontendContract(apiStub);
  const result = await tested.loadLiveScan(scanId);
  assert.deepEqual(calls.sort(), ['cwss', 'page', 'scenario', 'summary']);
  assert.equal(result.rows.length, 50);
  assert.equal(result.counts.total, 5251);
  assert.equal(result.counts.report, 500);
  assert.equal(result.counts.review, 3744);
  assert.equal(result.counts.suppress, 1007);
  assert.equal(result.counts.unclassified, 0);
  assert.equal(saves.length, 1);
  assert.equal(saves[0].findingsPayload.findings.length, 50);
});

test('trace-only restoration cannot be displayed as a successful full findings scan', async () => {
  const scanId = 'SCAN-RESTORED-TRACE';
  const apiStub = {
    scanSummary: async () => ({scan_id: scanId, has_full_scan_findings_payload: false, total_findings: 8}),
    findingsPage: async () => ({scan_id: scanId, findings: []}),
    cwssPage: async () => ({status: 'UNAVAILABLE', assessments: []})
  };
  const {tested, saves} = loadFrontendContract(apiStub);
  await assert.rejects(tested.loadLiveScan(scanId), /trace.*findings/);
  assert.equal(saves.length, 0);
});

test('small scan uses observed rows when global triage metadata is absent', () => {
  const {tested} = loadFrontendContract({});
  const result = tested.buildDataset('SCAN-SMALL', {}, {
    findings: [{finding_id: 'F-A', decision: 'REPORT'}, {finding_id: 'F-B', decision: 'REVIEW'}]
  });
  assert.equal(result.counts.total, 2);
  assert.equal(result.counts.report, 1);
  assert.equal(result.counts.review, 1);
  assert.equal(result.counts.suppress, 0);
});