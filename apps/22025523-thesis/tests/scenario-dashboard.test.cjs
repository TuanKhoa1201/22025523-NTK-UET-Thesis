const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const apiSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'services', 'api.js'), 'utf8');
const dashboardSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'services', 'scanOverview.js'), 'utf8');
const explorerSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'components', 'results', 'FindingsExplorer.jsx'), 'utf8');
const pageSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'pages', 'LiveFindings.jsx'), 'utf8');

class ApiError extends Error {}
function sliceFunction(src, begin, end) {
  const start = src.indexOf(begin);
  const finish = src.indexOf(end, start);
  assert.ok(start >= 0 && finish > start, `${begin} missing`);
  return src.slice(start, finish);
}
const scoreFn = sliceFunction(apiSource, 'async function cwssScenarioScoreMap(', '// CWSS Inference V2 is independent');
const scenarioConstAndPage = sliceFunction(apiSource, "const SCENARIO_PROFILE =", 'async function cwssV2ScenarioFinding(');
const factorKeys = ['TI','AP','AL','IC','FC','RP','RL','AV','AS','IN','SC','BI','DI','EX','EC','P'];
const factors = Object.fromEntries(factorKeys.map((key) => [key, {metric: key, code: 'D', classification: 'MITRE_DEFAULT'}]));
const SCENARIO = 'BUSINESS_CRITICAL_INTERNET_FACING';
const mkId = (i) => `FINDING-${String(i).padStart(4, '0')}`;
const mk = (i, cwssScore = 67.1) => ({
  finding_id: mkId(i), cwss: {
    finding_id: mkId(i), cwss_score: cwssScore,
    reference_context_hash: 'sha256-test-context',
    inference_version: 'NTK_CWSS_INFERENCE_V2',
    reference_profile: SCENARIO, metric_assessments: factors
  }
});
const response = (items, page, total, patch = {}) => ({
  status: 'OK', scan_id: 'SCAN-TEST', page, page_size: 100, total_matching: total,
  scenario_id: SCENARIO, hypothetical: true, verified_deployment: false,
  assessments: items, ...patch
});
function setup(pages) {
  const requests = [];
  const context = {
    ApiError,
    request: async (url) => {
      requests.push(url);
      const page = Number(new URL(url, 'http://localhost').searchParams.get('page'));
      assert.ok(pages.has(page), `Unexpected page ${page}`);
      return pages.get(page);
    },
    Map, Set, Number
  };
  const fn = vm.runInNewContext(`${scenarioConstAndPage}\n${scoreFn}\ncwssScenarioScoreMap`, context);
  return {fn, requests};
}

test('scenario is primary for the dashboard but not reclassified as verified deployment', () => {
  assert.match(dashboardSource, /api\.cwssScenarioScoreMap\(scanId,\s*\{signal\}\)/);
  assert.doesNotMatch(dashboardSource, /api\.cwssScoreMap\(scanId/);
  assert.match(apiSource, /response\?\.hypothetical !== true/);
  assert.match(apiSource, /response\?\.verified_deployment !== false/);
  assert.doesNotMatch(pageSource, /<DataNotice>CWSS /);
  const detailSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'pages', 'Results.jsx'), 'utf8');
  assert.match(detailSource, /REFERENCE_ASSUMPTION/);
  assert.match(explorerSource, /<th title="[^"]+">CWSS<\/th>/);
  assert.doesNotMatch(explorerSource, /<th>CWSS \(mặc định\)<\/th>/);
});

test('175 scenario assessments fetched in two pages, joined by finding ID', async () => {
  const {fn,requests} = setup(new Map([
    [1,response(Array.from({length:100}, (_,i)=>mk(i+1)),1,175)],
    [2,response(Array.from({length:75}, (_,i)=>mk(i+101)),2,175)]
  ]));
  const got = await fn('SCAN-TEST');
  assert.equal(got.complete, true);
  assert.equal(got.scores.size, 175);
  assert.equal(got.scores.get('FINDING-0101'), 67.1);
  assert.equal(got.hypothetical, true);
  assert.equal(got.verifiedDeployment, false);
  assert.equal(requests.length, 2);
  assert.ok(requests.every((u) => u.includes('page_size=100')));
});

test('missing second page does not mark whole-scan CWSS complete', async () => {
  const {fn} = setup(new Map([
    [1,response(Array.from({length:100}, (_,i)=>mk(i+1)),1,175)],
    [2,response([],2,175)]
  ]));
  const got = await fn('SCAN-TEST');
  assert.equal(got.complete, false);
});

test('duplicate CWSS IDs and null scores cannot create false complete state', async () => {
  const page1=Array.from({length:100}, (_,i)=>mk(i+1));
  const page2=Array.from({length:75}, (_,i)=>mk(i+101));
  page2[0]=mk(100);
  const result1 = await setup(new Map([[1,response(page1,1,175)],[2,response(page2,2,175)]])).fn('SCAN-TEST');
  assert.equal(result1.complete, false);
  assert.equal(result1.duplicateCount, 1);
  const result2 = await setup(new Map([[1,response([mk(1,null)],1,1)]])).fn('SCAN-TEST');
  assert.equal(result2.complete, false);
  assert.equal(result2.scores.size, 0);
});

test('numeric 0 and 100 remain valid CWSS values', async () => {
  const {fn} = setup(new Map([[1,response([mk(1,0),mk(2,100)],1,2)]]));
  const got = await fn('SCAN-TEST');
  assert.equal(got.complete,true);
  assert.equal(got.scores.get(mkId(1)),0);
  assert.equal(got.scores.get(mkId(2)),100);
});

test('reject scenario mislabeled as deployed/verified or wrong profile', async () => {
  for (const patch of [{hypothetical:false},{verified_deployment:true},{scenario_id:'GENERAL_JAVA'}]) {
    const {fn}=setup(new Map([[1,response([mk(1)],1,1,patch)]]));
    await assert.rejects(fn('SCAN-TEST'), /scenario response is invalid/);
  }
});

test('reject inconsistent total_matching across scenario pages', async () => {
  const {fn} = setup(new Map([
    [1,response(Array.from({length:100}, (_,i)=>mk(i+1)),1,175)],
    [2,response(Array.from({length:75}, (_,i)=>mk(i+101)),2,174)]
  ]));
  await assert.rejects(fn('SCAN-TEST'), /tổng findings/);
});
