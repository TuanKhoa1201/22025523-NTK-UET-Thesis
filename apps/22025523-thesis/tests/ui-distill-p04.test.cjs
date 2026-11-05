const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = (p) => fs.readFileSync(path.join(__dirname, '..', 'src', p), 'utf8');

const scanner = source('pages/Scanner.jsx');
const coverage = source('components/scanner/JobPanels.jsx');
const findings = source('pages/LiveFindings.jsx');
const charts = source('components/results/OverviewCharts.jsx');
const review = source('pages/UtilityPages.jsx');
const overview = source('services/scanOverview.js');

test('scanner keeps 10 stages and coverage data without summary widgets or footer', () => {
  assert.match(scanner, /<StageTiming job=\{liveJob\} counts=\{liveCounts\} \/>/);
  assert.match(scanner, /<CoveragePanel job=\{liveJob\} counts=\{liveCounts\} \/>/);
  assert.match(scanner, /stage\?\.duration_ms/);
  for (const term of ['T\u1ed4NG E2E BACKEND', 'T\u1ed4NG DURATION C\u00c1C STAGE', 'STAGE D\u00c0I NH\u1ea4T']) {
    assert.ok(!scanner.includes(term), term);
  }
  assert.doesNotMatch(scanner, /<div><span>OVERHEAD<\/span>/);
  assert.match(coverage, /Tr\u1ea1ng th\u00e1i coverage/);
  assert.doesNotMatch(coverage, /FULL_SOURCE_COVERAGE ch\u1ec9 m\u00f4 t\u1ea3/);
  assert.doesNotMatch(coverage, /Backend b\u00e1o ph\u1ea1m vi ph\u00e2n t\u00edch ch\u01b0a \u0111\u1ea7y \u0111\u1ee7/);
});

test('dashboard keeps real counts, safeguards and CWSS chart but removes noisy cards', () => {
  assert.match(findings, /useScanOverview\(scanId\)/);
  assert.match(findings, /data\?\.complete/);
  assert.match(findings, /buildAggregates\(data.rows, data.scores\)/);
  assert.match(findings, /backendTotal=\{data.total\}/);
  assert.match(findings, /<OverviewCharts agg=\{agg\} scoreInfo=\{scoreInfo\}/);
  assert.doesNotMatch(findings, /<DataNotice>CWSS /);
  assert.doesNotMatch(findings, /<StatCard label="Ph\u1ea1m vi qu\u00e9t Java"/);
  assert.doesNotMatch(findings, /<StatCard label="Tr\u1ea1ng th\u00e1i IRIS"/);
  assert.doesNotMatch(findings, /Ngu\u1ed3n KPI:/);
  assert.match(overview, /cwssScenarioScoreMap\(scanId,/);
  const explorer = source('components/results/FindingsExplorer.jsx');
  assert.match(explorer, /<th title="[^"]+">CWSS<\/th>/);
});

test('charts use only verifiable whole-scan data and keep full error fallback', () => {
  for (const name of ['Findings theo CWE', 'Findings theo quy\u1ebft \u0111\u1ecbnh triage', 'M\u1ee9c c\u1ea3nh b\u00e1o theo scanner', 'Ph\u00e2n b\u1ed1 \u0111i\u1ec3m CWSS']) {
    assert.ok(charts.includes(name), name);
  }
  assert.doesNotMatch(charts, /Findings theo ngu\u1ed3n ph\u00e1t hi\u1ec7n/);
  assert.doesNotMatch(charts, /scoreNote\(/);
  assert.match(charts, /Ch\u01b0a \u0111\u1ee7 d\u1eef li\u1ec7u CWSS/);
});

test('review and reports remain backend-connected while hiding empty evidence', () => {
  assert.doesNotMatch(review, /H\u00e0ng \u0111\u1ee3i h\u1ed7 tr\u1ee3 analyst review/);
  assert.doesNotMatch(review, /S\u1ed1 li\u1ec7u tab l\u1ea5y t\u1eeb summary\.triage_totals/);
  assert.doesNotMatch(review, /D\u1eef li\u1ec7u LIVE t\u1eeb backend cho scan/);
  assert.match(review, /row\.evidence !== undefined/);
  assert.match(review, /api\.findingsPage\(scanId,page,REVIEW_PAGE_SIZE/);
  assert.match(review, /api\.report\(data.scanId/);
  assert.match(review, /Xu\u1ea5t d\u1eef li\u1ec7u \u0111\u00e3 n\u1ea1p/);
});
