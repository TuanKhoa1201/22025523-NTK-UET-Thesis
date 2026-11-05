const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');

const overview = read('src/pages/Overview.jsx');
const charts = read('src/components/results/OverviewCharts.jsx');
const live = read('src/pages/LiveFindings.jsx');
const review = read('src/pages/UtilityPages.jsx');
const scoring = read('src/pages/Scoring.jsx');
const shell = read('src/components/layout/AppShell.jsx');
const css = read('src/styles/ntk-p14-frontend-polish.css');
const entry = read('src/main.jsx');

test('P0.14 removes recent activities without removing overview sections', () => {
  assert.doesNotMatch(overview, /Ho\u1ea1t \u0111\u1ed9ng g\u1ea7n \u0111\u00e2y|fetchOverviewStats|StatCard|api\.listScans/);
  assert.match(overview, /<section className="research-banner">/);
  assert.match(overview, /<Link to="\/scanner"/);
  assert.match(overview, /<SectionTitle title="C\u00f4ng ngh\u1ec7 ph\u00e2n t\u00edch"/);
});

test('P0.14 preserves complete-scan guard and backend CWSS source', () => {
  assert.match(live, /data\?\.complete \? buildAggregates\(data\.rows, data\.scores\)/);
  assert.match(charts, /agg\.byCwe/);
  assert.match(charts, /agg\.byDecision/);
  assert.match(charts, /agg\.bySeverity/);
  assert.match(charts, /agg\.byScore/);
  assert.match(charts, /scoreInfo\.status === 'ok' && scoreInfo\.scored > 0/);
  assert.match(charts, /Ch\u01b0a \u0111\u1ee7 d\u1eef li\u1ec7u CWSS/);
  assert.doesNotMatch(charts, /Math\.random|synthetic|mockFindings|bySource/);
});

test('P0.14 charts are clearly distinguished, with muted palette and legends', () => {
  assert.match(charts, /const DECISION_COLORS = \{REPORT:/);
  assert.match(charts, /const SEVERITY_COLORS = \{CRITICAL:/);
  assert.match(charts, /const SCORE_COLORS = \[/);
  assert.match(charts, /const pie = \(entries\) =>/);
  assert.match(charts, /const severityBar = \(entries\) =>/);
  assert.match(charts, /const scoreBar = \(entries\) =>/);
  assert.match(charts, /opts=\{\{renderer: 'svg'\}\}/);
  assert.match(charts, /aria: \{enabled: true/);
  assert.doesNotMatch(charts, /#(?:0ea5e9|38bdf8|a78bfa|818cf8)/i);
});

test('P0.14 does not confuse triage decisions with TP or FP', () => {
  assert.match(charts, /not verified true or false positive labels/);
  assert.match(charts, /TP\/FP/);
  assert.match(charts, /REPORT: '#d29a9f'/);
});

test('P0.14 uses identical single-line evidence action in three review pathways', () => {
  const actions = review.match(/className="button-secondary ntk-p14-review-action"/g) || [];
  assert.equal(actions.length, 3);
  assert.equal((review.match(/<span>Xem evidence<\/span><Icon name="ArrowRight" \/>/g) || []).length, 3);
  assert.match(css, /white-space: nowrap/);
  assert.match(css, /flex: 0 0 159px/);
  assert.match(css, /@media \(max-width: 560px\)/);
  assert.match(review, /api\.findingsPage\(scanId,page,REVIEW_PAGE_SIZE/);
});

test('P0.14 removes only requested scoring content, retaining MITRE metrics', () => {
  assert.doesNotMatch(scoring, /DataNotice|Hai ch\u1ebf \u0111\u1ed9 gi\u1ea3i th\u00edch|Ranh gi\u1edbi gi\u1eefa ch\u1ea5m \u0111i\u1ec3m/);
  assert.doesNotMatch(scoring, /Kh\u00f4ng t\u1ef1 t\u1ea1o h\u1ec7 s\u1ed1 tr\u1ecdng s\u1ed1/);
  assert.match(scoring, /MITRE CWSS 1\.0\.1/);
  for (const metric of ['TI','AP','AL','IC','FC','RP','RL','AV','AS','IN','SC','BI','DI','EX','EC','P']) {
    assert.match(scoring, new RegExp(`\\['${metric}'`));
  }
  assert.match(scoring, /groups\.map/);
});

test('P0.14 connected indicators are matched white halo lamps', () => {
  assert.match(shell, /backend\.status === 'CONNECTED'/);
  assert.match(shell, /status-dot \$\{connected \? 'online'/);
  assert.match(shell, /connection-pill \$\{connected \? 'connected'/);
  assert.match(css, /\.sidebar-status > \.status-dot\.online/);
  assert.match(css, /\.connection-pill\.connected > i/);
  assert.match(css, /radial-gradient\(circle/);
  assert.match(css, /::after/);
  assert.match(css, /:not\(\.connected\)/);
});

test('P0.14 theme loads after P0.13 without replacing the previous optical style', () => {
  assert.ok(entry.indexOf('ntk-p14-frontend-polish.css') > entry.indexOf('ntk-p12-pipeline-optical.css'));
  assert.match(entry, /ntk-p11-optical-contrast\.css/);
  assert.match(css, /\.ntk-p14-chart-grid/);
  assert.match(css, /prefers-reduced-motion/);
});
