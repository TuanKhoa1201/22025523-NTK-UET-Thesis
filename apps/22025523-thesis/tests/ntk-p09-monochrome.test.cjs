const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');

test('P0.9 imports graphite theme after P0.8 without altering React routes', () => {
  const main = read('src/main.jsx');
  assert.ok(main.indexOf("import './styles/ntk-p09-monochrome.css';") > main.indexOf("import './styles/ntk-p08-design-system.css';"));
  const app = read('src/App.jsx');
  assert.match(app, /<Route path="\/scanner" element=\{<ScannerRoute \/>\}/);
  assert.match(app, /<Route path="\/finding\/:id" element=\{<FindingDetail \/>\}/);
});

test('P0.9 is an offline monochrome appearance layer with visible focus', () => {
  const css = read('src/styles/ntk-p09-monochrome.css');
  assert.match(css, /color-scheme: dark/);
  assert.match(css, /--ntk-canvas: #121214/);
  assert.match(css, /--ntk-focus: #e8e8ec/);
  assert.match(css, /:focus-visible/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(css, /\.main-area::before/);
  assert.match(css, /ntk-graphite-waves\.svg/);
  assert.match(css, /\.uet-image-tile img/);
  assert.match(css, /\.scene3d-callout\.callout-1 i/);
  assert.doesNotMatch(css, /https?:\/\//);
  assert.doesNotMatch(css, /#(?:0ea5e9|38bdf8|a78bfa|818cf8|7dd3fc)/i);
  assert.ok(fs.statSync(path.join(root, 'public/ntk-graphite-waves.svg')).size > 300);
});

test('P0.9 covers the scanner, finding, data, history and research pages', () => {
  const css = read('src/styles/ntk-p09-monochrome.css');
  for (const name of [
    '.hero', '.guided-scan', '.guided-step', '.history-compact-row',
    '.rd-filters', '.rd-chart-note', '.review-tabs', '.ntk-p05-workflow',
    '.ntk-p05-distribution', '.ntk-p06-score', '.ntk-p06-guidance',
    '.university-card', '.formula-card', '.sidebar', '.topbar'
  ]) {
    assert.ok(css.includes(name), `${name} not themed`);
  }
});

test('P0.9 chart palette changes appearance, not data source or score logic', () => {
  const charts = read('src/components/results/OverviewCharts.jsx');
  assert.match(charts, /const TEXT = '#bfbfc7'/);
  assert.match(charts, /const GRID = '#494951'/);
  assert.match(charts, /agg\.byCwe/);
  assert.match(charts, /agg\.byDecision/);
  assert.match(charts, /agg\.bySeverity/);
  assert.match(charts, /agg\.byScore/);
  assert.match(charts, /scoreInfo\.scored > 0/);
});
