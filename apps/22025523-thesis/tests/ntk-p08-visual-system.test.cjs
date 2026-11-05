const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');

test('P0.8 theme loads last in the root entry after App routes', () => {
  const main = read('src/main.jsx');
  assert.match(main, /import '\.\/styles\/ntk-p08-design-system\.css';/);
  assert.ok(main.lastIndexOf('ntk-p08-design-system.css') > main.lastIndexOf('index.css'));
});

test('P0.8 theme centralizes semantic colors and keeps a dark code surface', () => {
  const css = read('src/styles/ntk-p08-design-system.css');
  for (const token of ['--bg:', '--surface:', '--border:', '--text:', '--blue:', '--ntk-brand:', '--ntk-focus:']) {
    assert.ok(css.includes(token), `Missing semantic token ${token}`);
  }
  assert.match(css, /\.ntk-p06-code-wrap pre[\s\S]*background: #102436/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
});

test('P0.8 adds accessible skip link without modifying navigation contracts', () => {
  const shell = read('src/components/layout/AppShell.jsx');
  assert.match(shell, /className="skip-link" href="#ntk-main"/);
  assert.match(shell, /id="ntk-main" className="content-area"/);
  assert.match(shell, /<Outlet context=\{\{backend\}\} \/>/);
});

test('P0.9 charts use graphite canvas contrast but preserve real aggregations', () => {
  const charts = read('src/components/results/OverviewCharts.jsx');
  assert.match(charts, /const GRID = '#494951'/);
  assert.match(charts, /agg\.byCwe/);
  assert.match(charts, /agg\.byDecision/);
  assert.match(charts, /agg\.byFlowProof/);
  assert.match(charts, /agg\.byScore/);
});

test('P0.8 has no backend service or scoring changes', () => {
  const app = read('src/App.jsx');
  assert.match(app, /<Route path="\/scanner" element=\{<ScannerRoute \/>\}/);
  assert.match(app, /<Route path="\/finding\/:id" element=\{<FindingDetail \/>\}/);
});
