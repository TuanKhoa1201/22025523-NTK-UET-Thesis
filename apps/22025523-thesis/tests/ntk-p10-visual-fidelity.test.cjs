const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = path.resolve(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');

test('P0.10 clarity stylesheet is last, preserving P0.9 and all application routes', () => {
  const main = read('src/main.jsx');
  const p09 = main.indexOf("import './styles/ntk-p09-monochrome.css';");
  const p10 = main.indexOf("import './styles/ntk-p10-sharpness.css';");
  assert.ok(p09 >= 0 && p10 > p09);
  assert.equal(main.split('ntk-p10-sharpness.css').length - 1, 1);
  const app = read('src/App.jsx');
  for (const route of ['/scanner','/history','/finding/:id','/findings','/reports']) {
    assert.ok(app.includes(`path="${route}"`), `Missing route ${route}`);
  }
});

test('UET logo uses the exact user-provided color image locally, without grayscale', () => {
  const logo = read('src/components/common/UETLogo.jsx');
  const css = read('src/styles/ntk-p10-sharpness.css');
  assert.match(logo, /BASE_URL\}uet-logo-original\.png/);
  assert.doesNotMatch(logo, /https?:\/\//);
  assert.match(css, /\.uet-image-tile img/);
  assert.match(css, /filter:\s*none\s*!important/);
  const asset = fs.readFileSync(path.join(root,'public/uet-logo-original.png'));
  assert.equal(asset.subarray(0,8).toString('hex'), '89504e470d0a1a0a');
  const sha = crypto.createHash('sha256').update(asset).digest('hex');
  assert.equal(sha, 'e5d475d3ac57bace5559eb903cb18c8835f7ff9bc7251b5b391cb66a6f8911ca');
});

test('history buttons appear as equal two-by-two actions with all original destinations', () => {
  const jsx = read('src/pages/HistoryPage.jsx');
  const css = read('src/styles/ntk-p10-sharpness.css');
  for (const token of [
    'history-action--results', 'history-action--report',
    'history-action--trace', 'history-action--hide'
  ]) assert.ok(jsx.includes(token) && css.includes(token), `${token} missing`);
  assert.match(css, /grid-template-columns:\s*repeat\(2,\s*minmax\(0,\s*1fr\)\)/);
  assert.match(jsx, /data-trace-only=\{traceOnly/);
  assert.match(jsx, /\/findings\$\{scanQuery\(record\.scanId\)\}/);
  assert.match(jsx, /\/reports\$\{scanQuery\(record\.scanId\)\}/);
  assert.match(jsx, /\/replay\?scan=\$\{encodeURIComponent\(record\.scanId\)\}/);
  assert.match(jsx, /disabled=\{running\}/);
  assert.match(jsx, /onClick=\{\(\) => onDelete\(record\)\}/);
});

test('P0.10 improves typography without neon colors, changing data or adding services', () => {
  const css = read('src/styles/ntk-p10-sharpness.css');
  assert.match(css, /\.hero h1/);
  assert.match(css, /text-shadow:\s*none/);
  assert.match(css, /font-synthesis:\s*none/);
  assert.match(css, /focus-visible/);
  assert.match(css, /prefers-reduced-motion/);
  assert.doesNotMatch(css, /#(?:0ea5e9|38bdf8|a78bfa|818cf8|7dd3fc)/i);
  assert.doesNotMatch(css, /https?:\/\//);
});
