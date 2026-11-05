const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('P0.11 optical contrast loads last, after P0.9 and P0.10', () => {
  const entry = read('src/main.jsx');
  const p09 = entry.indexOf('ntk-p09-monochrome.css');
  const p10 = entry.indexOf('ntk-p10-sharpness.css');
  const p11 = entry.indexOf('ntk-p11-optical-contrast.css');
  assert.ok(p09 >= 0 && p10 > p09 && p11 > p10);
  assert.equal(entry.match(/ntk-p11-optical-contrast\.css/g)?.length, 1);
});

test('P0.11 has a local vector with narrow pure-white rims and a contained halo', () => {
  const svg = read('public/ntk-p11-specular-waves.svg');
  assert.match(svg, /<svg[\s\S]+viewBox="0 0 1600 1100"/);
  assert.match(svg, /Optical razor-white glints/);
  assert.match(svg, /feGaussianBlur stdDeviation="5"/);
  assert.match(svg, /stroke-width="1\.75"/);
  assert.match(svg, /stop-color="#fff" stop-opacity="\.98"/);
  assert.doesNotMatch(svg, /<script|(?:href|xlink:href)=["']https?:/i);
});

test('P0.11 darkens the underlying canvas without changing layout or content', () => {
  const css = read('src/styles/ntk-p11-optical-contrast.css');
  assert.match(css, /\.main-area::before/);
  assert.match(css, /url\('\/ntk-p11-specular-waves\.svg'\)/);
  assert.match(css, /\.app-shell:has\(\.hero\) \.main-area::before/);
  assert.match(css, /\.hero-visual/);
  assert.match(css, /\.pillar-card/);
  assert.match(css, /focus|\.nav-item\.active/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(css, /@media print/);
  assert.doesNotMatch(css, /#(?:0ea5e9|38bdf8|a78bfa|818cf8|7dd3fc)/i);
  assert.doesNotMatch(css, /https?:\/\//i);
  // The patch is a purely decorative layer: all existing React pages remain in P0.10.
  const app = read('src/App.jsx');
  for (const route of ['/scanner', '/history', '/findings', '/reports', '/finding/:id']) {
    assert.ok(app.includes(`path="${route}"`));
  }
});

test('the original supplied full-color UET identity is preserved byte-for-byte', () => {
  const logo = fs.readFileSync(path.join(root, 'public/uet-logo-original.png'));
  const sha256 = crypto.createHash('sha256').update(logo).digest('hex');
  assert.equal(sha256, 'e5d475d3ac57bace5559eb903cb18c8835f7ff9bc7251b5b391cb66a6f8911ca');
  assert.match(read('src/styles/ntk-p11-optical-contrast.css'), /filter:\s*none\s*!important/);
  assert.match(read('src/components/common/UETLogo.jsx'), /uet-logo-original\.png/);
});
