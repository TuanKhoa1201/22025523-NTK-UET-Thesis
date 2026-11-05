const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const scanner = read('src/pages/Scanner.jsx');
const replay = read('src/pages/TraceReplay.jsx');
const detail = read('src/pages/Results.jsx');
const css = read('src/styles/ntk-p15-layout-cleanup.css');
const entry = read('src/main.jsx');

test('P0.15 scanner input is a single accessible GitHub field with compact advanced options', () => {
  assert.match(scanner, /ntk-p15-repo-section/);
  assert.match(scanner, /htmlFor="repo-url"/);
  assert.match(scanner, /id="repo-url"/);
  assert.match(scanner, /aria-describedby="repo-url-help"/);
  assert.match(scanner, /ntk-p15-repo-input/);
  assert.match(scanner, /ntk-p15-advanced-title/);
  assert.match(scanner, /ntk-p15-fresh-option/);
  assert.match(scanner, /checked=\{forceFresh\} disabled=\{busy\}/);
  assert.match(css, /\.ntk-p15-repo-input:focus-within/);
  assert.match(css, /\.ntk-p15-advanced\[open\]/);
});

test('P0.15 does not change scan backend contract, ZIP path or progress', () => {
  assert.match(scanner, /api\.createScanJob\(url\.trim\(\), undefined, \{signal:controller\.signal\}, \{/);
  assert.match(scanner, /scan_scope_policy: 'STRICT_FAIL_ON_LIMIT'/);
  assert.match(scanner, /force_fresh_scan:true,force_new_job:true/);
  assert.match(scanner, /api\.createZipJob\(file, \{signal:controller\.signal\}\)/);
  assert.match(scanner, /<SecurityAnalysisScene live=/);
});

test('P0.15 removes only two replay messages and groups controls into a spaced toolbar', () => {
  assert.doesNotMatch(replay, /Recorded Replay: chỉ đọc trace/);
  assert.doesNotMatch(replay, /Thời gian phát lại chỉ là thời lượng trình diễn/);
  assert.doesNotMatch(replay, /DataNotice/);
  assert.match(replay, /role="toolbar" aria-label="Điều khiển phát lại"/);
  assert.match(replay, /ntk-p15-replay-transport/);
  assert.match(replay, /ntk-p15-replay-speed/);
  assert.match(replay, /\[0\.5, 1, 2\]\.map/);
  assert.match(css, /margin: 24px 0 24px/);
  assert.match(css, /@media \(max-width: 560px\)/);
});

test('P0.15 replay still uses backend trace and preserves play, step and speed controls', () => {
  assert.match(replay, /api\.pipelineTrace\(scanId, \{signal: controller\.signal\}\)/);
  assert.match(replay, /onClick=\{\(\) => setPlaying\(\(value\) => !value\)\}/);
  assert.match(replay, /disabled=\{index === 0\}/);
  assert.match(replay, /disabled=\{index === 9\}/);
  assert.match(replay, /onClick=\{\(\) => setIndex\(index \+ 1\)\}/);
  assert.match(replay, /<ScanStageVisual step=\{step\}/);
});

test('P0.15 hides the finding analysis card section but retains raw evidence and CWSS audit data', () => {
  assert.doesNotMatch(detail, /<SectionTitle title="Bằng chứng phân tích"/);
  assert.doesNotMatch(detail, /ntk-p06-evidence-grid/);
  assert.match(detail, /sourceSnippet\(flat\)/);
  assert.match(detail, /iris_evidence:flat\?\.iris_evidence/);
  assert.match(detail, /llm_api_role:flat\?\.llm_api_role/);
  assert.match(detail, /source_provenance_record:flat\?\.source_provenance_record/);
  assert.match(detail, /referenceScore\.metric_assessments/);
  assert.match(detail, /api\.findingDetail\(scanId,id,detailUrl,\{signal\}\)/);
});

test('P0.15 runtime interface contains no typographic long dashes, with theme imported last', () => {
  const bad = [];
  const walk = (dir) => {
    for (const item of fs.readdirSync(dir, {withFileTypes: true})) {
      const full = path.join(dir,item.name);
      if (item.isDirectory()) walk(full);
      else if (/\.(jsx|js|css|html)$/.test(item.name) && /[\u2013\u2014]/.test(fs.readFileSync(full,'utf8'))) bad.push(full);
    }
  };
  walk(path.join(root,'src'));
  if (/[\u2013\u2014]/.test(read('index.html'))) bad.push('index.html');
  assert.deepEqual(bad, []);
  assert.ok(entry.indexOf('ntk-p15-layout-cleanup.css') > entry.indexOf('ntk-p14-frontend-polish.css'));
  assert.match(css, /prefers-reduced-motion/);
});
