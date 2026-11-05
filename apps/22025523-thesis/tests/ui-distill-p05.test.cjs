const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const src = (relative) => fs.readFileSync(path.join(__dirname, '..', 'src', relative), 'utf8');

const findings = src('components/results/FindingsExplorer.jsx');
const dataset = src('pages/DatasetExplorer.jsx');
const architecture = src('pages/Architecture.jsx');
const utility = src('pages/UtilityPages.jsx');
const app = src('App.jsx');
const nav = src('data/research.js');

// These are non-visual guards for the local P0.5 frontend. Live E2E requires backend.
test('finding filters expose the full supported CWE scope, every triage class and IRIS proof states', () => {
  assert.match(findings, /IN_SCOPE_CWES/);
  assert.match(findings, /\['REPORT', 'REVIEW', 'SUPPRESS'\]/);
  assert.match(findings, /IRIS_PROOF_STATES/);
  for (const key of ["'cwe'", "'decision'", "'proofState'", "'sort'"]) assert.ok(findings.includes(key), key);
  assert.match(findings, /countOf\(rows, 'cwe', value\)/);
  assert.match(findings, /countOf\(rows, 'decision', value\)/);
  assert.match(findings, /countOf\(rows, 'irisProofState', value\)/);
  assert.match(findings, /Không tìm thấy cảnh báo phù hợp/);
  assert.doesNotMatch(findings, /placeholder="CWSS (từ|đến)"/);
  assert.doesNotMatch(findings, /Mức scanner phản ánh độ nghiêm trọng của rule/);
});

test('finding sort is readable and CWSS remains backend-derived, including legitimate numeric zero', () => {
  for (const text of ['Điểm CWSS: cao đến thấp', 'Điểm CWSS: thấp đến cao', 'Theo tên tệp', 'Theo mã cảnh báo']) {
    assert.ok(findings.includes(text), text);
  }
  assert.match(findings, /scores\.get\(row\.id\)/);
  assert.match(findings, /score === undefined \? 'Chưa có'/);
  assert.match(findings, /toFixed\(1\)/);
  assert.match(findings, /scanQuery\(scanId\)/);
});

test('architecture uses two readable stage layouts while retaining clickable system components', () => {
  assert.match(architecture, /workflows\.map/);
  assert.match(architecture, /ntk-p05-workflow-steps/);
  assert.match(architecture, /workflow\.steps\.map/);
  assert.match(architecture, /architecture-selector/);
  assert.match(architecture, /setSelected\(index\)/);
  assert.match(src('styles/ntk-p05.css'), /\.ntk-p05-workflow-steps/);
});

test('research dataset page is simplified without removing manifest, page API or export', () => {
  assert.match(dataset, /api\.datasetManifest/);
  assert.match(dataset, /api\.datasetRecords\(datasetId, params/);
  assert.match(dataset, /api\.datasetExport\(datasetId, format\)/);
  assert.match(dataset, /\['csv', 'jsonl', 'xlsx'\]/);
  assert.match(dataset, /\.row_count/);
  assert.match(dataset, /<details className="ntk-p05-distribution">/);
  for (const text of ['Fine-tuning provenance', 'Quality gate summary', 'Manifest, bản ghi phân trang',
    'Backend xác nhận Track A nằm trong Track B', 'Track A subset: tất cả', 'Chỉ Track A gold', 'Ngoại trừ Track A gold',
    'placeholder="Split"', 'placeholder="Provenance tier"', 'training_eligibility_status', 'sha256_verified']) {
    assert.ok(!dataset.includes(text), text);
  }
  assert.match(dataset, /const params = \{page, page_size: pageSize, q: debouncedQuery, cwe, role\};/);
});

test('review pager is readable and still uses backend pagination, not synthetic data', () => {
  assert.match(utility, /ntk-p05-review-pagination/);
  assert.match(utility, /Trang <strong>\{page\}<\/strong>/);
  assert.match(utility, /\{showNum\(matching\)\} cảnh báo/);
  assert.match(utility, /api\.findingsPage\(scanId,page,REVIEW_PAGE_SIZE/);
});

test('status route and nav are hidden, thesis title is exact and disclaimer removed', () => {
  assert.doesNotMatch(nav, /\['\/status',/);
  assert.doesNotMatch(app, /path="\/status"/);
  assert.doesNotMatch(app, /import StatusPage/);
  assert.ok(fs.existsSync(path.join(__dirname, '..', 'src', 'pages', 'StatusPage.jsx')));
  assert.match(utility, /Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn\./);
  assert.doesNotMatch(utility, /Website giới thiệu sản phẩm đồ án; không phải cổng thông tin chính thức của nhà trường/);
});
