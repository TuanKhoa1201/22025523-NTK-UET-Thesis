const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const overview = fs.readFileSync(path.join(__dirname, '../src/pages/Overview.jsx'), 'utf8');
const scanner = fs.readFileSync(path.join(__dirname, '../src/pages/Scanner.jsx'), 'utf8');

const obsoleteOverview = [
  'Công cụ hỗ trợ phân tích — kết luận cần được xem xét theo bằng chứng',
  'Backend: CONNECTED',
  'Ba nguồn tín hiệu. Một kết luận có thể giải thích.',
  'Không có thành phần đơn lẻ nào được xem là bằng chứng tuyệt đối.',
  'Hai giai đoạn riêng biệt, cùng hướng tới kết quả phân tích có căn cứ.',
  'Thống kê chỉ bao phủ các bản ghi backend có thể truy xuất; không mặc định là tổng lifetime.'
];

test('overview removes recent-activity cards and obsolete API requests while keeping navigation', () => {
  for (const phrase of obsoleteOverview) assert(!overview.includes(phrase), `Obsolete copy: ${phrase}`);
  assert.match(overview, /<Link to="\/scanner" className="button-primary"/);
  assert.doesNotMatch(overview, /fetchOverviewStats|listScanJobs|listScans|StatCard/);
  assert.ok(!overview.includes('Ho\u1ea1t \u0111\u1ed9ng g\u1ea7n \u0111\u00e2y'));
  assert.match(overview, /<SectionTitle title="Công nghệ phân tích"/);
  assert.match(overview, /<SectionTitle title="Nghiên cứu và vận hành"/);
});

test('scanner removes four optional fields and preserves standard strict scan contract', () => {
  for (const id of ['git-ref', 'target-subpath', 'max-java-files', 'scan-scope-policy']) {
    assert(!scanner.includes(`id="${id}"`), `Unexpected advanced field: ${id}`);
  }
  assert.match(scanner, /api\.createScanJob\(url\.trim\(\), undefined, \{signal:controller\.signal\}, \{/);
  assert.match(scanner, /scan_scope_policy: 'STRICT_FAIL_ON_LIMIT'/);
  assert.doesNotMatch(scanner, /max_files_limit:Number\(maxFiles\)/);
  assert.match(scanner, /force_fresh_scan:true,force_new_job:true/);
  assert.match(scanner, /<summary><span className="ntk-p15-advanced-title">.*Tùy chọn kiểm thử<\/span>/);
});

test('scanner keeps ZIP and backend 10-stage progress without revealing raw idle state', () => {
  assert.match(scanner, /api\.createZipJob\(file, \{signal:controller\.signal\}\)/);
  assert.match(scanner, /<SecurityAnalysisScene live=/);
  assert.match(scanner, /<StageOverview job=\{liveJob\} \/>/);
  assert.match(scanner, /<summary>Thông tin kỹ thuật phiên quét<\/summary>/);
  assert.match(scanner, /<StageTiming job=\{liveJob\} counts=\{liveCounts\} \/>/);
  assert.match(scanner, /<CoveragePanel job=\{liveJob\} counts=\{liveCounts\} \/>/);
  assert.doesNotMatch(scanner, /Trạng thái vòng đời:/);
  assert.doesNotMatch(scanner, /Phiên phân tích trực tiếp/);
  assert.doesNotMatch(scanner, /Phạm vi và tính minh bạch/);
  assert.doesNotMatch(scanner, /đo tại trình duyệt, không phải thời gian thực thi backend/);
});
