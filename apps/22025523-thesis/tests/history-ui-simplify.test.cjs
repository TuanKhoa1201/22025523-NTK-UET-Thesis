const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const file = (name) => fs.readFileSync(path.join(__dirname, '..', name), 'utf8');

test('history source shows real GitHub URL or ZIP filename, never fabricates a URL', async () => {
  const {displaySource} = await import('../src/services/historyPresentation.js');
  const gh = displaySource({inputMode:'GITHUB_REPOSITORY_URL', repoUrl:'https://github.com/WebGoat/WebGoat.git'});
  assert.equal(gh.type,'GitHub');
  assert.equal(gh.href,'https://github.com/WebGoat/WebGoat.git');
  const zip = displaySource({inputMode:'JAVA_ZIP_ARCHIVE_UPLOAD',fileName:'example.zip'});
  assert.equal(zip.type,'ZIP');assert.equal(zip.value,'example.zip');assert.equal(zip.href,null);
  assert.equal(displaySource({inputMode:'ZIP'}).type,'ZIP');
  assert.equal(displaySource({inputMode:'GITHUB',repoUrl:'javascript:alert(1)'}).href,null);
  assert.equal(displaySource({inputMode:'GITHUB',repoUrl:'https://not-github.example/test'}).href,null);
  assert.equal(displaySource({}).type,'Chưa xác định');
});

test('duration and date helpers guard against missing values or malformed data', async () => {
  const {formatExecutionTime,formatScanTime} = await import('../src/services/historyPresentation.js');
  assert.equal(formatExecutionTime(612727),'10 phút 13 giây');
  assert.equal(formatExecutionTime(296091),'4 phút 56 giây');
  assert.equal(formatExecutionTime(0),'0 giây');
  assert.equal(formatExecutionTime(null),'-');
  assert.equal(formatExecutionTime(-100),'-');
  assert.equal(formatScanTime('not-a-date'),'-');
  assert.match(formatScanTime('2026-11-02T11:44:57Z'),/2026/);
});

test('all history cards show primary information without exposing technical scan IDs', () => {
  const history = file('src/pages/HistoryPage.jsx');
  const row = history.split('function Row(')[1].split('function ConfirmHide(')[0];
  for (const text of ['formatScanTime(record.startedAt)','formatScanTime(record.completedAt)','formatExecutionTime(record.backendMs)','displaySource(record)','history-time-grid','history-source-link']) {
    assert(row.includes(text),`Expected card field: ${text}`);
  }
  assert(!row.includes('record.restoration && <Badge'));
  assert(!row.includes('record.commit.slice'));
  assert(!row.includes('<h3 className="mono">{record.scanId}</h3>'));
  assert(!row.includes('record.candidates'));
  assert(!row.includes('record.verification'));
  assert.match(row,/\/findings\$\{scanQuery\(record\.scanId\)\}/);
  assert.match(row,/\/reports\$\{scanQuery\(record\.scanId\)\}/);
  assert.match(row,/\/replay\?scan=/);
  assert(!history.includes('Danh sách scan được nạp từ backend khi API hỗ trợ'));
  assert(!history.includes('localStorage chỉ là cache'));
  assert(!history.includes('LIVE_OR_FULL_PERSISTED_SCAN'));
});

test('requested report and architecture text removed but report export and architecture retained', () => {
  const reports = file('src/pages/UtilityPages.jsx');
  const arch = file('src/pages/Architecture.jsx');
  for (const text of ['Lịch sử và bản xuất báo cáo sẽ lấy từ backend khi API report sẵn sàng.', 'Chưa có phiên phân tích thực để hiển thị. Nút xuất được bật khi có dữ liệu demo.']) assert(!reports.includes(text));
  assert.match(reports,/api\.report\(/);
  assert.match(reports,/Chọn phiên phân tích/);
  for (const text of ['Hai giai đoạn nghiên cứu và vận hành được tách biệt;', 'REPORT là trạng thái ưu tiên theo policy,']) assert(!arch.includes(text));
  assert.match(arch,/architecture-explorer/);
});

test('training and evaluation pages removed from routing and nav without deleting research files', () => {
  const app = file('src/App.jsx');
  const nav = file('src/data/research.js');
  const overview = file('src/pages/Overview.jsx');
  for (const route of ['/training','/evaluation']) {
    assert(!app.includes(`path="${route}"`));
    assert(!nav.includes(`'${route}'`));
    assert(!overview.includes(`to="${route}"`));
  }
  assert.match(overview,/to="\/dataset"/);
  assert(fs.existsSync(path.join(__dirname,'../src/pages/ResearchPages.jsx')));
});
