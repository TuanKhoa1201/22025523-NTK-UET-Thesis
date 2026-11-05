const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {pathToFileURL} = require('node:url');

const root = path.join(__dirname, '..');
const page = fs.readFileSync(path.join(root, 'src/pages/Results.jsx'), 'utf8');
const styles = fs.readFileSync(path.join(root, 'src/styles/ntk-p06.css'), 'utf8');
const routes = fs.readFileSync(path.join(root, 'src/App.jsx'), 'utf8');
const helpers = import(pathToFileURL(path.join(root, 'src/services/findingPresentation.js')).href);

test('four supported CWE categories use clear Vietnamese labels without inventing a finding', async () => {
  const {getCweGuide} = await helpers;
  const expected = [
    ['CWE-022', 'CWE-22', 'Truy cập đường dẫn'],
    ['CWE-078', 'CWE-78', 'chèn lệnh'],
    ['CWE-079', 'CWE-79', 'chèn mã'],
    ['CWE-089', 'CWE-89', 'SQL']
  ];
  for (const [input, code, keyword] of expected) {
    const info = getCweGuide(input);
    assert.equal(info.code, code);
    assert.ok(info.title.includes(keyword), input);
    assert.ok(info.suggestion.length > 10);
  }
  assert.equal(getCweGuide('CWE-999').title, 'Cảnh báo cần kiểm tra');
});

test('CWSS permits valid 0 and 100, but never turns null or strings into scores', async () => {
  const {validCwssScore} = await helpers;
  assert.equal(validCwssScore({cwss_score: 0}), 0);
  assert.equal(validCwssScore({cwss_score: 100}), 100);
  for (const value of [null, undefined, '', '67.1', NaN, -1, 101, Infinity]) {
    assert.equal(validCwssScore({cwss_score: value}), null);
  }
});

test('absence of IRIS proof and API roles is never presented as safe', async () => {
  const {irisDescription, roleDescription} = await helpers;
  assert.equal(irisDescription({}), null);
  assert.equal(roleDescription({}), null);
  assert.match(irisDescription({iris_proof: 'UNKNOWN'}).text, /Chưa đủ bằng chứng/);
  assert.match(irisDescription({iris_proof: 'PROVEN_SAFE'}).text, /trong phạm vi phân tích/);
  assert.match(roleDescription({llm_api_role: {predicted_role: 'sink'}}).text, /Điểm sử dụng dữ liệu/);
});

test('the UI extracts only real code excerpts and respects source path separators', async () => {
  const {sourceSnippet, fileName, findReportedId} = await helpers;
  assert.equal(sourceSnippet({}), '');
  assert.equal(sourceSnippet({matched_code: 'String query = userInput;'}), 'String query = userInput;');
  assert.equal(fileName('src\\main\\java\\Users.java'), 'Users.java');
  assert.equal(findReportedId({finding: {finding_id: 'FINDING-002'}}), 'FINDING-002');
});

test('triage captions express priority and never claim expert TP or FP', async () => {
  const {triageExplanation} = await helpers;
  assert.match(triageExplanation('REPORT'), /Ưu tiên kiểm tra/);
  assert.match(triageExplanation('REVIEW'), /xem xét thêm/);
  assert.match(triageExplanation('SUPPRESS'), /không đồng nghĩa/);
});

test('live detail loads matching finding, scenario and baseline independently', () => {
  for (const expected of [
    'api.findingDetail(scanId,id,detailUrl,{signal})',
    'api.cwssV2Finding(scanId,id,{signal})',
    'api.cwssV2ScenarioFinding(scanId,id,{signal})',
    'returnedId!==id',
    'scenarioState.data?.finding_id===id',
    "scenarioState.data?.reference_profile==='BUSINESS_CRITICAL_INTERNET_FACING'",
    '<LiveDetailPage key={`${scanId}:${id}`}'
  ]) assert.ok(page.includes(expected), expected);
  assert.match(page, /score===null \? <strong/);
  assert.match(page, /validCwssScore\(referenceScore\)/);
});

test('technical scoring evidence stays accessible but collapsed by default', () => {
  assert.match(page, /<details className="ntk-p06-technical">/);
  assert.match(page, /Object\.entries\(referenceScore\.metric_assessments \|\| \{\}\)/);
  assert.match(page, /source_provenance_record:flat\?\.source_provenance_record/);
  assert.match(page, /baseline_general_java:baseline/);
  assert.match(page, /Quay lại kết quả/);
  assert.doesNotMatch(page, /Back to list/);
  assert.match(styles, /@media \(max-width: 740px\)/);
  assert.match(routes, /import '\.\/styles\/ntk-p06\.css'/);
});
