const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {pathToFileURL} = require('node:url');

const root = path.join(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');
const page = read('src/pages/Results.jsx');
const styles = read('src/styles/ntk-p06.css');
const findingHelpers = import(pathToFileURL(path.join(root, 'src/services/findingPresentation.js')).href);
const metrics = import(pathToFileURL(path.join(root, 'src/services/cwssPresentation.js')).href);

test('IRIS card recognizes real nested taint-flow evidence in the reported Java finding', async () => {
  const {irisDescription} = await findingHelpers;
  const source = {
    iris_proof: 'UNKNOWN',
    iris_evidence: {
      ast_parser_engine: 'OPENJDK17_JAVAC_TASK_AST',
      source_sink_trace_status: 'VERIFIED_TAINT_FLOW',
      flow_proof_state: 'PROVEN_TAINT',
      taint_reaches_sink: true,
      target_callee_identity: {class: 'Runtime', method: 'exec'}
    }
  };
  const got = irisDescription(source);
  assert.equal(got.code, 'PROVEN_TAINT');
  assert.match(got.text, /dữ liệu đầu vào/);
  assert.match(got.detail, /Runtime\.exec/);
  assert.match(got.origin, /javac\/AST/);
  assert.match(got.origin, /không tự coi là IRIS gốc/);
  assert.doesNotMatch(got.text, /đã khai thác thành công/);
});

test('IRIS handles proof in trace status when high-level proof is missing', async () => {
  const {irisDescription} = await findingHelpers;
  const got = irisDescription({iris_evidence: {source_sink_trace_status:'VERIFIED_TAINT_FLOW', taint_reaches_sink:true}});
  assert.equal(got.code,'PROVEN_TAINT');
  assert.ok(got.detail);
});

test('IRIS never fabricates proof from a missing or incomplete record', async () => {
  const {irisDescription} = await findingHelpers;
  assert.equal(irisDescription({}),null);
  assert.equal(irisDescription({iris_evidence:{}}),null);
  assert.match(irisDescription({iris_proof:'UNKNOWN'}).text, /Chưa đủ bằng chứng/);
  assert.match(irisDescription({iris_evidence:{taint_reaches_sink:false}}).detail,/Chưa thấy dữ liệu/);
});

test('contradictory IRIS proof is shown as inconsistent instead of trusted', async () => {
  const {irisDescription} = await findingHelpers;
  const got = irisDescription({iris_proof:'PROVEN_SAFE', iris_evidence:{flow_proof_state:'PROVEN_TAINT'}});
  assert.equal(got.code,'CONFLICT');
  assert.match(got.text,/chưa thống nhất/);
  const conflictingTrace = irisDescription({iris_evidence:{flow_proof_state:'PROVEN_TAINT',taint_reaches_sink:false}});
  assert.equal(conflictingTrace.code,'CONFLICT');
});

test('all 16 MITRE CWSS factors have meaningful Vietnamese titles and explanations', async () => {
  const {metricTitle,metricExplanation} = await metrics;
  const names = ['TI','AP','AL','IC','FC','RP','RL','AV','AS','IN','SC','BI','DI','EX','EC','P'];
  for (const name of names) {
    assert.notEqual(metricTitle(name),'Chỉ số CWSS');
    assert.ok(metricExplanation(name,{code:'D'}).length>40);
  }
  assert.match(metricExplanation('TI',{code:'H'}),/cao/);
  assert.match(metricExplanation('AV',{code:'I'}),/Internet/);
  assert.match(metricExplanation('P',{code:'NA'}),/không áp dụng/);
});

test('known CWSS reasons are explained in simple Vietnamese, not raw English', async () => {
  const {metricExplanation} = await metrics;
  assert.match(metricExplanation('TI', {code:'H',classification:'VERIFIED',reason:'Explicit shell command capability'}),/gọi lệnh của hệ điều hành/);
  assert.match(metricExplanation('AL', {code:'S',classification:'ESTIMATED',reason:'Conditional compromise layer from sink semantics, not acquired privilege level'}),/chưa xác nhận quyền thực tế/);
  assert.match(metricExplanation('FC', {code:'D',classification:'MITRE_DEFAULT',reason:'Official Default is not proof, including FC:D'}),/không xác nhận cảnh báo là đúng/);
  assert.match(metricExplanation('AP', {code:'RU',classification:'REFERENCE_ASSUMPTION',reason:'SYNTHETIC SCENARIO-CONDITIONAL: critical online transaction service'}),/chưa kiểm chứng tại nơi triển khai/);
  assert.match(metricExplanation('P', {code:'NA',classification:'NOT_APPLICABLE',reason:'Prevalence excluded for targeted individual finding'}),/một cảnh báo cụ thể/);
});

test('factor weight is taken from backend and missing values are not invented', async () => {
  const {metricWeight} = await metrics;
  assert.equal(metricWeight({weight:0}),'0,00');
  assert.equal(metricWeight({weight:1}),'1,00');
  assert.equal(metricWeight({weight:0.9}),'0,90');
  assert.equal(metricWeight({weight:'0.6'}),'0,60');
  for (const weight of [null,undefined,'',-1,1.1,NaN,Infinity,'not a number']) {
    assert.equal(metricWeight({weight}),'-');
  }
  assert.equal(metricWeight({code:'H'}),'-');
});

test('technical classification is translated without pretending assumed values are verified', async () => {
  const {metricSource} = await metrics;
  assert.equal(metricSource({classification:'REFERENCE_ASSUMPTION'}),'Điều kiện tham chiếu');
  assert.equal(metricSource({classification:'MITRE_DEFAULT'}),'Mặc định của MITRE');
  assert.equal(metricSource({classification:'VERIFIED'}),'Có căn cứ từ phân tích mã');
  assert.equal(metricSource({classification:'anything-unknown'}),'Nguồn chưa được phân loại');
});

test('detail UI contains exactly the requested compact copy and new numeric factor column', () => {
  assert.doesNotMatch(page, /<SectionTitle title="Bằng chứng phân tích"/);
  assert.match(page, /iris_evidence:flat\?\.iris_evidence/);
  assert.match(page, /llm_api_role:flat\?\.llm_api_role/);
  assert.match(page, /<th>Trọng số<\/th>/);
  assert.match(page, /metricWeight\(m\)/);
  assert.match(page, /metricExplanation\(name,m\)/);
  assert.match(page, /<strong className="ntk-p06-guidance-label">\{guide\.code\}:<\/strong>/);
  assert.doesNotMatch(page, /Gợi ý chung cho/);
  assert.doesNotMatch(page, /không dùng thay điểm chính/);
  assert.doesNotMatch(page, /CWSS được backend tính theo hồ sơ BUSINESS_CRITICAL_INTERNET_FACING/);
  assert.match(styles,/\.ntk-p07-metric-weight/);
});
