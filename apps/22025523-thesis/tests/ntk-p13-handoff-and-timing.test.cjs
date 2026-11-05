const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {test} = require('node:test');
const {pathToFileURL} = require('node:url');
const {createHash} = require('node:crypto');

const root = path.resolve(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root,name),'utf8');
const source = pathToFileURL(path.join(root,'src/components/scanner/liveStagePresentation.js')).href;

function live(partial={}) {
  return {
    stage:'RUNNING',state:'RUNNING',activeStage:10,publicationState:'PERSISTING_RESULTS',
    stages:[{stage_number:10,state:'COMPLETED',duration_ms:15.639}],
    resultsReady:false,...partial
  };
}

test('stage 10 remains in progress while backend saves the scan even if stage telemetry says completed', async () => {
  const {backendStageStatus,isLiveSessionReady} = await import(source);
  const persisting = live();
  assert.equal(isLiveSessionReady(persisting),false);
  assert.equal(backendStageStatus(9,persisting),'Đang hoàn tất phiên quét');
  assert.doesNotMatch(backendStageStatus(9,persisting),/Hoàn thành|15[.,]639/);
  assert.equal(backendStageStatus(9,live({stage:'LOADING_RESULTS',state:'COMPLETED'})),'Đang xác nhận kết quả');
  assert.equal(backendStageStatus(9,live({stage:'RESULTS_ERROR',state:'COMPLETED'})),'Chưa thể xác nhận kết quả');
});

test('only confirmed whole-job completion with loaded results completes stage 10', async () => {
  const {backendStageStatus,isLiveSessionReady} = await import(source);
  const pending = live({stage:'COMPLETED',state:'COMPLETED',resultsReady:false});
  assert.equal(isLiveSessionReady(pending),false);
  assert.equal(backendStageStatus(9,pending),'Đang xác nhận kết quả');
  const completed = live({stage:'COMPLETED',state:'COMPLETED',resultsReady:true});
  assert.equal(isLiveSessionReady(completed),true);
  assert.match(backendStageStatus(9,completed),/^Hoàn thành · 15[.,]639 ms$/);
  const failed = live({stage:'FAILED',state:'FAILED',resultsReady:false});
  assert.equal(isLiveSessionReady(failed),false);
  assert.doesNotMatch(backendStageStatus(9,failed),/^Hoàn thành/);
  assert.equal(backendStageStatus(9,live({activeStage:9,publicationState:'',stages:[]})),'Chưa bắt đầu');
});

test('previous pipeline stages preserve their actual backend status and durations', async () => {
  const {backendStageStatus} = await import(source);
  assert.match(backendStageStatus(0,live({stages:[{stage_number:1,state:'COMPLETED',duration_ms:0}]})),/^Hoàn thành · 0[.,]000 ms$/);
  assert.equal(backendStageStatus(4,live({stages:[{stage_number:5,state:'SKIPPED',reason:'no candidates'}]})),'Bỏ qua · no candidates');
  assert.equal(backendStageStatus(4,live({activeStage:5,stages:[]})),'Đang thực thi');
});

test('Scanner waits for matching findings before marking the 10-step UI complete or stopping the clock', () => {
  const file=read('src/pages/Scanner.jsx');
  const start=file.indexOf("if (state === 'COMPLETED') {");
  const setReady=file.indexOf("setLiveStage('COMPLETED');",start);
  const fetch=file.indexOf('await loadLiveScan(job.scan_id',start);
  const clockStopped=file.indexOf('window.clearInterval(timerRef.current);',fetch);
  assert.ok(start>=0 && start<fetch && fetch<clockStopped && clockStopped<setReady);
  assert.match(file,/resultsReady:\s*liveStage === 'COMPLETED'/);
  assert.match(file,/publicationState:\s*liveJob\?\.publication_state/);
  assert.match(file,/setLiveStage\('RESULTS_ERROR'\)/);
  assert.match(file,/Resume the elapsed clock after a page reload/);
});

test('P0.13 UET favicon has an actual transparent exterior and preserves the original official logo', () => {
  const logo=fs.readFileSync(path.join(root,'public/uet-logo-original.png'));
  assert.equal(createHash('sha256').update(logo).digest('hex'),
    'e5d475d3ac57bace5559eb903cb18c8835f7ff9bc7251b5b391cb66a6f8911ca');
  for (const name of ['favicon-32x32.png','uet-icon-192.png','uet-icon-512.png','apple-touch-icon.png']) {
    const png=fs.readFileSync(path.join(root,'public',name));
    assert.equal(png.subarray(1,4).toString(),'PNG');
    assert.equal(png[25],6,`Expected true RGBA PNG: ${name}`);
  }
  assert.match(read('index.html'),/favicon\.ico\?v=p13/);
  assert.match(read('index.html'),/favicon-32x32\.png\?v=p13/);
  assert.match(read('index.html'),/<title>22025523 - Phân tích bảo mật mã nguồn<\/title>/);
  assert.match(read('public/manifest.webmanifest'),/uet-icon-512\.png\?v=p13/);
});
