const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

function history(){
  const storage=new Map();
  const source=fs.readFileSync(path.join(__dirname,'../src/services/scanHistory.js'),'utf8')
    .replace(/^import .*\n/gm,'').replace(/^export /gm,'');
  const sandbox={readScanHistory:()=>[],removeScanRecord:()=>{},window:{localStorage:{
    getItem:key=>storage.get(key)||null,setItem:(key,value)=>storage.set(key,value)}}};
  vm.createContext(sandbox);vm.runInContext(source+'\nglobalThis.api={historyRecordFromBackend,upsertHistory,readHistory,mergeHistoryRecords};',sandbox);
  return sandbox.api;
}
test('persisted summary lifecycle and UTC fields populate history without treating OK as a state',()=>{
  const h=history();const record=h.historyRecordFromBackend({scan_id:'SCAN-TEST',status:'OK',job_state:'COMPLETED',
    repository_url:'https://github.com/example/repo.git',started_at_utc:'2026-11-01T16:40:45Z',finished_at_utc:'2026-11-01T16:41:18Z',
    triage_totals:{total_candidates:10,report_count:2,review_count:6,suppress_count:2}});
  assert.equal(record.status,'COMPLETED');assert.equal(record.report,2);assert.equal(record.review,6);assert.equal(record.suppress,2);
  assert.equal(record.repoUrl,'https://github.com/example/repo.git');assert.equal(record.completedAt,'2026-11-01T16:41:18Z');
});
test('transport success alone never fabricates completed history',()=>{
  const h=history();assert.equal(h.historyRecordFromBackend({status:'OK'}).status,undefined);
  assert.equal(h.historyRecordFromBackend({status:'OK',job_state:'FAILED'}).status,'FAILED');
});
test('authoritative backend values repair stale browser metadata without clearing missing fields',()=>{
  const h=history();h.upsertHistory({scanId:'SCAN-TEST',status:'OK',completedAt:'stale',repoUrl:'known'});
  h.upsertHistory(h.historyRecordFromBackend({scan_id:'SCAN-TEST',status:'OK',job_state:'COMPLETED',finished_at_utc:'2026-11-01T16:41:18Z'}),{authoritative:true});
  const row=h.readHistory()[0];assert.equal(row.status,'COMPLETED');assert.equal(row.completedAt,'2026-11-01T16:41:18Z');assert.equal(row.repoUrl,'known');
});

test('backend history remains complete beyond the bounded 50-record browser cache',()=>{
  const h=history();const remote=Array.from({length:92},(_,i)=>({scanId:'SCAN-'+i,status:'COMPLETED',startedAt:new Date(1700000000000+i*1000).toISOString()}));
  remote.forEach(row=>h.upsertHistory(row,{authoritative:true}));assert.equal(h.readHistory().length,50);
  const visible=h.mergeHistoryRecords(h.readHistory(),remote,[]);assert.equal(visible.length,92);
  assert(visible.some(row=>row.scanId==='SCAN-0'));assert.equal(visible[0].scanId,'SCAN-91');
});

test('history merge honors local hiding and preserves known fields missing from a summary',()=>{
  const h=history();const cached=[{scanId:'SCAN-1',repoUrl:'known',status:'COMPLETED'}];
  const remote=[{scanId:'SCAN-1',repoUrl:undefined,status:'FAILED'},{scanId:'SCAN-2',status:'COMPLETED'}];
  const visible=h.mergeHistoryRecords(cached,remote,[{scanId:'SCAN-2'}]);assert.equal(visible.length,1);
  assert.equal(visible[0].repoUrl,'known');assert.equal(visible[0].status,'FAILED');assert.equal(remote.length,2);
});