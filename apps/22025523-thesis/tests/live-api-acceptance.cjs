/** Exercise the actual frontend API adapter against a real local backend. */
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

test('real frontend adapter joins both CWSS modes by finding ID', {skip: !process.env.NTK_ACCEPTANCE_SCAN_ID}, async()=> {
  global.window={setTimeout,clearTimeout};
  const base=process.env.NTK_ACCEPTANCE_API || 'http://127.0.0.1:8765';
  const file=path.join(__dirname,'../src/services/api.js');
  const source=fs.readFileSync(file,'utf8').replace('import.meta.env.VITE_API_BASE_URL',JSON.stringify(base));
  const {api}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
  const scan=process.env.NTK_ACCEPTANCE_SCAN_ID;
  const summary=await api.scanSummary(scan);
  const page=await api.findingsPage(scan,1,50);
  const ids=page.findings.map(f=>f.finding_id);
  const general=await api.cwssV2ForFindingIds(scan,ids);
  const scenario=await api.cwssV2ScenarioPage(scan,1,50);
  assert.equal(general.status,'OK');
  assert.equal(general.assessments.length,ids.length);
  assert.equal(scenario.assessments.length,ids.length);
  assert.equal(summary.total_findings,ids.length);
  for(const f of page.findings){
    const assessed=general.assessments.find(row=>row.finding_id===f.finding_id).cwss;
    assert.equal(assessed.triage_decision,f.decision);
    assert.equal(Object.keys(assessed.metric_assessments).length,16);
    assert.equal(f.final_heuristic_score,null);
  }
  const fid=ids[ids.length-1];
  const detail=await api.findingDetail(scan,fid);
  const score=await api.cwssV2Finding(scan,fid);
  const conditional=await api.cwssV2ScenarioFinding(scan,fid);
  assert.equal(score.finding_id,fid);
  assert.equal(conditional.finding_id,fid);
  assert.equal(conditional.reference_profile,'BUSINESS_CRITICAL_INTERNET_FACING');
  const manifest=await api.datasetManifest();
  assert(manifest.datasets.every(d=>d.sha256_verified && d.row_count_verified));
  assert((await api.listScans()).supported);
  assert.equal((await api.pipelineTrace(scan)).stages.length,10);
  assert.equal((await api.model()).cloud_calls_enabled,false);
  assert.equal((await api.report(scan)).scan_id,scan);
  await assert.rejects(api.scanSummary('SCAN-NOT-FOUND-ACCEPTANCE'));
});
