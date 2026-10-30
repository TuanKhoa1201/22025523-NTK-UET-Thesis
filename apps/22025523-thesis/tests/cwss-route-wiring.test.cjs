/** Regression guards for the ACTUAL routed findings components. */
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const base=path.join(__dirname,'..','src');
const routes=fs.readFileSync(path.join(base,'App.jsx'),'utf8');
const active=fs.readFileSync(path.join(base,'pages','Results.jsx'),'utf8');

test('the app routes real findings through the CWSS-enabled Results module',()=> {
  assert.match(routes,/import \{FindingDetail, Results\} from '\.\/pages\/Results'/);
  assert.match(routes,/path="\/findings" element=\{<Results \/>\}/);
  assert.match(routes,/path="\/finding\/:id" element=\{<FindingDetail \/>\}/);
});

test('the active paginated results request CWSS for the matching scan/page',()=> {
  assert.match(active,/api\.cwssPage\(scanId,page,PAGE_SIZE,\{signal\}\)/);
  assert.match(active,/cwssState\.data\?\.scan_id===scanId/);
  assert.match(active,/entry\?\.finding_id/);
  assert.match(active,/CWSS 1\.0\.1/);
  assert.match(active,/Legacy heuristic/);
});

test('direct finding detail loads the matching CWSS record without changing triage',()=> {
  assert.match(active,/api\.findingDetail\(scanId,id,detailUrl,\{signal\}\)/);
  assert.match(active,/api\.cwssPage\(scanId,cwssPage,PAGE_SIZE,\{signal\}\)/);
  assert.match(active,/entry\?\.finding_id===id/);
  assert.match(active,/unknown_metrics:row\.cwss\.unknown_metrics/);
  assert.match(active,/Original backend finding record/);
});
