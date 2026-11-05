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
  assert.match(active,/api\.cwssV2ForFindingIds\(/);
  assert.match(active,/cwssState\.data\?\.scan_id===scanId/);
  assert.match(active,/entry\?\.finding_id/);
  assert.match(active,/CWSS V2/);
  assert.doesNotMatch(active,/Legacy heuristic/);
});

test('direct finding detail loads the matching CWSS record without changing triage',()=> {
  assert.match(active,/api\.findingDetail\(scanId,id,detailUrl,\{signal\}\)/);
  assert.match(active,/api\.cwssV2Finding\(scanId,id,\{signal\}\)/);
  assert.match(active,/api\.cwssV2ScenarioFinding\(scanId,id,\{signal\}\)/);
  assert.match(active,/metric_assessments/);
  assert.match(active,/source_provenance_record:flat\?\.source_provenance_record/);
});