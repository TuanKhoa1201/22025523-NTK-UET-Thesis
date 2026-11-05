const test = require('node:test');
const assert = require('node:assert/strict');

const read = () => import('../src/services/scanStatus.js');
const scan = 'SCAN-20261102114457-676FB9';
const trace = (status, extra = {}) => ({
  scan_id: scan,
  stages: [
    {number: 3, summary_metadata: {original_iris_analysis_status: 'NOT_APPLICABLE'}},
    {number: 5, summary_metadata: {original_iris_analysis_status: status,
      original_iris_reason_codes: ['API_ROLE_CONTRACT_UNSUPPORTED', 'NATIVE_PARAMETER_CONTRACT_UNSUPPORTED'], ...extra}}
  ]
});

test('Stage 05 IRIS_PARTIAL is read from a matching real trace shape', async () => {
  const {readIrisTraceStatus} = await read();
  assert.deepEqual(readIrisTraceStatus(trace('IRIS_PARTIAL'), scan), {
    status: 'IRIS_PARTIAL',
    reasonCodes: ['API_ROLE_CONTRACT_UNSUPPORTED', 'NATIVE_PARAMETER_CONTRACT_UNSUPPORTED']
  });
});

test('Never substitute another scan or stage as the IRIS result', async () => {
  const {readIrisTraceStatus} = await read();
  assert.equal(readIrisTraceStatus(trace('IRIS_PARTIAL'), 'SCAN-WRONG'), null);
  assert.equal(readIrisTraceStatus({scan_id: scan, stages: [{number: 6, summary_metadata: {original_iris_analysis_status: 'COMPLETED'}}]}, scan), null);
  assert.equal(readIrisTraceStatus({scan_id: scan, stages: []}, scan), null);
});

test('Unexpected status and reasons do not become trusted UI evidence', async () => {
  const {readIrisTraceStatus} = await read();
  assert.equal(readIrisTraceStatus(trace(''), scan), null);
  assert.equal(readIrisTraceStatus(trace('PARTIAL<script>'), scan), null);
  assert.deepEqual(readIrisTraceStatus(trace('COMPLETED', {original_iris_reason_codes: ['good', 'VALID_REASON']}), scan), {
    status: 'COMPLETED', reasonCodes: ['VALID_REASON']
  });
});
