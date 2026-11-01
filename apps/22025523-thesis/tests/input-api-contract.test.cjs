const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

async function loadApi(fetcher){
  const source=fs.readFileSync(path.join(__dirname,'../src/services/api.js'),'utf8').replace('import.meta.env.VITE_API_BASE_URL',JSON.stringify('http://127.0.0.1:8766'));
  global.window={setTimeout,clearTimeout};global.fetch=fetcher;
  return import('data:text/javascript;base64,'+Buffer.from(source+'\n// '+Math.random()).toString('base64'));
}
test('ZIP adapter uses asynchronous multipart upload without setting a broken multipart boundary',async()=>{
  let seen;
  const {api}=await loadApi(async(url,options)=>{seen={url,options};return new Response(JSON.stringify({job_id:'JOB-TEST',state:'QUEUED'}),{status:202});});
  const file=new File(['test'],'source.zip',{type:'application/zip'});
  const result=await api.createZipJob(file);assert.equal(result.state,'QUEUED');assert(seen.url.endsWith('/api/scan-jobs'));
  assert(seen.options.body instanceof FormData);assert.equal(seen.options.body.get('file').name,'source.zip');
  assert.equal(seen.options.headers['Content-Type'],undefined);
});
test('structured Java-only rejection retains backend code and presents a Vietnamese explanation',async()=>{
  const {api}=await loadApi(async()=>new Response(JSON.stringify({error_code:'NO_JAVA_FILES_IN_ZIP',error_message:'No Java'}),{status:422}));
  await assert.rejects(api.scanSummary('SCAN-TEST'),error=>error.code==='NO_JAVA_FILES_IN_ZIP' && error.message.includes('NTK hiện hỗ trợ Java') && error.message.includes('[NO_JAVA_FILES_IN_ZIP]'));
});
test('syntax failure is distinguished from a successful zero-candidate scan',async()=>{
  const {inputErrorMessage}=await loadApi(async()=>{throw Error('No request expected');});
  assert.match(inputErrorMessage({error_code:'JAVA_SYNTAX_ERROR'}),/lỗi cú pháp/);
  assert.match(inputErrorMessage({error_code:'JAVA_SYNTAX_ERROR'}),/\[JAVA_SYNTAX_ERROR\]/);
});
