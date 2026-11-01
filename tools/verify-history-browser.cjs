/** Isolated frontend 5174: clear its test browser cache; never alter backend history. */
const fs=require('fs'),assert=require('assert/strict');
async function main(){
 const root='work/e2e-multiproject-acceptance';const target=await(await fetch('http://127.0.0.1:9223/json/new?about:blank',{method:'PUT'})).json();
 const ws=new WebSocket(target.webSocketDebuggerUrl);await new Promise(r=>ws.onopen=r);let id=0;const pending=new Map(),errors=[],requests=[];
 ws.onmessage=({data})=>{const e=JSON.parse(data);if(e.id){pending.get(e.id)(e.result);pending.delete(e.id);}if(e.method==='Runtime.exceptionThrown')errors.push(e.params);if(e.method==='Network.requestWillBeSent')requests.push(e.params.request.url);};
 const send=(method,params={})=>new Promise(r=>{const key=++id;pending.set(key,r);ws.send(JSON.stringify({id:key,method,params}));});
 const js=async expression=>(await send('Runtime.evaluate',{expression,returnByValue:true})).result.value;
 try{
  await send('Page.enable');await send('Runtime.enable');await send('Network.enable');
  await send('Storage.clearDataForOrigin',{origin:'http://127.0.0.1:5174',storageTypes:'local_storage'});
  await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  const projectIds=JSON.parse(fs.readFileSync(root+'/projects-results.json')).map(r=>r.scan_id);
  const expected=await(await fetch('http://127.0.0.1:8766/api/scans?page_size=100')).json();
  await send('Page.navigate',{url:'http://127.0.0.1:5174/#/history'});let snapshot;
  for(let i=0;i<150;i++){
   snapshot=await js(`({text:document.body.innerText,rows:document.querySelectorAll('.report-row').length})`);
   if(snapshot.rows===expected.total_matching&&projectIds.every(id=>snapshot.text.includes(id)))break;
   await new Promise(r=>setTimeout(r,200));
  }
  assert.equal(snapshot.rows,expected.total_matching);assert(projectIds.every(id=>snapshot.text.includes(id)));
  assert(snapshot.text.includes('HOÀN TẤT'));assert(snapshot.text.includes('THẤT BẠI'));
  assert(!snapshot.text.includes('Phiên này không còn khả dụng'));assert(!/\uFFFD|\?{3,}/.test(snapshot.text));assert.equal(errors.length,0);
  assert(requests.some(url=>url.includes('/api/scans?page=1&page_size=100')));
  await js(`document.querySelectorAll('.report-row')[0].scrollIntoView({block:'center'})`);
  let pic=await send('Page.captureScreenshot',{format:'png'});fs.writeFileSync(root+'/browser/history-all-states.png',Buffer.from(pic.data,'base64'));
  await js(`[...document.querySelectorAll('.report-row')].find(row=>row.innerText.includes(${JSON.stringify(projectIds[0])})).scrollIntoView({block:'center'})`);
  pic=await send('Page.captureScreenshot',{format:'png'});fs.writeFileSync(root+'/browser/history-older-project.png',Buffer.from(pic.data,'base64'));
  const receipt={status:'PASS',clean_local_cache:true,backend_history_count:expected.total_matching,visible_rows:snapshot.rows,eight_project_ids_present:true,failed_and_completed_distinguished:true,errors};
  fs.writeFileSync(root+'/browser/history-pagination.json',JSON.stringify(receipt,null,2));console.log('HISTORY_BROWSER_PASS',snapshot.rows,'ALL_EIGHT',true);
 }finally{ws.close();}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
