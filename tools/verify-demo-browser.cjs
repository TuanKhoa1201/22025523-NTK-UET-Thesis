/** Read-only Edge/Chrome CDP acceptance using Node's built-in WebSocket. */
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {setTimeout: delay} = require('node:timers/promises');

async function main() {
  const base = process.env.NTK_BROWSER_URL || 'http://127.0.0.1:5173';
  const debug = process.env.NTK_CDP_URL || 'http://127.0.0.1:9223';
  const scan = process.env.NTK_ACCEPTANCE_SCAN_ID || 'SCAN-20261101164045-3AA266';
  const output = path.resolve(process.env.NTK_BROWSER_OUTPUT || 'work/final-validation/browser');
  fs.mkdirSync(output, {recursive: true});
  const version = await (await fetch(debug+'/json/version')).json();
  const target = await (await fetch(debug+'/json/new?about:blank', {method:'PUT'})).json();
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
  let seq=0, route='initial';
  const pending=new Map(), errors=[], apiErrors=[], downloads=[];
  ws.onmessage=({data})=>{
    const event=JSON.parse(data);
    if(event.id){
      const p=pending.get(event.id);
      if(p){clearTimeout(p.timer);pending.delete(event.id);event.error?p.reject(Error(JSON.stringify(event.error))):p.resolve(event.result);}
    }
    if(event.method==='Runtime.exceptionThrown')errors.push({route,...event.params.exceptionDetails});
    if(event.method==='Network.responseReceived' && event.params.response.status>=400)
      apiErrors.push({route,url:event.params.response.url,status:event.params.response.status});
    if(event.method==='Browser.downloadProgress')downloads.push(event.params);
  };
  const send=(method,params={})=>new Promise((resolve,reject)=>{
    const id=++seq;
    const timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout: '+method));},20000);
    pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));
  });
  const evaluate=async expression=>{
    const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
    if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));
    return r.result.value;
  };
  const wait=async(predicate,description)=>{
    const deadline=Date.now()+45000;
    while(Date.now()<deadline){if(await evaluate(predicate))return;await delay(250);}
    throw Error('UI timeout: '+description);
  };
  const shot=async(name,full=true)=>{
    let params={format:'png',captureBeyondViewport:full};
    if(full){const {cssContentSize:s}=await send('Page.getLayoutMetrics');params.clip={x:0,y:0,width:1440,height:Math.min(s.height,10000),scale:1};}
    const r=await send('Page.captureScreenshot',params);fs.writeFileSync(path.join(output,name+'.png'),Buffer.from(r.data,'base64'));
  };
  const click=async(text)=>evaluate(`(()=>{const b=[...document.querySelectorAll('button')].find(x=>x.textContent.trim()===${JSON.stringify(text)});if(!b)throw Error('Missing button');b.click();return true;})()`);
  const q='?scan_id='+encodeURIComponent(scan);
  const fid='FINDING-009-CWE089-doPost-L58';
  const pages=[
    ['overview','/'],['scanner','/scanner'],['history','/history'],['results','/results'+q],
    ['finding-detail','/finding/'+encodeURIComponent(fid)+q],['review','/review'+q],
    ['scoring','/scoring'],['reports','/reports'+q],['dataset','/dataset'],
    ['training','/training'],['evaluation','/evaluation'],['replay','/replay?scan='+encodeURIComponent(scan)],
  ];
  const results=[];
  try{
    await send('Page.enable');await send('Runtime.enable');await send('Network.enable');
    await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
    await send('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:path.join(output,'downloads'),eventsEnabled:true});
    for(const [name,hash] of pages){
      route=name;await send('Page.navigate',{url:base+'/#'+hash});
      await wait(`document.readyState==='complete' && !!document.querySelector('h1') && document.body.innerText.length>300`,name+' mount');
      await evaluate(`sessionStorage.setItem('22025523-scan-id',${JSON.stringify(scan)})`);
      if(name==='overview')await wait(`document.querySelectorAll('.stat-card strong').length===4 && [...document.querySelectorAll('.stat-card strong')].every(n=>n.innerText!=='…')`,'overview statistics settled');
      if(['history','results','finding-detail','review','reports'].includes(name))
        await wait(`document.body.innerText.includes(${JSON.stringify(name==='finding-detail'?fid:scan)}) && !document.body.innerText.includes('Đang tải trang')`,name+' live data');
      if(name==='results')await wait(`document.querySelectorAll('tbody tr').length===10 && document.body.innerText.includes('84.0/100') && document.body.innerText.includes('86.0/100')`,'results scores');
      if(name==='history')await wait(`document.querySelectorAll('.report-row').length>0 && [...document.querySelectorAll('.report-row')].every(n=>n.innerText.includes('HOÀN TẤT')) && document.body.innerText.includes('2 ứng viên')===false && document.body.innerText.includes('10 ứng viên')`,'completed history with backend totals');
      if(name==='finding-detail')await wait(`document.querySelectorAll('tbody tr').length===16 && document.body.innerText.includes('86.0/100') && document.body.innerText.includes('source_provenance_record')`,'16 metric detail');
      if(name==='dataset')await wait(`document.body.innerText.includes('781') && document.querySelectorAll('tbody tr').length>0`,'verified dataset');
      if(['training','evaluation'].includes(name))await wait(`document.body.innerText.includes('eo06_vnext31_trackb_recovery_20261024')`,'model provenance');
      if(name==='replay')await wait(`document.querySelectorAll('tbody tr').length===10`,'ten stages');
      await delay(650);
      const snapshot=await evaluate(`(()=>{const main=document.querySelector('.content-area')||document.querySelector('main')||document.body;return {heading:document.querySelector('h1')?.innerText,text:main.innerText,tableRows:document.querySelectorAll('tbody tr').length,overflow:document.documentElement.scrollWidth>innerWidth+2,alerts:[...document.querySelectorAll('[role=alert],.inline-error')].map(n=>n.innerText).filter(Boolean)};})()`);
      assert(!/\uFFFD|Ã[\u0080-\u00BF]|Ä[\u0080-\u00BF]|á[º»]|\?{3,}/u.test(snapshot.text),name+' Vietnamese encoding');
      assert(!/Unexpected Application Error|Something went wrong|Cannot read properties/.test(snapshot.text),name+' render crash');
      assert.equal(snapshot.alerts.length,0,name+' alerts: '+snapshot.alerts.join(';'));
      if(['results','finding-detail','replay'].includes(name))assert.equal(await evaluate(`document.querySelector('.breadcrumbs strong').innerText`),name==='replay'?'Phát lại trace':'Kết quả phát hiện','route breadcrumb');
      fs.writeFileSync(path.join(output,name+'.txt'),snapshot.text);
      await shot(name);
      if(name==='scanner'){
        await evaluate(`(()=>{const input=document.querySelector('#repo-url');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'not-a-github-url');input.dispatchEvent(new Event('input',{bubbles:true}));})()`);
        await delay(200);
        await evaluate(`(()=>{const button=[...document.querySelectorAll('button')].find(b=>b.classList.contains('button-primary'));if(!button)throw Error('Scanner submit absent');button.click();})()`);
        await wait(`!!document.querySelector('.inline-error,[role=alert]')`,'invalid GitHub URL rejected');
        await shot('scanner-validation',false);
      }
      if(name==='finding-detail'){
        await evaluate(`[...document.querySelectorAll('.card')].find(n=>n.textContent.includes('16 metric và nguồn gốc'))?.scrollIntoView()`);
        await shot('finding-metrics',false);
      }
      if(name==='review'){
        for(const tab of ['REVIEW','SUPPRESS']){
          await evaluate(`(()=>{const b=[...document.querySelectorAll('.review-tabs button')].find(n=>n.textContent.startsWith(${JSON.stringify(tab)}));b.click();})()`);
          await delay(800);
          const rows=await evaluate(`document.querySelectorAll('.review-row').length`);
          assert.equal(rows,tab==='REVIEW'?6:2,'review filter '+tab);
          await shot('review-'+tab.toLowerCase(),false);
        }
      }
      if(name==='reports'){
        await click('Báo cáo từ backend');
        for(let attempt=0;attempt<100 && !downloads.some(d=>d.state==='completed');attempt++)await delay(100);
        assert(downloads.some(d=>d.state==='completed'),'real browser download event completed');
        await shot('reports-download',false);
      }
      if(name==='replay'){
        for(let i=0;i<9;i++)await click('Sau');
        await wait(`document.querySelector('tbody tr.active')?.firstElementChild?.innerText==='10'`,'replay stage 10');
        await shot('replay-stage-10',false);
        await click('Về đầu');await click('Phát');await delay(1700);await click('Tạm dừng');
        const active=await evaluate(`document.querySelector('tbody tr.active')?.firstElementChild?.innerText`);
        assert.notEqual(active,'01','replay play advances');
      }
      results.push({page:name,status:'PASS',heading:snapshot.heading,tableRows:snapshot.tableRows,documentOverflow:snapshot.overflow,screenshot:name+'.png'});
      console.log('BROWSER_PAGE_PASS',name);
    }
    // Responsive sanity on the real results page; table containers may scroll.
    route='results-mobile';await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
    await send('Page.navigate',{url:base+'/#/results'+q});await wait(`document.querySelectorAll('tbody tr').length===10 && document.body.innerText.includes('84.0/100') && document.body.innerText.includes('86.0/100')`,'mobile results with CWSS');await delay(400);await shot('results-mobile',false);
    const reportFiles=fs.existsSync(path.join(output,'downloads'))?fs.readdirSync(path.join(output,'downloads')).filter(f=>f.endsWith('-report.json')):[];
    assert(reportFiles.length>0,'browser report download completed');
    reportFiles.sort((a,b)=>fs.statSync(path.join(output,'downloads',b)).mtimeMs-fs.statSync(path.join(output,'downloads',a)).mtimeMs);
    const report=JSON.parse(fs.readFileSync(path.join(output,'downloads',reportFiles[0]),'utf8'));assert.equal(report.scan_id,scan);
    assert.equal(errors.length,0,'browser runtime exceptions');assert.equal(apiErrors.length,0,'failed network responses');
    const reportResult={status:'PASS',browser:version.Browser,scan_id:scan,pages:results,mobileScreenshot:'results-mobile.png',reportDownloadVerified:true,errors,apiErrors};
    fs.writeFileSync(path.join(output,'browser-acceptance.json'),JSON.stringify(reportResult,null,2));console.log('BROWSER_ACCEPTANCE_PASS',results.length,'pages');
  }catch(error){
    fs.writeFileSync(path.join(output,'browser-failure.json'),JSON.stringify({route,error:error.stack,results,errors,apiErrors},null,2));
    try{await shot('failure-'+route,false);}catch{}
    throw error;
  }finally{ws.close();}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
