/** Actual browser checks for fresh multi-project scans and Scanner input states. */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {setTimeout:delay}=require('node:timers/promises');
async function main(){
  const root=path.resolve('work/e2e-multiproject-acceptance');const out=path.join(root,'browser');fs.mkdirSync(out,{recursive:true});
  const base=process.env.NTK_BROWSER_URL||'http://127.0.0.1:5174';
  const target=await(await fetch('http://127.0.0.1:9223/json/new?about:blank',{method:'PUT'})).json();
  const ws=new WebSocket(target.webSocketDebuggerUrl);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j;});
  let sequence=0,label='initial';const waiting=new Map(),errors=[],posts=[],results=[];
  ws.onmessage=({data})=>{const e=JSON.parse(data);if(e.id){const p=waiting.get(e.id);if(p){clearTimeout(p.timer);waiting.delete(e.id);e.error?p.reject(Error(JSON.stringify(e.error))):p.resolve(e.result);}}
    if(e.method==='Runtime.exceptionThrown')errors.push({label,details:e.params.exceptionDetails});
    if(e.method==='Network.requestWillBeSent'&&e.params.request.method==='POST')posts.push({label,url:e.params.request.url});};
  const send=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence;const timer=setTimeout(()=>reject(Error('CDP timeout '+method)),20000);waiting.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));});
  const js=async expression=>{const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
  const wait=async expression=>{const end=Date.now()+90000;while(Date.now()<end){if(await js(expression))return;await delay(200);}throw Error('UI timeout '+label);};
  const shot=async name=>{const r=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(out,name+'.png'),Buffer.from(r.data,'base64'));};
  const navigate=async hash=>{await send('Page.navigate',{url:base+'/#'+hash});await wait(`!!document.querySelector('h1') && document.readyState==='complete'`);};
  const setValue=async(selector,value)=>js(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(n,${JSON.stringify(value)});n.dispatchEvent(new Event('input',{bubbles:true}));})()`);
  try{
    await send('Page.enable');await send('Runtime.enable');await send('Network.enable');await send('DOM.enable');
    await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
    await send('Page.addScriptToEvaluateOnNewDocument',{source:`try{if(location.hash.startsWith('#/scanner')){sessionStorage.removeItem('22025523-active-job');sessionStorage.removeItem('22025523-scan-id');}}catch{}`});
    const projects=JSON.parse(fs.readFileSync(path.join(root,'projects-results.json'),'utf8'));
    for(const project of projects){
      label='project-'+project.label;await navigate('/results?scan_id='+project.scan_id);const n=project.full.findings.length;
      await wait(`document.body.innerText.includes(${JSON.stringify(project.scan_id)}) && document.querySelectorAll('tbody tr').length===${n}`);
      if(n)await wait(`document.body.innerText.includes('Đã tính kịch bản tham chiếu trên')`);
      else await wait(`document.body.innerText.includes('Không phát hiện ứng viên lỗ hổng thuộc phạm vi quy tắc hiện tại')`);
      if(project.full.coverage_status==='PARTIAL_BOUNDED')await wait(`document.body.innerText.includes('Đây là quét một phần')`);
      const text=await js('document.body.innerText');assert(!/\uFFFD|\?{3,}|Unexpected Application Error/.test(text));
      if(!n)assert(!text.includes('trên 0/0 finding'),'zero candidates have no CWSS assessment notice');
      assert(!text.includes('Không tải được findings'));await shot(label);results.push({test:label,status:'PASS',scan_id:project.scan_id,rows:n});console.log('BROWSER_PASS',label);
    }
    const inputs=JSON.parse(fs.readFileSync(path.join(root,'input-results.json'),'utf8'));
    for(const name of ['verified-safe','unknown']){
      const r=inputs.find(x=>x.label==='input-'+name);label='state-'+name;await navigate('/results?scan_id='+r.scan_id);
      await wait(`document.querySelectorAll('tbody tr').length===${r.full.findings.length} && document.body.innerText.includes('Đã tính kịch bản tham chiếu trên')`);
      await shot(label);results.push({test:label,status:'PASS'});
    }
    const zipCases=[...['python-only','javascript-only','typescript-only','cpp-only','go-only','readme-only','empty'].map(n=>[n,'NO_JAVA_FILES_IN_ZIP']),
      ['fake-java','JAVA_SYNTAX_ERROR'],['syntax-error','JAVA_SYNTAX_ERROR'],['corrupt','MALFORMED_ZIP_ARCHIVE_REJECTED'],
      ['renamed-zip','INVALID_ZIP_MAGIC_BYTES_REJECTED'],['zero-java',null],['nested-java',null],['mixed',null]];
    for(const [name,expected] of zipCases){
      label='upload-'+name;await navigate('/scanner');await wait(`document.body.innerText.includes('KẾT NỐI THỰC') && [...document.querySelectorAll('.tab-switcher button')].some(b=>b.textContent.includes('Tải tệp ZIP'))`);
      await js(`[...document.querySelectorAll('.tab-switcher button')].find(b=>b.textContent.includes('Tải tệp ZIP')).click()`);
      const doc=await send('DOM.getDocument');const {nodeId}=await send('DOM.querySelector',{nodeId:doc.root.nodeId,selector:'input[type=file]'});
      await send('DOM.setFileInputFiles',{nodeId,files:[path.join(root,'input-fixtures',name+'.zip')]});await delay(200);
      await js(`(()=>{const b=document.querySelector('.scanner-submit .button-primary');b.click();b.click();})()`);
      if(expected)await wait(`document.querySelector('.inline-error')?.innerText.includes(${JSON.stringify(expected)})`);
      else await wait(`document.body.innerText.includes('Đã hoàn thành phân tích. Không phát hiện ứng viên lỗ hổng thuộc phạm vi quy tắc hiện tại.')`);
      assert.equal(posts.filter(p=>p.label===label).length,1,'double click creates one POST');
      if(expected)await js(`document.querySelector('.inline-error').scrollIntoView({block:'center'})`);
      await shot(label);results.push({test:label,status:'PASS',error_code:expected,posts:1});console.log('BROWSER_PASS',label);
    }
    const gitCases=[['python','pypa/sampleproject'],['javascript','jonschlinkert/is-number'],['c','jserv/mini-arm-os'],['go','golang/example'],['readme','octocat/Hello-World'],
      ['invalid-branch','pypa/sampleproject','ntk-no-such-branch-20261102','','GIT_CLONE_FAILED'],
      ['invalid-commit','pypa/sampleproject','0000000000000000000000000000000000000000','','GIT_CHECKOUT_FAILED'],
      ['no-java-subpath','TuanKhoa1201/22025523-NTK-UET-Thesis','','docs','NO_JAVA_FILES_MATCHED_FILTERS']];
    for(const [name,repo,ref='',subpath='',code='NO_JAVA_FILES_FOUND'] of gitCases){
      label='git-'+name+'-error';await navigate('/scanner');await wait(`document.body.innerText.includes('KẾT NỐI THỰC') && !!document.querySelector('.tab-switcher button')`);
      await js(`[...document.querySelectorAll('.tab-switcher button')].find(b=>b.textContent.includes('GitHub Repository')).click()`);
      await wait(`!!document.querySelector('#repo-url') && !document.querySelector('.scanner-submit .button-primary').disabled`);
      await setValue('#repo-url','https://github.com/'+repo);await setValue('#git-ref',ref);await setValue('#target-subpath',subpath);
      await delay(100);await js(`document.querySelector('.scanner-submit .button-primary').click()`);
      await wait(`document.querySelector('.inline-error')?.innerText.includes(${JSON.stringify(code)})`);
      await js(`document.querySelector('.inline-error').scrollIntoView({block:'center'})`);await shot(label);results.push({test:label,status:'PASS',error_code:code});
      console.log('BROWSER_PASS',label);
    }
    const raw=JSON.parse(fs.readFileSync(path.join(root,'git-input-results.json'),'utf8')).find(x=>x.label==='git-input-python');
    label='failed-job-no-successful-results';await navigate('/results?scan_id='+raw.scan_id);
    await wait(`document.body.innerText.includes('Không tải được findings')`);
    assert(!(await js(`document.body.innerText.includes('Đã hoàn thành phân tích')`)),'failed job is never a successful zero-candidate scan');
    await shot(label);results.push({test:label,status:'PASS'});
    assert.equal(errors.length,0,'browser runtime exceptions');
    fs.writeFileSync(path.join(out,'input-browser.json'),JSON.stringify({status:'PASS',results,errors,posts},null,2));console.log('INPUT_BROWSER_PASS',results.length);
  }catch(error){fs.writeFileSync(path.join(out,'failure.json'),JSON.stringify({label,error:error.stack,results,errors,posts},null,2));try{await shot('failure');}catch{}throw error;}
  finally{ws.close();}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
