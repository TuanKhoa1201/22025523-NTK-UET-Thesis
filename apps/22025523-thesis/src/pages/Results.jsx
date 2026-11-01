import {useCallback,useEffect,useMemo,useState} from 'react';
import {Link,useLocation,useSearchParams} from 'react-router-dom';
import {Card,PageHeader,StatCard,Badge,SectionTitle,DataNotice,EmptyState,BarRow,Icon} from '../components/common/Ui';
import {demoFindings} from '../data/research';
import {useScanSelection,scanQuery,ACTIVE_KEY} from '../services/liveScan';
import {api} from '../services/api';
import {normalizeFinding} from '../services/scanData';
import {LiveGate,LiveResultsBody} from './LiveResults';

const PAGE_SIZE=50;
const num=(value)=> (value===undefined || value===null || value==='' || !Number.isFinite(Number(value)) ? null : Number(value));
const fmt=(value)=> (value===null ? '—' : value.toLocaleString());
const toneOf=(decision)=> (decision==='REPORT' ? 'red' : decision==='REVIEW' ? 'amber' : decision==='SUPPRESS' ? 'green' : 'neutral');
const cwssText=(row)=> row.cwssScore===null ? 'Chưa có' : `${row.cwssScore.toFixed(1)}/100`;
const scenarioText=(v)=> v && Number.isFinite(Number(v.cwss_score)) ? `${Number(v.cwss_score).toFixed(1)}/100 (giả định)` : 'Chưa có kịch bản';

function useActiveScanId() {
  const [params]=useSearchParams();
  return params.get('scan_id') || window.sessionStorage.getItem(ACTIVE_KEY) || '';
}

function useRemote(load,deps) {
  const [state,setState]=useState({status:'loading',data:null,error:''});
  const [attempt,setAttempt]=useState(0);
  useEffect(()=> {
    const controller=new AbortController();
    setState({status:'loading',data:null,error:''});
    load(controller.signal)
      .then((data)=> setState({status:'success',data,error:''}))
      .catch((error)=> {
        if (!controller.signal.aborted) setState({status:'error',data:null,error:error?.message || 'Không thể tải dữ liệu từ backend.'});
      });
    return ()=> controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  },[...deps,attempt]);
  const retry=useCallback(()=> setAttempt((value)=> value+1),[]);
  return [state,retry];
}

function SummaryStats({scanId,summary,pageData}) {
  const total=num(pageData?.total_count ?? summary?.total_count ?? summary?.total_findings);
  const matching=num(pageData?.total_matching);
  const by=summary?.triage_totals || summary?.decision_counts || summary?.triage_counts || summary || {};
  const pick=(key)=> num(by[`${key.toLowerCase()}_count`] ?? by[key] ?? by[key.toLowerCase()]);
  return (
    <div className="stats-grid">
      <StatCard label="Tổng findings (total_count)" value={fmt(total)} note={`LIVE · ${scanId}`} icon="Bug" />
      <StatCard label="Khớp bộ lọc (total_matching)" value={fmt(matching)} note="Theo API phân trang" icon="Filter" tone="blue" />
      <StatCard label="REPORT" value={fmt(pick('REPORT'))} note="Từ summary backend" icon="ShieldAlert" tone="amber" />
      <StatCard label="REVIEW / SUPPRESS" value={`${fmt(pick('REVIEW'))} / ${fmt(pick('SUPPRESS'))}`} note="Từ summary backend" icon="Eye" tone="green" />
    </div>
  );
}

function LiveFindings({scanId}) {
  const [page,setPage]=useState(1);
  const [summaryState,retrySummary]=useRemote((signal)=> api.scanSummary(scanId,{signal}),[scanId]);
  const [pageState,retryPage]=useRemote((signal)=> api.findingsPage(scanId,page,PAGE_SIZE,{signal}),[scanId,page]);
  const [cwssState,retryCwss]=useRemote((signal)=>
    pageState.status==='success'
      ? api.cwssV2ForFindingIds(
          scanId,
          (Array.isArray(pageState.data?.findings) ? pageState.data.findings : []).map((item)=>item?.finding_id).filter(Boolean),
          {signal}
        ).then((data)=>({...data,page}))
      : Promise.resolve({status:'PENDING_FINDINGS',scan_id:scanId,page,assessments:[]}),
    [scanId,page,pageState.status,pageState.data]);
  const [scenarioState,retryScenario]=useRemote((signal)=>
    pageState.status==='success'
      ? api.cwssV2ScenarioPage(scanId,page,PAGE_SIZE,{signal})
      : Promise.resolve({status:'PENDING_FINDINGS',scan_id:scanId,page,assessments:[]}),
    [scanId,page,pageState.status,pageState.data]);
  useEffect(()=> { setPage(1); },[scanId]);
  const pageData=pageState.data;
  const rows=useMemo(()=> {
    const list=pageData?.findings ?? pageData?.items ?? pageData?.results ?? [];
    // Keep CWSS as a read-only overlay; verify scan and page before joining by finding_id.
    const profile=cwssState.status==='success'
      && cwssState.data?.scan_id===scanId
      && Number(cwssState.data?.page)===page
      ? cwssState.data : null;
    const byFinding=new Map(
      (Array.isArray(profile?.assessments) ? profile.assessments : [])
        .filter((entry)=> entry?.finding_id && entry?.cwss && typeof entry.cwss==='object')
        .map((entry)=> [entry.finding_id,entry.cwss])
    );
    // Ranking order and source order differ: always bind by finding_id.
    const byScenario=new Map(
      (scenarioState.status==='success' && scenarioState.data?.scan_id===scanId &&
       Number(scenarioState.data?.page)===page && Array.isArray(scenarioState.data?.assessments)
        ? scenarioState.data.assessments : [])
        .map((entry)=>[entry.finding_id,entry.cwss])
    );
    return Array.isArray(list) ? list.map((item)=> ({
      ...normalizeFinding({
        ...item,
        ...(byFinding.has(item?.finding_id) ? {cwss:byFinding.get(item.finding_id)} : {})
      }),
      detailUrl:item?.detail_url,
      cwssScenario:byScenario.get(item?.finding_id)||null
    })) : [];
  },[pageData,cwssState.status,cwssState.data,scenarioState.status,scenarioState.data,scanId,page]);
  const totalMatching=num(pageData?.total_matching);
  const totalPages=num(pageData?.total_pages) ?? (totalMatching!==null ? Math.max(1,Math.ceil(totalMatching/PAGE_SIZE)) : null);
  const hasNext=totalPages!==null ? page<totalPages : rows.length===PAGE_SIZE;
  return (
    <>
      <PageHeader eyebrow="PHIÊN PHÂN TÍCH" title="Kết quả phát hiện" description={`Scan LIVE: ${scanId}`} actions={<Link to="/scanner" className="button-secondary"><Icon name="Plus" />Phiên phân tích mới</Link>} />
      <DataNotice>Điểm CWSS V2 được tính bằng công thức MITRE. Điểm kịch bản doanh nghiệp quan trọng có kết nối Internet dựa trên giả định tham chiếu, không phải môi trường đã xác minh. Điểm GENERAL_JAVA được giữ để đối chiếu. REPORT không đồng nghĩa lỗ hổng đã được chuyên gia xác nhận.</DataNotice>
      {cwssState.status==='loading' && <DataNotice>Đang tải 16 metric CWSS V2...</DataNotice>}
      {cwssState.status==='error' && <DataNotice>Không tải được CWSS V2; bằng chứng và quyết định triage vẫn giữ nguyên. {cwssState.error} <button className="button-secondary" onClick={retryCwss}>Thử lại</button></DataNotice>}
      {cwssState.status==='success' && (cwssState.data?.scan_id!==scanId || Number(cwssState.data?.page)!==page) && <DataNotice>CWSS response did not match the current scan/page; scores have not been attached.</DataNotice>}
      {cwssState.status==='success' && cwssState.data?.status!=='PENDING_FINDINGS' && cwssState.data?.scan_id===scanId && Number(cwssState.data?.page)===page && <DataNotice>Đã gắn CWSS V2 mặc định cho {rows.filter((row)=> row.cwss).length}/{rows.length} finding. MITRE_DEFAULT không phải bằng chứng triển khai. {cwssState.data?.status==='INCOMPLETE' ? 'Một số assessment chưa khớp finding_id.' : ''}</DataNotice>}
      {scenarioState.status==='loading' && <DataNotice>Đang tính CWSS V2 theo kịch bản giả định...</DataNotice>}
      {scenarioState.status==='error' && <DataNotice>Chưa tải được kịch bản giả định: {scenarioState.error}. Điểm mặc định và triage vẫn không thay đổi. <button className="button-secondary" onClick={retryScenario}>Thử lại</button></DataNotice>}
      {scenarioState.status==='success' && scenarioState.data?.status==='OK' && <DataNotice>Đã tính kịch bản tham chiếu trên {rows.filter((row)=>row.cwssScenario).length}/{rows.length} finding. Dữ liệu giả định về tài sản, Internet, xác thực, biện pháp bảo vệ và khả năng khai thác KHÔNG phải chứng cứ thực tế. Bấm Chi tiết để xem REFERENCE_ASSUMPTION và nguồn từng metric.</DataNotice>}
      {summaryState.status==='error' && <DataNotice>Không tải được summary (không chặn danh sách): {summaryState.error} <button className="button-secondary" onClick={retrySummary}>Thử lại</button></DataNotice>}
      <SummaryStats scanId={scanId} summary={summaryState.data} pageData={pageData} />
      <section className="section-block">
        <SectionTitle title="Danh sách findings" text="Evidence đầy đủ chỉ được tải khi mở chi tiết một finding." />
        <Card className="table-card">
          {pageState.status==='loading' && <DataNotice>Đang tải trang {page} từ backend…</DataNotice>}
          {pageState.status==='error' && <EmptyState title="Không tải được findings" text={pageState.error} icon="AlertTriangle" />}
          {pageState.status==='error' && <button className="button-secondary" onClick={retryPage}>Thử lại</button>}
          {pageState.status==='success' && !rows.length && <EmptyState title="Scan không có finding" text="Backend trả về 0 findings cho scan này. Điều này không có nghĩa ứng dụng an toàn." />}
          {pageState.status==='success' && rows.length>0 && (
            <div className="table-wrap"><table><thead><tr><th>Finding</th><th>CWE</th><th>File · line</th><th>Severity</th><th>CWSS V2 (kịch bản giả định)</th><th>GENERAL_JAVA</th><th>Triage</th><th></th></tr></thead><tbody>
              {rows.map((row)=> <tr key={row.id}><td className="mono">{row.id}</td><td><Badge tone="blue">{row.cwe||'—'}</Badge></td><td className="mono" title={row.file}>{String(row.file).split('/').slice(-1)}:{row.line}</td><td>{row.severity||'—'}</td><td className="mono">{scenarioText(row.cwssScenario)}</td><td className="mono">{cwssText(row)}</td><td><Badge tone={toneOf(row.decision)}>{row.decision||'—'}</Badge></td><td><Link className="table-link" to={`/finding/${encodeURIComponent(row.id)}${scanQuery(scanId)}`} state={{detailUrl:row.detailUrl}}>Chi tiết <Icon name="ArrowUpRight" /></Link></td></tr>)}
            </tbody></table></div>
          )}
          <div className="table-toolbar">
            <button className="button-secondary" disabled={page<=1 || pageState.status==='loading'} onClick={()=> setPage((value)=> Math.max(1,value-1))}>Trước</button>
            <span>Trang {page}{totalPages!==null ? ` / ${totalPages}` : ''}</span>
            <button className="button-secondary" disabled={!hasNext || pageState.status==='loading'} onClick={()=> setPage((value)=> value+1)}>Sau</button>
          </div>
        </Card>
      </section>
    </>
  );
}

function LiveDetailPage({scanId,id,detailUrl}) {
  // Finding detail is loaded independently of the 50-row results page.
  // finding_seq resolves the CWSS page; never attach an assessment by position alone.
  const [state,retry]=useRemote(async (signal)=> {
    const detail=await api.findingDetail(scanId,id,detailUrl,{signal});
    let cwss=null;
    let scenario=null;
    let scenarioError='';
    let cwssStatus='UNAVAILABLE';
    let cwssError='';
    try {
      cwss=await api.cwssV2Finding(scanId,id,{signal});
      cwssStatus='CWSS_V2_AVAILABLE';
    } catch (error) {
      if (signal.aborted) throw error;
      cwssError=String(error?.message || error);
    }
    try {
      scenario=await api.cwssV2ScenarioFinding(scanId,id,{signal});
    } catch(error) {
      if (signal.aborted) throw error;
      scenarioError=String(error?.message || error);
    }
    return {detail,cwss,scenario,scenarioError,cwssStatus,cwssError};
  },[scanId,id,detailUrl]);
  const detail=state.data?.detail;
  const flat=detail ? {
    ...(detail.finding && typeof detail.finding==='object' ? detail.finding : {}),
    ...detail,
    ...(state.data?.cwss ? {cwss:state.data.cwss} : {})
  } : null;
  const row=flat ? normalizeFinding(flat) : null;
  const displayed=state.data?.scenario || row?.cwss;
  const back=`/findings${scanQuery(scanId)}`;
  return (
    <>
      <PageHeader eyebrow={`FINDING / ${id}`} title={row?.title || id} description={`Scan ${scanId}`} actions={<Link to={back} className="button-secondary">Back to list</Link>} />
      {state.status==='loading' && <DataNotice>Loading finding evidence and the associated CWSS profile...</DataNotice>}
      {state.status==='error' && <><EmptyState title="Cannot load finding detail" text={state.error} icon="AlertTriangle" /><button className="button-secondary" onClick={retry}>Retry</button></>}
      {row && <>
        <DataNotice>Điểm CWSS V2 là mức ưu tiên điểm yếu có điều kiện, không phải xác suất TP hoặc CVSS. Nhóm metric REFERENCE_ASSUMPTION dựa trên bối cảnh giả định; quyết định REPORT/REVIEW/SUPPRESS là nhánh phân loại riêng.</DataNotice>
        <div className="finding-summary">
          <StatCard label="Severity" value={row.severity || 'N/A'} note="Scanner severity, not CWSS" icon="ShieldAlert" tone="amber" />
          <StatCard label="CWSS V2 - kịch bản giả định" value={scenarioText(state.data?.scenario)} note="Giả định doanh nghiệp quan trọng, Internet; chưa xác minh triển khai" icon="Gauge" />
          <StatCard label="CWSS V2 - GENERAL_JAVA" value={cwssText(row)} note="Đối chiếu theo trọng số mặc định MITRE" icon="Gauge" />
          <StatCard label="Triage" value={row.decision || 'N/A'} note="Not independently confirmed" icon="ScanEye" tone="violet" />
        </div>
        {!displayed && <DataNotice>Chưa có CWSS cho finding này. {state.data?.cwssError || ''}</DataNotice>}
        {!state.data?.scenario && state.data?.scenarioError && <DataNotice>Không tải được kịch bản giả định: {state.data.scenarioError}. Dữ liệu GENERAL_JAVA vẫn còn.</DataNotice>}
        {displayed && <Card title="CWSS Inference V2 — 16 metric và nguồn gốc">
          <p><strong>{state.data?.scenario ? 'KỊCH BẢN GIẢ ĐỊNH, KHÔNG PHẢI RỦI RO ĐÃ XÁC MINH' : 'GENERAL_JAVA — giá trị mặc định'}</strong></p>
          <p>Mode: {displayed.mode} | Profile: {displayed.reference_profile} | Version: {displayed.inference_version}.</p>
          <div className="table-wrap"><table>
            <thead><tr><th>Metric</th><th>Code</th><th>Weight</th><th>Classification</th><th>Rule</th><th>Reason / provenance</th></tr></thead>
            <tbody>{Object.entries(displayed.metric_assessments || {}).map(([name,m])=>(
              <tr key={name}><td className="mono">{name}</td><td>{m.code}</td>
                <td className="mono">{String(m.weight)}</td><td>{m.classification}</td>
                <td className="mono">{m.rule_id}</td><td>{m.reason}<div className="muted-text">{Array.isArray(m.evidence) ? m.evidence.join(' | ') : ''}</div></td>
              </tr>
            ))}</tbody>
          </table></div>
          <details><summary>Đối chiếu số học và provenance / GENERAL_JAVA</summary><pre><code>{JSON.stringify({
            scenario_score:displayed.cwss_score_exact,
            scenario_subscores:displayed.three_subscores,
            reference_context_hash:displayed.reference_context_hash,
            scenario_policy_hash:displayed.metric_assessments?.TI?.provenance?.policy_hash,
            baseline_general_java:row.cwss ? {
              score:row.cwss.cwss_score,
              subscores:row.cwss.three_subscores,
              metric_assessments:row.cwss.metric_assessments
            } : null,
            normalized_evidence:displayed.normalized_evidence
          },null,2)}</code></pre></details>
        </Card>}
        <Card title="Bằng chứng OpenGrep / IRIS / Qwen từ backend"><pre><code>{JSON.stringify({
        finding_id:id,
        cwe:flat?.cwe,
        file_path:flat?.file_path,
        line_number:flat?.line_number,
        scanner_rule_id:flat?.scanner_rule_id,
        matched_code:flat?.matched_code,
        iris_evidence:flat?.iris_evidence,
        llm_api_role:flat?.llm_api_role,
        source_provenance_record:flat?.source_provenance_record,
        triage_decision:flat?.triage_decision || flat?.decision,
      },null,2)}</code></pre></Card>
      </>}
    </>
  );
}

export function Results() {
  const scanId=useActiveScanId();
  if (scanId) return <LiveFindings scanId={scanId} />;
  return <LegacyResults />;
}

function LegacyResults() {
  const sel=useScanSelection();
  if (sel.mode==='live') {
    return <LiveGate sel={sel} title="Kết quả phát hiện">{(data)=> <LiveResultsBody data={data} table={<FindingsTable rows={data.rows} scanId={data.scanId} />} />}</LiveGate>;
  }
  const demo=sel.mode==='demo';
  const rows=demo ? demoFindings : [];
  const severity=['Critical','High','Medium','Low','Informational'];
  return (
    <>
      <PageHeader eyebrow="PHIЁN PHÂN TÍCH" title={demo ? 'Kết quả minh họa' : 'Kết quả phát hiện'} description={demo ? 'Bộ dữ liệu synthetic dùng để minh họa cách trình bày; không phải kết quả quét thực tế.' : 'Chưa có scan LIVE được nạp trong phiên này.'} actions={<Link to="/scanner" className="button-secondary"><Icon name="Plus" />Phiên phân tích mới</Link>} />
      {demo && <DataNotice>Dữ liệu mô phỏng — không phải kết quả quét thực tế. Các findings bên dưới chỉ minh họa giao diện, không xuất phát từ backend.</DataNotice>}
      {!demo ? <EmptyState title="Chưa có kết quả scan" text="Bắt đầu phân tích hoặc mở scan LIVE bằng scan_id từ backend." icon="ScanSearch" /> : <>
        <div className="stats-grid">
          <StatCard label="Candidate findings" value={rows.length} note="Synthetic demo" icon="Bug" />
          <StatCard label="REPORT" value="1" note="Ưu tiên kiểm tra" icon="ShieldAlert" tone="amber" />
          <StatCard label="REVIEW" value="2" note="Cần xem xét" icon="Eye" tone="blue" />
          <StatCard label="SUPPRESS" value="1" note="Giữ trong audit trail" icon="ShieldCheck" tone="green" />
        </div>
        <section className="section-block">
          <SectionTitle title="Tổng quan phân bố" text="Các biểu đồ dựa trên bộ findings minh họa ở trang này." />
          <div className="results-grid">
            <Card title="Findings by severity">{severity.map((level)=> <BarRow key={level} label={level} value={rows.filter((row)=> row.severity===level).length} max={4} color={level==='High' ? 'red' : level==='Medium' ? 'amber' : 'blue'} />)}</Card>
            <Card title="Phân bố CWE">{['CWE-022','CWE-078','CWE-079','CWE-089'].map((cwe)=> <BarRow key={cwe} label={cwe} value={rows.filter((row)=> row.cwe===cwe).length} max={2} />)}</Card>
            <Card title="Alert triage"><div className="donut-wrap"><div className="donut-chart"><div><b>4</b><span>DEMO</span></div></div><div className="donut-legend"><span><i className="legend-red" />REPORT · 1</span><span><i className="legend-amber" />REVIEW · 2</span><span><i className="legend-green" />SUPPRESS · 1</span></div></div></Card>
          </div>
        </section>
        <FindingsTable rows={rows} />
      </>}
    </>
  );
}

export function FindingsTable({rows=demoFindings,scanId=''}) {
  const [query,setQuery]=useState('');
  const [decision,setDecision]=useState('Tất cả quyết định');
  const filtered=useMemo(()=> rows.filter((row)=> `${row.id} ${row.title} ${row.file} ${row.cwe}`.toLowerCase().includes(query.toLowerCase())).filter((row)=> decision==='Tất cả quyết định' || row.decision===decision),[rows,query,decision]);
  return (
    <section className="section-block">
      <SectionTitle title="Danh sách findings" text="Candidate finding cần được đọc cùng evidence, policy và trạng thái review." />
      <Card className="table-card">
        <div className="table-toolbar"><input placeholder="Tìm ID, CWE, file..." value={query} onChange={(event)=> setQuery(event.target.value)} /><select value={decision} onChange={(event)=> setDecision(event.target.value)}><option>Tất cả quyết định</option><option>REPORT</option><option>REVIEW</option><option>SUPPRESS</option></select></div>
        {filtered.length ? <div className="table-wrap"><table><thead><tr><th>Finding</th><th>CWE / loại vấn đề</th><th>File · line</th><th>Severity</th><th>Triage</th><th></th></tr></thead><tbody>{filtered.map((row)=> <tr key={row.id}><td className="mono">{row.id}</td><td><Badge tone="blue">{row.cwe||'—'}</Badge><br />{row.title}</td><td className="mono">{String(row.file).split('/').slice(-1)}:{row.line}</td><td><Badge tone={row.severity==='High' ? 'red' : 'amber'}>{row.severity||'—'}</Badge></td><td><Badge tone={toneOf(row.decision)}>{row.decision||'—'}</Badge></td><td><Link className="table-link" to={`/finding/${encodeURIComponent(row.id)}${scanQuery(scanId)}`}>Chi tiết <Icon name="ArrowUpRight" /></Link></td></tr>)}</tbody></table></div> : <EmptyState title="Không tìm thấy finding" text="Thay đổi bộ lọc hoặc từ khóa tìm kiếm." />}
      </Card>
    </section>
  );
}

export function FindingDetail() {
  const scanId=useActiveScanId();
  const location=useLocation();
  const id=decodeURIComponent(window.location.hash.split('?')[0].split('/').pop());
  if (scanId) return <LiveDetailPage scanId={scanId} id={id} detailUrl={location.state?.detailUrl} />;
  return <DemoFindingDetail id={id} />;
}

function DemoFindingDetail({id}) {
  const finding=demoFindings.find((item)=> item.id===id);
  const [tab,setTab]=useState('OpenGrep');
  if (!finding) return <><PageHeader title="Chi tiết finding" description="Không có finding LIVE được nạp." /><EmptyState title="Không tìm thấy dữ liệu" text="Finding này chưa có trong dữ liệu demo hoặc backend chưa được kết nối." /></>;
  const tabs=['OpenGrep','IRIS','Language Model','Scoring','Decision'];
  return (
    <>
      <PageHeader eyebrow={`FINDING · ${finding.id}`} title={finding.title} description={`${finding.file}:${finding.line} · ${finding.cwe}`} actions={<Badge tone="amber">BẢN GHI MINH HỌA</Badge>} />
      <DataNotice>Finding synthetic minh họa — không phải kết quả phát hiện thực tế.</DataNotice>
      <div className="finding-summary"><StatCard label="Severity" value={finding.severity} note="Mức độ từ dữ liệu demo" icon="ShieldAlert" tone="amber" /><StatCard label="Triage" value={finding.decision} note="Chưa có chuyên gia xác nhận" icon="ScanEye" tone="violet" /></div>
      <Card title="Evidence explorer">
        <div className="evidence-tabs">{tabs.map((item)=> <button className={tab===item ? 'active' : ''} key={item} onClick={()=> setTab(item)}>{item}</button>)}</div>
        <div className="evidence-panel"><h3>{tab}</h3><p>{tab==='OpenGrep' ? 'Rule match candidate và vị trí code trong dữ liệu synthetic.' : tab==='IRIS' ? 'Chưa có verified dataflow trace trong ví dụ này.' : tab==='Language Model' ? `API role minh họa: ${finding.role}. Đây không phải xác nhận lỗ hổng.` : tab==='Scoring' ? 'CWSS V2 chưa được tính cho dữ liệu synthetic minh họa.' : finding.reason}</p></div>
      </Card>
      <section className="section-block"><SectionTitle title="Code context" text="Đoạn mã minh họa, không phải source code từ repository thật." /><Card className="code-card"><div className="code-header"><span className="mono">{finding.file}</span><Badge>JAVA · SAMPLE</Badge></div><pre><code>{` 81 public List<User> findUser(String input) {\n 82 String query="SELECT * FROM users WHERE name='" + input + "'";\n 83 // Candidate location for review\n 84 return statement.executeQuery(query);\n 85}`}</code></pre></Card></section>
    </>
  );
}