import {useCallback,useEffect,useMemo,useState} from 'react';
import {Link,useLocation,useSearchParams} from 'react-router-dom';
import {Card,PageHeader,StatCard,Badge,SectionTitle,DataNotice,EmptyState,BarRow,Icon} from '../components/common/Ui';
import {demoFindings} from '../data/research';
import {useScanSelection,scanQuery,ACTIVE_KEY} from '../services/liveScan';
import {api} from '../services/api';
import {normalizeFinding} from '../services/scanData';
import {LiveGate,LiveResultsBody} from './LiveResults';
import {LiveFindings as LiveDashboard} from './LiveFindings';
import {backendRecommendation, fileName, findReportedId, firstText, getCweGuide, irisProofExplanation, irisProofState, irisProofTone, sourceSnippet, triageExplanation, validCwssScore} from '../services/findingPresentation';
import {metricExplanation, metricLevel, metricSource, metricTitle, metricWeight} from '../services/cwssPresentation';

const PAGE_SIZE=50;
const num=(value)=> (value===undefined || value===null || value==='' || !Number.isFinite(Number(value)) ? null : Number(value));
const fmt=(value)=> (value===null ? '-' : value.toLocaleString());
const toneOf=(decision)=> (decision==='REPORT' ? 'red' : decision==='REVIEW' ? 'amber' : decision==='SUPPRESS' ? 'green' : 'neutral');
const cwssText=(row)=> row.cwssScore===null ? 'Chưa có' : `${row.cwssScore.toFixed(1)}/100`;
const scenarioText=(v)=> v && Number.isFinite(Number(v.cwss_score)) ? `${Number(v.cwss_score).toFixed(1)}/100` : 'Chưa có kịch bản';

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

// Superseded by LiveDashboard (whole-scan charts, filters); kept for reference.
// eslint-disable-next-line no-unused-vars
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
      {summaryState.data && <DataNotice>Phạm vi: {summaryState.data.coverage_status || 'Chưa xác định'} · {summaryState.data.java_files_scanned ?? '-'} file Java · {summaryState.data.rules_applied_count ?? '-'} quy tắc. Chỉ phân tích Java cho CWE-22, CWE-78, CWE-79, CWE-89; các ngôn ngữ khác không được phân tích. {summaryState.data.coverage_status === 'PARTIAL_BOUNDED' ? 'Đây là quét một phần, chưa bao phủ toàn bộ dự án.' : 'Coverage không phải chứng nhận bảo mật toàn repository.'}</DataNotice>}
      {cwssState.status==='loading' && <DataNotice>Đang tải 16 metric CWSS V2...</DataNotice>}
      {cwssState.status==='error' && <DataNotice>Không tải được CWSS V2; bằng chứng và quyết định triage vẫn giữ nguyên. {cwssState.error} <button className="button-secondary" onClick={retryCwss}>Thử lại</button></DataNotice>}
      {cwssState.status==='success' && (cwssState.data?.scan_id!==scanId || Number(cwssState.data?.page)!==page) && <DataNotice>CWSS response did not match the current scan/page; scores have not been attached.</DataNotice>}
      {rows.length>0 && cwssState.status==='success' && cwssState.data?.status!=='PENDING_FINDINGS' && cwssState.data?.scan_id===scanId && Number(cwssState.data?.page)===page && <DataNotice>Đã gắn CWSS V2 mặc định cho {rows.filter((row)=> row.cwss).length}/{rows.length} finding. MITRE_DEFAULT không phải bằng chứng triển khai. {cwssState.data?.status==='INCOMPLETE' ? 'Một số assessment chưa khớp finding_id.' : ''}</DataNotice>}
      {scenarioState.status==='loading' && <DataNotice>Đang tính CWSS V2 theo kịch bản giả định...</DataNotice>}
      {scenarioState.status==='error' && <DataNotice>Chưa tải được kịch bản giả định: {scenarioState.error}. Điểm mặc định và triage vẫn không thay đổi. <button className="button-secondary" onClick={retryScenario}>Thử lại</button></DataNotice>}
      {rows.length>0 && scenarioState.status==='success' && scenarioState.data?.status==='OK' && <DataNotice>Đã tính kịch bản tham chiếu trên {rows.filter((row)=>row.cwssScenario).length}/{rows.length} finding. Dữ liệu giả định về tài sản, Internet, xác thực, biện pháp bảo vệ và khả năng khai thác KHÔNG phải chứng cứ thực tế. Bấm Chi tiết để xem REFERENCE_ASSUMPTION và nguồn từng metric.</DataNotice>}
      {summaryState.status==='error' && <DataNotice>Không tải được summary (không chặn danh sách): {summaryState.error} <button className="button-secondary" onClick={retrySummary}>Thử lại</button></DataNotice>}
      <SummaryStats scanId={scanId} summary={summaryState.data} pageData={pageData} />
      <section className="section-block">
        <SectionTitle title="Danh sách findings" text="Evidence đầy đủ chỉ được tải khi mở chi tiết một finding." />
        <Card className="table-card">
          {pageState.status==='loading' && <DataNotice>Đang tải trang {page} từ backend…</DataNotice>}
          {pageState.status==='error' && <EmptyState title="Không tải được findings" text={pageState.error} icon="AlertTriangle" />}
          {pageState.status==='error' && <button className="button-secondary" onClick={retryPage}>Thử lại</button>}
          {pageState.status==='success' && !rows.length && <EmptyState title="Đã hoàn thành phân tích" text="Không phát hiện ứng viên lỗ hổng thuộc phạm vi quy tắc hiện tại. Không có finding để chấm CWSS; kết quả không chứng minh ứng dụng an toàn." />}
          {pageState.status==='success' && rows.length>0 && (
            <div className="table-wrap"><table><thead><tr><th>Finding</th><th>CWE</th><th>File · line</th><th>Bằng chứng IRIS</th><th>CWSS V2 (kịch bản giả định)</th><th>GENERAL_JAVA</th><th>Triage</th><th></th></tr></thead><tbody>
              {rows.map((row)=> <tr key={row.id}><td className="mono">{row.id}</td><td><Badge tone="blue">{row.cwe||'-'}</Badge></td><td className="mono" title={row.file}>{String(row.file).split('/').slice(-1)}:{row.line}</td><td><Badge tone={irisProofTone(row.irisProofState)}>{row.irisProofState}</Badge></td><td className="mono">{scenarioText(row.cwssScenario)}</td><td className="mono">{cwssText(row)}</td><td><Badge tone={toneOf(row.decision)}>{row.decision||'-'}</Badge></td><td><Link className="table-link" to={`/finding/${encodeURIComponent(row.id)}${scanQuery(scanId)}`} state={{detailUrl:row.detailUrl}}>Chi tiết <Icon name="ArrowUpRight" /></Link></td></tr>)}
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
  // Independent requests: a missing CWSS endpoint must not hide real finding evidence.
  // Each request remains scoped to this exact scan and finding ID.
  const [detailState,retryDetail]=useRemote(
    (signal)=> api.findingDetail(scanId,id,detailUrl,{signal}),[scanId,id,detailUrl]
  );
  const [cwssState,retryCwss]=useRemote(
    (signal)=> api.cwssV2Finding(scanId,id,{signal}),[scanId,id]
  );
  const [scenarioState,retryScenario]=useRemote(
    (signal)=> api.cwssV2ScenarioFinding(scanId,id,{signal}),[scanId,id]
  );
  const detail=detailState.status==='success' ? detailState.data : null;
  const returnedId=findReportedId(detail);
  const mismatch=Boolean(returnedId && returnedId!==id);
  const flat=detail && !mismatch ? {
    ...(detail.finding && typeof detail.finding==='object' ? detail.finding : {}),
    ...detail,
    finding_id:id
  } : null;
  const row=flat ? normalizeFinding(flat) : null;
  const referenceScore=scenarioState.status==='success'
    && scenarioState.data?.finding_id===id
    && scenarioState.data?.reference_profile==='BUSINESS_CRITICAL_INTERNET_FACING'
    ? scenarioState.data : null;
  const score=validCwssScore(referenceScore);
  const baseline=cwssState.status==='success' ? cwssState.data : null;
  const guide=getCweGuide(row?.cwe);
  const filePath=firstText(flat?.file_path,flat?.source_file,row?.file);
  const lineNumber=firstText(flat?.line_number,flat?.source_line,row?.line);
  const ruleId=firstText(flat?.scanner_rule_id,flat?.rule_id,flat?.opengrep_rule_id);
  const snippet=sourceSnippet(flat);
  const recommended=backendRecommendation(flat);
  const back=`/findings${scanQuery(scanId)}`;
  return (
    <div className="ntk-p06-detail">
      <PageHeader
        eyebrow="CHI TIẾT CẢNH BÁO"
        title={row ? guide.title : 'Chi tiết cảnh báo'}
        description={row ? `${guide.code}${filePath ? ` · ${fileName(filePath)}` : ''}${lineNumber ? `, dòng ${lineNumber}` : ''}` : undefined}
        actions={<Link to={back} className="button-secondary"><Icon name="ArrowLeft" /> Quay lại kết quả</Link>}
      />
      {detailState.status==='loading' && <DataNotice>Đang tải thông tin cảnh báo từ backend…</DataNotice>}
      {detailState.status==='error' && <>
        <EmptyState title="Không tải được chi tiết cảnh báo" text={detailState.error} icon="AlertTriangle" />
        <button className="button-secondary" onClick={retryDetail}>Thử lại</button>
      </>}
      {mismatch && <>
        <EmptyState title="Dữ liệu cảnh báo không khớp" text="Backend trả về mã cảnh báo khác với cảnh báo đang mở. Dữ liệu này sẽ không được hiển thị." icon="AlertTriangle" />
        <button className="button-secondary" onClick={retryDetail}>Tải lại</button>
      </>}
      {row && <>
        <div className="ntk-p06-hero">
          <Card className="ntk-p06-intro">
            <div className="ntk-p06-intro-header"><Badge tone="blue">{guide.code}</Badge><span>Loại vấn đề</span></div>
            <h2>{guide.title}</h2>
            <p>{guide.description}</p>
            <div className="ntk-p06-proof-stat">
              <span>Trạng thái bằng chứng IRIS</span>
              <Badge tone={irisProofTone(row.irisProofState)}>{row.irisProofState}</Badge>
              <p>{irisProofExplanation(row.irisProofState)}</p>
            </div>
          </Card>
          <Card className="ntk-p06-score">
            <span className="ntk-p06-kicker">ĐIỂM CWSS</span>
            <div className="ntk-p06-score-number" aria-label="Điểm CWSS trên thang 100">
              {score===null ? <strong className="ntk-p06-score-empty">-</strong> : <strong>{score.toFixed(1)}</strong>}
              <span>/100</span>
            </div>
            <p>Điểm ưu tiên xử lý</p>
            {scenarioState.status==='loading' && <small>Đang tải điểm từ backend…</small>}
            {scenarioState.status==='error' && <small>Không tải được điểm CWSS. <button type="button" onClick={retryScenario}>Thử lại</button></small>}
            {scenarioState.status==='success' && score===null && <small>Chưa có điểm hợp lệ cho cảnh báo này.</small>}
          </Card>
          <Card className="ntk-p06-triage">
            <span className="ntk-p06-kicker">TRẠNG THÁI XỬ LÝ</span>
            <div className="ntk-p06-decision"><Badge tone={toneOf(row.decision)}>{row.decision || 'Chưa có'}</Badge></div>
            <p>{triageExplanation(row.decision)}</p>
          </Card>
        </div>

        <section className="section-block ntk-p06-section">
          <SectionTitle title="Vị trí trong mã nguồn" />
          <Card className="ntk-p06-location">
            <div className="ntk-p06-location-grid">
              <div><span>Tệp Java</span><strong>{fileName(filePath) || 'Chưa có tên tệp'}</strong></div>
              <div><span>Dòng phát hiện</span><strong>{lineNumber || '-'}</strong></div>
              <div><span>Quy tắc OpenGrep</span><strong>{ruleId || 'Chưa có mã quy tắc'}</strong></div>
            </div>
            {filePath && <p className="ntk-p06-file-path" title={filePath}>{filePath}</p>}
            {snippet && <div className="ntk-p06-code-wrap">
              <h3>Đoạn mã được backend cung cấp</h3>
              <pre><code>{snippet.slice(0,5000)}</code></pre>
              {snippet.length>5000 && <small>Đoạn mã được rút gọn trên giao diện; bản gốc vẫn thuộc dữ liệu backend.</small>}
            </div>}
          </Card>
        </section>

        {(recommended || guide.suggestion) && <section className="section-block ntk-p06-section">
          <SectionTitle title="Hướng kiểm tra và khắc phục" />
          <Card className="ntk-p06-guidance">
            <p><strong className="ntk-p06-guidance-label">{guide.code}:</strong> {recommended || guide.suggestion}</p>
          </Card>
        </section>}

        <details className="ntk-p06-technical">
          <summary><span><Icon name="Layers" /> Chi tiết kỹ thuật và căn cứ chấm điểm</span><Icon name="ChevronDown" /></summary>
          <div className="ntk-p06-technical-body">
            {referenceScore && <>
              <h3>16 chỉ số CWSS và cách chấm điểm</h3>
              <p className="ntk-p07-weight-note">Trọng số là hệ số từ 0 đến 1 do backend cung cấp, không phải điểm CWSS riêng. Cột Nguồn cho biết dữ liệu được suy ra từ mã, ước lượng hay dựa trên điều kiện tham chiếu.</p>
              <div className="table-wrap"><table className="ntk-p06-metric-table">
                <thead><tr><th>Chỉ số</th><th>Mức đánh giá</th><th>Trọng số</th><th>Nguồn</th><th>Giải thích</th></tr></thead>
                <tbody>{Object.entries(referenceScore.metric_assessments || {}).map(([name,m])=>(
                  <tr key={name}>
                    <td><strong className="ntk-p07-metric-title">{metricTitle(name)}</strong><span className="ntk-p07-metric-code">{name}</span></td>
                    <td>{metricLevel(name,m)} <span className="ntk-p07-value-code">({m?.code ?? '-'})</span></td>
                    <td className="ntk-p07-metric-weight">{metricWeight(m)}</td>
                    <td>{metricSource(m)}</td>
                    <td>{metricExplanation(name,m)}</td>
                  </tr>
                ))}</tbody>
              </table></div>
            </>}
            {baseline && <p><strong>Điểm đối chiếu GENERAL_JAVA:</strong> {validCwssScore(baseline)===null ? 'Chưa có' : `${validCwssScore(baseline).toFixed(1)}/100`}.</p>}
            {cwssState.status==='loading' && <p>Đang tải điểm đối chiếu GENERAL_JAVA…</p>}
            {cwssState.status==='error' && <p>Không tải được điểm đối chiếu: {cwssState.error} <button type="button" className="button-secondary" onClick={retryCwss}>Thử lại</button></p>}
            <details className="ntk-p06-raw-json">
              <summary>Dữ liệu bằng chứng gốc và provenance (JSON)</summary>
              <pre><code>{JSON.stringify({
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
                reason_codes:flat?.reason_codes,
                scenario:referenceScore,
                baseline_general_java:baseline
              },null,2)}</code></pre>
            </details>
          </div>
        </details>
      </>}
    </div>
  );
}

export function Results() {
  const scanId=useActiveScanId();
  if (scanId) return <LiveDashboard scanId={scanId} />;
  return <LegacyResults />;
}

function LegacyResults() {
  const sel=useScanSelection();
  if (sel.mode==='live') {
    return <LiveGate sel={sel} title="Kết quả phát hiện">{(data)=> <LiveResultsBody data={data} table={<FindingsTable rows={data.rows} scanId={data.scanId} />} />}</LiveGate>;
  }
  const demo=sel.mode==='demo';
  const rows=demo ? demoFindings : [];
  return (
    <>
      <PageHeader eyebrow="PHIЁN PHÂN TÍCH" title={demo ? 'Kết quả minh họa' : 'Kết quả phát hiện'} description={demo ? 'Bộ dữ liệu synthetic dùng để minh họa cách trình bày; không phải kết quả quét thực tế.' : 'Chưa có scan LIVE được nạp trong phiên này.'} actions={<Link to="/scanner" className="button-secondary"><Icon name="Plus" />Phiên phân tích mới</Link>} />
      {demo && <DataNotice>Dữ liệu mô phỏng - không phải kết quả quét thực tế. Các findings bên dưới chỉ minh họa giao diện, không xuất phát từ backend.</DataNotice>}
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
            <Card title="Trạng thái bằng chứng IRIS">{['PROVEN_TAINT','PROVEN_SAFE','UNKNOWN'].map((state)=> <BarRow key={state} label={state} value={rows.filter((row)=> irisProofState(row)===state).length} max={4} color={state==='PROVEN_TAINT' ? 'red' : state==='PROVEN_SAFE' ? 'green' : 'amber'} />)}</Card>
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
        {filtered.length ? <div className="table-wrap"><table><thead><tr><th>Finding</th><th>CWE / loại vấn đề</th><th>File · line</th><th>Bằng chứng IRIS</th><th>Triage</th><th></th></tr></thead><tbody>{filtered.map((row)=> {const proof=irisProofState(row); return <tr key={row.id}><td className="mono">{row.id}</td><td><Badge tone="blue">{row.cwe||'-'}</Badge><br />{row.title}</td><td className="mono">{String(row.file).split('/').slice(-1)}:{row.line}</td><td><Badge tone={irisProofTone(proof)}>{proof}</Badge></td><td><Badge tone={toneOf(row.decision)}>{row.decision||'-'}</Badge></td><td><Link className="table-link" to={`/finding/${encodeURIComponent(row.id)}${scanQuery(scanId)}`}>Chi tiết <Icon name="ArrowUpRight" /></Link></td></tr>;})}</tbody></table></div> : <EmptyState title="Không tìm thấy finding" text="Thay đổi bộ lọc hoặc từ khóa tìm kiếm." />}
      </Card>
    </section>
  );
}

export function FindingDetail() {
  const scanId=useActiveScanId();
  const location=useLocation();
  const id=decodeURIComponent(window.location.hash.split('?')[0].split('/').pop());
  if (scanId) return <LiveDetailPage key={`${scanId}:${id}`} scanId={scanId} id={id} detailUrl={location.state?.detailUrl} />;
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
      <DataNotice>Finding synthetic minh họa - không phải kết quả phát hiện thực tế.</DataNotice>
      <div className="finding-summary"><StatCard label="Trạng thái bằng chứng IRIS" value={irisProofState(finding)} note={irisProofExplanation(irisProofState(finding))} icon="GitBranch" tone="blue" /><StatCard label="Triage" value={finding.decision} note="Chưa có chuyên gia xác nhận" icon="ScanEye" tone="violet" /></div>
      <Card title="Evidence explorer">
        <div className="evidence-tabs">{tabs.map((item)=> <button className={tab===item ? 'active' : ''} key={item} onClick={()=> setTab(item)}>{item}</button>)}</div>
        <div className="evidence-panel"><h3>{tab}</h3><p>{tab==='OpenGrep' ? 'Rule match candidate và vị trí code trong dữ liệu synthetic.' : tab==='IRIS' ? 'Chưa có verified dataflow trace trong ví dụ này.' : tab==='Language Model' ? `API role minh họa: ${finding.role}. Đây không phải xác nhận lỗ hổng.` : tab==='Scoring' ? 'CWSS V2 chưa được tính cho dữ liệu synthetic minh họa.' : finding.reason}</p></div>
      </Card>
      <section className="section-block"><SectionTitle title="Code context" text="Đoạn mã minh họa, không phải source code từ repository thật." /><Card className="code-card"><div className="code-header"><span className="mono">{finding.file}</span><Badge>JAVA · SAMPLE</Badge></div><pre><code>{` 81 public List<User> findUser(String input) {\n 82 String query="SELECT * FROM users WHERE name='" + input + "'";\n 83 // Candidate location for review\n 84 return statement.executeQuery(query);\n 85}`}</code></pre></Card></section>
    </>
  );
}