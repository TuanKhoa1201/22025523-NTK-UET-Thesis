import {lazy, Suspense, useMemo} from 'react';
import {Link} from 'react-router-dom';
import {PageHeader, StatCard, SectionTitle, DataNotice, EmptyState, Icon} from '../components/common/Ui';
import FindingsExplorer from '../components/results/FindingsExplorer';
import {useScanOverview, buildAggregates, IN_SCOPE_CWES} from '../services/scanOverview';
import '../styles/results-dashboard.css';

const OverviewCharts = lazy(() => import('../components/results/OverviewCharts'));
const n = (v) => (v === undefined || v === null || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
const fmt = (v) => (v === null ? '-' : v.toLocaleString());
const firstOf = (obj, keys) => {
  for (const src of [obj, obj?.summary]) {
    for (const key of keys) if (src?.[key] !== undefined && src?.[key] !== null && src?.[key] !== '') return src[key];
  }
  return undefined;
};

// agg is null until the finding list is verified COMPLETE; loaded rows are then
// never used as a stand-in for whole-scan KPIs (value shows "-" instead).
function Kpis({summary, rows, agg, backendTotal}) {
  const totals = summary.triage_totals || {};
  const dec = (d) => n(totals[`${d.toLowerCase()}_count`]) ?? (agg ? agg.byDecision.find(([k]) => k === d)?.[1] ?? 0 : null);
  const total = n(summary.total_findings ?? totals.total_candidates) ?? (agg ? rows.length : null);
  const cwes = agg ? agg.byCwe.filter(([k]) => IN_SCOPE_CWES.includes(k)).length : null;
  return (
    <>
      <div className="stats-grid rd-kpis">
        <StatCard label="File Java đã quét" value={fmt(n(summary.java_files_scanned))} note="Từ summary backend" icon="ScanSearch" />
        <StatCard label="Tổng findings" value={fmt(total)} note="Toàn bộ scan" icon="Bug" />
        <StatCard label="Findings đã tải / backend" value={`${rows.length.toLocaleString()} / ${fmt(backendTotal ?? null)}`} note={agg ? 'Đã xác minh đầy đủ' : 'Chưa xác minh đầy đủ'} icon="Database" tone={agg ? 'green' : 'amber'} />
        <StatCard label="REPORT" value={fmt(dec('REPORT'))} note="Ưu tiên kiểm tra, chưa xác nhận TP" icon="ShieldAlert" tone="amber" />
        <StatCard label="REVIEW" value={fmt(dec('REVIEW'))} note="Cần xem xét thêm" icon="Eye" tone="blue" />
        <StatCard label="SUPPRESS" value={fmt(dec('SUPPRESS'))} note="Giữ audit trail, chưa xác nhận FP" icon="ShieldCheck" tone="green" />
        <StatCard label="CWE trong phạm vi" value={cwes === null ? '-' : `${cwes} / ${IN_SCOPE_CWES.length}`} note="CWE-22, 78, 79, 89 có finding" icon="Filter" />
      </div>
    </>
  );
}

export function LiveFindings({scanId}) {
  const [state, retry] = useScanOverview(scanId);
  const data = state.data;
  const agg = useMemo(() => (data?.complete ? buildAggregates(data.rows, data.scores) : null), [data]);
  const scoreInfo = useMemo(() => (data
    ? {status: data.scoreStatus, total: data.rows.length, scored: data.rows.filter((row) => data.scores.has(row.id)).length}
    : null), [data]);
  const header = <PageHeader eyebrow="PHIÊN PHÂN TÍCH" title="Kết quả phát hiện" description={`Scan LIVE: ${scanId}`} actions={<Link to="/scanner" className="button-secondary"><Icon name="Plus" />Phiên phân tích mới</Link>} />;
  if (!scanId) {
    return <>{header}<EmptyState title="Chưa chọn scan" text="Hãy chạy một phiên phân tích mới hoặc mở Lịch sử để chọn scan." icon="Inbox" /></>;
  }
  if (state.status === 'loading') {
    const p = state.progress;
    return <>{header}<DataNotice>Đang tải toàn bộ findings của scan từ backend{p ? ` (${p.loaded.toLocaleString()}${p.total ? ` / ${p.total.toLocaleString()}` : ''})` : ''}… Số liệu tổng thể chỉ hiển thị khi tải đủ.</DataNotice></>;
  }
  if (state.status === 'error') {
    return <>{header}<EmptyState title="Không tải được kết quả" text={state.error} icon="AlertTriangle" /><button className="button-secondary" onClick={retry}>Thử lại</button></>;
  }
  const summary = data.summary;
  const iris = String(firstOf(summary, ['iris_status', 'iris_analysis_status', 'iris_run_status']) ?? data.irisTrace?.status ?? '');
  const irisReasons = data.irisTrace?.reasonCodes || [];
  return (
    <>
      {header}
      {iris.includes('PARTIAL') && <DataNotice>{iris}: IRIS/CodeQL chỉ phân tích một phần, chưa chứng minh bao phủ đầy đủ dataflow. Thiếu bằng chứng không đồng nghĩa an toàn. {irisReasons.length > 0 && `Reason codes: ${irisReasons.join(', ')}`}</DataNotice>}
      {String(firstOf(summary, ['coverage_status']) || '').includes('PARTIAL') && <DataNotice>Coverage {String(firstOf(summary, ['coverage_status']))}: đây là quét một phần, chưa bao phủ toàn bộ dự án. Chỉ phân tích Java cho CWE-22, 78, 79, 89.</DataNotice>}
      <Kpis summary={summary} rows={data.rows} agg={agg} backendTotal={data.total} />
      {!data.complete && <DataNotice>Mới tải được {data.rows.length.toLocaleString()}{data.total ? ` / ${data.total.toLocaleString()}` : ''} findings (dữ liệu một phần). Biểu đồ toàn scan và bộ lọc bị tạm ẩn để không hiển thị số liệu một phần như tổng toàn scan. <button className="button-secondary" onClick={retry}>Tải lại</button></DataNotice>}
      {!data.complete && data.reason && <DataNotice>Chưa xác minh đầy đủ: {data.reason}</DataNotice>}
      {data.scoreStatus === 'error' && <DataNotice>Không tải được điểm CWSS; bằng chứng và triage vẫn giữ nguyên. Biểu đồ phân bố điểm CWSS được tạm ẩn. <button className="button-secondary" onClick={retry}>Thử lại</button></DataNotice>}
      {data.scoreStatus === 'partial' && <DataNotice>Điểm CWSS của hồ sơ đã chọn chưa đủ hoặc không khớp findings; biểu đồ điểm toàn scan được tạm ẩn để tránh kết luận sai.</DataNotice>}
      {agg && (
        <section className="section-block">
          <SectionTitle title="Tổng quan toàn scan" text={`Tính từ ${data.rows.length.toLocaleString()} findings đã tải đủ qua /findings/page; CWSS ghép bằng finding_id.`} />
          <Suspense fallback={<DataNotice>Đang dựng biểu đồ…</DataNotice>}><OverviewCharts agg={agg} scoreInfo={scoreInfo} /></Suspense>
        </section>
      )}
      {data.complete && !data.rows.length && <EmptyState title="Đã hoàn thành phân tích" text="Không phát hiện ứng viên lỗ hổng thuộc phạm vi quy tắc hiện tại. Kết quả không chứng minh ứng dụng an toàn." />}
      {data.complete && data.rows.length > 0 && <FindingsExplorer rows={data.rows} scores={data.scores} scanId={scanId} />}
    </>
  );
}