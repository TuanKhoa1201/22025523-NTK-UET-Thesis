import {Link} from 'react-router-dom';
import {Card, PageHeader, StatCard, Badge, SectionTitle, DataNotice, EmptyState, BarRow, Icon} from '../components/common/Ui';
import {DURATION_FIELDS, scanQuery} from '../services/liveScan';

export function LiveGate({sel, title, children}) {
  const header = <PageHeader eyebrow="PHIÊN PHÂN TÍCH" title={title} description={`Scan LIVE: ${sel.scanId}`} />;
  if (sel.status === 'error') {
    return <>{header}<EmptyState title="Không tải được scan LIVE" text={sel.error} icon="AlertTriangle" /></>;
  }
  if (sel.status !== 'ready' || !sel.data) {
    return <>{header}<DataNotice>Đang tải metadata và findings của scan từ backend…</DataNotice></>;
  }
  return children(sel.data);
}

const distribution = (rows, key) => {
  const counts = new Map();
  rows.forEach((row) => {
    const label = String(row[key] || 'Không có dữ liệu');
    counts.set(label, (counts.get(label) || 0) + 1);
  });
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
};

function Bars({title, entries}) {
  const max = Math.max(1, ...entries.map(([, value]) => value));
  return <Card title={title}>{entries.map(([label, value]) => <BarRow key={label} label={label} value={value} max={max} color="blue" />)}</Card>;
}

export function LiveResultsBody({data, table}) {
  const {rows, counts, scan, findingsPayload} = data;
  const summary = findingsPayload?.summary || scan?.summary || {};
  const scalars = Object.entries(summary).filter(([, value]) => ['string', 'number', 'boolean'].includes(typeof value));
  const durations = DURATION_FIELDS.filter(([key]) => Number.isFinite(Number(scan?.[key])) && scan?.[key] !== null);
  return (
    <>
      <PageHeader eyebrow="PHIÊN PHÂN TÍCH" title="Kết quả phân tích thực tế" description={`Dữ liệu từ backend cho scan ${data.scanId}.`} actions={<Link to="/scanner" className="button-secondary"><Icon name="Plus" />Phiên phân tích mới</Link>} />
      <DataNotice>Thống kê tổng lấy từ summary backend; biểu đồ và danh sách bên dưới chỉ dựa trên {data.pagination?.loaded ?? rows.length} finding đầu tiên đã nạp. CWSS V2 là điểm ưu tiên điểm yếu theo 16 metric, không phải xác suất TP hay CVSS. Điểm theo kịch bản giả định chỉ có ý nghĩa khi đọc cùng nguồn từng metric.</DataNotice>
      {findingsPayload?.cwss_status === 'UNAVAILABLE' && <DataNotice>Không tải được thông tin CWSS; kết quả phát hiện và triage từ backend vẫn được giữ nguyên. Kiểm tra API /cwss/v1/ranking?mode=CWSS_AUTO_COMPLETE và log backend.</DataNotice>}
      {rows.some((row) => row.cwss) && <DataNotice>CWSS Inference V2 đã gắn cho {rows.filter((row) => row.cwss).length} finding. MITRE_DEFAULT và các giả định tham chiếu không phải bằng chứng xác minh môi trường.</DataNotice>}
      <div className="stats-grid">
        <StatCard label="Candidate findings" value={counts.total} note={`LIVE · ${data.scanId}`} icon="Bug" />
        <StatCard label="REPORT" value={counts.report} note="Ưu tiên kiểm tra" icon="ShieldAlert" tone="amber" />
        <StatCard label="REVIEW" value={counts.review} note="Cần xem xét" icon="Eye" tone="blue" />
        <StatCard label="SUPPRESS" value={counts.suppress} note="Giữ trong audit trail" icon="ShieldCheck" tone="green" />
      </div>
      {counts.unclassified > 0 && <DataNotice>{counts.unclassified} finding chưa có quyết định triage trong dữ liệu backend.</DataNotice>}
      <section className="section-block">
        <SectionTitle title="Tổng quan phân bố (mẫu trang đầu)" text="Biểu đồ chỉ dùng các findings đã tải, không đại diện cho toàn bộ scan." />
        <div className="results-grid">
          <Bars title="Findings by severity" entries={distribution(rows, 'severity')} />
          <Bars title="Phân bố CWE" entries={distribution(rows, 'cwe')} />
          <Bars title="Alert triage" entries={distribution(rows, 'decision')} />
        </div>
      </section>
      {(scalars.length > 0 || durations.length > 0) && (
        <section className="section-block">
          <SectionTitle title="Tóm tắt từ backend" text="Giá trị nguyên bản trong trường summary và thời lượng do backend báo cáo." />
          <Card>
            <div className="model-card-grid">
              {scalars.map(([key, value]) => <div key={key}><span>{key}</span><strong>{String(value)}</strong></div>)}
              {durations.map(([key, label]) => <div key={key}><span>{label}</span><strong>{Number(scan[key]).toLocaleString()} ms</strong></div>)}
            </div>
          </Card>
        </section>
      )}
      {table}
    </>
  );
}

export function LiveFindingDetail({data, id}) {
  const row = data.rows.find((item) => item.id === id);
  const back = `/findings${scanQuery(data.scanId)}`;
  if (!row) {
    return <><PageHeader title="Chi tiết finding" description={`Scan ${data.scanId}`} /><EmptyState title="Không tìm thấy finding" text="Finding này không có trong dữ liệu backend của scan đang chọn." /></>;
  }
  return (
    <>
      <PageHeader eyebrow={`FINDING · ${row.id}`} title={row.title || row.id} description={`${row.file}${row.line ? `:${row.line}` : ''} · ${row.cwe}`} actions={<Link to={back} className="button-secondary">Danh sách</Link>} />
      <div className="finding-summary">
        <StatCard label="Severity" value={row.severity || '—'} note="Từ backend" icon="ShieldAlert" tone="amber" />
        <StatCard label="CWSS V2 - GENERAL_JAVA" value={row.cwssScore === null ? 'Chưa có' : row.cwssScore.toFixed(1) + '/100' + (row.cwssProvisional ? ' (provisional)' : '')} note={row.cwss ? `${row.cwssUnknownMetrics} metric Unknown · ${row.cwss.assessment_status}` : 'Chưa tích hợp dữ liệu CWSS'} icon="Gauge" />
        <StatCard label="CWSS V2 - giả định" value={row.cwssScenarioScore === null ? 'Chưa có' : row.cwssScenarioScore.toFixed(1) + '/100'} note="REFERENCE_ASSUMPTION — không phải bối cảnh được xác minh" icon="Gauge" />
        <StatCard label="Triage" value={row.decision || '—'} note="Chưa có xác nhận chuyên gia" icon="ScanEye" tone="violet" />
      </div>
      {row.cwss && <Card title="CWSS Inference V2 - 16 metrics, evidence and status">
        <p>Điểm ưu tiên điểm yếu, không suy ra True Positive hoặc độ nghiêm trọng CVSS. Các metric Unknown cần ngữ cảnh được xác minh.</p>
        <pre><code>{JSON.stringify({
          score: row.cwss.cwss_score,
          status: row.cwss.assessment_status,
          unknown_metrics: row.cwss.unknown_metrics,
          vector: row.cwss.metric_vector,
          metric_assessments: row.cwss.metric_assessments,
          three_subscores: row.cwss.three_subscores,
          normalized_evidence: row.cwss.normalized_evidence,
          inference_version: row.cwss.inference_version
        }, null, 2)}</code></pre>
      </Card>}
      <Card title="Bằng chứng backend (không hiển thị điểm xếp hạng cũ)"><pre><code>{JSON.stringify({
        finding_id:row.id,
        file_path:row.file,
        line_number:row.line,
        cwe:row.cwe,
        evidence:row.evidence,
        triage:row.decision,
      },null,2)}</code></pre></Card>
      <Badge tone="blue">{row.collections.join(' · ')}</Badge>
    </>
  );
}