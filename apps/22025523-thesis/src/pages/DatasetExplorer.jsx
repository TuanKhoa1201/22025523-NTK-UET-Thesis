import {useEffect, useState} from 'react';
import {Card, PageHeader, SectionTitle, Badge, DataNotice, EmptyState, Icon} from '../components/common/Ui';
import {api} from '../services/api';

const DATASETS = [
  ['track_a_trusted_gold', 'Track A · Trusted Gold Pilot'],
  ['track_b_audited_full', 'Track B · Audited Full'],
  ['dev_vnext_3_1', 'Development · VNext.3.1'],
  ['quarantine_review_queue', 'Quarantine · Review Queue']
];

const DATASET_COPY = {
  track_a_trusted_gold: ['Track A · Dữ liệu tin cậy', 'Tập mẫu chọn lọc để đối chiếu chất lượng.'],
  track_b_audited_full: ['Track B · Dữ liệu huấn luyện', 'Tập dữ liệu chính dùng để tinh chỉnh mô hình.'],
  dev_vnext_3_1: ['Dữ liệu đánh giá', 'Dùng để kiểm tra mô hình, không dùng để huấn luyện.'],
  quarantine_review_queue: ['Dữ liệu chờ rà soát', 'Tạm loại khỏi huấn luyện để kiểm soát chất lượng.']
};

function DatasetCard({item}) {
  const [name, detail] = DATASET_COPY[item.dataset_id] || [item.title || item.dataset_id, 'Dữ liệu nghiên cứu.'];
  const numericCount = Number(item.row_count);
  const count = item.row_count === undefined || item.row_count === null || !Number.isFinite(numericCount)
    ? '-' : numericCount.toLocaleString('vi-VN');
  return <Card className="dataset-stat ntk-p05-dataset-stat"><span className="dataset-count">{count}</span><h3>{name}</h3><p>{detail}</p></Card>;
}

function Cell({value, children, className = ''}) {
  const text = value === undefined || value === null ? '' : String(value);
  return <td className={`cell-trunc ${className}`} title={text}>{children ?? (text || '-')}</td>;
}

function downloadName(disposition, datasetId, format) {
  const match = disposition.match(/filename="?([^";]+)"?/i);
  return match?.[1] || `${datasetId}.${format}`;
}

export default function DatasetExplorer() {
  const [manifest, setManifest] = useState(null);
  const [manifestError, setManifestError] = useState('');
  const [datasetId, setDatasetId] = useState(DATASETS[1][0]);
  const [records, setRecords] = useState([]);
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [cwe, setCwe] = useState('');
  const [role, setRole] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [pageInfo, setPageInfo] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [exportError, setExportError] = useState('');
  const [exporting, setExporting] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    api.datasetManifest({signal: controller.signal})
      .then(setManifest)
      .catch((failure) => {
        if (!controller.signal.aborted) setManifestError(failure.message || 'Không tải được manifest.');
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedQuery(query.trim()), 350);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    const controller = new AbortController();
    const params = {page, page_size: pageSize, q: debouncedQuery, cwe, role};
    setLoading(true);
    setError('');
    api.datasetRecords(datasetId, params, {signal: controller.signal})
      .then((response) => {
        if (controller.signal.aborted) return;
        setRecords(Array.isArray(response?.records) ? response.records : []);
        setPageInfo(response || {});
      })
      .catch((failure) => {
        if (!controller.signal.aborted) {
          setRecords([]);
          setError(failure.message || 'Không thể tải dữ liệu từ backend.');
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [datasetId, page, pageSize, debouncedQuery, cwe, role]);

  const changeFilter = (setter) => (event) => {
    setter(event.target.value);
    setPage(1);
  };

  const exportDataset = async (format) => {
    setExporting(format);
    setExportError('');
    let objectUrl = '';
    try {
      const result = await api.datasetExport(datasetId, format);
      objectUrl = URL.createObjectURL(result.blob);
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = downloadName(result.disposition, datasetId, format);
      link.click();
    } catch (failure) {
      setExportError(failure.message || `Không tải được ${format}.`);
    } finally {
      if (objectUrl) window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      setExporting('');
    }
  };

  const entries = Array.isArray(manifest?.datasets) ? manifest.datasets : [];
  const selected = entries.find((item) => item.dataset_id === datasetId);
  const totalPages = Number(pageInfo.total_pages || 0);

  return (
    <>
      <PageHeader eyebrow="NGHIÊN CỨU · DỮ LIỆU" title="Dữ liệu nghiên cứu và kiểm soát chất lượng" actions={
        <div className="guided-actions">{['csv', 'jsonl', 'xlsx'].map((format) => <button key={format} className="button-secondary" disabled={Boolean(exporting)} onClick={() => exportDataset(format)}><Icon name="Download" />{exporting === format ? 'Đang tải…' : `Tải ${format.toUpperCase()}`}</button>)}</div>
      } />
      {manifestError && <div className="inline-error" role="alert">{manifestError}</div>}
      <div className="dataset-cards">{(entries.length ? entries : DATASETS.map(([dataset_id, title]) => ({dataset_id, title, row_count: '-'}))).map((item) => <DatasetCard key={item.dataset_id} item={item} />)}</div>
      <section className="section-block">
        <SectionTitle title="Khám phá dữ liệu" />
        <Card className="table-card">
          <div className="table-toolbar">
            <select value={datasetId} onChange={(event) => {setDatasetId(event.target.value); setPage(1);}}>{DATASETS.map(([id, label]) => <option value={id} key={id}>{label}</option>)}</select>
            <input value={query} onChange={(event) => {setQuery(event.target.value); setPage(1);}} placeholder="Tìm sample, class, method..." />
            <input value={cwe} onChange={changeFilter(setCwe)} placeholder="CWE, ví dụ CWE-089" />
            <input value={role} onChange={changeFilter(setRole)} placeholder="API role" />
          </div>
          {exportError && <div className="inline-error" role="alert">{exportError}</div>}
          {error && <div className="inline-error" role="alert">{error}</div>}
          <div className="table-wrap">
            <table><thead><tr><th>Sample ID</th><th>CWE</th><th>API</th><th>Signature</th><th>Role</th><th>Provenance</th><th>Split</th></tr></thead>
              <tbody>{records.map((row) => (
                <tr key={row.sample_id}>
                  <Cell value={row.sample_id} className="mono" />
                  <Cell value={row.cwe}><Badge tone="blue">{row.cwe}</Badge></Cell>
                  <Cell value={`${row.package_name} ${row.class_name}.${row.method_name}`} className="mono" />
                  <Cell value={row.signature} className="mono" />
                  <Cell value={row.role}><Badge tone="violet">{row.role}</Badge></Cell>
                  <Cell value={row.provenance_tier || row.evidence_tier} />
                  <Cell value={`${row.split ?? ''}${row.in_track_a_gold_subset ? ' · Track A' : ''}`} />
                </tr>
              ))}</tbody>
            </table>
            {loading && <DataNotice>Đang tải trang từ backend…</DataNotice>}
            {!loading && !error && !records.length && <EmptyState title="Không có bản ghi phù hợp" text="Không có dữ liệu thay thế minh họa; kiểm tra dataset hoặc bộ lọc." />}
          </div>
          <div className="pagination"><span>{Number(pageInfo.total_matching_rows ?? 0).toLocaleString()} kết quả · {Number(pageInfo.total_dataset_rows ?? selected?.row_count ?? 0).toLocaleString()} dòng trong dataset · Trang {pageInfo.page || page}/{totalPages || '-'}</span><select value={pageSize} onChange={(event) => {setPageSize(Number(event.target.value)); setPage(1);}}><option value={20}>20 / trang</option><option value={50}>50 / trang</option><option value={100}>100 / trang</option></select><button disabled={!pageInfo.has_prev_page} onClick={() => setPage((value) => Math.max(1, value - 1))}>Trang trước</button><button disabled={!pageInfo.has_next_page} onClick={() => setPage((value) => value + 1)}>Trang sau</button></div>
        </Card>
      </section>
      {selected?.distribution && <details className="ntk-p05-distribution">
        <summary><span>Phân bố dữ liệu</span><Icon name="ChevronDown" /></summary>
        <div className="ntk-p05-distribution-content">
          {[
            ['Theo vai trò API', selected.distribution.by_role],
            ['Theo loại lỗ hổng (CWE)', selected.distribution.by_cwe]
          ].map(([heading, values]) => <section key={heading}>
            <h3>{heading}</h3>
            {Object.entries(values || {}).length ? <div className="ntk-p05-distribution-list">
              {Object.entries(values).map(([label, value]) => <div key={label}><span>{label}</span><strong>{Number(value).toLocaleString('vi-VN')}</strong></div>)}
            </div> : <p>Chưa có dữ liệu phân bố.</p>}
          </section>)}
        </div>
      </details>}
    </>
  );
}