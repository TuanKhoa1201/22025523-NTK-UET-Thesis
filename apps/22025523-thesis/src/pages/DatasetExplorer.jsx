import {useEffect, useState} from 'react';
import {Card, PageHeader, SectionTitle, Badge, DataNotice, EmptyState, Icon} from '../components/common/Ui';
import {api} from '../services/api';

const DATASETS = [
  ['track_a_trusted_gold', 'Track A · Trusted Gold Pilot'],
  ['track_b_audited_full', 'Track B · Audited Full'],
  ['dev_vnext_3_1', 'Development · VNext.3.1'],
  ['quarantine_review_queue', 'Quarantine · Review Queue']
];

function DatasetCard({item}) {
  return <Card className="dataset-stat"><span className="dataset-count">{Number(item.row_count ?? 0).toLocaleString()}</span><h3>{item.title || item.dataset_id}</h3><p>{item.dataset_id}</p><p>SHA-256 {item.sha256_verified ? 'đã xác minh' : 'chưa xác minh'} · row count {item.row_count_verified ? 'đã xác minh' : 'chưa xác minh'}</p><p>{item.training_eligibility_status || (item.training_eligible ? 'Đủ điều kiện huấn luyện' : 'Không dùng huấn luyện')}</p></Card>;
}

function Cell({value, children, className = ''}) {
  const text = value === undefined || value === null ? '' : String(value);
  return <td className={`cell-trunc ${className}`} title={text}>{children ?? (text || '—')}</td>;
}

function fieldRows(value) {
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).map(([key, item]) => [
    key.replaceAll('_', ' '),
    item && typeof item === 'object' ? JSON.stringify(item) : String(item)
  ]);
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
  const [split, setSplit] = useState('');
  const [provenance, setProvenance] = useState('');
  const [goldOnly, setGoldOnly] = useState('');
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
    const params = {page, page_size: pageSize, q: debouncedQuery, cwe, role, split, provenance_tier: provenance, in_track_a_gold_subset: goldOnly};
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
  }, [datasetId, page, pageSize, debouncedQuery, cwe, role, split, provenance, goldOnly]);

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
  const training = manifest?.eo06_training_provenance || {};
  const trainingSet = entries.find((row) => row.dataset_id === training.primary_training_dataset_id);
  const privacy = manifest?.privacy_and_redistribution_audit || {};
  const licenseDistribution = trainingSet?.distribution?.by_spdx_license || {};
  const knownLicenses = Object.keys(licenseDistribution).filter((name) => name && name !== 'UNKNOWN');
  const trainingRun = training.eo06_run_id ?? training.training_execution_receipt?.run_id;
  const trackB = training.primary_training_dataset_rows;
  const trackA = training.pilot_subset_dataset_rows;
  const devRows = training.validation_dataset_rows;
  const privacyRows = fieldRows(manifest?.privacy_and_redistribution_audit);

  return (
    <>
      <PageHeader eyebrow="NGHIÊN CỨU · DỮ LIỆU" title="Dữ liệu nghiên cứu và kiểm soát chất lượng" description="Manifest, bản ghi phân trang và artifact tải xuống được lấy trực tiếp từ backend." actions={
        <div className="guided-actions">{['csv', 'jsonl', 'xlsx'].map((format) => <button key={format} className="button-secondary" disabled={Boolean(exporting)} onClick={() => exportDataset(format)}><Icon name="Download" />{exporting === format ? 'Đang tải…' : `Tải ${format.toUpperCase()}`}</button>)}</div>
      } />
      {manifestError && <div className="inline-error" role="alert">{manifestError}</div>}
      <DataNotice>{training.track_a_is_strict_subset_of_track_b === true
        ? 'Backend xác nhận Track A nằm trong Track B; không cộng chồng. Development chỉ phục vụ validation; Quarantine không dùng để huấn luyện.'
        : 'Đang chờ manifest dataset xác thực để hiển thị quan hệ tập huấn luyện, validation và quarantine.'}</DataNotice>
      <div className="dataset-cards">{(entries.length ? entries : DATASETS.map(([dataset_id, title]) => ({dataset_id, title, row_count: '—'}))).map((item) => <DatasetCard key={item.dataset_id} item={item} />)}</div>
      <Card className="model-card" title="Fine-tuning provenance">
        <div className="model-card-grid"><div><span>BASE MODEL</span><strong>{training.base_model_id || 'Chưa có thông tin từ backend'}</strong></div><div><span>ADAPTER</span><strong>{training.best_adapter_arm_id || 'Chưa có thông tin từ backend'}</strong></div><div><span>CHECKPOINT</span><strong>{training.best_adapter_arm_id && training.best_checkpoint_epoch ? `${training.best_adapter_arm_id}_epoch${training.best_checkpoint_epoch}` : 'Chưa có thông tin checkpoint'}</strong></div><div><span>RELEASE</span><strong>{manifest?.dataset_release_version || '—'}</strong></div></div>
        <h4>Model and Training</h4>
        <div className="model-card-grid">
          <div><span>TRAINING DATASET</span><strong>{trainingSet?.title || training.primary_training_dataset_id || 'Chưa xác định được nguồn huấn luyện'}</strong></div>
          <div><span>TRAINING SPLIT</span><strong>{trackB != null ? `Train Track B: ${trackB} mẫu${devRows != null ? ` · Dev: ${devRows} mẫu` : ''}` : 'Chưa xác định tập chia'}</strong></div>
          <div><span>TRAINING RUN ID</span><strong>{trainingRun || 'Chưa có run ID'}</strong></div>
        </div>
        <h4>API Role Taxonomy</h4>
        <div className="role-badges">{['source', 'sink', 'taint-propagator', 'none'].map((value) => <Badge tone="blue" key={value}>{value}</Badge>)}</div>
        {manifest?.api_role_taxonomy && <details className="technical-details"><summary>Chi tiết taxonomy từ manifest</summary><pre><code>{JSON.stringify(manifest.api_role_taxonomy, null, 2)}</code></pre></details>}
        <h4>Data Quality and Provenance</h4>
        <div className="model-card-grid">
          <div><span>VERIFIED PROVENANCE</span><strong>{privacy.all_training_records_open_source_spdx_verified === true ? 'Đã kiểm chứng đối với Track B' : 'Chưa được xác nhận'}</strong></div>
          <div><span>SPDX LICENSING</span><strong>{knownLicenses.length ? knownLicenses.join(', ') : privacy.all_training_records_open_source_spdx_verified === true ? 'SPDX nguồn mở đã xác minh (xem phân bố từng dataset)' : 'Chưa xác định SPDX'}</strong></div>
          <div><span>TRACK B JSONL SHA-256</span><strong>{training.primary_training_dataset_sha256 || 'Chưa có checksum'}</strong></div>
          <div><span>TRAINING ELIGIBILITY</span><strong>{trainingSet?.training_eligibility_status || 'Chưa có trạng thái xét duyệt'}</strong></div>
          <div><span>TRACK A INCLUSION POLICY</span><strong>{training.track_a_is_strict_subset_of_track_b === true && trackA != null && trackB != null ? `Track A (${trackA}) nằm trong Track B (${trackB}); không cộng chồng` : 'Chưa xác nhận quan hệ hai tập'}</strong></div>
          <div><span>ADAPTER SHA-256</span><strong>{training.best_adapter_sha256 || 'Chưa có checksum adapter'}</strong></div>
        </div>
        <p className="panel-note">Mã SHA-256 ở trên thuộc JSONL Track B dùng cho training; dữ liệu Excel xuất từ API có checksum riêng. Đối chiếu execution receipt khi đánh giá kết quả huấn luyện.</p>
        <h4>Privacy Audit</h4>
        {privacyRows.length
          ? <div className="model-card-grid">{privacyRows.map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}</div>
          : <p>Manifest chưa cung cấp privacy and redistribution audit.</p>}
        {manifest?.privacy_and_redistribution_audit && <details className="technical-details"><summary>Privacy audit JSON từ manifest</summary><pre><code>{JSON.stringify(manifest.privacy_and_redistribution_audit, null, 2)}</code></pre></details>}
        <h4>Export formats</h4>
        <div className="role-badges">{['CSV', 'JSONL', 'XLSX'].map((format) => <Badge tone="violet" key={format}>{format}</Badge>)}</div>
      </Card>
      <section className="section-block">
        <SectionTitle title="Data Explorer · bản ghi từ backend" text="Bộ lọc và phân trang được gửi tới API; giá trị dài được cắt hiển thị (rê chuột để xem đầy đủ) nhưng tệp xuất không bị cắt." />
        <Card className="table-card">
          <div className="table-toolbar">
            <select value={datasetId} onChange={(event) => {setDatasetId(event.target.value); setPage(1);}}>{DATASETS.map(([id, label]) => <option value={id} key={id}>{label}</option>)}</select>
            <input value={query} onChange={(event) => {setQuery(event.target.value); setPage(1);}} placeholder="Tìm sample, class, method..." />
            <input value={cwe} onChange={changeFilter(setCwe)} placeholder="CWE, ví dụ CWE-089" />
            <input value={role} onChange={changeFilter(setRole)} placeholder="API role" />
            <input value={split} onChange={changeFilter(setSplit)} placeholder="Split" />
            <input value={provenance} onChange={changeFilter(setProvenance)} placeholder="Provenance tier" />
            <select value={goldOnly} onChange={changeFilter(setGoldOnly)}><option value="">Track A subset: tất cả</option><option value="true">Chỉ Track A gold</option><option value="false">Ngoại trừ Track A gold</option></select>
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
          <div className="pagination"><span>{Number(pageInfo.total_matching_rows ?? 0).toLocaleString()} kết quả · {Number(pageInfo.total_dataset_rows ?? selected?.row_count ?? 0).toLocaleString()} dòng trong dataset · Trang {pageInfo.page || page}/{totalPages || '—'}</span><select value={pageSize} onChange={(event) => {setPageSize(Number(event.target.value)); setPage(1);}}><option value={20}>20 / trang</option><option value={50}>50 / trang</option><option value={100}>100 / trang</option></select><button disabled={!pageInfo.has_prev_page} onClick={() => setPage((value) => Math.max(1, value - 1))}>Trang trước</button><button disabled={!pageInfo.has_next_page} onClick={() => setPage((value) => value + 1)}>Trang sau</button></div>
        </Card>
      </section>
      {selected?.distribution && <Card title="Phân bố backend"><pre><code>{JSON.stringify(selected.distribution, null, 2)}</code></pre></Card>}
      {selected?.quality_gate_summary && <Card title="Quality gate summary"><pre><code>{JSON.stringify(selected.quality_gate_summary, null, 2)}</code></pre></Card>}
    </>
  );
}