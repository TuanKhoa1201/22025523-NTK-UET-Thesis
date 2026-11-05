import { useEffect, useMemo, useState } from 'react';
import {api} from '../services/api';
import { Card, PageHeader, SectionTitle, Badge, BarRow, DataNotice, EmptyState } from '../components/common/Ui';
import { Icon } from '../components/common/Ui';
import { datasetSamples, roleLabels } from '../data/research';

const workflowTraining = ['Nguồn dữ liệu', 'Provenance', 'Quality gates', 'Role annotation', 'LoRA fine-tuning', 'Evaluation', 'Checkpoint'];
const workflowRuntime = ['Java repository / ZIP', 'Source inventory', 'OpenGrep', 'IRIS context & dataflow', 'Qwen role inference', 'Evidence fusion', 'Scoring & triage', 'Findings'];

export function Architecture() {
  const [selected, setSelected] = useState('OpenGrep');
  const [simple, setSimple] = useState(false);
  const steps = ['OpenGrep', 'IRIS', 'Qwen2.5-Coder + LoRA', 'Evidence Fusion', 'Alert Triage'];
  const descriptions = {
    OpenGrep: ['Tìm dấu hiệu đáng nghi.', 'Rule matches và candidate findings.', 'Có thể bỏ sót lỗ hổng; candidate chưa phải kết luận.'],
    IRIS: ['Kiểm tra ngữ cảnh và đường đi dữ liệu.', 'Java context, cấu trúc và dataflow trong phạm vi hỗ trợ.', 'Không mặc định chứng minh được dataflow liên thủ tục.'],
    'Qwen2.5-Coder + LoRA': ['Phân loại vai trò API.', 'source, sink, taint-propagator hoặc none.', 'Role classification không tự xác nhận vulnerability.'],
    'Evidence Fusion': ['Tổng hợp các tín hiệu.', 'Evidence và score theo policy hệ thống.', 'CWSS V2 là lớp ưu tiên điểm yếu độc lập, không phải xác suất TP.'],
    'Alert Triage': ['Hỗ trợ ưu tiên kiểm tra.', 'REPORT, REVIEW hoặc SUPPRESS cùng reason codes.', 'REPORT không đồng nghĩa chuyên gia đã xác nhận.']
  };
  return (
    <>
      <PageHeader eyebrow="NỀN TẢNG" title="Kiến trúc hệ thống" description="Hai luồng nghiên cứu và vận hành, được trình bày riêng để làm rõ vai trò từng thành phần." actions={<button className={`button-secondary ${simple ? 'selected' : ''}`} onClick={() => setSimple(!simple)}><Icon name="BookOpen" />{simple ? 'Giải thích kỹ thuật' : 'Giải thích đơn giản'}</button>} />
      <ArchitectureFlow title="A · Giai đoạn nghiên cứu và huấn luyện" steps={workflowTraining} accent="violet" />
      <ArchitectureFlow title="B · Giai đoạn phân tích mã nguồn" steps={workflowRuntime} />
      <section className="section-block"><SectionTitle title="Vai trò và giới hạn" text="Chọn một thành phần để xem input, output và giới hạn phân tích." />
        <div className="architecture-layout"><div className="architecture-nodes">{steps.map((step, i) => <button key={step} className={`architecture-node ${selected === step ? 'active' : ''}`} onClick={() => setSelected(step)}><span>0{i + 1}</span><strong>{step}</strong><Icon name="ArrowRight" /></button>)}</div>
          <Card className="node-detail" title={selected}><div className="detail-grid"><div><span>VAI TRÒ</span><p>{simple ? descriptions[selected][0] : `Thành phần ${selected} bổ sung một lớp tín hiệu vào quy trình phân tích.`}</p></div><div><span>OUTPUT</span><p>{descriptions[selected][1]}</p></div><div><span>GIỚI HẠN</span><p>{descriptions[selected][2]}</p></div></div></Card>
        </div>
      </section>
    </>
  );
}

function ArchitectureFlow({ title, steps, accent = 'blue' }) {
  return <Card className={`flow-card flow-${accent}`} title={title}><div className="flow-scroll">{steps.map((step, index) => <div className="flow-step" key={step}><div className="flow-step-box"><span>0{index + 1}</span><strong>{step}</strong></div>{index < steps.length - 1 && <div className="flow-connector"><i /></div>}</div>)}</div></Card>;
}

export function Dataset() {
  const [query, setQuery] = useState('');
  const [cwe, setCwe] = useState('Tất cả CWE');
  const [role, setRole] = useState('Tất cả role');
  const [page, setPage] = useState(0);
  const rows = useMemo(() => datasetSamples.filter((item) => `${item.id} ${item.className} ${item.method} ${item.package}`.toLowerCase().includes(query.toLowerCase())).filter((item) => cwe === 'Tất cả CWE' || item.cwe === cwe).filter((item) => role === 'Tất cả role' || item.role === role), [query, cwe, role]);
  const download = async () => {
    const XLSX = await import('xlsx');
    const book = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(book, XLSX.utils.json_to_sheet([{ origin: 'synthetic_demo', note: 'Dữ liệu minh họa, không phải dataset nghiên cứu chính thức' }]), 'Overview');
    XLSX.utils.book_append_sheet(book, XLSX.utils.json_to_sheet(datasetSamples), 'Samples');
    XLSX.writeFile(book, 'vulnscope-synthetic-demo.xlsx');
  };
  return (
    <>
      <PageHeader eyebrow="NGHIÊN CỨU · DỮ LIỆU" title="Dữ liệu nghiên cứu và kiểm soát chất lượng" description="Theo dõi cấu trúc dataset, provenance và quality gates trước khi sử dụng trong fine-tuning." actions={<button className="button-primary" onClick={download}><Icon name="Download" />Tải Excel minh họa</button>} />
      <DataNotice>Data Explorer hiện dùng một tập mẫu nhỏ có nhãn <b>Dữ liệu minh họa</b>. Dataset chính thức chưa được nạp vào giao diện; nút tải dataset nghiên cứu sẽ được kích hoạt khi có artifact thật.</DataNotice>
      <div className="dataset-cards">
        <DatasetCard title="Track A · Trusted Gold Pilot" count="275" note="Tập đáng tin cậy trong quá trình phát triển." />
        <DatasetCard title="Track B · Audited Full" count="781" note="Fine-tuning EO06: 275 Trusted Gold + 506 multi-tool SAST audited." />
        <DatasetCard title="Development Set" count="166" note="Được dùng trong đánh giá và lựa chọn mô hình." />
        <DatasetCard title="Quarantine / Review" count="137" note="Tách riêng để kiểm tra; không tự động cộng vào training." />
      </div>
      <DataNotice>Track A là một phần thuộc Track B; không cộng 275 và 781 như hai tập độc lập. Track B không được gọi toàn bộ là independently human-verified gold.</DataNotice>
      <section className="section-block">
        <SectionTitle title="Data Explorer · dữ liệu minh họa" text="Các trường bên dưới mô phỏng cấu trúc bản ghi. Không đại diện cho phân bố chính thức." />
        <Card className="table-card">
          <div className="table-toolbar"><input value={query} onChange={(event) => { setQuery(event.target.value); setPage(0); }} placeholder="Tìm sample, class, method..." /><select value={cwe} onChange={(event) => setCwe(event.target.value)}><option>Tất cả CWE</option>{['CWE-022', 'CWE-078', 'CWE-079', 'CWE-089'].map((value) => <option key={value}>{value}</option>)}</select><select value={role} onChange={(event) => setRole(event.target.value)}><option>Tất cả role</option>{roleLabels.map((value) => <option key={value}>{value}</option>)}</select></div>
          <div className="table-wrap"><table><thead><tr><th>Sample ID</th><th>CWE</th><th>Package / Class</th><th>Method</th><th>Signature</th><th>Role</th><th>Split</th></tr></thead><tbody>{rows.slice(page * 5, page * 5 + 5).map((row) => <tr key={row.id}><td className="mono">{row.id}</td><td><Badge tone="blue">{row.cwe}</Badge></td><td className="mono">{row.package}<br />{row.className}</td><td className="mono">{row.method}</td><td className="mono">{row.signature}</td><td><Badge tone="violet">{row.role}</Badge></td><td>{row.split}</td></tr>)}</tbody></table>{!rows.length && <EmptyState title="Không có bản ghi phù hợp" text="Thử điều chỉnh từ khóa hoặc bộ lọc." />}</div>
          <div className="pagination"><span>{rows.length} bản ghi minh họa</span><button disabled={page === 0} onClick={() => setPage(0)}>Trang trước</button><button disabled={rows.length <= (page + 1) * 5} onClick={() => setPage(page + 1)}>Trang sau</button></div>
        </Card>
      </section>
    </>
  );
}

function DatasetCard({ title, count, note }) {
  return <Card className="dataset-stat"><span className="dataset-count">{count}</span><h3>{title}</h3><p>{note}</p></Card>;
}

function ModelResearch({evaluation=false}) {
  const [state,setState]=useState({status:'loading',data:null,error:''});
  useEffect(()=> {
    const controller=new AbortController();
    api.model({signal:controller.signal}).then(data=>setState({status:'success',data,error:''}))
      .catch(error=>{if(!controller.signal.aborted)setState({status:'error',data:null,error:error.message});});
    return ()=>controller.abort();
  },[]);
  const model=state.data;
  const provenance=model?.eo06_training_provenance;
  const receipt=provenance?.training_execution_receipt;
  const metrics=[['Development Macro-F1',receipt?.best_dev_macro_f1],['Historical Holdout Macro-F1',receipt?.holdout_macro_f1],['Historical Holdout JSON valid rate',receipt?.holdout_json_valid_rate]];
  return <>
    <PageHeader eyebrow="NGHIÊN CỨU · DỮ LIỆU BACKEND" title={evaluation?'Đánh giá thực nghiệm':'Huấn luyện và checkpoint'} description="Provenance và receipt được tải từ /api/model; không huấn luyện lại trong phiên demo." />
    {state.status==='loading' && <DataNotice>Đang tải dữ liệu mô hình từ backend...</DataNotice>}
    {state.status==='error' && <DataNotice>Không tải được dữ liệu: {state.error}</DataNotice>}
    {model && <Card title="Checkpoint production"><p>Base model: {model.base_model_id}</p><p>Adapter: {model.adapter_arm_id}</p><p>SHA-256: <code>{model.best_adapter_sha256}</code></p><p>Thiết bị thực: {model.actual_model_device} · {model.actual_model_dtype}</p><p>Trạng thái: {model.model_load_state} · Cloud calls: {String(model.cloud_calls_enabled)}</p></Card>}
    {provenance && <Card title="Provenance huấn luyện từ backend"><p>Run: {provenance.eo06_run_id}</p><p>Dataset: {provenance.primary_training_dataset_id} · {provenance.primary_training_dataset_rows} records</p><p>Dataset SHA-256: <code>{provenance.primary_training_dataset_sha256}</code></p><p>Best epoch: {provenance.best_checkpoint_epoch}</p></Card>}
    {receipt && <Card title="Receipt lịch sử · API role classification"><div className="table-wrap"><table><thead><tr><th>Chỉ số</th><th>Giá trị từ receipt</th></tr></thead><tbody>{metrics.map(([label,value])=><tr key={label}><td>{label}</td><td>{typeof value==='number'?`${(value*100).toFixed(2)}%`:'Chưa có dữ liệu'}</td></tr>)}</tbody></table></div><p>Run {receipt.run_id} · {receipt.completed_utc}</p><details><summary>Receipt backend</summary><pre>{JSON.stringify(receipt,null,2)}</pre></details></Card>}
    <DataNotice>Receipt là kết quả lịch sử được backend cung cấp, không phải phép đo mới trong phiên này. Macro-F1 API role không phải độ chính xác phát hiện lỗ hổng end-to-end. Scan GitHub chỉ chứng minh pipeline và bằng chứng cục bộ; chưa có ground-truth audit mới để công bố TP/FP accuracy. Historical holdout không được coi là blind test mới.</DataNotice>
  </>;
}
export function Training() { return <ModelResearch />; }
export function Evaluation() { return <ModelResearch evaluation />; }
export function Scoring() { return <DataNotice>Điểm ưu tiên chính thức sử dụng MITRE CWSS Inference V2.</DataNotice>; }