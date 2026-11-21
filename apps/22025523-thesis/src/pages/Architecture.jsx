import {useState} from 'react';
import {Card, PageHeader, SectionTitle, Icon} from '../components/common/Ui';

const runtimeSteps = [
  'GitHub / ZIP',
  'OpenGrep',
  'Evidence & SHA-256',
  'Qwen3.5-9B (Ollama)',
  'Kiểm chứng trích dẫn',
  'Human Review',
];

const components = [
  {
    name: 'Intake & Kiểm tra an toàn nguồn Java',
    icon: 'FolderGit2',
    role: 'Tiếp nhận GitHub Repository hoặc tệp ZIP',
    input: 'URL GitHub công khai (kèm commit SHA tùy chọn) hoặc tệp nén .zip.',
    output: 'Thư mục nguồn Java đã cách ly và danh sách tệp .java hợp lệ.',
    contribution: 'Ngăn chặn path traversal, symlink ngoài vùng cho phép, ZIP bomb và option injection trước khi quét.',
    limitation: 'Chỉ phân tích tệp .java nằm trong giới hạn dung lượng và số tệp cho phép của API.',
    explanation: 'Hệ thống kiểm tra an toàn đầu vào đồng bộ trước khi đưa job vào hàng đợi thực thi.',
  },
  {
    name: 'OpenGrep Static Analysis',
    icon: 'ScanSearch',
    role: 'Phát hiện ứng viên CWE-22 & CWE-89',
    input: 'Mã nguồn Java và tập luật OpenGrep YAML cục bộ.',
    output: 'opengrep.json, SARIF và scan-manifest.json ghi nhận mã băm tiền quét.',
    contribution: 'Sàng lọc nhanh các vị trí nghi ngờ Path Traversal (CWE-22) và SQL Injection (CWE-89) trên cùng một lượt quét.',
    limitation: 'Phân tích tĩnh dựa trên mẫu quy tắc có thể sinh cảnh báo giả hoặc bỏ sót luồng phức tạp ngoài tập luật.',
    explanation: 'OpenGrep chạy duy nhất một lần và bàn giao trực tiếp biên nhận sang bước thu thập bằng chứng.',
  },
  {
    name: 'Evidence Collection & Snapshot SHA-256',
    icon: 'Code2',
    role: 'Trích xuất dòng mã thật & ngữ cảnh phương thức',
    input: 'Vị trí cảnh báo OpenGrep và tệp .java thật trên đĩa.',
    output: 'Các đoạn mã nguồn có số dòng chính xác, raw_trace, java_context và snapshot SHA-256.',
    contribution: 'Bảo đảm mô hình và giao diện chỉ làm việc trên dòng Java thật đã chụp tại thời điểm quét.',
    limitation: 'Tệp vượt quá giới hạn đọc 1 MB hoặc không giải mã được UTF-8 sẽ ghi nhận lỗi bằng chứng.',
    explanation: 'Tách biệt đường dẫn máy chủ nội bộ với bằng chứng định danh theo đường dẫn tương đối và SHA-256.',
  },
  {
    name: 'Qwen3.5-9B qua Ollama cục bộ',
    icon: 'Cpu',
    role: 'Phân loại cảnh báo theo hợp đồng blind',
    input: 'Snippets, vị trí dòng, luồng dữ liệu (Source → Intermediate → Sink) và ngữ cảnh cấu trúc Java.',
    output: 'Trạng thái thô (SUPPORTED, REFUTED, UNDETERMINED), giải thích, gợi ý khắc phục và trích dẫn.',
    contribution: 'Chạy hoàn toàn cục bộ qua loopback Ollama; không gửi mã nguồn lên dịch vụ đám mây.',
    limitation: 'Khi Ollama mất kết nối hoặc hết thời gian chờ, hệ thống giữ trạng thái UNDETERMINED để người dùng kiểm tra.',
    explanation: 'Mô hình chỉ tiếp nhận đoạn mã thật đã xác minh và bắt buộc trả về trích dẫn kèm dòng và SHA-256.',
  },
  {
    name: 'Citation & Integrity Validator',
    icon: 'ShieldCheck',
    role: 'Kiểm chứng trích dẫn dòng mã thật & SHA-256',
    input: 'Phản hồi JSON từ mô hình và snapshot mã nguồn gốc.',
    output: 'validated_status, validator_downgraded, citation_check và citation_provenance.',
    contribution: 'Tự động hạ cấp kết luận về UNDETERMINED nếu mô hình thiếu trích dẫn hoặc trích dẫn sai dòng/quote/SHA-256.',
    limitation: 'Trích dẫn khớp nguồn (MATCHED) không đồng nghĩa đã chứng minh lỗ hổng cuối cùng; vẫn cần người kiểm duyệt.',
    explanation: 'Thực thi nguyên tắc fail-closed: không tin cậy kết luận thiếu bằng chứng trích dẫn từ LLM.',
  },
  {
    name: 'SQLite ReviewStore & STALE_SOURCE Guard',
    icon: 'Database',
    role: 'Hàng đợi Human Review & Kiểm tra trôi mã nguồn',
    input: 'Kết quả đã kiểm chứng và quyết định kèm lý do từ người kiểm duyệt.',
    output: 'Trạng thái OPEN / CONFIRMED_TRUE / CONFIRMED_FALSE và lịch sử sự kiện kiểm toán.',
    contribution: 'Đề xuất REFUTED của AI vẫn giữ trạng thái OPEN; xác nhận cảnh báo giả bị chặn (409 STALE_SOURCE) nếu mã nguồn đã thay đổi.',
    limitation: 'Các thư mục quét chỉ đọc không cho phép ghi quyết định mới.',
    explanation: 'Bảo đảm mọi quyết định loại cảnh báo giả đều do con người xác nhận và dựa trên mã nguồn nguyên vẹn.',
  },
];

export default function ArchitecturePage() {
  const [selected, setSelected] = useState(0);
  const item = components[selected];

  return (
    <>
      <PageHeader
        eyebrow="KIẾN TRÚC HỆ THỐNG"
        title="Kiến trúc OpenGrep + Qwen3.5-9B + Kiểm chứng bằng chứng"
        description="Quy trình 6 giai đoạn từ tiếp nhận mã nguồn Java tới hàng đợi Human Review trên SQLite."
      />
      <section className="ntk-p05-workflow ntk-p05-runtime" aria-label="Quy trình phân tích 6 giai đoạn">
        <header className="ntk-p05-workflow-header">
          <div className="ntk-p05-stage-marker">06</div>
          <div>
            <span className="ntk-p05-stage-eyebrow">LUỒNG PHÂN TÍCH CHÍNH THỨC</span>
            <h2>Từ mã nguồn Java tới bằng chứng đã kiểm chứng</h2>
            <p>Không dùng cloud LLM, không tự loại cảnh báo giả khi chưa có xác nhận của người kiểm duyệt.</p>
          </div>
          <span className="ntk-p05-stage-count">{runtimeSteps.length} bước</span>
        </header>
        <ol className="ntk-p05-workflow-steps">
          {runtimeSteps.map((step, stepIndex) => (
            <li className="ntk-p05-workflow-step" key={step}>
              <span className="ntk-p05-step-number">{String(stepIndex + 1).padStart(2, '0')}</span>
              <strong>{step}</strong>
              <span className="ntk-p05-step-arrow" aria-hidden="true">
                {stepIndex < runtimeSteps.length - 1 && <Icon name="ArrowRight" />}
              </span>
            </li>
          ))}
        </ol>
      </section>

      <section className="section-block architecture-roles">
        <SectionTitle title="Vai trò và giới hạn từng thành phần" />
        <div className="architecture-explorer">
          <nav className="architecture-selector" aria-label="Thành phần kiến trúc">
            {components.map((component, index) => (
              <button
                key={component.name}
                type="button"
                className={selected === index ? 'active' : ''}
                onClick={() => setSelected(index)}
              >
                <span className="selector-number">{String(index + 1).padStart(2, '0')}</span>
                <span className="selector-icon"><Icon name={component.icon} /></span>
                <span className="selector-label"><b>{component.name}</b><small>{component.role}</small></span>
                <Icon name="ChevronRight" />
              </button>
            ))}
          </nav>
          <Card className="architecture-explanation">
            <div className="explanation-title">
              <span><Icon name={item.icon} /></span>
              <div>
                <small>THÀNH PHẦN {String(selected + 1).padStart(2, '0')}</small>
                <h2>{item.name}</h2>
                <p>{item.role}</p>
              </div>
            </div>
            <div className="architecture-description"><h3>Vai trò trong hệ thống</h3><p>{item.explanation}</p></div>
            <div className="io-grid">
              <InfoBlock title="Đầu vào" text={item.input} icon="LogIn" />
              <InfoBlock title="Đầu ra" text={item.output} icon="LogOut" />
            </div>
            <div className="contribution-limit">
              <InfoBlock title="Đóng góp" text={item.contribution} icon="Target" />
              <InfoBlock title="Giới hạn" text={item.limitation} icon="TriangleAlert" />
            </div>
          </Card>
        </div>
      </section>
    </>
  );
}

function InfoBlock({title, text, icon}) {
  return (
    <div className="architecture-info">
      <span><Icon name={icon} /></span>
      <div><h3>{title}</h3><p>{text}</p></div>
    </div>
  );
}
