import {Link} from 'react-router-dom';
import {Badge, Card, Icon, SectionTitle} from '../components/common/Ui';

const roles = [
  {
    num: '01',
    icon: 'ScanSearch',
    title: 'Phân tích tĩnh OpenGrep',
    text: 'Quét mã nguồn Java bằng tập luật nguồn mở, tập trung trước vào CWE-22 (Path Traversal) và CWE-89 (SQL Injection), đồng thời ghi nhận mã băm SHA-256 tệp nguồn.',
  },
  {
    num: '02',
    icon: 'Cpu',
    title: 'Suy luận Qwen3.5-9B cục bộ',
    text: 'Chạy hoàn toàn cục bộ thông qua Ollama theo hợp đồng blind chỉ dựa trên đoạn mã Java thật và luồng dữ liệu, không gửi mã nguồn lên dịch vụ đám mây.',
  },
  {
    num: '03',
    icon: 'ShieldCheck',
    title: 'Kiểm chứng bằng chứng & Người kiểm duyệt',
    text: 'Đối chiếu trích dẫn dòng mã và SHA-256; giữ lại cảnh báo chưa đủ bằng chứng (UNDETERMINED) và yêu cầu con người xác nhận trước khi loại cảnh báo giả.',
  },
];

function HybridEngineVisual() {
  return (
    <div
      className="v2-hero-visual"
      aria-label="Minh họa kết hợp phân tích tĩnh OpenGrep và mô hình ngôn ngữ lớn Qwen3.5-9B"
    >
      <div className="v2-hv-bg" aria-hidden="true">
        <svg className="v2-hv-grid-svg" viewBox="0 0 480 340" preserveAspectRatio="xMidYMid slice">
          <defs>
            <pattern id="v2HvGrid" width="28" height="28" patternUnits="userSpaceOnUse">
              <path d="M 28 0 L 0 0 0 28" fill="none" stroke="rgba(221, 224, 230, 0.085)" strokeWidth="0.75" />
            </pattern>
            <radialGradient id="v2HvFadeGrad" cx="50%" cy="50%" r="58%">
              <stop offset="0%" stopColor="white" stopOpacity="1" />
              <stop offset="70%" stopColor="white" stopOpacity="0.35" />
              <stop offset="100%" stopColor="white" stopOpacity="0" />
            </radialGradient>
            <mask id="v2HvGridMask">
              <rect width="480" height="340" fill="url(#v2HvFadeGrad)" />
            </mask>
          </defs>
          <rect width="480" height="340" fill="url(#v2HvGrid)" mask="url(#v2HvGridMask)" />
          <path
            d="M -20 278 C 115 240, 225 118, 500 50"
            fill="none"
            stroke="rgba(221, 224, 230, 0.1)"
            strokeWidth="1"
          />
          <path
            d="M -20 302 C 138 266, 255 150, 500 90"
            fill="none"
            stroke="rgba(186, 200, 224, 0.07)"
            strokeWidth="0.85"
          />
        </svg>
        <span className="v2-hv-glow v2-hv-glow--left" />
        <span className="v2-hv-glow v2-hv-glow--right" />
      </div>

      <div className="v2-hv-header">
        <span className="v2-hv-tag">
          <span className="v2-hv-tag-dot" aria-hidden="true" />
          STATIC ANALYSIS + LOCAL LLM
        </span>
        <span className="v2-hv-index" aria-hidden="true">01 → 02</span>
      </div>

      <div className="v2-hv-stage">
        <div className="v2-hv-node v2-hv-node--opengrep">
          <div className="v2-hv-node-top">
            <span className="v2-hv-icon-wrap" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="7 8 3 12 7 16" />
                <polyline points="17 8 21 12 17 16" />
                <line x1="13.5" y1="6.5" x2="10.5" y2="17.5" />
                <circle cx="12" cy="12" r="9.5" strokeOpacity="0.22" strokeDasharray="3 3" />
              </svg>
            </span>
            <span className="v2-hv-step">01</span>
          </div>

          <div className="v2-hv-node-body">
            <strong className="v2-hv-title">OpenGrep</strong>
            <span className="v2-hv-role">Phân tích tĩnh</span>
          </div>

          <div className="v2-hv-motif" aria-hidden="true">
            <svg viewBox="0 0 132 38" fill="none">
              <rect x="0" y="3" width="64" height="3.5" rx="1.75" fill="rgba(221, 224, 230, 0.22)" />
              <rect x="0" y="11" width="96" height="3.5" rx="1.75" fill="rgba(221, 224, 230, 0.16)" />
              <rect
                x="0"
                y="18.5"
                width="112"
                height="5"
                rx="2.5"
                fill="rgba(206, 218, 238, 0.22)"
                stroke="rgba(228, 234, 246, 0.45)"
                strokeWidth="0.7"
              />
              <circle cx="123" cy="21" r="2.6" fill="#E8EEF8" />
              <rect x="0" y="28.5" width="76" height="3.5" rx="1.75" fill="rgba(221, 224, 230, 0.14)" />
            </svg>
          </div>

          <span className="v2-hv-port v2-hv-port--out" aria-hidden="true" />
        </div>

        <div className="v2-hv-bridge" aria-hidden="true">
          <svg className="v2-hv-conduit v2-hv-conduit--h" viewBox="0 0 88 108" fill="none" preserveAspectRatio="none">
            <defs>
              <linearGradient id="v2HvRailH" x1="0" y1="54" x2="88" y2="54" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#9EA7B8" stopOpacity="0.32" />
                <stop offset="50%" stopColor="#FFFFFF" stopOpacity="0.86" />
                <stop offset="100%" stopColor="#C8D5EA" stopOpacity="0.48" />
              </linearGradient>
              <linearGradient id="v2HvPulseH" x1="0" y1="54" x2="88" y2="54" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.15" />
                <stop offset="50%" stopColor="#FFFFFF" stopOpacity="0.98" />
                <stop offset="100%" stopColor="#DCE6F7" stopOpacity="0.2" />
              </linearGradient>
            </defs>
            <path d="M 0 30 C 24 30, 28 50, 44 50 C 60 50, 64 30, 88 30" stroke="rgba(221, 224, 230, 0.26)" strokeWidth="1" />
            <path d="M 0 78 C 24 78, 28 58, 44 58 C 60 58, 64 78, 88 78" stroke="rgba(221, 224, 230, 0.26)" strokeWidth="1" />
            <line x1="0" y1="54" x2="88" y2="54" stroke="url(#v2HvRailH)" strokeWidth="1.6" />
            <line
              className="v2-hv-signal-pulse"
              x1="0"
              y1="54"
              x2="88"
              y2="54"
              stroke="url(#v2HvPulseH)"
              strokeWidth="2.4"
              strokeLinecap="round"
            />
          </svg>

          <svg className="v2-hv-conduit v2-hv-conduit--v" viewBox="0 0 108 56" fill="none" preserveAspectRatio="none">
            <defs>
              <linearGradient id="v2HvRailV" x1="54" y1="0" x2="54" y2="56" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#9EA7B8" stopOpacity="0.32" />
                <stop offset="50%" stopColor="#FFFFFF" stopOpacity="0.86" />
                <stop offset="100%" stopColor="#C8D5EA" stopOpacity="0.48" />
              </linearGradient>
            </defs>
            <path d="M 30 0 C 30 18, 50 20, 50 28 C 50 36, 30 38, 30 56" stroke="rgba(221, 224, 230, 0.26)" strokeWidth="1" />
            <path d="M 78 0 C 78 18, 58 20, 58 28 C 58 36, 78 38, 78 56" stroke="rgba(221, 224, 230, 0.26)" strokeWidth="1" />
            <line x1="54" y1="0" x2="54" y2="56" stroke="url(#v2HvRailV)" strokeWidth="1.6" />
          </svg>

          <span className="v2-hv-relay">
            <svg className="v2-hv-relay-arrow" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <line x1="3" y1="8" x2="12.5" y2="8" />
              <polyline points="8.5 4 12.5 8 8.5 12" />
            </svg>
          </span>
        </div>

        <div className="v2-hv-node v2-hv-node--qwen">
          <span className="v2-hv-port v2-hv-port--in" aria-hidden="true" />

          <div className="v2-hv-node-top">
            <span className="v2-hv-icon-wrap v2-hv-icon-wrap--llm" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <rect x="6.5" y="6.5" width="11" height="11" rx="2.5" />
                <circle cx="12" cy="12" r="2.2" fill="currentColor" fillOpacity="0.24" />
                <line x1="9.5" y1="3" x2="9.5" y2="6.5" />
                <line x1="14.5" y1="3" x2="14.5" y2="6.5" />
                <line x1="9.5" y1="17.5" x2="9.5" y2="21" />
                <line x1="14.5" y1="17.5" x2="14.5" y2="21" />
                <line x1="3" y1="9.5" x2="6.5" y2="9.5" />
                <line x1="3" y1="14.5" x2="6.5" y2="14.5" />
                <line x1="17.5" y1="9.5" x2="21" y2="9.5" />
                <line x1="17.5" y1="14.5" x2="21" y2="14.5" />
              </svg>
            </span>
            <span className="v2-hv-step">02</span>
          </div>

          <div className="v2-hv-node-body">
            <strong className="v2-hv-title">Qwen3.5-9B</strong>
            <span className="v2-hv-role">Suy luận ngữ cảnh</span>
          </div>

          <div className="v2-hv-motif" aria-hidden="true">
            <svg viewBox="0 0 132 38" fill="none">
              <path d="M 10 10 L 42 19 L 10 28" stroke="rgba(200, 214, 236, 0.36)" strokeWidth="1.15" />
              <path d="M 42 19 L 76 11 M 42 19 L 76 27" stroke="rgba(221, 224, 230, 0.34)" strokeWidth="1.15" />
              <line x1="76" y1="11" x2="122" y2="11" stroke="rgba(221, 224, 230, 0.3)" strokeWidth="3" strokeLinecap="round" />
              <line x1="76" y1="19" x2="110" y2="19" stroke="rgba(212, 224, 244, 0.5)" strokeWidth="3" strokeLinecap="round" />
              <line x1="76" y1="27" x2="118" y2="27" stroke="rgba(221, 224, 230, 0.2)" strokeWidth="3" strokeLinecap="round" />
              <circle cx="10" cy="10" r="2.4" fill="rgba(221, 224, 230, 0.62)" />
              <circle cx="10" cy="28" r="2.4" fill="rgba(221, 224, 230, 0.62)" />
              <circle cx="42" cy="19" r="3.4" fill="#FFFFFF" fillOpacity="0.92" />
              <circle cx="76" cy="11" r="2.3" fill="rgba(212, 224, 244, 0.88)" />
              <circle cx="76" cy="27" r="2.3" fill="rgba(212, 224, 244, 0.65)" />
            </svg>
          </div>
        </div>
      </div>

      <div className="v2-hv-footer" aria-hidden="true">
        <span>Phát hiện cảnh báo</span>
        <span className="v2-hv-footer-line" />
        <span>Phân tích &amp; giải thích</span>
      </div>
    </div>
  );
}

export default function Overview() {
  return (
    <>
      <section className="v2-overview-hero">
        <div className="v2-hero-copy">
          <div className="eyebrow v2-hero-eyebrow">
            <span className="eyebrow-dot" aria-hidden="true" />
            <span className="v2-hero-eyebrow-text">
              22025523 · ĐỒ ÁN TỐT NGHIỆP NGÀNH MẠNG MÁY TÍNH VÀ TRUYỀN THÔNG DỮ LIỆU
            </span>
          </div>
          <h1 className="v2-hero-title">
            Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn.
          </h1>
          <div className="v2-hero-actions">
            <Link to="/scanner" className="button-primary">
              <Icon name="ScanSearch" />Bắt đầu phân tích<Icon name="ArrowRight" />
            </Link>
          </div>
          <div className="v2-hero-scope" aria-label="Phạm vi trọng tâm">
            <Badge tone="blue">Java · CWE-22 Path Traversal</Badge>
            <Badge tone="blue">Java · CWE-89 SQL Injection</Badge>
          </div>
        </div>

        <HybridEngineVisual />
      </section>

      <section className="section-block">
        <SectionTitle title="Ba vai trò trong quy trình kiểm chứng" />
        <div className="v2-pillar-grid">
          {roles.map((role) => (
            <article key={role.num} className="v2-pillar-card">
              <div className="v2-pillar-top">
                <span className="v2-pillar-icon"><Icon name={role.icon} /></span>
                <span className="v2-pillar-num">{role.num}</span>
              </div>
              <h3>{role.title}</h3>
              <p>{role.text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="section-block">
        <Card className="v2-thesis-footer-card">
          <div>
            <Badge tone="blue">ĐỒ ÁN TỐT NGHIỆP · VNU-UET</Badge>
            <h2>Trường Đại học Công nghệ — Đại học Quốc gia Hà Nội</h2>
            <p>Sinh viên: Nguyễn Tuấn Khoa (22025523) · Giảng viên hướng dẫn: TS. Nguyễn Đại Thọ</p>
          </div>
          <Link to="/about" className="button-secondary">
            Thông tin đề tài <Icon name="ArrowRight" />
          </Link>
        </Card>
      </section>
    </>
  );
}
