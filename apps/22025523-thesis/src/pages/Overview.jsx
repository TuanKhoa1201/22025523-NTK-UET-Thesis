import {Link} from 'react-router-dom';
import {motion} from 'framer-motion';
import {Icon,Card,SectionTitle,Badge} from '../components/common/Ui';
import {pipelinePhases} from '../data/research';

const pillars=[
  ['ScanSearch','OpenGrep','Phát hiện các mẫu mã nguồn có dấu hiệu rủi ro dựa trên quy tắc phân tích tĩnh.'],
  ['GitBranch','IRIS','Phân tích cấu trúc Java, ngữ cảnh và luồng dữ liệu trong phạm vi được hỗ trợ.'],
  ['Cpu','Mô hình ngôn ngữ','Phân loại vai trò API và bổ sung tín hiệu ngữ nghĩa cho quá trình đánh giá.']
];

export default function Overview() {
  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-dot" /> 22025523 · NỀN TẢNG NGHIÊN CỨU BẢO MẬT MÃ NGUỒN</div>
          <h1>Phân tích mã nguồn.<br /><em>Kết nối bằng chứng.</em></h1>
          <p>Nền tảng nghiên cứu kết hợp phân tích tĩnh, ngữ cảnh chương trình và mô hình ngôn ngữ để hỗ trợ nhận diện rủi ro trong mã nguồn Java.</p>
          <div className="hero-actions">
            <Link to="/scanner" className="button-primary"><Icon name="ScanSearch" />Bắt đầu phân tích<Icon name="ArrowRight" /></Link>
            <Link to="/architecture" className="button-secondary">Khám phá kiến trúc</Link>
          </div>
        </div>
        <motion.div className="hero-visual" initial={{opacity:0,scale:.96}} animate={{opacity:1,scale:1}} transition={{duration:.6}}>
          <div className="visual-orbit orbit-one" /><div className="visual-orbit orbit-two" />
          <div className="visual-core"><Icon name="ScanSearch" /><span>22025523</span></div>
          <div className="visual-node node-open"><Icon name="ScanSearch" /><span>OpenGrep</span></div>
          <div className="visual-node node-iris"><Icon name="GitBranch" /><span>IRIS</span></div>
          <div className="visual-node node-llm"><Icon name="Cpu" /><span>Qwen + LoRA</span></div>
          <div className="visual-link link-a" /><div className="visual-link link-b" /><div className="visual-link link-c" />
          <div className="visual-caption">EVIDENCE FUSION <span>→</span> FINDINGS</div>
        </motion.div>
      </section>
      <section className="section-block">
        <SectionTitle title="Công nghệ phân tích" />
        <div className="pillar-grid">{pillars.map(([icon,title,text],index)=> <motion.div key={title} className="pillar-card" whileHover={{y:-4}} transition={{duration:.2}}><div className={`pillar-icon pillar-${index}`}><Icon name={icon} /></div><h3>{title}</h3><p>{text}</p><span className="pillar-index">0{index+1}</span></motion.div>)}</div>
      </section>
      <section className="section-block">
        <SectionTitle title="Nghiên cứu và vận hành" />
        <div className="journey-grid">
          <Card className="journey-card" title="01 / Xây dựng mô hình">
            <div className="journey-flow">{['Dataset','Quality gates','LoRA','Đánh giá','Model release'].map((item,index)=> <span key={item}>{item}{index<4 && <Icon name="ChevronRight" />}</span>)}</div>
            <p>Chuẩn hóa dữ liệu API role, kiểm soát chất lượng nhãn, fine-tuning và lựa chọn checkpoint.</p>
            <Link to="/dataset">Khám phá dữ liệu nghiên cứu <Icon name="ArrowRight" /></Link>
          </Card>
          <Card className="journey-card" title="02 / Phân tích mã nguồn">
            <div className="journey-flow">{pipelinePhases.slice(1,6).map(([name],index)=> <span key={name}>{['Java','OpenGrep','IRIS','Qwen','Fusion'][index]}{index<4 && <Icon name="ChevronRight" />}</span>)}</div>
            <p>Từ source Java đến candidate, bằng chứng, scoring và triage cảnh báo.</p>
            <Link to="/architecture">Khám phá kiến trúc <Icon name="ArrowRight" /></Link>
          </Card>
        </div>
      </section>
      <section className="research-banner">
        <div><Badge tone="blue">ĐỒ ÁN TỐT NGHIỆP</Badge><h2>Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn</h2><p>Trường Đại học Công nghệ - Đại học Quốc gia Hà Nội</p></div>
        <Link to="/about" className="button-secondary">Thông tin đề tài <Icon name="ArrowRight" /></Link>
      </section>
    </>
  );
}