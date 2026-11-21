import {Card, PageHeader, Badge, DataNotice} from '../components/common/Ui';
import UETLogo from '../components/common/UETLogo';

export function About() {
  return (
    <>
      <PageHeader
        eyebrow="THÔNG TIN HỌC THUẬT"
        title="Giới thiệu đề tài"
        description="Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn."
      />
      <div className="university-card">
        <UETLogo variant="about" />
        <div className="university-details">
          <Badge tone="blue">ĐỒ ÁN TỐT NGHIỆP</Badge>
          <h2>Trường Đại học Công nghệ<br />Đại học Quốc gia Hà Nội</h2>
          <p>VNU University of Engineering and Technology (VNU-UET)</p>
        </div>
      </div>
      <Card className="thesis-card" title="Thông tin đề tài" style={{marginTop: '18px'}}>
        <div className="thesis-grid v2-thesis-grid">
          <div className="v2-thesis-item">
            <span>TÊN ĐỀ TÀI</span>
            <strong>Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn</strong>
          </div>
          <div className="v2-thesis-item">
            <span>GIẢNG VIÊN HƯỚNG DẪN</span>
            <strong>TS. Nguyễn Đại Thọ</strong>
          </div>
          <div className="v2-thesis-item">
            <span>SINH VIÊN THỰC HIỆN</span>
            <strong>Nguyễn Tuấn Khoa</strong>
          </div>
          <div className="v2-thesis-item">
            <span>MÃ SINH VIÊN</span>
            <strong className="mono">22025523</strong>
          </div>
          <div className="v2-thesis-item">
            <span>NGÀNH HỌC</span>
            <strong>Mạng máy tính và truyền thông dữ liệu</strong>
          </div>
          <div className="v2-thesis-item">
            <span>LỚP</span>
            <strong>K67-I-CN</strong>
          </div>
          <div className="v2-thesis-item">
            <span>TRƯỜNG</span>
            <strong>Trường Đại học Công nghệ — Đại học Quốc gia Hà Nội</strong>
          </div>
          <div className="v2-thesis-item">
            <span>PHẠM VI ƯU TIÊN</span>
            <strong>Java · CWE-22 (Path Traversal) &amp; CWE-89 (SQL Injection)</strong>
          </div>
        </div>
      </Card>
      <div style={{marginTop: '18px'}}>
        <DataNotice>
          Giới hạn phạm vi: kết quả phụ thuộc vào tập luật OpenGrep và mã nguồn Java được cung cấp;
          không phát hiện cảnh báo (NO_FINDINGS) không đồng nghĩa mã nguồn hoàn toàn an toàn.
        </DataNotice>
      </div>
    </>
  );
}
