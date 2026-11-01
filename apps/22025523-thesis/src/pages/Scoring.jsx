import {Card, DataNotice, PageHeader, SectionTitle, Badge} from '../components/common/Ui';

const groups = [
  {title: 'Base Finding', metrics: [
    ['TI','Technical Impact','Bằng chứng sink/IRIS; nếu chưa đủ dùng MITRE Default.'],
    ['AP','Acquired Privilege','Giả định quyền dịch vụ phải khai báo, không suy ra từ CWE.'],
    ['AL','Acquired Privilege Layer','Ước lượng có điều kiện từ ngữ nghĩa sink, không khẳng định chiếm quyền.'],
    ['IC','Internal Control Effectiveness','Chỉ gọi là VERIFIED nếu có bằng chứng kiểm soát cụ thể.'],
    ['FC','Finding Confidence','Không tự nâng lên Proven True bằng dự đoán LLM hoặc REPORT.']
  ]},
  {title: 'Attack Surface', metrics: [
    ['RP','Required Privilege','Quyền cần có để tiếp cận chức năng theo giả định xác thực.'],
    ['RL','Required Privilege Layer','Lớp đặc quyền cần có, nếu chưa biết phải ghi nguồn.'],
    ['AV','Access Vector','Internet/Intranet/Local tùy kịch bản khai báo.'],
    ['AS','Authentication Strength','Không khẳng định hệ thống không xác thực chỉ vì là servlet.'],
    ['IN','Level of Interaction','Dựa trên bằng chứng HTTP/IRIS hoặc ước lượng có điều kiện.'],
    ['SC','Deployment Scope','Phạm vi triển khai là giả định, không phải thông tin từ scanner.']
  ]},
  {title: 'Environmental', metrics: [
    ['BI','Business Impact','Mức quan trọng tài sản do kịch bản tham chiếu khai báo.'],
    ['DI','Likelihood of Discovery','Giả định khả năng phát hiện, không phải tỷ lệ được đo thực nghiệm.'],
    ['EX','Likelihood of Exploit','Giả định độ thuận lợi khai thác, không phải PoC đã chạy.'],
    ['EC','External Control Effectiveness','WAF/ACL/vận hành không tự suy ra từ mã nguồn.'],
    ['P','Prevalence','Không áp dụng (NA) trong chính sách targeted individual finding.']
  ]}
];

export default function ScoringPage() {
  return (
    <>
      <PageHeader eyebrow="PHƯƠNG PHÁP" title="Chấm điểm SAST theo MITRE CWSS 1.0.1"
        description="Đánh giá mức ưu tiên điểm yếu từ 16 metric có nguồn gốc; tách biệt với việc xác minh cảnh báo." />
      <DataNotice>
        Hệ thống sử dụng CWSS Inference V2. Điểm có điều kiện theo bối cảnh, không phải xác suất
        True Positive, không phải CVSS và không xác nhận một lỗ hổng đang khai thác được.
        Các giả định chưa kiểm chứng phải ghi rõ trạng thái REFERENCE_ASSUMPTION.
      </DataNotice>
      <section className="section-block">
        <SectionTitle title="Công thức và nguồn gốc" text="Không tự tạo hệ số trọng số chấm điểm." />
        <Card title="MITRE CWSS 1.0.1">
          <p><strong>CWSS = Base Finding × Attack Surface × Environmental</strong></p>
          <p>Base Finding được chuẩn hóa trong [0,100]; Attack Surface và Environmental trong [0,1].
            Trọng số của 16 metric được lấy từ đặc tả CWSS, không học từ các nhãn TP/FP.</p>
          <p>Tham khảo chính thức: <a href="https://cwe.mitre.org/cwss/cwss_v1.0.1.html"
            target="_blank" rel="noopener noreferrer">MITRE — Common Weakness Scoring System 1.0.1</a>.</p>
        </Card>
      </section>
      <section className="section-block">
        <SectionTitle title="Hai chế độ giải thích kết quả" text="Kịch bản tham chiếu không được ngụy trang thành sự thật môi trường." />
        <div className="two-column">
          <Card title="GENERAL_JAVA — mặc định">
            <Badge tone="blue">MITRE_DEFAULT</Badge>
            <p>Chưa khẳng định đặc tính triển khai; metric thiếu bằng chứng giữ giá trị mặc định
              MITRE. Điểm có thể thấp và không kết luận ứng dụng an toàn.</p>
          </Card>
          <Card title="BUSINESS_CRITICAL_INTERNET_FACING — giả định">
            <Badge tone="amber">SCENARIO-CONDITIONAL</Badge>
            <p>Giả định một dịch vụ nghiệp vụ quan trọng, kết nối Internet, không cần xác thực
              và không có biện pháp giảm thiểu trong kịch bản. Nguồn là fixture tham chiếu
              synthetic-domain-v1 có khai báo rationale, không phải bằng chứng triển khai.
              Bộ máy áp dụng các mã trọng số MITRE mà không nâng Finding Confidence thành Proven True.</p>
          </Card>
        </div>
      </section>
      <section className="section-block">
        <SectionTitle title="16 metric và nguyên tắc gán nguồn" text="Mỗi metric có code, weight, classification, rule_id và evidence trong chi tiết finding LIVE." />
        {groups.map((group) => (
          <Card key={group.title} title={group.title}>
            <div className="table-wrap"><table>
              <thead><tr><th>Metric</th><th>Tên MITRE</th><th>Quy tắc diễn giải</th></tr></thead>
              <tbody>{group.metrics.map(([code,name,meaning]) => (
                <tr key={code}><td className="mono">{code}</td><td>{name}</td><td>{meaning}</td></tr>
              ))}</tbody>
            </table></div>
          </Card>
        ))}
      </section>
      <section className="section-block">
        <Card title="Ranh giới giữa chấm điểm và phân loại cảnh báo">
          <p><strong>OpenGrep</strong> phát hiện ứng viên; <strong>IRIS</strong> cung cấp
            AST/dataflow trong phạm vi hỗ trợ; <strong>Qwen LoRA</strong> phân loại vai trò API.
            Bộ phận triage quyết định REPORT, REVIEW hoặc SUPPRESS theo các bằng chứng và policy.</p>
          <p>CWSS là lớp ưu tiên điểm yếu độc lập, không được tự thay đổi triage.
            Một cảnh báo REPORT không đồng nghĩa Finding Confidence được xác minh độc lập.</p>
        </Card>
      </section>
    </>
  );
}
