import {Card, PageHeader, SectionTitle} from '../components/common/Ui';

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
      <section className="section-block">
        <SectionTitle title="Công thức và nguồn gốc" />
        <Card title="MITRE CWSS 1.0.1">
          <p><strong>CWSS = Base Finding × Attack Surface × Environmental</strong></p>
          <p>Base Finding được chuẩn hóa trong [0,100]; Attack Surface và Environmental trong [0,1].
            Trọng số của 16 metric được lấy từ đặc tả CWSS, không học từ các nhãn TP/FP.</p>
          <p>Tham khảo chính thức: <a href="https://cwe.mitre.org/cwss/cwss_v1.0.1.html"
            target="_blank" rel="noopener noreferrer">MITRE - Common Weakness Scoring System 1.0.1</a>.</p>
        </Card>
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
    </>
  );
}