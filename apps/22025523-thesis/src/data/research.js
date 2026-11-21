export const PRIORITY_CWES = ['CWE-22', 'CWE-89'];

export const navGroups = [
  {
    title: '',
    items: [
      ['/', 'Tổng quan', 'Grid'],
      ['/scanner', 'Phân tích mã nguồn', 'Scan'],
      ['/history', 'Lịch sử phân tích', 'Clock'],
      ['/status', 'Trạng thái hệ thống', 'Activity'],
      ['/about', 'Giới thiệu đề tài', 'Info'],
    ],
  },
];

export const pipelinePhases = [
  ['INTAKE_VALIDATION', 'Tiếp nhận & kiểm tra an toàn mã nguồn Java', 'Archive'],
  ['OPENGREP_SCAN', 'Phân tích tĩnh OpenGrep & ghi biên nhận băm nguồn', 'Scan'],
  ['EVIDENCE_COLLECTION', 'Trích xuất bằng chứng & ngữ cảnh phương thức Java', 'Code'],
  ['QWEN_INFERENCE', 'Suy luận Qwen3.5-9B cục bộ qua Ollama (hợp đồng blind)', 'Cpu'],
  ['CITATION_VALIDATION', 'Kiểm chứng trích dẫn dòng mã thật & SHA-256', 'ShieldCheck'],
  ['REVIEW_STORE_COMMIT', 'Khởi tạo hàng đợi Human Review trên SQLite', 'Database'],
];
