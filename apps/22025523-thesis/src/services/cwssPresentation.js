// Vietnamese explanations of MITRE CWSS 1.0.1 factor codes.
// We display weights returned by the Python backend; never recalculate CWSS here.
const META = Object.freeze({
  TI: ['Mức ảnh hưởng kỹ thuật', 'Mức tác hại có thể xảy ra nếu điểm yếu bị khai thác'],
  AP: ['Quyền có thể đạt được', 'Quyền mà người tấn công có thể đạt được sau khi khai thác'],
  AL: ['Phạm vi quyền đạt được', 'Phần của hệ thống mà quyền đó có thể ảnh hưởng'],
  IC: ['Biện pháp bảo vệ trong ứng dụng', 'Mức độ bảo vệ của các kiểm soát nằm trong chương trình'],
  FC: ['Độ tin cậy của cảnh báo', 'Mức chắc chắn của bằng chứng phát hiện, không phải tỷ lệ đúng/sai'],
  RP: ['Quyền cần có trước tấn công', 'Quyền tối thiểu cần có để tiếp cận chức năng liên quan'],
  RL: ['Phạm vi quyền cần có', 'Phần của hệ thống cần quyền truy cập trước khi tấn công'],
  AV: ['Cách tiếp cận điểm yếu', 'Con đường được dùng để tiếp cận vị trí có vấn đề'],
  AS: ['Yêu cầu xác thực', 'Mức bảo vệ của bước đăng nhập hoặc xác thực'],
  IN: ['Mức tương tác cần thiết', 'Mức độ thao tác của người dùng cần có để tấn công xảy ra'],
  SC: ['Phạm vi triển khai bị ảnh hưởng', 'Các cấu hình hay bản triển khai có thể gặp điểm yếu'],
  BI: ['Tác động đến hoạt động', 'Ảnh hưởng có thể có đối với hoạt động của tổ chức'],
  DI: ['Khả năng bị phát hiện', 'Mức dễ hay khó để kẻ tấn công tìm ra điểm yếu'],
  EX: ['Khả năng bị khai thác', 'Mức dễ hay khó để khai thác sau khi đã phát hiện'],
  EC: ['Biện pháp bảo vệ bên ngoài', 'Mức bảo vệ từ hệ thống hoặc môi trường bên ngoài ứng dụng'],
  P: ['Mức phổ biến của điểm yếu', 'Tần suất kiểu điểm yếu này xuất hiện trong phần mềm']
});

const LEVELS = Object.freeze({
  TI: {C:'cực kỳ nghiêm trọng', H:'cao', M:'trung bình', L:'thấp', N:'không có tác động'},
  AP: {A:'quyền quản trị', P:'quyền đặc biệt một phần', RU:'quyền người dùng thường', L:'quyền hạn chế', N:'không tăng quyền'},
  AL: {A:'trong ứng dụng', S:'trên hệ điều hành', N:'trên mạng', E:'trên hạ tầng tổ chức'},
  IC: {N:'chưa có biện pháp bảo vệ', L:'bảo vệ còn hạn chế', M:'bảo vệ trung bình', I:'bảo vệ gián tiếp', B:'bảo vệ tương đối mạnh', C:'bảo vệ đầy đủ'},
  FC: {T:'có bằng chứng có thể tiếp cận', LT:'đã thấy điểm yếu tại đoạn mã, chưa rõ khả năng tiếp cận', F:'cảnh báo không chính xác theo đánh giá', D:'mức mặc định'},
  RP: {N:'không cần quyền', L:'quyền khách', RU:'quyền người dùng thường', P:'một số quyền đặc biệt', A:'quyền quản trị'},
  RL: {A:'trong ứng dụng', S:'trên hệ điều hành', N:'trên mạng', E:'trên hạ tầng tổ chức'},
  AV: {I:'qua Internet', R:'qua mạng nội bộ', V:'qua mạng riêng', A:'qua mạng lân cận', L:'từ máy cục bộ', P:'tiếp cận trực tiếp thiết bị'},
  AS: {S:'xác thực mạnh', M:'xác thực trung bình', W:'xác thực yếu', N:'không cần xác thực'},
  IN: {A:'tự động, không cần người dùng thao tác', T:'cần thao tác thông thường', M:'cần thao tác ít phổ biến', O:'phụ thuộc cơ hội', H:'cần nhiều thao tác khó', NI:'không có tương tác phù hợp'},
  SC: {A:'nhiều hoặc tất cả cấu hình', M:'cấu hình thường gặp', R:'cấu hình hiếm gặp', P:'có thể tiếp cận nhưng bị giới hạn'},
  BI: {C:'đặc biệt nghiêm trọng', H:'cao', M:'trung bình', L:'thấp', N:'không đáng kể'},
  DI: {H:'dễ phát hiện', M:'cần thêm công sức để phát hiện', L:'khó phát hiện'},
  EX: {H:'dễ khai thác trong điều kiện đánh giá', M:'có thể khai thác nhưng không chắc chắn', L:'khó khai thác', N:'không có khả năng khai thác'},
  EC: {N:'chưa có biện pháp bảo vệ', L:'bảo vệ còn hạn chế', M:'bảo vệ trung bình', I:'bảo vệ gián tiếp', B:'bảo vệ tương đối mạnh', C:'bảo vệ đầy đủ'},
  P: {W:'rất phổ biến', H:'phổ biến', C:'xuất hiện định kỳ', L:'hiếm gặp'}
});

const COMMON = Object.freeze({
  D: 'mức mặc định của phương pháp',
  UK: 'chưa đủ thông tin',
  U: 'chưa đủ thông tin',
  NA: 'không áp dụng cho phép đánh giá này',
  Q: 'giá trị được định lượng riêng'
});

const SOURCES = Object.freeze({
  VERIFIED: 'Có căn cứ từ phân tích mã',
  EVIDENCE_BASED: 'Dựa trên bằng chứng phân tích',
  ESTIMATED: 'Backend ước lượng',
  REFERENCE_ASSUMPTION: 'Điều kiện tham chiếu',
  MITRE_DEFAULT: 'Mặc định của MITRE',
  NOT_APPLICABLE: 'Không áp dụng',
  UNKNOWN: 'Chưa xác định'
});

export function metricTitle(metric) {
  return META[metric]?.[0] || 'Chỉ số CWSS';
}

export function metricLevel(metric, assessment) {
  const code = typeof assessment?.code === 'string' ? assessment.code.trim().toUpperCase() : '';
  return LEVELS[metric]?.[code] || COMMON[code] || (code ? `mức ${code}` : 'chưa có giá trị');
}

export function metricExplanation(metric, assessment) {
  const description = META[metric]?.[1] || 'Yếu tố góp phần vào việc chấm điểm';
  const level = metricLevel(metric, assessment);
  const reason = typeof assessment?.reason === 'string' ? assessment.reason : '';
  const classification = typeof assessment?.classification === 'string' ? assessment.classification.toUpperCase() : '';
  let basis = '';

  // Translate only reasons whose meaning is known. The unmodified reason stays in raw JSON.
  if (/explicit shell command capability/i.test(reason)) {
    basis = 'Đoạn mã có khả năng gọi lệnh của hệ điều hành.';
  } else if (/conditional compromise layer from sink semantics/i.test(reason)) {
    basis = 'Phạm vi ảnh hưởng được suy ra từ cách sử dụng API, chưa xác nhận quyền thực tế.';
  } else if (/official default is not proof/i.test(reason)) {
    basis = 'Sử dụng giá trị mặc định; bản thân giá trị này không xác nhận cảnh báo là đúng.';
  } else if (/prevalence excluded for targeted individual finding/i.test(reason)) {
    basis = 'Không xét độ phổ biến khi đang đánh giá một cảnh báo cụ thể.';
  } else if (/synthetic scenario-conditional|critical online transaction service/i.test(reason)) {
    basis = 'Theo bối cảnh tham chiếu về dịch vụ trực tuyến quan trọng; chưa kiểm chứng tại nơi triển khai.';
  } else if (classification === 'REFERENCE_ASSUMPTION') {
    basis = 'Giá trị từ điều kiện tham chiếu, chưa được xác minh thực tế.';
  } else if (classification === 'MITRE_DEFAULT') {
    basis = 'Giá trị mặc định theo phương pháp MITRE, không phải bằng chứng thực nghiệm.';
  } else if (classification === 'ESTIMATED') {
    basis = 'Backend ước lượng dựa trên dữ liệu phân tích hiện có.';
  }
  return `${description}: ${level}.${basis ? ` ${basis}` : ''}`;
}

export function metricSource(assessment) {
  const classification = typeof assessment?.classification === 'string' ? assessment.classification.trim().toUpperCase() : '';
  return SOURCES[classification] || 'Nguồn chưa được phân loại';
}

// Numerical weights in the CWSS formula are generally in [0, 1], not 0-100 points.
// This is presentation of the backend value, NOT a client-side scoring model.
export function metricWeight(assessment) {
  const value = assessment?.weight;
  const normalized = typeof value === 'number' ? value :
    typeof value === 'string' && /^(?:0(?:\.\d+)?|1(?:\.0+)?)$/.test(value.trim()) ? Number(value) : null;
  return normalized !== null && Number.isFinite(normalized) && normalized >= 0 && normalized <= 1
    ? normalized.toLocaleString('vi-VN', {minimumFractionDigits:2, maximumFractionDigits:4})
    : '-';
}
