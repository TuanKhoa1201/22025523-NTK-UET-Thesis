import {useEffect, useMemo, useState} from 'react';
import {Link} from 'react-router-dom';
import {Card, Badge, SectionTitle, EmptyState, Icon} from '../common/Ui';
import {scanQuery} from '../../services/liveScan';
import {IN_SCOPE_CWES} from '../../services/scanOverview';
import {IRIS_PROOF_STATES, irisProofTone} from '../../services/findingPresentation';

const PER_PAGE = 25;
const DECISIONS = ['REPORT', 'REVIEW', 'SUPPRESS'];
const SORTS = [
  ['score-desc', 'Điểm CWSS: cao đến thấp'],
  ['score-asc', 'Điểm CWSS: thấp đến cao'],
  ['cwe', 'Theo loại lỗ hổng (CWE)'],
  ['file', 'Theo tên tệp'],
  ['id', 'Theo mã cảnh báo']
];
const toneOf = (d) => (d === 'REPORT' ? 'red' : d === 'REVIEW' ? 'amber' : d === 'SUPPRESS' ? 'green' : 'neutral');
const countOf = (rows, key, value) => rows.filter((row) => row[key] === value).length;
const sortText = (a, b) => String(a || '').localeCompare(String(b || ''), 'vi', {numeric: true});

export default function FindingsExplorer({rows, scores, scanId}) {
  const [filters, setFilters] = useState({query: '', cwe: '', decision: '', proofState: '', sort: 'score-desc'});
  const [page, setPage] = useState(1);
  const set = (key) => (event) => setFilters((previous) => ({...previous, [key]: event.target.value}));
  const cweOptions = useMemo(() => [...new Set([...IN_SCOPE_CWES, ...rows.map((row) => row.cwe).filter(Boolean)])].sort(sortText), [rows]);
  const decisionOptions = useMemo(() => [...new Set([...DECISIONS, ...rows.map((row) => row.decision).filter(Boolean)])], [rows]);
  const proofOptions = useMemo(() => [...new Set([...IRIS_PROOF_STATES, ...rows.map((row) => row.irisProofState).filter(Boolean)])], [rows]);
  const filtered = useMemo(() => {
    const q = filters.query.trim().toLowerCase();
    const matched = rows.filter((row) => {
      if (q && !`${row.id} ${row.file}`.toLowerCase().includes(q)) return false;
      if (filters.cwe && row.cwe !== filters.cwe) return false;
      if (filters.decision && row.decision !== filters.decision) return false;
      if (filters.proofState && row.irisProofState !== filters.proofState) return false;
      return true;
    });
    const score = (row) => scores.get(row.id);
    const byScoreDescending = (a, b) => (score(b) ?? -1) - (score(a) ?? -1) || sortText(a.id, b.id);
    const compare = {
      'score-desc': byScoreDescending,
      'score-asc': (a, b) => (score(a) ?? Infinity) - (score(b) ?? Infinity) || sortText(a.id, b.id),
      cwe: (a, b) => sortText(a.cwe, b.cwe) || byScoreDescending(a, b),
      file: (a, b) => sortText(a.file, b.file) || sortText(a.id, b.id),
      id: (a, b) => sortText(a.id, b.id)
    }[filters.sort] ?? byScoreDescending;
    return [...matched].sort(compare);
  }, [rows, scores, filters]);
  useEffect(() => { setPage(1); }, [filters]);
  const pages = Math.max(1, Math.ceil(filtered.length / PER_PAGE));
  const visible = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE);
  const hasActiveFilters = Boolean(filters.query || filters.cwe || filters.decision || filters.proofState);
  return (
    <section className="section-block ntk-p05-findings">
      <SectionTitle title="Danh sách findings" />
      <Card className="table-card">
        <div className="rd-filters ntk-p05-findings-filters">
          <label className="ntk-p05-input-group ntk-p05-findings-search">
            <span>Tìm cảnh báo</span>
            <input aria-label="Tìm theo mã cảnh báo hoặc tệp" placeholder="Mã cảnh báo hoặc tên tệp…" value={filters.query} onChange={set('query')} />
          </label>
          <label className="ntk-p05-input-group">
            <span>Loại lỗ hổng</span>
            <select aria-label="Lọc theo CWE" value={filters.cwe} onChange={set('cwe')}>
              <option value="">Tất cả CWE</option>
              {cweOptions.map((value) => <option key={value} value={value}>{value} ({countOf(rows, 'cwe', value)})</option>)}
            </select>
          </label>
          <label className="ntk-p05-input-group">
            <span>Quyết định</span>
            <select aria-label="Lọc theo quyết định" value={filters.decision} onChange={set('decision')}>
              <option value="">Tất cả quyết định</option>
              {decisionOptions.map((value) => <option key={value} value={value}>{value} ({countOf(rows, 'decision', value)})</option>)}
            </select>
          </label>
          <label className="ntk-p05-input-group">
            <span>Bằng chứng IRIS</span>
            <select aria-label="Lọc theo trạng thái bằng chứng IRIS" value={filters.proofState} onChange={set('proofState')}>
              <option value="">Tất cả trạng thái</option>
              {proofOptions.map((value) => <option key={value} value={value}>{value} ({countOf(rows, 'irisProofState', value)})</option>)}
            </select>
          </label>
          <label className="ntk-p05-input-group ntk-p05-sort">
            <span>Sắp xếp theo</span>
            <select aria-label="Sắp xếp danh sách findings" value={filters.sort} onChange={set('sort')}>
              {SORTS.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
            </select>
          </label>
          {hasActiveFilters && <button type="button" className="button-secondary ntk-p05-clear" onClick={() => setFilters({query: '', cwe: '', decision: '', proofState: '', sort: filters.sort})}>Xóa lọc</button>}
        </div>
        <p className="muted-text rd-count">Hiển thị {filtered.length.toLocaleString()} / {rows.length.toLocaleString()} cảnh báo</p>
        {!visible.length ? <EmptyState title="Không tìm thấy cảnh báo phù hợp" text="Hãy thử bộ lọc khác. Các lựa chọn có số lượng 0 không có kết quả trong phiên quét này." /> : (
          <div className="table-wrap"><table className="rd-table"><thead><tr><th>Finding</th><th>CWE</th><th>File · line</th><th>Bằng chứng IRIS</th><th title="CWSS theo hồ sơ tham chiếu BUSINESS_CRITICAL_INTERNET_FACING; điều kiện triển khai chưa được xác minh.">CWSS</th><th>Triage</th><th></th></tr></thead><tbody>
            {visible.map((row) => {
              const score = scores.get(row.id);
              return <tr key={row.id}><td className="mono rd-id" title={row.id}>{row.id}</td><td><Badge tone="blue">{row.cwe}</Badge></td>
                <td className="mono rd-file" title={row.file}>{row.file.split('/').slice(-1)}:{row.line}</td><td><Badge tone={irisProofTone(row.irisProofState)}>{row.irisProofState}</Badge></td>
                <td className="mono">{score === undefined ? 'Chưa có' : `${score.toFixed(1)}/100`}</td>
                <td><Badge tone={toneOf(row.decision)}>{row.decision}</Badge></td>
                <td><Link className="table-link" to={`/finding/${encodeURIComponent(row.id)}${scanQuery(scanId)}`} state={{detailUrl: row.detailUrl}}>Chi tiết <Icon name="ArrowUpRight" /></Link></td></tr>;
            })}
          </tbody></table></div>
        )}
        <div className="table-toolbar ntk-p05-list-pagination">
          <button className="button-secondary" disabled={page <= 1} onClick={() => setPage((previous) => previous - 1)}>Trước</button>
          <span>Trang <strong>{page}</strong> / {pages}</span>
          <button className="button-secondary" disabled={page >= pages} onClick={() => setPage((previous) => previous + 1)}>Tiếp</button>
        </div>
      </Card>
    </section>
  );
}
