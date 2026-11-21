import {useEffect, useMemo, useState} from 'react';
import {Link} from 'react-router-dom';
import {Card, Badge, SectionTitle, EmptyState, Icon} from '../common/Ui';
import {scanQuery} from '../../services/liveScan';
import {
  PRIORITY_CWES,
  VALIDATED_STATUSES,
  HUMAN_REVIEW_STATES,
  fileName,
  validatedStatusMeta,
  humanReviewMeta,
  citationCheckTone,
} from '../../services/findingPresentation';

const PER_PAGE = 25;
const SORTS = [
  ['default', 'Mặc định theo vị trí quét'],
  ['cwe', 'Theo mã CWE'],
  ['validated', 'Theo nhận định Qwen'],
  ['human', 'Theo trạng thái kiểm duyệt'],
  ['file', 'Theo tên tệp Java'],
  ['id', 'Theo mã cảnh báo'],
];

const countOf = (rows, key, value) => rows.filter((row) => row[key] === value).length;
const sortText = (a, b) => String(a || '').localeCompare(String(b || ''), 'vi', {numeric: true});

export default function FindingsExplorer({rows, scanId}) {
  const [filters, setFilters] = useState({
    query: '',
    cwe: '',
    validatedStatus: '',
    humanReviewState: '',
    sort: 'default',
  });
  const [page, setPage] = useState(1);

  const setField = (key) => (event) => setFilters((previous) => ({...previous, [key]: event.target.value}));

  const cweOptions = useMemo(
    () => [...new Set([...PRIORITY_CWES, ...rows.map((row) => row.cwe).filter(Boolean)])].sort(sortText),
    [rows],
  );
  const validatedOptions = useMemo(
    () => [...new Set([...VALIDATED_STATUSES, ...rows.map((row) => row.validatedStatus).filter(Boolean)])],
    [rows],
  );
  const humanOptions = useMemo(
    () => [...new Set([...HUMAN_REVIEW_STATES, ...rows.map((row) => row.humanReviewState).filter(Boolean)])],
    [rows],
  );

  const filtered = useMemo(() => {
    const q = filters.query.trim().toLowerCase();
    const matched = rows.filter((row) => {
      if (q) {
        const haystack = `${row.id} ${row.ruleId} ${row.cwe} ${row.file} ${row.title}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      if (filters.cwe && row.cwe !== filters.cwe) return false;
      if (filters.validatedStatus && row.validatedStatus !== filters.validatedStatus) return false;
      if (filters.humanReviewState && row.humanReviewState !== filters.humanReviewState) return false;
      return true;
    });

    if (filters.sort === 'default') return matched;
    const compare = {
      cwe: (a, b) => sortText(a.cwe, b.cwe) || sortText(a.file, b.file) || sortText(a.id, b.id),
      validated: (a, b) => sortText(a.validatedStatus, b.validatedStatus) || sortText(a.id, b.id),
      human: (a, b) => sortText(a.humanReviewState, b.humanReviewState) || sortText(a.id, b.id),
      file: (a, b) => sortText(a.file, b.file) || (Number(a.line) || 0) - (Number(b.line) || 0),
      id: (a, b) => sortText(a.id, b.id),
    }[filters.sort];
    return compare ? [...matched].sort(compare) : matched;
  }, [rows, filters]);

  useEffect(() => {
    setPage(1);
  }, [filters]);

  const pages = Math.max(1, Math.ceil(filtered.length / PER_PAGE));
  const visible = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE);
  const hasActiveFilters = Boolean(filters.query || filters.cwe || filters.validatedStatus || filters.humanReviewState);

  return (
    <section className="section-block ntk-p05-findings">
      <SectionTitle title="Danh sách cảnh báo" />
      <Card className="table-card" style={{padding: 0}}>
        <div className={`rd-filters ntk-p05-findings-filters v2-findings-filters ${hasActiveFilters ? 'has-clear' : ''}`}>
          <label className="ntk-p05-input-group ntk-p05-findings-search">
            <span>Tìm cảnh báo</span>
            <input
              aria-label="Tìm theo mã cảnh báo, rule hoặc tệp"
              placeholder="Mã cảnh báo, rule, tệp Java…"
              value={filters.query}
              onChange={setField('query')}
            />
          </label>
          <label className="ntk-p05-input-group">
            <span>Loại lỗ hổng (CWE)</span>
            <select aria-label="Lọc theo CWE" value={filters.cwe} onChange={setField('cwe')}>
              <option value="">Tất cả CWE</option>
              {cweOptions.map((value) => (
                <option key={value} value={value}>{value} ({countOf(rows, 'cwe', value)})</option>
              ))}
            </select>
          </label>
          <label className="ntk-p05-input-group">
            <span>Nhận định Qwen</span>
            <select
              aria-label="Lọc theo nhận định Qwen"
              value={filters.validatedStatus}
              onChange={setField('validatedStatus')}
            >
              <option value="">Tất cả</option>
              {validatedOptions.map((value) => (
                <option key={value} value={value}>{value} ({countOf(rows, 'validatedStatus', value)})</option>
              ))}
            </select>
          </label>
          <label className="ntk-p05-input-group">
            <span>Người kiểm duyệt</span>
            <select
              aria-label="Lọc theo trạng thái người kiểm duyệt"
              value={filters.humanReviewState}
              onChange={setField('humanReviewState')}
            >
              <option value="">Tất cả</option>
              {humanOptions.map((value) => (
                <option key={value} value={value}>{value} ({countOf(rows, 'humanReviewState', value)})</option>
              ))}
            </select>
          </label>
          <label className="ntk-p05-input-group ntk-p05-sort">
            <span>Sắp xếp</span>
            <select aria-label="Sắp xếp danh sách cảnh báo" value={filters.sort} onChange={setField('sort')}>
              {SORTS.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
            </select>
          </label>
          {hasActiveFilters && (
            <button
              type="button"
              className="button-secondary ntk-p05-clear v2-findings-clear-btn"
              onClick={() => setFilters({query: '', cwe: '', validatedStatus: '', humanReviewState: '', sort: filters.sort})}
            >
              Xóa lọc
            </button>
          )}
        </div>

        {!visible.length ? (
          <EmptyState
            title="Không tìm thấy cảnh báo phù hợp"
            text="Thay đổi bộ lọc CWE, trạng thái Qwen, Human Review hoặc từ khóa tìm kiếm."
          />
        ) : (
          <div className="table-wrap">
            <table className="v2-findings-table">
              <thead>
                <tr>
                  <th>CWE &amp; Tệp Java</th>
                  <th>Nhận định Qwen</th>
                  <th>Trích dẫn</th>
                  <th>Người kiểm duyệt</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {visible.map((row) => {
                  const vMeta = validatedStatusMeta(row.validatedStatus);
                  const hMeta = humanReviewMeta(row.humanReviewState);
                  const shortFile = fileName(row.file) || row.file || 'Java';
                  const shortId = row.id.length > 16 ? `${row.id.slice(0, 12)}…` : row.id;
                  return (
                    <tr key={row.id}>
                      <td>
                        <div style={{display: 'flex', flexWrap: 'wrap', gap: '6px', alignItems: 'center', marginBottom: '4px'}}>
                          <Badge tone="blue">{row.cwe}</Badge>
                          <strong className="mono" title={row.file}>
                            {shortFile}:{row.line || '-'}
                          </strong>
                        </div>
                        <span className="v2-cell-sub mono" title={`${row.file} · ${row.id}`}>
                          {row.file !== shortFile ? `${row.file} · ` : ''}{shortId}
                        </span>
                      </td>
                      <td>
                        <Badge tone={vMeta.tone}>{row.validatedStatus}</Badge>
                        <span className="v2-cell-sub">{vMeta.viLabel}</span>
                        {row.validatorDowngraded && <span className="v2-cell-warn">Đã hạ cấp kiểm chứng</span>}
                      </td>
                      <td>
                        <Badge tone={citationCheckTone(row.citationCheck)}>
                          {row.citationCheck} ({row.citationsCount})
                        </Badge>
                      </td>
                      <td>
                        <Badge tone={hMeta.tone}>{row.humanReviewState}</Badge>
                        <span className="v2-cell-sub">{hMeta.viLabel}</span>
                      </td>
                      <td style={{whiteSpace: 'nowrap', textAlign: 'right'}}>
                        <Link
                          className="table-link"
                          to={`/finding/${encodeURIComponent(row.id)}${scanQuery(scanId)}`}
                          state={{detailUrl: row.detailUrl}}
                        >
                          Xem chi tiết <Icon name="ArrowUpRight" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="table-toolbar ntk-p05-list-pagination v2-table-footer-bar">
          <p className="muted-text v2-table-footer-count">
            Hiển thị <strong>{filtered.length.toLocaleString('vi-VN')}</strong> / {rows.length.toLocaleString('vi-VN')} cảnh báo
          </p>
          <div className="v2-table-pagination-controls">
            <button type="button" className="button-secondary button-compact" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Trước</button>
            <span>Trang <strong>{page}</strong> / {pages}</span>
            <button type="button" className="button-secondary button-compact" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>Tiếp</button>
          </div>
        </div>
      </Card>
    </section>
  );
}
