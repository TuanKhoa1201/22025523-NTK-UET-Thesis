import {useState} from 'react';
import {Card} from '../common/Ui';
import {PRIORITY_CWES} from '../../services/findingPresentation';

const CWE_SUBTITLES = {
  'CWE-22': 'Path Traversal',
  'CWE-89': 'SQL Injection',
};

const VALIDATED_ITEMS = [
  {key: 'SUPPORTED', label: 'Supported', sub: 'AI có cơ sở', color: '#DF9DA3'},
  {key: 'REFUTED', label: 'Refuted', sub: 'AI nghi giả', color: '#E2C593'},
  {key: 'UNDETERMINED', label: 'Undetermined', sub: 'Chưa đủ bằng chứng', color: '#8E96A6'},
];

const HUMAN_ITEMS = [
  {key: 'OPEN', label: 'Open', sub: 'Chờ duyệt', color: '#B8C7DE'},
  {key: 'CONFIRMED_TRUE', label: 'Confirmed True', sub: 'Xác nhận thật', color: '#DF9DA3'},
  {key: 'CONFIRMED_FALSE', label: 'Confirmed False', sub: 'Xác nhận giả', color: '#9BD1B5'},
];

const pctOf = (value, total) => (total > 0 ? Math.round((value / total) * 100) : 0);

function CweColumnChartCard({title, rows, total}) {
  const [hoveredKey, setHoveredKey] = useState('');
  const maxVal = Math.max(1, ...rows.map((r) => r.value));
  const activeItem = rows.find((r) => r.key === hoveredKey) || null;

  const chartW = 280;
  const chartH = 148;
  const padTop = 26;
  const padBottom = 38;
  const plotH = chartH - padTop - padBottom;
  const count = Math.max(1, rows.length);
  const slotW = (chartW - 24) / count;
  const barW = Math.min(44, Math.max(22, slotW * 0.42));

  return (
    <Card className="v2-dist-card v2-chart-card">
      <div className="v2-chart-head">
        <h3>{title}</h3>
        <span className="v2-chart-pill mono">
          {activeItem
            ? `${activeItem.label} · ${pctOf(activeItem.value, total)}%`
            : `Tổng: ${total.toLocaleString('vi-VN')}`}
        </span>
      </div>
      {rows.length === 0 ? (
        <p className="panel-note" style={{margin: 0, fontSize: '12.5px'}}>Chưa có dữ liệu</p>
      ) : (
        <div className="v2-column-chart-wrap">
          <svg
            className="v2-column-chart-svg"
            viewBox={`0 0 ${chartW} ${chartH}`}
            role="img"
            aria-label={`${title}: ${rows.map((r) => `${r.label} ${r.value}`).join(', ')}`}
          >
            <defs>
              <linearGradient id="v2CweBarFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#DCE6F5" stopOpacity="0.95" />
                <stop offset="100%" stopColor="#7C8CA8" stopOpacity="0.58" />
              </linearGradient>
              <linearGradient id="v2CweBarActive" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#FFFFFF" stopOpacity="1" />
                <stop offset="100%" stopColor="#A9BCD9" stopOpacity="0.82" />
              </linearGradient>
            </defs>

            {[0, 0.5, 1].map((ratio) => {
              const y = padTop + plotH * (1 - ratio);
              return (
                <line
                  key={ratio}
                  x1="12"
                  y1={y}
                  x2={chartW - 12}
                  y2={y}
                  stroke={ratio === 0 ? 'rgba(221, 224, 230, 0.2)' : 'rgba(221, 224, 230, 0.08)'}
                  strokeDasharray={ratio === 0 ? undefined : '3 3'}
                  strokeWidth="1"
                />
              );
            })}

            {rows.map((item, idx) => {
              const cx = 12 + slotW * idx + slotW / 2;
              const barH = item.value > 0 ? Math.max(8, (item.value / maxVal) * plotH) : 0;
              const y = padTop + plotH - barH;
              const isHover = hoveredKey === item.key;
              return (
                <g
                  key={item.key}
                  className="v2-chart-bar-group"
                  onMouseEnter={() => setHoveredKey(item.key)}
                  onMouseLeave={() => setHoveredKey('')}
                >
                  <rect
                    x={cx - slotW / 2}
                    y={padTop - 10}
                    width={slotW}
                    height={plotH + padBottom + 10}
                    fill="transparent"
                  />
                  {barH > 0 && (
                    <rect
                      x={cx - barW / 2}
                      y={y}
                      width={barW}
                      height={barH}
                      rx={6}
                      fill={isHover ? 'url(#v2CweBarActive)' : 'url(#v2CweBarFill)'}
                    />
                  )}
                  <text
                    x={cx}
                    y={(barH > 0 ? y : padTop + plotH) - 7}
                    textAnchor="middle"
                    className="v2-chart-bar-value"
                  >
                    {item.value.toLocaleString('vi-VN')}
                  </text>
                  <text
                    x={cx}
                    y={padTop + plotH + 17}
                    textAnchor="middle"
                    className="v2-chart-bar-label"
                  >
                    {item.label}
                  </text>
                  {item.sub && (
                    <text
                      x={cx}
                      y={padTop + plotH + 31}
                      textAnchor="middle"
                      className="v2-chart-bar-sub"
                    >
                      {item.sub}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        </div>
      )}
    </Card>
  );
}

function DonutChartCard({title, items, total}) {
  const [hoveredKey, setHoveredKey] = useState('');
  const activeItem = items.find((item) => item.key === hoveredKey) || null;
  const radius = 42;
  const circumference = 2 * Math.PI * radius;

  let cumulative = 0;
  const segments = items.map((item) => {
    const share = total > 0 ? item.value / total : 0;
    const length = share * circumference;
    const offset = -cumulative;
    cumulative += length;
    return {...item, share, length, offset};
  });

  return (
    <Card className="v2-dist-card v2-chart-card">
      <div className="v2-chart-head">
        <h3>{title}</h3>
        <span className="v2-chart-pill mono">
          {activeItem
            ? `${pctOf(activeItem.value, total)}%`
            : `Tổng: ${total.toLocaleString('vi-VN')}`}
        </span>
      </div>
      <div className="v2-donut-layout">
        <div className="v2-donut-figure">
          <svg
            className="v2-donut-svg"
            viewBox="0 0 112 112"
            role="img"
            aria-label={`${title}: ${items.map((item) => `${item.label} ${item.value}`).join(', ')}`}
          >
            <circle
              cx="56"
              cy="56"
              r={radius}
              fill="none"
              stroke="rgba(255, 255, 255, 0.08)"
              strokeWidth="12"
            />
            {total > 0 && segments.map((seg) => (
              seg.value > 0 ? (
                <circle
                  key={seg.key}
                  cx="56"
                  cy="56"
                  r={radius}
                  fill="none"
                  stroke={seg.color}
                  strokeWidth={hoveredKey === seg.key ? 14 : 12}
                  strokeDasharray={`${seg.length} ${Math.max(0, circumference - seg.length)}`}
                  strokeDashoffset={seg.offset}
                  transform="rotate(-90 56 56)"
                  className="v2-donut-seg"
                  opacity={hoveredKey && hoveredKey !== seg.key ? 0.42 : 1}
                  onMouseEnter={() => setHoveredKey(seg.key)}
                  onMouseLeave={() => setHoveredKey('')}
                />
              ) : null
            ))}
          </svg>
          <div className="v2-donut-center" aria-hidden="true">
            <strong>{(activeItem ? activeItem.value : total).toLocaleString('vi-VN')}</strong>
            <span>{activeItem ? `${pctOf(activeItem.value, total)}%` : 'Tổng'}</span>
          </div>
        </div>

        <ul className="v2-donut-legend">
          {items.map((item) => {
            const pct = pctOf(item.value, total);
            const isHover = hoveredKey === item.key;
            return (
              <li
                key={item.key}
                className={isHover ? 'is-active' : ''}
                onMouseEnter={() => setHoveredKey(item.key)}
                onMouseLeave={() => setHoveredKey('')}
              >
                <span className="v2-legend-left">
                  <i className="v2-legend-dot" style={{background: item.color}} aria-hidden="true" />
                  <span className="v2-legend-text">
                    <strong>{item.label}</strong>
                    <small>{item.sub}</small>
                  </span>
                </span>
                <span className="v2-legend-metric mono">
                  <strong>{item.value.toLocaleString('vi-VN')}</strong>
                  <small>{pct}%</small>
                </span>
              </li>
            );
          })}
        </ul>
      </div>
    </Card>
  );
}

export default function OverviewCharts({agg}) {
  if (!agg) return null;
  const total = agg.byCwe.reduce((sum, [, v]) => sum + Number(v || 0), 0);

  const cweMap = new Map(agg.byCwe.map(([cwe, count]) => [cwe, Number(count || 0)]));
  const orderedCwes = [
    ...PRIORITY_CWES,
    ...agg.byCwe.map(([cwe]) => cwe).filter((cwe) => !PRIORITY_CWES.includes(cwe)),
  ].slice(0, 6);
  const cweRows = orderedCwes.map((cwe) => ({
    key: cwe,
    label: cwe,
    sub: CWE_SUBTITLES[cwe] || '',
    value: cweMap.get(cwe) ?? 0,
  }));

  const validatedMap = new Map(agg.byValidatedStatus.map(([k, v]) => [k, Number(v || 0)]));
  const validatedItems = VALIDATED_ITEMS.map((item) => ({
    ...item,
    value: validatedMap.get(item.key) ?? 0,
  }));

  const humanMap = new Map(agg.byHumanReviewState.map(([k, v]) => [k, Number(v || 0)]));
  const humanItems = HUMAN_ITEMS.map((item) => ({
    ...item,
    value: humanMap.get(item.key) ?? 0,
  }));

  return (
    <div className="v2-dist-grid v2-charts-grid" role="region" aria-label="Biểu đồ phân bố cảnh báo theo CWE, nhận định Qwen và người kiểm duyệt">
      <CweColumnChartCard title="Phân loại CWE" rows={cweRows} total={total} />
      <DonutChartCard title="Nhận định Qwen" items={validatedItems} total={total} />
      <DonutChartCard title="Quyết định người kiểm duyệt" items={humanItems} total={total} />
    </div>
  );
}
