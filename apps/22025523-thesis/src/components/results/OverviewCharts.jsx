import ReactECharts from 'echarts-for-react';
import {Card} from '../common/Ui';

// Presentation-only: all counts come from verified scan aggregates.
const TEXT = '#bfbfc7';
const GRID = '#494951';
const WHITE = '#f5f5f7';
const MUTED = '#999ba5';
const TOOLTIP = {
  backgroundColor: '#222227', borderColor: '#85858f', borderWidth: 1,
  textStyle: {color: WHITE, fontSize: 12},
  extraCssText: 'box-shadow: 0 12px 32px rgba(0,0,0,.48); border-radius: 10px; padding: 9px 12px;'
};
const DECISION_COLORS = {REPORT: '#d29a9f', REVIEW: '#d0ae7f', SUPPRESS: '#92b4a5', UNKNOWN: '#999ba7'};
const CWE_COLORS = {'CWE-22': '#c9b293', 'CWE-78': '#cb9889', 'CWE-79': '#aaa7bd', 'CWE-89': '#a9c0c6'};
const IRIS_PROOF_COLORS = {PROVEN_TAINT: '#cb8f93', PROVEN_SAFE: '#88ad9c', UNKNOWN: '#c7aa78'};
const SCORE_COLORS = ['#aab2be', '#8daea8', '#c5b692', '#d4a47f', '#cf8e91'];
const count = (entries) => entries.reduce((total, [, value]) => total + Number(value || 0), 0);
const fmt = (value) => Number(value).toLocaleString('vi-VN');
const metallic = (color) => ({
  type: 'linear', x: 0, y: 0, x2: 1, y2: 0,
  colorStops: [{offset: 0, color: '#6c6c74'}, {offset: 1, color}]
});
const baseAxis = {axisLine: {lineStyle: {color: '#63636e'}}, axisTick: {show: false}, axisLabel: {color: TEXT, fontSize: 12}};

const bar = (entries, palette, ariaDescription = 'Finding count in the selected verified scan', left = 83) => ({
  backgroundColor: 'transparent', textStyle: {color: TEXT},
  aria: {enabled: true, description: ariaDescription},
  animationDuration: 450,
  grid: {left, right: 44, top: 15, bottom: 22},
  tooltip: {...TOOLTIP, trigger: 'axis', axisPointer: {type: 'shadow'}, valueFormatter: (value) => `${fmt(value)} finding`},
  xAxis: {type: 'value', min: 0, minInterval: 1, axisLabel: {color: MUTED, fontSize: 11}, axisLine: {show: false},
    axisTick: {show: false}, splitLine: {lineStyle: {color: GRID, opacity: .46, type: 'dashed'}}},
  yAxis: {type: 'category', inverse: true, data: entries.map(([name]) => name),
    ...baseAxis, axisLine: {show: false}, axisLabel: {color: WHITE, fontSize: 12, fontWeight: 600}},
  series: [{name: 'Findings', type: 'bar', barMaxWidth: 23, barMinHeight: 1,
    data: entries.map(([name, value]) => ({value, itemStyle: {color: metallic(palette[name] || '#b9bac4'), borderRadius: [0, 5, 5, 0]}})),
    label: {show: true, position: 'right', distance: 9, color: WHITE, fontSize: 12, fontWeight: 700,
      formatter: ({value}) => fmt(value)}, emphasis: {focus: 'self'}}]
});

const pie = (entries) => {
  const total = count(entries);
  const values = Object.fromEntries(entries);
  return {
    backgroundColor: 'transparent', textStyle: {color: TEXT},
    aria: {enabled: true, description: 'Triage decisions, not verified true or false positive labels'},
    animationDuration: 550,
    color: entries.map(([name]) => DECISION_COLORS[name] || DECISION_COLORS.UNKNOWN),
    tooltip: {...TOOLTIP, trigger: 'item', formatter: '{b}: {c} finding ({d}%)'},
    legend: {bottom: 0, left: 'center', itemWidth: 10, itemHeight: 10, itemGap: 17,
      textStyle: {color: TEXT, fontSize: 12}, formatter: (name) => `${name}  ${fmt(values[name] || 0)}`},
    graphic: [
      {type: 'text', left: 'center', top: '34%', silent: true,
        style: {text: fmt(total), textAlign: 'center', fill: WHITE, font: '700 31px Segoe UI, Arial'}},
      {type: 'text', left: 'center', top: '50%', silent: true,
        style: {text: 'FINDINGS', textAlign: 'center', fill: MUTED, font: '600 10px Segoe UI, Arial'}}
    ],
    series: [{type: 'pie', radius: ['51%', '71%'], center: ['50%', '43%'], minAngle: 1,
      itemStyle: {borderColor: '#202025', borderWidth: 3, borderRadius: 5},
      label: {show: false}, labelLine: {show: false}, emphasis: {scale: true, scaleSize: 4},
      data: entries.map(([name, value]) => ({name, value}))}]
  };
};

const scoreBar = (entries) => ({
  backgroundColor: 'transparent', textStyle: {color: TEXT},
  aria: {enabled: true, description: 'CWSS values returned by backend, never re-scored by frontend'},
  animationDuration: 450,
  grid: {left: 40, right: 15, top: 24, bottom: 38},
  tooltip: {...TOOLTIP, trigger: 'axis', axisPointer: {type: 'shadow'}, valueFormatter: (value) => `${fmt(value)} finding`},
  xAxis: {type: 'category', data: entries.map(([name]) => name), ...baseAxis,
    axisLabel: {color: TEXT, fontSize: 11, interval: 0}},
  yAxis: {type: 'value', min: 0, minInterval: 1, axisLabel: {color: MUTED, fontSize: 11},
    axisLine: {show: false}, axisTick: {show: false}, splitLine: {lineStyle: {color: GRID, opacity: .46, type: 'dashed'}}},
  series: [{type: 'bar', barMaxWidth: 56, barMinHeight: 1,
    data: entries.map(([, value], index) => ({value,
      itemStyle: {color: metallic(SCORE_COLORS[index] || '#bcbcc5'), borderRadius: [5, 5, 0, 0]}})),
    label: {show: true, position: 'top', color: WHITE, fontSize: 12, fontWeight: 700,
      formatter: ({value}) => value ? fmt(value) : ''}, emphasis: {focus: 'self'}}]
});

function Chart({title, note, entries, option, chartHeight = 268, tag = 'WHOLE SCAN'}) {
  return (
    <Card className="ntk-p14-chart-card" title={title} action={<span className="ntk-p14-chart-tag">{tag}</span>}>
      <div className="ntk-p14-chart-canvas" role="group" aria-label={title}>
        <ReactECharts option={option} style={{height: chartHeight, width: '100%'}} opts={{renderer: 'svg'}} notMerge />
      </div>
      <div className="ntk-p14-chart-footer"><span>{note}</span><strong>{fmt(count(entries))} findings</strong></div>
    </Card>
  );
}

export default function OverviewCharts({agg, scoreInfo}) {
  const hasScores = scoreInfo.status === 'ok' && scoreInfo.scored > 0;
  return (
    <div className="rd-chart-grid ntk-p14-chart-grid">
      <Chart title="Findings theo CWE" note="Nhóm CWE có findings trong phiên quét" entries={agg.byCwe}
        option={bar(agg.byCwe, CWE_COLORS)} chartHeight={Math.max(250, Math.min(390, agg.byCwe.length * 45 + 110))} />
      <Chart title="Findings theo quyết định triage" note="Trạng thái xử lý; không phải kết luận TP/FP" entries={agg.byDecision}
        option={pie(agg.byDecision)} />
      <Chart title="Trạng thái bằng chứng IRIS" note="flow_proof_state do backend cung cấp; UNKNOWN không đồng nghĩa an toàn" entries={agg.byFlowProof}
        option={bar(agg.byFlowProof, IRIS_PROOF_COLORS, 'Finding count grouped by backend IRIS flow proof state', 125)} />
      {hasScores
        ? <Chart title="Phân bố điểm CWSS (0-100)" note="Phân bổ điểm do backend cung cấp" entries={agg.byScore}
            tag="CWSS BACKEND" option={scoreBar(agg.byScore)} />
        : <Card className="ntk-p14-chart-card ntk-p14-chart-empty" title="Phân bố điểm CWSS (0-100)">
            <p className="muted-text">Chưa đủ dữ liệu CWSS để vẽ biểu đồ toàn scan (trạng thái: {scoreInfo.status}; {scoreInfo.scored.toLocaleString()} / {scoreInfo.total.toLocaleString()} finding có điểm hợp lệ). Frontend không tự tính điểm.</p>
          </Card>}
    </div>
  );
}
