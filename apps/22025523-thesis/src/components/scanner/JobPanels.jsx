import {useEffect, useState} from 'react';
import {Badge, Card, DataNotice} from '../common/Ui';
import {api} from '../../services/api';
import {runtimeVerificationMeta} from '../../services/findingPresentation';
import {errorInfo, fmtMs, resolveStages, skipNote} from '../../services/jobModel';

function JsonDetails({summary, title}) {
  if (summary === null || summary === undefined) return null;
  return (
    <details className="v2-sub-details">
      <summary>{title}</summary>
      <div className="v2-sub-details-body">
        <pre className="v2-pre-block"><code>{typeof summary === 'string' ? summary : JSON.stringify(summary, null, 2)}</code></pre>
      </div>
    </details>
  );
}

export function StageOverview({job}) {
  const stages = resolveStages(job);
  return (
    <Card title="6 giai đoạn xử lý trên backend">
      <div className="mini-pipeline">
        {stages.map((stage) => (
          <div key={stage.key} className={`stage-cat-${stage.cat}`} title={`${stage.key} · ${stage.label}`}>
            <span>{String(stage.number).padStart(2, '0')}</span>
            {stage.name}
            {stage.number < stages.length && <i />}
          </div>
        ))}
      </div>
      <p className="panel-note">Trạng thái từng chặng được đồng bộ trực tiếp từ API <code>/api/scan-jobs</code>.</p>
    </Card>
  );
}

export function FailureDetails({job}) {
  const info = errorInfo(job);
  const failed = resolveStages(job).find((stage) => stage.cat === 'FAILED');
  return (
    <section className="card failure-details" role="alert">
      <span className="eyebrow">PHIÊN PHÂN TÍCH THẤT BẠI · CHẨN ĐOÁN TỪ API</span>
      <h2 style={{marginTop: '6px', marginBottom: '12px'}}>
        {failed
          ? `Dừng tại giai đoạn ${String(failed.number).padStart(2, '0')} · ${failed.name}`
          : 'Máy chủ API báo phiên phân tích thất bại (FAILED)'}
      </h2>
      <dl className="kv-list">
        <dt>Mã lỗi (error_code)</dt><dd className="mono">{info.code || 'API không cung cấp'}</dd>
        <dt>Thông báo lỗi</dt><dd>{info.message || 'API không cung cấp'}</dd>
        {failed && (
          <>
            <dt>Giai đoạn (stage_key)</dt><dd className="mono">{failed.key}</dd>
            <dt>Thời lượng</dt><dd>{fmtMs(failed.duration)}</dd>
          </>
        )}
        {failed?.error && <><dt>Chi tiết chặng</dt><dd>{failed.error}</dd></>}
      </dl>
      <div style={{display: 'grid', gap: '8px', marginTop: '12px'}}>
        {failed?.summary && <JsonDetails summary={failed.summary} title="Mở metadata giai đoạn" />}
        {info.limits && <JsonDetails summary={info.limits} title="Mở giới hạn tài nguyên API" />}
      </div>
      {info.steps.length > 0 && (
        <ul className="clean-list" style={{marginTop: '10px'}}>
          {info.steps.map((step) => <li key={String(step)}>{typeof step === 'string' ? step : JSON.stringify(step)}</li>)}
        </ul>
      )}
    </section>
  );
}

export function StageTiming({job}) {
  const stages = resolveStages(job);
  const durations = stages.map((stage) => stage.duration).filter((value) => value !== null);
  const sum = durations.reduce((total, value) => total + value, 0);
  const raw = job?.total_e2e_duration_ms;
  const total = raw === null || raw === undefined ? NaN : Number(raw);
  const longest = stages.filter((stage) => stage.duration !== null).sort((a, b) => b.duration - a.duration)[0];

  return (
    <section className="section-block" style={{marginTop: '14px'}}>
      <h3 style={{fontSize: '13px', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '10px'}}>
        Thời gian thực thi 6 giai đoạn (do API đo)
      </h3>
      <Card className="table-card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>#</th><th>Giai đoạn</th><th>Trạng thái</th><th>Thời lượng</th><th>Tỷ lệ</th><th>Ghi chú</th></tr>
            </thead>
            <tbody>
              {stages.map((stage) => {
                const note = skipNote(stage);
                const tone = stage.cat === 'COMPLETED' ? 'green'
                  : stage.cat === 'FAILED' ? 'red'
                    : stage.cat === 'RUNNING' ? 'blue'
                      : stage.cat === 'SKIPPED' ? 'amber'
                        : 'neutral';
                return (
                  <tr key={stage.key} className={`stage-cat-${stage.cat}`}>
                    <td className="mono">{String(stage.number).padStart(2, '0')}</td>
                    <td>
                      <strong>{stage.name}</strong>
                      <span className="v2-cell-sub mono">{stage.key}</span>
                    </td>
                    <td><Badge tone={tone}>{stage.label}</Badge></td>
                    <td className="mono">{fmtMs(stage.duration)}</td>
                    <td className="mono">{stage.duration !== null && sum > 0 ? `${(stage.duration / sum * 100).toFixed(1)}%` : '-'}</td>
                    <td>
                      {note && <p style={{margin: '0 0 6px', fontSize: '12px'}}>{note}</p>}
                      <JsonDetails summary={stage.summary} title="Metadata" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
      <div className="v2-scanner-metrics" style={{marginTop: '12px'}}>
        <div className="v2-mini-metric"><span>Tổng thời gian E2E</span><strong>{fmtMs(total)}</strong></div>
        <div className="v2-mini-metric"><span>Tổng cộng các chặng</span><strong>{fmtMs(sum)}</strong></div>
        <div className="v2-mini-metric"><span>Chặng lâu nhất</span><strong>{longest ? `${longest.name} (${fmtMs(longest.duration)})` : '-'}</strong></div>
        <div className="v2-mini-metric"><span>Chế độ LLM</span><strong>{job?.no_llm ? 'Bỏ qua Qwen (no_llm)' : 'Qwen3.5-9B (Ollama cục bộ)'}</strong></div>
      </div>
    </section>
  );
}

export function CoveragePanel({job}) {
  const scanId = job?.scan_id ?? '';
  const state = String(job?.state ?? '').toUpperCase();
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);
  const [requestError, setRequestError] = useState('');

  useEffect(() => {
    if (!scanId || state === 'RUNNING' || state === 'QUEUED') {
      setSummary(null);
      setLoading(false);
      setRequestError('');
      return undefined;
    }
    const controller = new AbortController();
    setLoading(true);
    setRequestError('');
    api.scanSummary(scanId, {signal: controller.signal})
      .then((doc) => {
        if (!controller.signal.aborted) setSummary(doc);
      })
      .catch((error) => {
        if (!controller.signal.aborted) setRequestError(error.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [scanId, state]);

  const rtMeta = summary ? runtimeVerificationMeta(summary.qwen_runtime_verified) : null;

  const rows = [
    ['Chế độ đầu vào', job?.input_mode || summary?.input_mode || '-'],
    ['Nguồn mã', job?.file_name || job?.repo_url || summary?.file_name || summary?.repo_url || '-'],
    ['Commit xác nhận', job?.resolved_commit || summary?.resolved_commit || '-'],
    ['Số tệp Java đã quét', summary?.java_files_scanned ?? job?.stages?.[0]?.summary_metadata?.java_files_count ?? '-'],
    ['Phiên bản OpenGrep', summary?.opengrep_version || '-'],
    ['Rules SHA-256', summary?.rules_sha256 || '-'],
    ['Prompt contract', summary?.prompt_contract ? `${summary.prompt_contract}${summary.prompt_version ? ` (${summary.prompt_version})` : ''}` : '-'],
    ['Tổng cảnh báo', summary?.total_findings ?? job?.progress?.total_findings ?? '-'],
    ['Trích dẫn khớp nguồn (MATCHED)', summary?.matched_citation_count ?? '-'],
    ['Bị hạ cấp về UNDETERMINED', summary?.validator_downgraded_count ?? '-'],
    ['Trạng thái xác thực runtime Qwen', rtMeta ? rtMeta.label : '-'],
  ];

  return (
    <section className="section-block" style={{marginTop: '16px'}}>
      <h3 style={{fontSize: '13px', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '10px'}}>
        Thông tin xác minh &amp; Provenance phiên quét
      </h3>
      <Card className="table-card">
        {loading && <DataNotice>Đang tải summary từ API…</DataNotice>}
        {requestError && <DataNotice>Không tải được summary: {requestError}</DataNotice>}
        <div className="table-wrap">
          <table>
            <tbody>
              {rows.map(([label, value]) => (
                <tr key={label}>
                  <td style={{width: '34%'}}><strong>{label}</strong></td>
                  <td className="mono wrap-value">{String(value)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </section>
  );
}
