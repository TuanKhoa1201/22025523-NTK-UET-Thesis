import {useEffect, useRef, useState} from 'react';
import {Link, useOutletContext} from 'react-router-dom';
import {Card, PageHeader, Icon} from '../components/common/Ui';
import SecurityAnalysisScene from '../components/scanner/SecurityAnalysisScene';
import {CoveragePanel, FailureDetails, StageOverview} from '../components/scanner/JobPanels';
import {api, inputErrorMessage} from '../services/api';
import {currentStageIndex, resolveStages, skipNote} from '../services/jobModel';
import {loadLiveScan, scanQuery} from '../services/liveScan';
import {readHistory, upsertHistory} from '../services/scanHistory';

const phaseCount = 10;
const JOB_KEY = '22025523-active-job';
const STAGE_KEYS = [
  'PROJECT_INTAKE', 'SOURCE_INVENTORY', 'OPENGREP_DETECTION', 'CONTEXT_EXTRACTION',
  'IRIS_PROGRAM_ANALYSIS', 'LLM_INFERENCE', 'EVIDENCE_FUSION', 'SAST_SCORING',
  'ALERT_VERIFICATION', 'REPORT_SYNTHESIS'
];

function stageNumber(stage, index) {
  const value = Number(stage?.stage_number ?? stage?.stage_no ?? stage?.number);
  if (Number.isInteger(value) && value >= 1 && value <= 10) return value;
  const key = String(stage?.stage_key ?? stage?.key ?? stage?.stage_id ?? '').toUpperCase();
  const found = STAGE_KEYS.indexOf(key);
  return found >= 0 ? found + 1 : index + 1;
}

function formatMs(value) {
  return value !== null && value !== undefined && value !== '' && Number.isFinite(Number(value))
    ? `${Number(value).toLocaleString('vi-VN', {minimumFractionDigits: 3, maximumFractionDigits: 3})} ms`
    : '-';
}

function StageTiming({job, counts}) {
  const stages = Array.isArray(job?.stages) ? job.stages : [];
  const resolved = resolveStages(job);
  const byNumber = new Map(stages.map((stage, index) => [stageNumber(stage, index), stage]));
  const durations = [...byNumber.values()].map((stage) => Number(stage.duration_ms)).filter(Number.isFinite);
  const sum = durations.reduce((total, value) => total + value, 0);
  return (
    <section className="section-block">
      <h3>THỜI GIAN THỰC THI 10 GIAI ĐOẠN</h3>
      <Card className="table-card">
        <div className="table-wrap">
          <table>
            <thead><tr><th>#</th><th>Stage</th><th>Backend state</th><th>Duration</th><th>Tỷ lệ</th><th>Metadata</th></tr></thead>
            <tbody>{Array.from({length: phaseCount}, (_, index) => {
              const stage = byNumber.get(index + 1);
              const current = resolved[index];
              const active = current.cat === 'RUNNING';
              const status = current.label;
              const elapsed = Number(stage?.running_elapsed_ms);
              const note = skipNote(current, counts);
              return (
                <tr key={index}>
                  <td>{String(index + 1).padStart(2, '0')}</td>
                  <td>{stage?.stage_name || stage?.name || STAGE_KEYS[index]}</td>
                  <td>{status}{active && Number.isFinite(elapsed) ? ` · elapsed ${formatMs(elapsed)}` : ''}{note ? ` · ${note}` : ''}</td>
                  <td>{formatMs(stage?.duration_ms)}</td>
                  <td>{stage?.duration_ms !== null && stage?.duration_ms !== undefined && Number.isFinite(Number(stage?.duration_ms)) && sum > 0 ? `${(Number(stage.duration_ms) / sum * 100).toFixed(2)}%` : '-'}</td>
                  <td className="mono">{stage?.summary_metadata ? JSON.stringify(stage.summary_metadata) : '-'}</td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      </Card>
    </section>
  );
}

export default function Scanner() {
  const backend = useOutletContext()?.backend ?? {status: 'CHECKING', health: null};
  const [tab, setTab] = useState('github');
  const [url, setUrl] = useState('');
  const [forceFresh, setForceFresh] = useState(false);
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [elapsedMs, setElapsedMs] = useState(0);
  const [liveStatus, setLiveStatus] = useState('');
  const [liveStage, setLiveStage] = useState('IDLE');
  const [backendMs, setBackendMs] = useState(null);
  const [liveScanId, setLiveScanId] = useState('');
  const [liveCounts, setLiveCounts] = useState(null);
  const [liveJob, setLiveJob] = useState(null);
  const [interrupted, setInterrupted] = useState(false);
  const [jobId, setJobId] = useState(() => window.sessionStorage.getItem(JOB_KEY) || '');
  const timerRef = useRef(null);
  const startRef = useRef(Number(window.sessionStorage.getItem(JOB_KEY + '-started')) || 0);
  const requestRef = useRef(null);
  const pendingRef = useRef(false);
  const inputRef = useRef(null);
  const simulationRef = useRef(null);

  useEffect(() => () => {
    window.clearInterval(timerRef.current);
    requestRef.current?.abort();
  }, []);

  // Resume the elapsed clock after a page reload while a known backend job
  // remains active. No stage duration or scan result is simulated here.
  useEffect(() => {
    if (!jobId || !startRef.current || timerRef.current) return;
    setElapsedMs(Math.max(0, Date.now() - startRef.current));
    timerRef.current = window.setInterval(() => {
      setElapsedMs(Math.max(0, Date.now() - startRef.current));
    }, 250);
  }, [jobId]);

  const scrollToSimulation = () => {
    requestAnimationFrame(() => simulationRef.current?.scrollIntoView({behavior: 'smooth', block: 'start'}));
  };

  useEffect(() => {
    if (!jobId) return undefined;
    const controller = new AbortController();
    let stopped = false;
    let pollTimer;

    const poll = async () => {
      try {
        const job = await api.scanJob(jobId, {signal: controller.signal});
        if (stopped) return;
        setInterrupted(false);
        setLiveJob(job);
        const state = String(job?.state || '').toUpperCase();
        if (state !== 'COMPLETED') setLiveStage(state || 'IDLE');
        if (job?.scan_id) {
          window.sessionStorage.setItem('22025523-scan-id', job.scan_id);
          setLiveScanId(job.scan_id);
        }
        if (state === 'QUEUED' || state === 'RUNNING') {
          setLiveStatus(state === 'QUEUED'
            ? 'Đang chờ lượt phân tích'
            : job.publication_state === 'PERSISTING_RESULTS'
              ? 'Đang hoàn tất và lưu kết quả phiên quét…'
              : `Đang phân tích mã nguồn${job.active_stage ? ` · Bước ${job.active_stage}/10` : ''}`);
          pollTimer = window.setTimeout(poll, 750);
          return;
        }
        if (state === 'COMPLETED') {
          // A completed stage-10 trace is not a completed scan. Wait for the
          // terminal job AND the matching backend findings before closing
          // the visual pipeline and freezing its total elapsed time.
          setLiveStage('LOADING_RESULTS');
          setLiveStatus('Backend đã xử lý xong. Đang xác nhận kết quả phiên quét…');
          if (!job.scan_id) {
            window.clearInterval(timerRef.current);
            timerRef.current = null;
            setLiveStage('RESULTS_ERROR');
            setLiveStatus('Không có mã phiên để xác nhận kết quả.');
            setError('Job báo hoàn tất nhưng chưa cung cấp scan_id hợp lệ.');
            setBusy(false);
            return;
          }
          try {
            const data = await loadLiveScan(job.scan_id, controller.signal);
            if (stopped) return;
            if (!data?.counts) throw new Error('Backend chưa cung cấp thống kê của phiên.');
            const total = data.scan?.total_e2e_duration_ms;
            setBackendMs(typeof total === 'number' && Number.isFinite(total) ? total : null);
            setLiveCounts(data.counts);
            window.clearInterval(timerRef.current);
            timerRef.current = null;
            if (startRef.current) setElapsedMs(Math.max(0, Date.now() - startRef.current));
            else if (typeof total === 'number' && Number.isFinite(total)) setElapsedMs(total);
            setLiveStage('COMPLETED');
            setLiveStatus(data.counts.total === 0
              ? 'Quét hoàn tất. Chưa phát hiện cảnh báo trong phạm vi kiểm tra.'
              : 'Quét hoàn tất. Kết quả đã sẵn sàng.');
          } catch (failure) {
            if (stopped || controller.signal.aborted) return;
            window.clearInterval(timerRef.current);
            timerRef.current = null;
            if (startRef.current) setElapsedMs(Math.max(0, Date.now() - startRef.current));
            setLiveStage('RESULTS_ERROR');
            setLiveStatus('Backend kết thúc nhưng chưa xác nhận được kết quả.');
            setError(`Không thể tải kết quả của phiên ${job.scan_id}: ${failure.message}`);
          }
          setBusy(false);
          return;
        }
        if (state === 'FAILED') {
          window.clearInterval(timerRef.current);
          timerRef.current = null;
          if (startRef.current) setElapsedMs(Math.max(0, Date.now() - startRef.current));
          setBusy(false);
          setLiveStatus('Quét không thành công.');
          setError(inputErrorMessage(job));
          if (job.scan_id) upsertHistory({scanId: job.scan_id, status: 'FAILED'});
          return;
        }
        setLiveStatus('Chưa xác định được tiến trình. Đang thử kết nối lại.');
        pollTimer = window.setTimeout(poll, 1500);
      } catch (failure) {
        if (!stopped && !controller.signal.aborted) {
          setInterrupted(true);
          setLiveStatus(`Mất kết nối khi theo dõi. Đang thử lại. ${failure.message}`);
          pollTimer = window.setTimeout(poll, 1500);
        }
      }
    };

    poll();
    return () => {
      stopped = true;
      window.clearTimeout(pollTimer);
      controller.abort();
    };
  }, [jobId]);

  useEffect(() => {
    if (jobId || busy || pendingRef.current) return undefined;
    const scanId = window.sessionStorage.getItem('22025523-scan-id');
    if (!scanId) return undefined;
    const controller = new AbortController();
    setLiveScanId(scanId);
    loadLiveScan(scanId, controller.signal)
      .then((data) => {
        setLiveCounts(data.counts);
        setLiveStage('COMPLETED');
        const total = data.scan?.total_e2e_duration_ms;
        setBackendMs(typeof total === 'number' && Number.isFinite(total) ? total : null);
        if (typeof total === 'number' && Number.isFinite(total)) setElapsedMs(total);
      })
      .catch((failure) => {
        if (!controller.signal.aborted) setError(failure.message);
      });
    return () => controller.abort();
  }, [jobId, busy]);

  const startLive = async () => {
    if (pendingRef.current || busy) return;
    setError('');
    if (backend.status !== 'CONNECTED') {
      const statusMessage = backend.status === 'CHECKING'
        ? 'Đang kiểm tra backend. Vui lòng thử lại sau khi kiểm tra hoàn tất.'
        : 'Backend chưa được xác nhận kết nối. Hãy kiểm tra trạng thái API trước khi chạy LIVE.';
      setError(statusMessage);
      setLiveStatus(statusMessage);
      return;
    }
    if (tab === 'zip' && (!file || !/\.zip$/i.test(file.name))) {
      setError('Chọn tệp .zip chứa mã nguồn Java.');
      return;
    }
    const uploadLimit = backend.health?.source_inventory_limits?.max_zip_upload_bytes ?? 25*1024*1024;
    if (tab === 'zip' && file.size > uploadLimit) {
      setError(`Tệp ZIP vượt giới hạn ${Math.round(uploadLimit/1024/1024)} MB [MAX_ZIP_UPLOAD_BYTES_EXCEEDED]`);
      return;
    }
    if (tab === 'github' && !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/.test(url.trim())) {
      setError('Nhập URL repository GitHub công khai hợp lệ.');
      return;
    }
    pendingRef.current = true;
    // A new submission owns the status panel. Do not restore the previous
    // scan while its job ID is cleared or overwrite this request's HTTP error.
    window.sessionStorage.removeItem(JOB_KEY);
    window.sessionStorage.removeItem(JOB_KEY + '-started');
    window.sessionStorage.removeItem('22025523-scan-id');
    const controller = new AbortController();
    requestRef.current = controller;
    const startedAt = new Date().toISOString();
    let submittedId = '';
    setBusy(true);
    setLiveJob(null);
    setJobId('');
    setLiveCounts(null);
    setLiveScanId('');
    setLiveStatus('Đang gửi yêu cầu phân tích');
    setLiveStage('SUBMITTING');
    setBackendMs(null);
    setElapsedMs(0);
    startRef.current = Date.now();
    window.clearInterval(timerRef.current);
    timerRef.current = window.setInterval(() => setElapsedMs(Date.now() - startRef.current), 250);
    scrollToSimulation();
    try {
      setLiveStage('WAITING_FOR_RESPONSE');
      setLiveStatus('Đang gửi yêu cầu đến máy chủ');
      // Giao diện đơn giản dùng nhánh mặc định, toàn bộ phạm vi Java và giới hạn an toàn của backend.
      // Không gửi commit, subpath hoặc max_files_limit giả định thay cho lựa chọn người dùng.
      const result = tab === 'zip'
        ? await api.createZipJob(file, {signal:controller.signal})
        : await api.createScanJob(url.trim(), undefined, {signal:controller.signal}, {
            scan_scope_policy: 'STRICT_FAIL_ON_LIMIT',
            ...(forceFresh ? {force_fresh_scan:true,force_new_job:true} : {})
          });
      if (typeof result?.job_id !== 'string' || !result.job_id) {
        throw new Error('Backend chưa trả về job_id theo hợp đồng hiện tại. Không thể theo dõi job này.');
      }
      submittedId = result.scan_id || '';
      window.sessionStorage.setItem(JOB_KEY, result.job_id);
      window.sessionStorage.setItem(JOB_KEY + '-started', String(startRef.current));
      if (submittedId) {
        window.sessionStorage.setItem('22025523-scan-id', submittedId);
        setLiveScanId(submittedId);
        upsertHistory({scanId: submittedId, jobId: result.job_id, repoUrl:tab==='github'?url.trim():undefined, fileName:tab==='zip'?file.name:undefined, inputMode:tab==='zip'?'ZIP':'GITHUB', startedAt, status: result.state || 'QUEUED'});
      }
      setJobId(result.job_id);
      setLiveJob(result);
      setLiveStage(String(result.state || 'QUEUED').toUpperCase());
      setLiveStatus('Yêu cầu phân tích đã được tiếp nhận');
    } catch (failure) {
      if (!controller.signal.aborted) {
        setError(failure.message || 'Không thể kết nối máy chủ phân tích.');
        setLiveStatus('Không thể xác nhận trạng thái quét');
        setLiveStage('FAILED');
        setBusy(false);
        window.clearInterval(timerRef.current);
      }
    } finally {
      pendingRef.current = false;
      requestRef.current = null;
    }
  };

  const statusMessage = liveStatus || (liveStage === 'COMPLETED'
    ? 'Đã tải kết quả phiên phân tích gần nhất.'
    : ({
    CHECKING: 'Đang kiểm tra kết nối máy chủ…',
    CONNECTED: 'Sẵn sàng phân tích dự án Java.',
    DISCONNECTED: 'Chưa kết nối được máy chủ phân tích.',
    ERROR: 'Không thể kết nối đến máy chủ phân tích.'
    }[backend.status] || 'Chưa có phiên phân tích đang chạy.'));
  const simpleStatus = liveStage === 'COMPLETED' ? 'Hoàn tất'
    : liveStage === 'FAILED' ? 'Thất bại'
      : liveStage === 'QUEUED' ? 'Đang chờ'
        : busy || ['RUNNING', 'SUBMITTING', 'WAITING_FOR_RESPONSE'].includes(liveStage)
          ? 'Đang phân tích'
          : null;

  const latest = readHistory().find((record) => record.status === 'COMPLETED');
  const resultId = liveScanId || latest?.scanId || '';
  const stageIndex = currentStageIndex(liveJob);
  const activeStage = stageIndex === null ? null : stageIndex + 1;
  const livePhase = activeStage || 0;
  const jobFailed = String(liveJob?.state || '').toUpperCase() === 'FAILED';

  return (
    <>
      <PageHeader eyebrow="ỨNG DỤNG PHÂN TÍCH" title="Phân tích dự án" description="Nhập liên kết GitHub hoặc tải tệp ZIP chứa mã nguồn Java để bắt đầu." />
      <div className="scanner-layout">
        <div className="scanner-main">
          <div className="tab-switcher">
            <button className={tab === 'github' ? 'active' : ''} onClick={() => setTab('github')}><Icon name="Github" />GitHub Repository</button>
            <button className={tab === 'zip' ? 'active' : ''} onClick={() => setTab('zip')}><Icon name="Archive" />Tải tệp ZIP</button>
          </div>
          <Card className="scanner-input-card">
            {tab === 'github' ? (
              <div className="input-section ntk-p15-repo-section">
                <div className="ntk-p15-field-header">
                  <label htmlFor="repo-url">Liên kết dự án GitHub</label>
                  <span className="ntk-p15-field-meta">Java / Public</span>
                </div>
                <div className="input-with-icon ntk-p15-repo-input">
                  <Icon name="Github" />
                  <input
                    id="repo-url"
                    type="url"
                    value={url}
                    disabled={busy}
                    onChange={(event) => setUrl(event.target.value)}
                    placeholder="https://github.com/owner/repository"
                    aria-describedby="repo-url-help"
                    autoComplete="url"
                    spellCheck={false}
                  />
                </div>
                <p id="repo-url-help" className="scanner-input-hint ntk-p15-repo-hint"><Icon name="Info" />Chỉ hỗ trợ dự án Java công khai.</p>
                <details className="scanner-advanced ntk-p15-advanced">
                  <summary><span className="ntk-p15-advanced-title"><Icon name="Sliders" />Tùy chọn kiểm thử</span><Icon name="ChevronDown" /></summary>
                  <div className="ntk-p15-advanced-body">
                    <label className="scanner-fresh-option ntk-p15-fresh-option">
                      <input type="checkbox" checked={forceFresh} disabled={busy} onChange={(event) => setForceFresh(event.target.checked)} />
                      <span><strong>Quét mới không dùng bộ nhớ đệm</strong><small>Có thể mất nhiều thời gian hơn.</small></span>
                    </label>
                  </div>
                </details>
              </div>
            ) : (
              <button className={`dropzone ${file ? 'has-file' : ''}`} onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => {event.preventDefault(); setFile(event.dataTransfer.files[0] || null);}}>
                <input ref={inputRef} type="file" accept=".zip,application/zip" hidden onChange={(event) => setFile(event.target.files[0] || null)} />
                <span className="drop-icon"><Icon name={file ? 'FileArchive' : 'UploadCloud'} /></span>
                <strong>{file?.name || 'Kéo thả tệp ZIP vào đây'}</strong>
                <span>{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB` : 'hoặc chọn tệp từ thiết bị · chỉ hỗ trợ .zip'}</span>
                <span className="button-secondary">{file ? 'Chọn tệp khác' : 'Chọn tệp ZIP'}</span>
              </button>
            )}
            {tab === 'zip' && <p className="scanner-input-hint">Chỉ phân tích mã nguồn Java trong tệp ZIP.</p>}
            {error && <div className="inline-error" role="alert"><Icon name="AlertTriangle" />{error}</div>}
            <div className="scanner-submit scanner-submit--minimal">
              <button className="button-primary" disabled={busy} onClick={startLive}>
                <Icon name="ScanSearch" />{busy ? 'Đang phân tích…' : 'Bắt đầu phân tích'}<Icon name="ArrowRight" />
              </button>
            </div>
          </Card>
        </div>
        <aside className="scanner-aside">
          <StageOverview job={liveJob} />
        </aside>
      </div>
      <div ref={simulationRef} className="simulation-anchor">
        <SecurityAnalysisScene live={{stage: liveStage, state: String(liveJob?.state || liveStage).toUpperCase(), activeStage: ['COMPLETED', 'LOADING_RESULTS', 'RESULTS_ERROR'].includes(liveStage) || liveJob?.publication_state === 'PERSISTING_RESULTS' ? 10 : activeStage, stages: liveJob?.stages || [], counts: liveCounts, publicationState: liveJob?.publication_state, resultsReady: liveStage === 'COMPLETED' && liveCounts !== null && Boolean(liveScanId) && (!liveJob?.scan_id || liveJob.scan_id === liveScanId), interrupted}} phase={livePhase} elapsedMs={elapsedMs} running={busy} />
        <section className="card live-scan-status live-scan-status--compact" aria-live="polite">
          <div className="scan-status-heading">
            <h2>Tiến trình quét</h2>
            {simpleStatus && <span className={`scan-status-chip ${liveStage === 'FAILED' ? 'scan-status-chip--failed' : ''}`}>{simpleStatus}</span>}
          </div>
          <p className="scan-status-message">{statusMessage}</p>
          {interrupted && <p className="inline-warning">Kết nối bị gián đoạn. Hệ thống đang thử kết nối lại.</p>}
          {backendMs !== null && <p>Thời gian xử lý: <strong>{(backendMs / 1000).toLocaleString('vi-VN', {maximumFractionDigits: 1})} giây</strong></p>}
          {liveStage === 'COMPLETED' && liveCounts && liveCounts.total === 0 && <p>Không tìm thấy cảnh báo thuộc phạm vi quét; kết quả này không chứng minh mã nguồn hoàn toàn an toàn.</p>}
          <div className="scan-status-actions">
            {resultId && liveStage !== 'FAILED' && <Link className="button-secondary" to={`/findings${scanQuery(resultId)}`}>{liveScanId ? 'Xem kết quả' : 'Mở phiên gần nhất'} <Icon name="ArrowRight" /></Link>}
            {liveScanId && !busy && <Link className="scan-status-replay" to={`/replay?scan=${encodeURIComponent(liveScanId)}`}>Xem lại quá trình quét <Icon name="ArrowRight" /></Link>}
          </div>
        </section>
        {jobFailed && <FailureDetails job={liveJob} />}
        {(liveJob || liveScanId) && (
          <details className="scanner-technical-details">
            <summary>Thông tin kỹ thuật phiên quét</summary>
            {liveScanId && <p>Mã phiên: <code>{liveScanId}</code></p>}
            {liveJob && <StageTiming job={liveJob} counts={liveCounts} />}
            {liveJob && <CoveragePanel job={liveJob} counts={liveCounts} />}
          </details>
        )}
      </div>
    </>
  );
}