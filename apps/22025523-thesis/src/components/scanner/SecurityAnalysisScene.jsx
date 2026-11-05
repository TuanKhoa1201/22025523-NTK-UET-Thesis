import {useState} from 'react';
import {Icon} from '../common/Ui';
import {scanGuide} from '../../data/scanGuide';
import ScanStageVisual from './ScanStageVisual';
import {backendStageStatus, isLiveSessionReady} from './liveStagePresentation';

const LIVE_NOTICE='Trực quan hóa kiến trúc trong khi backend đang phân tích. Các bước chuyển động không biểu thị tiến độ thực tế của từng engine.';
const LIVE_STATUS={
  IDLE:'SẴN SÀNG',
  SUBMITTING:'ĐANG GỬI YÊU CẦU',
  WAITING_FOR_RESPONSE:'ĐANG CHỜ BACKEND',
  QUEUED:'JOB ĐANG XẾP HÀNG',
  RUNNING:'JOB ĐANG CHẠY',
  LOADING_RESULTS:'ĐANG TẢI KẾT QUẢ',
  RESULTS_ERROR:'CHƯA THỂ TẢI KẾT QUẢ',
  COMPLETED:'BACKEND ĐÃ HOÀN TẤT',
  FAILED:'THẤT BẠI'
};

export default function SecurityAnalysisScene(props) {
  return <SceneBody {...props} complete={props.complete || isLiveSessionReady(props.live)} />;
}

function SceneBody({
  phase=0,elapsedMs=0,phaseDurations=[],running=false,paused=false,complete=false,
  onReplay,onPause,onResume,live=null
}) {
  const [selected,setSelected]=useState(0);
  const backendStage = Number(live?.activeStage);
  const hasBackendStage = Number.isInteger(backendStage) && backendStage >= 1 && backendStage <= 10;
  const ready = isLiveSessionReady(live);
  const active=live
    ? hasBackendStage ? backendStage - 1 : ready || ['LOADING_RESULTS', 'RESULTS_ERROR'].includes(live.stage) ? 9 : 0
    : complete ? 9 : running || paused ? Math.max(0,Math.min(phase-1,9)) : selected;
  const step=scanGuide[active];
  const previous=active>0 ? scanGuide[active-1] : null;
  const next=active<9 ? scanGuide[active+1] : null;
  const liveCounts = ready ? live.counts : null;
  const statusText=(index)=> live
    ? backendStageStatus(index, live)
    : complete || (running || paused) && index<phase-1
      ? 'Hoàn tất'
      : running && index===phase-1 ? 'Đang thực hiện' : 'Chưa chạy';

  return (
    <section className="guided-scan" id="scan-simulation" aria-live="polite">
      <header className="guided-heading">
        <div>
          {live ? <span className="guided-eyebrow"><i /> TRỰC QUAN HÓA PIPELINE · LIVE</span> : (
          <span className="guided-eyebrow"><i /> MÔ PHỎNG TRÌNH BÀY PIPELINE</span>
          )}
          <h2>Phân tích theo từng bước</h2>
          <p>Quan sát lần lượt đầu vào, xử lý và đầu ra của từng chặng.</p>
        </div>
        <div className="guided-actions">
          {live ? <span className="sim-badge">TRỰC QUAN HÓA KIẾN TRÚC</span> : (
          <span className="sim-badge">DỮ LIỆU MINH HỌA</span>
          )}
          {!live && (<>
          {running && <button onClick={onPause}><Icon name="Pause" />Tạm dừng</button>}
          {paused && <button onClick={onResume}><Icon name="Play" />Tiếp tục</button>}
          {(complete || elapsedMs>0) && <button onClick={onReplay}><Icon name="RotateCcw" />Phát lại</button>}
          </>)}
        </div>
      </header>
      {live?.interrupted && <div className="inline-warning" role="status"><Icon name="AlertTriangle" />Gián đoạn kết nối - đang hiển thị trạng thái đã xác minh gần nhất.</div>}

      <div className="guided-layout">
        <nav className="guided-stepper" aria-label="Các bước mô phỏng">
          <div className="stepper-heading"><b>CÁC BƯỚC PHÂN TÍCH</b><span>10 chặng</span></div>
          {scanGuide.map((item,index)=> (
            <button
              key={item.title}
              className={`guided-step ${index===active && (!live || hasBackendStage || ready || live.stage==='LOADING_RESULTS') ? 'active' : ''} ${(statusText(index)==='Hoàn tất' || statusText(index).startsWith('Hoàn thành')) ? 'done' : ''}`}
              onClick={()=> !live && !running && !paused && !complete && setSelected(index)}
              disabled={Boolean(live) || running || paused || complete}
              aria-current={index===active && (!live || hasBackendStage || ready || live.stage==='LOADING_RESULTS') ? 'step' : undefined}
            >
              <span className="guided-step-number">{(statusText(index)==='Hoàn tất' || statusText(index).startsWith('Hoàn thành')) ? <Icon name="Check" /> : String(index+1).padStart(2,'0')}</span>
              <span className="guided-step-copy"><b>{item.title}</b><small>{statusText(index)}</small></span>
            </button>
          ))}
        </nav>

        <div className="guided-main">
          <div className="guided-status-row">
            {live ? <span><i className={ready ? 'complete' : running ? 'pulse' : ''} />{live.stage === 'RUNNING' && active===9 && backendStageStatus(9,live).startsWith('Đang') ? 'ĐANG HOÀN TẤT PHIÊN' : LIVE_STATUS[live.stage] || live.state || 'SẴN SÀNG'}</span> : (
            <span><i className={running ? 'pulse' : complete ? 'complete' : ''} />{complete ? 'DEMO HOÀN TẤT' : running ? `ĐANG THỰC HIỆN · ${String(active+1).padStart(2,'0')} / 10` : paused ? 'ĐÃ TẠM DỪNG' : 'SẴN SÀNG TRÌNH DIỄN'}</span>
            )}
            <b>{formatDuration(elapsedMs)}</b>
          </div>
          <ScanStageVisual step={step} index={active} previous={previous} next={next} live={Boolean(live)} liveCounts={liveCounts} />
          {!live && (
          <div className="guided-progress">
            <span style={{width: `${complete ? 100 : running ? (phase/10)*100 : ((active+1)/10)*100}%`}} />
          </div>
          )}
          <div className="guided-phase-footer">
            {live ? <span>Thời gian thực tại trình duyệt</span> : (
            <span>Thời gian trình diễn mô phỏng</span>
            )}
            {live ? <span>{liveCounts ? `${liveCounts.total} ứng viên · ${liveCounts.report} / ${liveCounts.review} / ${liveCounts.suppress}` : hasBackendStage ? `Backend active_stage: ${backendStage}` : 'Backend chưa báo active_stage'}</span> : (
            <span>{complete ? '10 / 10 bước' : `${active+1} / 10 bước`}</span>
            )}
          </div>
        </div>

        <aside className="guided-explanation">
          <div className="explanation-step"><span>{String(active+1).padStart(2,'0')}</span><small>GIẢI THÍCH BƯỚC</small></div>
          <h3>{step.title}</h3>
          <p className="explanation-purpose">{step.purpose}</p>
          <InfoRow title="Đầu vào" text={step.input} icon="LogIn" />
          <InfoRow title="Xử lý chính" text={step.process} icon="Settings2" />
          <InfoRow title="Đầu ra" text={step.output} icon="LogOut" />
          <div className="pipeline-meaning"><Icon name="Lightbulb" /><p>{step.meaning}</p></div>
        </aside>
      </div>

      {!live && (
      <div className="phase-duration-list">
        {scanGuide.map((item,index)=> {
          const duration=phaseDurations[index];
          const completed=complete || (running || paused) && index<phase-1;
          const current=running && index===phase-1;
          return <div key={item.title} className={`duration-item ${completed ? 'done' : ''} ${current ? 'current' : ''}`}>
            <span>{String(index+1).padStart(2,'0')}</span>
            <b>{item.title}</b>
            <small>{duration ? formatDuration(duration) : current ? 'Đang thực hiện' : 'Chưa chạy'}</small>
          </div>;
        })}
      </div>
      )}
      {live ? <p className="guided-disclaimer">{LIVE_NOTICE}</p> : (
      <p className="guided-disclaimer">Đây là mô phỏng trực quan. Thời gian thể hiện thời lượng trình diễn, không phải thời gian thực thi OpenGrep, IRIS hoặc mô hình. Kết quả thực chỉ xuất hiện từ backend.</p>
      )}
    </section>
  );
}

function InfoRow({title,text,icon}) {
  return <div className="guided-info-row"><span><Icon name={icon} /></span><div><b>{title}</b><p>{text}</p></div></div>;
}

function formatDuration(milliseconds) {
  const seconds=Math.max(0,milliseconds || 0)/1000;
  const minutes=Math.floor(seconds/60);
  return `${String(minutes).padStart(2,'0')}:${(seconds-minutes*60).toFixed(2).padStart(5,'0')}`;
}