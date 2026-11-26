import {Badge, Icon} from '../common/Ui';
import {resolveStage05CitationTelemetry} from './liveStagePresentation';
import {
  Easing,
  TIMELINE_FPS,
  TIMELINE_MODES,
  formatDurationMs,
  interpolate,
  spring,
} from './remotionEngine';

const TOTAL_STAGES = 6;

function safeNumber(value) {
  if (value === null || value === undefined || value === '' || typeof value === 'boolean') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function stageToneFromCat(cat) {
  if (cat === 'COMPLETED') return 'green';
  if (cat === 'FAILED') return 'red';
  if (cat === 'SKIPPED' || cat === 'DEGRADED' || cat === 'CANCELLED') return 'amber';
  if (cat === 'RUNNING') return 'blue';
  return 'neutral';
}

/* ============================================================================
   6 Bespoke Remotion-Driven 3D Isometric Stage Scenes
   All coordinates, camera tilt, particle packets, and chart bars are driven
   deterministically by (localFrame, cycleFrame, localProgress) via spring()
   and interpolate().
   ============================================================================ */

function Stage01Intake3D({localFrame, cycle, stage, mode, reducedMotion}) {
  const enter = reducedMotion ? 1 : spring({frame: localFrame, fps: TIMELINE_FPS, config: {damping: 15, stiffness: 115}});
  const card1 = reducedMotion ? 1 : spring({frame: localFrame, delay: 8, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 120}});
  const card2 = reducedMotion ? 1 : spring({frame: localFrame, delay: 16, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 120}});
  const card3 = reducedMotion ? 1 : spring({frame: localFrame, delay: 24, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 120}});
  const sweep = reducedMotion ? 0.62 : (cycle % 1);
  const gateX = interpolate(sweep, [0, 0.5, 1], [156, 252, 156], {easing: Easing.easeInOutSine});
  const pulse = reducedMotion ? 0.8 : 0.45 + 0.55 * Math.sin(cycle * Math.PI * 2);
  const meta = stage?.summary || {};
  const isPreview = mode === TIMELINE_MODES.PREVIEW;
  const modeLabel = meta.input_mode === 'ZIP' ? 'ZIP ARCHIVE' : 'GITHUB / ZIP';
  const javaCount = safeNumber(meta.java_files_count);

  const cards = isPreview
    ? [
        {name: 'FileServlet.java', badge: 'MINH HỌA · PATH', y: 40, x: 266, s: card1},
        {name: 'UserDao.java', badge: 'MINH HỌA · SYMLINK', y: 92, x: 274, s: card2},
        {name: 'AuthFilter.java', badge: 'MINH HỌA · SIZE', y: 144, x: 266, s: card3},
      ]
    : [
        {name: 'Kiểm tra đường dẫn', badge: stage?.cat === 'COMPLETED' ? 'HOÀN TẤT BƯỚC 01' : 'THEO TRẠNG THÁI API', y: 40, x: 266, s: card1},
        {name: 'Chặn symlink / vượt cấp', badge: 'CHÍNH SÁCH SANDBOX', y: 92, x: 274, s: card2},
        {name: 'Inventory .java', badge: javaCount !== null ? `${javaCount} TỆP TỪ API` : 'CHƯA CÓ SỐ LIỆU', y: 144, x: 266, s: card3},
      ];

  return (
    <div
      className="v2-rm-3d-rig"
      style={{
        transform: `rotateX(${interpolate(enter, [0, 1], [18, 9])}deg) rotateY(${interpolate(enter, [0, 1], [-18, -7])}deg) scale(${interpolate(enter, [0, 1], [0.92, 1])})`,
        opacity: interpolate(enter, [0, 0.6], [0.55, 1]),
      }}
    >
      <svg className="v2-rm-scene-svg" viewBox="0 0 420 230" role="img" aria-label="Sơ đồ giai đoạn tiếp nhận và kiểm tra an toàn mã nguồn Java">
        <defs>
          <linearGradient id="rm01-beam" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#DDE0E6" stopOpacity="0" />
            <stop offset="50%" stopColor="#F5F5F6" stopOpacity="0.85" />
            <stop offset="100%" stopColor="#DDE0E6" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="rm01-card" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#252936" />
            <stop offset="100%" stopColor="#13161E" />
          </linearGradient>
        </defs>

        {/* Isometric floor grid */}
        <g opacity="0.28" stroke="#9EA4B3" strokeWidth="0.7">
          <path d="M24 198 L210 156 L396 198 L210 226 Z" fill="rgba(255,255,255,0.02)" />
          <line x1="86" y1="184" x2="272" y2="212" />
          <line x1="148" y1="170" x2="334" y2="198" />
          <line x1="148" y1="212" x2="334" y2="184" />
        </g>

        {/* Left 3D Source Vault */}
        <g transform={`translate(24, ${interpolate(enter, [0, 1], [68, 56])})`}>
          <rect x="0" y="0" width="112" height="106" rx="12" fill="url(#rm01-card)" stroke="rgba(221,224,230,0.28)" strokeWidth="1.2" />
          <rect x="12" y="14" width="66" height="15" rx="4" fill="rgba(255,255,255,0.07)" />
          <text x="18" y="24.5" fill="#B4B7BE" fontSize="8" fontFamily="monospace" fontWeight="600">{modeLabel}</text>
          <rect x="12" y="40" width="88" height="7" rx="3.5" fill="rgba(245,245,246,0.22)" />
          <rect x="12" y="54" width="68" height="6" rx="3" fill="rgba(180,183,190,0.16)" />
          <rect x="12" y="67" width="76" height="6" rx="3" fill="rgba(180,183,190,0.12)" />
          <circle cx="94" cy="90" r="4" fill="#8CB4E0" opacity={pulse} />
          <text x="12" y="93" fill="#8A8E99" fontSize="8" fontFamily="monospace">{isPreview ? 'MINH HỌA SANDBOX' : 'SANDBOX ISOLATED'}</text>
        </g>

        {/* Dataflow rail from Vault through Safety Gate */}
        <path d="M136 108 H258" stroke="rgba(221,224,230,0.28)" strokeWidth="1.5" strokeDasharray="4 4" />
        <circle
          cx={interpolate(sweep, [0, 1], [142, 254])}
          cy="108"
          r="3.8"
          fill="#F5F5F6"
        />

        {/* Animated Security Gate Plane */}
        <g transform={`translate(${gateX}, 30)`}>
          <rect x="-2" y="0" width="4" height="152" rx="2" fill="url(#rm01-beam)" opacity="0.9" />
          <rect x="-34" y="-6" width="68" height="18" rx="6" fill="#171A23" stroke="rgba(245,245,246,0.34)" strokeWidth="1" />
          <text x="0" y="6" textAnchor="middle" fill="#F5F5F6" fontSize="7.5" fontFamily="monospace" fontWeight="700">SAFETY GATE</text>
        </g>

        {/* 3 Stacked Floating Java File Cards */}
        {cards.map((f) => (
          <g
            key={f.name}
            transform={`translate(${interpolate(f.s, [0, 1], [f.x + 28, f.x])}, ${f.y})`}
            opacity={interpolate(f.s, [0, 0.7], [0, 1])}
          >
            <rect x="0" y="0" width="128" height="40" rx="9" fill="url(#rm01-card)" stroke="rgba(221,224,230,0.24)" strokeWidth="1.1" />
            <circle cx="14" cy="20" r="4.5" fill="rgba(140,180,224,0.18)" stroke="#8CB4E0" strokeWidth="1.2" />
            <text x="26" y="17" fill="#F5F5F6" fontSize="8.8" fontFamily="monospace" fontWeight="600">{f.name}</text>
            <text x="26" y="30" fill="#B4B7BE" fontSize="7.2" fontFamily="monospace">{f.badge}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}

function Stage02OpenGrep3D({localFrame, cycle, stage, mode, reducedMotion}) {
  const enter = reducedMotion ? 1 : spring({frame: localFrame, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 120}});
  const sweep = reducedMotion ? 0.55 : (cycle % 1);
  const laserY = interpolate(sweep, [0, 0.5, 1], [44, 152, 44], {easing: Easing.easeInOutSine});
  const hit1 = Math.abs(laserY - 82) < 20 ? 1 : 0.45;
  const hit2 = Math.abs(laserY - 126) < 20 ? 1 : 0.45;
  const manifestEnter = reducedMotion ? 1 : spring({frame: localFrame, delay: 20, fps: TIMELINE_FPS, config: {damping: 15, stiffness: 110}});
  const isPreview = mode === TIMELINE_MODES.PREVIEW;
  const manifestLabel = isPreview
    ? 'MINH HỌA MANIFEST'
    : stage?.cat === 'COMPLETED' || stage?.cat === 'DEGRADED'
      ? 'ĐÃ GHI MANIFEST'
      : stage?.cat === 'RUNNING'
        ? 'ĐANG QUÉT TĨNH…'
        : 'CHƯA CÓ TELEMETRY';

  return (
    <div
      className="v2-rm-3d-rig"
      style={{
        transform: `rotateX(${interpolate(enter, [0, 1], [16, 8])}deg) rotateY(${interpolate(enter, [0, 1], [14, 5])}deg) scale(${interpolate(enter, [0, 1], [0.93, 1])})`,
        opacity: interpolate(enter, [0, 0.6], [0.55, 1]),
      }}
    >
      <svg className="v2-rm-scene-svg" viewBox="0 0 420 230" role="img" aria-label="Sơ đồ giai đoạn quét tĩnh OpenGrep CWE-22 và CWE-89">
        <defs>
          <linearGradient id="rm02-laser" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#F5F5F6" stopOpacity="0" />
            <stop offset="50%" stopColor="#F5F5F6" stopOpacity="0.92" />
            <stop offset="100%" stopColor="#8CB4E0" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="rm02-slab" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#232734" />
            <stop offset="100%" stopColor="#12141C" />
          </linearGradient>
        </defs>

        {/* Shadow back code slab for 3D depth */}
        <rect x="44" y="34" width="212" height="156" rx="12" fill="#0F1118" stroke="rgba(221,224,230,0.12)" />

        {/* Foreground AST/Java Code Slab */}
        <rect x="30" y="24" width="212" height="156" rx="12" fill="url(#rm02-slab)" stroke="rgba(221,224,230,0.28)" strokeWidth="1.2" />
        <text x="44" y="42" fill="#8A8E99" fontSize="8" fontFamily="monospace">OPENGREP ENGINE · RULESET YAML</text>

        {/* Simulated Java code lines */}
        {[58, 70, 82, 94, 106, 118, 126, 140, 154].map((y, idx) => {
          const isCwe22 = y === 82;
          const isCwe89 = y === 126;
          const barW = [110, 146, 168, 92, 134, 120, 174, 102, 86][idx];
          return (
            <g key={y}>
              <text x="42" y={y + 4} fill="#5E6370" fontSize="7.5" fontFamily="monospace">{String(12 + idx * 5).padStart(2, '0')}</text>
              <rect
                x="60"
                y={y - 3}
                width={barW}
                height="6.5"
                rx="3"
                fill={isCwe22 ? 'rgba(223,142,149,0.52)' : isCwe89 ? 'rgba(226,197,147,0.48)' : 'rgba(221,224,230,0.14)'}
              />
              {isCwe22 && (
                <g opacity={hit1}>
                  <circle cx="226" cy={y} r="5.5" fill="rgba(223,142,149,0.22)" stroke="#DF8E95" strokeWidth="1.2" />
                </g>
              )}
              {isCwe89 && (
                <g opacity={hit2}>
                  <circle cx="226" cy={y} r="5.5" fill="rgba(226,197,147,0.22)" stroke="#E2C593" strokeWidth="1.2" />
                </g>
              )}
            </g>
          );
        })}

        {/* Moving OpenGrep Laser Sweep */}
        <g transform={`translate(26, ${laserY})`}>
          <rect x="0" y="-9" width="220" height="18" fill="url(#rm02-laser)" opacity="0.28" />
          <line x1="0" y1="0" x2="220" y2="0" stroke="#F5F5F6" strokeWidth="1.8" />
        </g>

        {/* Right Floating Candidate Cards + scan-manifest.json */}
        <g
          transform={`translate(${interpolate(manifestEnter, [0, 1], [292, 268])}, 28)`}
          opacity={interpolate(manifestEnter, [0, 0.7], [0, 1])}
        >
          <rect x="0" y="0" width="126" height="46" rx="9" fill="url(#rm02-slab)" stroke={hit1 > 0.8 ? '#DF8E95' : 'rgba(223,142,149,0.35)'} strokeWidth="1.2" />
          <text x="12" y="18" fill="#DF8E95" fontSize="9" fontFamily="monospace" fontWeight="700">CWE-22 SCOPE</text>
          <text x="12" y="33" fill="#B4B7BE" fontSize="8" fontFamily="monospace">Path Traversal Sink</text>

          <rect x="0" y="58" width="126" height="46" rx="9" fill="url(#rm02-slab)" stroke={hit2 > 0.8 ? '#E2C593' : 'rgba(226,197,147,0.35)'} strokeWidth="1.2" />
          <text x="12" y="76" fill="#E2C593" fontSize="9" fontFamily="monospace" fontWeight="700">CWE-89 SCOPE</text>
          <text x="12" y="91" fill="#B4B7BE" fontSize="8" fontFamily="monospace">SQL Injection Sink</text>

          <rect x="0" y="116" width="126" height="54" rx="9" fill="#141720" stroke="rgba(221,224,230,0.28)" strokeWidth="1.1" />
          <text x="12" y="133" fill="#F5F5F6" fontSize="8.5" fontFamily="monospace" fontWeight="600">scan-manifest.json</text>
          <text x="12" y="147" fill="#B4B7BE" fontSize="7.3" fontFamily="monospace">{manifestLabel}</text>
          <text x="12" y="160" fill="#8A8E99" fontSize="7.2" fontFamily="monospace">SHA-256 PROVENANCE</text>
        </g>

        {/* Connector trails */}
        <path d="M242 82 H268 M242 126 H268" stroke="rgba(221,224,230,0.3)" strokeWidth="1.2" strokeDasharray="3 3" />
      </svg>
    </div>
  );
}

function Stage03Evidence3D({localFrame, cycle, stage, mode, reducedMotion}) {
  const enter = reducedMotion ? 1 : spring({frame: localFrame, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 118}});
  const trace = reducedMotion ? 0.72 : (cycle % 1);
  const dotX = interpolate(trace, [0, 1], [66, 354], {easing: Easing.easeInOutCubic});
  const dotY = 118 - Math.sin(trace * Math.PI) * 34;
  const isPreview = mode === TIMELINE_MODES.PREVIEW;
  const meta = stage?.summary && typeof stage.summary === 'object' ? stage.summary : {};
  const realHash = typeof meta.scan_sha256 === 'string' && meta.scan_sha256.trim() ? meta.scan_sha256.trim() : '';
  const hashStripText = isPreview
    ? 'MINH HỌA: SHA-256 tệp nguồn Java được chụp lúc quét'
    : realHash
      ? `scan_sha256: ${realHash.slice(0, 24)}…`
      : stage?.cat === 'RUNNING'
        ? 'Đang trích xuất ngữ cảnh AST & chụp mã băm SHA-256…'
        : 'SHA-256 chi tiết hiển thị ở từng cảnh báo từ API';
  const sealText = isPreview
    ? 'PREVIEW'
    : realHash
      ? 'RECORDED'
      : stage?.cat === 'RUNNING'
        ? 'RUNNING'
        : 'API DATA';

  return (
    <div
      className="v2-rm-3d-rig"
      style={{
        transform: `rotateX(${interpolate(enter, [0, 1], [15, 7])}deg) rotateY(${interpolate(enter, [0, 1], [-14, -5])}deg) scale(${interpolate(enter, [0, 1], [0.93, 1])})`,
        opacity: interpolate(enter, [0, 0.6], [0.55, 1]),
      }}
    >
      <svg className="v2-rm-scene-svg" viewBox="0 0 420 230" role="img" aria-label="Sơ đồ giai đoạn trích xuất bằng chứng AST và băm SHA-256">
        <defs>
          <linearGradient id="rm03-card" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#242834" />
            <stop offset="100%" stopColor="#12141B" />
          </linearGradient>
        </defs>

        {/* 3D Layered Taint Trace Nodes: Source -> Intermediate -> Sink */}
        <path
          d="M66 118 Q210 50 354 118"
          fill="none"
          stroke="rgba(221,224,230,0.24)"
          strokeWidth="1.8"
          strokeDasharray="5 5"
        />
        <circle cx={dotX} cy={dotY} r="4.5" fill="#F5F5F6" />

        {[
          {x: 24, y: 78, tag: 'SOURCE', title: 'Đầu vào nguồn', accent: '#8CB4E0'},
          {x: 152, y: 42, tag: 'AST CONTEXT', title: 'Method Scope + Vars', accent: '#DDE0E6'},
          {x: 280, y: 78, tag: 'SINK', title: 'Điểm thực thi nhạy cảm', accent: '#DF8E95'},
        ].map((node, i) => {
          const s = reducedMotion ? 1 : spring({frame: localFrame, delay: i * 10, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 120}});
          return (
            <g
              key={node.tag}
              transform={`translate(${node.x}, ${interpolate(s, [0, 1], [node.y + 16, node.y])})`}
              opacity={interpolate(s, [0, 0.7], [0, 1])}
            >
              <rect x="0" y="0" width="116" height="62" rx="10" fill="url(#rm03-card)" stroke="rgba(221,224,230,0.24)" strokeWidth="1.1" />
              <circle cx="14" cy="18" r="3.5" fill={node.accent} />
              <text x="23" y="21" fill={node.accent} fontSize="8" fontFamily="monospace" fontWeight="700">{node.tag}</text>
              <text x="12" y="42" fill="#F5F5F6" fontSize="8.2" fontFamily="monospace">{node.title}</text>
              <rect x="12" y="50" width="82" height="3.5" rx="2" fill="rgba(255,255,255,0.12)" />
            </g>
          );
        })}

        {/* Bottom SHA-256 Immutable Evidence Strip */}
        <g transform="translate(36, 162)">
          <rect x="0" y="0" width="348" height="44" rx="10" fill="#13161E" stroke="rgba(221,224,230,0.28)" strokeWidth="1.1" />
          <text x="14" y="17" fill="#B4B7BE" fontSize="7.8" fontFamily="monospace" fontWeight="600">EVIDENCE SNAPSHOT · SHA-256 INTEGRITY</text>
          <text x="14" y="33" fill="#DDE0E6" fontSize="8" fontFamily="monospace">{hashStripText}</text>
          <rect x="284" y="12" width="52" height="20" rx="5" fill="rgba(255,255,255,0.06)" stroke="rgba(221,224,230,0.28)" />
          <text x="310" y="25" textAnchor="middle" fill="#DDE0E6" fontSize="7.5" fontFamily="monospace" fontWeight="700">{sealText}</text>
        </g>
      </svg>
    </div>
  );
}

function Stage04Qwen3D({localFrame, cycle, noLlm, stage, reducedMotion}) {
  const enter = reducedMotion ? 1 : spring({frame: localFrame, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 115}});
  const skipped = noLlm || stage?.cat === 'SKIPPED';
  const pulse = reducedMotion ? 0.7 : (cycle % 1);

  const nodesL = [82, 126, 170];
  const nodesM = [74, 108, 142, 176];
  const nodesR = [92, 126, 160];

  return (
    <div
      className="v2-rm-3d-rig"
      style={{
        transform: `rotateX(${interpolate(enter, [0, 1], [15, 7])}deg) rotateY(${interpolate(enter, [0, 1], [12, 4])}deg) scale(${interpolate(enter, [0, 1], [0.93, 1])})`,
        opacity: interpolate(enter, [0, 0.6], [0.55, 1]),
      }}
    >
      <svg className="v2-rm-scene-svg" viewBox="0 0 420 230" role="img" aria-label="Mô phỏng 3D suy luận Qwen3.5-9B cục bộ qua Ollama">
        <defs>
          <linearGradient id="rm04-box" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#252936" />
            <stop offset="100%" stopColor="#12141B" />
          </linearGradient>
        </defs>

        {/* Left Blind Evidence Card */}
        <rect x="20" y="34" width="96" height="162" rx="11" fill="url(#rm04-box)" stroke="rgba(221,224,230,0.22)" />
        <text x="68" y="54" textAnchor="middle" fill="#B4B7BE" fontSize="8" fontFamily="monospace" fontWeight="700">BLIND INPUT</text>
        {nodesL.map((y, idx) => (
          <g key={y}>
            <rect x="30" y={y - 11} width="76" height="22" rx="6" fill="rgba(255,255,255,0.04)" stroke="rgba(221,224,230,0.14)" />
            <text x="68" y={y + 3} textAnchor="middle" fill="#DDE0E6" fontSize="7.5" fontFamily="monospace">
              {['Snippet', 'Trace', 'AST Scope'][idx]}
            </text>
          </g>
        ))}

        {/* Center Local Ollama Qwen3.5-9B Neural Matrix */}
        <rect
          x="138"
          y="22"
          width="144"
          height="186"
          rx="13"
          fill="url(#rm04-box)"
          stroke={skipped ? 'rgba(226,197,147,0.45)' : 'rgba(245,245,246,0.34)'}
          strokeWidth="1.3"
        />
        <text x="210" y="40" textAnchor="middle" fill="#F5F5F6" fontSize="9.5" fontFamily="monospace" fontWeight="700">
          Qwen3.5-9B · OLLAMA
        </text>
        <text x="210" y="53" textAnchor="middle" fill={skipped ? '#E2C593' : '#65B48C'} fontSize="7.2" fontFamily="monospace">
          {skipped ? 'BYPASSED (NO_LLM MODE)' : 'LOCAL INFERENCE · ZERO CLOUD'}
        </text>

        {/* Attention synapse edges */}
        {!skipped && nodesL.map((y1, i) => (
          nodesM.map((y2, j) => {
            const activeEdge = ((i + j) % 3 === Math.floor(pulse * 3));
            return (
              <line
                key={`${i}-${j}`}
                x1="166"
                y1={y1}
                x2="210"
                y2={y2}
                stroke={activeEdge ? '#F5F5F6' : 'rgba(221,224,230,0.16)'}
                strokeWidth={activeEdge ? '1.35' : '0.8'}
              />
            );
          })
        ))}
        {!skipped && nodesM.map((y1, i) => (
          nodesR.map((y2, j) => {
            const activeEdge = ((i + j + 1) % 3 === Math.floor(pulse * 3));
            return (
              <line
                key={`r-${i}-${j}`}
                x1="210"
                y1={y1}
                x2="254"
                y2={y2}
                stroke={activeEdge ? '#DDE0E6' : 'rgba(221,224,230,0.14)'}
                strokeWidth={activeEdge ? '1.3' : '0.8'}
              />
            );
          })
        ))}

        {/* Matrix neurons */}
        {!skipped ? (
          <>
            {nodesL.map((y) => <circle key={`nl-${y}`} cx="166" cy={y} r="4" fill="#171A23" stroke="#DDE0E6" strokeWidth="1.3" />)}
            {nodesM.map((y, idx) => (
              <circle
                key={`nm-${y}`}
                cx="210"
                cy={y}
                r="4.5"
                fill={idx === Math.floor(pulse * 4) ? '#F5F5F6' : '#232735'}
                stroke="#F5F5F6"
                strokeWidth="1.2"
              />
            ))}
            {nodesR.map((y) => <circle key={`nr-${y}`} cx="254" cy={y} r="4" fill="#171A23" stroke="#DDE0E6" strokeWidth="1.3" />)}
          </>
        ) : (
          <g>
            <path d="M158 118 H262" stroke="#E2C593" strokeWidth="2" strokeDasharray="5 4" />
            <rect x="164" y="100" width="92" height="36" rx="8" fill="rgba(226,197,147,0.12)" stroke="rgba(226,197,147,0.45)" />
            <text x="210" y="121" textAnchor="middle" fill="#E2C593" fontSize="8.5" fontFamily="monospace" fontWeight="700">CHẾ ĐỘ ĐỐI CHỨNG</text>
          </g>
        )}

        {/* Right Structured JSON Proposals */}
        <g transform="translate(302, 42)">
          {[
            {label: 'SUPPORTED', y: 0, color: '#DF8E95', dim: skipped},
            {label: 'REFUTED', y: 50, color: '#E2C593', dim: skipped},
            {label: 'UNDETERMINED', y: 100, color: '#DDE0E6', dim: false},
          ].map((out) => (
            <g key={out.label} opacity={out.dim ? 0.32 : 1}>
              <rect x="0" y={out.y} width="98" height="38" rx="8" fill="url(#rm04-box)" stroke="rgba(221,224,230,0.22)" />
              <circle cx="13" cy={out.y + 19} r="3.5" fill={out.color} />
              <text x="23" y={out.y + 22} fill={out.color} fontSize="7.8" fontFamily="monospace" fontWeight="700">{out.label}</text>
            </g>
          ))}
        </g>

        <path d="M116 114 H138 M282 114 H302" stroke="rgba(245,245,246,0.42)" strokeWidth="1.4" />
      </svg>
    </div>
  );
}

function citationBadgePalette(tone) {
  if (tone === 'green') {
    return {
      stroke: '#65B48C',
      boxStroke: 'rgba(101,180,140,0.45)',
      fill: 'rgba(22,36,30,0.96)',
      text: '#65B48C',
      lineWidth: '1.6',
      dash: undefined,
    };
  }
  if (tone === 'red') {
    return {
      stroke: '#DF8E95',
      boxStroke: 'rgba(223,142,149,0.5)',
      fill: 'rgba(42,20,24,0.96)',
      text: '#DF8E95',
      lineWidth: '1.5',
      dash: undefined,
    };
  }
  if (tone === 'amber') {
    return {
      stroke: '#E2C593',
      boxStroke: 'rgba(226,197,147,0.48)',
      fill: 'rgba(40,32,18,0.96)',
      text: '#E2C593',
      lineWidth: '1.4',
      dash: '4 3',
    };
  }
  if (tone === 'blue') {
    return {
      stroke: '#8CB4E0',
      boxStroke: 'rgba(140,180,224,0.42)',
      fill: 'rgba(20,28,40,0.96)',
      text: '#8CB4E0',
      lineWidth: '1.3',
      dash: '4 3',
    };
  }
  return {
    stroke: 'rgba(221,224,230,0.2)',
    boxStroke: 'rgba(255,255,255,0.12)',
    fill: '#141720',
    text: '#8A8E99',
    lineWidth: '1',
    dash: '4 4',
  };
}

function Stage05Citation3D({localFrame, mode, stage, liveCounts, reducedMotion}) {
  const enter = reducedMotion ? 1 : spring({frame: localFrame, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 120}});
  // Strictly separate real backend citation evidence from UI animation or prefers-reduced-motion.
  const telemetry = resolveStage05CitationTelemetry({mode, stage, liveCounts});

  return (
    <div
      className="v2-rm-3d-rig"
      data-citation-telemetry-status={telemetry.aggregateStatus}
      style={{
        transform: `rotateX(${interpolate(enter, [0, 1], [15, 7])}deg) rotateY(${interpolate(enter, [0, 1], [-12, -4])}deg) scale(${interpolate(enter, [0, 1], [0.93, 1])})`,
        opacity: interpolate(enter, [0, 0.6], [0.55, 1]),
      }}
    >
      <svg className="v2-rm-scene-svg" viewBox="0 0 420 230" role="img" aria-label="Đối chiếu trích dẫn mã nguồn thật và SHA-256 theo dữ liệu API">
        <defs>
          <linearGradient id="rm05-pane" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#242834" />
            <stop offset="100%" stopColor="#12141B" />
          </linearGradient>
        </defs>

        {/* Left Plane: Model Citation */}
        <rect x="20" y="34" width="124" height="160" rx="11" fill="url(#rm05-pane)" stroke="rgba(221,224,230,0.24)" />
        <text x="82" y="53" textAnchor="middle" fill="#B4B7BE" fontSize="8" fontFamily="monospace" fontWeight="700">MODEL CITATION</text>

        {/* Right Plane: Original Source Snapshot */}
        <rect x="276" y="34" width="124" height="160" rx="11" fill="url(#rm05-pane)" stroke="rgba(221,224,230,0.24)" />
        <text x="338" y="53" textAnchor="middle" fill="#B4B7BE" fontSize="8" fontFamily="monospace" fontWeight="700">JAVA SNAPSHOT</text>

        {/* Verification Check Rows strictly backed by API telemetry */}
        {telemetry.checks.map((item) => {
          const pal = citationBadgePalette(item.tone);
          return (
            <g key={item.key} data-citation-check={item.key} data-citation-status={item.status}>
              <rect x="30" y={item.y - 10} width="104" height="20" rx="5" fill="rgba(255,255,255,0.04)" stroke={pal.boxStroke} />
              <text x="40" y={item.y + 3} fill="#DDE0E6" fontSize="8" fontFamily="monospace">{item.label}</text>

              <rect x="286" y={item.y - 10} width="104" height="20" rx="5" fill="rgba(255,255,255,0.04)" stroke={pal.boxStroke} />
              <text x="296" y={item.y + 3} fill="#DDE0E6" fontSize="8" fontFamily="monospace">{item.label} REAL</text>

              <line
                x1="134"
                y1={item.y}
                x2="286"
                y2={item.y}
                stroke={pal.stroke}
                strokeWidth={pal.lineWidth}
                strokeDasharray={pal.dash}
              />
              <rect
                x="164"
                y={item.y - 9}
                width="92"
                height="18"
                rx="9"
                fill={pal.fill}
                stroke={pal.stroke}
              />
              <text x="210" y={item.y + 3} textAnchor="middle" fill={pal.text} fontSize="6.9" fontFamily="monospace" fontWeight="700">
                {item.badgeText}
              </text>
            </g>
          );
        })}

        {/* Guardrail footer callout */}
        <text x="210" y="212" textAnchor="middle" fill="#8A8E99" fontSize="7.6" fontFamily="monospace">
          {telemetry.isIllustrative
            ? 'MINH HỌA PREVIEW · THIẾU BẰNG CHỨNG → HẠ CẤP UNDETERMINED'
            : telemetry.aggregateStatus === 'CONFLICT'
              ? 'MÂU THUẪN DỮ LIỆU CITATION TỪ API · KHÔNG KẾT LUẬN ALL_MATCHED'
              : telemetry.aggregateStatus === 'MALFORMED'
                ? 'DỮ LIỆU CITATION SAI ĐỊNH DẠNG · KHÔNG TỰ SUY DIỄN MATCH'
                : telemetry.aggregateStatus === 'PARTIAL'
                  ? 'DỮ LIỆU CITATION CHƯA ĐẦY ĐỦ · CHƯA ĐỦ BẰNG CHỨNG ALL_MATCHED'
                  : telemetry.hasBackendEvidence
                    ? 'TỔNG HỢP THEO API · ĐỐI CHIẾU TỪNG FINDING Ở DANH SÁCH CẢNH BÁO'
                    : 'CHƯA CÓ BẰNG CHỨNG CITATION TỪ API · KHÔNG TỰ SUY DIỄN MATCH'}
        </text>
      </svg>
    </div>
  );
}

function Stage06Store3D({localFrame, cycle, liveCounts, reducedMotion}) {
  const enter = reducedMotion ? 1 : spring({frame: localFrame, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 118}});
  const packet = reducedMotion ? 0.65 : (cycle % 1);
  const packetX = interpolate(packet, [0, 1], [164, 246], {easing: Easing.easeInOutCubic});

  return (
    <div
      className="v2-rm-3d-rig"
      style={{
        transform: `rotateX(${interpolate(enter, [0, 1], [15, 7])}deg) rotateY(${interpolate(enter, [0, 1], [12, 4])}deg) scale(${interpolate(enter, [0, 1], [0.93, 1])})`,
        opacity: interpolate(enter, [0, 0.6], [0.55, 1]),
      }}
    >
      <svg className="v2-rm-scene-svg" viewBox="0 0 420 230" role="img" aria-label="Mô phỏng 3D khởi tạo hàng đợi Human Review trên SQLite">
        <defs>
          <linearGradient id="rm06-cyl" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#1B1F2B" />
            <stop offset="50%" stopColor="#2B3040" />
            <stop offset="100%" stopColor="#151822" />
          </linearGradient>
          <linearGradient id="rm06-card" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#242835" />
            <stop offset="100%" stopColor="#12141B" />
          </linearGradient>
        </defs>

        {/* Left Isometric 3D SQLite Stacked Disks */}
        <g transform="translate(36, 42)">
          {[96, 56, 16].map((y, idx) => (
            <g key={y}>
              <path d={`M0 ${y} v24 a62 16 0 0 0 124 0 v-24 z`} fill="url(#rm06-cyl)" stroke="rgba(221,224,230,0.28)" strokeWidth="1.1" />
              <ellipse cx="62" cy={y} rx="62" ry="16" fill="#232735" stroke="rgba(245,245,246,0.34)" strokeWidth="1.1" />
              <text x="62" y={y + 4} textAnchor="middle" fill="#F5F5F6" fontSize="8" fontFamily="monospace" fontWeight="700">
                {['events (audit)', 'warnings', 'scans'][idx]}
              </text>
            </g>
          ))}
          <text x="62" y="154" textAnchor="middle" fill="#8A8E99" fontSize="8" fontFamily="monospace">review.sqlite · COMMITTED</text>
        </g>

        {/* Transfer track to Human Review Queue */}
        <path d="M162 110 H248" stroke="rgba(221,224,230,0.3)" strokeWidth="1.5" strokeDasharray="4 4" />
        <circle cx={packetX} cy="110" r="4" fill="#65B48C" />

        {/* Right Human Review Queue Panel */}
        <g transform="translate(248, 32)">
          <rect x="0" y="0" width="150" height="162" rx="11" fill="url(#rm06-card)" stroke="rgba(221,224,230,0.28)" strokeWidth="1.2" />
          <text x="14" y="21" fill="#F5F5F6" fontSize="8.8" fontFamily="monospace" fontWeight="700">HUMAN REVIEW QUEUE</text>
          <text x="14" y="34" fill="#65B48C" fontSize="7.4" fontFamily="monospace">MỌI CẢNH BÁO GIỮ TRẠNG THÁI OPEN</text>

          {[
            {label: 'SUPPORTED', val: liveCounts && Number.isInteger(liveCounts.supported) ? liveCounts.supported : '—', color: '#DF8E95', y: 48},
            {label: 'REFUTED (OPEN)', val: liveCounts && Number.isInteger(liveCounts.refutedOpen) ? liveCounts.refutedOpen : '—', color: '#E2C593', y: 84},
            {label: 'UNDETERMINED', val: liveCounts && Number.isInteger(liveCounts.undetermined) ? liveCounts.undetermined : '—', color: '#B4B7BE', y: 120},
          ].map((row) => (
            <g key={row.label} transform={`translate(12, ${row.y})`}>
              <rect x="0" y="0" width="126" height="28" rx="6" fill="rgba(255,255,255,0.04)" stroke="rgba(255,255,255,0.1)" />
              <circle cx="11" cy="14" r="3.5" fill={row.color} />
              <text x="21" y="17" fill="#DDE0E6" fontSize="7.8" fontFamily="monospace">{row.label}</text>
              <text x="116" y="17.5" textAnchor="end" fill="#F5F5F6" fontSize="9.5" fontFamily="monospace" fontWeight="700">{row.val}</text>
            </g>
          ))}
        </g>
      </svg>
    </div>
  );
}

/* ============================================================================
   Synchronized Right-Hand Telemetry & Animated Stage Chart Panel
   Strictly reflects real backend metadata / counts / progress whenever present.
   ============================================================================ */

function TelemetryEmptyNotice({title, statusLabel, note}) {
  return (
    <div className="v2-rm-mini-chart">
      <div className="v2-rm-mini-chart-title">
        <span>{title}</span>
        <strong className="mono">{statusLabel}</strong>
      </div>
      <p className="panel-note" style={{margin: '6px 0 0', fontSize: '12px'}}>
        {note}
      </p>
    </div>
  );
}

function StageTelemetryChart({activeIndex, stage, mode, liveCounts, progress, noLlm, localFrame, reducedMotion}) {
  const anim = reducedMotion ? 1 : spring({frame: Math.max(localFrame, 12), fps: TIMELINE_FPS, config: {damping: 16, stiffness: 130}});
  const meta = stage?.summary && typeof stage.summary === 'object' ? stage.summary : {};
  const isPreview = mode === TIMELINE_MODES.PREVIEW;

  if (activeIndex === 0) {
    const javaCount = safeNumber(meta.java_files_count);
    const nonJavaCount = safeNumber(meta.non_java_files_count);
    const total = (javaCount ?? 0) + (nonJavaCount ?? 0);
    if (javaCount !== null) {
      const bars = [
        {
          label: 'Tệp .java trong inventory',
          value: javaCount,
          realValue: javaCount,
          pct: total > 0 ? (javaCount / total) * 100 : (javaCount > 0 ? 100 : 0),
          color: '#DDE0E6',
        },
        ...(nonJavaCount !== null
          ? [{
              label: 'Tệp khác (bỏ qua)',
              value: nonJavaCount,
              realValue: nonJavaCount,
              pct: total > 0 && nonJavaCount > 0 ? (nonJavaCount / total) * 100 : 0,
              color: '#6E7380',
            }]
          : []),
      ];
      return <MetricBars title="Kiểm kê & lọc nguồn Java" items={bars} anim={anim} />;
    }
    if (!isPreview) {
      return (
        <TelemetryEmptyNotice
          title="Kiểm kê & lọc nguồn Java"
          statusLabel={stage?.cat === 'RUNNING' ? 'Đang kiểm kê…' : 'Chưa có dữ liệu'}
          note={stage?.cat === 'RUNNING'
            ? 'Backend đang kiểm tra nguồn và lập danh mục tệp .java.'
            : 'API chưa trả metadata số lượng tệp cho giai đoạn 01.'}
        />
      );
    }
    return (
      <MetricBars
        title="Kiểm kê & lọc nguồn Java (Minh họa)"
        items={[
          {label: 'Kiểm tra URL / ZIP an toàn', value: 'Bước 1', pct: 100, color: '#DDE0E6'},
          {label: 'Chặn symlink & path traversal', value: 'Bước 2', pct: 84, color: '#65B48C'},
          {label: 'Lập danh mục tệp .java', value: 'Bước 3', pct: 72, color: '#8CB4E0'},
        ]}
        anim={anim}
      />
    );
  }

  if (activeIndex === 1) {
    const candidates = safeNumber(meta.findings_count ?? meta.candidate_count ?? progress?.total_findings ?? liveCounts?.total);
    if (!isPreview && candidates === null) {
      return (
        <TelemetryEmptyNotice
          title="Phạm vi tập luật OpenGrep"
          statusLabel={stage?.cat === 'RUNNING' ? 'Đang quét…' : 'Chưa có dữ liệu'}
          note={stage?.cat === 'RUNNING'
            ? 'OpenGrep đang phân tích tĩnh tập luật CWE-22 và CWE-89 trên máy chủ.'
            : 'API chưa trả số ứng viên OpenGrep cho giai đoạn 02.'}
        />
      );
    }
    const bars = isPreview
      ? [
          {label: 'CWE-22 · Path Traversal', value: 'Minh họa 01', pct: 92, color: '#DF8E95'},
          {label: 'CWE-89 · SQL Injection', value: 'Minh họa 02', pct: 86, color: '#E2C593'},
          {label: 'Biên nhận scan-manifest', value: 'SHA-256', pct: 100, color: '#65B48C'},
        ]
      : [
          {label: 'Ứng viên ghi nhận từ API', value: `${candidates} ứng viên`, realValue: candidates, pct: candidates > 0 ? 100 : 0, color: '#65B48C'},
        ];
    return <MetricBars title={isPreview ? 'Phạm vi tập luật OpenGrep (Minh họa)' : 'Kết quả OpenGrep từ API'} items={bars} anim={anim} />;
  }

  if (activeIndex === 2) {
    const recordsCount = safeNumber(meta.records_count ?? progress?.total_findings ?? liveCounts?.total);
    if (!isPreview && recordsCount === null) {
      return (
        <TelemetryEmptyNotice
          title="Cấu trúc hồ sơ bằng chứng"
          statusLabel={stage?.cat === 'RUNNING' ? 'Đang thu thập…' : 'Chưa có dữ liệu'}
          note={stage?.cat === 'RUNNING'
            ? 'Đang trích xuất đoạn mã Java thật, dataflow trace và SHA-256 nguồn.'
            : 'API chưa trả số lượng hồ sơ bằng chứng cho giai đoạn 03.'}
        />
      );
    }
    const bars = isPreview
      ? [
          {label: 'Đoạn mã dòng Java thật', value: 'Minh họa', pct: 96, color: '#DDE0E6'},
          {label: 'Luồng taint & ngữ cảnh AST', value: 'Source → Sink', pct: 88, color: '#8CB4E0'},
          {label: 'Chụp mã băm SHA-256', value: 'Chống drift', pct: 100, color: '#65B48C'},
        ]
      : [
          {label: 'Hồ sơ bằng chứng đã thu thập', value: `${recordsCount} hồ sơ`, realValue: recordsCount, pct: recordsCount > 0 ? 100 : 0, color: '#DDE0E6'},
        ];
    return <MetricBars title={isPreview ? 'Cấu trúc hồ sơ bằng chứng (Minh họa)' : 'Hồ sơ bằng chứng từ API'} items={bars} anim={anim} />;
  }

  if (activeIndex === 3) {
    const skipped = noLlm || stage?.cat === 'SKIPPED';
    const processed = safeNumber(progress?.processed_findings);
    const totalFindings = safeNumber(progress?.total_findings ?? liveCounts?.total);
    const hasRealPct = !isPreview && !skipped && totalFindings !== null && totalFindings > 0 && processed !== null;
    const pct = skipped
      ? 0
      : hasRealPct
        ? Math.min(100, Math.round((processed / totalFindings) * 100))
        : 0;

    const radius = 32;
    const circ = 2 * Math.PI * radius;
    const dashOffset = skipped
      ? circ
      : hasRealPct
        ? circ * (1 - (pct / 100) * anim)
        : isPreview
          ? circ * (1 - 0.75 * anim)
          : circ;

    return (
      <div className="v2-rm-mini-chart">
        <div className="v2-rm-mini-chart-title">
          <span>{skipped ? 'Trạng thái chế độ đối chứng' : isPreview ? 'Tiến độ suy luận Qwen3.5-9B (Minh họa)' : 'Tiến độ suy luận Qwen3.5-9B'}</span>
          <strong className="mono">
            {skipped
              ? 'NO_LLM'
              : hasRealPct
                ? `${processed}/${totalFindings}`
                : isPreview
                  ? 'PREVIEW'
                  : stage?.cat === 'RUNNING'
                    ? 'Đang suy luận…'
                    : 'Chưa có số liệu'}
          </strong>
        </div>
        <div className="v2-rm-qwen-gauge">
          <svg width="78" height="78" viewBox="0 0 84 84" aria-hidden="true">
            <circle cx="42" cy="42" r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="7" />
            <circle
              cx="42"
              cy="42"
              r={radius}
              fill="none"
              stroke={skipped ? '#E2C593' : hasRealPct ? '#65B48C' : '#DDE0E6'}
              strokeWidth="7"
              strokeLinecap="round"
              strokeDasharray={circ}
              strokeDashoffset={dashOffset}
              transform="rotate(-90 42 42)"
            />
            <text x="42" y="45" textAnchor="middle" fill="#F5F5F6" fontSize={hasRealPct || skipped ? '13' : '10'} fontFamily="monospace" fontWeight="700">
              {skipped ? 'OFF' : hasRealPct ? `${pct}%` : isPreview ? '9B' : '—'}
            </text>
          </svg>
          <div className="v2-rm-qwen-legend">
            <span><strong>Runtime:</strong> Ollama cục bộ</span>
            <span><strong>Hợp đồng:</strong> Blind Evidence</span>
            <span><strong>Đầu ra:</strong> {skipped ? 'Giữ UNDETERMINED' : 'JSON + Trích dẫn'}</span>
          </div>
        </div>
      </div>
    );
  }

  if (activeIndex === 4) {
    const telemetry = resolveStage05CitationTelemetry({mode, stage, liveCounts});
    if (isPreview) {
      return (
        <MetricBars
          title="Cổng kiểm chứng trích dẫn (Minh họa)"
          items={[
            {label: 'Khớp đường dẫn & số dòng', value: 'PATH + LINE', pct: 100, color: '#8CB4E0'},
            {label: 'Khớp nguyên văn đoạn mã', value: 'QUOTE', pct: 94, color: '#DDE0E6'},
            {label: 'Đối chiếu SHA-256 nguồn', value: 'INTEGRITY', pct: 100, color: '#B4B7BE'},
          ]}
          anim={anim}
        />
      );
    }
    const canRenderCountBars = (
      telemetry.aggregateStatus !== 'CONFLICT'
      && telemetry.aggregateStatus !== 'MALFORMED'
      && telemetry.counts
      && telemetry.counts.total !== null
      && telemetry.counts.total > 0
    );
    if (canRenderCountBars) {
      const denom = telemetry.counts.total;
      const realBars = [
        telemetry.counts.matched !== null
          ? {label: 'Trích dẫn khớp (MATCHED)', value: telemetry.counts.matched, realValue: telemetry.counts.matched, pct: (telemetry.counts.matched / denom) * 100, color: '#65B48C'}
          : null,
        telemetry.counts.notVerified !== null
          ? {label: 'Chưa xác minh (NOT_VERIFIED)', value: telemetry.counts.notVerified, realValue: telemetry.counts.notVerified, pct: (telemetry.counts.notVerified / denom) * 100, color: '#E2C593'}
          : null,
        telemetry.counts.invalid !== null
          ? {label: 'Không khớp (INVALID)', value: telemetry.counts.invalid, realValue: telemetry.counts.invalid, pct: (telemetry.counts.invalid / denom) * 100, color: '#DF8E95'}
          : null,
      ].filter(Boolean);
      if (realBars.length > 0) {
        return (
          <div>
            <MetricBars title="Tổng hợp kiểm chứng trích dẫn (từ API)" items={realBars} anim={anim} />
            <p className="panel-note" style={{margin: '6px 0 0', fontSize: '11.5px'}}>{telemetry.aggregateNote}</p>
          </div>
        );
      }
    }
    const statusBadgeText = telemetry.aggregateStatus === 'CHECKING'
      ? 'Đang kiểm tra…'
      : telemetry.aggregateStatus === 'NO_DATA'
        ? 'Chưa có dữ liệu'
        : telemetry.aggregateStatus === 'PARTIAL'
          ? 'Chưa đủ bằng chứng'
          : telemetry.aggregateStatus === 'CONFLICT'
            ? 'Mâu thuẫn dữ liệu'
            : telemetry.aggregateStatus === 'MALFORMED'
              ? 'Sai định dạng'
              : telemetry.aggregateStatus;
    return (
      <TelemetryEmptyNotice
        title="Cổng kiểm chứng trích dẫn"
        statusLabel={statusBadgeText}
        note={`${telemetry.aggregateLabel}. ${telemetry.aggregateNote}`}
      />
    );
  }

  // Stage 06: SQLite & live verdict distribution chart
  const total = Number.isInteger(liveCounts?.total) ? liveCounts.total : 0;
  const hasRefutedOpen = Number.isInteger(liveCounts?.refutedOpen);
  const supportedVal = Number.isInteger(liveCounts?.supported) ? liveCounts.supported : 0;
  const refutedMetricVal = hasRefutedOpen
    ? liveCounts.refutedOpen
    : (Number.isInteger(liveCounts?.refuted) ? liveCounts.refuted : 0);
  const undeterminedVal = Number.isInteger(liveCounts?.undetermined) ? liveCounts.undetermined : 0;
  if (liveCounts && !liveCounts.incomplete && total > 0) {
    const items = [
      {label: 'SUPPORTED', value: liveCounts.supported ?? '—', realValue: supportedVal, pct: (supportedVal / total) * 100, color: '#DF8E95'},
      {label: hasRefutedOpen ? 'REFUTED (OPEN)' : 'REFUTED (Qwen)', value: hasRefutedOpen ? liveCounts.refutedOpen : (liveCounts.refuted ?? '—'), realValue: refutedMetricVal, pct: (refutedMetricVal / total) * 100, color: '#E2C593'},
      {label: 'UNDETERMINED', value: liveCounts.undetermined ?? '—', realValue: undeterminedVal, pct: (undeterminedVal / total) * 100, color: '#8CB4E0'},
    ];
    return <MetricBars title="Phân bổ kết quả đã lưu SQLite" items={items} anim={anim} />;
  }
  if (!isPreview) {
    return (
      <TelemetryEmptyNotice
        title="Lưu trữ SQLite & Human Review"
        statusLabel={liveCounts?.confirmedNoFindings ? '0 cảnh báo' : stage?.cat === 'RUNNING' ? 'Đang ghi SQLite…' : 'Chưa có dữ liệu'}
        note={liveCounts?.confirmedNoFindings
          ? 'Phiên hoàn tất với 0 cảnh báo trong phạm vi tập luật hiện tại (NO_FINDINGS).'
          : 'Kết quả phân bổ cảnh báo chỉ hiển thị sau khi API xác nhận dữ liệu trong SQLite.'}
      />
    );
  }
  return (
    <MetricBars
      title="Cấu trúc lưu trữ Human Review (Minh họa)"
      items={[
        {label: 'Bảng scans & warnings', value: 'SQLite', pct: 100, color: '#DDE0E6'},
        {label: 'Trạng thái chờ duyệt', value: 'OPEN', pct: 92, color: '#65B48C'},
        {label: 'Audit trail kiểm duyệt', value: 'Sẵn sàng', pct: 85, color: '#8CB4E0'},
      ]}
      anim={anim}
    />
  );
}

function MetricBars({title, items, anim}) {
  return (
    <div className="v2-rm-mini-chart">
      <div className="v2-rm-mini-chart-title">
        <span>{title}</span>
      </div>
      <div className="v2-rm-bars">
        {items.map((item) => {
          const isZeroReal = item.realValue === 0 || Number(item.pct) <= 0;
          const computedWidth = isZeroReal ? 0 : Math.max(2, Math.min(100, item.pct * anim));
          return (
            <div className="v2-rm-bar-row" key={item.label}>
              <div className="v2-rm-bar-meta">
                <span>{item.label}</span>
                <strong className="mono">{item.value}</strong>
              </div>
              <div className="v2-rm-bar-track">
                <div
                  className="v2-rm-bar-fill"
                  style={{
                    width: `${computedWidth}%`,
                    backgroundColor: item.color,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function ScanStageVisual({
  step,
  index = 0,
  stage = null,
  segment = null,
  mode = TIMELINE_MODES.PREVIEW,
  localFrame = 0,
  cycle = 0,
  syncModeLabel = 'XEM TRƯỚC PIPELINE 6 GIAI ĐOẠN',
  syncTone = 'neutral',
  liveCounts = null,
  progress = null,
  noLlm = false,
  reducedMotion = false,
}) {
  const activeIndex = Math.max(0, Math.min(TOTAL_STAGES - 1, index));
  const stageCat = stage?.cat || 'UNKNOWN';
  const durationLabel = mode === TIMELINE_MODES.PREVIEW
    ? 'Minh họa (chưa chạy)'
    : segment?.measuredMs !== null && segment?.measuredMs !== undefined
      ? formatDurationMs(segment.measuredMs, {compact: true})
      : stageCat === 'RUNNING'
        ? 'Đang thực thi…'
        : stageCat === 'SKIPPED'
          ? 'Bỏ qua'
          : stageCat === 'CANCELLED'
            ? 'Đã hủy'
            : stageCat === 'COMPLETED' || stageCat === 'DEGRADED' || stageCat === 'FAILED'
              ? 'Chưa có số liệu thời lượng'
              : 'Chưa thực thi';
  const shareLabel = mode === TIMELINE_MODES.PREVIEW
    ? 'Minh họa'
    : segment?.sharePct !== null && segment?.sharePct !== undefined
      ? `${segment.sharePct.toFixed(1)}%`
      : 'Chưa có số liệu';

  return (
    <div className={`v2-rm-theater is-cat-${stageCat.toLowerCase()}`}>
      <div className="v2-rm-backdrop" aria-hidden="true" />

      <div className="v2-rm-hud-top">
        <span className={`v2-rm-sync-pill is-${syncTone}`}>
          <i aria-hidden="true" />
          <span>{syncModeLabel}</span>
        </span>
        <div className="v2-rm-hud-right">
          <span className="v2-rm-key-pill mono">{step?.key || ''}</span>
          <span className="v2-rm-counter-pill mono">
            {String(activeIndex + 1).padStart(2, '0')} <em>/</em> 06
          </span>
        </div>
      </div>

      <div className="v2-rm-stage-grid">
        <div className="v2-rm-3d-viewport">
          {activeIndex === 0 && <Stage01Intake3D localFrame={localFrame} cycle={cycle} stage={stage} mode={mode} reducedMotion={reducedMotion} />}
          {activeIndex === 1 && <Stage02OpenGrep3D localFrame={localFrame} cycle={cycle} stage={stage} mode={mode} reducedMotion={reducedMotion} />}
          {activeIndex === 2 && <Stage03Evidence3D localFrame={localFrame} cycle={cycle} stage={stage} mode={mode} reducedMotion={reducedMotion} />}
          {activeIndex === 3 && <Stage04Qwen3D localFrame={localFrame} cycle={cycle} noLlm={noLlm} stage={stage} reducedMotion={reducedMotion} />}
          {activeIndex === 4 && <Stage05Citation3D localFrame={localFrame} mode={mode} stage={stage} liveCounts={liveCounts} reducedMotion={reducedMotion} />}
          {activeIndex === 5 && <Stage06Store3D localFrame={localFrame} cycle={cycle} liveCounts={liveCounts} reducedMotion={reducedMotion} />}
        </div>

        <aside className="v2-rm-telemetry-panel" aria-label="Thông số giai đoạn đang hiển thị">
          <div className="v2-rm-telemetry-head">
            <span className="v2-rm-stage-badge mono">
              <Icon name={step?.icon || 'Layers'} />
              GIAI ĐOẠN {String(activeIndex + 1).padStart(2, '0')}
            </span>
            <Badge tone={stageToneFromCat(stageCat)}>{stage?.label || 'Sẵn sàng'}</Badge>
          </div>

          <h3 className="v2-rm-stage-heading">{step?.title}</h3>
          <p className="v2-rm-stage-desc">{step?.purpose}</p>

          <StageTelemetryChart
            activeIndex={activeIndex}
            stage={stage}
            mode={mode}
            liveCounts={liveCounts}
            progress={progress}
            noLlm={noLlm}
            localFrame={localFrame}
            reducedMotion={reducedMotion}
          />

          <div className="v2-rm-telemetry-foot">
            <div>
              <span>Thời lượng backend</span>
              <strong className="mono">{durationLabel}</strong>
            </div>
            <div>
              <span>Tỷ trọng E2E</span>
              <strong className="mono">{shareLabel || '—'}</strong>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
