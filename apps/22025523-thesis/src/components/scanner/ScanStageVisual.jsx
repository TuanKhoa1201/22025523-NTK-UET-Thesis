import {Badge, Icon} from '../common/Ui';
import {
  Easing,
  TIMELINE_FPS,
  formatCompactDuration,
  interpolate,
  spring,
} from './remotionEngine';

const TOTAL_STAGES = 6;

function safeNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function stageToneFromCat(cat) {
  if (cat === 'COMPLETED') return 'green';
  if (cat === 'FAILED') return 'red';
  if (cat === 'SKIPPED') return 'amber';
  if (cat === 'RUNNING') return 'blue';
  return 'neutral';
}

/* ============================================================================
   6 Bespoke Remotion-Driven 3D Isometric Stage Scenes
   All coordinates, camera tilt, particle packets, and chart bars are driven
   deterministically by (localFrame, cycleFrame, localProgress) via spring()
   and interpolate().
   ============================================================================ */

function Stage01Intake3D({localFrame, cycle, stage, reducedMotion}) {
  const enter = reducedMotion ? 1 : spring({frame: localFrame, fps: TIMELINE_FPS, config: {damping: 15, stiffness: 115}});
  const card1 = reducedMotion ? 1 : spring({frame: localFrame, delay: 8, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 120}});
  const card2 = reducedMotion ? 1 : spring({frame: localFrame, delay: 16, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 120}});
  const card3 = reducedMotion ? 1 : spring({frame: localFrame, delay: 24, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 120}});
  const sweep = reducedMotion ? 0.62 : (cycle % 1);
  const gateX = interpolate(sweep, [0, 0.5, 1], [156, 252, 156], {easing: Easing.easeInOutSine});
  const pulse = reducedMotion ? 0.8 : 0.45 + 0.55 * Math.sin(cycle * Math.PI * 2);
  const meta = stage?.summary || {};
  const modeLabel = meta.input_mode === 'ZIP' ? 'ZIP ARCHIVE' : 'GITHUB / ZIP';

  return (
    <div
      className="v2-rm-3d-rig"
      style={{
        transform: `rotateX(${interpolate(enter, [0, 1], [18, 9])}deg) rotateY(${interpolate(enter, [0, 1], [-18, -7])}deg) scale(${interpolate(enter, [0, 1], [0.92, 1])})`,
        opacity: interpolate(enter, [0, 0.6], [0.55, 1]),
      }}
    >
      <svg className="v2-rm-scene-svg" viewBox="0 0 420 230" role="img" aria-label="Mô phỏng 3D giai đoạn tiếp nhận và kiểm tra an toàn mã nguồn Java">
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
          <circle cx="94" cy="90" r="4" fill="#65B48C" opacity={pulse} />
          <text x="12" y="93" fill="#8A8E99" fontSize="8" fontFamily="monospace">SANDBOX ISOLATED</text>
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
        {[
          {name: 'FileServlet.java', badge: 'NO TRAVERSAL', y: 40, x: 266, s: card1},
          {name: 'UserDao.java', badge: 'NO SYMLINK', y: 92, x: 274, s: card2},
          {name: 'AuthFilter.java', badge: 'SIZE BOUNDED', y: 144, x: 266, s: card3},
        ].map((f) => (
          <g
            key={f.name}
            transform={`translate(${interpolate(f.s, [0, 1], [f.x + 28, f.x])}, ${f.y})`}
            opacity={interpolate(f.s, [0, 0.7], [0, 1])}
          >
            <rect x="0" y="0" width="128" height="40" rx="9" fill="url(#rm01-card)" stroke="rgba(221,224,230,0.24)" strokeWidth="1.1" />
            <circle cx="14" cy="20" r="4.5" fill="rgba(101,180,140,0.22)" stroke="#65B48C" strokeWidth="1.2" />
            <text x="26" y="17" fill="#F5F5F6" fontSize="9.5" fontFamily="monospace" fontWeight="600">{f.name}</text>
            <text x="26" y="30" fill="#65B48C" fontSize="7.5" fontFamily="monospace">{f.badge} ✓</text>
          </g>
        ))}
      </svg>
    </div>
  );
}

function Stage02OpenGrep3D({localFrame, cycle, reducedMotion}) {
  const enter = reducedMotion ? 1 : spring({frame: localFrame, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 120}});
  const sweep = reducedMotion ? 0.55 : (cycle % 1);
  const laserY = interpolate(sweep, [0, 0.5, 1], [44, 152, 44], {easing: Easing.easeInOutSine});
  const hit1 = Math.abs(laserY - 82) < 20 ? 1 : 0.45;
  const hit2 = Math.abs(laserY - 126) < 20 ? 1 : 0.45;
  const manifestEnter = reducedMotion ? 1 : spring({frame: localFrame, delay: 20, fps: TIMELINE_FPS, config: {damping: 15, stiffness: 110}});

  return (
    <div
      className="v2-rm-3d-rig"
      style={{
        transform: `rotateX(${interpolate(enter, [0, 1], [16, 8])}deg) rotateY(${interpolate(enter, [0, 1], [14, 5])}deg) scale(${interpolate(enter, [0, 1], [0.93, 1])})`,
        opacity: interpolate(enter, [0, 0.6], [0.55, 1]),
      }}
    >
      <svg className="v2-rm-scene-svg" viewBox="0 0 420 230" role="img" aria-label="Mô phỏng 3D giai đoạn quét tĩnh OpenGrep CWE-22 và CWE-89">
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
          <text x="12" y="18" fill="#DF8E95" fontSize="9" fontFamily="monospace" fontWeight="700">CWE-22 MATCH</text>
          <text x="12" y="33" fill="#B4B7BE" fontSize="8" fontFamily="monospace">Path Traversal Sink</text>

          <rect x="0" y="58" width="126" height="46" rx="9" fill="url(#rm02-slab)" stroke={hit2 > 0.8 ? '#E2C593' : 'rgba(226,197,147,0.35)'} strokeWidth="1.2" />
          <text x="12" y="76" fill="#E2C593" fontSize="9" fontFamily="monospace" fontWeight="700">CWE-89 MATCH</text>
          <text x="12" y="91" fill="#B4B7BE" fontSize="8" fontFamily="monospace">SQL Injection Sink</text>

          <rect x="0" y="116" width="126" height="54" rx="9" fill="#141720" stroke="rgba(221,224,230,0.28)" strokeWidth="1.1" />
          <text x="12" y="133" fill="#F5F5F6" fontSize="8.5" fontFamily="monospace" fontWeight="600">scan-manifest.json</text>
          <text x="12" y="147" fill="#65B48C" fontSize="7.5" fontFamily="monospace">JSON/SARIF PARITY ✓</text>
          <text x="12" y="160" fill="#8A8E99" fontSize="7.2" fontFamily="monospace">SHA-256 RECORDED</text>
        </g>

        {/* Connector trails */}
        <path d="M242 82 H268 M242 126 H268" stroke="rgba(221,224,230,0.3)" strokeWidth="1.2" strokeDasharray="3 3" />
      </svg>
    </div>
  );
}

function Stage03Evidence3D({localFrame, cycle, reducedMotion}) {
  const enter = reducedMotion ? 1 : spring({frame: localFrame, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 118}});
  const trace = reducedMotion ? 0.72 : (cycle % 1);
  const dotX = interpolate(trace, [0, 1], [66, 354], {easing: Easing.easeInOutCubic});
  const dotY = 118 - Math.sin(trace * Math.PI) * 34;

  return (
    <div
      className="v2-rm-3d-rig"
      style={{
        transform: `rotateX(${interpolate(enter, [0, 1], [15, 7])}deg) rotateY(${interpolate(enter, [0, 1], [-14, -5])}deg) scale(${interpolate(enter, [0, 1], [0.93, 1])})`,
        opacity: interpolate(enter, [0, 0.6], [0.55, 1]),
      }}
    >
      <svg className="v2-rm-scene-svg" viewBox="0 0 420 230" role="img" aria-label="Mô phỏng 3D giai đoạn trích xuất bằng chứng AST và băm SHA-256">
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
          {x: 24, y: 78, tag: 'SOURCE · L18', title: 'req.getParameter', accent: '#8CB4E0'},
          {x: 152, y: 42, tag: 'AST CONTEXT', title: 'Method Scope + Vars', accent: '#DDE0E6'},
          {x: 280, y: 78, tag: 'SINK · L46', title: 'new File(base, p)', accent: '#DF8E95'},
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
              <text x="12" y="42" fill="#F5F5F6" fontSize="9" fontFamily="monospace">{node.title}</text>
              <rect x="12" y="50" width="82" height="3.5" rx="2" fill="rgba(255,255,255,0.12)" />
            </g>
          );
        })}

        {/* Bottom SHA-256 Immutable Evidence Strip */}
        <g transform="translate(36, 162)">
          <rect x="0" y="0" width="348" height="44" rx="10" fill="#13161E" stroke="rgba(221,224,230,0.28)" strokeWidth="1.1" />
          <text x="14" y="17" fill="#B4B7BE" fontSize="7.8" fontFamily="monospace" fontWeight="600">EVIDENCE SNAPSHOT · IMMUTABLE SHA-256</text>
          <text x="14" y="33" fill="#65B48C" fontSize="8.8" fontFamily="monospace">sha256: e721caadbf2c5caaf76c322d907ea4ca…ba9e19e</text>
          <rect x="292" y="12" width="44" height="20" rx="5" fill="rgba(101,180,140,0.14)" stroke="rgba(101,180,140,0.4)" />
          <text x="314" y="25" textAnchor="middle" fill="#65B48C" fontSize="8" fontFamily="monospace" fontWeight="700">SEALED</text>
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

function Stage05Citation3D({localFrame, cycle, reducedMotion}) {
  const enter = reducedMotion ? 1 : spring({frame: localFrame, fps: TIMELINE_FPS, config: {damping: 14, stiffness: 120}});
  const sweep = reducedMotion ? 0.78 : (cycle % 1);
  const checks = [
    {label: 'PATH', y: 74, passAt: 0.18},
    {label: 'LINE', y: 104, passAt: 0.38},
    {label: 'QUOTE', y: 134, passAt: 0.58},
    {label: 'SHA-256', y: 164, passAt: 0.78},
  ];

  return (
    <div
      className="v2-rm-3d-rig"
      style={{
        transform: `rotateX(${interpolate(enter, [0, 1], [15, 7])}deg) rotateY(${interpolate(enter, [0, 1], [-12, -4])}deg) scale(${interpolate(enter, [0, 1], [0.93, 1])})`,
        opacity: interpolate(enter, [0, 0.6], [0.55, 1]),
      }}
    >
      <svg className="v2-rm-scene-svg" viewBox="0 0 420 230" role="img" aria-label="Mô phỏng 3D kiểm chứng trích dẫn mã nguồn thật và SHA-256">
        <defs>
          <linearGradient id="rm05-pane" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#242834" />
            <stop offset="100%" stopColor="#12141B" />
          </linearGradient>
        </defs>

        {/* Left Plane: Model Citation */}
        <rect x="20" y="34" width="136" height="160" rx="11" fill="url(#rm05-pane)" stroke="rgba(221,224,230,0.24)" />
        <text x="88" y="53" textAnchor="middle" fill="#B4B7BE" fontSize="8" fontFamily="monospace" fontWeight="700">MODEL CITATION</text>

        {/* Right Plane: Original Source Snapshot */}
        <rect x="264" y="34" width="136" height="160" rx="11" fill="url(#rm05-pane)" stroke="rgba(221,224,230,0.24)" />
        <text x="332" y="53" textAnchor="middle" fill="#B4B7BE" fontSize="8" fontFamily="monospace" fontWeight="700">JAVA SNAPSHOT</text>

        {/* Verification Check Rows + Center Lock Beams */}
        {checks.map((item) => {
          const verified = reducedMotion || sweep >= item.passAt;
          return (
            <g key={item.label}>
              <rect x="32" y={item.y - 10} width="112" height="20" rx="5" fill="rgba(255,255,255,0.04)" stroke={verified ? 'rgba(101,180,140,0.45)' : 'rgba(255,255,255,0.1)'} />
              <text x="42" y={item.y + 3} fill="#DDE0E6" fontSize="8" fontFamily="monospace">{item.label}</text>

              <rect x="276" y={item.y - 10} width="112" height="20" rx="5" fill="rgba(255,255,255,0.04)" stroke={verified ? 'rgba(101,180,140,0.45)' : 'rgba(255,255,255,0.1)'} />
              <text x="286" y={item.y + 3} fill="#DDE0E6" fontSize="8" fontFamily="monospace">{item.label} REAL</text>

              <line
                x1="144"
                y1={item.y}
                x2="276"
                y2={item.y}
                stroke={verified ? '#65B48C' : 'rgba(221,224,230,0.16)'}
                strokeWidth={verified ? '1.6' : '1'}
                strokeDasharray={verified ? undefined : '4 4'}
              />
              <rect
                x="182"
                y={item.y - 9}
                width="56"
                height="18"
                rx="9"
                fill={verified ? 'rgba(22,36,30,0.96)' : '#141720'}
                stroke={verified ? '#65B48C' : 'rgba(221,224,230,0.2)'}
              />
              <text x="210" y={item.y + 3} textAnchor="middle" fill={verified ? '#65B48C' : '#8A8E99'} fontSize="7.5" fontFamily="monospace" fontWeight="700">
                {verified ? 'MATCH ✓' : 'CHECK…'}
              </text>
            </g>
          );
        })}

        {/* Guardrail footer callout */}
        <text x="210" y="212" textAnchor="middle" fill="#8A8E99" fontSize="8" fontFamily="monospace">
          THIẾU BẰNG CHỨNG → HẠ CẤP TỰ ĐỘNG VỀ UNDETERMINED
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

function StageTelemetryChart({activeIndex, stage, liveCounts, progress, noLlm, localFrame, reducedMotion}) {
  const anim = reducedMotion ? 1 : spring({frame: Math.max(localFrame, 12), fps: TIMELINE_FPS, config: {damping: 16, stiffness: 130}});
  const meta = stage?.summary && typeof stage.summary === 'object' ? stage.summary : {};

  if (activeIndex === 0) {
    const javaCount = safeNumber(meta.java_files_count);
    const nonJavaCount = safeNumber(meta.non_java_files_count);
    const total = (javaCount ?? 0) + (nonJavaCount ?? 0);
    const bars = javaCount !== null
      ? [
          {label: 'Tệp .java hợp lệ', value: javaCount, pct: total > 0 ? Math.max(12, (javaCount / total) * 100) : 100, color: '#DDE0E6'},
          {label: 'Tệp khác (bỏ qua)', value: nonJavaCount ?? 0, pct: total > 0 ? Math.max(8, ((nonJavaCount ?? 0) / total) * 100) : 0, color: '#6E7380'},
        ]
      : [
          {label: 'Kiểm tra URL / ZIP an toàn', value: 'Bước 1', pct: 100, color: '#DDE0E6'},
          {label: 'Chặn symlink & path traversal', value: 'Bước 2', pct: 84, color: '#65B48C'},
          {label: 'Lập danh mục tệp .java', value: 'Bước 3', pct: 72, color: '#8CB4E0'},
        ];
    return <MetricBars title="Kiểm kê & lọc nguồn Java" items={bars} anim={anim} />;
  }

  if (activeIndex === 1) {
    const candidates = safeNumber(meta.findings_count ?? meta.candidate_count ?? progress?.total_findings ?? liveCounts?.total);
    const bars = [
      {label: 'CWE-22 · Path Traversal', value: candidates !== null ? 'Đang quét / đã quét' : 'Ưu tiên 01', pct: 92, color: '#DF8E95'},
      {label: 'CWE-89 · SQL Injection', value: candidates !== null ? 'Đang quét / đã quét' : 'Ưu tiên 02', pct: 86, color: '#E2C593'},
      {label: 'Biên nhận scan-manifest', value: candidates !== null ? `${candidates} ứng viên` : 'SHA-256', pct: 100, color: '#65B48C'},
    ];
    return <MetricBars title="Phạm vi tập luật OpenGrep" items={bars} anim={anim} />;
  }

  if (activeIndex === 2) {
    const recordsCount = safeNumber(meta.records_count ?? progress?.total_findings ?? liveCounts?.total);
    const bars = [
      {label: 'Đoạn mã dòng Java thật', value: recordsCount !== null ? `${recordsCount} hồ sơ` : 'Source Lines', pct: 96, color: '#DDE0E6'},
      {label: 'Luồng taint & ngữ cảnh AST', value: 'Source → Sink', pct: 88, color: '#8CB4E0'},
      {label: 'Chụp mã băm SHA-256', value: 'Chống drift', pct: 100, color: '#65B48C'},
    ];
    return <MetricBars title="Cấu trúc hồ sơ bằng chứng" items={bars} anim={anim} />;
  }

  if (activeIndex === 3) {
    const skipped = noLlm || stage?.cat === 'SKIPPED';
    const processed = safeNumber(progress?.processed_findings);
    const totalFindings = safeNumber(progress?.total_findings ?? liveCounts?.total);
    const hasRealPct = !skipped && (
      (totalFindings !== null && totalFindings > 0 && processed !== null) ||
      stage?.cat === 'COMPLETED'
    );
    const pct = skipped
      ? 0
      : totalFindings && totalFindings > 0 && processed !== null
        ? Math.min(100, Math.round((processed / totalFindings) * 100))
        : stage?.cat === 'COMPLETED'
          ? 100
          : 100;

    const radius = 32;
    const circ = 2 * Math.PI * radius;
    const dashOffset = skipped
      ? circ
      : hasRealPct
        ? circ * (1 - (pct / 100) * anim)
        : circ * (1 - 0.75 * anim);

    return (
      <div className="v2-rm-mini-chart">
        <div className="v2-rm-mini-chart-title">
          <span>{skipped ? 'Trạng thái chế độ đối chứng' : 'Tiến độ suy luận Qwen3.5-9B'}</span>
          <strong className="mono">
            {skipped ? 'NO_LLM' : totalFindings !== null && processed !== null ? `${processed}/${totalFindings}` : hasRealPct ? `${pct}%` : 'LOCAL'}
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
            <text x="42" y="45" textAnchor="middle" fill="#F5F5F6" fontSize={hasRealPct || skipped ? '13' : '10.5'} fontFamily="monospace" fontWeight="700">
              {skipped ? 'OFF' : hasRealPct ? `${pct}%` : '9B'}
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
    const bars = [
      {label: 'Khớp đường dẫn & số dòng', value: 'PATH + LINE', pct: 100, color: '#65B48C'},
      {label: 'Khớp nguyên văn đoạn mã', value: 'QUOTE', pct: 94, color: '#DDE0E6'},
      {label: 'Đối chiếu SHA-256 nguồn', value: 'INTEGRITY', pct: 100, color: '#8CB4E0'},
    ];
    return <MetricBars title="Cổng kiểm chứng trích dẫn" items={bars} anim={anim} />;
  }

  // Stage 06: SQLite & live verdict distribution chart
  const total = Number.isInteger(liveCounts?.total) ? liveCounts.total : 0;
  const hasRefutedOpen = Number.isInteger(liveCounts?.refutedOpen);
  const refutedMetricVal = hasRefutedOpen
    ? liveCounts.refutedOpen
    : (Number.isInteger(liveCounts?.refuted) ? liveCounts.refuted : 0);
  const items = liveCounts && !liveCounts.incomplete && total > 0
    ? [
        {label: 'SUPPORTED', value: liveCounts.supported ?? '—', pct: Math.max(8, ((liveCounts.supported ?? 0) / total) * 100), color: '#DF8E95'},
        {label: hasRefutedOpen ? 'REFUTED (OPEN)' : 'REFUTED (Qwen)', value: hasRefutedOpen ? liveCounts.refutedOpen : (liveCounts.refuted ?? '—'), pct: Math.max(8, (refutedMetricVal / total) * 100), color: '#E2C593'},
        {label: 'UNDETERMINED', value: liveCounts.undetermined ?? '—', pct: Math.max(8, ((liveCounts.undetermined ?? 0) / total) * 100), color: '#8CB4E0'},
      ]
    : [
        {label: 'Bảng scans & warnings', value: 'SQLite', pct: 100, color: '#DDE0E6'},
        {label: 'Trạng thái chờ duyệt', value: 'OPEN', pct: 92, color: '#65B48C'},
        {label: 'Audit trail kiểm duyệt', value: 'Sẵn sàng', pct: 85, color: '#8CB4E0'},
      ];
  return <MetricBars title={liveCounts ? 'Phân bổ kết quả đã lưu SQLite' : 'Cấu trúc lưu trữ Human Review'} items={items} anim={anim} />;
}

function MetricBars({title, items, anim}) {
  return (
    <div className="v2-rm-mini-chart">
      <div className="v2-rm-mini-chart-title">
        <span>{title}</span>
      </div>
      <div className="v2-rm-bars">
        {items.map((item) => (
          <div className="v2-rm-bar-row" key={item.label}>
            <div className="v2-rm-bar-meta">
              <span>{item.label}</span>
              <strong className="mono">{item.value}</strong>
            </div>
            <div className="v2-rm-bar-track">
              <div
                className="v2-rm-bar-fill"
                style={{
                  width: `${Math.max(4, Math.min(100, item.pct * anim))}%`,
                  backgroundColor: item.color,
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ScanStageVisual({
  step,
  index = 0,
  stage = null,
  segment = null,
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
  const durationLabel = segment?.measuredMs !== null && segment?.measuredMs !== undefined
    ? formatCompactDuration(segment.measuredMs)
    : stageCat === 'RUNNING'
      ? 'Đang đo…'
      : '—';
  const shareLabel = segment?.sharePct !== null && segment?.sharePct !== undefined
    ? `${segment.sharePct.toFixed(1)}%`
    : null;

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
          {activeIndex === 0 && <Stage01Intake3D localFrame={localFrame} cycle={cycle} stage={stage} reducedMotion={reducedMotion} />}
          {activeIndex === 1 && <Stage02OpenGrep3D localFrame={localFrame} cycle={cycle} reducedMotion={reducedMotion} />}
          {activeIndex === 2 && <Stage03Evidence3D localFrame={localFrame} cycle={cycle} reducedMotion={reducedMotion} />}
          {activeIndex === 3 && <Stage04Qwen3D localFrame={localFrame} cycle={cycle} noLlm={noLlm} stage={stage} reducedMotion={reducedMotion} />}
          {activeIndex === 4 && <Stage05Citation3D localFrame={localFrame} cycle={cycle} reducedMotion={reducedMotion} />}
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
