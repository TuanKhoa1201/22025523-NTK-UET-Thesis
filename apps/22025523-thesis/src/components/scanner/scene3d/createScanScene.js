/*
 * NTK P0.12 - Monochrome Dark Tech / Optical Contrast.
 * Real Three.js geometry for ten conceptual pipeline stages.
 * No fabricated vulnerability scores, backend progress or triage evidence.
 */
const SILVER = '#e6e7ec';
const WHITE = '#ffffff';
const ASH = '#9699a3';
const GRAPHITE = '#33343b';

export function createScanScene(THREE, scene) {
  const geometries = new Set();
  const materials = new Set();
  const stageGroups = [];
  const packets = [];
  const floaters = [];
  const scanners = [];
  const driven = [];
  const root = new THREE.Group();
  scene.add(root);

  const rememberGeo = (item) => { geometries.add(item); return item; };
  const rememberMat = (item) => { materials.add(item); return item; };
  const basic = (color = WHITE, opacity = 1, extras = {}) => rememberMat(new THREE.MeshBasicMaterial({
    color, opacity, transparent: opacity < 1, depthWrite: opacity === 1,
    side: THREE.DoubleSide, ...extras
  }));
  const surface = (color = SILVER, opacity = 1) => rememberMat(new THREE.MeshPhysicalMaterial({
    color, metalness: 0.58, roughness: 0.23, clearcoat: 0.9,
    clearcoatRoughness: 0.18, transparent: opacity < 1, opacity,
    depthWrite: opacity === 1, side: THREE.DoubleSide
  }));
  const wire = (parent, w, h, d, at, opacity = 0.75) => {
    const box = rememberGeo(new THREE.BoxGeometry(w, h, d));
    const edges = rememberGeo(new THREE.EdgesGeometry(box));
    const part = new THREE.LineSegments(edges, rememberMat(new THREE.LineBasicMaterial({
      color: WHITE, transparent: true, opacity, depthWrite: false
    })));
    part.position.set(...at);
    parent.add(part);
    return part;
  };
  const box = (parent, at, size, mat) => {
    const mesh = new THREE.Mesh(rememberGeo(new THREE.BoxGeometry(...size)), mat);
    mesh.position.set(...at);
    parent.add(mesh);
    return mesh;
  };
  const sphere = (parent, at, radius, mat, segments = 20) => {
    const mesh = new THREE.Mesh(rememberGeo(new THREE.SphereGeometry(radius, segments, 12)), mat);
    mesh.position.set(...at);
    parent.add(mesh);
    return mesh;
  };
  const crystal = (parent, at, radius, mat) => {
    const mesh = new THREE.Mesh(rememberGeo(new THREE.OctahedronGeometry(radius, 0)), mat);
    mesh.position.set(...at);
    parent.add(mesh);
    return mesh;
  };
  const torus = (parent, at, radius, mat, rotation = [0, 0, 0], thickness = 0.012, arc = Math.PI * 2) => {
    const mesh = new THREE.Mesh(rememberGeo(new THREE.TorusGeometry(radius, thickness, 8, 112, arc)), mat);
    mesh.position.set(...at);
    mesh.rotation.set(...rotation);
    parent.add(mesh);
    return mesh;
  };
  const curve = (coords) => new THREE.CatmullRomCurve3(coords.map((coords3) => new THREE.Vector3(...coords3)));
  const path = (parent, coords, {opacity = 0.65, width = 0.010, animated = false, speed = 0.22, offset = 0} = {}) => {
    const spline = curve(coords);
    const pts = spline.getPoints(50);
    const geometry = rememberGeo(new THREE.BufferGeometry().setFromPoints(pts));
    parent.add(new THREE.Line(geometry, rememberMat(new THREE.LineBasicMaterial({
      color: WHITE, transparent: true, opacity, depthWrite: false
    }))));
    // Narrow chrome filaments are surrounded by a restrained, softly lit edge.
    const beam = new THREE.Mesh(
      rememberGeo(new THREE.TubeGeometry(spline, 50, width, 5, false)),
      basic(SILVER, opacity * 0.18, {blending: THREE.AdditiveBlending, depthWrite: false})
    );
    parent.add(beam);
    if (animated) {
      const dot = sphere(parent, coords[0], 0.041, basic(WHITE));
      packets.push({dot, spline, speed, offset, parent});
    }
    return spline;
  };
  const beam = (parent, start, end, options = {}) => path(parent, [start, end], options);
  const outlinePanel = (parent, at, size, opacity = 0.6) => {
    box(parent, at, size, basic(GRAPHITE, 0.44));
    return wire(parent, size[0], size[1], size[2], at, opacity);
  };
  const bars = (parent, x, y, count, gap, lengths, material = basic(ASH, 0.74)) => {
    for (let i = 0; i < count; i += 1) {
      const length = lengths[i % lengths.length];
      box(parent, [x + length / 2, y - i * gap, 0.20], [length, 0.032, 0.015], material);
    }
  };
  const float = (mesh, amount = 0.045, speed = 0.8, phase = 0) => {
    floaters.push({mesh, amount, speed, phase, y: mesh.position.y});
    return mesh;
  };
  const labelSpark = (parent, at, radius = 0.035) => {
    sphere(parent, at, radius, basic(WHITE));
    sphere(parent, at, radius * 2, basic(WHITE, 0.10));
  };
  const group = () => {
    const item = new THREE.Group();
    item.visible = false;
    root.add(item);
    stageGroups.push(item);
    return item;
  };

  // 01: repository / ZIP -> files -> intake core.
  {
    const s = group();
    const repo = new THREE.Group();
    repo.position.set(-2.53, 0.05, 0.15);
    s.add(repo);
    wire(repo, 0.86, 0.86, 0.76, [0, 0, 0], 0.90);
    wire(repo, 0.60, 0.60, 0.58, [0.08, 0.05, 0.01], 0.30);
    beam(repo, [-0.19, 0.12, 0.40], [-0.03, -0.01, 0.40], {opacity: 0.9});
    beam(repo, [-0.02, -0.02, 0.40], [0.18, -0.17, 0.40], {opacity: 0.9});
    float(repo, 0.06, 0.7);
    for (let i = 0; i < 6; i += 1) {
      const y = (i - 2.5) * 0.31;
      const x = -1.75 + (i % 2) * 0.36;
      float(outlinePanel(s, [x, y, 0.30], [0.26, 0.34, 0.042], 0.55), 0.025, 0.9, i * 0.65);
      path(s, [[-2.05, y * 0.5, 0.18], [x, y, 0.2], [-0.56, y * 0.20, 0.12]], {opacity: 0.36, animated: i < 4, offset: i / 6, speed: 0.22});
    }
    for (let i = 0; i < 3; i += 1) path(s, [[0.70, 0, 0], [1.3, (i - 1) * 0.15, 0.16], [2.8, (i - 1) * 0.35, -0.1]], {opacity: 0.5, animated: true, offset: i / 3});
  }

  // 02: Java files -> package hierarchy -> source inventory.
  {
    const s = group();
    for (let i = 0; i < 5; i += 1) {
      const z = -0.1 + i * 0.09;
      const p = outlinePanel(s, [-2.65 + i * 0.14, (i - 2) * 0.12, z], [0.50, 0.69, 0.04], i === 4 ? 0.82 : 0.25);
      float(p, 0.024, 0.8, i);
      bars(s, -2.71 + i * 0.14, 0.12 + (i - 2) * 0.12, 3, 0.13, [0.20, 0.29, 0.16], basic(ASH, 0.48));
      if (i < 4) path(s, [[-1.8, (i - 2) * 0.26, 0], [-0.9, (i - 2) * 0.21, -0.1], [-0.45, (i - 2) * 0.11, 0]], {opacity: 0.3, animated: true, offset: i / 5});
    }
    const hierarchy = [[0.9, 0, -0.28], [1.45, 0.86, -0.05], [1.45, -0.86, -0.05], [2.17, 1.18, 0.1], [2.17, 0.54, 0.1], [2.17, -0.54, 0.1], [2.17, -1.18, 0.1], [2.95, 0.87, 0.04], [2.95, -0.87, 0.04]];
    [[0,1],[0,2],[1,3],[1,4],[2,5],[2,6],[4,7],[6,8]].forEach(([a,b]) => beam(s, hierarchy[a], hierarchy[b], {opacity: 0.52}));
    hierarchy.forEach((p, i) => i % 3 ? labelSpark(s, p, 0.037) : crystal(s, p, 0.09, surface(SILVER)));
  }

  // 03: OpenGrep candidate pattern scanner (not a confirmed vulnerability).
  {
    const s = group();
    for (let row = 0; row < 4; row += 1) {
      for (let col = 0; col < 4; col += 1) {
        const x = -2.75 + col * 0.56;
        const y = 1.04 - row * 0.68;
        outlinePanel(s, [x, y, -0.03], [0.39, 0.46, 0.06], row === 1 && col === 2 ? 0.95 : 0.28);
        box(s, [x, y + 0.08, 0.06], [0.24, 0.025, 0.01], basic(WHITE, 0.45));
      }
    }
    const light = box(s, [-2.80, 0, 0.34], [0.042, 2.68, 0.035], basic(WHITE, 0.94));
    const softLight = box(s, [-2.80, 0, 0.30], [0.22, 2.68, 0.025], basic(WHITE, 0.11));
    scanners.push({light, softLight});
    for (let row = 0; row < 3; row += 1) path(s, [[-0.48, (row - 1) * 0.65, 0], [0.16, (row - 1) * 0.21, 0], [1.7, (row - 1) * 0.23, -0.05], [2.7, 0, 0.06]], {opacity: 0.5, animated: true, offset: row / 3, speed: 0.31});
    torus(s, [2.58, 0, 0.1], 0.43, basic(WHITE, 0.75), [0, 0, 0], 0.012);
    torus(s, [2.58, 0, 0.1], 0.19, basic(ASH, 0.46), [0, 0, 0], 0.008);
    labelSpark(s, [2.58, 0, 0.11], 0.06);
  }

  // 04: method context -> source slices -> context window.
  {
    const s = group();
    for (let i = 0; i < 4; i += 1) {
      const y = 0.98 - i * 0.66;
      outlinePanel(s, [-2.47, y, 0], [0.84, 0.45, 0.055], 0.58);
      bars(s, -2.76, y + 0.10, 2, 0.15, [0.38, 0.55], basic(ASH, 0.66));
      path(s, [[-1.92, y, 0.08], [-1.15, y * 0.72, -0.05], [-0.56, y * 0.22, -0.10]], {opacity: 0.35, animated: i < 3, offset: i / 4});
    }
    for (let i = 0; i < 4; i += 1) {
      const x = 1.30 + i * 0.39;
      float(outlinePanel(s, [x, (i - 1.5) * 0.12, 0.08], [0.56, 1.40, 0.06], i === 1 ? 0.91 : 0.42), 0.029, 0.6, i);
      for (let j = 0; j < 4; j += 1) box(s, [x, 0.44 - j * 0.28 + (i - 1.5) * 0.12, 0.15], [0.25 + (j % 2) * 0.09, 0.03, 0.01], basic(SILVER, j === 1 ? 0.95 : 0.40));
    }
  }

  // 05: IRIS AST + semantic source-to-sink proof path.
  {
    const s = group();
    const ast = [[-2.50,1.20,0],[-2.72,0.42,0],[-1.90,0.44,0],[-2.93,-0.45,0],[-2.27,-0.45,0],[-1.61,-0.46,0],[-2.29,-1.18,0]];
    [[0,1],[0,2],[1,3],[1,4],[2,5],[4,6]].forEach(([a,b]) => beam(s, ast[a], ast[b], {opacity:0.47}));
    ast.forEach((point,i)=>i<3 ? crystal(s,point,0.09,surface(SILVER)) : labelSpark(s,point,0.045));
    const trace = [[0.61, 0, 0.06], [1.10, 0.64, 0], [1.62, 0.37, 0], [2.02, -0.43, 0], [2.70, 0, 0.12]];
    for(let i=0;i<trace.length-1;i++) beam(s, trace[i],trace[i+1],{opacity:0.87,animated:true,offset:i/5,speed:0.31});
    trace.forEach((p,i)=>i===0 || i===4 ? crystal(s,p,0.13,surface(WHITE)) : sphere(s,p,0.07,surface(SILVER)));
    torus(s, [2.70, 0, 0.12], 0.30, basic(WHITE, 0.7));
  }

  // 06: local Qwen LoRA semantic classification as a neural-layer topology.
  {
    const s = group();
    const cols = [-2.67,-1.66,1.72,2.62];
    const counts = [3,4,4,3];
    const positions = cols.map((x,col)=>Array.from({length:counts[col]},(_,i)=>[x,(i-(counts[col]-1)/2)*0.69,-0.18]));
    for(let col=0;col<cols.length-1;col++){
      positions[col].forEach((a,i)=>positions[col+1].forEach((b,j)=>{
        if((i+j)%2===0 || i===j) beam(s,a,b,{opacity:0.22,animated:col===1 && i===j,offset:(i+j)/8,speed:0.19});
      }));
    }
    positions.forEach((column,col)=>column.forEach((at,row)=>sphere(s,at,col===3 ? 0.083:0.071,surface(row===1 && col>=2 ? WHITE:ASH))));
    for(let i=0;i<4;i++){
      const len=[0.84,0.54,0.31,0.19][i];
      box(s,[2.18+len/2,1.39-i*0.15,0.30],[len,0.035,0.015],basic(SILVER,i===0?0.85:0.36));
    }
  }

  // 07: three evidence streams merge into one auditable decision context.
  {
    const s = group();
    const roots=[[-2.63,1.05,0],[-2.63,0,0],[-2.63,-1.05,0]];
    roots.forEach((at,i)=>{
      if(i===0) wire(s,0.4,0.4,0.4,at,0.8);
      else if(i===1) torus(s,at,0.18,basic(WHITE,0.82),[0,0,0],0.023);
      else crystal(s,at,0.23,surface(SILVER));
      path(s,[at,[-1.58,at[1]*0.82,0],[-0.8,at[1]*0.35,0],[-0.48,0,0]],{opacity:0.82,animated:true,offset:i/3,speed:0.3});
    });
    for(let i=0;i<3;i++){
      path(s,[[0.70,0,0],[1.28,(i-1)*0.19,0],[2.0,(i-1)*0.31,0]],{opacity:0.64,animated:true,offset:i/3});
      float(outlinePanel(s,[2.45+i*0.13,(i-1)*0.12,0.1],[1.18,0.75,0.065],0.6),0.018,0.7,i);
      bars(s,1.99+i*0.13,0.11+(i-1)*0.12,2,0.16,[0.52,0.39],basic(SILVER,0.49));
    }
  }

  // 08: 16-factor assessment wheel (no invented CWSS values).
  {
    const s = group();
    const wheel = new THREE.Group();
    s.add(wheel);
    for(let i=0;i<16;i++){
      const arc= Math.PI * 2/16 * 0.78;
      const segment = torus(wheel,[0,0,0],1.25,basic(i%4===0?WHITE:ASH,i%4===0?0.95:0.59),[0,0,(i/16)*Math.PI*2],0.036,arc);
      driven.push({mesh:segment,phase:i,kind:'metric'});
    }
    torus(wheel,[0,0,-0.04],1.46,basic(SILVER,0.20),[0.15,0,0],0.010);
    for(let i=0;i<5;i++){
      const h=[0.32,0.69,0.50,0.88,0.59][i];
      box(s,[-2.78+i*0.37,-0.94+h/2,0.18],[0.20,h,0.045],surface(i===3?WHITE:ASH,0.82));
      beam(s,[-2.84+i*0.37,0.48,0.11],[-2.74+i*0.37,0.48,0.11],{opacity:0.4});
    }
    for(let i=0;i<3;i++){
      outlinePanel(s,[2.46,0.79-i*0.78,0],[0.85,0.37,0.055],0.45+i*0.17);
      box(s,[2.39,0.79-i*0.78,0.08],[0.40,0.034,0.01],basic(WHITE,0.45+i*0.19));
    }
  }

  // 09: REPORT / REVIEW / SUPPRESS are triage decisions, not expert TP/FP labels.
  {
    const s = group();
    outlinePanel(s,[-2.55,0,0],[0.72,0.77,0.13],0.8);
    crystal(s,[-2.55,0.02,0.16],0.24,surface(WHITE));
    for(let i=0;i<3;i++){
      const y=0.99-i*0.99;
      path(s,[[-2.1,0,0],[-1.21,0,0],[0.70,0,0],[1.46,y*0.8,0],[2.13,y,0]],{opacity:0.76,animated:true,offset:i/3,speed:0.24});
      outlinePanel(s,[2.47,y,0],[0.72,0.56,0.08],0.76);
      if(i===0) bars(s,2.27,y+0.09,2,0.16,[0.35,0.22],basic(WHITE,0.82));
      if(i===1) torus(s,[2.46,y,0.10],0.15,basic(WHITE,0.78));
      if(i===2) beam(s,[2.31,y-0.11,0.13],[2.63,y+0.11,0.13],{opacity:0.88});
    }
  }

  // 10: report data, metric chart and final audit document.
  {
    const s = group();
    const heights=[0.42,0.67,0.96,0.72,1.18];
    heights.forEach((h,i)=>{
      const mesh=box(s,[-2.69+i*0.38,-0.87+h/2,0.08],[0.25,h,0.14],surface(i===4?WHITE:ASH,0.94));
      driven.push({mesh,phase:i,kind:'bar',height:h});
    });
    path(s,[[-2.67,0.0,0.22],[-1.70,0.53,0.22],[-0.52,0,0.02]],{opacity:0.60,animated:true});
    for(let i=0;i<4;i++){
      const x=2.10+i*0.095;
      const p=outlinePanel(s,[x,0.02,0.04],[1.10,1.50,0.08],i===3?0.95:0.33);
      float(p,0.02,0.55,i*0.5);
    }
    bars(s,1.77,0.48,5,0.23,[0.47,0.30,0.50,0.37,0.43],basic(SILVER,0.82));
    torus(s,[2.52,-0.69,0.17],0.14,basic(WHITE,0.80));
    beam(s,[0.66,0,0],[1.48,0,0],{opacity:0.82,animated:true,speed:0.22});
  }

  // A restrained central optical core persists through all stages.
  const core = new THREE.Group();
  core.position.z = 0.28;
  root.add(core);
  const coreShell = sphere(core,[0,0,0],0.46,surface('#b4b7bd'),32);
  sphere(core,[-0.12,0.15,0.31],0.12,basic(WHITE,0.22));
  const facets = new THREE.LineSegments(
    rememberGeo(new THREE.EdgesGeometry(rememberGeo(new THREE.IcosahedronGeometry(0.51,1)))),
    rememberMat(new THREE.LineBasicMaterial({color:WHITE,transparent:true,opacity:0.16,depthWrite:false}))
  );
  core.add(facets);
  const ring1 = torus(core,[0,0,0],0.84,basic(WHITE,0.88),[0.78,0.17,0.14],0.016);
  const ring2 = torus(core,[0,0,-0.05],1.14,basic(SILVER,0.38),[1.10,-0.35,-0.22],0.010);
  const ring3 = torus(core,[0,0,-0.22],1.42,basic(ASH,0.18),[0.25,0.82,0.25],0.008);
  const orbitDots = [];
  for(let i=0;i<11;i++){
    const angle=i/11*Math.PI*2;
    const at=[Math.cos(angle)*1.47,Math.sin(angle)*1.19,-0.27];
    const dot=sphere(root,at,i%3===0?0.044:0.028,basic(i%3===0?WHITE:ASH,0.88));
    orbitDots.push({dot,angle});
  }

  // P0.13: a strictly sequential handoff. The previous scene fades OUT
  // completely before the next scene fades IN. Never render two stage groups
  // at the same time, including when a user jumps through stages rapidly.
  const EXIT_SECONDS = 0.23;
  const ENTER_SECONDS = 0.40;
  const smoothstep = (value) => {
    const t = Math.max(0, Math.min(1, value));
    return t * t * (3 - 2 * t);
  };

  // Materials belong to exactly one stage group. Preserve their original
  // opacity and render mode, since many panels and beams are already translucent.
  const stageMaterials = stageGroups.map((stage) => {
    const entries = new Map();
    stage.traverse((object) => {
      const list = Array.isArray(object.material) ? object.material : [object.material];
      list.filter(Boolean).forEach((material) => {
        if (!entries.has(material)) {
          entries.set(material, {
            opacity: material.opacity ?? 1,
            transparent: Boolean(material.transparent),
            depthWrite: Boolean(material.depthWrite)
          });
        }
      });
    });
    return entries;
  });
  const alphaByStage = stageGroups.map(() => 0);
  let requestedPhase = -1;
  let transition = null;

  function applyStageOpacity(index, opacity, entering = false) {
    const alpha = Math.max(0, Math.min(1, opacity));
    alphaByStage[index] = alpha;
    const stage = stageGroups[index];
    stage.visible = alpha > 0.001;
    if (!stage.visible) return;
    // A small lateral glide is perceptible but does not disturb the static UI.
    stage.scale.setScalar(0.965 + 0.035 * alpha);
    stage.position.x = (entering ? 1 : -1) * (1 - alpha) * 0.12;
    stageMaterials[index].forEach((original, material) => {
      material.opacity = original.opacity * alpha;
      material.transparent = original.transparent || alpha < 0.999;
      material.depthWrite = original.depthWrite && alpha >= 0.999;
    });
  }

  function handoffTo(nextPhase, time) {
    // A new stage may be requested during either half of an earlier handoff.
    // Choose only the single *actually visible* group as the outgoing scene.
    const from = alphaByStage.findIndex((alpha) => alpha > 0.001);
    const fromAlpha = from < 0 ? 0 : alphaByStage[from];
    const same = from === nextPhase;
    transition = {
      from: same ? -1 : from,
      to: nextPhase,
      fromAlpha: same ? 0 : fromAlpha,
      toAlpha: same ? fromAlpha : 0,
      started: time,
      exitSeconds: same || from < 0 ? 0 : EXIT_SECONDS * fromAlpha
    };
    requestedPhase = nextPhase;
  }

  function updateHandoff(time, requested, reducedMotion) {
    if (requestedPhase === -1) {
      requestedPhase = requested;
      applyStageOpacity(requested, 1, true);
      return;
    }
    if (requested !== requestedPhase) handoffTo(requested, time);
    if (!transition || reducedMotion) {
      stageGroups.forEach((_, i) => applyStageOpacity(i, i === requested ? 1 : 0, true));
      transition = null;
      return;
    }
    const elapsed = Math.max(0, time - transition.started);
    const {from, to, fromAlpha, toAlpha, exitSeconds} = transition;
    // First half: no next-stage geometry is displayed.
    // Second half: the previous stage has zero opacity and is invisible.
    if (elapsed < exitSeconds) {
      stageGroups.forEach((_, i) => applyStageOpacity(
        i, i === from ? fromAlpha * (1 - smoothstep(elapsed / exitSeconds)) : 0, false
      ));
    } else {
      const amount = smoothstep((elapsed - exitSeconds) / ENTER_SECONDS);
      stageGroups.forEach((_, i) => applyStageOpacity(
        i, i === to ? toAlpha + (1 - toAlpha) * amount : 0, true
      ));
      if (amount >= 1) transition = null;
    }
  }

  return {
    update(time, delta, phase, reducedMotion) {
      const safe = Math.max(0, Math.min(9, Number.isInteger(phase) ? phase : 0));
      updateHandoff(time, safe, reducedMotion);

      const t=reducedMotion?0:time;
      core.rotation.y=reducedMotion?0:time*0.075;
      coreShell.rotation.y=reducedMotion?0:time*0.10;
      facets.rotation.y=reducedMotion?0:time*0.13;
      ring1.rotation.z=0.14+(reducedMotion?0:time*0.14);
      ring2.rotation.y=-0.35+(reducedMotion?0:time*0.075);
      ring3.rotation.z=0.25+(reducedMotion?0:-time*0.048);
      const pulse=reducedMotion?1:1+Math.sin(t*1.40)*0.018;
      core.scale.setScalar(pulse);
      orbitDots.forEach(({dot,angle},i)=>{
        dot.position.x=Math.cos(angle+(reducedMotion?0:time*0.025))*(1.49+(i%3)*0.05);
        dot.position.y=Math.sin(angle+(reducedMotion?0:time*0.025))*(1.18+(i%2)*0.05);
      });
      floaters.forEach(({mesh,amount,speed,phase:offset,y})=>{
        mesh.position.y=y+(reducedMotion?0:Math.sin(time*speed+offset)*amount);
      });
      packets.forEach(({dot,spline,speed,offset,parent})=>{
        if(!parent.visible) return;
        const p=(reducedMotion?offset:(time*speed+offset)%1);
        dot.position.copy(spline.getPointAt(p));
      });
      scanners.forEach(({light,softLight})=>{
        const x=reducedMotion?-1.9:-2.8+((time*0.38)%1)*2.52;
        light.position.x=x;softLight.position.x=x;
      });
      driven.forEach(({mesh,phase:i,kind,height})=>{
        if(kind==='metric') mesh.rotation.y=reducedMotion?0:Math.sin(time*0.40+i*0.25)*0.06;
        if(kind==='bar') {
          const amt=reducedMotion?1:0.88+Math.sin(time*1.05+i*0.77)*0.12;
          mesh.scale.y=amt;
          mesh.position.y=-0.87+(height*amt)/2;
        }
      });
    },
    dispose(){
      scene.remove(root);
      geometries.forEach((geo)=>geo.dispose());
      materials.forEach((mat)=>mat.dispose());
    }
  };
}
