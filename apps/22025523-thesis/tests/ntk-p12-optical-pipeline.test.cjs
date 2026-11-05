const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {test} = require('node:test');
const {createHash} = require('node:crypto');

const root = path.resolve(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');

test('P0.12 is imported after optical contrast without changing existing page layout', () => {
  const entry = read('src/main.jsx');
  assert.ok(entry.indexOf('ntk-p11-optical-contrast.css') < entry.indexOf('ntk-p12-pipeline-optical.css'));
  const theme = read('src/styles/ntk-p12-pipeline-optical.css');
  assert.match(theme, /\.guided-visual\.visual-3d/);
  assert.doesNotMatch(theme, /\.sidebar\s*\{|\.main-area\s*\{|\.guided-layout\s*\{/);
  assert.match(read('src/components/scanner/SecurityAnalysisScene.jsx'), /<ScanStageVisual/);
});

test('real Three.js scene remains frontend-only and follows stage without simulated scan outcomes', () => {
  const scene = read('src/components/scanner/scene3d/createScanScene.js');
  const view = read('src/components/scanner/scene3d/Scene3D.jsx');
  assert.equal((scene.match(/const s = group\(\);/g) || []).length, 10);
  assert.match(scene, /updateHandoff/);
  assert.match(scene, /EXIT_SECONDS/);
  assert.match(scene, /ENTER_SECONDS/);
  assert.match(scene, /getPointAt/);
  assert.match(view, /webglcontextlost/);
  assert.match(view, /prefers-reduced-motion/);
  assert.match(view, /ACESFilmicToneMapping/);
  assert.doesNotMatch(scene, /#(?:48d7ff|a48bff|ff6474|46dfaa)/i);
  assert.doesNotMatch(scene, /92\.4\s*\/\s*100|PASS\s*≥\s*90/);
  assert.match(read('src/components/scanner/ScanStageVisual.jsx'), /liveCounts/);
});

test('Chrome tab uses the original UET identity and a short dash', () => {
  const html = read('index.html');
  assert.match(html, /href="\/favicon\.ico\?v=p13"/);
  assert.match(html, /href="\/favicon-32x32\.png\?v=p13"/);
  assert.match(html, /<title>22025523 - Phân tích bảo mật mã nguồn<\/title>/);
  assert.doesNotMatch(html, /greta-preview\.s3/);
  const original = fs.readFileSync(path.join(root,'public/uet-logo-original.png'));
  assert.equal(createHash('sha256').update(original).digest('hex'),
    'e5d475d3ac57bace5559eb903cb18c8835f7ff9bc7251b5b391cb66a6f8911ca');
  for (const file of ['favicon.ico','favicon-32x32.png','apple-touch-icon.png','uet-icon-192.png','manifest.webmanifest']) {
    assert.ok(fs.statSync(path.join(root,'public',file)).size > 0,file);
  }
});

test('the ten stage objects can be created, updated and disposed using Three.js shape contracts', async () => {
  class Vector3 {
    constructor(x=0,y=0,z=0) {this.set(x,y,z);}
    set(x=0,y=0,z=0){this.x=x;this.y=y;this.z=z;return this;}
    copy(v){return this.set(v.x,v.y,v.z);}
  }
  class Euler {set(x,y,z){this.x=x;this.y=y;this.z=z;}}
  class Scale {setScalar(v){this.x=v;this.y=v;this.z=v;}}
  class Object3D {
    constructor(){this.children=[];this.position=new Vector3();this.rotation=new Euler();this.scale=new Scale();this.visible=true;}
    add(...items){this.children.push(...items);}
    remove(...items){this.children=this.children.filter(v=>!items.includes(v));}
    traverse(cb){cb(this);this.children.forEach(child=>child.traverse?.(cb));}
  }
  class Geometry {dispose(){} setFromPoints(){return this;} setAttribute(){return this;}}
  class Material {constructor(options={}){Object.assign(this,options);} dispose(){}}
  class Mesh extends Object3D {constructor(geometry,material){super();this.geometry=geometry;this.material=material;}}
  class CatmullRomCurve3 {
    constructor(pts){this.pts=pts;}
    getPointAt(t){const k=Math.min(this.pts.length-2,Math.floor(t*(this.pts.length-1)));const s=t*(this.pts.length-1)-k;const a=this.pts[k],b=this.pts[k+1];return new Vector3(a.x+(b.x-a.x)*s,a.y+(b.y-a.y)*s,a.z+(b.z-a.z)*s);}
    getPoints(n){return Array.from({length:n+1},(_,i)=>this.getPointAt(i/n));}
  }
  const fake = {
    Group:Object3D,Vector3,Mesh,Line:Mesh,LineSegments:Mesh,Points:Mesh,Sprite:Mesh,
    BoxGeometry:Geometry,EdgesGeometry:Geometry,SphereGeometry:Geometry,OctahedronGeometry:Geometry,
    TorusGeometry:Geometry,TubeGeometry:Geometry,BufferGeometry:Geometry,IcosahedronGeometry:Geometry,
    MeshBasicMaterial:Material,MeshPhysicalMaterial:Material,LineBasicMaterial:Material,PointsMaterial:Material,
    SpriteMaterial:Material,CatmullRomCurve3,DoubleSide:2,AdditiveBlending:1,
    BufferAttribute:class {constructor(array){this.array=array;}},
    CanvasTexture:class {dispose(){} }
  };
  const moduleURL = pathToFileURL(path.join(root,'src/components/scanner/scene3d/createScanScene.js')).href;
  const {createScanScene} = await import(moduleURL);
  const scene = new Object3D();
  const visual = createScanScene(fake,scene);
  assert.equal(scene.children.length,1);
  const groups = scene.children[0].children.filter(x=>x instanceof Object3D && x.visible===false);
  assert.equal(groups.length,10);
  const onlyOne = (message) => assert.ok(groups.filter(g=>g.visible).length <= 1,message);
  for(let stage=0;stage<10;stage++){
    visual.update(1.3+stage,0.016,stage,false); onlyOne('first frame: no scene overlap');
    visual.update(1.5+stage,0.016,stage,false); onlyOne('exit frame: no scene overlap');
    visual.update(2.0+stage,0.016,stage,false); onlyOne('entry frame: no scene overlap');
    visual.update(2.1+stage,0.016,stage,true); onlyOne('reduced-motion frame: no scene overlap');
  }
  // Rapid phase jumps and rewind must not leave stale previous objects alive.
  visual.update(25.00,0.016,9,false); onlyOne('final scene');
  visual.update(25.03,0.016,0,false); onlyOne('rewind start');
  visual.update(25.09,0.016,4,false); onlyOne('interrupt while exiting');
  visual.update(25.24,0.016,2,false); onlyOne('another interrupted handoff');
  visual.update(26.00,0.016,2,false); onlyOne('handoff has settled');
  assert.equal(groups.findIndex(g=>g.visible),2);
  visual.update(26.05,0.016,9,true);
  assert.equal(groups.findIndex(g=>g.visible),9);
  visual.dispose();
  assert.equal(scene.children.length,0);
});
