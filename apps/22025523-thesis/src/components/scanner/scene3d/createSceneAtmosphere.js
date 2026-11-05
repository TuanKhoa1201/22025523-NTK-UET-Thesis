/* Near-black architectural grid, silver optical trails and restrained glints. */
const WHITE = '#ffffff';
export function createSceneAtmosphere(THREE, scene) {
  const root = new THREE.Group();
  scene.add(root);
  const geometries = new Set();
  const materials = new Set();
  const textures = new Set();
  const rememberGeo = (item) => { geometries.add(item); return item; };
  const rememberMat = (item) => { materials.add(item); return item; };
  const rememberTex = (item) => { textures.add(item); return item; };

  const basicLine = (opacity) => rememberMat(new THREE.LineBasicMaterial({
    color: '#f5f5f7', transparent: true, opacity, depthWrite: false
  }));
  const track = (coords, opacity = 0.35) => {
    const spline = new THREE.CatmullRomCurve3(coords.map((pos) => new THREE.Vector3(...pos)));
    const geo = rememberGeo(new THREE.BufferGeometry().setFromPoints(spline.getPoints(85)));
    const line = new THREE.Line(geo, basicLine(opacity));
    root.add(line);
    return spline;
  };

  // Technical drawing underlay, deliberately quiet behind the actual geometry.
  const grid = [];
  for (let x = -3.6; x <= 3.61; x += 0.42) {
    grid.push(new THREE.Vector3(x, -1.88, -2.45), new THREE.Vector3(x, 1.88, -2.45));
  }
  for (let y = -1.88; y <= 1.89; y += 0.42) {
    grid.push(new THREE.Vector3(-3.65, y, -2.45), new THREE.Vector3(3.65, y, -2.45));
  }
  root.add(new THREE.LineSegments(
    rememberGeo(new THREE.BufferGeometry().setFromPoints(grid)), basicLine(0.11)
  ));
  const strongAxis = [];
  [-1.26, 0, 1.26].forEach((x) => strongAxis.push(
    new THREE.Vector3(x, -1.83, -2.40), new THREE.Vector3(x, 1.83, -2.40)
  ));
  root.add(new THREE.LineSegments(
    rememberGeo(new THREE.BufferGeometry().setFromPoints(strongAxis)), basicLine(0.10)
  ));

  const rings = [];
  [
    [1.47, [0.19, 0.31, 0.0], 0.29],
    [1.82, [1.02, 0.08, -0.22], 0.20],
    [2.13, [0.30, 0.77, 0.24], 0.16]
  ].forEach(([radius, rotation, opacity], index) => {
    const ring = new THREE.Mesh(
      rememberGeo(new THREE.TorusGeometry(radius, index === 0 ? 0.008 : 0.006, 6, 140)),
      rememberMat(new THREE.MeshBasicMaterial({
        color: index === 0 ? WHITE : '#a6a9b1',
        opacity, transparent: true, depthWrite: false
      }))
    );
    ring.rotation.set(...rotation);
    ring.position.z = -0.9 - index * 0.18;
    root.add(ring);
    rings.push(ring);
  });

  // Fine glints at the ends of the scene are optical, not extra interface controls.
  track([[-3.95, -1.58, -2.14], [-3.35,-1.32,-2.05], [-2.1,-1.64,-2.0], [0.1,-1.92,-2.03], [2.4,-1.63,-2.02], [3.9,-1.40,-2.14]], 0.14);
  track([[-3.88,1.56,-2.10],[-2.3,1.88,-2.09],[-0.40,2.06,-2.02],[2.15,1.78,-2.06],[3.83,1.56,-2.10]],0.12);
  track([[-3.68, -1.74, -2.25], [-2.1, -1.35, -2.11], [0.22,-1.76,-2.17], [2.5,-1.53,-2.25], [3.63,-1.82,-2.20]],0.07);

  const dots = [];
  const count = 65;
  const base = new Float32Array(count * 3);
  for(let i=0;i<count;i++){
    base[i*3] = ((i*53)%127)/18 - 3.5;
    base[i*3+1] = ((i*67)%113)/30 - 1.9;
    base[i*3+2] = -2 + ((i*11)%21)/35;
  }
  const pointsGeo = rememberGeo(new THREE.BufferGeometry());
  const pointAttr = new THREE.BufferAttribute(base.slice(), 3);
  pointsGeo.setAttribute('position', pointAttr);
  root.add(new THREE.Points(pointsGeo, rememberMat(new THREE.PointsMaterial({
    color:'#e8e9ed', size:0.018, transparent:true, opacity:0.44,
    sizeAttenuation:true, depthWrite:false
  }))));
  const dotMat = rememberMat(new THREE.MeshBasicMaterial({color:WHITE}));
  const nodeGeo = rememberGeo(new THREE.SphereGeometry(0.029,10,8));
  for(let i=0;i<23;i++){
    const theta=i/23*Math.PI*2;
    const point = new THREE.Mesh(nodeGeo,dotMat);
    point.position.set(Math.cos(theta)*2.48, Math.sin(theta)*1.58, -1.18);
    root.add(point);
    dots.push({point,theta});
  }

  // Lightweight radial opacity texture for carefully positioned specular glints.
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = 64;
  const ctx = canvas.getContext('2d');
  if (ctx) {
    const gradient = ctx.createRadialGradient(32,32,0,32,32,32);
    gradient.addColorStop(0,'rgba(255,255,255,0.87)');
    gradient.addColorStop(0.10,'rgba(255,255,255,0.47)');
    gradient.addColorStop(0.35,'rgba(255,255,255,0.10)');
    gradient.addColorStop(1,'rgba(255,255,255,0)');
    ctx.fillStyle = gradient;
    ctx.fillRect(0,0,64,64);
  }
  const glintTexture = rememberTex(new THREE.CanvasTexture(canvas));
  const glintMaterials = [0.23,0.16,0.17,0.14].map((opacity)=>rememberMat(new THREE.SpriteMaterial({
    map:glintTexture, color:WHITE, transparent:true, opacity,
    blending:THREE.AdditiveBlending, depthWrite:false
  })));
  const glints = [];
  [[-2.98,-1.45,-1.63],[2.45,1.55,-1.58],[0.65,1.73,-1.55],[2.82,-1.52,-1.64]]
    .forEach((at,i)=>{
      const sprite = new THREE.Sprite(glintMaterials[i]);
      sprite.position.set(...at);
      sprite.scale.setScalar(i===0?0.82:0.55);
      root.add(sprite);
      glints.push(sprite);
    });

  const flow = [];
  const flowPaths = [
    track([[-3.35,-0.13,-1.02],[-2.19,0.17,-1.18],[-0.98,-0.22,-1.05],[-0.3,0.0,-1.0]],0.16),
    track([[0.47,0.0,-1.0],[1.46,0.23,-1.06],[2.54,-0.11,-1.16],[3.35,0.08,-1.0]],0.16)
  ];
  const flowGeometry = rememberGeo(new THREE.SphereGeometry(0.028, 7, 7));
  for(let i=0;i<6;i++){
    const obj = new THREE.Mesh(flowGeometry,dotMat);
    root.add(obj);
    flow.push({obj,spline:flowPaths[i%2], offset:(i%3)/3});
  }

  return {
    update(time, delta, reducedMotion){
      const moving = !reducedMotion;
      if(moving){
        rings[0].rotation.z += delta*0.026;
        rings[1].rotation.x -= delta*0.014;
        rings[2].rotation.y += delta*0.018;
      }
      const positions=pointAttr.array;
      for(let i=0;i<count;i++){
        positions[i*3+1]=base[i*3+1]+(moving?Math.sin(time*0.35+i*0.79)*0.035:0);
      }
      pointAttr.needsUpdate = true;
      dots.forEach(({point,theta},i)=>{
        const rad=theta+(moving?time*0.014:0);
        point.position.x=Math.cos(rad)*(2.45+(i%3)*0.05);
        point.position.y=Math.sin(rad)*(1.55+(i%2)*0.06);
        point.scale.setScalar(moving?0.84+0.16*(1+Math.sin(time*0.9+i)):1);
      });
      glints.forEach((sprite,i)=>{
        sprite.material.opacity=moving?0.13+Math.max(0,Math.sin(time*0.54+i*2.1))*0.15:0.18;
      });
      flow.forEach(({obj,spline,offset})=>{
        obj.position.copy(spline.getPointAt(moving?(time*0.10+offset)%1:offset));
      });
    },
    dispose(){
      scene.remove(root);
      geometries.forEach((item)=>item.dispose());
      materials.forEach((item)=>item.dispose());
      textures.forEach((item)=>item.dispose());
    }
  };
}
