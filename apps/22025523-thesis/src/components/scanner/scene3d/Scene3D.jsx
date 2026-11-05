import {useEffect, useRef} from 'react';
import * as THREE from 'three';
import {createScanScene} from './createScanScene';
import {createSceneAtmosphere} from './createSceneAtmosphere';

export default function Scene3D({phase, onFailure}) {
  const canvasRef = useRef(null);
  const phaseRef = useRef(phase);
  const failureRef = useRef(onFailure);

  phaseRef.current = phase;
  failureRef.current = onFailure;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;

    let renderer;
    let scanScene;
    let atmosphere;
    let resizeObserver;
    let resizeHandler;
    let frameId = 0;
    let stopped = false;
    let failureReported = false;
    let previousTime = 0;

    const reportFailure = (error) => {
      if (failureReported) return;
      failureReported = true;
      stopped = true;
      window.cancelAnimationFrame(frameId);
      if (import.meta.env.DEV) {
        console.error('[Scanner Three.js] Renderer failure:', error);
        console.error('[Scanner Three.js] Stack:', error?.stack || '(no stack available)');
      }
      failureRef.current?.(error);
    };

    const handleContextLost = (event) => {
      event.preventDefault();
      reportFailure(new Error('WebGL context lost on scanner canvas.'));
    };

    const handleWindowError = (event) => {
      if (!import.meta.env.DEV) return;
      console.error('[Scanner diagnostic] Window error:', event.message, event.error?.stack || event.filename);
    };

    const handleRejection = (event) => {
      if (!import.meta.env.DEV) return;
      console.error('[Scanner diagnostic] Unhandled rejection:', event.reason?.stack || event.reason);
    };

    window.addEventListener('error', handleWindowError);
    window.addEventListener('unhandledrejection', handleRejection);
    canvas.addEventListener('webglcontextlost', handleContextLost);

    try {
      renderer = new THREE.WebGLRenderer({
        canvas,
        antialias: true,
        alpha: false,
        powerPreference: 'high-performance',
        failIfMajorPerformanceCaveat: false
      });
      renderer.setPixelRatio(Math.min(2, Math.max(1.5, window.devicePixelRatio || 1)));
      renderer.setClearColor('#030305', 1);
      renderer.outputColorSpace = THREE.SRGBColorSpace;
      renderer.toneMapping = THREE.ACESFilmicToneMapping;
      renderer.toneMappingExposure = 1.28;

      const scene = new THREE.Scene();
      scene.background = new THREE.Color('#030305');

      const camera = new THREE.PerspectiveCamera(39, 1, 0.1, 80);
      camera.position.set(0, 0, 7.45);
      camera.lookAt(0, 0, -0.1);

      scene.add(new THREE.AmbientLight(0xffffff, 0.72));
      const keyLight = new THREE.DirectionalLight(0xffffff, 2.10);
      keyLight.position.set(-3, 5, 6);
      scene.add(keyLight);
      const rimLight = new THREE.DirectionalLight(0xf0f0f5, 1.05);
      rimLight.position.set(3, -2, -2);
      scene.add(rimLight);
      const fillLight = new THREE.DirectionalLight(0xc0c2cc, 0.55);
      fillLight.position.set(3, 0, 5);
      scene.add(fillLight);

      atmosphere = createSceneAtmosphere(THREE, scene);
      scanScene = createScanScene(THREE, scene);

      const resize = () => {
        if (stopped) return;
        const bounds = canvas.getBoundingClientRect();
        const width = Math.max(1, Math.floor(bounds.width));
        const height = Math.max(1, Math.floor(bounds.height));
        renderer.setSize(width, height, false);
        camera.aspect = width / height;
        camera.position.z = camera.aspect < 1.15 ? 10.1 : camera.aspect < 1.4 ? 8.65 : 7.45;
        camera.updateProjectionMatrix();
      };

      if ('ResizeObserver' in window) {
        resizeObserver = new ResizeObserver(resize);
        resizeObserver.observe(canvas);
      } else {
        resizeHandler = resize;
        window.addEventListener('resize', resizeHandler);
      }
      resize();

      if (import.meta.env.DEV) {
        const context = renderer.getContext();
        console.info('[Scanner Three.js] Renderer created', {
          version: THREE.REVISION,
          context: context.getParameter(context.VERSION),
          canvas: `${canvas.width}x${canvas.height}`,
          renderLoop: 'single persistent canvas'
        });
      }

      const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
      const renderFrame = (time) => {
        if (stopped) return;
        const delta = previousTime ? Math.min((time - previousTime) / 1000, 0.05) : 0;
        previousTime = time;

        try {
          atmosphere.update(time / 1000, delta, reducedMotion.matches);
          scanScene.update(time / 1000, delta, phaseRef.current, reducedMotion.matches);
          renderer.render(scene, camera);
          frameId = window.requestAnimationFrame(renderFrame);
        } catch (error) {
          reportFailure(error);
        }
      };

      frameId = window.requestAnimationFrame(renderFrame);
    } catch (error) {
      reportFailure(error);
    }

    return () => {
      stopped = true;
      window.cancelAnimationFrame(frameId);
      window.removeEventListener('error', handleWindowError);
      window.removeEventListener('unhandledrejection', handleRejection);
      canvas.removeEventListener('webglcontextlost', handleContextLost);
      if (resizeHandler) window.removeEventListener('resize', resizeHandler);
      resizeObserver?.disconnect();
      scanScene?.dispose();
      atmosphere?.dispose();
      renderer?.dispose();
    };
  }, []);

  return (
    <div className="scene3d-canvas">
      <canvas
        ref={canvasRef}
        aria-label={`Mô hình 3D mô phỏng bước phân tích ${phase + 1}`}
      />
    </div>
  );
}