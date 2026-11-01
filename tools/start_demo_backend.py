"""Idempotent WSL demo startup. Never stop processes or replace scan databases."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / 'backend/ntk-production-v2/scripts/ntk_web_backend_service.py'


def health(port):
    try:
        with urlopen(f'http://127.0.0.1:{port}/api/health', timeout=3) as response:
            return json.load(response)
    except (OSError, ValueError):
        return None


def start(runtime, port, check_only=False):
    runtime = runtime.resolve()
    if not runtime.is_relative_to(ROOT / 'work'):
        raise ValueError('Demo runtime must be under this worktree/work; original runtime is never modified')
    config_path = runtime / 'launch-env.json'
    config = json.loads(config_path.read_text())
    required = ['NTK_STORAGE_DIR','NTK_EXT4_CACHE_DIR','NTK_BASE_MODEL_PATH','NTK_BEST_ADAPTER_PATH','NTK_DATASET_DIR','JAVA_HOME']
    for key in required:
        if not Path(config[key]).is_dir():
            raise ValueError(f'Missing directory: {key}')
    store = Path(config['NTK_STORAGE_DIR']).resolve()
    cache = Path(config['NTK_EXT4_CACHE_DIR']).resolve()
    if store != runtime / 'storage' or not cache.is_relative_to(runtime):
        raise ValueError('Configuration points outside the selected demo runtime')
    if not (store / 'SCAN-20261101164045-3AA266.json').is_file():
        raise ValueError('Accepted demo scan missing; refusing to create an empty/replacement store')
    if not list(store.rglob('*.sqlite3')):
        raise ValueError('Existing demo assessment databases missing; refusing replacement')
    if not (Path(config['NTK_BEST_ADAPTER_PATH']) / 'adapter_config.json').is_file():
        raise ValueError('LoRA checkpoint is incomplete')
    java = subprocess.run([str(Path(config['JAVA_HOME'])/'bin/java'),'-version'],capture_output=True,text=True,timeout=10)
    if java.returncode or 'version "17.' not in java.stderr + java.stdout:
        raise ValueError('A working JDK 17 is required')
    pid_path = runtime / 'backend.pid'
    pid = int(pid_path.read_text().strip()) if pid_path.exists() else None
    proc_path = Path('/proc') / str(pid) if pid else None
    own_live_pid = False
    if proc_path and proc_path.exists():
        argv = (proc_path/'cmdline').read_bytes().decode().split('\0')
        own_live_pid = str(SERVICE) in argv and '--port' in argv and argv[argv.index('--port')+1] == str(port)
        if not own_live_pid:
            raise ValueError('PID file belongs to another live process; refusing to signal or overwrite it')
    current = health(port)
    if current:
        if current.get('service') != 'ntk-iris-local-sast-backend' or Path(current.get('persistent_storage_dir','')).resolve() != store:
            raise ValueError('Port already serves another backend/runtime; refusing replacement')
        print(json.dumps({'status':'EXISTING','port':port,'pid':pid,'storage':str(store),'database_replaced':False}))
        return
    if check_only:
        raise RuntimeError('Backend is not healthy; check-only does not start services')
    if own_live_pid:
        raise RuntimeError('Identified backend process is alive but unhealthy; no duplicate or automatic restart')
    with socket.socket() as probe:
        if probe.connect_ex(('127.0.0.1',port)) == 0:
            raise RuntimeError('Port is occupied; refusing to replace its owner')
    env = dict(os.environ)
    allowed = set(required) | {'NTK_JAVAC_BIN','NTK_INFERENCE_DEVICE','HF_HUB_OFFLINE','TRANSFORMERS_OFFLINE'}
    env.update({key:str(value) for key,value in config.items() if key in allowed})
    env.update(PYTHONDONTWRITEBYTECODE='1',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1')
    env['PATH'] = str(Path(config['JAVA_HOME'])/'bin') + ':' + env.get('PATH','')
    with (runtime/'backend-demo.log').open('ab') as log:
        process = subprocess.Popen([sys.executable,'-B','-u',str(SERVICE),'--serve-http','--port',str(port)],
            cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    pid_path.write_text(str(process.pid)+'\n')
    deadline = time.monotonic()+30
    while time.monotonic()<deadline:
        if process.poll() is not None:
            raise RuntimeError(f'Backend exited {process.returncode}; inspect backend-demo.log')
        current=health(port)
        if current and current.get('status')=='OK':
            if Path(current['persistent_storage_dir']).resolve()!=store:
                raise RuntimeError('Unexpected runtime on the requested port')
            print(json.dumps({'status':'STARTED','port':port,'pid':process.pid,'storage':str(store),'database_replaced':False}))
            return
        time.sleep(.25)
    raise RuntimeError('Backend startup timed out; process retained for inspection, no destructive retry')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir',type=Path,default=ROOT/'work/acceptance/runtime')
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--check-only',action='store_true')
    args=parser.parse_args()
    try:
        # Serialise launcher invocations; this lock never locks/replaces SQLite.
        with (args.runtime_dir/'demo-start.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            start(args.runtime_dir,args.port,args.check_only)
    except (OSError, ValueError, RuntimeError) as error:
        print('DEMO_BACKEND_ERROR='+str(error),file=sys.stderr)
        raise SystemExit(1)
