"""Content-bound ext4 engine caches and bounded subprocess receipts."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import zipfile


def file_hash(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(4*1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def key(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def write_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.tmp-'+str(os.getpid()))
    temporary.write_text(json.dumps(value,indent=2));os.replace(temporary,path)


def run_process(argv,log,env,timeout_sec=600,max_rss_bytes=6*1024**3,cancel_event=None):
    import psutil
    started=time.monotonic();peak=0;cpu=0;read=write=0;io_supported=hasattr(psutil.Process,'io_counters')
    with Path(log).open('w') as output:
        process=subprocess.Popen(argv,stdout=output,stderr=subprocess.STDOUT,env=env,start_new_session=True)
        try:
            while process.poll() is None:
                if time.monotonic()-started>timeout_sec:raise TimeoutError('ENGINE_PROCESS_TIMEOUT')
                if cancel_event is not None and cancel_event.is_set():raise RuntimeError('IRIS_CANCELLED')
                try:
                    parent=psutil.Process(process.pid);tree=[parent,*parent.children(recursive=True)]
                    rss=0;cpu_now=0;read_now=write_now=0
                    for child in tree:
                        try:
                            rss+=child.memory_info().rss;t=child.cpu_times();cpu_now+=t.user+t.system
                            if io_supported:
                                io=child.io_counters();read_now+=io.read_bytes;write_now+=io.write_bytes
                        except psutil.Error:pass
                    peak=max(peak,rss);cpu=max(cpu,cpu_now);read=max(read,read_now);write=max(write,write_now)
                    if rss>max_rss_bytes:raise RuntimeError('ENGINE_PROCESS_TREE_RSS_LIMIT')
                except psutil.NoSuchProcess:pass
                time.sleep(.2)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGTERM)
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
            raise
    return {'argv':argv,'exit_code':process.returncode,'duration_ms':round((time.monotonic()-started)*1000,3),
            'peak_process_tree_rss_bytes':peak,'sampled_cpu_seconds_lower_bound':cpu,
            'sampled_read_bytes_lower_bound':read if io_supported else None,
            'sampled_write_bytes_lower_bound':write if io_supported else None,'disk_io_measurement_available':io_supported}


def verify_source_archive(database,source_root,manifest):
    """Require the real extractor's source archive to contain every input byte."""
    root=Path(source_root).resolve().as_posix().lstrip('/')+'/'
    with zipfile.ZipFile(Path(database)/'src.zip') as archive:
        names=set(archive.namelist())
        for relative,meta in manifest.items():
            name=root+relative
            if name not in names or hashlib.sha256(archive.read(name)).hexdigest()!=meta['sha256']:
                raise ValueError('CODEQL_EXTRACTION_SOURCE_ARCHIVE_MISMATCH:'+relative)
    if not (Path(database)/'db-java').is_dir():raise ValueError('CODEQL_JAVA_DATASET_MISSING')
    return {'java_files_archived_and_verified':len(manifest),'source_archive_sha256':file_hash(Path(database)/'src.zip'),
            'database_metadata_sha256':file_hash(Path(database)/'codeql-database.yml')}


def dependency_receipt(database):
    """Hash concrete Maven artifacts referenced by extraction logs when present.

    No descriptors/scripts from the scanned project enter staging. Unknown
    dependency completeness remains separate from engine execution status.
    """
    import re
    files={}
    for log in (Path(database)/'log').rglob('*.log'):
        for name in re.findall(r'(/[^\s"\[\]]+\.jar)',log.read_text(errors='replace')):
            path=Path(name.rstrip('),;'))
            if path.is_file():files[str(path.resolve())]=file_hash(path)
    return files


def database(root,source_root,manifest,identity,cli,java_home,env,timeout_sec,max_rss,cancel_event=None):
    """A separate DB key excludes model/query policy but includes extraction."""
    extractor=Path(cli).parent/'java/codeql-extractor.yml'
    db_identity={'source_identity':identity['source_identity'],'source_manifest':manifest,
        'codeql_version':identity['codeql_version'],'codeql_build':identity.get('codeql_build'),
        'extractor_sha256':file_hash(extractor),'java_home':java_home,
        'jdk_modules_sha256':file_hash(Path(java_home)/'lib/modules'),
        'mode':'JAVA_ONLY_NO_BUILD_NO_DESCRIPTORS_V1','xml':False,'properties':False,
        'dependency_policy':'PIN_EXTRACTED_DEPENDENCY_ARTIFACTS_NO_USER_BUILD_SCRIPTS'}
    entry=Path(root)/'databases'/key(db_identity);ready=entry/'ready.json';staged=entry/'java-source';db=entry/'database'
    entry.mkdir(parents=True,exist_ok=True)
    import fcntl
    with (entry/'build.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if ready.exists():
            receipt=json.loads(ready.read_text())
            if receipt['identity']!=db_identity:raise ValueError('DATABASE_CACHE_IDENTITY_MISMATCH')
            check=verify_source_archive(db,staged,manifest)
            if check!=receipt['archive_verification']:raise ValueError('DATABASE_CACHE_ARCHIVE_CHANGED')
            if any(not Path(p).is_file() or file_hash(p)!=sha for p,sha in receipt['resolved_dependencies'].items()):
                raise ValueError('DATABASE_CACHE_DEPENDENCY_CHANGED')
            return db,staged,{**receipt,'cache_hit':True,'actual_creation_duration_ms':0}
        if db.exists():raise ValueError('INCOMPLETE_DATABASE_CACHE_REQUIRES_SEPARATE_RETRY_DIRECTORY')
        staged.mkdir(exist_ok=True)
        for relative,meta in manifest.items():
            data=(Path(source_root)/relative).read_bytes()
            if hashlib.sha256(data).hexdigest()!=meta['sha256']:raise ValueError('SOURCE_CHANGED_BEFORE_EXTRACTION')
            target=staged/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        argv=[cli,'database','create',str(db),'--language=java','--build-mode=none','--source-root='+str(staged),
              '--search-path='+str(Path(cli).parent/'java'),'--threads=1','--ram=2048']
        process=run_process(argv,entry/'creation.log',env,timeout_sec,max_rss,cancel_event)
        if process['exit_code']:raise RuntimeError('CODEQL_DATABASE_CREATION_FAILED')
        receipt={'identity':db_identity,'database_id':key(db_identity),'database':str(db),
            'archive_verification':verify_source_archive(db,staged,manifest),'creation':process,
            'resolved_dependencies':dependency_receipt(db),'cache_hit':False,
            'actual_creation_duration_ms':process['duration_ms']}
        write_json(ready,receipt);return db,staged,receipt
