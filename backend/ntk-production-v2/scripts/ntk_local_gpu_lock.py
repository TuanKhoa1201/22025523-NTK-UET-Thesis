"""One local Qwen generation at a time across NTK and IRIS processes (WSL)."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import tempfile


@contextmanager
def gpu_inference_lock():
    if os.name!='posix':
        yield
        return
    import fcntl
    path=Path(tempfile.gettempdir())/('ntk-qwen-gpu-'+str(os.getuid())+'.lock')
    descriptor=os.open(path,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        info=os.fstat(descriptor)
        if info.st_uid!=os.getuid() or not stat.S_ISREG(info.st_mode):raise RuntimeError('UNTRUSTED_GPU_LOCK_FILE')
        fcntl.flock(descriptor,fcntl.LOCK_EX)
        try:yield
        finally:fcntl.flock(descriptor,fcntl.LOCK_UN)
    finally:os.close(descriptor)
