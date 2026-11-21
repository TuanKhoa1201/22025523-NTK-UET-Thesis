"""Safe Java source intake for GitHub repositories and ZIP archives.

Defends against:
- Command / Git option injection (never invokes a shell; strict URL/SHA validation; `--` separator)
- Path traversal (`..`, absolute paths, drive letters, NTFS alternate data streams, reserved names)
- Symlink / junction escape (blocks symlinks in ZIP headers and post-extraction filesystem walks)
- ZIP bombs (enforces archive size, entry count, compression ratio, and streamed byte counters)
- Non-Java or oversized source inputs (enforces <=1 MB UTF-8 Java files matching v2.triage.evidence)
"""
from __future__ import annotations

import io
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit
import zipfile

from v2.api.config import IntakeLimits
from v2.triage.evidence import digest

_GITHUB_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
_COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


class IntakeError(ValueError):
    def __init__(self, error_code: str, message: str, *, http_status: int = 400, details: dict | None = None):
        super().__init__(message)
        self.error_code = error_code
        self.http_status = http_status
        self.details = dict(details or {})

    def to_dict(self) -> dict:
        payload = {
            "error_code": self.error_code,
            "error_message": str(self),
        }
        if self.details:
            payload["details"] = self.details
        return payload


def validate_github_url(raw_url: str, commit_sha: str | None = None) -> tuple[str, str, str, str | None]:
    """Validate and canonicalize a public GitHub HTTPS URL without shell/option hazards."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise IntakeError("INVALID_GITHUB_URL", "Liên kết GitHub không được để trống.")
    cleaned = raw_url.strip()
    if len(cleaned) > 300 or any(ord(ch) < 32 or ch.isspace() for ch in cleaned):
        raise IntakeError("INVALID_GITHUB_URL", "Liên kết GitHub chứa ký tự điều khiển hoặc khoảng trắng không hợp lệ.")
    parsed = urlsplit(cleaned)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise IntakeError("INVALID_GITHUB_URL", "Chỉ chấp nhận kho mã nguồn HTTPS công khai trên github.com.")
    if parsed.username or parsed.password or parsed.port is not None or parsed.query or parsed.fragment:
        raise IntakeError("INVALID_GITHUB_URL", "Liên kết GitHub không được chứa thông tin xác thực, cổng, query hoặc fragment.")
    if "\\" in parsed.path or "//" in parsed.path.lstrip("/"):
        raise IntakeError("INVALID_GITHUB_URL", "Đường dẫn kho GitHub không hợp lệ.")

    parts = [seg for seg in parsed.path.split("/") if seg]
    if len(parts) != 2:
        raise IntakeError("INVALID_GITHUB_URL", "Liên kết GitHub phải có dạng https://github.com/<owner>/<repo>.")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if (
        not owner
        or not repo
        or owner in (".", "..")
        or repo in (".", "..")
        or owner.startswith("-")
        or repo.startswith("-")
        or not _GITHUB_SEGMENT_RE.fullmatch(owner)
        or not _GITHUB_SEGMENT_RE.fullmatch(repo)
    ):
        raise IntakeError("INVALID_GITHUB_URL", "Tên chủ sở hữu hoặc tên repository GitHub không hợp lệ.")

    validated_sha = None
    if commit_sha is not None and str(commit_sha).strip():
        sha_str = str(commit_sha).strip()
        if not _COMMIT_SHA_RE.fullmatch(sha_str):
            raise IntakeError("INVALID_COMMIT_SHA", "Commit SHA phải gồm 7–40 ký tự thập lục phân.")
        validated_sha = sha_str.lower()

    canonical_url = f"https://github.com/{owner}/{repo}"
    return canonical_url, owner, repo, validated_sha


def _validate_relative_member_path(raw_name: str) -> PurePosixPath:
    if not isinstance(raw_name, str) or not raw_name or "\x00" in raw_name:
        raise IntakeError("ZIP_PATH_TRAVERSAL", "Tệp ZIP chứa đường dẫn rỗng hoặc ký tự null.")
    if any(ord(ch) < 32 for ch in raw_name):
        raise IntakeError("ZIP_PATH_TRAVERSAL", "Tệp ZIP chứa ký tự điều khiển trong tên tệp.")
    if raw_name.startswith(("/", "\\")) or "\\" in raw_name or ":" in raw_name:
        raise IntakeError("ZIP_PATH_TRAVERSAL", f"Tệp ZIP chứa đường dẫn tuyệt đối hoặc ký tự không an toàn: {raw_name!r}")
    posix = PurePosixPath(raw_name)
    parts = posix.parts
    if not parts or len(parts) > 32:
        raise IntakeError("ZIP_PATH_TRAVERSAL", "Đường dẫn trong tệp ZIP vượt quá độ sâu cho phép.")
    for part in parts:
        if part in ("", ".", ".."):
            raise IntakeError("ZIP_PATH_TRAVERSAL", f"Phát hiện path traversal trong tệp ZIP: {raw_name!r}")
        if len(part) > 180 or part.endswith((" ", ".")):
            raise IntakeError("ZIP_PATH_TRAVERSAL", f"Tên mục trong tệp ZIP không hợp lệ trên Windows: {part!r}")
        stem = part.split(".", 1)[0].upper()
        if stem in _WINDOWS_RESERVED:
            raise IntakeError("ZIP_PATH_TRAVERSAL", f"Tên thiết bị hệ thống bị cấm trong tệp ZIP: {part!r}")
    return posix


def _is_zip_symlink_or_special(info: zipfile.ZipInfo) -> bool:
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    if unix_mode:
        file_type = stat.S_IFMT(unix_mode)
        if file_type == stat.S_IFLNK:
            return True
        if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
            return True
    # Windows FILE_ATTRIBUTE_REPARSE_POINT (0x400) in low byte/word
    dos_attrs = info.external_attr & 0xFFFF
    if dos_attrs & 0x0400:
        return True
    return False


def verify_extracted_java_tree(source_root: Path, limits: IntakeLimits, *, empty_code: str = "NO_JAVA_FILES_FOUND") -> dict:
    """Verify an extracted/cloned directory has safe regular files and valid <=1MB UTF-8 Java files."""
    resolved_root = Path(source_root).resolve(strict=True)
    if not resolved_root.is_dir():
        raise IntakeError("INVALID_SOURCE_TREE", "Thư mục mã nguồn không tồn tại.")

    def _walk_err(exc: OSError) -> None:
        raise IntakeError("SOURCE_TREE_IO_ERROR", f"Không thể duyệt cây thư mục mã nguồn: {exc}") from exc

    total_files = 0
    total_bytes = 0
    java_hashes: dict[str, str] = {}
    non_java_files = 0

    for parent, dirs, files in os.walk(resolved_root, topdown=True, followlinks=False, onerror=_walk_err):
        parent_path = Path(parent)
        for dname in dirs:
            dpath = parent_path / dname
            if dpath.is_symlink() or (hasattr(dpath, "is_junction") and dpath.is_junction()):
                raise IntakeError("SYMLINK_ESCAPE_DETECTED", f"Thư mục nguồn chứa liên kết tượng trưng/junction bị cấm: {dname}")
            resolved_dir = dpath.resolve(strict=True)
            if not resolved_dir.is_relative_to(resolved_root):
                raise IntakeError("SYMLINK_ESCAPE_DETECTED", f"Thư mục nguồn thoát khỏi gốc cho phép: {dname}")
        for fname in files:
            fpath = parent_path / fname
            if fpath.is_symlink() or (hasattr(fpath, "is_junction") and fpath.is_junction()):
                raise IntakeError("SYMLINK_ESCAPE_DETECTED", f"Tệp nguồn là liên kết tượng trưng bị cấm: {fname}")
            resolved_file = fpath.resolve(strict=True)
            if not resolved_file.is_relative_to(resolved_root) or not resolved_file.is_file():
                raise IntakeError("SYMLINK_ESCAPE_DETECTED", f"Tệp nguồn không hợp lệ hoặc thoát khỏi thư mục gốc: {fname}")
            total_files += 1
            if total_files > limits.max_zip_entries:
                raise IntakeError(
                    "TOO_MANY_SOURCE_FILES",
                    f"Dự án vượt quá giới hạn {limits.max_zip_entries} tệp.",
                    details={"max_files": limits.max_zip_entries},
                )
            fsize = resolved_file.stat().st_size
            total_bytes += fsize
            if total_bytes > limits.max_uncompressed_bytes:
                raise IntakeError(
                    "SOURCE_SIZE_LIMIT_EXCEEDED",
                    f"Tổng dung lượng giải nén vượt quá giới hạn {limits.max_uncompressed_bytes // (1024 * 1024)} MB.",
                )
            if resolved_file.suffix.lower() == ".java":
                if len(java_hashes) + 1 > limits.max_java_files:
                    raise IntakeError(
                        "MAX_JAVA_FILES_EXCEEDED",
                        f"Số tệp Java vượt quá giới hạn an toàn ({limits.max_java_files} tệp).",
                        details={"max_java_files": limits.max_java_files},
                    )
                if fsize > limits.max_single_java_bytes:
                    rel = resolved_file.relative_to(resolved_root).as_posix()
                    raise IntakeError(
                        "JAVA_FILE_TOO_LARGE",
                        f"Tệp Java {rel} vượt quá giới hạn 1 MB của bộ kiểm chứng bằng chứng.",
                    )
                raw = resolved_file.read_bytes()
                try:
                    raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    rel = resolved_file.relative_to(resolved_root).as_posix()
                    raise IntakeError("JAVA_ENCODING_UNSUPPORTED", f"Tệp Java {rel} không phải mã hóa UTF-8 hợp lệ.") from exc
                rel = resolved_file.relative_to(resolved_root).as_posix()
                java_hashes[rel] = digest(raw)
            else:
                non_java_files += 1

    if not java_hashes:
        raise IntakeError(
            empty_code,
            "Không tìm thấy tệp mã nguồn .java nào trong dữ liệu đầu vào.",
        )

    return {
        "total_files": total_files,
        "java_files_count": len(java_hashes),
        "non_java_files_count": non_java_files,
        "total_bytes": total_bytes,
        "java_sha256": dict(sorted(java_hashes.items())),
    }


def extract_safe_zip(zip_data: bytes | Path, dest_dir: Path, limits: IntakeLimits) -> dict:
    """Validate and safely stream-extract a ZIP archive containing Java sources."""
    dest_dir = Path(dest_dir).resolve()
    if dest_dir.exists():
        raise IntakeError("INTERNAL_WORKSPACE_COLLISION", "Thư mục giải nén tạm đã tồn tại.", http_status=500)

    if isinstance(zip_data, (bytes, bytearray)):
        archive_size = len(zip_data)
        header = bytes(zip_data[:4])
        stream_ctx = lambda: io.BytesIO(zip_data)
    else:
        zp = Path(zip_data).resolve(strict=True)
        archive_size = zp.stat().st_size
        with zp.open("rb") as fh:
            header = fh.read(4)
        stream_ctx = lambda: zp.open("rb")

    if archive_size == 0:
        raise IntakeError("EMPTY_ZIP_ARCHIVE", "Tệp ZIP rỗng.")
    if archive_size > limits.max_zip_upload_bytes:
        raise IntakeError(
            "MAX_ZIP_UPLOAD_BYTES_EXCEEDED",
            f"Tệp ZIP vượt giới hạn tải lên {limits.max_zip_upload_bytes // (1024 * 1024)} MB.",
            http_status=413,
        )
    if header not in (b"PK\x03\x04", b"PK\x05\x06"):
        raise IntakeError("INVALID_ZIP_ARCHIVE", "Tệp tải lên không phải định dạng ZIP hợp lệ.")

    dest_dir.mkdir(parents=True, exist_ok=False)
    try:
        with stream_ctx() as raw_handle:
            try:
                zf = zipfile.ZipFile(raw_handle, "r")
            except zipfile.BadZipFile as exc:
                raise IntakeError("INVALID_ZIP_ARCHIVE", f"Cấu trúc tệp ZIP bị hỏng hoặc không hợp lệ: {exc}") from exc

            with zf:
                infos = zf.infolist()
                if not infos:
                    raise IntakeError("NO_JAVA_FILES_IN_ZIP", "Tệp ZIP không chứa tệp nào.")
                if len(infos) > limits.max_zip_entries:
                    raise IntakeError(
                        "ZIP_TOO_MANY_ENTRIES",
                        f"Tệp ZIP chứa {len(infos)} mục, vượt giới hạn {limits.max_zip_entries}.",
                    )

                declared_total = 0
                for info in infos:
                    if info.flag_bits & 0x1:
                        raise IntakeError("ZIP_ENCRYPTED_FORBIDDEN", "Không hỗ trợ tệp ZIP đặt mật khẩu.")
                    if _is_zip_symlink_or_special(info):
                        raise IntakeError("ZIP_SYMLINK_FORBIDDEN", f"Tệp ZIP chứa symlink hoặc tệp đặc biệt bị cấm: {info.filename!r}")
                    stripped_dir = info.filename.rstrip("/") if info.is_dir() else info.filename
                    if not stripped_dir:
                        continue
                    _validate_relative_member_path(stripped_dir)
                    if info.file_size < 0 or info.file_size > limits.max_single_file_bytes:
                        raise IntakeError(
                            "ZIP_ENTRY_TOO_LARGE",
                            f"Mục {info.filename!r} vượt giới hạn kích thước tệp đơn lẻ ({limits.max_single_file_bytes // (1024 * 1024)} MB).",
                        )
                    declared_total += info.file_size
                    if declared_total > limits.max_uncompressed_bytes:
                        raise IntakeError(
                            "ZIP_BOMB_DETECTED",
                            f"Tổng dung lượng giải nén khai báo vượt giới hạn an toàn ({limits.max_uncompressed_bytes // (1024 * 1024)} MB).",
                        )
                    if info.file_size > 65536 and info.compress_size > 0:
                        ratio = info.file_size / max(1, info.compress_size)
                        if ratio > limits.max_compression_ratio:
                            raise IntakeError(
                                "ZIP_BOMB_DETECTED",
                                f"Tỷ lệ nén bất thường ({ratio:.1f}:1) trên {info.filename!r}; từ chối để ngăn ZIP bomb.",
                            )

                actual_total = 0
                for info in infos:
                    if info.is_dir():
                        stripped = info.filename.rstrip("/")
                        if stripped:
                            rel_dir = _validate_relative_member_path(stripped)
                            target_dir = dest_dir.joinpath(*rel_dir.parts)
                            target_dir.mkdir(parents=True, exist_ok=True)
                            if not target_dir.resolve(strict=True).is_relative_to(dest_dir):
                                raise IntakeError("ZIP_PATH_TRAVERSAL", "Thư mục giải nén thoát khỏi vùng an toàn.")
                        continue

                    rel_file = _validate_relative_member_path(info.filename)
                    target_file = dest_dir.joinpath(*rel_file.parts)
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    if not target_file.parent.resolve(strict=True).is_relative_to(dest_dir):
                        raise IntakeError("ZIP_PATH_TRAVERSAL", "Đường dẫn giải nén thoát khỏi vùng an toàn.")
                    if target_file.exists():
                        raise IntakeError("ZIP_DUPLICATE_ENTRY", f"Tệp ZIP chứa đường dẫn trùng lặp: {info.filename!r}")

                    entry_bytes = 0
                    with zf.open(info, "r") as src, target_file.open("xb") as dst:
                        while True:
                            chunk = src.read(65536)
                            if not chunk:
                                break
                            entry_bytes += len(chunk)
                            actual_total += len(chunk)
                            if entry_bytes > limits.max_single_file_bytes or actual_total > limits.max_uncompressed_bytes:
                                raise IntakeError(
                                    "ZIP_BOMB_DETECTED",
                                    "Dung lượng giải nén thực tế vượt quá giới hạn an toàn; đã hủy giải nén.",
                                )
                            dst.write(chunk)

        inventory = verify_extracted_java_tree(dest_dir, limits, empty_code="NO_JAVA_FILES_IN_ZIP")
        inventory["archive_bytes"] = archive_size
        return inventory
    except Exception:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise


class _GitStepTimeout(Exception):
    def __init__(self, step: str, cleanup: dict, stderr_bytes: int = 0):
        super().__init__(step)
        self.step = step
        self.cleanup = cleanup
        self.stderr_bytes = stderr_bytes


_GIT_STEP_TIMEOUT_CODES = {
    "clone": ("GITHUB_CLONE_TIMEOUT", "Quá thời gian chờ khi tải kho GitHub (git clone)."),
    "checkout": ("GITHUB_CHECKOUT_TIMEOUT", "Quá thời gian chờ khi chuyển tới commit yêu cầu (git checkout)."),
    "rev-parse": ("GITHUB_REV_PARSE_TIMEOUT", "Quá thời gian chờ khi đọc commit hiện tại (git rev-parse HEAD)."),
}

# Raw Git stderr may contain credentials or other untrusted text, and truncating before redaction can
# expose secrets. It is therefore never copied into errors, job records or HTTP responses; only a
# fixed failure category, the exit code and the stderr byte count are reported.
_GIT_FAILURE_PATTERNS = (
    ("REPOSITORY_NOT_FOUND", ("repository not found", "not found")),
    ("AUTHENTICATION_REQUIRED", ("authentication failed", "could not read username", "terminal prompts disabled")),
    ("DNS_RESOLUTION_FAILED", ("could not resolve host",)),
    ("NETWORK_TIMEOUT", ("timed out", "timeout")),
    ("TLS_ERROR", ("ssl", "certificate")),
    ("NETWORK_ERROR", ("unable to access", "failed to connect", "connection reset", "early eof")),
)


def _classify_git_failure(raw_stderr: bytes) -> str:
    text = raw_stderr.decode("utf-8", errors="replace").lower()
    for kind, needles in _GIT_FAILURE_PATTERNS:
        if any(n in text for n in needles):
            return kind
    return "UNKNOWN"


def _file_size(fh) -> int:
    try:
        fh.flush()
        fh.seek(0, os.SEEK_END)
        return int(fh.tell())
    except OSError:
        return -1


# Git process trees whose termination could not be verified. While any remain, no new Git
# step is started (fail closed) until reconciliation proves they have exited.
_LINGERING_GIT_TREES: list[dict] = []
_LINGERING_LOCK = threading.Lock()


def _win_create_kill_on_close_job(owner: dict | None = None):
    """Return a Windows Job Object handle that kills all members when closed, or None if unavailable.

    With `owner`, the handle is recorded in `owner["job"]` immediately after CreateJobObjectW succeeds
    (before configuration). If configuration fails, the close result is checked: success sets
    `owner["job_closed"]`, failure records `owner["close_error"]` and the handle stays owned."""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class _IoCounters(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class _BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _ExtLimit(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimit),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return None
    if owner is not None:
        owner["job"] = job  # ownership first: never an unowned handle
    info = _ExtLimit()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not _win_job_call("SetInformationJobObject", wintypes.HANDLE(job), 9, ctypes.byref(info), ctypes.sizeof(info)):
        closed = bool(_win_job_call("CloseHandle", wintypes.HANDLE(job)))
        if owner is not None:
            if closed:
                owner["job_closed"] = True
            else:
                owner["close_error"] = ctypes.get_last_error() or -1
        return None
    return job


def _win_job_call(name: str, *args):
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = getattr(k32, name)
    fn.restype = wintypes.BOOL
    return fn(*args)


def _win_job_active_processes(job) -> int | None:
    import ctypes
    from ctypes import wintypes

    class _Accounting(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong), ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    info = _Accounting()
    ok = _win_job_call(
        "QueryInformationJobObject", wintypes.HANDLE(job), 1, ctypes.byref(info), ctypes.sizeof(info), None
    )
    return int(info.ActiveProcesses) if ok else None


def _win_resume_suspended_process(pid: int) -> bool:
    """Resume the (single) primary thread of a process created with CREATE_SUSPENDED.

    Safe against PID reuse: the caller still holds the process handle, so the PID cannot be recycled.
    """
    import ctypes
    from ctypes import wintypes

    class _ThreadEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD), ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)]
    k32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)]
    k32.OpenThread.restype = wintypes.HANDLE
    k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.ResumeThread.restype = wintypes.DWORD
    k32.ResumeThread.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

    snap = k32.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
    if not snap or snap == wintypes.HANDLE(-1).value:
        return False
    resumed = 0
    failed = False
    try:
        entry = _ThreadEntry()
        entry.dwSize = ctypes.sizeof(_ThreadEntry)
        ok = k32.Thread32First(snap, ctypes.byref(entry))
        while ok:
            if entry.th32OwnerProcessID == pid:
                th = k32.OpenThread(0x0002, False, entry.th32ThreadID)  # THREAD_SUSPEND_RESUME
                if not th:
                    failed = True
                else:
                    try:
                        if k32.ResumeThread(th) == 0xFFFFFFFF:
                            failed = True
                        else:
                            resumed += 1
                    finally:
                        k32.CloseHandle(th)
            ok = k32.Thread32Next(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return resumed > 0 and not failed


class _GitStepCleanupFailed(Exception):
    """The step's own process finished, but termination of its whole tree could not be verified."""

    def __init__(self, step: str, cleanup: dict, returncode: int | None):
        super().__init__(step)
        self.step = step
        self.cleanup = cleanup
        self.returncode = returncode


class _GitStepOutputLimit(Exception):
    """stdout or stderr exceeded the configured byte cap; output is discarded, never truncated."""

    def __init__(self, step: str, stream: str, size: int, limit: int, cleanup: dict, verified: bool = True):
        super().__init__(step)
        self.step = step
        self.stream = stream
        self.size = size
        self.limit = limit
        self.cleanup = cleanup
        self.verified = verified  # False: size unknown/changed -> output could not be verified


# Byte caps for captured child output (checked while running and after exit).
MAX_SUBPROCESS_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 16 * 1024 * 1024
# Separate, bounded budget for terminating and verifying a process tree.
CLEANUP_BUDGET_SECONDS = 5.0
_OUTPUT_POLL_SECONDS = 0.05


def _tree_remaining(entry: dict) -> int | None:
    """Live processes in a tracked tree (root + Job members); None means it could not be observed.

    The root is observed through its own process handle (`Popen.poll`), so an empty Job never hides a
    root that was not assigned to it, and PID reuse cannot be mistaken for the root. Root state alone is
    never treated as proof that the tree has stopped: Job membership is always queried as well.
    """
    count = 0
    root = entry.get("proc")
    if root is not None:
        try:
            if root.poll() is None:
                count += 1
        except Exception:
            return None
    if entry["kind"] == "job":
        if entry.get("job_closed"):
            return count
        members = _win_job_active_processes(entry["job"])
        if members is None:
            return None
        return count + members
    try:
        os.killpg(entry["pgid"], 0)
        return count + 1
    except ProcessLookupError:
        return count
    except OSError:
        return None


def _terminate_tree(entry: dict) -> bool:
    ok = True
    if entry["kind"] == "job":
        if not entry.get("job_closed"):
            from ctypes import wintypes

            ok = bool(_win_job_call("TerminateJobObject", wintypes.HANDLE(entry["job"]), 1))
    else:
        import signal

        try:
            os.killpg(entry["pgid"], signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            ok = False
    root = entry.get("proc")
    if root is not None:
        try:
            if root.poll() is None:
                root.kill()  # TerminateProcess on the root's own handle, never a bare PID
        except Exception:
            ok = False
    return ok


def _wait_tree_empty(entry: dict, deadline: float) -> int | None:
    """Poll until the tree is empty or the absolute monotonic `deadline` passes."""
    remaining = _tree_remaining(entry)
    while remaining != 0 and time.monotonic() < deadline:
        time.sleep(0.05)
        remaining = _tree_remaining(entry)
    return remaining


def _close_tree_handle(entry: dict) -> bool:
    """Close the Job handle once; returns whether it is (now) closed. KILL_ON_JOB_CLOSE applies."""
    if entry["kind"] != "job" or entry.get("job_closed"):
        return True
    from ctypes import wintypes

    if _win_job_call("CloseHandle", wintypes.HANDLE(entry["job"])):
        entry["job_closed"] = True
        return True
    return False


# Ownership registry states. Every external step registers its entry BEFORE any OS resource is
# allocated; later transitions only update that entry's existing "state" key (no list append on the
# failure path). Only PENDING entries (and legacy entries without a state) block new launches.
_STATE_PREPARING = "PREPARING"
_STATE_RUNNING = "RUNNING"
_STATE_FINALIZING = "FINALIZING"
_STATE_PENDING = "PENDING"
_STATE_CLOSED = "CLOSED"
# Fail-closed fallback: set when a registry state transition itself fails (e.g. MemoryError). While set,
# no new process is resumed; it is cleared only by restarting the API process (operator decision).
_REGISTRY_FAULT = False


def _set_state(entry: dict, state: str) -> None:
    entry["state"] = state  # existing key on a registered entry: no container growth


def _transition(entry: dict, state: str, *, terminal: bool = False) -> bool:
    """Change a registered entry's state under the launch-gate lock. A failed update sets the fail-closed
    `_REGISTRY_FAULT` before the lock is released (no window for a concurrent resume). For terminal
    transitions (CLOSED/PENDING) the entry is additionally flagged `state_unverified`, so reconciliation
    treats it as a blocker instead of a normal running entry."""
    global _REGISTRY_FAULT
    with _LINGERING_LOCK:
        try:
            _set_state(entry, state)
            return True
        except Exception:
            _REGISTRY_FAULT = True
            if terminal:
                try:
                    entry["state_unverified"] = True
                except Exception:
                    pass
            return False


def _is_blocking(entry: dict) -> bool:
    return entry.get("state", _STATE_PENDING) == _STATE_PENDING or entry.get("state_unverified") is True


def _launch_blocked_locked() -> bool:
    """Caller holds `_LINGERING_LOCK`."""
    return _REGISTRY_FAULT or any(_is_blocking(e) for e in _LINGERING_GIT_TREES)


def _owner_valid_locked(entry: dict, proc) -> bool:
    """Caller holds `_LINGERING_LOCK`: the entry is registered and owns this process and an open Job."""
    return (entry.get("proc") is proc and entry.get("job") is not None and not entry.get("job_closed")
            and any(e is entry for e in _LINGERING_GIT_TREES))


def _register_owner(step: str, kind: str) -> dict:
    """Create and register the owner entry before any Job/file/process exists. Raises on failure, in
    which case nothing has been allocated."""
    entry = {"state": _STATE_PREPARING, "step": step, "kind": kind, "job": None, "pgid": None,
             "proc": None, "job_closed": False, "close_error": None, "state_unverified": False}
    with _LINGERING_LOCK:
        _LINGERING_GIT_TREES.append(entry)
    return entry


def _unregister(entry: dict) -> None:
    """Drop a CLOSED entry (by identity). A failure leaves a non-blocking CLOSED entry for reconcile."""
    try:
        with _LINGERING_LOCK:
            for i, e in enumerate(_LINGERING_GIT_TREES):
                if e is entry:
                    del _LINGERING_GIT_TREES[i]
                    break
    except Exception:
        pass


def _finalize_tree(entry: dict, step: str, deadline: float) -> dict:
    """Single finalization path for every outcome once a process exists. Terminates the tree, verifies
    root AND Job emptiness within `deadline`, and only then closes the Job handle. Verified -> CLOSED and
    unregistered; anything unverified -> the registered entry becomes PENDING (blocks new launches)."""
    _transition(entry, _STATE_FINALIZING)
    cleanup: dict = {"step": step, "ownership": "JOB_OBJECT_BEFORE_RESUME" if entry["kind"] == "job" else "PROCESS_GROUP"}
    cleanup["terminate_ok"] = _terminate_tree(entry)
    remaining = _wait_tree_empty(entry, deadline)
    root = entry.get("proc")
    try:
        root_exited = root is None or root.poll() is not None
    except Exception:
        root_exited = False
    cleanup["root_exited"] = bool(root_exited)
    cleanup["remaining_processes"] = remaining
    handle_closed = _close_tree_handle(entry) if remaining == 0 else False
    cleanup["handle_closed"] = handle_closed
    cleanup["clean"] = bool(root_exited and remaining == 0 and handle_closed)
    if cleanup["clean"]:
        if _transition(entry, _STATE_CLOSED, terminal=True):
            _unregister(entry)
    else:
        _transition(entry, _STATE_PENDING, terminal=True)
    return cleanup


def _finalize_tree_safe(entry: dict, step: str, deadline: float) -> dict:
    """`_finalize_tree` that never raises: an exception inside cleanup marks the (already registered)
    entry PENDING and is reported as safe metadata, so the caller keeps its own primary error."""
    try:
        return _finalize_tree(entry, step, deadline)
    except Exception as exc:
        _transition(entry, _STATE_PENDING, terminal=True)
        return {"step": step, "clean": False, "cleanup_error": type(exc).__name__}


def _reconcile_lingering_git_jobs(budget_seconds: float = 2.0) -> int:
    """Retry termination of PENDING trees within ONE monotonic budget for all entries.

    Entries owned by running steps (PREPARING/RUNNING/FINALIZING) are never touched here. Returns how
    many trees are still not proven exited (root exited, Job empty, handle closed)."""
    deadline = time.monotonic() + max(0.0, budget_seconds)
    with _LINGERING_LOCK:
        for entry in list(_LINGERING_GIT_TREES):
            if not _is_blocking(entry):
                continue
            try:
                if _tree_remaining(entry) != 0:
                    _terminate_tree(entry)
                if _wait_tree_empty(entry, deadline) == 0 and _close_tree_handle(entry):
                    _set_state(entry, _STATE_CLOSED)
            except Exception:
                pass
        try:
            _LINGERING_GIT_TREES[:] = [e for e in _LINGERING_GIT_TREES if e.get("state") != _STATE_CLOSED]
        except Exception:
            pass
        return sum(1 for e in _LINGERING_GIT_TREES if _is_blocking(e))


class _GitStepInternalError(Exception):
    """An unexpected exception after the process was created; carries only its type name + cleanup."""

    def __init__(self, step: str, error_type: str, cleanup: dict):
        super().__init__(step)
        self.step = step
        self.error_type = error_type
        self.cleanup = cleanup


def _output_check(out_f, err_f, limit: int) -> tuple[str, str, int] | None:
    """Return (kind, stream, size) when a stream is over the cap ("over") or its size is unknown
    ("unverified"); an unknown size is never treated as within the limit."""
    for name, fh in (("stdout", out_f), ("stderr", err_f)):
        size = _file_size(fh)
        if size < 0:
            return "unverified", name, size
        if size > limit:
            return "over", name, size
    return None


def _read_capped(fh, name: str, limit: int) -> bytes:
    """Read at most limit+1 bytes; fail (never truncate) when over the cap, unreadable, or changed."""
    size = _file_size(fh)
    if size < 0:
        raise _OutputDecision("unverified", name, size)
    try:
        fh.seek(0)
        data = fh.read(limit + 1)
    except OSError:
        raise _OutputDecision("unverified", name, size) from None
    if len(data) > limit or size > limit:
        raise _OutputDecision("over", name, max(size, len(data)))
    if len(data) != size:
        raise _OutputDecision("unverified", name, size)
    return data


class _OutputDecision(Exception):
    def __init__(self, kind: str, stream: str, size: int):
        super().__init__(kind)
        self.kind = kind
        self.stream = stream
        self.size = size


def _run_git_step(
    step: str,
    cmd: list[str],
    *,
    timeout_seconds: float,
    env: dict,
    max_output_bytes: int | None = None,
) -> subprocess.CompletedProcess:
    """Run one external step (Git or OpenGrep) with a real wall-clock bound over its whole, provably owned
    process tree.

    `subprocess.run(capture_output=True, timeout=...)` on Windows kills only the direct child and then
    calls an unbounded `communicate()`; launchers (`cmd\\git.exe`, `opengrep.cmd -> python -> wsl.exe`)
    have descendants inheriting stdout/stderr, so the call blocks until they exit. Invariants here:
    - ownership first: the owner entry is registered before the Job, temp files or process exist; if
      registration fails nothing is created. Every allocated Job handle is referenced by that entry, and
      cleanup outcomes only change the entry's state (CLOSED -> unregistered, otherwise PENDING);
    - once the process exists, ANY exception still goes through `_finalize_tree_safe`; without a process,
      the (empty) Job handle is closed and the close result is checked — a failed close keeps it PENDING;
    - on Windows the process is created SUSPENDED and assigned to a KILL_ON_JOB_CLOSE Job Object; the
      launch decision (no PENDING entry, no registry fault) and the resume happen atomically under
      `_LINGERING_LOCK`, the same lock guarding every state transition; the lock is never held while
      the step runs;
    - output goes to temporary files; the final decision is made only after verified cleanup with a
      capped read (limit+1 bytes); over-cap, unknown size or size/read mismatch fails the step.
    Limits: OS calls are not interruptible; under real memory exhaustion even raising may fail, in which
    case the registered entry (or the registry fault flag) is what keeps new launches blocked.
    """
    global _REGISTRY_FAULT
    limit = int(MAX_SUBPROCESS_OUTPUT_BYTES if max_output_bytes is None else max_output_bytes)
    if _reconcile_lingering_git_jobs() or _REGISTRY_FAULT:
        raise IntakeError(
            "GITHUB_GIT_CLEANUP_PENDING",
            "Tiến trình Git của lượt tải trước chưa được xác nhận đã dừng; tạm từ chối lượt tải GitHub mới.",
            http_status=503,
        )

    is_nt = os.name == "nt"
    try:
        entry = _register_owner(step, "job" if is_nt else "pgid")
    except Exception:
        raise IntakeError(
            "GIT_PROCESS_ISOLATION_FAILED",
            "Không đăng ký được quyền sở hữu tiến trình; không tạo tài nguyên và từ chối chạy.",
            http_status=503,
            details={"git_step": step, "reason": "OWNERSHIP_REGISTRATION_FAILED"},
        ) from None

    out_f = err_f = None
    try:
        if is_nt:
            from ctypes import wintypes

            job = _win_create_kill_on_close_job(entry)
            if job is None:
                raise IntakeError(
                    "GIT_PROCESS_ISOLATION_FAILED",
                    "Không tạo được Windows Job Object để quản lý tiến trình Git; từ chối chạy git.",
                    http_status=503,
                    details={"git_step": step, "reason": "JOB_OBJECT_UNAVAILABLE"},
                )
            entry["job"] = job
        out_f = tempfile.TemporaryFile()
        err_f = tempfile.TemporaryFile()
        popen_kwargs: dict = {"stdin": subprocess.DEVNULL, "stdout": out_f, "stderr": err_f, "env": env}
        if is_nt:
            popen_kwargs["creationflags"] = (
                0x00000004  # CREATE_SUSPENDED
                | subprocess.CREATE_NEW_PROCESS_GROUP
                | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, **popen_kwargs)
        entry["proc"] = proc
        if not is_nt:
            entry["pgid"] = proc.pid

        # From here on the process exists: every path below reaches _finalize_tree_safe.
        outcome, info = "run", None
        try:
            if is_nt:
                if not _win_job_call("AssignProcessToJobObject", wintypes.HANDLE(entry["job"]), wintypes.HANDLE(int(proc._handle))):
                    outcome, info = "isolation", "JOB_ASSIGNMENT_REFUSED"
                else:
                    # Atomic launch contract (single critical section, released before waiting):
                    # check fault/blockers -> verify ownership -> record RUNNING -> only then resume.
                    with _LINGERING_LOCK:
                        if _launch_blocked_locked():
                            outcome = "pending"
                        elif not _owner_valid_locked(entry, proc):
                            outcome, info = "isolation", "OWNERSHIP_UNVERIFIED"
                        else:
                            try:
                                _set_state(entry, _STATE_RUNNING)
                            except Exception:
                                _REGISTRY_FAULT = True  # still under the lock; never resumed
                                outcome, info = "isolation", "REGISTRY_STATE_UPDATE_FAILED"
                            else:
                                if not _win_resume_suspended_process(proc.pid):
                                    outcome, info = "isolation", "RESUME_FAILED"
            else:
                _transition(entry, _STATE_RUNNING)
            if outcome == "run":
                run_deadline = time.monotonic() + timeout_seconds
                while proc.poll() is None:
                    check = _output_check(out_f, err_f, limit)
                    if check:
                        outcome, info = "output", check
                        break
                    if time.monotonic() >= run_deadline:
                        outcome = "timeout"
                        break
                    time.sleep(_OUTPUT_POLL_SECONDS)
                else:
                    outcome = "exited"
        except Exception as exc:
            outcome, info = "internal", type(exc).__name__

        cleanup = _finalize_tree_safe(entry, step, time.monotonic() + CLEANUP_BUDGET_SECONDS)

        if outcome == "pending":
            raise IntakeError(
                "GITHUB_GIT_CLEANUP_PENDING",
                "Tiến trình của lượt trước chưa được xác nhận đã dừng; tạm từ chối chạy tiến trình mới.",
                http_status=503,
                details={"git_step": step, "process_cleanup": cleanup},
            )
        if outcome == "isolation":
            details = {"git_step": step, "reason": info, "root_exited": cleanup.get("root_exited", False),
                       "process_cleanup": cleanup}
            if not cleanup["clean"]:
                details["cleanup_status"] = "CLEANUP_FAILED"
            raise IntakeError(
                "GIT_PROCESS_ISOLATION_FAILED",
                "Không thiết lập được quyền quản lý tiến trình Git trước khi chạy; từ chối chạy git.",
                http_status=503,
                details=details,
            )
        if outcome == "internal":
            raise _GitStepInternalError(step, info, cleanup)
        if outcome == "timeout":
            raise _GitStepTimeout(step, cleanup, _file_size(err_f))
        if outcome == "output":
            kind, stream, size = info
            raise _GitStepOutputLimit(step, stream, size, limit, cleanup, verified=(kind == "over"))
        if not cleanup["clean"]:
            raise _GitStepCleanupFailed(step, cleanup, proc.returncode)
        # Final output decision only after verified cleanup: nothing can still be writing.
        try:
            stdout = _read_capped(out_f, "stdout", limit)
            stderr = _read_capped(err_f, "stderr", limit)
        except _OutputDecision as dec:
            raise _GitStepOutputLimit(step, dec.stream, dec.size, limit, cleanup, verified=(dec.kind == "over")) from None
        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
    finally:
        for fh in (out_f, err_f):
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass
        if entry["proc"] is None:
            # No process was created: the owner holds at most an empty Job. Close it once and check the
            # result; a failed/unverified close keeps the entry PENDING for reconciliation, which re-checks
            # the handle via a Job query before closing (never dropped, never closed blindly twice).
            try:
                if entry["job"] is None or entry["job_closed"]:
                    closed = True
                elif entry["close_error"] is not None:
                    closed = False
                else:
                    closed = _close_tree_handle(entry)
            except Exception:
                closed = False
            if closed:
                if _transition(entry, _STATE_CLOSED, terminal=True):
                    _unregister(entry)
            else:
                _transition(entry, _STATE_PENDING, terminal=True)


def clone_github_repo(
    raw_url: str,
    commit_sha: str | None,
    dest_dir: Path,
    limits: IntakeLimits,
    *,
    timeout_seconds: int = 60,
) -> dict:
    """Safely clone a public HTTPS GitHub repository without shell execution or symlink checkout."""
    canonical_url, owner, repo, validated_sha = validate_github_url(raw_url, commit_sha)
    git_bin = shutil.which("git")
    if not git_bin:
        raise IntakeError("GIT_UNAVAILABLE", "Máy chủ chưa cài đặt git để tải kho GitHub.", http_status=503)

    dest_dir = Path(dest_dir).resolve()
    if dest_dir.exists():
        raise IntakeError("INTERNAL_WORKSPACE_COLLISION", "Thư mục clone tạm đã tồn tại.", http_status=500)

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"
    env["GCM_INTERACTIVE"] = "never"

    clone_cmd = [
        git_bin,
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "core.symlinks=false",
        "-c", "submodule.recurse=false",
        "clone",
        "--no-tags",
        "--single-branch",
    ]
    if not validated_sha:
        clone_cmd.extend(["--depth", "1"])
    clone_cmd.extend(["--", canonical_url + ".git", str(dest_dir)])

    try:
        proc = _run_git_step("clone", clone_cmd, timeout_seconds=timeout_seconds, env=env,
                             max_output_bytes=MAX_GIT_OUTPUT_BYTES)
        if proc.returncode != 0:
            kind = _classify_git_failure(proc.stderr)
            raise IntakeError(
                "GITHUB_CLONE_FAILED",
                f"Không thể tải kho GitHub công khai ({canonical_url}) [{kind}, exit {proc.returncode}].",
                http_status=400,
                details={
                    "git_step": "clone",
                    "git_failure_kind": kind,
                    "git_exit_code": proc.returncode,
                    "stderr_bytes": len(proc.stderr),
                },
            )

        if validated_sha:
            chk = _run_git_step(
                "checkout",
                [git_bin, "-C", str(dest_dir), "-c", "core.symlinks=false", "checkout", "--quiet", validated_sha, "--"],
                timeout_seconds=timeout_seconds,
                env=env,
                max_output_bytes=MAX_GIT_OUTPUT_BYTES,
            )
            if chk.returncode != 0:
                raise IntakeError(
                    "GITHUB_COMMIT_NOT_FOUND",
                    f"Không tìm thấy commit {validated_sha} trong kho {canonical_url}.",
                    http_status=400,
                )

        rev = _run_git_step(
            "rev-parse",
            [git_bin, "-C", str(dest_dir), "rev-parse", "HEAD"],
            timeout_seconds=min(15, timeout_seconds),
            env=env,
            max_output_bytes=MAX_GIT_OUTPUT_BYTES,
        )
        resolved_commit = rev.stdout.decode("utf-8", errors="replace").strip() if rev.returncode == 0 else validated_sha

        # Strip .git metadata before inventorying or scanning so git hooks/objects are never retained.
        git_meta = dest_dir / ".git"
        if git_meta.exists():
            shutil.rmtree(git_meta, ignore_errors=True)

        inventory = verify_extracted_java_tree(dest_dir, limits, empty_code="NO_JAVA_FILES_FOUND")
        return {
            **inventory,
            "repo_url": canonical_url,
            "owner": owner,
            "repo": repo,
            "resolved_commit": resolved_commit,
        }
    except _GitStepTimeout as exc:
        shutil.rmtree(dest_dir, ignore_errors=True)
        code, message = _GIT_STEP_TIMEOUT_CODES[exc.step]
        details = {"git_step": exc.step, "timeout_seconds": timeout_seconds, "process_cleanup": exc.cleanup}
        details["stderr_bytes"] = exc.stderr_bytes
        if not exc.cleanup.get("clean"):
            details["cleanup_status"] = "CLEANUP_FAILED"
            message += " Không xác nhận được việc dừng toàn bộ tiến trình Git con của lượt thử."
        raise IntakeError(code, message, http_status=504, details=details) from None
    except _GitStepCleanupFailed as exc:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise IntakeError(
            "GITHUB_GIT_CLEANUP_FAILED",
            "Bước git đã kết thúc nhưng không xác nhận được việc dừng toàn bộ tiến trình con; từ chối tiếp tục.",
            http_status=503,
            details={"git_step": exc.step, "cleanup_status": "CLEANUP_FAILED", "process_cleanup": exc.cleanup},
        ) from None
    except _GitStepOutputLimit as exc:
        shutil.rmtree(dest_dir, ignore_errors=True)
        details = {"git_step": exc.step, "output_stream": exc.stream, "output_bytes": exc.size,
                   "limit_bytes": exc.limit, "process_cleanup": exc.cleanup}
        if not exc.cleanup.get("clean"):
            details["cleanup_status"] = "CLEANUP_FAILED"
        if exc.verified:
            code = "GITHUB_OUTPUT_LIMIT_EXCEEDED"
            message = f"Đầu ra của git ({exc.stream}) vượt giới hạn {exc.limit} byte; đã dừng và loại bỏ đầu ra."
        else:
            code = "GITHUB_OUTPUT_UNVERIFIED"
            message = f"Không xác minh được kích thước đầu ra của git ({exc.stream}); loại bỏ đầu ra."
        raise IntakeError(code, message, http_status=502, details=details) from None
    except _GitStepInternalError as exc:
        shutil.rmtree(dest_dir, ignore_errors=True)
        details = {"git_step": exc.step, "primary_error": exc.error_type, "process_cleanup": exc.cleanup}
        if not exc.cleanup.get("clean"):
            details["cleanup_status"] = "CLEANUP_FAILED"
        raise IntakeError(
            "GITHUB_GIT_PROCESS_ERROR",
            "Lỗi nội bộ khi quản lý tiến trình git; đã chạy bước dọn dẹp cây tiến trình.",
            http_status=500,
            details=details,
        ) from None
    except Exception:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise
