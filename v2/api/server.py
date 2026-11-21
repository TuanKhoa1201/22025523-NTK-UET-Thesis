"""Standard-library ThreadingHTTPServer REST adapter for v2.api."""
from __future__ import annotations

from email.parser import BytesParser
from email.policy import default as email_default_policy
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import time
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from v2.api.config import ApiConfig
from v2.api.intake import IntakeError
from v2.api.jobs import ScanJobManager
from v2.api.service import ApiServiceError, TriageApiService
from v2.triage.evidence import EvidenceError, strict_json

MAX_JSON_BODY_BYTES = 65_536
DEFAULT_DRAIN_TIMEOUT_SECONDS = 0.25
DEFAULT_BODY_READ_TIMEOUT_SECONDS = 10.0

_RE_JOB_ID = re.compile(r"^/api/scan-jobs/([^/]+)$")
_RE_SCAN_DETAIL = re.compile(r"^/api/scans/([^/]+)$")
_RE_SCAN_SUMMARY = re.compile(r"^/api/scans/([^/]+)/summary$")
_RE_SCAN_FINDINGS = re.compile(r"^/api/scans/([^/]+)/findings(?:/page)?$")
_RE_SCAN_QUEUE = re.compile(r"^/api/scans/([^/]+)/review-queue$")
_RE_SCAN_REVIEW_HISTORY = re.compile(r"^/api/scans/([^/]+)/review-history$")
_RE_SCAN_REPORT = re.compile(r"^/api/scans/([^/]+)/report$")
_RE_FINDING_DETAIL = re.compile(r"^/api/scans/([^/]+)/findings/([^/]+)$")
_RE_FINDING_HISTORY = re.compile(r"^/api/scans/([^/]+)/findings/([^/]+)/history$")
_RE_FINDING_ACTION = re.compile(r"^/api/scans/([^/]+)/findings/([^/]+)/(confirm-true|confirm-false|reopen)$")


def _extract_bearer_token(headers) -> str | None:
    auth = headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return token
    alt = headers.get("X-API-Token") or ""
    if alt.strip():
        return alt.strip()
    return None


def _parse_multipart_form(content_type: str, raw_body: bytes) -> tuple[dict[str, str], dict[str, tuple[str, bytes]]]:
    header_bytes = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
    msg = BytesParser(policy=email_default_policy).parsebytes(header_bytes + raw_body)
    if not msg.is_multipart():
        raise IntakeError("INVALID_MULTIPART_PAYLOAD", "Yêu cầu tải tệp phải ở định dạng multipart/form-data hợp lệ.")
    fields: dict[str, str] = {}
    files: dict[str, tuple[str, bytes]] = {}
    for part in msg.iter_parts():
        if part.get_content_disposition() != "form-data":
            continue
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename is not None:
            files[str(name)] = (str(filename), payload)
        else:
            fields[str(name)] = payload.decode("utf-8", errors="replace")
    return fields, files


def _first_qs(qs: dict[str, list[str]], key: str, default: str | None = None) -> str | None:
    vals = qs.get(key)
    return vals[0] if vals else default


def _bool_qs(qs: dict[str, list[str]], key: str, default: bool = False) -> bool:
    raw = _first_qs(qs, key)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int_qs(qs: dict[str, list[str]], key: str, default: int) -> int:
    raw = _first_qs(qs, key)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ApiServiceError("INVALID_QUERY_PARAM", f"Tham số {key!r} phải là số nguyên.", http_status=400) from exc


class ThesisApiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, config: ApiConfig):
        self.api_config = config
        self.service = TriageApiService(config)
        self.jobs = ScanJobManager(config)
        self.drain_timeout_seconds = DEFAULT_DRAIN_TIMEOUT_SECONDS
        self.body_read_timeout_seconds = DEFAULT_BODY_READ_TIMEOUT_SECONDS
        super().__init__((config.host, config.port), ThesisApiRequestHandler)

    def server_close(self) -> None:
        try:
            self.jobs.shutdown(wait=False)
        finally:
            super().server_close()


class ThesisApiRequestHandler(BaseHTTPRequestHandler):
    server: ThesisApiServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Suppress noisy default stderr logging during tests; structured errors are returned in JSON.
        return

    @property
    def cfg(self) -> ApiConfig:
        return self.server.api_config

    def _check_cors(self) -> tuple[bool, str | None]:
        origin = self.headers.get("Origin")
        if not origin:
            return True, None
        normalized = origin.strip().rstrip("/")
        if normalized in self.cfg.cors_origins:
            return True, normalized
        return False, None

    def _is_authenticated(self) -> bool:
        expected = self.cfg.api_token
        if not expected:
            return False
        supplied = _extract_bearer_token(self.headers)
        if not supplied:
            return False
        return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))

    def _require_read_auth(self) -> None:
        if self.cfg.api_token and self.cfg.read_auth_mode == "required":
            if not self._is_authenticated():
                raise ApiServiceError(
                    "UNAUTHORIZED",
                    "Yêu cầu API token hợp lệ trong header Authorization: Bearer <token>.",
                    http_status=401,
                )

    def _require_write_auth(self) -> None:
        if not self.cfg.api_token:
            raise ApiServiceError(
                "AUTH_TOKEN_NOT_CONFIGURED",
                "Máy chủ chưa cấu hình NTK_API_TOKEN; các thao tác thay đổi dữ liệu và khởi chạy quét bị khóa an toàn.",
                http_status=503,
            )
        if not self._is_authenticated():
            raise ApiServiceError(
                "UNAUTHORIZED",
                "Yêu cầu xác thực bằng API token hợp lệ để thực hiện thao tác này.",
                http_status=401,
            )

    def _drain_small_unread_post_body(self) -> bool:
        """Bounded-time drain for small unread POST bodies on early errors; aborts and closes on slow/incomplete clients."""
        if getattr(self, "command", "") != "POST" or getattr(self, "_body_consumed", False):
            return True
        if getattr(self, "_body_aborted", False):
            return False
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            return False
        try:
            length = int(raw_len)
        except ValueError:
            return False
        if length < 0 or length > MAX_JSON_BODY_BYTES:
            return False
        if length == 0:
            self._body_consumed = True
            return True

        drain_timeout = float(getattr(self.server, "drain_timeout_seconds", DEFAULT_DRAIN_TIMEOUT_SECONDS))
        deadline = time.monotonic() + max(0.01, drain_timeout)
        remaining = length
        prev_timeout = self.connection.gettimeout()
        try:
            while remaining > 0:
                rem_time = deadline - time.monotonic()
                if rem_time <= 0:
                    return False
                self.connection.settimeout(rem_time)
                chunk = self.rfile.read1(min(65536, remaining))
                if not chunk:
                    return False
                remaining -= len(chunk)
            self._body_consumed = True
            return True
        except (TimeoutError, OSError):
            return False
        finally:
            try:
                self.connection.settimeout(prev_timeout)
            except OSError:
                pass

    def _send_json(self, status_code: int, payload: dict[str, Any], cors_origin: str | None) -> None:
        close_after = bool(self.close_connection)
        if not close_after and status_code >= 400 and not self._drain_small_unread_post_body():
            close_after = True
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if close_after:
            self.close_connection = True
            self.send_header("Connection", "close")
        if cors_origin:
            self.send_header("Access-Control-Allow-Origin", cors_origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def _read_bounded_body(self, max_bytes: int, too_large_code: str = "PAYLOAD_TOO_LARGE") -> bytes:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            raise ApiServiceError("LENGTH_REQUIRED", "Thiếu header Content-Length.", http_status=411)
        try:
            length = int(raw_len)
        except ValueError as exc:
            raise ApiServiceError("INVALID_CONTENT_LENGTH", "Content-Length không hợp lệ.", http_status=400) from exc
        if length < 0:
            raise ApiServiceError("INVALID_CONTENT_LENGTH", "Content-Length âm không hợp lệ.", http_status=400)
        if length > max_bytes:
            raise ApiServiceError(
                too_large_code,
                f"Kích thước dữ liệu gửi lên vượt giới hạn cho phép ({max_bytes} bytes).",
                http_status=413,
            )
        if length == 0:
            self._body_consumed = True
            return b""

        read_timeout = float(getattr(self.server, "body_read_timeout_seconds", DEFAULT_BODY_READ_TIMEOUT_SECONDS))
        deadline = time.monotonic() + max(0.05, read_timeout)
        remaining = length
        chunks = []
        prev_timeout = self.connection.gettimeout()
        try:
            while remaining > 0:
                rem_time = deadline - time.monotonic()
                if rem_time <= 0:
                    raise TimeoutError("request body deadline exceeded")
                self.connection.settimeout(rem_time)
                want = min(65536, remaining)
                chunk = self.rfile.read1(want)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        except TimeoutError as exc:
            self._body_aborted = True
            self.close_connection = True
            raise ApiServiceError(
                "REQUEST_BODY_TIMEOUT",
                "Hết thời gian chờ nhận đầy đủ dữ liệu yêu cầu.",
                http_status=408,
            ) from exc
        except OSError as exc:
            self._body_aborted = True
            self.close_connection = True
            raise ApiServiceError(
                "INCOMPLETE_REQUEST_BODY",
                "Kết nối bị gián đoạn khi đang đọc dữ liệu yêu cầu.",
                http_status=400,
            ) from exc
        finally:
            try:
                self.connection.settimeout(prev_timeout)
            except OSError:
                pass

        data = b"".join(chunks)
        if len(data) != length:
            self._body_aborted = True
            self.close_connection = True
            raise ApiServiceError("INCOMPLETE_REQUEST_BODY", "Nội dung HTTP request bị ngắt quãng.", http_status=400)
        self._body_consumed = True
        return data

    def _read_json_body(self) -> dict[str, Any]:
        raw = self._read_bounded_body(MAX_JSON_BODY_BYTES)
        if not raw:
            raise ApiServiceError("EMPTY_JSON_BODY", "Nội dung JSON không được để trống.", http_status=400)
        try:
            parsed = strict_json(raw.decode("utf-8"))
        except (EvidenceError, UnicodeDecodeError) as exc:
            raise ApiServiceError("INVALID_JSON_BODY", f"JSON đầu vào không hợp lệ: {exc}", http_status=400) from exc
        if not isinstance(parsed, dict):
            raise ApiServiceError("INVALID_JSON_BODY", "JSON đầu vào phải là một đối tượng (object).", http_status=400)
        return parsed

    def do_OPTIONS(self) -> None:
        cors_ok, cors_origin = self._check_cors()
        if not cors_ok:
            self._send_json(
                403,
                {"error_code": "CORS_ORIGIN_FORBIDDEN", "error_message": "Origin không nằm trong danh sách cho phép."},
                None,
            )
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if cors_origin:
            self.send_header("Access-Control-Allow-Origin", cors_origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Token")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self) -> None:
        cors_ok, cors_origin = self._check_cors()
        if not cors_ok:
            self._send_json(
                403,
                {"error_code": "CORS_ORIGIN_FORBIDDEN", "error_message": "Origin không nằm trong danh sách cho phép."},
                None,
            )
            return

        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query, keep_blank_values=False)

        try:
            if path == "/api/health":
                payload = self.server.service.health(authenticated=self._is_authenticated())
                self._send_json(200, payload, cors_origin)
                return

            self._require_read_auth()

            if path == "/api/model":
                ol = self.server.service.probe_ollama()
                self._send_json(
                    200,
                    {
                        "status": "OK" if (ol["reachable"] and ol["model_installed"]) else "DEGRADED",
                        "engine": "Ollama Local HTTP",
                        "cloud_inference": False,
                        "lora_or_finetuning_enabled": False,
                        "ollama": ol,
                    },
                    cors_origin,
                )
                return

            if path == "/api/scan-jobs":
                self._send_json(200, self.server.jobs.list_jobs(), cors_origin)
                return

            m = _RE_JOB_ID.match(path)
            if m:
                job_id = unquote(m.group(1))
                self._send_json(200, self.server.jobs.get_job(job_id), cors_origin)
                return

            if path == "/api/scans":
                self._send_json(200, self.server.service.list_scans(), cors_origin)
                return

            m = _RE_SCAN_DETAIL.match(path) or _RE_SCAN_SUMMARY.match(path)
            if m:
                scan_id = unquote(m.group(1))
                entry = self.server.service.resolve_scan(scan_id)
                summary = self.server.service.build_scan_summary(entry)
                if summary["is_test_or_mock"] and self.cfg.runtime_origin != "mock":
                    raise ApiServiceError(
                        "TEST_DATA_ISOLATED",
                        "Dữ liệu kiểm thử mô phỏng (mock) bị cách ly khỏi chế độ vận hành thực.",
                        http_status=403,
                    )
                self._send_json(200, summary, cors_origin)
                return

            m = _RE_SCAN_FINDINGS.match(path)
            if m:
                scan_id = unquote(m.group(1))
                data = self.server.service.list_findings(
                    scan_id,
                    page=_int_qs(qs, "page", 1),
                    page_size=_int_qs(qs, "page_size", 50),
                    cwe=_first_qs(qs, "cwe"),
                    query=_first_qs(qs, "query") or _first_qs(qs, "q"),
                    file_filter=_first_qs(qs, "file"),
                    validated_status=_first_qs(qs, "validated_status"),
                    human_review_state=_first_qs(qs, "human_review_state"),
                    include_confirmed_false=_bool_qs(qs, "include_confirmed_false", True),
                )
                self._send_json(200, data, cors_origin)
                return

            m = _RE_SCAN_QUEUE.match(path)
            if m:
                scan_id = unquote(m.group(1))
                include_all = _bool_qs(qs, "include_all", False) or _bool_qs(qs, "all", False)
                self._send_json(200, self.server.service.get_review_queue(scan_id, include_all=include_all), cors_origin)
                return

            m = _RE_SCAN_REVIEW_HISTORY.match(path)
            if m:
                scan_id = unquote(m.group(1))
                self._send_json(200, self.server.service.get_scan_review_history(scan_id), cors_origin)
                return

            m = _RE_SCAN_REPORT.match(path)
            if m:
                scan_id = unquote(m.group(1))
                self._send_json(200, self.server.service.export_scan_report(scan_id), cors_origin)
                return

            m = _RE_FINDING_HISTORY.match(path)
            if m:
                scan_id = unquote(m.group(1))
                finding_id = unquote(m.group(2))
                inc_rej = _bool_qs(qs, "include_rejected", True)
                self._send_json(
                    200,
                    self.server.service.get_finding_history(scan_id, finding_id, include_rejected=inc_rej),
                    cors_origin,
                )
                return

            m = _RE_FINDING_DETAIL.match(path)
            if m:
                scan_id = unquote(m.group(1))
                finding_id = unquote(m.group(2))
                self._send_json(200, self.server.service.get_finding_detail(scan_id, finding_id), cors_origin)
                return

            raise ApiServiceError("ROUTE_NOT_FOUND", f"Không tồn tại endpoint GET {path}.", http_status=404)

        except IntakeError as exc:
            self._send_json(exc.http_status, exc.to_dict(), cors_origin)
        except ApiServiceError as exc:
            self._send_json(exc.http_status, exc.to_dict(), cors_origin)
        except Exception as exc:
            self._send_json(
                500,
                {"error_code": "INTERNAL_SERVER_ERROR", "error_message": f"Lỗi xử lý nội bộ: {type(exc).__name__}"},
                cors_origin,
            )

    def do_POST(self) -> None:
        self._body_consumed = False
        self._body_aborted = False
        cors_ok, cors_origin = self._check_cors()
        if not cors_ok:
            self._send_json(
                403,
                {"error_code": "CORS_ORIGIN_FORBIDDEN", "error_message": "Origin không nằm trong danh sách cho phép."},
                None,
            )
            return

        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"

        try:
            self._require_write_auth()

            if path == "/api/scan-jobs":
                ctype = (self.headers.get("Content-Type") or "").strip()
                if ctype.lower().startswith("multipart/form-data"):
                    max_multipart = self.cfg.limits.max_zip_upload_bytes + 65536
                    raw_body = self._read_bounded_body(max_multipart, too_large_code="MAX_ZIP_UPLOAD_BYTES_EXCEEDED")
                    fields, files = _parse_multipart_form(ctype, raw_body)
                    if "file" not in files:
                        raise IntakeError("MISSING_ZIP_FILE", "Vui lòng đính kèm tệp .zip trong trường 'file'.")
                    fname, zbytes = files["file"]
                    no_llm = fields.get("no_llm", "").strip().lower() in ("1", "true", "yes")
                    job = self.server.jobs.submit_zip_job(fname, zbytes, no_llm=no_llm)
                    self._send_json(202, job, cors_origin)
                    return

                body = self._read_json_body()
                repo_url = body.get("repo_url")
                commit_sha = body.get("commit_sha")
                no_llm = bool(body.get("no_llm", False))
                job = self.server.jobs.submit_github_job(repo_url, commit_sha, no_llm=no_llm)
                self._send_json(202, job, cors_origin)
                return

            m = _RE_FINDING_ACTION.match(path)
            if m:
                scan_id = unquote(m.group(1))
                finding_id = unquote(m.group(2))
                action = m.group(3)
                body = self._read_json_body()
                actor = body.get("actor", "")
                reason = body.get("reason", "")
                updated = self.server.service.decide_finding(scan_id, finding_id, action, actor, reason)
                self._send_json(200, updated, cors_origin)
                return

            raise ApiServiceError("ROUTE_NOT_FOUND", f"Không tồn tại endpoint POST {path}.", http_status=404)

        except IntakeError as exc:
            self._send_json(exc.http_status, exc.to_dict(), cors_origin)
        except ApiServiceError as exc:
            self._send_json(exc.http_status, exc.to_dict(), cors_origin)
        except Exception as exc:
            self._send_json(
                500,
                {"error_code": "INTERNAL_SERVER_ERROR", "error_message": f"Lỗi xử lý nội bộ: {type(exc).__name__}"},
                cors_origin,
            )
