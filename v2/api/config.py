"""Configuration and security boundary checks for v2.api."""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import os
from pathlib import Path
from typing import Sequence

from v2.api import DEFAULT_API_HOST, DEFAULT_API_PORT, FORBIDDEN_PORTS
from v2.g1_integration.bridge import DEFAULT_G1_RULES
from v2.g1_integration.fork_support.scanner_config import validate_opengrep_binary
from v2.triage.ollama import DEFAULT_PROMPT_CONTRACT, PROMPT_CONTRACTS, OllamaClient

REPO_ROOT = Path(__file__).resolve().parents[2]
SEALED_SUBTREES = (
    REPO_ROOT / "v2" / "baseline",
    REPO_ROOT / "v2" / "triage",
    REPO_ROOT / "v2" / "g1_integration",
    REPO_ROOT / "v2" / "g1_audit",
    REPO_ROOT / "v2" / "g1_runtime",
    REPO_ROOT / "v2" / "demo",
)

DEFAULT_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
)


def _split_list(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    parts = []
    for chunk in raw.replace(";", ",").split(","):
        cleaned = chunk.strip()
        if cleaned:
            parts.append(cleaned)
    return tuple(dict.fromkeys(parts))


def _split_paths(raw: str | None) -> tuple[Path, ...]:
    if not raw:
        return ()
    sep = ";" if ";" in raw else os.pathsep
    out: list[Path] = []
    for item in raw.split(sep):
        cleaned = item.strip()
        if cleaned:
            p = Path(cleaned).expanduser().resolve()
            if p not in out:
                out.append(p)
    return tuple(out)


def is_private_or_tailscale_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if addr.is_unspecified or addr.is_multicast:
        return False
    # Loopback (127.0.0.0/8, ::1), RFC1918 private, or Tailscale CGNAT (100.64.0.0/10)
    tailscale_net = ipaddress.ip_network("100.64.0.0/10")
    return bool(addr.is_loopback or addr.is_private or (addr.version == 4 and addr in tailscale_net))


def ensure_not_inside_sealed_tree(path: Path, label: str) -> Path:
    resolved = Path(path).expanduser().resolve()
    for sealed in SEALED_SUBTREES:
        sealed_resolved = sealed.resolve()
        if resolved == sealed_resolved or resolved.is_relative_to(sealed_resolved):
            raise ValueError(f"{label} must not point inside sealed backend directory {sealed_resolved}: {resolved}")
    return resolved


@dataclass(frozen=True)
class IntakeLimits:
    max_zip_upload_bytes: int = 25 * 1024 * 1024
    max_zip_entries: int = 2000
    max_uncompressed_bytes: int = 50 * 1024 * 1024
    max_single_file_bytes: int = 10 * 1024 * 1024
    max_single_java_bytes: int = 1_000_000
    max_java_files: int = 500
    max_compression_ratio: float = 100.0

    def to_dict(self) -> dict[str, int | float]:
        return {
            "max_zip_upload_bytes": self.max_zip_upload_bytes,
            "max_zip_entries": self.max_zip_entries,
            "max_uncompressed_bytes": self.max_uncompressed_bytes,
            "max_single_file_bytes": self.max_single_file_bytes,
            "max_single_java_bytes": self.max_single_java_bytes,
            "max_java_files": self.max_java_files,
            "max_compression_ratio": self.max_compression_ratio,
        }


@dataclass(frozen=True)
class ApiConfig:
    host: str = DEFAULT_API_HOST
    port: int = DEFAULT_API_PORT
    allow_public_bind: bool = False
    data_dir: Path = field(default_factory=lambda: REPO_ROOT / "runs" / "web-api-data")
    readonly_scan_dirs: tuple[Path, ...] = ()
    reviewable_scan_dirs: tuple[Path, ...] = ()
    api_token: str | None = None
    read_auth_mode: str = "required"  # "required" | "write-only"
    cors_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS
    opengrep_binary: str = "opengrep"
    rules_path: Path = field(default_factory=lambda: DEFAULT_G1_RULES.resolve())
    ollama_endpoint: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3.5:9b-q4_K_M"
    prompt_contract: str = DEFAULT_PROMPT_CONTRACT
    ollama_timeout_seconds: float = 90.0
    opengrep_timeout_seconds: int = 60
    git_clone_timeout_seconds: int = 60
    job_timeout_seconds: float = 300.0
    max_concurrent_scans: int = 1
    max_queued_jobs: int = 4
    runtime_origin: str = "unverified"  # "unverified" | "mock"
    limits: IntakeLimits = field(default_factory=IntakeLimits)

    def __post_init__(self) -> None:
        if type(self.port) is not int or not (0 <= self.port <= 65535):
            raise ValueError(f"invalid port: {self.port!r}")
        if self.port in FORBIDDEN_PORTS:
            raise ValueError(f"port {self.port} is reserved and forbidden by project security policy")
        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("host must be a non-empty address")
        if not self.allow_public_bind and not is_private_or_tailscale_host(self.host.strip()):
            raise ValueError(
                f"refusing public bind address {self.host!r}; bind to 127.0.0.1 or a private/Tailscale IP"
            )
        if self.read_auth_mode not in ("required", "write-only"):
            raise ValueError(f"read_auth_mode must be 'required' or 'write-only', got {self.read_auth_mode!r}")
        if self.api_token is not None:
            cleaned_token = self.api_token.strip()
            if len(cleaned_token) < 12:
                raise ValueError("api_token must be at least 12 characters when configured")
            object.__setattr__(self, "api_token", cleaned_token)
        resolved_data = ensure_not_inside_sealed_tree(self.data_dir, "data_dir")
        object.__setattr__(self, "data_dir", resolved_data)
        resolved_ro = tuple(Path(p).expanduser().resolve() for p in self.readonly_scan_dirs)
        object.__setattr__(self, "readonly_scan_dirs", resolved_ro)
        resolved_rw = tuple(ensure_not_inside_sealed_tree(p, "reviewable_scan_dirs") for p in self.reviewable_scan_dirs)
        object.__setattr__(self, "reviewable_scan_dirs", resolved_rw)

        normalized_origins: list[str] = []
        for origin in self.cors_origins:
            cleaned = origin.strip().rstrip("/")
            if not cleaned:
                continue
            if cleaned == "*" or not (cleaned.startswith("http://") or cleaned.startswith("https://")):
                raise ValueError(f"wildcard or invalid CORS origin forbidden: {origin!r}")
            if cleaned not in normalized_origins:
                normalized_origins.append(cleaned)
        object.__setattr__(self, "cors_origins", tuple(normalized_origins))

        validate_opengrep_binary(self.opengrep_binary)
        resolved_rules = Path(self.rules_path).expanduser().resolve(strict=True)
        if not resolved_rules.is_file():
            raise ValueError(f"rules_path must be an existing local file: {resolved_rules}")
        object.__setattr__(self, "rules_path", resolved_rules)

        if self.prompt_contract not in PROMPT_CONTRACTS:
            raise ValueError(f"unsupported prompt_contract: {self.prompt_contract!r}")
        if self.runtime_origin not in ("unverified", "mock"):
            raise ValueError(f"unsupported runtime_origin: {self.runtime_origin!r}")

        # Validate loopback-only Ollama URL & local Qwen model name using sealed OllamaClient checks.
        OllamaClient(
            endpoint=self.ollama_endpoint,
            model=self.ollama_model,
            timeout=self.ollama_timeout_seconds,
            runtime_origin=self.runtime_origin,
        )

        if self.max_concurrent_scans < 1 or self.max_concurrent_scans > 4:
            raise ValueError("max_concurrent_scans must be between 1 and 4")
        if self.max_queued_jobs < 1 or self.max_queued_jobs > 32:
            raise ValueError("max_queued_jobs must be between 1 and 32")
        if self.job_timeout_seconds <= 0 or self.ollama_timeout_seconds <= 0 or self.opengrep_timeout_seconds <= 0:
            raise ValueError("timeouts must be positive")

    @classmethod
    def from_env(cls, overrides: dict | None = None) -> "ApiConfig":
        env = os.environ
        token = env.get("NTK_API_TOKEN") or None
        default_read_mode = "required" if token else "write-only"
        cors_raw = env.get("NTK_CORS_ORIGINS")
        cors = _split_list(cors_raw) if cors_raw else DEFAULT_CORS_ORIGINS
        params: dict = {
            "host": env.get("NTK_API_HOST", DEFAULT_API_HOST),
            "port": int(env.get("NTK_API_PORT", str(DEFAULT_API_PORT))),
            "allow_public_bind": env.get("NTK_API_ALLOW_PUBLIC_BIND", "").strip() == "1",
            "data_dir": Path(env.get("NTK_API_DATA_DIR", str(REPO_ROOT / "runs" / "web-api-data"))),
            "readonly_scan_dirs": _split_paths(env.get("NTK_READONLY_SCAN_DIRS")),
            "reviewable_scan_dirs": _split_paths(env.get("NTK_REVIEWABLE_SCAN_DIRS")),
            "api_token": token,
            "read_auth_mode": env.get("NTK_API_READ_AUTH", default_read_mode).strip().lower(),
            "cors_origins": cors,
            "opengrep_binary": env.get("OPENGREP_BINARY", "opengrep"),
            "rules_path": Path(env["NTK_RULES_PATH"]) if env.get("NTK_RULES_PATH") else DEFAULT_G1_RULES.resolve(),
            "ollama_endpoint": env.get("NTK_OLLAMA_ENDPOINT", "http://127.0.0.1:11434"),
            "ollama_model": env.get("NTK_OLLAMA_MODEL", "qwen3.5:9b-q4_K_M"),
            "prompt_contract": env.get("NTK_PROMPT_CONTRACT", DEFAULT_PROMPT_CONTRACT),
            "ollama_timeout_seconds": float(env.get("NTK_OLLAMA_TIMEOUT", "90")),
            "opengrep_timeout_seconds": int(env.get("NTK_OPENGREP_TIMEOUT", "60")),
            "git_clone_timeout_seconds": int(env.get("NTK_GIT_CLONE_TIMEOUT", "60")),
            "job_timeout_seconds": float(env.get("NTK_JOB_TIMEOUT", "300")),
            "max_concurrent_scans": int(env.get("NTK_MAX_CONCURRENT_SCANS", "1")),
            "max_queued_jobs": int(env.get("NTK_MAX_QUEUED_JOBS", "4")),
            "runtime_origin": env.get("NTK_RUNTIME_ORIGIN", "unverified"),
            "limits": IntakeLimits(
                max_zip_upload_bytes=int(env.get("NTK_MAX_ZIP_BYTES", str(25 * 1024 * 1024))),
                max_zip_entries=int(env.get("NTK_MAX_ZIP_ENTRIES", "2000")),
                max_uncompressed_bytes=int(env.get("NTK_MAX_UNCOMPRESSED_BYTES", str(50 * 1024 * 1024))),
                max_java_files=int(env.get("NTK_MAX_JAVA_FILES", "500")),
            ),
        }
        if overrides:
            for k, v in overrides.items():
                if v is not None:
                    params[k] = v
        return cls(**params)
