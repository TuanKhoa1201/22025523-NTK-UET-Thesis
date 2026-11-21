"""CLI entrypoint for the local/Tailscale HTTP API server (`python -m v2.api`)."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from v2.api import DEFAULT_API_HOST, DEFAULT_API_PORT
from v2.api.config import ApiConfig, _split_list, _split_paths
from v2.api.server import ThesisApiServer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="HTTP API adapter cho công cụ OpenGrep + Qwen3.5-9B (Ollama cục bộ) + Human Review"
    )
    parser.add_argument("--host", help=f"Địa chỉ lắng nghe (mặc định: {DEFAULT_API_HOST} hoặc IP Tailscale)")
    parser.add_argument("--port", type=int, help=f"Cổng lắng nghe (mặc định: {DEFAULT_API_PORT}; cấm cổng 8765)")
    parser.add_argument("--data-dir", type=Path, help="Thư mục lưu dữ liệu vận hành của API ngoài vùng niêm phong")
    parser.add_argument("--readonly-scan-dirs", help="Danh sách thư mục scan có sẵn chỉ đọc (phân tách bởi dấu ;)")
    parser.add_argument("--reviewable-scan-dirs", help="Danh sách thư mục scan cho phép kiểm duyệt (phân tách bởi dấu ;)")
    parser.add_argument("--cors-origins", help="Danh sách Origin được phép gọi API (phân tách bởi dấu phẩy)")
    parser.add_argument("--read-auth", choices=("required", "write-only"), help="Chế độ xác thực cho các endpoint đọc")
    parser.add_argument("--opengrep-binary", help="Đường dẫn hoặc tên binary opengrep cục bộ")
    parser.add_argument("--rules-path", type=Path, help="Đường dẫn tệp luật YAML cục bộ")
    parser.add_argument("--ollama-endpoint", help="Endpoint loopback của Ollama (mặc định: http://127.0.0.1:11434)")
    parser.add_argument("--ollama-model", help="Tên mô hình Qwen cục bộ (mặc định: qwen3.5:9b-q4_K_M)")
    args = parser.parse_args(argv)

    overrides = {
        "host": args.host,
        "port": args.port,
        "data_dir": args.data_dir,
        "readonly_scan_dirs": _split_paths(args.readonly_scan_dirs) if args.readonly_scan_dirs else None,
        "reviewable_scan_dirs": _split_paths(args.reviewable_scan_dirs) if args.reviewable_scan_dirs else None,
        "cors_origins": _split_list(args.cors_origins) if args.cors_origins else None,
        "read_auth_mode": args.read_auth,
        "opengrep_binary": args.opengrep_binary,
        "rules_path": args.rules_path,
        "ollama_endpoint": args.ollama_endpoint,
        "ollama_model": args.ollama_model,
    }
    try:
        config = ApiConfig.from_env(overrides)
    except ValueError as exc:
        print(f"[CONFIG_ERROR] {exc}", file=sys.stderr)
        return 2

    server = ThesisApiServer(config)
    bound_host, bound_port = server.server_address[:2]
    print(
        f"NTK Thesis API đang lắng nghe tại http://{bound_host}:{bound_port} "
        f"(read_auth={config.read_auth_mode}, write_token_configured={bool(config.api_token)})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nĐang dừng NTK Thesis API...", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
