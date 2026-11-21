"""HTTP API adapter for the OpenGrep + local Qwen3.5-9B Java vulnerability triage system.

This package is a thin coordination and transport layer over the audited `v2.triage`,
`v2.baseline.fork`, and `v2.g1_integration` modules. It never re-implements or weakens
citation validation, source SHA-256 checks, STALE_SOURCE drift guards, or human review states.
"""

API_SERVICE_NAME = "ntk-thesis-api"
API_VERSION = "1.0.0"
API_CONTRACT_SCHEMA = "ntk-thesis-web-api-1"
REPORT_SCHEMA = "ntk-thesis-scan-report-1"
FORBIDDEN_PORTS = frozenset({8765})
DEFAULT_API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8780
