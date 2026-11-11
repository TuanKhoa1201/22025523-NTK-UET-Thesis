# Derived from hardw00t/simple_semgrepAI scanner.py, MIT; see ../LICENSE.
import subprocess
import json
import os
from pathlib import Path
from typing import Optional, Dict, List
from .config import OpenGrepConfig


class ScanError(RuntimeError):
    """No successful scan may be inferred from a failed/partial engine run."""


class SemgrepScanner:
    """Compatibility name retained for the upstream scan/_process_results interface."""

    def __init__(self, config=None, output_dir=Path("reports")):
        self.config = config or OpenGrepConfig()
        self.output_dir = Path(output_dir).resolve()
        self.target_root = None

    def _run(self, label, command):
        env = os.environ.copy()
        env["SEMGREP_LOG_FILE"] = str(self.output_dir / "opengrep.log")
        env["SEMGREP_SETTINGS_FILE"] = str(self.output_dir / "settings.yml")
        env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        env["OPENGREP_ENABLE_VERSION_CHECK"] = "0"
        env["SEMGREP_SEND_METRICS"] = "off"
        (self.output_dir / (label + ".command.json")).write_text(
            json.dumps(command, indent=2), encoding="utf-8")
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    encoding="utf-8", errors="replace",
                                    timeout=self.config.timeout + 30, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            (self.output_dir / (label + ".failure.txt")).write_text(str(exc), encoding="utf-8")
            raise ScanError(str(exc)) from exc
        for name, value in (("stdout", result.stdout), ("stderr", result.stderr)):
            (self.output_dir / (label + "." + name + ".txt")).write_text(value, encoding="utf-8")
        (self.output_dir / (label + ".exit.txt")).write_text(str(result.returncode), encoding="utf-8")
        if result.returncode != 0:
            raise ScanError(f"{label} exited {result.returncode}; see captured stderr")
        return result.stdout

    def verify_semgrep_installation(self):
        return self._run("version", [self.config.executable, "--version"]).strip()

    def scan(self, target_path: Path, rules_path: Optional[Path] = None) -> Dict:
        target_path = Path(target_path).resolve()
        if not target_path.exists():
            raise ScanError("target does not exist")
        self.target_root = target_path if target_path.is_dir() else target_path.parent
        if self.output_dir.exists() and any(self.output_dir.iterdir()):
            raise ScanError("output directory must be new or empty; preserve previous evidence")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        config = self.config
        if rules_path is not None:
            config = OpenGrepConfig(config.executable, Path(rules_path), config.timeout, config.jobs)
        version = self.verify_semgrep_installation()
        results = {}
        for fmt in ("json", "sarif"):
            raw = self._run(fmt, config.command(target_path, fmt))
            (self.output_dir / ("opengrep." + fmt)).write_text(raw, encoding="utf-8")
            try:
                results[fmt] = json.loads(raw)
            except (ValueError, TypeError) as exc:
                raise ScanError(f"invalid {fmt}; REVIEW required") from exc
        self.validate_json(results["json"])
        sarif = results["sarif"]
        if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
            raise ScanError("invalid SARIF envelope; REVIEW required")
        results["engine_version"] = version
        return results

    @staticmethod
    def validate_json(document):
        if not isinstance(document, dict) or not isinstance(document.get("results"), list):
            raise ScanError("invalid results envelope; REVIEW required")
        if document.get("errors"):
            raise ScanError("engine reported errors/partial scan; REVIEW required")
        for item in document["results"]:
            if not isinstance(item, dict):
                raise ScanError("invalid finding; REVIEW required")
            extra = item.get("extra")
            if not isinstance(extra, dict) or not isinstance(extra.get("metadata", {}), dict):
                raise ScanError("invalid finding extra/metadata; REVIEW required")
            if not isinstance(item.get("path"), str) or not item["path"]:
                raise ScanError("missing finding path; REVIEW required")
            if not isinstance(item.get("check_id"), str) or not item["check_id"]:
                raise ScanError("missing rule ID; REVIEW required")
            for key in ("start", "end"):
                loc = item.get(key)
                if not isinstance(loc, dict) or type(loc.get("line")) is not int or loc["line"] < 1:
                    raise ScanError("invalid finding location; REVIEW required")

    def _extract_code(self, result: Dict) -> str:
        """Extract code snippet with context from a finding."""
        # First try to get from result
        code = result.get('lines', '')
        if code and code != "requires login":
            return code.strip()

        # Then try extra.lines
        if 'extra' in result:
            code = result['extra'].get('lines', '')
            if code and code != "requires login":
                return code.strip()

        # If we got here, try to read from file
        try:
            raw_path = result.get('path', '')
            if not raw_path:
                return "No file path available"

            # Handle relative paths
            path = Path(raw_path)
            if not path.is_absolute():
                # First try relative to cwd
                cwd_path = Path.cwd() / path
                if cwd_path.exists():
                    path = cwd_path
                else:
                    # Try cleaning up path
                    clean_path = Path(raw_path.lstrip('./'))
                    cwd_path = Path.cwd() / clean_path
                    if cwd_path.exists():
                        path = cwd_path

            path = path.resolve()
            if self.target_root is not None and not path.is_relative_to(self.target_root):
                return "Source path outside scan target; REVIEW required"
            if not path.exists():
                return f"File not found: {raw_path}"

            # Read the file and extract relevant lines
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Get line numbers
            start_line = result.get('start', {}).get('line', 0)
            end_line = result.get('end', {}).get('line', start_line)

            # Validate line numbers
            if start_line < 1 or start_line > len(lines):
                return f"Invalid start line: {start_line}"
            if end_line < start_line or end_line > len(lines):
                end_line = start_line

            # Get context lines
            context_lines = 10
            start_idx = max(0, start_line - 1 - context_lines)
            end_idx = min(len(lines), end_line + context_lines)

            # Extract the lines
            code_lines = lines[start_idx:end_idx]

            # Add line numbers and highlight the vulnerable lines
            numbered_lines = []
            for i, line in enumerate(code_lines, start=start_idx + 1):
                prefix = f"{i:4d} | "
                if start_line <= i <= end_line:
                    numbered_lines.append(f">>> {prefix}{line.rstrip()}")
                else:
                    numbered_lines.append(f"    {prefix}{line.rstrip()}")

            return '\n'.join(numbered_lines)

        except Exception as e:
            return f"Error extracting code: {str(e)}"

    def _process_results(self, results: Dict) -> List[Dict]:
        """Process and normalize Semgrep results."""
        self.validate_json(results['json'])
        findings = []

        for result in results['json'].get('results', []):
            # Extract metadata
            metadata = result.get('extra', {}).get('metadata', {})

            # Extract code with context
            code = self._extract_code(result)

            finding = {
                'rule_id': result.get('check_id'),
                'severity': result.get('extra', {}).get('severity', 'UNKNOWN'),
                'message': result.get('extra', {}).get('message', ''),
                'path': result.get('path', ''),
                'line': result.get('start', {}).get('line', 0),
                'code': code,
                'dataflow': self._extract_dataflow(result),
                'references': self._extract_references(result),
                'security_patterns': self._extract_security_patterns(result),
                'review_status': 'REVIEW',
                'metadata': {
                    'cwe': metadata.get('cwe', []),
                    'owasp': metadata.get('owasp', ''),
                    'category': metadata.get('category', ''),
                    'technology': metadata.get('technology', []),
                    'vulnerability_class': metadata.get('vulnerability_class', []),
                    'confidence': metadata.get('confidence', 'UNKNOWN'),
                    'source': metadata.get('source', ''),
                    'shortlink': metadata.get('shortlink', '')
                }
            }
            findings.append(finding)

        return findings

    def _extract_dataflow(self, result: Dict):
        """Preserve native OpenGrep tagged trace structures without guessing steps."""
        extra = result.get("extra", {})
        if "dataflow_trace" in extra:
            return extra["dataflow_trace"]
        return result.get("dataflow_trace", [])

    def _extract_references(self, result: Dict) -> List[Dict]:
        """Extract reference information from a finding."""
        references = []
        if 'related_locations' in result:
            for ref in result['related_locations']:
                references.append({
                    'path': ref.get('path'),
                    'line': ref.get('start', {}).get('line'),
                    'snippet': ref.get('snippet')
                })
        return references

    def _extract_security_patterns(self, result: Dict) -> List[Dict]:
        """Extract security pattern information from a finding."""
        security_patterns = []
        if 'security-patterns' in result:
            for pattern in result['security-patterns']:
                security_patterns.append({
                    'pattern': pattern.get('pattern'),
                    'severity': pattern.get('severity')
                })
        return security_patterns
