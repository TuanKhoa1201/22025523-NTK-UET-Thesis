"""Local scanner configuration; deliberately independent of upstream LLM imports."""
from dataclasses import dataclass
from pathlib import Path


DEFAULT_RULES = Path(__file__).resolve().parents[2] / "rules" / "java.yml"


@dataclass(frozen=True)
class OpenGrepConfig:
    executable: str = "opengrep"
    rules: Path = DEFAULT_RULES
    timeout: int = 60
    jobs: int = 1

    def __post_init__(self):
        if self.timeout <= 0 or self.jobs <= 0:
            raise ValueError("timeout and jobs must be positive")
        if not Path(self.rules).is_file():
            raise ValueError("rules must be an existing local file; registry/URLs are forbidden")

    def command(self, target: Path, output_format: str):
        if output_format not in ("json", "sarif"):
            raise ValueError("unsupported output format")
        return [self.executable, "scan", "--config", str(Path(self.rules).resolve()),
                "--" + output_format, "--dataflow-traces", "--no-git-ignore",
                "--disable-version-check", "--jobs", str(self.jobs),
                "--timeout", str(self.timeout), "--include", "*.java", str(target.resolve())]
