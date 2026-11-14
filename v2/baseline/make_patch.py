"""Generate the reviewable patch between the pinned snapshot and scanner-only fork."""
import difflib
from pathlib import Path

BASE = Path(__file__).resolve().parent


def render_patch():
    parts = []
    for name in ("scanner.py", "config.py", "cli.py", "scan_manifest.py"):
        path = Path("semgrepai") / name
        source = BASE / "upstream" / path
        old = source.read_text(encoding="utf-8").splitlines(keepends=True) if source.exists() else []
        new = (BASE / "fork" / path).read_text(encoding="utf-8").splitlines(keepends=True)
        parts.extend(difflib.unified_diff(old, new, fromfile="a/" + path.as_posix() if source.exists() else "/dev/null",
                                        tofile="b/" + path.as_posix()))
    return "".join(parts)


if __name__ == "__main__":
    (BASE / "opengrep.patch").write_text(render_patch(), encoding="utf-8", newline="\n")
    print("Updated v2/baseline/opengrep.patch")
