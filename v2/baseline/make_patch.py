"""Generate the reviewable patch between the pinned snapshot and scanner-only fork."""
import difflib
from pathlib import Path

BASE = Path(__file__).resolve().parent


def render_patch():
    parts = []
    for name in ("scanner.py", "config.py", "cli.py"):
        path = Path("semgrepai") / name
        old = (BASE / "upstream" / path).read_text(encoding="utf-8").splitlines(keepends=True)
        new = (BASE / "fork" / path).read_text(encoding="utf-8").splitlines(keepends=True)
        parts.extend(difflib.unified_diff(old, new, fromfile="a/" + path.as_posix(),
                                        tofile="b/" + path.as_posix()))
    return "".join(parts)


if __name__ == "__main__":
    (BASE / "opengrep.patch").write_text(render_patch(), encoding="utf-8", newline="\n")
    print("Updated v2/baseline/opengrep.patch")
