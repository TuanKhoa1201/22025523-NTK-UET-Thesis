"""Generate the reviewable patch between the pinned snapshot and scanner-only fork."""
import difflib
from pathlib import Path

base = Path(__file__).resolve().parent
parts = []
for name in ("scanner.py", "config.py", "cli.py"):
    path = Path("semgrepai") / name
    old = (base / "upstream" / path).read_text(encoding="utf-8").splitlines(keepends=True)
    new = (base / "fork" / path).read_text(encoding="utf-8").splitlines(keepends=True)
    parts.extend(difflib.unified_diff(old, new, fromfile="a/" + path.as_posix(),
                                    tofile="b/" + path.as_posix()))
(base / "opengrep.patch").write_text("".join(parts), encoding="utf-8")
print("Updated v2/baseline/opengrep.patch")
