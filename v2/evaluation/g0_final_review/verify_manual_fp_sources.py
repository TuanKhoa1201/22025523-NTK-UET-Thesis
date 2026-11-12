"""Public-source re-check of the four author-assigned FALSE_POSITIVE labels (#08/#09/#10/#15).

Sources: WebGoat at the pinned commit (public, HTTPS) and demo/UserDao.java read in-memory from the
advisor-provided opengrep-triage.zip (path given by --advisor-zip; its content is never written to the
repository). File identities are compared with the SHA-256 recorded for the captured experiment
sources; matching hashes mean the review below concerns exactly the scanned bytes.

Prints structural facts only (no verdict is produced): validator placement, callers, quote handling,
directory-boundary constant. Exit 0 = all identities match, 2 = mismatch, 3 = input unavailable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

WEBGOAT_COMMIT = "5357a65e054976cd7d79b81ef3906ded050ed921"
BASE = f"https://raw.githubusercontent.com/WebGoat/WebGoat/{WEBGOAT_COMMIT}/src/main/java/org/owasp/webgoat/"
FILES = {
    "SqlInjectionLesson8.java": "lessons/sqlinjection/introduction/SqlInjectionLesson8.java",
    "UserService.java": "container/users/UserService.java",
    "WebGoatUser.java": "container/users/WebGoatUser.java",
    "UserForm.java": "container/users/UserForm.java",
    "RegistrationController.java": "container/users/RegistrationController.java",
}
# Captured-source SHA-256 as recorded in the experiment evidence register (identity check only).
CAPTURED_SHA256 = {
    "SqlInjectionLesson8.java": "6e158ffbf3d9278d788280550e450ce982491a3a361aa7c80041a853193f6bd5",
    "UserService.java": "736d13a9bdea1cca24eb7cd49f2d669e1877834ab4c7cf3571a65a09b5f56587",
    "UserDao.java": "6c890fc869f74cdceb6bd8f73e04be4fc7ffb4defdab008c098642e146be1d24",
}


def grep(text: str, pattern: str) -> list[str]:
    return [f"{i}: {l.strip()}" for i, l in enumerate(text.splitlines(), 1) if re.search(pattern, l)]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--advisor-zip", type=Path, required=True)
    args = ap.parse_args(argv)
    src, identity = {}, {}
    try:
        for name, rel in FILES.items():
            with urllib.request.urlopen(BASE + rel, timeout=60) as r:
                src[name] = r.read()
        with zipfile.ZipFile(args.advisor_zip) as z:
            member = next(n for n in z.namelist() if n.endswith("demo/UserDao.java"))
            src["UserDao.java"] = z.read(member)
    except (OSError, StopIteration, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "INCOMPLETE", "error": f"{type(exc).__name__}: {exc}"}))
        return 3
    for name, expected in CAPTURED_SHA256.items():
        identity[name] = hashlib.sha256(src[name]).hexdigest() == expected
    t = {k: v.decode("utf-8") for k, v in src.items()}
    facts = {
        "#08_#09_log_quote_handling": grep(t["SqlInjectionLesson8.java"], r"replace\(|INSERT INTO access_log|executeUpdate\(logQuery|log\(connection"),
        "#10_sink": grep(t["UserService.java"], r"CREATE SCHEMA|public void addUser"),
        "#10_pattern_on_WebGoatUser": grep(t["WebGoatUser.java"], r"@Pattern"),
        "#10_pattern_on_UserForm": grep(t["UserForm.java"], r"@Pattern"),
        "#10_callers_of_addUser": grep(t["RegistrationController.java"], r"addUser\(|@Valid|@PostMapping|@GetMapping"),
        "#15_base_dir_and_guard": grep(t["UserDao.java"], r"BASE_DIR|getCanonicalPath|new File\("),
    }
    ok = all(identity.values())
    print(json.dumps({"status": "PASS" if ok else "FAIL", "identity_matches_captured": identity,
                      "webgoat_commit": WEBGOAT_COMMIT, "facts": facts}, ensure_ascii=False, indent=1))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
