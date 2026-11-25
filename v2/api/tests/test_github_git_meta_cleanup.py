"""Regression and fail-closed security tests for .git metadata cleanup in v2.api.intake.

Covers:
- Normal Windows read-only `.git/objects/pack/*.pack` cleanup and size-limit parity.
- Real Windows delete-refusal counterexamples (NTFS ACL deny DC+DE WinError 5 and open-handle lock WinError 32).
- Real Windows NTFS root junctions (external sentinel, internal target, broken junction) and nested junctions.
- Real symlinks (nested file/dir symlinks, broken root symlink, delete-denied broken symlink) when supported.
- Workspace boundary containment and ambiguous path rejection.
- Independent post-condition fail-closed verification (lstat PermissionError, scandir residual, mocked no-op helper).
- Exception-path workspace rollback safety preserving primary IntakeError and external sentinels.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from v2.api import intake
from v2.api.config import IntakeLimits


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _create_junction(link_path: Path, target_dir: Path) -> None:
    res = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link_path), str(target_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        raise unittest.SkipTest(f"NTFS junction creation unavailable: {res.stdout} {res.stderr}")


def _try_symlink(target: Path, link_path: Path, *, target_is_directory: bool = False) -> None:
    try:
        os.symlink(target, link_path, target_is_directory=target_is_directory)
    except OSError as exc:
        raise unittest.SkipTest(f"OS symlink creation unavailable in this environment: {exc}") from exc


def _create_sentinel(base_dir: Path, tag: str) -> tuple[Path, Path, str, int]:
    sdir = base_dir / f"sentinel_{tag}"
    sdir.mkdir(parents=True, exist_ok=False)
    sfile = sdir / "protected.txt"
    payload = f"IMMUTABLE_SENTINEL_{tag}\n".encode("utf-8")
    sfile.write_bytes(payload)
    os.chmod(sfile, stat.S_IREAD)
    attrs = getattr(os.lstat(sfile), "st_file_attributes", 0)
    return sdir, sfile, _sha256(sfile), attrs


def _force_teardown(root: Path, acl_paths: list[Path], link_paths: list[Path]) -> None:
    username = os.environ.get("USERNAME", "")
    for p in reversed(acl_paths):
        if os.name == "nt" and username:
            subprocess.run(["icacls", str(p), "/L", "/remove:d", username], capture_output=True, check=False)
            subprocess.run(["icacls", str(p), "/remove:d", username], capture_output=True, check=False)
        try:
            st = os.lstat(p)
            if not (os.name == "nt" and (getattr(st, "st_file_attributes", 0) & 0x400)):
                os.chmod(p, stat.S_IWRITE | stat.S_IREAD | (stat.S_IXUSR if stat.S_ISDIR(st.st_mode) and os.name != "nt" else 0))
        except OSError:
            pass
    for lp in reversed(link_paths):
        try:
            st = os.lstat(lp)
            is_rep = stat.S_ISLNK(st.st_mode) or (os.name == "nt" and bool(getattr(st, "st_file_attributes", 0) & 0x400))
            if is_rep:
                if stat.S_ISDIR(st.st_mode):
                    os.rmdir(lp)
                else:
                    os.unlink(lp)
        except OSError:
            pass
    if root.exists():
        for dirpath, dirnames, filenames in os.walk(root, topdown=False, followlinks=False):
            dp = Path(dirpath)
            for fn in filenames:
                fp = dp / fn
                try:
                    st = os.lstat(fp)
                    if stat.S_ISLNK(st.st_mode) or (os.name == "nt" and bool(getattr(st, "st_file_attributes", 0) & 0x400)):
                        os.unlink(fp)
                    else:
                        os.chmod(fp, stat.S_IWRITE | stat.S_IREAD)
                        os.unlink(fp)
                except OSError:
                    pass
            for dn in dirnames:
                sub = dp / dn
                try:
                    st = os.lstat(sub)
                    if stat.S_ISLNK(st.st_mode) or (os.name == "nt" and bool(getattr(st, "st_file_attributes", 0) & 0x400)):
                        try:
                            os.rmdir(sub)
                        except OSError:
                            os.unlink(sub)
                    else:
                        os.chmod(sub, stat.S_IWRITE | stat.S_IREAD | (stat.S_IXUSR if os.name != "nt" else 0))
                        os.rmdir(sub)
                except OSError:
                    pass
        try:
            os.rmdir(root)
        except OSError:
            pass


def _make_fake_git(dest: Path, setup_fn):
    def fake_run_git_step(step, cmd, *, timeout_seconds, env, max_output_bytes):
        if step == "clone":
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "Demo.java").write_text("public class Demo {}\n", encoding="utf-8")
            setup_fn(dest)
            return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")
        if step == "checkout":
            return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")
        if step == "rev-parse":
            return subprocess.CompletedProcess(cmd, 0, stdout=b"4e98f1cbbf896fdd06edcc9930515ebe0ade7c69\n", stderr=b"")
        raise AssertionError(f"Unexpected git step: {step}")

    return fake_run_git_step


class TestGithubGitMetaCleanup(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="ntk_git_meta_test_"))
        self._acl_paths: list[Path] = []
        self._link_paths: list[Path] = []

    def tearDown(self) -> None:
        _force_teardown(self._tmp, self._acl_paths, self._link_paths)

    def _assert_sentinel_intact(self, sdir: Path, sfile: Path, expected_sha: str, expected_attrs: int) -> None:
        self.assertTrue(sdir.is_dir(), "Sentinel directory must remain intact")
        self.assertTrue(sfile.is_file(), "Sentinel file must remain intact")
        self.assertEqual(_sha256(sfile), expected_sha, "Sentinel content/SHA-256 must not change")
        self.assertEqual(
            getattr(os.lstat(sfile), "st_file_attributes", 0),
            expected_attrs,
            "Sentinel file attributes/read-only state must not change",
        )

    def _deny_delete_windows(self, parent_dir: Path, child: Path, *, child_is_link: bool = False) -> None:
        username = os.environ.get("USERNAME", "")
        if os.name != "nt" or not username:
            self.skipTest("Windows NTFS icacls test requires Windows environment")
        cmds = [
            (["icacls", str(parent_dir), "/deny", f"{username}:(DC)"], parent_dir),
            (["icacls", str(child), *(["/L"] if child_is_link else []), "/deny", f"{username}:(DE)"], child),
        ]
        for cmd, target in cmds:
            r = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if r.returncode != 0:
                self.skipTest(f"icacls /deny unavailable: {r.stdout} {r.stderr}")
            self._acl_paths.append(target)

    def test_rmtree_readonly_safe_removes_readonly_git_packfiles(self) -> None:
        git_dir = self._tmp / "repo" / ".git"
        pack_dir = git_dir / "objects" / "pack"
        pack_dir.mkdir(parents=True)
        pack_file = pack_dir / "pack-test.pack"
        pack_file.write_bytes(b"X" * 4096)
        os.chmod(pack_file, stat.S_IREAD)
        os.chmod(pack_dir, stat.S_IREAD)

        intake._rmtree_readonly_safe(git_dir, workspace_root=self._tmp / "repo")
        with self.assertRaises(FileNotFoundError):
            os.lstat(git_dir)

    def test_clone_github_repo_strips_readonly_git_pack_before_size_check(self) -> None:
        dest = self._tmp / "source_ro"
        limits = IntakeLimits(max_uncompressed_bytes=4096, max_single_file_bytes=4096)

        def setup(d: Path) -> None:
            pack_dir = d / ".git" / "objects" / "pack"
            pack_dir.mkdir(parents=True, exist_ok=True)
            big_pack = pack_dir / "pack-history.pack"
            big_pack.write_bytes(b"P" * 20_000)
            os.chmod(big_pack, stat.S_IREAD)

        with patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest, setup)):
            inv = intake.clone_github_repo(
                "https://github.com/WebGoat/WebGoat",
                "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                dest,
                limits,
            )

        with self.assertRaises(FileNotFoundError):
            os.lstat(dest / ".git")
        self.assertEqual(inv["java_files_count"], 1)
        self.assertLess(inv["total_bytes"], 100)
        self.assertEqual(inv["resolved_commit"], "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69")

    @unittest.skipUnless(os.name == "nt", "Windows NTFS ACL counterexample")
    def test_windows_acl_deny_delete_fails_closed_in_clone_and_helper(self) -> None:
        # 1. Helper direct check
        repo_h = self._tmp / "acl_helper"
        pack_h = repo_h / ".git" / "objects" / "pack"
        pack_h.mkdir(parents=True)
        locked_h = pack_h / "denied.pack"
        locked_h.write_bytes(b"ACL_DENY_HELPER")
        self._deny_delete_windows(pack_h, locked_h)

        with self.assertRaises(PermissionError):
            intake._rmtree_readonly_safe(repo_h / ".git", workspace_root=repo_h)
        self.assertTrue(os.lstat(repo_h / ".git"))

        # 2. clone_github_repo() fail-closed before verify_extracted_java_tree
        dest = self._tmp / "acl_clone"

        def setup(d: Path) -> None:
            pack_dir = d / ".git" / "objects" / "pack"
            pack_dir.mkdir(parents=True, exist_ok=True)
            locked = pack_dir / "denied.pack"
            locked.write_bytes(b"ACL_DENY_CLONE")
            self._deny_delete_windows(pack_dir, locked)

        with (
            patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest, setup)),
            patch.object(intake, "verify_extracted_java_tree", side_effect=AssertionError("must not reach inventory")),
        ):
            with self.assertRaises(intake.IntakeError) as ctx:
                intake.clone_github_repo(
                    "https://github.com/WebGoat/WebGoat",
                    "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                    dest,
                    IntakeLimits(),
                )
        self.assertEqual(ctx.exception.error_code, "GITHUB_GIT_METADATA_CLEANUP_FAILED")
        self.assertEqual(ctx.exception.details.get("stage"), "git_metadata_cleanup")

    @unittest.skipUnless(os.name == "nt", "Windows kernel sharing-violation file lock counterexample")
    def test_windows_open_handle_lock_fails_closed_in_clone(self) -> None:
        dest = self._tmp / "lock_clone"
        handles = []

        def setup(d: Path) -> None:
            pack_dir = d / ".git" / "objects" / "pack"
            pack_dir.mkdir(parents=True, exist_ok=True)
            locked = pack_dir / "open.pack"
            locked.write_bytes(b"LOCKED_FILE")
            os.chmod(locked, stat.S_IREAD)
            handles.append(open(locked, "rb"))

        try:
            with (
                patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest, setup)),
                patch.object(intake, "verify_extracted_java_tree", side_effect=AssertionError("must not reach inventory")),
            ):
                with self.assertRaises(intake.IntakeError) as ctx:
                    intake.clone_github_repo(
                        "https://github.com/WebGoat/WebGoat",
                        "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                        dest,
                        IntakeLimits(),
                    )
            self.assertEqual(ctx.exception.error_code, "GITHUB_GIT_METADATA_CLEANUP_FAILED")
            self.assertEqual(ctx.exception.details.get("winerror"), 32)
        finally:
            for fh in handles:
                fh.close()

    @unittest.skipUnless(os.name == "nt", "Windows NTFS junction counterexample")
    def test_windows_root_junction_rejected_by_helper_and_clone_sentinel_intact(self) -> None:
        sdir, sfile, ssha, sattrs = _create_sentinel(self._tmp, "root_junc")

        # 1. Helper direct check
        repo_h = self._tmp / "junc_helper_repo"
        repo_h.mkdir()
        j_h = repo_h / ".git"
        _create_junction(j_h, sdir)
        self._link_paths.append(j_h)

        with self.assertRaises(OSError):
            intake._rmtree_readonly_safe(j_h)
        self._assert_sentinel_intact(sdir, sfile, ssha, sattrs)

        # 2. clone_github_repo() external sentinel
        dest_ext = self._tmp / "junc_clone_ext"

        def setup_ext(d: Path) -> None:
            j = d / ".git"
            _create_junction(j, sdir)
            self._link_paths.append(j)

        with (
            patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest_ext, setup_ext)),
            patch.object(intake, "verify_extracted_java_tree", side_effect=AssertionError("must not reach inventory")),
        ):
            with self.assertRaises(intake.IntakeError) as ctx:
                intake.clone_github_repo(
                    "https://github.com/WebGoat/WebGoat",
                    "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                    dest_ext,
                    IntakeLimits(),
                )
        self.assertEqual(ctx.exception.error_code, "SYMLINK_ESCAPE_DETECTED")
        self.assertEqual(ctx.exception.details.get("stage"), "git_metadata_cleanup")
        self._assert_sentinel_intact(sdir, sfile, ssha, sattrs)

        # 3. clone_github_repo() internal target junction (must never succeed)
        dest_int = self._tmp / "junc_clone_int"

        def setup_int(d: Path) -> None:
            inner = d / "assets"
            inner.mkdir()
            (inner / "a.txt").write_text("ok", encoding="utf-8")
            j = d / ".git"
            _create_junction(j, inner)
            self._link_paths.append(j)

        with (
            patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest_int, setup_int)),
            patch.object(intake, "verify_extracted_java_tree", side_effect=AssertionError("must not reach inventory")),
        ):
            with self.assertRaises(intake.IntakeError) as ctx_int:
                intake.clone_github_repo(
                    "https://github.com/WebGoat/WebGoat",
                    "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                    dest_int,
                    IntakeLimits(),
                )
        self.assertEqual(ctx_int.exception.error_code, "SYMLINK_ESCAPE_DETECTED")

    @unittest.skipUnless(os.name == "nt", "Windows NTFS nested junction counterexample")
    def test_windows_nested_junction_inside_git_rejected_and_sentinel_intact(self) -> None:
        sdir, sfile, ssha, sattrs = _create_sentinel(self._tmp, "nested_junc")
        dest = self._tmp / "nested_junc_clone"

        def setup(d: Path) -> None:
            hooks = d / ".git" / "hooks"
            hooks.mkdir(parents=True)
            (d / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            nj = hooks / "evil_junction"
            _create_junction(nj, sdir)
            self._link_paths.append(nj)

        with (
            patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest, setup)),
            patch.object(intake, "verify_extracted_java_tree", side_effect=AssertionError("must not reach inventory")),
        ):
            with self.assertRaises(intake.IntakeError) as ctx:
                intake.clone_github_repo(
                    "https://github.com/WebGoat/WebGoat",
                    "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                    dest,
                    IntakeLimits(),
                )
        self.assertEqual(ctx.exception.error_code, "SYMLINK_ESCAPE_DETECTED")
        self._assert_sentinel_intact(sdir, sfile, ssha, sattrs)

    def test_nested_symlinks_and_broken_root_symlink_fail_closed(self) -> None:
        sdir, sfile, ssha, sattrs = _create_sentinel(self._tmp, "nested_sym")
        dest_nested = self._tmp / "nested_sym_clone"

        def setup_nested(d: Path) -> None:
            hooks = d / ".git" / "hooks"
            hooks.mkdir(parents=True)
            _try_symlink(sdir, hooks / "dir_sym", target_is_directory=True)
            _try_symlink(sfile, hooks / "file_sym", target_is_directory=False)
            self._link_paths.extend([hooks / "dir_sym", hooks / "file_sym"])

        with (
            patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest_nested, setup_nested)),
            patch.object(intake, "verify_extracted_java_tree", side_effect=AssertionError("must not reach inventory")),
        ):
            with self.assertRaises(intake.IntakeError) as ctx:
                intake.clone_github_repo(
                    "https://github.com/WebGoat/WebGoat",
                    "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                    dest_nested,
                    IntakeLimits(),
                )
        self.assertEqual(ctx.exception.error_code, "SYMLINK_ESCAPE_DETECTED")
        self._assert_sentinel_intact(sdir, sfile, ssha, sattrs)

        # Broken root symlink
        dest_broken = self._tmp / "broken_sym_clone"

        def setup_broken(d: Path) -> None:
            sym = d / ".git"
            _try_symlink(self._tmp / "nonexistent_target", sym)
            self._link_paths.append(sym)

        with (
            patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest_broken, setup_broken)),
            patch.object(intake, "verify_extracted_java_tree", side_effect=AssertionError("must not reach inventory")),
        ):
            with self.assertRaises(intake.IntakeError) as ctx_b:
                intake.clone_github_repo(
                    "https://github.com/WebGoat/WebGoat",
                    "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                    dest_broken,
                    IntakeLimits(),
                )
        self.assertEqual(ctx_b.exception.error_code, "SYMLINK_ESCAPE_DETECTED")

    @unittest.skipUnless(os.name == "nt", "Windows broken NTFS junction counterexample")
    def test_windows_broken_root_junction_fails_closed(self) -> None:
        dest = self._tmp / "broken_junc_clone"

        def setup(d: Path) -> None:
            ephemeral = self._tmp / "ephemeral_target_dir"
            ephemeral.mkdir()
            j = d / ".git"
            _create_junction(j, ephemeral)
            self._link_paths.append(j)
            ephemeral.rmdir()

        with (
            patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest, setup)),
            patch.object(intake, "verify_extracted_java_tree", side_effect=AssertionError("must not reach inventory")),
        ):
            with self.assertRaises(intake.IntakeError) as ctx:
                intake.clone_github_repo(
                    "https://github.com/WebGoat/WebGoat",
                    "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                    dest,
                    IntakeLimits(),
                )
        self.assertEqual(ctx.exception.error_code, "SYMLINK_ESCAPE_DETECTED")
        self.assertEqual(ctx.exception.details.get("reparse_kind"), "NTFS_JUNCTION")

    def test_boundary_containment_rejects_escape_and_ambiguous_paths(self) -> None:
        ws = self._tmp / "workspace"
        ws.mkdir()
        sdir, sfile, ssha, sattrs = _create_sentinel(self._tmp, "boundary")

        with self.assertRaises(OSError):
            intake._rmtree_readonly_safe(sdir, workspace_root=ws)
        with self.assertRaises(OSError):
            intake._rmtree_readonly_safe(ws / ".." / sdir.name, workspace_root=ws)
        with self.assertRaises(OSError):
            intake._rmtree_readonly_safe(ws, workspace_root=ws)
        self._assert_sentinel_intact(sdir, sfile, ssha, sattrs)

    def test_mock_postcheck_fails_closed_on_noop_helper_and_lstat_permission_error(self) -> None:
        # 1. Mocked helper returns None without deleting .git -> independent post-check MUST fail closed.
        dest1 = self._tmp / "mock_noop_helper"

        def setup1(d: Path) -> None:
            (d / ".git").mkdir(parents=True)
            (d / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

        with (
            patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest1, setup1)),
            patch.object(intake, "_rmtree_readonly_safe", return_value=None),
            patch.object(intake, "verify_extracted_java_tree", side_effect=AssertionError("must not reach inventory")),
        ):
            with self.assertRaises(intake.IntakeError) as ctx1:
                intake.clone_github_repo(
                    "https://github.com/WebGoat/WebGoat",
                    "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                    dest1,
                    IntakeLimits(),
                )
        self.assertEqual(ctx1.exception.error_code, "GITHUB_GIT_METADATA_CLEANUP_FAILED")
        self.assertEqual(ctx1.exception.details.get("reason"), "POSTCHECK_METADATA_REMAINS")

        # 2. Mocked post-check os.lstat raises PermissionError -> MUST fail closed.
        dest2 = self._tmp / "mock_postcheck_perm"
        real_lstat = os.lstat

        def flaky_lstat(path, *args, **kwargs):
            p = Path(path)
            if p.name == ".git" and p.parent.resolve() == dest2.resolve():
                try:
                    return real_lstat(path, *args, **kwargs)
                except FileNotFoundError:
                    raise PermissionError(13, "Simulated post-check PermissionError", str(path)) from None
            return real_lstat(path, *args, **kwargs)

        with (
            patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest2, setup1)),
            patch("v2.api.intake.os.lstat", side_effect=flaky_lstat),
            patch.object(intake, "verify_extracted_java_tree", side_effect=AssertionError("must not reach inventory")),
        ):
            with self.assertRaises(intake.IntakeError) as ctx2:
                intake.clone_github_repo(
                    "https://github.com/WebGoat/WebGoat",
                    "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                    dest2,
                    IntakeLimits(),
                )
        self.assertEqual(ctx2.exception.error_code, "GITHUB_GIT_METADATA_CLEANUP_FAILED")

    @unittest.skipUnless(os.name == "nt", "Windows rollback cleanup safety with NTFS junction")
    def test_exception_rollback_cleanup_preserves_primary_error_and_sentinel(self) -> None:
        sdir, sfile, ssha, sattrs = _create_sentinel(self._tmp, "rollback")
        dest = self._tmp / "rollback_clone"

        def setup(d: Path) -> None:
            (d / ".git").mkdir(parents=True)
            (d / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            j = d / "src_link"
            _create_junction(j, sdir)
            self._link_paths.append(j)

        with patch.object(intake, "_run_git_step", side_effect=_make_fake_git(dest, setup)):
            with self.assertRaises(intake.IntakeError) as ctx:
                intake.clone_github_repo(
                    "https://github.com/WebGoat/WebGoat",
                    "4e98f1cbbf896fdd06edcc9930515ebe0ade7c69",
                    dest,
                    IntakeLimits(),
                )
        self.assertEqual(ctx.exception.error_code, "SYMLINK_ESCAPE_DETECTED")
        self._assert_sentinel_intact(sdir, sfile, ssha, sattrs)


if __name__ == "__main__":
    unittest.main()
