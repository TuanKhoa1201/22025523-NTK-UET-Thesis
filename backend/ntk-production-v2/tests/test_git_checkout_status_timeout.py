"""Git status remains fail-closed, including on slow Windows/WSL DrvFS."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ntk_web_backend_service as service


class GitStatusTimeoutTests(unittest.TestCase):
    def test_status_keeps_full_untracked_check_and_long_timeout(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(service.subprocess, 'run', return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout='', stderr='')) as call:
                self.assertTrue(service.cached_checkout_is_clean(Path(temp)))
        cmd = call.call_args.args[0]
        self.assertIn('--untracked-files=all', cmd)
        self.assertIn('core.filemode=false', cmd)
        self.assertGreaterEqual(call.call_args.kwargs['timeout'], 90)
        self.assertEqual(call.call_args.kwargs['env']['GIT_OPTIONAL_LOCKS'], '0')

    def test_dirty_tracked_or_untracked_is_rejected(self):
        for raw in (' M Modified.java\n', '?? Extra.java\n'):
            with self.subTest(raw=raw):
                with patch.object(service.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=raw, stderr='')):
                    self.assertFalse(service.cached_checkout_is_clean(Path('/tmp/test-repo')))

    def test_timeout_is_explicit_error_not_clean_checkout(self):
        with patch.object(service.subprocess, 'run', side_effect=subprocess.TimeoutExpired('git', 120)):
            with self.assertRaises(service.GitCheckoutVerificationError) as error:
                service.cached_checkout_is_clean(Path('/tmp/test-repo'))
        self.assertEqual(error.exception.code, 'GIT_STATUS_VERIFICATION_TIMEOUT')

    def test_git_failure_is_explicit_error(self):
        with patch.object(service.subprocess, 'run', return_value=subprocess.CompletedProcess(
                args=[], returncode=128, stdout='', stderr='fatal: invalid index')):
            with self.assertRaises(service.GitCheckoutVerificationError) as error:
                service.cached_checkout_is_clean(Path('/tmp/test-repo'))
        self.assertEqual(error.exception.code, 'GIT_STATUS_PROCESS_FAILED')

    def test_timeout_configuration_is_bounded(self):
        for timeout in ('0', '999', 'invalid'):
            with self.subTest(timeout=timeout):
                with self.assertRaises(service.GitCheckoutVerificationError) as error:
                    service.cached_checkout_is_clean(Path('/tmp/test-repo'),
                        env={'NTK_GIT_STATUS_TIMEOUT_SEC': timeout})
                self.assertEqual(error.exception.code, 'GIT_STATUS_TIMEOUT_CONFIG_INVALID')

    def test_real_tiny_git_repo_clean_and_dirty(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
            (root / 'Example.java').write_text('class Example {}\n')
            subprocess.run(['git', '-C', str(root), 'add', 'Example.java'], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=NTK Test',
                            '-c', 'user.email=ntk-test@example.invalid',
                            'commit', '-qm', 'fixture'], check=True, capture_output=True)
            self.assertTrue(service.cached_checkout_is_clean(root))
            (root / 'extra.java').write_text('class Extra {}\n')
            self.assertFalse(service.cached_checkout_is_clean(root))


if __name__ == '__main__':
    unittest.main()
