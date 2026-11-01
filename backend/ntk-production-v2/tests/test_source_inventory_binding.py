"""Content hashes for every cached source must bind to the current checkout."""
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
import ntk_web_backend_service as service


class CachedSourceTests(unittest.TestCase):
    def test_mode_only_cache_change_is_ignored_but_changed_bytes_and_untracked_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'Plain.java';source.write_text('class Plain {}')
            def git(*args):
                return subprocess.run(['git','-C',str(root),*args],check=True,capture_output=True,text=True)
            git('init','-q');git('config','core.filemode','true');git('add','Plain.java')
            git('-c','user.name=NTK acceptance','-c','user.email=acceptance@example.invalid','commit','-qm','fixture')
            source.chmod(0o755)
            self.assertTrue(service.cached_checkout_is_clean(root))
            self.assertEqual(git('config','--get','core.filemode').stdout.strip(),'true')
            source.write_text('class Changed {}')
            self.assertFalse(service.cached_checkout_is_clean(root))
            source.write_text('class Plain {}');(root/'Extra.java').write_text('class Extra {}')
            self.assertFalse(service.cached_checkout_is_clean(root))

    def test_middle_file_change_or_missing_hash_invalidates_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = ['a.java', 'b.java', 'c.java']
            hashes = {}
            for name in paths:
                (root/name).write_text('class Example {}')
                hashes[name] = hashlib.sha256((root/name).read_bytes()).hexdigest()
            inventory = {'java_files': paths, 'file_sha256_map': hashes}
            self.assertTrue(service.cached_inventory_matches_sources(root, inventory))
            (root/'b.java').write_text('class Changed {}')
            self.assertFalse(service.cached_inventory_matches_sources(root, inventory))
            (root/'b.java').write_text('class Example {}')
            del hashes['b.java']
            self.assertFalse(service.cached_inventory_matches_sources(root, inventory))

    def test_traversal_or_source_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root/'Source.java';source.write_text('class Source {}')
            sha = hashlib.sha256(source.read_bytes()).hexdigest()
            for relative in ['../Source.java', str(source)]:
                self.assertFalse(service.cached_inventory_matches_sources(root, {'java_files':[relative], 'file_sha256_map':{relative:sha}}))
            (root/'Link.java').symlink_to(source)
            self.assertFalse(service.cached_inventory_matches_sources(root, {'java_files':['Link.java'], 'file_sha256_map':{'Link.java':sha}}))
