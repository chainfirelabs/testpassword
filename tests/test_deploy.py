"""Each deploy/ folder must stand alone, and the copies must not drift apart."""
from pathlib import Path
import re
import unittest

DEPLOY = Path(__file__).resolve().parents[1] / 'deploy'
FOLDERS = sorted(path.parent for path in DEPLOY.rglob('compose.yaml'))


class DeployFolders(unittest.TestCase):
    def test_expected_folders(self):
        self.assertEqual([folder.relative_to(DEPLOY).as_posix() for folder in FOLDERS],
                         ['external-s3', 'split/api-host', 'split/data-host', 'standalone', 'standalone-s3'])

    def test_mounts_stay_inside_folder(self):
        for folder in FOLDERS:
            compose = (folder / 'compose.yaml').read_text()
            self.assertNotRegex(compose, r'\.\./', folder)
            # ./data is created at deploy time; every other mount ships with the folder.
            for source in re.findall(r'^\s*- (\./[^:]+):', compose, re.M):
                if source != './data':
                    self.assertTrue((folder / source).exists(), f'{folder}: {source}')

    def test_folders_that_download_have_one_step_ingest(self):
        for folder in FOLDERS:
            compose = (folder / 'compose.yaml').read_text()
            if 'download-sha1:' in compose:
                self.assertIn('\n  ingest:\n', compose, folder)

    def test_pinned_images_agree(self):
        pins = {}
        for folder in FOLDERS:
            for image in re.findall(r'image: ([^\s$]+@sha256:[0-9a-f]{64})', (folder / 'compose.yaml').read_text()):
                pins.setdefault(image.split('@')[0].split(':')[0], set()).add(image)
        self.assertEqual({name: refs for name, refs in pins.items() if len(refs) > 1}, {})

    def test_proxy_copies_agree(self):
        copies = {}
        for path in DEPLOY.rglob('proxy/**/*'):
            if path.is_file() and path.name != '.gitkeep':
                relative = path.relative_to(next(p for p in path.parents if p.name == 'proxy'))
                copies.setdefault(relative, set()).add(path.read_text())
        self.assertEqual({str(name): len(texts) for name, texts in copies.items() if len(texts) > 1}, {})


if __name__ == '__main__':
    unittest.main()
