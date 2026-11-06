"""Verify stand identity, manifest completeness and shared report failure semantics offline."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Run, Stand, verify_bundle


class CommonTests(unittest.TestCase):
    """Keep artifact and transport validation independent of live systems."""

    def fixture(self, root):
        """Create a minimal exact manifest with a nested file named manifest.json."""
        (root / 'nested').mkdir()
        (root / 'nested/manifest.json').write_text('{}')
        data = {'schema': 1, 'platform': 'linux-arm64', 'files': {'nested/manifest.json': hashlib.sha256(b'{}').hexdigest()}}
        (root / 'manifest.json').write_text(json.dumps(data))

    def test_nested_manifest_is_hashed(self):
        """A nested manifest filename cannot bypass artifact inventory or digest checks."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            verify_bundle(root)
            (root / 'nested/manifest.json').write_text('changed')
            with self.assertRaises(ValueError):
                verify_bundle(root)

    def test_extra_and_symlink_rejected(self):
        """Unexpected files and links fail before an artifact can be delivered."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / 'extra').write_text('extra')
            with self.assertRaises(ValueError):
                verify_bundle(root)
            (root / 'extra').unlink()
            (root / 'nested/manifest.json').unlink()
            (root / 'nested/manifest.json').symlink_to('../manifest.json')
            with self.assertRaises(ValueError):
                verify_bundle(root)

    def test_experimental_preflight_has_no_connection(self):
        """Keenetic placeholders are refused before invoking any transport command."""
        stand = Stand({'name': 'router', 'transport': 'ssh', 'host': 'router.invalid', 'user': 'root', 'platform': 'keenetic-arm64-experimental', 'expected_hostname': 'router'})
        with patch.object(subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                stand.preflight()
            run.assert_not_called()

    def test_wrong_identity_rejected(self):
        """A reachable host with the wrong identity cannot pass preflight."""
        stand = Stand({'name': 'lab', 'transport': 'ssh', 'host': 'lab.invalid', 'user': 'root', 'platform': 'linux-arm64', 'expected_hostname': 'expected'})
        with patch.object(stand, 'run', return_value=subprocess.CompletedProcess([], 0, 'unexpected\n')):
            with self.assertRaises(ValueError):
                stand.preflight()

    def test_failure_report(self):
        """A failing process produces FAIL with its exact exit status in the report."""
        with tempfile.TemporaryDirectory() as directory:
            report = Run(Path(directory) / 'output')
            self.assertFalse(report.phase('negative', [sys.executable, '-c', 'raise SystemExit(7)']))
            self.assertEqual(report.results[0]['exit'], 7)
            self.assertEqual(report.results[0]['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
