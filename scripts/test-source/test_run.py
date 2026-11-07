"""Verify durable source-run failure reports without invoking tools or stands."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('source_runner', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class SourceReportingTests(unittest.TestCase):
    """Ensure missing prerequisites and cancellation cannot be mistaken for success."""

    def test_interruption_reported(self):
        """Cancellation records an explicit incomplete failure and nonzero exit."""
        report = Mock()
        with patch.object(runner, 'ACTIVE_REPORT', report), patch.object(runner, 'main', side_effect=KeyboardInterrupt()):
            self.assertEqual(runner.entrypoint(), 130)
        report.fail.assert_called_once_with('interrupted', 'Source validation interrupted; coverage incomplete')

    def test_prerequisite_failure_reported(self):
        """A missing local prerequisite becomes a durable FAIL record."""
        report = Mock()
        with patch.object(runner, 'ACTIVE_REPORT', report), patch.object(runner, 'main', side_effect=FileNotFoundError('missing tool')):
            self.assertEqual(runner.entrypoint(), 2)
        report.fail.assert_called_once_with('prerequisite-or-orchestration', 'missing tool')

    def test_source_manifest_includes_non_ignored_untracked_files(self):
        """Disposable API sources include untracked files while respecting Git ignores."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tracked = root / 'backend/cmd/hestia/main.go'
            untracked = root / 'backend/internal/platform/compose.go'
            tracked.parent.mkdir(parents=True)
            untracked.parent.mkdir(parents=True)
            tracked.write_text('package main\n')
            untracked.write_text('package platform\n')
            names = [str(tracked.relative_to(root)), str(untracked.relative_to(root))]
            listing = ('\0'.join(names) + '\0').encode()
            with patch.object(runner, 'ROOT', root), patch.object(runner.subprocess, 'check_output', return_value=listing) as check:
                self.assertEqual(runner.source_files(), names)
                self.assertIn('--others', check.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
