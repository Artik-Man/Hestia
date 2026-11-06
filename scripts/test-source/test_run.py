"""Verify durable source-run failure reports without invoking tools or stands."""
import importlib.util
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
