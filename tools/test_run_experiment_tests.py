"""Regression against an experiment file silently running zero tests."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ExperimentRunnerTests(unittest.TestCase):
    """Exercise the same process boundary as the repository's test-experiments target."""

    def test_empty_module_fails_the_parent_command(self):
        """An existing test file with no discovered cases must produce a nonzero parent exit status."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / "tools" / "run_experiment_tests.py"
            runner.parent.mkdir()
            shutil.copyfile(Path(__file__).with_name(runner.name), runner)
            empty = root / "experiments" / "fixture" / "test_empty.py"
            empty.parent.mkdir(parents=True)
            empty.write_text('"""A fixture accidentally containing no tests."""\n')
            result = subprocess.run(
                [sys.executable, "-B", str(runner)],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("No test cases in", result.stderr)
            self.assertIn("test_empty.py", result.stderr)
