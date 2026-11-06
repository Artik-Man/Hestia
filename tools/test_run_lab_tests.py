"""Regression against a lab file silently running zero tests."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class LabRunnerTests(unittest.TestCase):
    """Exercise the same process boundary as the repository's test-lab target."""

    def test_script_tree_runs_hyphenated_nonpackage_directory(self):
        """A failing case in a nonpackage scripts/test-source folder must fail the workflow gate."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / "tools" / "run_lab_tests.py"
            runner.parent.mkdir()
            shutil.copyfile(Path(__file__).with_name(runner.name), runner)
            test = root / "scripts" / "test-source" / "test_failure.py"
            test.parent.mkdir(parents=True)
            test.write_text('import unittest\nclass Regression(unittest.TestCase):\n    def test_failure(self):\n        self.fail("discovery sentinel")\n')
            result = subprocess.run([sys.executable, str(runner), "--tree", "scripts"], cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("discovery sentinel", result.stderr)
            self.assertIn("Ran 1 test", result.stderr)

    def test_empty_script_tree_fails(self):
        """A workflow tree without any modules cannot produce a successful empty run."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / "tools" / "run_lab_tests.py"
            runner.parent.mkdir()
            shutil.copyfile(Path(__file__).with_name(runner.name), runner)
            result = subprocess.run([sys.executable, str(runner), "--tree", "scripts"], cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("No lab test modules", result.stderr)

    def test_empty_module_fails_the_parent_command(self):
        """An existing test file with no discovered cases must produce a nonzero parent exit status."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / "tools" / "run_lab_tests.py"
            runner.parent.mkdir()
            shutil.copyfile(Path(__file__).with_name(runner.name), runner)
            empty = root / "tests" / "lab" / "fixture" / "test_empty.py"
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
