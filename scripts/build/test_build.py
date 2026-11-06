"""Check publication rejects runtime or source drift without invoking a compiler."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('artifact_build', Path(__file__).with_name('run.py'))
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class BuildTests(unittest.TestCase):
    """Verify final packaged bytes against the inputs that were approved before compilation."""

    def test_runtime_mutation_after_initial_check(self):
        """A modified runtime copy cannot inherit the original pinned provenance in its manifest."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bin').mkdir()
            runtime = root / 'bin/awg'
            runtime.write_bytes(b'approved')
            expected = BUILD.file_hash(runtime)
            runtime.write_bytes(b'mutated during build')
            with self.assertRaisesRegex(RuntimeError, 'Packaged runtime'):
                BUILD.verify_packaged_inputs(root, {'awg': expected}, {})

    def test_source_mutation_during_packaging(self):
        """A source edit after compilation fails the final packaging provenance guard."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.py'
            source.write_text('approved')
            expected = BUILD.file_hash(source)
            source.write_text('edited while packaging')
            with patch.object(BUILD, 'ROOT', root):
                with self.assertRaisesRegex(RuntimeError, 'during packaging'):
                    BUILD.verify_packaged_inputs(root, {}, {'input.py': expected})

    def test_go_check_has_no_packaging_dependencies(self):
        """CI Go-only mode invokes the shared compiler without checking runtime or invoking npm."""
        with patch.object(BUILD.sys, 'argv', ['run.py', '--check-go', '--output', '/tmp/go-check']), patch.object(BUILD, 'compile_go') as compile_go, patch.object(BUILD, 'build') as package:
            BUILD.main()
        compile_go.assert_called_once_with(Path('/tmp/go-check').resolve())
        package.assert_not_called()

    def test_frontend_license_notice_is_packaged(self):
        """Both artifact variants receive the generated notice within the installed browser tree."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'frontend/browser').mkdir(parents=True)
            (root / 'frontend/browser/index.html').write_text('panel')
            (root / 'frontend/3rdpartylicenses.txt').write_text('dependency notices')
            BUILD.copy_frontend(root / 'frontend', root / 'bundle/browser')
            self.assertEqual((root / 'bundle/browser/3rdpartylicenses.txt').read_text(), 'dependency notices')


if __name__ == '__main__':
    unittest.main()
