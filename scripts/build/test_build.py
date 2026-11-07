"""Check publication rejects runtime or source drift without invoking a compiler."""
import importlib.util
import hashlib
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

    def test_keenetic_awg_uses_static_runtime(self):
        """Keenetic bundles pin both AWG tool copies to the known static ARM64 runtime."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'keenetic-arm64-experimental'
            (root / 'bin').mkdir(parents=True)
            (root / 'opt/bin').mkdir(parents=True)
            expected_binary = b'static awg runtime'
            expected_hash = hashlib.sha256(expected_binary).hexdigest()
            for target in (root / 'bin/awg', root / 'opt/bin/awg'):
                target.write_bytes(expected_binary)
            BUILD.verify_packaged_inputs(root, {'awg-keenetic-static': expected_hash}, {})
            (root / 'opt/bin/awg').write_bytes(b'wrong dynamic runtime')
            with self.assertRaisesRegex(RuntimeError, 'awg-keenetic-static'):
                BUILD.verify_packaged_inputs(root, {'awg-keenetic-static': expected_hash}, {})

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

    def test_keenetic_init_uses_busybox_short_options(self):
        """Keenetic lifecycle uses the short start-stop-daemon flags supported by target BusyBox."""
        source = (BUILD.ROOT / 'deploy/keenetic/S99hestia').read_text()
        preflight = (BUILD.ROOT / 'backend/cmd/keenetic-preflight/main.go').read_text()
        self.assertIn('for option in -S -K -b -m -p -x -s;', source)
        self.assertIn('start-stop-daemon -S -b -m -p "$PIDFILE" -x "$DAEMON"', source)
        self.assertIn('start-stop-daemon -K -p "$PIDFILE" -x "$DAEMON" -s TERM', source)
        self.assertIn('start-stop-daemon -K -p "$PIDFILE" -x "$DAEMON" -s KILL', source)
        self.assertIn('"$BUSYBOX" usleep 100000', source)
        self.assertNotIn('sleep 0.1', source)
        for unsupported in ('--make-pidfile', '--pidfile', '--exec', '--background', '--retry'):
            self.assertNotIn(unsupported, source)
        self.assertIn('mustOutput("/opt/bin/busybox", "uname", "-m")', preflight)
        self.assertNotIn('mustOutput("/bin/uname", "-m")', preflight)
        self.assertNotIn('print-architecture', preflight)
        self.assertNotIn('verifyOpkgArchitecture', preflight)

    def test_keenetic_package_declares_profile_unicode_dependency(self):
        """The IPK and its manifest include Entware's Python Unicode module package."""
        source = (BUILD.ROOT / 'scripts/build/run.py').read_text()
        self.assertIn("['python3-light', 'python3-codecs', 'busybox', 'libc']", source)
        self.assertIn("'entware_dependencies': ['python3-light', 'python3-codecs', 'busybox', 'libc']", source)

    def test_keenetic_managed_panel_uses_installed_country_map(self):
        """The managed panel does not receive a custom country-map override it rejects."""
        source = (BUILD.ROOT / 'backend/internal/services/entware/process.go').read_text()
        panel = source.split('case services.Panel:', 1)[1].split('case services.DNS:', 1)[0]
        self.assertNotIn('"-country-map"', panel)

    def test_keenetic_package_seeds_install_lock(self):
        """A fresh Entware package contains the stable root-only lock used by managed readers."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            BUILD.stage_keenetic_install_lock(root)
            lock = root / 'opt/var/lock/hestia-install.lock'
            self.assertTrue(lock.is_file())
            self.assertEqual(lock.read_bytes(), b'')
            self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

    def test_keenetic_panel_registers_physical_helper_without_awg(self):
        """The read-only physical inventory helper is wired independently from AWG features."""
        process = (BUILD.ROOT / 'backend/internal/services/entware/process.go').read_text()
        panel = (BUILD.ROOT / 'backend/internal/panel/panel.go').read_text()
        spec = process.split('case services.Panel:', 1)[1].split('case services.DNS:', 1)[0]
        self.assertIn('"-enable-physical"', spec)
        self.assertIn('enablePhysical := flag.Bool("enable-physical"', panel)
        self.assertIn('if *enablePhysical {', panel)
        inventory_block = panel.split('if *enablePhysical {', 1)[1].split('if *enableAWG {', 1)[0]
        self.assertIn('writes.physicalInventory = runAWGHelper', inventory_block)
        self.assertNotIn('writes.physical =', inventory_block)
        self.assertIn('registerPhysical(api, writes.physicalInventory, writes.physical)', panel)
        self.assertIn('registerHysteria2(api, writes.hysteria2)', panel)


if __name__ == '__main__':
    unittest.main()
