"""Check publication rejects runtime or source drift without invoking a compiler."""
import importlib.util
import hashlib
import json
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
            uapi = BUILD.KEENETIC_AWG_UAPI_DIRECTORY.encode()
            expected_binary = b'static awg runtime' + uapi + b'/'
            expected_hash = hashlib.sha256(expected_binary).hexdigest()
            for target in (root / 'bin/awg', root / 'opt/bin/awg'):
                target.write_bytes(expected_binary)
            (root / 'opt/bin/amneziawg-go').write_bytes(b'AWG daemon ' + uapi)
            BUILD.verify_packaged_inputs(root, {'awg-keenetic-static': expected_hash}, {})
            (root / 'opt/bin/awg').write_bytes(b'wrong dynamic runtime')
            with self.assertRaisesRegex(RuntimeError, 'awg-keenetic-static'):
                BUILD.verify_packaged_inputs(root, {'awg-keenetic-static': expected_hash}, {})

    def test_keenetic_awg_tools_and_daemon_share_uapi_directory(self):
        """Keenetic packaging rejects an AWG CLI that still targets the default UAPI directory."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'opt/bin').mkdir(parents=True)
            uapi = BUILD.KEENETIC_AWG_UAPI_DIRECTORY.encode()
            (root / 'opt/bin/amneziawg-go').write_bytes(b'prefix' + uapi + b'suffix')
            (root / 'opt/bin/awg').write_bytes(b'prefix' + uapi + b'/suffix')
            BUILD.verify_keenetic_awg_uapi(root)
            (root / 'opt/bin/awg').write_bytes(b'/var/run/amneziawg/interface.sock')
            with self.assertRaisesRegex(RuntimeError, 'UAPI socket directories'):
                BUILD.verify_keenetic_awg_uapi(root)

    def test_keenetic_awg_uapi_path_matches_runtime_adapter(self):
        """The package's shared UAPI path equals the directory used by the Entware runtime adapter."""
        source = (BUILD.ROOT / 'backend/internal/awgruntime/entware_linux.go').read_text()
        self.assertIn(BUILD.KEENETIC_AWG_UAPI_DIRECTORY, source)

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
        supervisor = (BUILD.ROOT / 'backend/internal/services/entware/ipc.go').read_text()
        preflight = (BUILD.ROOT / 'backend/cmd/keenetic-preflight/main.go').read_text()
        self.assertIn('for option in -S -K -b -m -p -x -s;', source)
        self.assertIn('start-stop-daemon -S -b -m -p "$PIDFILE" -x "$DAEMON"', source)
        self.assertIn('start-stop-daemon -K -p "$PIDFILE" -x "$DAEMON" -s TERM', source)
        self.assertIn('start-stop-daemon -K -p "$PIDFILE" -x "$DAEMON" -s KILL', source)
        self.assertIn('"$BUSYBOX" usleep 100000', source)
        self.assertIn('READY_TIMEOUT_SECONDS=2820', source)
        self.assertIn('while [ "$attempt" -lt "$((READY_TIMEOUT_SECONDS * 10))" ]; do', source)
        self.assertIn('const bootRecoveryLimit = 47 * time.Minute', supervisor)
        self.assertIn('"$DAEMON" -service-ingress-quiesce', source)
        self.assertIn('find_opkg_ancestor()', source)
        self.assertIn('Cannot identify the enclosing opkg process; refusing package replacement', source)
        self.assertIn('"$OPKG_PID" "$BOOT_ID" "$OPKG_START"', source)
        self.assertIn("awk '{ print $20 }'", source)
        manager = (BUILD.ROOT / 'backend/internal/services/entware/manager.go').read_text()
        marker_parser = (BUILD.ROOT / 'backend/internal/services/entware/maintenance_marker.go').read_text()
        self.assertIn('info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0', manager)
        self.assertIn('parsePackageMaintenanceMarker(data)', manager)
        self.assertIn('strings.Count(marker, "\\n") != 1', marker_parser)
        self.assertIn('strconv.Itoa(pid) != fields[0]', marker_parser)
        self.assertIn('strconv.FormatUint(startTime, 10) != fields[2]', marker_parser)
        self.assertIn('Hestia services were restored; package maintenance was canceled', source)
        self.assertIn('Hestia restart failed; package marker remains for guarded recovery', source)
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
            ingress_lock = root / 'opt/var/lock/hestia-ingress.lock'
            self.assertEqual(ingress_lock.read_bytes(), b'')
            self.assertEqual(ingress_lock.stat().st_mode & 0o777, 0o600)

    def test_keenetic_package_stages_complete_geoip_payload(self):
        """A Keenetic bundle includes the pinned index and every country routing rule set."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            BUILD.stage_keenetic_geoip(root)
            geoip = root / 'opt/share/hestia/geoip'
            BUILD.verify_keenetic_geoip(geoip)
            manifest = json.loads((geoip / 'manifest.json').read_bytes())
            self.assertEqual(len(manifest['countries']), 249)
            catalogue = (geoip / 'countries.txt').read_text(encoding='ascii').splitlines()
            self.assertEqual(len(catalogue), 249)
            self.assertEqual(catalogue, sorted(set(catalogue)))
            self.assertTrue((geoip / 'rule-set-source.sha256').is_file())
            self.assertTrue((geoip / 'RU.json').is_file())
            self.assertTrue((geoip / 'country.bin').read_bytes().startswith(b'HGI1'))

    def test_keenetic_postinst_seeds_each_whitespace_catalogue_country(self):
        """The installed country catalogue format matches postinst's line-by-line seed loop."""
        source = (BUILD.ROOT / 'deploy/keenetic/ipk/postinst').read_text()
        self.assertIn('while IFS= read -r code; do', source)
        self.assertIn('done <"$geoip_data/countries.txt"', source)
        self.assertIn('rule-set compile', source)
        self.assertIn('.srs', source)

    def test_keenetic_package_stages_synchronous_ingress_hook(self):
        """The Keenetic IPK installs the bounded netfilter callback with executable permissions."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            BUILD.stage_keenetic_hooks(root)
            hook = root / 'opt/etc/ndm/netfilter.d/090-hestia-ingress.sh'
            self.assertEqual(hook.read_text(), (BUILD.ROOT / 'deploy/keenetic/netfilter.d/090-hestia-ingress.sh').read_text())
            self.assertEqual(hook.stat().st_mode & 0o777, 0o755)
            self.assertIn('-service-reconcile-ingress', hook.read_text())
            self.assertIn('MARKER_BOOT" = "$BOOT_ID"', hook.read_text())
            self.assertIn('MARKER_START"', hook.read_text())
            self.assertIn('[ -z "$MARKER_EXTRA" ]', hook.read_text())
            self.assertIn('busybox wc -l <"$MAINTENANCE"', hook.read_text())
            self.assertIn("sed -n '2,$p'", hook.read_text())
            self.assertIn('MARKER_SIZE" = "$MARKER_EXPECTED_SIZE"', hook.read_text())
            self.assertIn("busybox stat -c '%u %a %h %s'", hook.read_text())
            self.assertIn('[ "$MARKER_UID" = 0 ]', hook.read_text())
            self.assertIn('opkg | opkg-cl', hook.read_text())

    def test_keenetic_source_manifest_tracks_ingress_implementation(self):
        """The artifact provenance allowlist covers every new ingress source and its target hook."""
        source = (BUILD.ROOT / 'scripts/build/run.py').read_text()
        inputs = (
            'backend/internal/binding/keenetic_ingress.go',
            'backend/internal/network/keeneticroute/ingress_codec_test.go',
            'backend/internal/network/keeneticroute/ingress_netlink_codec.go',
            'backend/internal/network/keeneticroute/ingress_netlink_linux.go',
            'backend/internal/network/keeneticroute/ingress_policy.go',
            'backend/internal/network/keeneticroute/ingress_policy_test.go',
            'backend/internal/network/keeneticroute/ingress_reconcile.go',
            'backend/internal/network/keeneticroute/ingress_reconcile_test.go',
            'backend/internal/services/entware/ingress_default.go',
            'backend/internal/services/entware/ingress_keenetic.go',
            'backend/internal/services/entware/ingress_profile.go',
            'backend/internal/services/entware/ingress_profile_test.go',
            'backend/internal/services/entware/maintenance_marker.go',
            'backend/internal/services/entware/maintenance_marker_test.go',
            'backend/pkg/keeneticrci/policy.go',
            'backend/pkg/keeneticrci/policy_test.go',
            'deploy/keenetic/netfilter.d/090-hestia-ingress.sh',
        )
        for path in inputs:
            with self.subTest(path=path):
                self.assertIn("'" + path + "'", source)

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
