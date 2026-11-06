"""Verify offline artifact refusal and rollback serialization without changing a stand."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('deploy_driver', Path(__file__).with_name('run.py'))
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class DeployTests(unittest.TestCase):
    """Exercise negative delivery and the real rollback function with fake system commands."""

    def test_experimental_before_connection(self):
        """Experimental artifacts fail before preflight, copy or mutation."""
        stand = Mock()
        with patch.object(DRIVER, 'verify_bundle', return_value={'platform': 'keenetic-arm64-experimental', 'experimental': True}):
            with self.assertRaises(ValueError):
                DRIVER.deploy(Path('/unused'), stand, Mock())
        stand.preflight.assert_not_called()
        stand.copy.assert_not_called()

    def rollback(self, changed, restore_failure=False, stop_failure=False):
        """Run extracted rollback code while recording lock, stop and restore ordering."""
        source = Path(__file__).with_name('apply.sh').read_text()
        function = source.split('# rollback restores', 1)[1].split('trap rollback EXIT', 1)[0]
        function = '# rollback restores' + function
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config.sha256').write_text('config\n')
            (root / 'published.sha256').write_text('published\n')
            setup = '''set +e
backup=$1
ready=1
published=1
released=1
units=(hestia.service)
awg_units=()
# flock records the exclusive rollback boundary.
flock() { echo lock; }
# config_digest models the unchanged installed profile.
config_digest() { echo config; }
# application_digest models either this or a newer publication.
application_digest() { echo "$2"; }
# stop_existing_units records service mutations without executing them.
stop_existing_units() { echo stop; }
# rm avoids touching real application paths.
rm() { :; }
# tar records a restoration without extracting real files.
tar() { echo restore; }
# resume records completion without starting services.
resume() { echo resume; }
'''.replace('echo "$2";', 'echo newer;' if changed else 'echo published;')
            if stop_failure:
                setup = setup.replace('stop_existing_units() { echo stop; }', 'stop_existing_units() { echo stop; return 1; }')
            if restore_failure:
                setup = setup.replace('tar() { echo restore; }', 'tar() { echo restore; return 1; }')
            return subprocess.run(['bash', '-c', setup + function + '\nfalse\nrollback\n', '_', str(root)], capture_output=True, text=True)

    def test_rollback_refuses_newer_application(self):
        """A newer publication is preserved without stopping its services or restoring files."""
        result = self.rollback(True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('lock', result.stdout)
        self.assertNotIn('restore', result.stdout)
        self.assertNotIn('stop', result.stdout)

    def test_rollback_lock_precedes_restore(self):
        """Unchanged-generation rollback takes the lock before touching services and files."""
        result = self.rollback(False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.splitlines(), ['lock', 'stop', 'restore', 'resume'])

    def test_restore_failure_is_reported(self):
        """A failed backup extraction never claims successful restoration or restarts services."""
        result = self.rollback(False, restore_failure=True)
        self.assertNotIn('prior application restored', result.stderr)
        self.assertNotIn('resume', result.stdout)
        self.assertIn('restoration failed', result.stderr)

    def fresh_rollback(self, pending):
        """Run the real fresh rollback against temporary paths and a changed publication."""
        source = Path(__file__).with_name('fresh.sh').read_text()
        function = '# rollback restores' + source.split('# rollback restores', 1)[1].split('trap rollback EXIT', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'hestia'
            config.mkdir()
            (config / 'profile.json').write_text('operator state')
            if pending:
                (config / '.binding-pending').write_text('pending')
            (root / 'lock').touch()
            (root / 'published.sha256').write_text('published\n')
            function = function.replace('/etc/hestia', str(config)).replace('/run/hestia-install.lock', str(root / 'lock'))
            setup = """set +e
backup=$1
backup_ready=1
base_complete=1
released=1
new_panel=0
new_snapshot=0
units=()
paths=()
# flock records acquisition without using the global lock.
flock() { echo lock; }
# fresh_identity represents an intervening publication.
fresh_identity() { echo newer; }
# stop_existing_units records any forbidden early destructive operation.
stop_existing_units() { echo stopped; }
"""
            result = subprocess.run(['bash', '-c', setup + function + '\nfalse\nrollback\n', '_', str(root)], capture_output=True, text=True)
            self.assertEqual((config / 'profile.json').read_text(), 'operator state')
            return result

    def test_fresh_refuses_intervening_generation(self):
        """A changed first-install generation is preserved before service stops or removal."""
        result = self.fresh_rollback(False)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('stopped', result.stdout)
        self.assertIn('generation changed', result.stderr)

    def test_fresh_refuses_pending_binding(self):
        """A pending binding transaction prevents the outer fresh wrapper deleting its state."""
        result = self.fresh_rollback(True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('stopped', result.stdout)
        self.assertIn('Pending binding', result.stderr)

    def test_stop_failure_prevents_restoration(self):
        """Failure to quiesce services aborts destructive restore and preserves the backup."""
        result = self.rollback(False, stop_failure=True)
        self.assertNotIn('restore', result.stdout)
        self.assertNotIn('resume', result.stdout)
        self.assertIn('could not stop', result.stderr)

    def test_standard_lock_mode(self):
        """The actual updater permission guard accepts standard0640 and rejects group-writable0660."""
        source = Path(__file__).with_name('apply.sh').read_text()
        guard = next(line for line in source.splitlines() if line.startswith('[[ $(stat -c %a /run/hestia-install.lock)'))
        setup = '# stat supplies the installed lock mode without touching host files.\nstat() { echo "$1_mode"; }\n'
        for mode, expected in [('640', 0), ('660', 1)]:
            command = setup.replace('$1_mode', mode) + guard
            result = subprocess.run(['bash', '-c', command], capture_output=True)
            self.assertEqual(result.returncode, expected)

    def test_stop_helper_absent_and_failed_units(self):
        """Absent optional units are harmless while a loaded unit that cannot stop fails closed."""
        helper = Path(__file__).parents[1] / 'shared/paths.sh'
        setup = """source "$1"
# systemctl simulates unit lookup and records an actual stop failure.
systemctl() {
    if [[ $1 == show ]]; then
        if [[ $4 == absent.service ]]; then echo not-found; else echo loaded; fi
    else echo attempted-stop; return 1; fi
}
stop_existing_units "$2"
"""
        absent = subprocess.run(['bash', '-c', setup, '_', str(helper), 'absent.service'], capture_output=True, text=True)
        failed = subprocess.run(['bash', '-c', setup, '_', str(helper), 'active.service'], capture_output=True, text=True)
        self.assertEqual(absent.returncode, 0)
        self.assertNotIn('attempted-stop', absent.stdout)
        self.assertEqual(failed.returncode, 1)
        self.assertIn('attempted-stop', failed.stdout)


if __name__ == '__main__':
    unittest.main()
