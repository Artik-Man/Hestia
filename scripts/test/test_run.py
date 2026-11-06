"""Verify installed testing reports failures and never loses final cleanup on cancellation."""
import hashlib
import importlib.util
import stat
import tarfile
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('installed_runner', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class InstalledRunnerTests(unittest.TestCase):
    """Use fake transport to verify cleanup without guest access."""

    def test_stage_contains_transitive_lab_dependencies(self):
        """The public fixture bundle must include the full dependency closure of all thirteen cases."""
        required = (
            'deploy/scheme3/guest-profile.json',
            'tests/lab/awg-multi/lab.sh', 'tests/lab/wg-underlay/lab.sh',
            'tests/lab/hysteria2/lab.sh', 'tests/lab/controller-routing/lab.sh',
            'tests/lab/group-quality/lab.sh', 'tests/lab/physical-connections/inventory.sh',
            'tests/lab/partial-loss/lab.sh', 'tests/lab/connection-quality/run.sh',
            'tests/lab/dns-panel/verify.py', 'tests/lab/failover/fixture.sh',
            'tests/lab/failover/config.json', 'tests/lab/failover/probes.py',
            'tests/lab/fakeip/traffic.py', 'tests/lab/scoped/config.json',
            'tests/lab/scoped/probes.py', 'tests/lab/observer/fixture.py',
            'tests/lab/steer-deny/check.py',
        )
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            execute = subprocess.run

            def skip_compiler(command, **kwargs):
                """Mock only Go compilation while exercising real tracked-source discovery and staging."""
                if command[:2] == ['go', 'build']:
                    return subprocess.CompletedProcess(command, 0)
                return execute(command, **kwargs)

            with patch.object(runner.subprocess, 'run', side_effect=skip_compiler):
                runner.prepare(stage)
            for name in required:
                self.assertTrue((stage / 'repo' / name).is_file(), name)
            # Execute the real staged relative imports/config builders, without a network or binary.
            script = ('import runpy,sys; from pathlib import Path; root=Path(sys.argv[1]); '
                      'group=runpy.run_path(str(root/"tests/lab/group-quality/check.py")); '
                      'out=root/"generated"; out.mkdir(); group["config"](out); '
                      'runpy.run_path(str(root/"tests/lab/scoped/probes.py")); '
                      'runpy.run_path(str(root/"tests/lab/controller-routing/verify.py"))')
            subprocess.run([runner.sys.executable, '-c', script, str(stage / 'repo')], check=True)
            self.assertFalse((stage / 'repo/deploy/profile.py').exists(), 'compiler must come from installed stand')

    def test_tar_metadata_cannot_make_stage_public(self):
        """Real extraction of a 0755 archive root must finish with a private 0700 run directory."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'source'
            source.mkdir(mode=0o755)
            source.chmod(0o755)
            (source / 'fixture').write_text('public test fixture')
            archive = base / 'incoming.tar'
            with tarfile.open(archive, 'w') as stream:
                stream.add(source, arcname='.')
            guest = base / 'guest'
            command = runner.extraction_command(str(guest), str(archive), subprocess.check_output(['hostname', '-s'], text=True).strip(), hashlib.sha256(archive.read_bytes()).hexdigest())
            subprocess.run(command, check=True)
            self.assertEqual(stat.S_IMODE(guest.stat().st_mode), 0o700)
            self.assertEqual((guest / 'fixture').read_text(), 'public test fixture')
            self.assertFalse(archive.exists())
            self.assertFalse((guest / 'fixtures.tar').exists())

    def test_transport_failure_still_checks_invariants(self):
        """After successful baseline a remote transport exception must still stop and verify state."""
        report = Mock()
        report.phase.side_effect = [True, subprocess.CalledProcessError(1, ['transport']), True, True]
        stand = Mock(data={'expected_hostname': 'chosen'}, env={})
        stand.run.return_value = Mock(returncode=0)
        with self.assertRaises(subprocess.CalledProcessError):
            runner.run_guest(report, stand, '/var/tmp/hestia-validation-test', 'test')
        names = [call.args[0] for call in report.phase.call_args_list]
        self.assertIn('installed-final-invariants', names)
        stand.run.assert_called_once()

    def test_cancellation_stops_and_verifies(self):
        """Polite interruption yields failure and verifies installed preservation before returning."""
        report = Mock()
        report.phase.side_effect = [True, KeyboardInterrupt(), True, True]
        stand = Mock(data={'expected_hostname': 'chosen'}, env={})
        stand.run.return_value = Mock(returncode=0)
        self.assertFalse(runner.run_guest(report, stand, '/var/tmp/hestia-validation-test', 'test'))
        report.fail.assert_called_once()
        self.assertIn('installed-final-invariants', [call.args[0] for call in report.phase.call_args_list])

    def test_prepare_failure_does_not_claim_preservation(self):
        """A failed baseline reports skipped runtime tests instead of checking a nonexistent snapshot."""
        report = Mock()
        report.phase.side_effect = [False, True]
        stand = Mock(data={'expected_hostname': 'chosen'}, env={})
        stand.run.return_value = Mock(returncode=0)
        self.assertFalse(runner.run_guest(report, stand, '/var/tmp/hestia-validation-test', 'test'))
        report.skip.assert_called_once()
        self.assertNotIn('installed-final-invariants', [call.args[0] for call in report.phase.call_args_list])

    def test_final_change_fails_run(self):
        """Passing functional checks cannot hide changed installed configuration or routes."""
        report = Mock()
        report.phase.side_effect = [True, True, True, False, True]
        stand = Mock(data={'expected_hostname': 'chosen'}, env={})
        stand.run.return_value = Mock(returncode=0)
        self.assertFalse(runner.run_guest(report, stand, '/var/tmp/hestia-validation-test', 'test'))


if __name__ == '__main__':
    unittest.main()
