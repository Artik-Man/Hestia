"""Host-only failure tests for installed acceptance ownership and cleanup contracts."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('acceptance', Path(__file__).with_name('acceptance.py'))
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class AcceptanceSafetyTests(unittest.TestCase):
    """Prove failed or interrupted checks preserve foreign state and remove owned state."""

    def test_fixture_rejects_changed_profile(self):
        """A user change must prevent mutation even if the profile remains otherwise valid."""
        profile = json.loads(Path(__file__).with_name('profile.json').read_text())
        profile['foreign'] = True
        with self.assertRaisesRegex(RuntimeError, 'empty deny'):
            acceptance.validate_fixture(profile)

    def test_partial_binding_failure_cleans_owned_list(self):
        """A failed binding after successful creation must delete its own unchanged list."""
        self.check_partial_failure(RuntimeError('binding failed'))

    def test_interruption_cleans_owned_list(self):
        """A polite interruption inside binding must unwind the same owned-list cleanup."""
        self.check_partial_failure(KeyboardInterrupt())

    def check_partial_failure(self, failure):
        """Simulate real mutable API state and assert finally performs the CAS deletion."""
        state = {'lists': [], 'groups': []}
        deleted = []

        def request(path, method='GET', body=None):
            """Apply creates/deletes to fixture state and fail only the binding request."""
            if method == 'POST':
                saved = dict(body, id='owned-id', enabled=False)
                state['lists'].append(saved)
                return 201, saved
            if method == 'PUT':
                raise failure
            if method == 'DELETE':
                self.assertEqual(body, state['lists'][0])
                deleted.append(body['id'])
                state['lists'].clear()
                return 204, None
            if path == '/api/groups-and-rules':
                return 200, json.loads(json.dumps(state))
            return 200, {}

        with patch.object(acceptance, 'guard', return_value={}), patch.object(acceptance, 'request', side_effect=request):
            with self.assertRaises(type(failure)):
                acceptance.api_acceptance()
        self.assertEqual(deleted, ['owned-id'])
        self.assertEqual(state['lists'], [])

    def test_concurrent_list_edit_is_preserved(self):
        """Cleanup refuses a matching unique name whose contents were changed by someone else."""
        item = {'id': 'owned-id', 'name': 'run', 'group': '', 'enabled': False, 'masks': ['foreign.invalid']}
        with patch.object(acceptance, 'snapshot', return_value={'lists': [item]}), patch.object(acceptance, 'request') as request:
            with self.assertRaisesRegex(RuntimeError, 'concurrently'):
                acceptance.cleanup_list('run', False)
            request.assert_not_called()

    def test_preexisting_dns_is_untouched(self):
        """Existing DNS config must be refused before any systemctl or write operation."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'dns.json'
            path.write_bytes(b'foreign config')
            with patch.object(acceptance, 'guard'), patch.object(acceptance, 'DNS_CONFIG', path), patch.object(acceptance.subprocess, 'check_output') as command:
                with self.assertRaisesRegex(RuntimeError, 'preexisting'):
                    acceptance.dns_smoke()
                command.assert_not_called()
            self.assertEqual(path.read_bytes(), b'foreign config')

    def test_dns_changed_during_stop_is_preserved(self):
        """A concurrent replacement during systemd stop cannot be deleted by cleanup."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'dns.json'

            def command(argv, **kwargs):
                """Fail startup and introduce an unrelated config while stopping the unit."""
                if argv[1] == 'start':
                    raise RuntimeError('startup failed')
                if argv[1] == 'stop':
                    path.write_bytes(b'foreign replacement')

            with patch.object(acceptance, 'guard'), patch.object(acceptance, 'DNS_CONFIG', path), patch.object(acceptance.subprocess, 'check_output', return_value='inactive'), patch.object(acceptance.subprocess, 'run', side_effect=command), patch.object(acceptance.os, 'fchown'), patch.object(acceptance.grp, 'getgrnam'):
                with self.assertRaisesRegex(RuntimeError, 'during stop'):
                    acceptance.dns_smoke()
            self.assertEqual(path.read_bytes(), b'foreign replacement')


if __name__ == '__main__':
    unittest.main()
