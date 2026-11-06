"""Exercise legacy observer paths and route snapshots without a live gateway."""
from pathlib import Path
import subprocess
import tempfile
import unittest

APPLY = Path(__file__).with_name('apply.sh')
HELPERS = Path(__file__).parents[1] / 'shared/paths.sh'


class UpdateCompatibilityTests(unittest.TestCase):
    """Check preservation and failure contracts using real shell fragments."""

    def test_missing_observer_preflight(self):
        """Only the observer may be absent; unsafe observer targets still fail."""
        source = APPLY.read_text()
        fragment = source[source.index('for file in /usr/local/bin/hestia '):source.index('[[ -d /usr/local/share/hestia-panel/current ]]')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('hestia', 'hestia-panel', 'profile.py', 'smoke.py'):
                (root / name).touch()
            fragment = fragment.replace('/usr/local/bin/', directory + '/').replace('/usr/local/lib/hestia/', directory + '/')
            setup = '''set -euo pipefail
# die_if_untrusted_file models type/permission guards independent of host UID.
die_if_untrusted_file() { [[ ! -L $1 && (! -e $1 || -f $1) ]]; }
'''
            result = subprocess.run(['bash', '-c', setup + fragment], capture_output=True)
            self.assertEqual(result.returncode, 0)
            observer = root / 'hestia-observe'
            observer.symlink_to(root / 'missing')
            self.assertNotEqual(subprocess.run(['bash', '-c', setup + fragment], capture_output=True).returncode, 0)
            observer.unlink()
            observer.mkdir()
            self.assertNotEqual(subprocess.run(['bash', '-c', setup + fragment], capture_output=True).returncode, 0)
            observer.rmdir()
            (root / 'hestia').unlink()
            self.assertNotEqual(subprocess.run(['bash', '-c', setup + fragment], capture_output=True).returncode, 0)

    def test_observer_backup_and_rollback(self):
        """Real backup and rollback restore either the previous observer or absence."""
        source = APPLY.read_text()
        backup_code = source[source.index('for path in "${paths[@]}"; do'):source.index('route_snapshot 4 "$backup/routes4"')]
        rollback = '# rollback restores' + source.split('# rollback restores', 1)[1].split('trap rollback EXIT', 1)[0]
        for existed in (False, True):
            with self.subTest(existed=existed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                directory = str(root)
                (root / 'required').touch()
                observer = root / 'observer'
                if existed:
                    observer.write_text('old')
                (root / 'config.sha256').write_text('config\n')
                (root / 'published.sha256').write_text('published\n')
                # Redirect only filesystem roots; use actual tar and rm for restoration.
                backup_fragment = backup_code.replace('usr/local/bin/hestia-observe', str(observer).lstrip('/'))
                setup = r'''set -euo pipefail
backup=$1
paths=("${2#/}" "${1#/}/required")
existing_paths=()
absent_paths=()
ready=1
published=1
released=1
units=(example.service)
awg_units=(example-awg.service)
# flock models an available deployment lock.
flock() { :; }
# config_digest models unchanged configuration.
config_digest() { echo config; }
# application_digest models this updater publication.
application_digest() { echo published; }
# stop_existing_units models successful quiescence.
stop_existing_units() { :; }
# resume records successful service restoration.
resume() { echo resumed; }
'''
                rollback_fragment = rollback.replace('/usr/local/share/hestia-panel/current', str(root / 'unused-panel'))
                command = setup + backup_fragment + '\nprintf new > "$2"\n' + rollback_fragment + '\ntrap rollback EXIT\nfalse\n'
                result = subprocess.run(['bash', '-c', command, '_', directory, str(observer)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('prior application restored', result.stderr)
                self.assertEqual(observer.exists(), existed)
                if existed:
                    self.assertEqual(observer.read_text(), 'old')
                else:
                    self.assertEqual((root / 'absent.txt').read_text(), str(observer) + '\n')

    def snapshot(self, content: str, failure: bool = False) -> tuple[int, str, str]:
        """Capture real normalization output with a controlled ip command."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'input').write_text(content)
            command = '''set -euo pipefail
source "$1"
# ip supplies deterministic route output and an optional capture failure.
ip() { cat "$2_input"; return "$3_status"; }
route_snapshot 6 "$2/raw"
'''.replace('$2_input', str(root / 'input')).replace('$3_status', '1' if failure else '0')
            result = subprocess.run(['bash', '-c', command, '_', str(HELPERS), directory], capture_output=True)
            canonical = root / 'raw.canonical'
            raw = root / 'raw'
            return result.returncode, canonical.read_text() if canonical.exists() else '', raw.read_text() if raw.exists() else ''

    def test_route_permutation_and_raw_evidence(self):
        """Independent IPv4/IPv6 rows normalize equally while raw order survives."""
        rows = ['10.0.0.0/24 dev eth0 metric 10\n', 'fe80::/64 dev awg0 metric 256\n', 'fe80::/64 dev awg1 metric 256\n']
        first = self.snapshot(''.join(rows))
        second = self.snapshot(''.join(reversed(rows)))
        self.assertEqual(first[0], 0)
        self.assertEqual(second[0], 0)
        self.assertEqual(first[1], second[1])
        self.assertNotEqual(first[2], second[2])

    def test_route_changes_and_capture_failure(self):
        """Attribute changes, duplicate loss and capture failures cannot pass."""
        row = 'default via 192.0.2.1 dev eth0 metric 100\n'
        first = self.snapshot(row)
        self.assertEqual(first[0], 0)
        self.assertNotEqual(first[1], self.snapshot(row.replace('100', '200'))[1])
        self.assertNotEqual(first[1], self.snapshot(row + row)[1])
        self.assertNotEqual(self.snapshot(row, True)[0], 0)
        self.assertNotEqual(self.snapshot('not-a-route\n')[0], 0)
        self.assertNotEqual(self.snapshot('fe80::/64 metric 256\n')[0], 0)

    def test_nexthop_and_equal_destination_order(self):
        """Nexthop order and equal-destination route ordering remain significant."""
        first = 'default nexthop via 192.0.2.1 dev eth0 weight 1 nexthop via 192.0.2.2 dev eth1 weight 1\n'
        second = 'default nexthop via 192.0.2.2 dev eth1 weight 1 nexthop via 192.0.2.1 dev eth0 weight 1\n'
        self.assertEqual(self.snapshot(first)[0], 0)
        self.assertNotEqual(self.snapshot(first)[1], self.snapshot(second)[1])
        rows = ['default via 192.0.2.1 dev eth0 metric 100\n', 'default via 192.0.2.2 dev eth1 metric 100\n']
        self.assertNotEqual(self.snapshot(''.join(rows))[1], self.snapshot(''.join(reversed(rows)))[1])


if __name__ == '__main__':
    unittest.main()
