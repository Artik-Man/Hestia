"""Verify installer/systemd locking with real flock and isolated fake services."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("flock") and shutil.which("sha256sum"), "requires Linux flock and sha256sum")
class InstallLifecycleTests(unittest.TestCase):
    """Exercise actual installer lifecycle functions without root or system services."""

    def run_lifecycle(self, body, startup=False):
        """Run installer functions against private files and return the observed process result."""
        source = Path(__file__).with_name("install.sh").read_text()
        functions = source.split("# generation_fingerprint records", 1)[1].split("trap cleanup EXIT", 1)[0]
        functions = "# generation_fingerprint records" + functions
        activation = source.split('replace "$work/marker" "$marker" 0600\n', 1)[1].split("start=$SECONDS", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            setup = r'''
set -u
work=$1
config=$work/etc
mkdir "$config"
lock=$work/lock
exec 9>"$lock"
flock -n 9
managed=("$work/config")
printf old >"$work/backup-0"
printf published >"$work/config"
printf profile >"$config/profile.json"
transaction=1
released=0
had_group=1
services=(hestia.service hestia-sing-box.service)
managed_units=(hestia-binding-recovery.service hestia-binding-watch.path)
declare -A active enabled
for unit in "${managed_units[@]}"; do active[$unit]=active; enabled[$unit]=enabled; done
# systemctl models recovery taking a separately opened instance of the same configuration lock.
systemctl() {
    case "$1:${2:-}" in
        restart:hestia-binding-watch.path|start:hestia-binding-recovery.service|start:hestia-binding-watch.path)
            flock -n "$lock" true || { echo recovery-lock-conflict >&2; return 49; } ;;
    esac
}
# cp asserts rollback owns the lock while it replaces the managed file.
cp() {
    if flock -n "$lock" true; then echo unlocked-restore >&2; return 99; fi
    command cp "$@"
}
# rm leaves evidence intact for assertions after cleanup exits its shell.
rm() { :; }
'''
            script = setup + functions + ("set -e\n" + activation if startup else "") + body
            result = subprocess.run(["bash", "-c", script, "test", directory], text=True, capture_output=True)
            current = (Path(directory) / "config").read_text()
            return result, current

    def test_recovery_starts_outside_publication_lock(self):
        """The actual activation sequence lets the required recovery process acquire its lock."""
        result, _ = self.run_lifecycle('exit 0\n', startup=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rollback_locks_files_and_unlocks_service_restart(self):
        """Failure restoration owns the lock, then allows restored recovery to reacquire it."""
        result, current = self.run_lifecycle('release_install_lock\nfalse\ncleanup\n')
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("unlocked-restore", result.stderr)
        self.assertNotIn("recovery-lock-conflict", result.stderr)
        self.assertEqual(current, "old")

    def test_rollback_preserves_intervening_commit(self):
        """A completed newer generation without a pending marker is never overwritten."""
        result, current = self.run_lifecycle('release_install_lock\nprintf newer >"$work/config"\nfalse\ncleanup\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Rollback refused", result.stderr)
        self.assertEqual(current, "newer")

    def test_rollback_preserves_pending_transaction(self):
        """A new transaction marker prevents destructive rollback even before file changes."""
        result, current = self.run_lifecycle('release_install_lock\ntouch "$config/.binding-pending"\nfalse\ncleanup\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Rollback refused", result.stderr)
        self.assertEqual(current, "published")

    def test_rollback_preserves_config_not_replaced_by_installer(self):
        """A config-preserving update must detect a later profile change outside managed files."""
        result, current = self.run_lifecycle('release_install_lock\nprintf newer >"$config/profile.json"\nfalse\ncleanup\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Rollback refused", result.stderr)
        self.assertEqual(current, "published")

    def test_rollback_preserves_new_generation_file(self):
        """A generation file absent at publication cannot silently appear before rollback."""
        result, current = self.run_lifecycle('release_install_lock\nprintf newer >"$config/sing-box.json"\nfalse\ncleanup\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Rollback refused", result.stderr)
        self.assertEqual(current, "published")

    def test_rollback_preserves_new_awg_metadata(self):
        """An AWG entry added outside the installer replacement set prevents rollback."""
        result, current = self.run_lifecycle('release_install_lock\nmkdir -p "$config/awg/new"\nprintf newer >"$config/awg/new/metadata.json"\nfalse\ncleanup\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Rollback refused", result.stderr)
        self.assertEqual(current, "published")
