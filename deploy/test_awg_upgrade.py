"""Exercise migration sequencing without starting services or touching kernel policy."""

from pathlib import Path
import subprocess
import unittest


class AWGUpgradeTests(unittest.TestCase):
    """Check the installer's transport proofs across its backend activation boundary."""

    def test_manual_runtime_starts_before_guards_and_confirms_after_backend(self):
        """Record fake service calls and require the exact pre- and post-backend proofs."""
        script = r'''
source "$1"
python3() { echo "iptest-parent 0 auto"; echo "iptest-child 1 manual 3"; }
systemctl() { echo "$*"; }
wait_awg_proof() { echo "proof $2 $3 $4 ${5:-30}"; }
restart_ready_awg compiler
echo backend
confirm_manual_awg compiler
'''
        result = subprocess.run(
            ["bash", "-eu", "-c", script, "test", str(Path(__file__).with_name("awg-upgrade.sh"))],
            check=True, text=True, capture_output=True,
        )
        self.assertEqual(result.stdout.splitlines(), [
            "stop hestia-awg@iptest-parent.service", "start hestia-awg@iptest-parent.service",
            "stop hestia-awg@iptest-child.service", "start hestia-awg@iptest-child.service",
            "proof iptest-parent 0 ready 30", "proof iptest-child 1 guards 30", "backend",
            "proof iptest-child 1 ready 66",
        ])
