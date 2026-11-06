"""Test an explicitly selected installed Linux stand without deployment or live configuration edits."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/shared'))
from common import Run, Stand

LABS = ('awg-multi', 'wg-underlay', 'hysteria2', 'controller-routing',
        'group-quality', 'physical-connections', 'partial-loss',
        'connection-quality', 'dns-panel')
FIXTURE_DEPENDENCIES = (
    'deploy/scheme3/guest-profile.json',
    'tests/lab/failover/config.json',
    'tests/lab/failover/fixture.sh',
    'tests/lab/failover/probes.py',
    'tests/lab/fakeip/traffic.py',
    'tests/lab/scoped/config.json',
    'tests/lab/scoped/probes.py',
    'tests/lab/observer/fixture.py',
    'tests/lab/steer-deny/check.py',
)


def prepare(destination: Path) -> None:
    """Copy public test fixtures and build only the measurement helper, never application binaries."""
    tracked = subprocess.check_output(['git', 'ls-files', '-z', 'tests/lab', 'experiments'], cwd=ROOT).decode().split('\0')
    selected = {'scripts/test/' + name for name in ('guest.sh', 'network.sh', 'read_only.py')}
    selected.update(('backend/go.mod', 'backend/go.sum'))
    selected.update(FIXTURE_DEPENDENCIES)
    for name in tracked:
        if name.startswith('experiments/'):
            name = 'tests/lab/' + name.removeprefix('experiments/')
        if any(name.startswith('tests/lab/' + lab + '/') for lab in LABS) and Path(name).suffix in ('.py', '.sh', '.json', '.go') and (ROOT / name).is_file():
            selected.add(name)
    for name in sorted(selected):
        path = ROOT / name
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != ROOT and parent.is_relative_to(ROOT)):
            raise RuntimeError('Symlink in test fixture source')
        target = destination / 'repo' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH='arm64')
    subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-o', str(destination / 'quality-test-service'), '../tests/lab/connection-quality/service/main.go'], cwd=destination / 'repo/backend', env=env, check=True)
    (destination / 'fixture-source.json').write_text(json.dumps({
        'role': 'test fixtures only; application binaries copied on stand',
        'files': {name: hashlib.sha256((destination / 'repo' / name).read_bytes()).hexdigest() for name in sorted(selected)},
    }, indent=2))


def run_guest(report: Run, stand: Stand, guest: str, run_id: str) -> bool:
    """Bound guest work to an owned transient unit and always check final preservation invariants."""
    unit = 'hestia-validation-' + run_id
    script = guest + '/repo/scripts/test/guest.sh'
    expected = stand.data['expected_hostname']
    panel = stand.data.get('panel_url', 'http://127.0.0.1:8080')
    prepared = False
    success = False

    def remote(name: str, phase: str) -> bool:
        """Run one isolated stage on the verified stand using its immutable expected identity."""
        return report.phase(name, stand.command([
            'systemd-run', '--unit=' + unit, '--collect', '--wait', '--pipe',
            '--property=RuntimeMaxSec=1800', '--property=TimeoutStopSec=30',
            '--property=KillMode=control-group', 'bash', script, guest, phase, expected, panel], sudo=True), env=stand.env)

    try:
        prepared = remote('installed-snapshot', 'prepare')
        if prepared:
            acceptance = remote('installed-read-only-and-isolated-acceptance', 'acceptance')
            network = remote('installed-isolated-network', 'network')
            success = acceptance and network
        else:
            report.skip('installed-runtime-tests', 'snapshot or dependency preflight failed')
    except KeyboardInterrupt:
        report.fail('interrupted', 'Stopping owned validation unit; installed configuration is never restored blindly')
    finally:
        try:
            stopped = stand.run(['systemctl', 'stop', unit], sudo=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
            if stopped.returncode:
                active = stand.run(['systemctl', 'is-active', '--quiet', unit], sudo=True, timeout=20)
                if active.returncode == 0:
                    raise RuntimeError('Validation transient unit remains active')
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            report.fail('guest-stop', str(error))
            success = False
        if prepared:
            preserved = report.phase('installed-final-invariants', stand.command(['bash', script, guest, 'final', expected, panel], sudo=True), env=stand.env)
            success = success and preserved
        logs = report.phase('guest-logs', stand.command(['bash', '-ec', 'for f in "$1"/*.log; do test ! -f "$f" || { printf "LOG %s\\n" "${f##*/}"; cat "$f"; }; done', '_', guest], sudo=True), env=stand.env)
        success = success and logs
    return success


def extraction_command(guest: str, incoming: str, expected: str, digest: str) -> list[str]:
    """Verify a private archive copy and enforce root directory privacy after tar restores metadata."""
    return ['bash', '-ec', 'test "$(hostname -s)" = "$3"; umask 077; mkdir "$1"; cp "$2" "$1/fixtures.tar"; test "$(sha256sum "$1/fixtures.tar" | cut -d " " -f1)" = "$4"; tar --no-same-owner -xf "$1/fixtures.tar" -C "$1"; chmod 0700 "$1"; rm "$2" "$1/fixtures.tar"', '_', guest, incoming, expected, digest]


def main() -> int:
    """Require an explicit descriptor, stage fixtures and test only its already installed runtime."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stand', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    run_id = time.strftime('%Y%m%d-%H%M%S') + '-' + str(os.getpid())
    report = Run(args.output or ROOT / 'experiments/dev-validation/evidence' / ('installed-' + run_id))
    try:
        stand = Stand.load(args.stand)
        stand.preflight()
        (report.output / 'scope.json').write_text(json.dumps({'stand': stand.name, 'hostname': stand.data['expected_hostname'], 'platform': stand.platform, 'scope': 'installed read-only + copied-runtime private fixtures', 'historical': ['partial-loss prototype'], 'source_helper': 'quality measurement fixture'}, indent=2))
        guest = '/var/tmp/hestia-validation-' + run_id
        incoming = '/tmp/hestia-validation-' + run_id + '.tar'
        with tempfile.TemporaryDirectory(prefix='hestia-installed-test-') as temporary:
            stage = Path(temporary) / 'stage'
            stage.mkdir(mode=0o700)
            prepare(stage)
            shutil.copyfile(stage / 'fixture-source.json', report.output / 'fixture-source.json')
            archive = Path(temporary) / 'fixtures.tar'
            with tarfile.open(archive, 'w') as tar:
                tar.add(stage, arcname='.')
            stand.copy(archive, incoming)
            setup = extraction_command(guest, incoming, stand.data['expected_hostname'], hashlib.sha256(archive.read_bytes()).hexdigest())
            stand.run(setup, sudo=True, check=True, timeout=120)
        return 0 if run_guest(report, stand, guest, run_id) else 1
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.fail('preflight-or-transport', str(error))
        return 2


if __name__ == '__main__':
    sys.exit(main())
