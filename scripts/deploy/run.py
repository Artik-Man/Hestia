"""Deploy a previously built Linux application artifact to one explicit existing stand."""
import argparse
from pathlib import Path
import subprocess
import shutil
import sys
import tarfile
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
from common import ROOT, Run, Stand, file_hash, verify_bundle


def deploy(bundle, stand, report):
    """Verify artifact and stand before delivery, then run the rollback-capable updater under systemd."""
    manifest = verify_bundle(bundle)
    if manifest['platform'] != 'linux-arm64' or manifest.get('experimental'):
        raise ValueError('Experimental Keenetic artifacts cannot be deployed: adapter/ipk work is pending')
    if manifest['platform'] != stand.platform:
        raise ValueError('Artifact and stand platforms differ')
    stand.preflight()
    token = time.strftime('%Y%m%d-%H%M%S') + '-' + str(__import__('os').getpid())
    remote = '/var/tmp/hestia-deploy-' + token
    incoming = '/tmp/hestia-deploy-' + token + '.tar'
    unit = 'hestia-deploy-' + token
    with tempfile.TemporaryDirectory(prefix='hestia-delivery-') as directory:
        snapshot = Path(directory) / 'snapshot'
        shutil.copytree(bundle, snapshot, symlinks=True)
        snapshot.chmod(0o700)
        verify_bundle(snapshot)
        archive = Path(directory) / 'artifact.tar'
        with tarfile.open(archive, 'w') as tar:
            tar.add(snapshot, arcname='.')
        stand.copy(archive, incoming)
        setup = ['bash', '-ec', 'test "$(hostname -s)" = "$3"; umask 077; mkdir "$1"; cp "$2" "$1/payload.tar"; test "$(sha256sum "$1/payload.tar" | cut -d " " -f1)" = "$4"; tar --no-same-owner -xf "$1/payload.tar" -C "$1"; chmod 0700 "$1"; rm "$2" "$1/payload.tar"', '_', remote, incoming, stand.data['expected_hostname'], file_hash(archive)]
        stand.run(setup, sudo=True, check=True, timeout=60)
        command = stand.command(['systemd-run', '--unit=' + unit, '--collect', '--wait', '--pipe', '--property=RuntimeMaxSec=1800', '--property=TimeoutStopSec=480', '--property=KillMode=control-group', 'bash', remote + '/scripts/apply.sh', remote, stand.data['expected_hostname']], sudo=True)
        try:
            return report.phase('deploy-existing', command, env=stand.env)
        finally:
            stopped = stand.run(['systemctl', 'stop', unit], sudo=True, timeout=500, capture_output=True)
            if stopped.returncode and stand.run(['systemctl', 'is-active', '--quiet', unit], sudo=True, timeout=20).returncode == 0:
                raise RuntimeError('Deployment unit is still active; preserve staging and inspect its journal')


def main():
    """Require both explicit stand descriptor and immutable artifact; never build during deployment."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stand', type=Path, required=True)
    parser.add_argument('--bundle', '--artifact', dest='bundle', type=Path, required=True)
    parser.add_argument('--type', choices=('linux', 'keenetic'), required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.type == 'keenetic':
        parser.error('Keenetic bundle is experimental; deployment adapter/ipk is not implemented')
    report = Run(args.output or ROOT / 'experiments/dev-validation/evidence' / ('deploy-' + time.strftime('%Y%m%d-%H%M%S')))
    try:
        return 0 if deploy(args.bundle.resolve(), Stand.load(args.stand), report) else 1
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        report.fail('deploy', error)
        return 1


if __name__ == '__main__':
    sys.exit(main())
