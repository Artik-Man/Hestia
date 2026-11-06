"""Build distinct Linux and experimental Keenetic application artifacts without accessing a stand."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
from common import ROOT, file_hash, verify_bundle


def compile_go(destination):
    """Compile the three ARM64 Linux commands without frontend, runtime inputs or stand access."""
    env = dict(os.environ, GOOS='linux', GOARCH='arm64', CGO_ENABLED='0')
    subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-o', str(destination) + '/', './cmd/hestia', './cmd/hestia-panel', './cmd/hestia-observe'], cwd=ROOT / 'backend', env=env, check=True)


def copy_frontend(source, destination):
    """Package browser assets together with Angular's generated third-party license notices."""
    shutil.copytree(source / 'browser', destination)
    shutil.copyfile(source / '3rdpartylicenses.txt', destination / '3rdpartylicenses.txt')


def verify_packaged_inputs(bundle, locks, inputs):
    """Reject changed runtime copies or source bytes before recording a publishable manifest."""
    for name, expected in locks.items():
        target = bundle / name if name == 'sing.tgz' else bundle / 'bin' / name
        if file_hash(target) != expected:
            raise RuntimeError('Packaged runtime differs from pinned input: ' + name)
    if any(not (ROOT / name).is_file() or file_hash(ROOT / name) != digest for name, digest in inputs.items()):
        raise RuntimeError('Build inputs changed during packaging; refusing misleading artifact provenance')


def build(output, runtime):
    """Compile application and panel once, then publish two immutable manifests with explicit platform limits."""
    locks = json.loads((ROOT / 'scripts/build/runtime-lock.json').read_text())
    for name, expected in locks.items():
        if not (runtime / name).is_file() or (runtime / name).is_symlink() or file_hash(runtime / name) != expected:
            raise ValueError('Missing or mismatched pinned ARM64 runtime input: ' + str(runtime / name))
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    tracked = subprocess.check_output(['git', 'ls-files', 'backend', 'frontend', 'deploy', 'scripts'], cwd=ROOT, text=True).splitlines()
    tracked += ['scripts/build/run.py', 'scripts/deploy/apply.sh', 'scripts/shared/common.py', 'scripts/shared/paths.sh', 'scripts/deploy/fresh.sh', 'scripts/deploy/default-profile.json', 'scripts/build/runtime-lock.json']
    inputs = {name: file_hash(ROOT / name) for name in sorted(set(tracked)) if (ROOT / name).is_file()}
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True))
    version = time.strftime('%Y%m%d-%H%M%S') + '-' + revision[:12]
    target = output.resolve() / version
    if target.exists():
        raise ValueError('Version output already exists')
    with tempfile.TemporaryDirectory(prefix='hestia-build-') as directory:
        work = Path(directory)
        compile_go(work / 'bin')
        subprocess.run(['npm', 'run', 'build', '--', '--output-path', str(work / 'frontend')], cwd=ROOT / 'frontend', check=True)
        if any(not (ROOT / name).is_file() or file_hash(ROOT / name) != digest for name, digest in inputs.items()):
            raise RuntimeError('Build inputs changed during compilation; refusing misleading artifact provenance')
        target.mkdir(parents=True)
        for platform in ('linux-arm64', 'keenetic-arm64-experimental'):
            bundle = target / platform
            bundle.mkdir()
            shutil.copytree(work / 'bin', bundle / 'bin')
            for name in ('amneziawg-go', 'awg'):
                shutil.copyfile(runtime / name, bundle / 'bin' / name)
                (bundle / 'bin' / name).chmod(0o755)
            shutil.copyfile(runtime / 'sing.tgz', bundle / 'sing.tgz')
            copy_frontend(work / 'frontend', bundle / 'browser')
            (bundle / 'helpers').mkdir()
            for name in ('profile.py', 'smoke.py', 'awg-upgrade.sh'):
                shutil.copyfile(ROOT / 'deploy' / name, bundle / 'helpers' / name)
            (bundle / 'scripts').mkdir()
            for name in ('apply.sh', 'fresh.sh', 'default-profile.json'):
                shutil.copyfile(ROOT / 'scripts/deploy' / name, bundle / 'scripts' / name)
            for name in subprocess.check_output(['git', 'ls-files', 'deploy'], cwd=ROOT, text=True).splitlines():
                source = ROOT / name
                if source.is_file() and not source.is_symlink():
                    target_file = bundle / 'repo' / name
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target_file)
            countries = bundle / 'repo/backend/internal/geoip/countries.txt'
            countries.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / 'backend/internal/geoip/countries.txt', countries)
            shutil.copyfile(ROOT / 'scripts/shared/common.py', bundle / 'scripts/common.py')
            shutil.copyfile(ROOT / 'scripts/shared/paths.sh', bundle / 'scripts/paths.sh')
            verify_packaged_inputs(bundle, locks, inputs)
            manifest = {'schema': 1, 'version': version, 'revision': revision,
                        'platform': platform, 'architecture': 'aarch64', 'dirty': dirty, 'source_inputs': inputs,
                        'experimental': platform.startswith('keenetic'),
                        'runtime_prerequisites': {'sing-box': '1.14.4', 'amneziawg-go': '3.1.20260828', 'awg-tools': '3.1.20260812'},
                        'runtime_inputs': locks, 'deployment': 'initial-or-managed-update',
                        'limitations': ['Linux ARM64 systemd and Debian-compatible runtime required'] if platform == 'linux-arm64' else ['Generic ARM64 binaries only', 'Keenetic adapters and ipk packaging are not implemented', 'Deployment is refused'],
                        'files': {str(p.relative_to(bundle)): file_hash(p) for p in sorted(bundle.rglob('*')) if p.is_file()}}
            (bundle / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            verify_bundle(bundle)
            print(bundle, flush=True)
    return target


def main():
    """Build both platforms into a new versioned directory; never overwrite an earlier artifact."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/artifacts')
    parser.add_argument('--runtime-dir', type=Path, default=ROOT / 'dist/runtime')
    parser.add_argument('--check-go', action='store_true', help='Compile Go commands only; no distribution artifact or frontend')
    args = parser.parse_args()
    if args.check_go:
        compile_go(args.output.resolve())
    else:
        build(args.output, args.runtime_dir)


if __name__ == '__main__':
    main()
