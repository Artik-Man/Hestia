"""Build distinct Linux and experimental Keenetic application artifacts without accessing a stand."""
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
from common import ROOT, file_hash, verify_bundle
from ipk import create_ipk

KEENETIC_AWG_UAPI_DIRECTORY = '/opt/tmp/hestia-awg-uapi-26b84f/runtime/amneziawg'
KEENETIC_GEOIP_SHA256 = 'e5c8459d638a272ece7f4d7cfa49dce18d91b4f403f6940ba9249bf0db3781fd'


def compile_go(destination):
    """Compile distinct Linux and Keenetic ARM64 commands without runtime inputs or stand access."""
    env = dict(os.environ, GOOS='linux', GOARCH='arm64', CGO_ENABLED='0')
    for platform, tags in (('linux-arm64', None), ('keenetic-arm64-experimental', 'keenetic')):
        output = destination / platform / 'bin'
        output.mkdir(parents=True, exist_ok=True)
        command = ['go', 'build', '-trimpath', '-buildvcs=false']
        if tags:
            command.extend(['-tags', tags])
        commands = ['./cmd/hestia', './cmd/hestia-panel', './cmd/hestia-observe', './cmd/hestia-cli']
        if tags == 'keenetic':
            commands.append('./cmd/keenetic-preflight')
        command.extend(['-o', str(output) + '/', *commands])
        subprocess.run(command, cwd=ROOT / 'backend', env=env, check=True)
        research_output = destination / platform / 'research'
        research_output.mkdir(parents=True, exist_ok=True)
        research_command = ['go', 'build', '-trimpath', '-buildvcs=false']
        if tags:
            research_command.extend(['-tags', tags])
        research_command.extend([
            '-o', str(research_output) + '/',
            './cmd/keenetic-rci-ethernet',
            './cmd/keenetic-rci-interface-schema',
            './cmd/keenetic-rci-survey-schema',
            './cmd/keenetic-rci-wisp-status',
        ])
        if tags == 'keenetic':
            research_command.append('./cmd/keenetic-route-preflight')
        subprocess.run(research_command, cwd=ROOT / 'backend', env=env, check=True)


def copy_frontend(source, destination):
    """Package browser assets together with Angular's generated third-party license notices."""
    shutil.copytree(source / 'browser', destination)
    shutil.copyfile(source / '3rdpartylicenses.txt', destination / '3rdpartylicenses.txt')


def stage_keenetic_rootfs(bundle, runtime):
    """Stage the Entware filesystem layout and pinned runtime candidates under /opt."""
    opt_bin = bundle / 'opt/bin'
    opt_bin.mkdir(parents=True, exist_ok=True)
    for name in ('hestia', 'hestia-panel', 'hestia-observe'):
        shutil.copyfile(bundle / 'bin' / name, opt_bin / name)
        (opt_bin / name).chmod(0o755)
    for name, source_name in (('amneziawg-go', 'amneziawg-go-keenetic'),
                              ('awg', 'awg-keenetic-static')):
        shutil.copyfile(runtime / source_name, opt_bin / name)
        (opt_bin / name).chmod(0o755)
    library = bundle / 'opt/lib/hestia'
    library.mkdir(parents=True, exist_ok=True)
    prefix = 'sing-box-1.14.4-linux-arm64/'
    for name in ('sing-box', 'libcronet.so', 'LICENSE'):
        member_name = prefix + name
        with tarfile.open(runtime / 'sing.tgz', 'r:gz') as archive:
            try:
                member = archive.getmember(member_name)
            except KeyError as error:
                raise RuntimeError('Pinned sing-box archive is missing ' + name) from error
            if not member.isfile():
                raise RuntimeError('Pinned sing-box archive contains a non-regular ' + name)
            stream = archive.extractfile(member)
            if stream is None:
                raise RuntimeError('Pinned sing-box archive member cannot be read: ' + name)
            with stream, (library / name).open('wb') as output:
                shutil.copyfileobj(stream, output)
        (library / name).chmod(0o755 if name == 'sing-box' else 0o644)
    shutil.copyfile(ROOT / 'deploy/profile.py', library / 'profile.py')
    (library / 'profile.py').chmod(0o644)
    stage_keenetic_geoip(bundle)
    stage_keenetic_hooks(bundle)
    assets = bundle / 'opt/share/hestia-panel/current'
    shutil.copytree(bundle / 'browser', assets)
    stage_keenetic_install_lock(bundle)


def stage_keenetic_hooks(bundle):
    """Install the bounded NDM mangle hook that requests synchronous route reconciliation."""
    source = ROOT / 'deploy/keenetic/netfilter.d/090-hestia-ingress.sh'
    target = bundle / 'opt/etc/ndm/netfilter.d/090-hestia-ingress.sh'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755)


def stage_keenetic_install_lock(bundle):
    """Create owner-only install and ingress flock files required by runtime readers and writers."""
    lock = bundle / 'opt/var/lock/hestia-install.lock'
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_bytes(b'')
    lock.chmod(0o600)
    ingress_lock = bundle / 'opt/var/lock/hestia-ingress.lock'
    ingress_lock.write_bytes(b'')
    ingress_lock.chmod(0o600)


def prepare_keenetic_config(bundle, work):
    """Compile and stage a managed deny-by-default profile for first install and opkg conffile preservation."""
    config = bundle / 'opt/etc/hestia'
    config.mkdir(parents=True, mode=0o700)
    config.chmod(0o700)
    profile = ROOT / 'scripts/deploy/default-profile-keenetic.json'
    shutil.copyfile(profile, config / 'profile.json')
    stage = work / 'keenetic-default-profile'
    stage.mkdir(mode=0o700)
    subprocess.run([sys.executable, '-I', str(ROOT / 'deploy/profile.py'), str(profile), str(stage)], check=True)
    for name in ('snapshot.json', 'sing-box.json'):
        shutil.copyfile(stage / name, config / name)
    for name, source in (('profile-source.sha256', config / 'profile.json'),
                         ('profile-backend.sha256', config / 'sing-box.json')):
        (config / name).write_text(file_hash(source) + '\n')
    (config / '.installer-managed').write_text('1\n')
    for path in config.iterdir():
        path.chmod(0o600)


def verify_packaged_inputs(bundle, locks, inputs):
    """Reject changed runtime copies or source bytes before recording a publishable manifest."""
    for name, expected in locks.items():
        if name == 'amneziawg-go-keenetic':
            if not bundle.name.startswith('keenetic-'):
                continue
            target = bundle / 'opt/bin/amneziawg-go'
        elif name == 'awg-keenetic-static':
            if not bundle.name.startswith('keenetic-'):
                continue
            for target in (bundle / 'bin/awg', bundle / 'opt/bin/awg'):
                if file_hash(target) != expected:
                    raise RuntimeError('Packaged runtime differs from pinned input: ' + name)
            verify_keenetic_awg_uapi(bundle)
            continue
        elif name == 'awg':
            if bundle.name.startswith('keenetic-'):
                continue
            target = bundle / 'bin/awg'
        else:
            target = bundle / name if name == 'sing.tgz' else bundle / 'bin' / name
        if file_hash(target) != expected:
            raise RuntimeError('Packaged runtime differs from pinned input: ' + name)
    if any(not (ROOT / name).is_file() or file_hash(ROOT / name) != digest for name, digest in inputs.items()):
        raise RuntimeError('Build inputs changed during packaging; refusing misleading artifact provenance')


def stage_keenetic_geoip(bundle):
    """Build and stage the pinned country database and sing-box rule sets under /opt/share."""
    archive = ROOT / 'deploy/geoip/dbip-country-lite-2026-11.csv.gz'
    if file_hash(archive) != KEENETIC_GEOIP_SHA256:
        raise RuntimeError('Pinned Keenetic GeoIP archive hash does not match')
    target = bundle / 'opt/share/hestia/geoip'
    if target.exists():
        raise RuntimeError('Keenetic GeoIP output already exists')
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='hestia-keenetic-geoip-') as directory:
        generated = Path(directory) / 'geoip'
        subprocess.run(
            [sys.executable, '-I', str(ROOT / 'deploy/import_geoip.py'), str(archive), str(generated)],
            cwd=ROOT,
            check=True,
        )
        shutil.copytree(generated, target)
    countries = (ROOT / 'backend/internal/geoip/countries.txt').read_text(encoding='ascii').split()
    (target / 'countries.txt').write_text('\n'.join(countries) + '\n', encoding='ascii')
    shutil.copyfile(ROOT / 'deploy/geoip/README.md', target / 'NOTICE')
    source_hashes = '\n'.join((
        file_hash(archive),
        file_hash(ROOT / 'deploy/import_geoip.py'),
        file_hash(ROOT / 'backend/internal/geoip/countries.txt'),
    )).encode()
    (target / 'rule-set-source.sha256').write_text(hashlib.sha256(source_hashes).hexdigest() + '\n')
    verify_keenetic_geoip(target)


def verify_keenetic_geoip(directory):
    """Reject incomplete or malformed GeoIP payloads before publishing the Keenetic package."""
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    countries = manifest.get('countries')
    catalogue = set((ROOT / 'backend/internal/geoip/countries.txt').read_text(encoding='ascii').split())
    if not isinstance(countries, list) or not countries or countries != sorted(set(countries)):
        raise RuntimeError('Keenetic GeoIP manifest is invalid')
    if set(countries) != catalogue or not (directory / 'country.bin').is_file():
        raise RuntimeError('Keenetic GeoIP data is incomplete')
    if (directory / 'country.bin').read_bytes()[:4] != b'HGI1':
        raise RuntimeError('Keenetic GeoIP index header is invalid')
    if not {'countries.txt', 'NOTICE', 'rule-set-source.sha256'}.issubset({path.name for path in directory.iterdir()}):
        raise RuntimeError('Keenetic GeoIP metadata is incomplete')
    countries_file = (directory / 'countries.txt').read_text(encoding='ascii').splitlines()
    if not countries_file or countries_file != sorted(set(countries_file)) or set(countries_file) != catalogue:
        raise RuntimeError('Keenetic GeoIP country catalogue is invalid')
    if any(not (directory / (code + '.json')).is_file() for code in countries):
        raise RuntimeError('Keenetic GeoIP rule sets are incomplete')


def verify_keenetic_awg_uapi(bundle):
    """Require the Keenetic AWG CLI and daemon to use one identical private UAPI socket directory."""
    directory = KEENETIC_AWG_UAPI_DIRECTORY.encode()
    daemon = (bundle / 'opt/bin/amneziawg-go').read_bytes()
    tools = (bundle / 'opt/bin/awg').read_bytes()
    if directory not in daemon or directory + b'/' not in tools:
        raise RuntimeError('Keenetic AWG runtime binaries use different UAPI socket directories')


def build(output, runtime):
    """Compile platform-specific applications and publish immutable manifests with explicit platform limits."""
    locks = json.loads((ROOT / 'scripts/build/runtime-lock.json').read_text())
    for name, expected in locks.items():
        if not (runtime / name).is_file() or (runtime / name).is_symlink() or file_hash(runtime / name) != expected:
            raise ValueError('Missing or mismatched pinned ARM64 runtime input: ' + str(runtime / name))
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    tracked = subprocess.check_output(['git', 'ls-files', 'backend', 'frontend', 'deploy', 'scripts'], cwd=ROOT, text=True).splitlines()
    tracked += ['scripts/build/run.py', 'scripts/deploy/apply.sh', 'scripts/shared/common.py', 'scripts/shared/paths.sh', 'scripts/deploy/fresh.sh', 'scripts/deploy/default-profile.json', 'scripts/deploy/default-profile-keenetic.json', 'scripts/build/runtime-lock.json']
    tracked += [
        'deploy/keenetic/S99hestia',
        'deploy/keenetic/netfilter.d/090-hestia-ingress.sh',
        'deploy/keenetic/ipk/preinst',
        'deploy/keenetic/ipk/postinst',
        'deploy/keenetic/ipk/prerm',
        'deploy/keenetic/ipk/postrm',
        'scripts/build/ipk.py',
        'backend/cmd/keenetic-rci-ethernet/main.go',
        'backend/cmd/keenetic-rci-interface-schema/main.go',
        'backend/cmd/keenetic-preflight/main.go',
        'backend/cmd/keenetic-rci-survey-schema/main.go',
        'backend/cmd/keenetic-rci-wisp-status/main.go',
        'backend/cmd/keenetic-route-preflight/main.go',
        'backend/cmd/hestia-cli/main.go',
        'backend/internal/hestiacli/fileserver.go',
        'backend/internal/binding/command_timeout.go',
        'backend/pkg/keeneticrci/client.go',
        'backend/pkg/keeneticrci/ethernet.go',
        'backend/pkg/keeneticrci/schema.go',
        'backend/pkg/keeneticrci/version.go',
        'backend/pkg/keeneticrci/wireless.go',
        'backend/internal/network/keeneticphysical/carrier.go',
        'backend/internal/network/keeneticroute/exec_linux.go',
        'backend/internal/network/keeneticroute/ingress_codec_test.go',
        'backend/internal/network/keeneticroute/ingress_netlink_codec.go',
        'backend/internal/network/keeneticroute/ingress_netlink_linux.go',
        'backend/internal/network/keeneticroute/ingress_netlink_linux_integration_test.go',
        'backend/internal/network/keeneticroute/ingress_rule_state.go',
        'backend/internal/network/keeneticroute/ingress_rule_state_linux.go',
        'backend/internal/network/keeneticroute/ingress_rule_state_linux_test.go',
        'backend/internal/network/keeneticroute/ingress_rule_state_test.go',
        'backend/internal/network/keeneticroute/ingress_policy.go',
        'backend/internal/network/keeneticroute/ingress_policy_test.go',
        'backend/internal/network/keeneticroute/ingress_reconcile.go',
        'backend/internal/network/keeneticroute/ingress_reconcile_test.go',
        'backend/internal/controller/carrier_default.go',
        'backend/internal/controller/carrier_keenetic.go',
        'backend/internal/storage/installed_default.go',
        'backend/internal/storage/installed_keenetic.go',
        'backend/internal/storage/layout.go',
        'backend/internal/storage/layout_test.go',
        'backend/internal/platform/doc.go',
        'backend/internal/platform/compose_default.go',
        'backend/internal/platform/compose_keenetic.go',
        'backend/internal/platform/opkgtun_keenetic.go',
        'backend/internal/platform/unavailable.go',
        'backend/internal/services/entware/doc.go',
        'backend/internal/services/entware/ipc.go',
        'backend/internal/services/entware/ingress_default.go',
        'backend/internal/services/entware/ingress_keenetic.go',
        'backend/internal/services/entware/ingress_profile.go',
        'backend/internal/services/entware/ingress_profile.go',
        'backend/internal/services/entware/ingress_profile_test.go',
        'backend/internal/services/entware/maintenance_marker.go',
        'backend/internal/services/entware/maintenance_marker_test.go',
        'backend/internal/services/entware/manager.go',
        'backend/internal/services/entware/processes.go',
        'backend/internal/services/entware/process.go',
        'backend/internal/services/entware/smoke.go',
        'backend/internal/services/entware/ingress_default.go',
        'backend/internal/services/entware/ingress_keenetic.go',
        'backend/internal/network/keeneticroute/ingress_codec_test.go',
        'backend/internal/network/keeneticroute/ingress_netlink_codec.go',
        'backend/internal/network/keeneticroute/ingress_netlink_linux.go',
        'backend/internal/network/keeneticroute/ingress_policy.go',
        'backend/internal/network/keeneticroute/ingress_policy_test.go',
        'backend/internal/network/keeneticroute/ingress_reconcile.go',
        'backend/internal/network/keeneticroute/ingress_reconcile_test.go',
        'backend/internal/profileexec/paths_default.go',
        'backend/internal/profileexec/paths_keenetic.go',
        'backend/internal/profileexec/profile.go',
        'backend/internal/profileexec/profile_test.go',
        'backend/internal/binding/keenetic_ingress.go',
        'backend/pkg/keeneticrci/policy.go',
        'backend/pkg/keeneticrci/policy_test.go',
        'deploy/keenetic/netfilter.d/090-hestia-ingress.sh',
        'backend/internal/platformhelper/run_default.go',
        'backend/internal/platformhelper/run_keenetic.go',
        'backend/internal/awgruntime/unsupported.go',
        'backend/internal/awgruntime/entware_linux.go',
        'backend/internal/awg/platform_keenetic.go',
        'frontend/src/core/services/api/generated/model/nativeEthernetPort.ts',
    ]
    inputs = {name: file_hash(ROOT / name) for name in sorted(set(tracked)) if (ROOT / name).is_file()}
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True))
    version = time.strftime('%Y%m%d-%H%M%S') + '-' + revision[:12]
    target = output.resolve() / version
    if target.exists():
        raise ValueError('Version output already exists')
    with tempfile.TemporaryDirectory(prefix='hestia-build-') as directory:
        work = Path(directory)
        compile_go(work / 'bin')
        frontends = {}
        for platform, configuration in (('linux-arm64', 'vm'), ('keenetic-arm64-experimental', 'keenetic')):
            frontend = work / 'frontend' / platform
            subprocess.run(['npm', 'run', 'build', '--', '--configuration', configuration,
                            '--output-path', str(frontend)], cwd=ROOT / 'frontend', check=True)
            frontends[platform] = frontend
        if any(not (ROOT / name).is_file() or file_hash(ROOT / name) != digest for name, digest in inputs.items()):
            raise RuntimeError('Build inputs changed during compilation; refusing misleading artifact provenance')
        target.mkdir(parents=True)
        for platform in ('linux-arm64', 'keenetic-arm64-experimental'):
            bundle = target / platform
            bundle.mkdir()
            compiled_platform = work / 'bin' / platform / 'bin'
            shutil.copytree(compiled_platform, bundle / 'bin')
            awg_runtime = 'awg-keenetic-static' if platform.startswith('keenetic') else 'awg'
            for name, runtime_name in (('amneziawg-go', 'amneziawg-go'), ('awg', awg_runtime)):
                shutil.copyfile(runtime / runtime_name, bundle / 'bin' / name)
                (bundle / 'bin' / name).chmod(0o755)
            shutil.copyfile(runtime / 'sing.tgz', bundle / 'sing.tgz')
            copy_frontend(frontends[platform], bundle / 'browser')
            (bundle / 'helpers').mkdir()
            for name in ('profile.py', 'smoke.py', 'awg-upgrade.sh'):
                shutil.copyfile(ROOT / 'deploy' / name, bundle / 'helpers' / name)
            (bundle / 'scripts').mkdir()
            for name in ('apply.sh', 'fresh.sh'):
                shutil.copyfile(ROOT / 'scripts/deploy' / name, bundle / 'scripts' / name)
            default_profile = 'default-profile-keenetic.json' if platform.startswith('keenetic') else 'default-profile.json'
            shutil.copyfile(ROOT / 'scripts/deploy' / default_profile, bundle / 'scripts/default-profile.json')
            if platform.startswith('keenetic'):
                stage_keenetic_rootfs(bundle, runtime)
                prepare_keenetic_config(bundle, work)
                init_script = bundle / 'opt/etc/init.d/S99hestia'
                init_script.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / 'deploy/keenetic/S99hestia', init_script)
                init_script.chmod(0o755)
                package = bundle / ('hestia_' + version + '_aarch64-3.10.ipk')
                create_ipk(bundle, package, version, ['python3-light', 'python3-codecs', 'busybox', 'libc'],
                           work / 'bin/keenetic-arm64-experimental/bin/keenetic-preflight')
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
                        'go_build_tags': ['keenetic'] if platform.startswith('keenetic') else [],
                        'experimental': platform.startswith('keenetic'),
                        'runtime_prerequisites': {'sing-box': '1.14.4', 'amneziawg-go': '3.1.20260828', 'awg-tools': '3.1.20260812'},
                        'entware_dependencies': ['python3-light', 'python3-codecs', 'busybox', 'libc'] if platform.startswith('keenetic') else [],
                        'runtime_inputs': locks, 'deployment': 'initial-or-managed-update' if platform == 'linux-arm64' else 'experimental-ipk-and-rootfs',
                        'limitations': ['Linux ARM64 systemd and Debian-compatible runtime required'] if platform == 'linux-arm64' else ['An earlier IPK revision was installed and its lifecycle hooks, Entware supervisor, Go smoke, panel, controller, router, readiness, and LAN API were checked on KN-1012 / KeeneticOS 5.2 Beta 3; repeat acceptance for this exact revision is recorded separately', 'WireGuard/AmneziaWG and Hysteria 2 profile CRUD is included in this experimental build; runtime/dataplane, route ownership, fail-closed and rollback are not validated on KN-1012', 'DNS, Wi-Fi/WISP and mapping native Ethernet IDs to kernel devices remain unavailable or unverified', 'The Entware init applet and declared dependencies were checked during the earlier KN-1012 installation, not independently across target versions', 'opkg upgrade is not transactionally rolled back if postinst fails; restore requires reinstalling a prior IPK and preserving conffiles'],
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
    parser.add_argument('--check-go', action='store_true', help='Compile Linux and Keenetic Go commands only; no distribution artifact or frontend')
    args = parser.parse_args()
    if args.check_go:
        compile_go(args.output.resolve())
    else:
        build(args.output, args.runtime_dir)


if __name__ == '__main__':
    main()
