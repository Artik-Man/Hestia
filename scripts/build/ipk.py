"""Create a deterministic Entware-compatible IPK from a staged /opt tree."""
import argparse
import gzip
from pathlib import Path
import re
import tarfile
import tempfile


def _archive_bytes(entries, root, prefix=''):
    """Return a deterministic gzip-compressed GNU tar containing the supplied relative paths."""
    import io

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.GNU_FORMAT) as archive:
        for relative in sorted(entries):
            path = root / prefix / relative
            archive_path = Path(prefix) / relative if prefix else relative
            info = archive.gettarinfo(str(path), arcname='./' + archive_path.as_posix())
            info.uid = 0
            info.gid = 0
            info.uname = 'root'
            info.gname = 'root'
            info.mtime = 0
            if info.isfile():
                with path.open('rb') as stream:
                    archive.addfile(info, stream)
            else:
                archive.addfile(info)
    compressed = bytearray(gzip.compress(raw.getvalue(), compresslevel=9, mtime=0))
    compressed[9] = 255
    return bytes(compressed)


def _safe_tree(root):
    """Return regular files and directories in a package root while rejecting links and special files."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError('IPK package tree root must be a regular directory')
    entries = []
    for path in root.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('IPK input contains a link or special file: ' + str(path))
        entries.append(path.relative_to(root))
    return entries


def create_ipk(rootfs, output, version, dependencies, preflight_binary=None):
    """Pack a rootfs and optional Go preflight helper into an Entware aarch64-3.10 IPK."""
    source_root = Path(rootfs)
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError('IPK rootfs must be a regular directory')
    package_root = source_root.resolve()
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError('IPK output already exists')
    if (package_root / 'opt').is_symlink() or not (package_root / 'opt').is_dir():
        raise ValueError('IPK rootfs must contain /opt')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+~-]{0,63}', version):
        raise ValueError('Invalid IPK package version')
    if not dependencies or any(not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*( \(.*\))?', item) for item in dependencies):
        raise ValueError('Invalid IPK dependencies')
    entries = _safe_tree(package_root / 'opt')
    control = '\n'.join((
        'Package: hestia',
        'Version: ' + version,
        'Depends: ' + ', '.join(dependencies),
        'Architecture: aarch64-3.10',
        'Maintainer: Hestia',
        'Description: Hestia gateway for Entware on Keenetic',
        '',
    )).encode()
    with tempfile.TemporaryDirectory(prefix='hestia-ipk-') as temporary:
        control_root = Path(temporary)
        (control_root / 'control').write_bytes(control)
        control_files = [Path('control')]
        conffiles = [
            '/opt/etc/hestia/.installer-managed',
            '/opt/etc/hestia/profile.json',
            '/opt/etc/hestia/profile-source.sha256',
            '/opt/etc/hestia/profile-backend.sha256',
            '/opt/etc/hestia/snapshot.json',
            '/opt/etc/hestia/sing-box.json',
        ]
        (control_root / 'conffiles').write_text('\n'.join(conffiles) + '\n')
        control_files.append(Path('conffiles'))
        for name in ('preinst', 'postinst', 'prerm', 'postrm'):
            source = Path(__file__).resolve().parents[2] / 'deploy' / 'keenetic' / 'ipk' / name
            if source.is_file():
                (control_root / name).write_bytes(source.read_bytes())
                (control_root / name).chmod(0o755)
                control_files.append(Path(name))
        if preflight_binary is not None:
            helper = Path(preflight_binary)
            if helper.is_symlink() or not helper.is_file():
                raise ValueError('IPK Go preflight helper must be a regular file')
            (control_root / 'keenetic-preflight').write_bytes(helper.read_bytes())
            (control_root / 'keenetic-preflight').chmod(0o755)
            control_files.append(Path('keenetic-preflight'))
        control_archive = _archive_bytes(control_files, control_root)
        data_archive = _archive_bytes(entries, package_root, 'opt')
    destination.parent.mkdir(parents=True, exist_ok=True)
    outer_root = destination.parent / (destination.stem + '.ipk-root')
    outer_root.mkdir(parents=True, exist_ok=False)
    try:
        (outer_root / 'debian-binary').write_text('2.0\n')
        (outer_root / 'control.tar.gz').write_bytes(control_archive)
        (outer_root / 'data.tar.gz').write_bytes(data_archive)
        outer = _archive_bytes([Path(name) for name in ('debian-binary', 'control.tar.gz', 'data.tar.gz')], outer_root)
        destination.write_bytes(outer)
        destination.chmod(0o644)
    finally:
        for path in outer_root.iterdir():
            path.unlink()
        outer_root.rmdir()


def main():
    """Create one IPK file from a staged rootfs without accessing an Entware device."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--depends', action='append', default=[])
    arguments = parser.parse_args()
    create_ipk(arguments.rootfs, arguments.output, arguments.version, arguments.depends)


if __name__ == '__main__':
    main()
