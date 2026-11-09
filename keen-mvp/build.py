"""Build a small standalone Entware IPK for the Keenetic OpkgTun MVP."""
import argparse
import gzip
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parent


def file_info(path, archive_name):
    """Return deterministic root-owned archive metadata for one regular file."""
    info = tarfile.TarInfo(archive_name)
    info.size = path.stat().st_size
    info.mode = path.stat().st_mode & 0o777
    info.uid = 0
    info.gid = 0
    info.uname = 'root'
    info.gname = 'root'
    info.mtime = 0
    return info


def tar_gzip(files, base, prefix=''):
    """Create a reproducible gzip-compressed tar archive from relative file paths."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.GNU_FORMAT) as archive:
        for relative in sorted(files):
            source = base / relative
            name = Path(prefix) / relative if prefix else relative
            with source.open('rb') as stream:
                archive.addfile(file_info(source, './' + name.as_posix()), stream)
    content = bytearray(gzip.compress(raw.getvalue(), compresslevel=9, mtime=0))
    content[9] = 255
    return bytes(content)


def package(output, version):
    """Compile the static ARM64 binary and assemble a standalone aarch64-3.10 IPK."""
    output = output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='keen-mvp-') as temporary:
        work = Path(temporary)
        stage = work / 'root'
        files = {
            Path('opt/bin/keen-mvp'): (work / 'keen-mvp', 0o755),
            Path('opt/etc/init.d/S52keen-mvp'): (ROOT / 'S52keen-mvp', 0o755),
        }
        (stage / 'opt/bin').mkdir(parents=True)
        (stage / 'opt/etc/init.d').mkdir(parents=True)
        subprocess.run(
            ['go', 'build', '-trimpath', '-ldflags=-s -w', '-o', str(work / 'keen-mvp'), '.'],
            cwd=ROOT,
            env={**os.environ, 'CGO_ENABLED': '0', 'GOOS': 'linux', 'GOARCH': 'arm64'},
            check=True,
        )
        for destination, (source, mode) in files.items():
            target = stage / destination
            shutil.copyfile(source, target)
            target.chmod(mode)

        control = work / 'control'
        control.mkdir()
        (control / 'control').write_text(
            '\n'.join((
                'Package: keen-mvp',
                'Version: ' + version,
                'Depends: busybox',
                'Architecture: aarch64-3.10',
                'Maintainer: Hestia',
                'Description: Experimental Keenetic OpkgTun interface prototype',
                '',
            )),
        )
        for name in ('postinst', 'prerm'):
            shutil.copyfile(ROOT / 'ipk' / name, control / name)
            (control / name).chmod(0o755)
        control_tar = tar_gzip([Path(name) for name in ('control', 'postinst', 'prerm')], control)
        data_tar = tar_gzip(
            [Path('bin/keen-mvp'), Path('etc/init.d/S52keen-mvp')],
            stage / 'opt',
            'opt',
        )

        outer = work / 'keen-mvp.ipk'
        outer_root = work / 'outer'
        outer_root.mkdir()
        (outer_root / 'debian-binary').write_text('2.0\n')
        (outer_root / 'control.tar.gz').write_bytes(control_tar)
        (outer_root / 'data.tar.gz').write_bytes(data_tar)
        outer_tar = tar_gzip(
            [Path('debian-binary'), Path('control.tar.gz'), Path('data.tar.gz')],
            outer_root,
        )
        output.write_bytes(outer_tar)
        output.chmod(0o644)


def main():
    """Parse package build options and write the requested IPK artifact."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/keen-mvp_0.1.0-3_aarch64-3.10.ipk')
    parser.add_argument('--version', default='0.1.0-3')
    arguments = parser.parse_args()
    package(arguments.output, arguments.version)


if __name__ == '__main__':
    main()
