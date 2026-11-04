#!/usr/bin/env python3
"""Safely seed the managed profile from the existing scheme3 configuration."""

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


MANAGED_NAMES = (
    "profile.json",
    "profile-source.sha256",
    "profile-backend.sha256",
)


def read_json(path: Path) -> object:
    """Read one required JSON file and reject symlinks or non-regular files."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"not a regular file: {path}")
    return json.loads(path.read_bytes())


def tagged_outbounds(config: dict) -> dict:
    """Index unique tagged outbounds without losing nested semantics."""
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        raise ValueError("backend has no outbounds array")
    indexed = {}
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            raise ValueError("backend contains an invalid outbound")
        tag = outbound.get("tag")
        if not isinstance(tag, str) or not tag or tag in indexed:
            raise ValueError("backend outbound tags are missing or duplicated")
        indexed[tag] = outbound
    return indexed


def backend_matches(current: dict, candidate: dict) -> bool:
    """Compare backend fields and normalize tagged outbound order."""
    if set(current) != set(candidate) or "outbounds" not in current:
        return False
    for name in current:
        if name != "outbounds" and current[name] != candidate[name]:
            return False
    return tagged_outbounds(current) == tagged_outbounds(candidate)


def compare_candidate(
    root: Path, seed: Path, compiler: Path
) -> tuple[bytes, bytes, bytes]:
    """Compile the seed and prove it preserves installed behavior."""
    for name in ("snapshot.json", "sing-box.json"):
        info = (root / name).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise ValueError(f"unsafe installed configuration: {name}")
    with tempfile.TemporaryDirectory(
        prefix="hestia-profile-adoption-"
    ) as temporary:
        stage = Path(temporary)
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(compiler),
                str(seed),
                str(stage),
                str(seed.parent),
            ],
            check=True,
            stdin=subprocess.DEVNULL,
        )
        current_snapshot = read_json(root / "snapshot.json")
        candidate_snapshot = read_json(stage / "snapshot.json")
        if current_snapshot != candidate_snapshot:
            raise ValueError(
                "candidate snapshot changes the existing controller state"
            )
        current_backend = read_json(root / "sing-box.json")
        candidate_backend = read_json(stage / "sing-box.json")
        if not isinstance(current_backend, dict) or not isinstance(
            candidate_backend, dict
        ):
            raise ValueError("backend root must be an object")
        if not backend_matches(current_backend, candidate_backend):
            raise ValueError(
                "candidate backend changes existing traffic behavior"
            )
    profile = seed.read_bytes()
    backend = (root / "sing-box.json").read_bytes()
    return (
        profile,
        (hashlib.sha256(profile).hexdigest() + "\n").encode(),
        (hashlib.sha256(backend).hexdigest() + "\n").encode(),
    )


def verify_owned_file(path: Path, expected: bytes) -> bool:
    """Check whether an artifact is the expected root-owned regular file."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ValueError(f"unsafe adoption artifact: {path.name}")
    if path.read_bytes() != expected:
        raise ValueError(f"conflicting adoption artifact: {path.name}")
    return True


def atomic_file(path: Path, data: bytes, mode: int) -> None:
    """Publish one root-owned file atomically with exact permissions."""
    descriptor, temporary = tempfile.mkstemp(
        prefix=".profile-", dir=path.parent
    )
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary).unlink(missing_ok=True)
        raise


def install_generation(
    root: Path, marker: Path, data: tuple[bytes, bytes, bytes]
) -> None:
    """Install a managed profile generation and publish its marker last."""
    expected = dict(zip(MANAGED_NAMES, data))
    created = []
    try:
        for name, contents in expected.items():
            path = root / name
            if verify_owned_file(path, contents):
                continue
            atomic_file(path, contents, 0o600)
            created.append(path)
        atomic_file(marker, b"1\n", 0o600)
    except BaseException:
        for path in reversed(created):
            try:
                if verify_owned_file(path, expected[path.name]):
                    path.unlink()
            except (OSError, ValueError):
                pass
        raise


def remove_generation(
    root: Path, marker: Path, data: tuple[bytes, bytes, bytes]
) -> None:
    """Remove only exact root-owned artifacts from an incomplete adoption."""
    if marker.exists() or marker.is_symlink():
        info = marker.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or marker.read_bytes() != b"1\n"
        ):
            raise ValueError("unsafe installer marker during rollback")
        marker.unlink()
    for name, contents in zip(MANAGED_NAMES, data):
        path = root / name
        if verify_owned_file(path, contents):
            path.unlink()


def main() -> None:
    """Check or adopt the existing topology without changing live routes."""
    if len(sys.argv) != 5 or sys.argv[1] not in {"check", "adopt", "rollback"}:
        raise ValueError(
            "usage: adopt-profile.py {check|adopt|rollback} ROOT SEED COMPILER"
        )
    action = sys.argv[1]
    root, seed, compiler = map(Path, sys.argv[2:])
    if os.geteuid() != 0:
        raise ValueError("must run as root")
    if root.is_symlink() or not root.is_dir():
        raise ValueError("unsafe Hestia configuration directory")
    marker = root / ".installer-managed"
    if action == "rollback":
        data = compare_candidate(root, seed, compiler)
        remove_generation(root, marker, data)
        return
    if marker.exists() or marker.is_symlink():
        marker_info = marker.lstat()
        if (
            not stat.S_ISREG(marker_info.st_mode)
            or marker_info.st_uid != 0
            or stat.S_IMODE(marker_info.st_mode) != 0o600
            or marker.read_bytes() != b"1\n"
        ):
            raise ValueError("unsafe installer marker")
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(compiler),
                "--validate-managed",
                str(root),
            ],
            check=True,
            stdin=subprocess.DEVNULL,
        )
        return
    data = compare_candidate(root, seed, compiler)
    if action == "adopt":
        install_generation(root, marker, data)
        try:
            root_data = (root / "sing-box.json").read_bytes()
            if (
                hashlib.sha256(root_data).hexdigest().encode() + b"\n"
                != data[2]
            ):
                raise ValueError("installed backend changed during adoption")
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(compiler),
                    "--validate-managed",
                    str(root),
                ],
                check=True,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, ValueError, subprocess.CalledProcessError):
            remove_generation(root, marker, data)
            raise


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
    ) as error:
        sys.exit(f"scheme3 profile adoption failed: {error}")
