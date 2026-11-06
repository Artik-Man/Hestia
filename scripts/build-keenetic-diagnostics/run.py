"""Build a local, versioned ARM64 diagnostic bundle without accessing a device."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIRS = (
    "backend/cmd/hestia-keenetic-diagnostics",
    "backend/internal/keeneticdiagnostics",
    "scripts/build-keenetic-diagnostics",
)
SOURCE_FILES = (
    "backend/go.mod",
    "backend/go.sum",
    "docs/features/keenetic-diagnostics.md",
)


def file_hash(path: Path) -> str:
    """Return the SHA-256 of a regular input file without loading it all at once."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_inputs() -> dict[str, str]:
    """Hash all relevant tracked and untracked sources; reject symbolic links."""
    paths = [ROOT / name for name in SOURCE_FILES]
    for name in SOURCE_DIRS:
        directory = ROOT / name
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError("Missing or symbolic source directory: " + name)
        for path in sorted(directory.rglob("*")):
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            if path.is_symlink():
                raise ValueError("Symbolic source is not supported: " + str(path))
            if path.is_file():
                paths.append(path)
    if not any(path.suffix == ".go" for path in paths):
        raise ValueError("Diagnostic Go sources are missing")
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symbolic source file: " + str(path))
    return {str(path.relative_to(ROOT)): file_hash(path) for path in sorted(paths)}


def git_metadata() -> tuple[str, bool]:
    """Read local revision and worktree status, including untracked source files."""
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        timeout=30,
    ).strip()
    dirty = bool(
        subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=ROOT,
            text=True,
            timeout=30,
        )
    )
    return revision, dirty


def compiler_environment() -> dict[str, str]:
    """Pin an offline static Linux ARM64 build and ignore ambient Go overrides."""
    return dict(
        os.environ,
        GOOS="linux",
        GOARCH="arm64",
        CGO_ENABLED="0",
        GOPROXY="off",
        GOSUMDB="off",
        GOTOOLCHAIN="local",
        GOFLAGS="",
        GOWORK="off",
        GOENV="off",
        GOEXPERIMENT="",
        GOARM64="v8.0",
    )


def compile_binary(source: Path, binary: Path, version: str) -> None:
    """Compile the isolated source snapshot; propagate compiler failure or timeout."""
    subprocess.run(
        [
            "go",
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags",
            "-X main.buildVersion=" + version,
            "-o",
            str(binary),
            "./cmd/hestia-keenetic-diagnostics",
        ],
        cwd=source / "backend",
        env=compiler_environment(),
        check=True,
        timeout=300,
    )


def build(output: Path, version: str | None = None) -> Path:
    """Publish a complete diagnostic directory, refusing reused names or input drift."""
    if version is not None and not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", version
    ):
        raise ValueError("Version must be a simple name of at most 100 characters")
    revision, dirty = git_metadata()
    version = version or (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + revision[:12]
    )
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    target = output / version
    lock = output / ("." + version + ".lock")
    lock.mkdir()
    try:
        if target.exists() or target.is_symlink():
            raise FileExistsError("Artifact version already exists: " + str(target))
        inputs = source_inputs()
        with tempfile.TemporaryDirectory(
            prefix=".diagnostic-build-", dir=output
        ) as directory:
            work = Path(directory)
            snapshot = work / "source"
            for name, digest in inputs.items():
                destination = snapshot / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
                if file_hash(destination) != digest:
                    raise RuntimeError(
                        "Source changed while taking build snapshot: " + name
                    )
            bundle = work / "bundle"
            (bundle / "bin").mkdir(parents=True)
            compile_binary(
                snapshot, bundle / "bin/hestia-keenetic-diagnostics", version
            )
            shutil.copyfile(
                snapshot / "scripts/build-keenetic-diagnostics/readme.md",
                bundle / "README.md",
            )
            shutil.copyfile(
                snapshot / "docs/features/keenetic-diagnostics.md",
                bundle / "SPECIFICATION.md",
            )
            if source_inputs() != inputs or git_metadata() != (revision, dirty):
                raise RuntimeError("Sources or repository state changed during build")
            go_version = subprocess.check_output(
                ["go", "version"],
                env=compiler_environment(),
                text=True,
                timeout=30,
            ).strip()
            manifest = {
                "schema": 1,
                "version": version,
                "revision": revision,
                "dirty": dirty,
                "source_inputs": inputs,
                "platform": "keenetic-diagnostics-linux-arm64",
                "architecture": "aarch64",
                "cgo_enabled": False,
                "go_version": go_version,
                "deployment": "not-installed",
                "hardware_validation": "not-performed",
                "limitations": [
                    "Inventory only; no network capability tests",
                    "Keenetic compatibility is not confirmed",
                    "Not an application installer or an ipk package",
                ],
                "files": {
                    str(path.relative_to(bundle)): file_hash(path)
                    for path in sorted(bundle.rglob("*"))
                    if path.is_file()
                },
            }
            (bundle / "manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            sums = "".join(
                file_hash(path) + "  " + str(path.relative_to(bundle)) + "\n"
                for path in sorted(bundle.rglob("*"))
                if path.is_file()
            )
            (bundle / "SHA256SUMS").write_text(sums, encoding="utf-8")
            if target.exists() or target.is_symlink():
                raise FileExistsError("Artifact version already exists: " + str(target))
            bundle.rename(target)
        return target
    finally:
        lock.rmdir()


def main() -> None:
    """Parse local output options and print the published bundle path on success."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "dist/keenetic-diagnostics"
    )
    parser.add_argument("--version", help="Optional immutable artifact version")
    args = parser.parse_args()
    print(build(args.output, args.version))


if __name__ == "__main__":
    main()
