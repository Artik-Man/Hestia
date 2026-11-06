"""Run source-only regression gates without any stand connection or deployment."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/shared'))
from common import Run as Report

ACTIVE_REPORT = None

def digest_tree(root):
    """Return path/content hashes of regular files for reproducibility comparison."""
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob('*')) if p.is_file()}


def checked(command, cwd=ROOT, env=None):
    """Run an argument-vector command and raise on failure without shell interpolation."""
    return subprocess.run(command, cwd=cwd, env=env, check=True)


def source_files():
    """Select tracked backend sources for disposable API regeneration, rejecting symlinks."""
    tracked = subprocess.check_output(['git', 'ls-files', '-z', 'backend'], cwd=ROOT).decode().split('\0')
    names = [name for name in tracked if name and (ROOT / name).is_file()]
    for name in names:
        path = ROOT / name
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != ROOT and parent.is_relative_to(ROOT)):
            raise RuntimeError('Symlink in staged source: ' + name)
    return sorted(names)


def copy_source(destination):
    """Copy the explicit public manifest, never arbitrary untracked files or symlinks."""
    for name in source_files():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)


def api_reproducible():
    """Regenerate API in a disposable tree and compare it to current worktree bytes."""
    with tempfile.TemporaryDirectory(prefix='hestia-api-check-') as temporary:
        temp = Path(temporary)
        copy_source(temp)
        shutil.copytree(ROOT / 'frontend/scripts', temp / 'frontend/scripts')
        shutil.copytree(ROOT / 'frontend/.cache', temp / 'frontend/.cache')
        checked(['go', '-C', str(temp / 'backend'), 'run', './tools/openapi', '-output', 'api/openapi.yaml'])
        checked(['node', 'scripts/generate-client.mjs'], temp / 'frontend')
        for relative in ('backend/api', 'frontend/src/core/services/api/generated'):
            if digest_tree(ROOT / relative) != digest_tree(temp / relative):
                raise RuntimeError('Generated API differs: ' + relative)


def main():
    """Run all mandatory host gates and report host-platform limitations explicitly."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--internal', choices=('api',))
    args = parser.parse_args()
    if args.internal == 'api':
        api_reproducible()
        return 0
    run_id = time.strftime('%Y%m%d-%H%M%S') + '-' + str(os.getpid())
    global ACTIVE_REPORT
    report = Report(args.output or ROOT / 'experiments/dev-validation/evidence' / ('source-' + run_id))
    ACTIVE_REPORT = report
    tracked = subprocess.check_output(['git', 'ls-files', '-z', 'backend', 'frontend', 'tools', 'Makefile', 'scripts'], cwd=ROOT).decode().split('\0')
    names = {name for name in tracked if name and (ROOT / name).is_file()}
    names.update(str(path.relative_to(ROOT)) for path in (ROOT / 'scripts').rglob('*') if path.is_file() and path.suffix in ('.py', '.sh', '.json'))
    (report.output / 'source.json').write_text(json.dumps({
        'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
        'files': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(names)},
    }, indent=2))
    env = dict(os.environ)
    for tool in ('go', 'node', 'npm', 'java', 'python3', 'shfmt', 'shellcheck'):
        value = env.get(tool.upper(), tool)
        if shutil.which(value) is None:
            report.fail('preflight', 'Missing dependency: ' + value)
            return 2
    phases = [
        ('source-check', ['make', 'check'], ROOT),
        ('api-reproducibility', [sys.executable, str(Path(__file__)), '--internal', 'api'], ROOT),
        ('frontend-format', ['npm', 'run', 'format:check'], ROOT / 'frontend'),
        ('frontend-lint', ['npm', 'run', 'lint'], ROOT / 'frontend'),
        ('frontend-unit', ['npm', 'test'], ROOT / 'frontend'),
        ('frontend-build', ['npm', 'run', 'build'], ROOT / 'frontend'),
        ('frontend-browser', ['npm', 'run', 'test:browser'], ROOT / 'frontend'),
        ('source-race', ['go', 'test', '-race', '-count=1', './internal/binding', './internal/controller', './internal/dnsresolver', './internal/dnsservice', './internal/quality', './internal/storage', './internal/network/...'], ROOT / 'backend'),
    ]
    (report.output / 'scope.json').write_text(json.dumps({'scope': 'source', 'host': sys.platform, 'limitation': 'Host Go tests may skip Linux-only raw socket and offline NetworkManager cases. scripts/test checks copied installed runtimes in isolated networking fixtures, not Linux Go unit/offline NetworkManager coverage.'}, indent=2))
    results = [report.phase(name, command, cwd=cwd, env=env) for name, command, cwd in phases]
    return 0 if all(results) else 1


def entrypoint() -> int:
    """Record prerequisite errors and interruptions in the active report before returning failure."""
    try:
        return main()
    except KeyboardInterrupt:
        if ACTIVE_REPORT is not None:
            ACTIVE_REPORT.fail('interrupted', 'Source validation interrupted; coverage incomplete')
        return 130
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        if ACTIVE_REPORT is not None:
            ACTIVE_REPORT.fail('prerequisite-or-orchestration', str(error))
        print('Source validation failed:', error, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(entrypoint())
