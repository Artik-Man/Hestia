"""Shared stand transport, artifact verification and phase reporting for independent commands."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]


class Stand:
    """Describe one explicitly chosen Linux ARM64 system without changing its power state."""

    def __init__(self, data):
        """Validate public connection settings; passwords and embedded shell expressions are rejected."""
        self.data = data
        allowed = {'name', 'transport', 'instance', 'lima_home', 'host', 'user', 'port', 'expected_hostname', 'platform', 'fixture', 'panel_url'}
        if set(data) - allowed or data.get('transport') not in {'lima', 'ssh'}:
            raise ValueError('Unsupported stand fields or transport')
        self.name = data['name']
        self.platform = data['platform']
        self.fixture = data.get('fixture', False)
        if self.platform not in {'linux-arm64', 'keenetic-arm64-experimental'} or not isinstance(self.fixture, bool):
            raise ValueError('Invalid platform or fixture flag')
        for key in ('name', 'expected_hostname'):
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', data[key]):
                raise ValueError('Invalid stand identity')
        panel = urllib.parse.urlsplit(data.get('panel_url', 'http://127.0.0.1:8080'))
        if panel.scheme != 'http' or panel.username or panel.password or panel.query or panel.fragment or panel.path not in {'', '/'}:
            raise ValueError('Panel URL must be a plain HTTP literal-IP origin')
        ipaddress.ip_address(panel.hostname)
        if panel.port is not None and not 1 <= panel.port <= 65535:
            raise ValueError('Invalid panel port')
        self.env = dict(os.environ)
        if data['transport'] == 'lima':
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', data['instance']):
                raise ValueError('Invalid Lima instance')
            self.env['LIMA_HOME'] = str(Path(data['lima_home']).expanduser().resolve())
            self.tool = os.environ.get('LIMACTL', shutil.which('limactl') or '/private/tmp/hestia-vm-run/bin/limactl')
        else:
            for key in ('host', 'user'):
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,253}', data[key]):
                    raise ValueError('Invalid SSH endpoint')
            if not isinstance(data.get('port', 22), int) or not 1 <= data.get('port', 22) <= 65535:
                raise ValueError('Invalid SSH port')

    @classmethod
    def load(cls, path):
        """Load one explicit descriptor; never infer a target from the current shell."""
        return cls(json.loads(Path(path).read_text()))

    def command(self, argv, sudo=False):
        """Return transport arguments for exactly the supplied remote argument vector."""
        remote = (['sudo', '-n'] if sudo else []) + [str(arg) for arg in argv]
        if self.data['transport'] == 'lima':
            return [self.tool, 'shell', self.data['instance'], '--', *remote]
        return ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-p', str(self.data.get('port', 22)), self.data['user'] + '@' + self.data['host'], shlex.join(remote)]

    def run(self, argv, sudo=False, **kwargs):
        """Execute a bounded remote command using this descriptor's explicit environment."""
        return subprocess.run(self.command(argv, sudo), env=self.env, **kwargs)

    def preflight(self):
        """Require an already-running matching guest and Linux ARM64 before any remote writes."""
        if self.platform != 'linux-arm64':
            raise ValueError('Experimental Keenetic has no deploy/test adapter yet')
        if self.data['transport'] == 'lima':
            raw = subprocess.check_output([self.tool, 'list', self.data['instance'], '--json'], env=self.env, text=True)
            machine = json.loads(raw)
            if machine.get('name') != self.data['instance'] or machine.get('status') != 'Running':
                raise ValueError('Selected Lima guest must already be Running')
        for command, expected in ((['hostname', '-s'], self.data['expected_hostname']), (['uname', '-s'], 'Linux'), (['uname', '-m'], 'aarch64')):
            actual = self.run(command, check=True, capture_output=True, text=True, timeout=20).stdout.strip()
            if actual != expected:
                raise ValueError('Stand identity mismatch: ' + command[0])

    def copy(self, local, remote):
        """Copy one local artifact to a generated absolute path without exposing authentication secrets."""
        if not re.fullmatch(r'/tmp/hestia-[A-Za-z0-9_.-]+', remote):
            raise ValueError('Remote copy path must be an owned /tmp/hestia-* file')
        if self.data['transport'] == 'lima':
            command = [self.tool, 'copy', str(local), self.data['instance'] + ':' + remote]
        else:
            command = ['scp', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-P', str(self.data.get('port', 22)), str(local), self.data['user'] + '@' + self.data['host'] + ':' + remote]
        subprocess.run(command, env=self.env, check=True, timeout=300)


def load_stand(path):
    """Return a validated explicit stand descriptor for deploy and installed tests."""
    return Stand.load(path)


def file_hash(path):
    """Compute a regular file digest without loading large artifacts into memory."""
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_bundle(directory):
    """Require exact manifest file inventory and hashes, rejecting traversal and symlinks."""
    root = Path(directory).resolve()
    if not (root / 'manifest.json').is_file() or (root / 'manifest.json').is_symlink():
        raise ValueError('Manifest must be a regular file')
    manifest = json.loads((root / 'manifest.json').read_text())
    if manifest.get('schema') != 1 or manifest.get('platform') not in {'linux-arm64', 'keenetic-arm64-experimental'}:
        raise ValueError('Unsupported artifact manifest')
    actual = set()
    for path in root.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('Artifact contains a link or special file')
        if path.is_file() and path != root / 'manifest.json':
            actual.add(str(path.relative_to(root)))
    if actual != set(manifest['files']):
        raise ValueError('Artifact inventory differs from manifest')
    for name, expected in manifest['files'].items():
        if file_hash(root / name) != expected:
            raise ValueError('Artifact checksum mismatch: ' + name)
    return manifest


class Run:
    """Collect phase status and logs, retaining failure evidence and explicit skipped phases."""

    def __init__(self, output):
        """Create a new private result directory; never reuse an earlier run."""
        self.output = output
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.results = []

    def phase(self, name, command, cwd=ROOT, env=None):
        """Execute one bounded command, record its status and stream its log after completion."""
        log = self.output / (name + '.log')
        print('RUN', name, 'log=' + str(log), flush=True)
        start = time.monotonic()
        with log.open('w') as stream:
            try:
                process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    code = process.wait(timeout=3600)
                except (KeyboardInterrupt, subprocess.TimeoutExpired):
                    if name == 'installed-browser':
                        process.terminate()
                    else:
                        os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=480)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    raise
            except (OSError, subprocess.TimeoutExpired) as error:
                stream.write(str(error) + '\n')
                code = 2
        status = 'PASS' if code == 0 else 'FAIL'
        self.results.append({'name': name, 'status': status, 'exit': code, 'seconds': round(time.monotonic() - start, 2), 'command': command, 'log': str(log)})
        print(status, name, str(round(time.monotonic() - start, 2)) + 's', str(log), flush=True)
        self.save()
        return code == 0

    def skip(self, name, reason):
        """Expose a mandatory phase that could not run because a prerequisite failed."""
        self.results.append({'name': name, 'status': 'SKIP', 'reason': reason})
        self.save()

    def fail(self, name, error):
        """Record preflight or orchestration errors as visible failed phases."""
        self.results.append({'name': name, 'status': 'FAIL', 'error': str(error)})
        self.save()

    def save(self):
        """Persist machine-readable and human-readable summaries after every phase."""
        (self.output / 'results.json').write_text(json.dumps(self.results, indent=2) + '\n')
        (self.output / 'summary.txt').write_text(''.join(f"{r['status']} {r['name']}\n" for r in self.results))


# Report is the shared name retained alongside Run for source and installed-test drivers.
Report = Run
