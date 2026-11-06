"""Verify only the installed, empty deny-only dev fixture and restore owned test changes."""
from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import time
from typing import Union
import urllib.error
import urllib.request
import uuid

JSON = Union[None, bool, int, float, str, list['JSON'], dict[str, 'JSON']]
PROFILE = Path('/etc/hestia/profile.json')
DNS_CONFIG = Path('/etc/hestia/dns.json')
API = 'http://127.0.0.1:8080'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects outside the fixed installed API origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Fail a redirect instead of sending test requests to another origin."""
        raise RuntimeError('unexpected API redirect')


def require(condition: bool, message: str) -> None:
    """Raise a stable non-secret failure without relying on optimized assertions."""
    if not condition:
        raise RuntimeError(message)


def validate_fixture(profile: object) -> None:
    """Require the exact known deny-only profile before any installed mutation."""
    expected = json.loads(Path(__file__).with_name('profile.json').read_text())
    require(profile == expected, 'installed profile is not the empty deny fixture')


def private_json(path: Path) -> JSON:
    """Read a bounded regular root-owned file without following its final symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
                not meta.st_mode & 0o022 and meta.st_size <= 1 << 20,
                'unsafe installed fixture file')
        return json.load(stream)


def guard() -> JSON:
    """Refuse wrong hosts, unowned fixtures, active connectors or nonempty routing."""
    require(os.geteuid() == 0 and socket.gethostname().split('.')[0] ==
            'lima-hestia-dev', 'acceptance is restricted to root on hestia-dev')
    marker = PROFILE.parent / '.dev-validation'
    info = marker.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
            stat.S_IMODE(info.st_mode) == 0o600,
            'missing trusted dev fixture marker')
    require(marker.read_text().strip().endswith(' dev-local-only'),
            'unrecognized dev fixture marker')
    profile = private_json(PROFILE)
    validate_fixture(profile)
    require(not list((PROFILE.parent / 'awg').iterdir()),
            'AWG store is not empty')
    active = subprocess.check_output(
        ['systemctl', 'list-units', 'hestia-awg*', '--state=active', '--no-legend'],
        text=True)
    require(not active.strip(), 'connector service is active')
    print('PASS empty installed deny fixture guard', flush=True)
    return profile


def request(path: str, method: str = 'GET', body: JSON = None) -> tuple[int, JSON]:
    """Call the fixed loopback API with bounded JSON and no redirect following."""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(req, timeout=310)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        payload = response.read((1 << 20) + 1)
        require(len(payload) <= 1 << 20, 'oversized API response')
        return response.status, json.loads(payload) if payload else None


def snapshot() -> dict[str, JSON]:
    """Read the public snapshot and reject malformed collections before cleanup."""
    status, value = request('/api/groups-and-rules')
    require(status == 200 and isinstance(value, dict), 'snapshot unavailable')
    require(isinstance(value.get('lists'), list) and
            isinstance(value.get('groups'), list), 'invalid snapshot')
    return value


def owned_list(value: object, name: str) -> bool:
    """Recognize only this run's list in one of its expected binding states."""
    return (isinstance(value, dict) and isinstance(value.get('id'), str) and
            value.get('name') == name and
            value.get('masks') == ['*.binding-accept.invalid'] and
            value.get('group') in ('', 'default') and
            value.get('enabled') == (value.get('group') == 'default'))


def cleanup_list(name: str, uncertain: bool) -> None:
    """Delete only an owned list through CAS; wait for an interrupted detached creation."""
    deadline = time.monotonic() + (100 if uncertain else 0)
    while True:
        value = snapshot()
        candidates = [item for item in value['lists']
                      if isinstance(item, dict) and item.get('name') == name]
        require(len(candidates) <= 1, 'ambiguous owned test list')
        if candidates:
            item = candidates[0]
            require(owned_list(item, name), 'test list changed concurrently; preserved')
            status, _ = request('/api/domain-lists/' + item['id'], 'DELETE', item)
            require(status == 204, 'owned list cleanup conflict; preserved')
            return
        if time.monotonic() >= deadline:
            return
        time.sleep(.25)


def api_acceptance() -> None:
    """Exercise installed reads and a CAS binding transaction, always cleaning its own list."""
    before_profile = guard()
    for path in ('navigation', 'groups-and-rules', 'awg', 'awg-underlays',
                 'hysteria2', 'physical-connections', 'quality', 'traffic',
                 'traffic/settings', 'country-map', 'dns/policy'):
        status, _ = request('/api/' + path)
        require(status == 200, 'installed GET failed: ' + path)
        print('PASS GET /api/' + path, flush=True)
    before = snapshot()
    name = 'Binding acceptance ' + uuid.uuid4().hex
    uncertain = True
    try:
        status, saved = request('/api/domain-lists', 'POST',
                               {'name': name, 'group': '',
                                'masks': ['*.binding-accept.invalid']})
        uncertain = False
        require(status == 201 and owned_list(saved, name), 'test list creation failed')
        identifier = saved['id']
        for old, new, expected in (('', 'default', 200), ('', '', 409),
                                   ('default', '', 200)):
            status, _ = request('/api/list-binding', 'PUT',
                                {'listId': identifier, 'expectedGroup': old,
                                 'group': new})
            require(status == expected, 'binding CAS response mismatch')
        print('PASS installed binding, stale CAS and unbinding', flush=True)
    finally:
        cleanup_list(name, uncertain)
    require(snapshot() == before and private_json(PROFILE) == before_profile,
            'concurrent configuration change detected; not overwritten')
    print('PASS semantic installed profile restored', flush=True)


def invalid_helpers() -> None:
    """Require stable rejection of malformed allowed operations and arbitrary root commands."""
    before = guard()
    for mode, payload, code in (('-apply-binding', b'{}', 1),
                                ('-create-group', b'{"name":123}', 42)):
        result = subprocess.run(['sudo', '-u', 'hestia-panel', 'sudo', '-n',
                                 '/usr/local/bin/hestia', mode], input=payload,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=100)
        require(result.returncode == code, 'invalid helper request was not rejected')
    result = subprocess.run(['sudo', '-u', 'hestia-panel', 'sudo', '-n', '/usr/bin/id'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=10)
    require(result.returncode != 0 and private_json(PROFILE) == before,
            'privilege boundary or configuration preservation failed')
    print('PASS malformed helpers and arbitrary sudo rejected', flush=True)


def dns_smoke() -> None:
    """Start the real DNS unit with an exclusively owned loopback config, then restore dormant state."""
    guard()
    require(not DNS_CONFIG.exists() and not DNS_CONFIG.is_symlink(),
            'preexisting DNS configuration is preserved')
    state = subprocess.check_output(['systemctl', 'show', '-p', 'ActiveState',
                                     '--value', 'hestia-dns.service'], text=True).strip()
    require(state == 'inactive', 'DNS service is not dormant')
    content = json.dumps({'listen': '127.0.0.1:1053', 'router': '127.0.0.2',
                          'directResolvers': {}}).encode()
    fd = os.open(DNS_CONFIG, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    inode = os.fstat(fd).st_ino
    started = False
    written = False
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), 0, grp.getgrnam('hestia-snapshot').gr_gid)
            os.fchmod(stream.fileno(), 0o640)
            stream.write(content)
        written = True
        started = True
        subprocess.run(['systemctl', 'start', 'hestia-dns.service'], check=True, timeout=20)
        packet = struct.pack('!6H', 1234, 256, 1, 0, 0, 0) + b'\x04deny\x07invalid\x00\x00\x01\x00\x01'
        deadline = time.monotonic() + 8
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(('127.0.0.2', 0))
                sock.settimeout(.3)
                sock.sendto(packet, ('127.0.0.1', 1053))
                try:
                    reply = sock.recv(4096)
                    break
                except TimeoutError:
                    require(time.monotonic() < deadline, 'installed DNS did not reply')
        require(reply[:2] == packet[:2] and reply[3] & 15 == 2, 'DNS did not fail closed')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('127.0.0.2', 0))
            sock.settimeout(2)
            sock.connect(('127.0.0.1', 1053))
            sock.sendall(len(packet).to_bytes(2, 'big') + packet)
            size = int.from_bytes(read_exact(sock, 2), 'big')
            reply = read_exact(sock, size)
            require(len(reply) >= 12 and reply[3] & 15 == 2, 'TCP DNS did not fail closed')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.3', 0))
            sock.settimeout(.4)
            sock.sendto(packet, ('127.0.0.1', 1053))
            try:
                sock.recv(4096)
            except TimeoutError:
                pass
            else:
                raise RuntimeError('unapproved client received DNS response')
        print('PASS installed DNS UDP/TCP deny and client isolation', flush=True)
    finally:
        meta = DNS_CONFIG.lstat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_ino == inode and
                (not written or DNS_CONFIG.read_bytes() == content),
                'DNS configuration changed concurrently; preserved with service state')
        if started:
            subprocess.run(['systemctl', 'stop', 'hestia-dns.service'], check=True, timeout=20)
        meta = DNS_CONFIG.lstat()
        require(meta.st_ino == inode and stat.S_ISREG(meta.st_mode) and
                (not written or DNS_CONFIG.read_bytes() == content),
                'DNS configuration changed during stop; preserved')
        DNS_CONFIG.unlink()
        subprocess.run(['systemctl', 'reset-failed', 'hestia-dns.service'],
                       check=True, timeout=10)
        require(subprocess.check_output(['systemctl', 'show', '-p', 'ActiveState',
                '--value', 'hestia-dns.service'], text=True).strip() == 'inactive',
                'DNS service did not return to dormant state')
        print('PASS restored dormant DNS configuration', flush=True)


def read_exact(sock: socket.socket, size: int) -> bytes:
    """Read one bounded DNS TCP frame or reject early EOF."""
    require(0 < size <= 65535, 'invalid DNS frame size')
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        require(bool(chunk), 'short DNS frame')
        data += chunk
    return data


def interrupted(signum: int, _frame: object) -> None:
    """Unwind owned-resource finally blocks on polite process interruption."""
    raise KeyboardInterrupt('acceptance interrupted')


def main() -> None:
    """Run one explicit installed acceptance mode and fail closed on exceptions."""
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('guard', 'api', 'dns', 'invalid'))
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    {'guard': guard, 'api': api_acceptance, 'dns': dns_smoke,
     'invalid': invalid_helpers}[args.mode]()


if __name__ == '__main__':
    main()
