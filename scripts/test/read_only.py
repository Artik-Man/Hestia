"""Check the installed loopback API without emitting private payloads or mutating state."""
import ipaddress
import json
import subprocess
import sys
from urllib.parse import urlsplit
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep every installed API probe on its explicitly selected loopback origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Refuse redirects rather than contacting an unintended endpoint."""
        raise RuntimeError('API redirect refused')


def local_origin(value: str) -> str:
    """Validate a literal HTTP origin against loopback or an address assigned on this stand."""
    url = urlsplit(value)
    if url.scheme != 'http' or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        raise ValueError('panel_url must be a local HTTP origin without credentials or path')
    address = ipaddress.ip_address(url.hostname)
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError('Invalid panel port')
    if not address.is_loopback:
        interfaces = json.loads(subprocess.check_output(['ip', '-j', 'address', 'show'], text=True))
        local = {ipaddress.ip_address(item['local']) for interface in interfaces for item in interface.get('addr_info', [])}
        if address not in local:
            raise ValueError('panel_url address is not assigned to the selected stand')
    return value.rstrip('/')


def main() -> None:
    """Require successful bounded JSON reads; never POST, PUT, DELETE or print contents."""
    origin = local_origin(sys.argv[1] if len(sys.argv) == 2 else 'http://127.0.0.1:8080')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for path in ('navigation', 'groups-and-rules', 'awg', 'awg-underlays', 'hysteria2',
                 'physical-connections', 'quality', 'traffic', 'traffic/settings',
                 'country-map', 'dns/policy'):
        with opener.open(origin + '/api/' + path, timeout=20) as response:
            payload = response.read((1 << 20) + 1)
            if response.status != 200 or len(payload) > 1 << 20:
                raise RuntimeError('Installed API response invalid: ' + path)
            json.loads(payload)
        print('PASS read-only GET /api/' + path, flush=True)


if __name__ == '__main__':
    main()
