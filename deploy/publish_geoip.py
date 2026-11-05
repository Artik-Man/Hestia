"""Copy validated exact public-IP routing rules across the panel/dataplane ownership boundary."""

import ipaddress
import json
import os
from pathlib import Path
import stat
import tempfile

SOURCE = Path("/var/lib/hestia-geoip-proposals")
TARGET = Path("/var/lib/hestia-geoip-overrides")
LIMIT = 4096
# Match the worker's public-destination policy, including ranges Python classifies
# differently across Debian versions. IPv6 lookup candidates are global unicast.
GLOBAL_V6 = ipaddress.ip_network("2000::/3")
EXCLUSIONS = tuple(map(ipaddress.ip_network, (
    "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32",
    "2002::/16", "3fff::/20",
)))


def read_rules(directory, name):
    """Read one bounded regular proposal without following links or waiting on special files."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024:
            raise ValueError("invalid proposal file")
        data = stream.read(256 * 1024 + 1)
    if len(data) > 256 * 1024:
        raise ValueError("proposal too large")
    doc = json.loads(data)
    if not isinstance(doc, dict) or set(doc) != {"version", "rules"} or doc["version"] != 3:
        raise ValueError("invalid rule schema")
    rules = doc["rules"]
    if rules == []:
        return []
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict) or set(rules[0]) != {"ip_cidr"}:
        raise ValueError("invalid rule")
    hosts = rules[0]["ip_cidr"]
    if not isinstance(hosts, list) or len(hosts) > LIMIT:
        raise ValueError("invalid address count")
    result = []
    for value in hosts:
        if not isinstance(value, str) or len(value) > 50:
            raise ValueError("invalid address")
        host = ipaddress.ip_network(value)
        address = host.network_address
        if (
            host.num_addresses != 1 or not address.is_global or address.is_multicast
            or "%" in value or (address.version == 6 and address not in GLOBAL_V6)
            or any(address in prefix for prefix in EXCLUSIONS)
        ):
            raise ValueError("expected one public host")
        result.append(str(host))
    return result


def publish(source, target, catalogue):
    """Validate the whole bounded batch and atomically replace only modified country files."""
    directory = os.open(source, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        batch = {}
        seen = set()
        for code in catalogue.split():
            if len(code) != 2 or not code.isascii() or not code.isalpha() or not code.isupper():
                raise ValueError("invalid catalogue")
            hosts = read_rules(directory, code + ".json")
            if len(hosts) + len(seen) > LIMIT or any(ip in seen for ip in hosts) or len(set(hosts)) != len(hosts):
                raise ValueError("invalid exact country assignments")
            seen.update(hosts)
            batch[code] = hosts
    finally:
        os.close(directory)
    for code, hosts in batch.items():
        path = target / (code + ".json")
        data = json.dumps({"version": 3, "rules": [{"ip_cidr": hosts}] if hosts else []}, separators=(",", ":")).encode()
        if path.is_file() and path.read_bytes().strip() == data:
            continue
        with tempfile.NamedTemporaryFile(dir=target, delete=False) as out:
            try:
                out.write(data)
                out.flush()
                os.fchmod(out.fileno(), 0o644)
                os.fsync(out.fileno())
                os.replace(out.name, path)
            finally:
                Path(out.name).unlink(missing_ok=True)


if __name__ == "__main__":
    publish(SOURCE, TARGET, Path("/usr/share/hestia/geoip/countries.txt").read_text(encoding="ascii"))
