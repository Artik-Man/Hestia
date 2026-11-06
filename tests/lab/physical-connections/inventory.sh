#!/usr/bin/env bash
# Verify Linux discovery against the genuine stand Ethernet interface in an isolated mount namespace, using a synthetic managed profile.
set -euo pipefail
[[ $(hostname -s) == lima-hestia-dev && $(id -u) == 0 && $# == 1 && -x $1 ]] || exit 1
[[ $(readlink /proc/self/ns/mnt) != "$(readlink /proc/1/ns/mnt)" ]] || exit 1
binary=$(realpath "$1")
mount --make-rprivate /
mount -t tmpfs tmpfs /etc
mount -t tmpfs tmpfs /run
umask 077
mkdir /etc/hestia
printf '1\n' >/etc/hestia/.installer-managed
touch /run/hestia-install.lock
# Select a real Ethernet device without assuming its name or link state.
# Exit 77 explicitly reports that hardware inventory cannot be exercised here.
python3 - <<'PYTHON'
import json
from pathlib import Path
ports = sorted(p for p in Path('/sys/class/net').iterdir()
               if (p / 'device').exists() and (p / 'type').read_text().strip() == '1'
               and not (p / 'wireless').exists() and not (p / 'phy80211').exists())
if not ports:
    print('SKIP physical inventory: no hardware-backed Ethernet interface')
    raise SystemExit(77)
name = ports[0].name
missing = 'hst-missing'
if (Path('/sys/class/net') / missing).exists():
    raise RuntimeError('synthetic missing-interface name already exists')
try:
    online = (ports[0] / 'carrier').read_text().strip() == '1'
except OSError:
    online = False
Path('/run/expected.json').write_text(json.dumps({'name': name, 'online': online, 'missing': missing}))
Path('/etc/hestia/profile.json').write_text(json.dumps({'version': 2, 'interfaces': [
    {'id': 'bench-ethernet', 'type': 'direct', 'bind_interface': name},
    {'id': 'bench-absent', 'type': 'direct', 'bind_interface': missing}]}))
PYTHON
echo "kernel $(uname -r); helper sha256 $(sha256sum "$binary" | cut -d' ' -f1)"
printf '{}\n' | "$binary" -physical-list >/run/inventory.json
python3 - <<'PY'
import json
from pathlib import Path
inventory = json.loads(Path("/run/inventory.json").read_text())
interfaces = {item["interfaceName"]: item for item in inventory["interfaces"]}
expected = json.loads(Path('/run/expected.json').read_text())
name, missing = expected['name'], expected['missing']
assert interfaces[name] == dict(interfaceName=name, kind="ethernet", present=True, online=expected['online'], exitIds=["bench-ethernet"])
assert interfaces[missing] == dict(interfaceName=missing, kind="ethernet", present=False, online=False, exitIds=["bench-absent"])
assert isinstance(inventory["wifiAvailable"], bool) and inventory["wifiProfiles"] == []
print(json.dumps(inventory, ensure_ascii=False, sort_keys=True))
PY
