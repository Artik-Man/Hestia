#!/usr/bin/env bash
# Verify Linux discovery against the genuine load1 eth0 in an isolated mount namespace, using a synthetic managed profile.
set -euo pipefail
[[ $(hostname -s) == lima-hestia-load-01 && $(id -u) == 0 && $# == 1 && -x $1 ]] || exit 1
[[ $(readlink /proc/self/ns/mnt) != "$(readlink /proc/1/ns/mnt)" ]] || exit 1
binary=$(realpath "$1")
mount --make-rprivate /
mount -t tmpfs tmpfs /etc
mount -t tmpfs tmpfs /run
umask 077
mkdir /etc/hestia
printf '1\n' >/etc/hestia/.installer-managed
touch /run/hestia-install.lock
cat >/etc/hestia/profile.json <<'PROFILE'
{"version":2,"interfaces":[{"id":"bench-ethernet","type":"direct","bind_interface":"eth0"},{"id":"bench-absent","type":"direct","bind_interface":"eth-missing"}]}
PROFILE
echo "kernel $(uname -r); helper sha256 $(sha256sum "$binary" | cut -d' ' -f1)"
printf '{}\n' | "$binary" -physical-list >/run/inventory.json
python3 - <<'PY'
import json
from pathlib import Path
inventory = json.loads(Path("/run/inventory.json").read_text())
interfaces = {item["interfaceName"]: item for item in inventory["interfaces"]}
assert set(interfaces) == {"eth0", "eth-missing"}, interfaces
assert interfaces["eth0"] == dict(interfaceName="eth0", kind="ethernet", present=True, online=True, exitIds=["bench-ethernet"])
assert interfaces["eth-missing"] == dict(interfaceName="eth-missing", kind="ethernet", present=False, online=False, exitIds=["bench-absent"])
assert inventory["wifiAvailable"] is False and inventory["wifiProfiles"] == []
print(json.dumps(inventory, ensure_ascii=False, sort_keys=True))
PY
