#!/usr/bin/env bash
# Build two independent WireGuard peers on a fresh, dedicated Debian test VM.
set -euo pipefail
umask 077
[[ $(hostname -s) == lima-hestia-binding-test && $EUID == 0 ]] || {
    echo "Requires root on lima-hestia-binding-test" >&2
    exit 1
}
work=/var/tmp/hestia-binding-lab
mkdir -m 0700 "$work"

# shellcheck source=peer.sh
source "$(dirname "$0")/peer.sh"
peer 1 alpha "$work"
peer 2 beta "$work"
cat >"$work/profile.json" <<'JSON'
{
  "version": 1,
  "socks_port": 1080,
  "interfaces": [
    {"id":"exit-alpha","type":"wireguard","config_file":"alpha.conf"},
    {"id":"exit-beta","type":"wireguard","config_file":"beta.conf"}
  ],
  "groups": [
    {"id":"group-alpha","exits":["exit-alpha"]},
    {"id":"group-beta","exits":["exit-beta"]}
  ],
  "lists": [
    {"id":"target","group":"group-alpha","masks":["*.bound.lab.test","*.second.lab.test"]},
    {"id":"control","group":"group-alpha","masks":["*.control.lab.test"]}
  ],
  "healthy":{"exit-alpha":true,"exit-beta":true}
}
JSON
