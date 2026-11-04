#!/usr/bin/env bash
# Create three isolated local receivers for the group- and exit-order experiment.
set -euo pipefail
umask 077
[[ $(hostname -s) == lima-hestia-binding-test && $EUID == 0 ]] || {
    echo "Requires root on lima-hestia-binding-test" >&2
    exit 1
}
work=/var/tmp/hestia-group-order
mkdir -m 0700 "$work"
# shellcheck source=../list-binding/peer.sh
source "$(dirname "$0")/../list-binding/peer.sh"
peer 1 alpha "$work"
peer 2 beta "$work"
peer 3 reserve "$work"
cat >"$work/profile.json" <<'JSON'
{
  "version": 1, "socks_port": 1080,
  "interfaces": [
    {"id":"exit-alpha","type":"wireguard","config_file":"alpha.conf"},
    {"id":"exit-reserve","type":"wireguard","config_file":"reserve.conf"},
    {"id":"exit-beta","type":"wireguard","config_file":"beta.conf"}
  ],
  "groups": [
    {"id":"group-alpha","exits":["exit-alpha","exit-reserve"]},
    {"id":"group-beta","exits":["exit-beta"]}
  ],
  "lists": [
    {"id":"tie-beta","group":"group-beta","masks":["*.tie.lab.test"]},
    {"id":"tie-alpha","group":"group-alpha","masks":["*.tie.lab.test"]},
    {"id":"pinned-alpha","group":"group-alpha","masks":["*.alpha.lab.test"]},
    {"id":"pinned-beta","group":"group-beta","masks":["*.beta.lab.test"]}
  ],
  "healthy":{"exit-alpha":true,"exit-reserve":true,"exit-beta":true}
}
JSON
