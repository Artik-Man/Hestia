#!/usr/bin/env bash
# Start an isolated real panel with only the group-order helper permitted through sudo.
set -euo pipefail
[[ $(hostname -s) == lima-hestia-binding-test && $EUID == 0 && $# == 2 ]] || {
    echo "Usage on hestia-binding-test: sudo bash panel.sh PANEL_BINARY BROWSER_DIST" >&2
    exit 1
}
useradd --system --no-create-home --groups hestia-snapshot hestia-order-panel
printf '%s\n' 'hestia-order-panel ALL=(root) NOPASSWD: /usr/local/bin/hestia -apply-group-order' >/etc/sudoers.d/hestia-order-panel
chmod 0440 /etc/sudoers.d/hestia-order-panel
visudo -cf /etc/sudoers.d/hestia-order-panel
systemd-run --quiet --unit=hestia-order-panel --uid=hestia-order-panel \
    "$(realpath "$1")" -listen 127.0.0.1:18439 -snapshot /etc/hestia/snapshot.json \
    -assets "$(realpath "$2")" -enable-group-order
